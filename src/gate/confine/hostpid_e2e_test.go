//go:build linux && jail_e2e

package confine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Each native leg also exercises forced ABI 5. Keeping the repetitions inside
// the registered leg makes the two-ABI mutation runner include that boundary.
func hostPIDSpecs(abi int) []Spec {
	specs := []Spec{{Profile: ProfileROv1, Net: true, ForceABI: abi}}
	if abi == 0 {
		specs = append(specs, Spec{Profile: ProfileROv1, Net: true, ForceABI: 5})
	}
	return specs
}
func TestJailMatrixP15c(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			t.Run("L-PROCESS-MRELEASE", func(t *testing.T) { hostMrelease(t, cfg.abi) })

			t.Run("L-SIGNAL-HOST", func(t *testing.T) { hostSignalEffect(t, hostPIDSpecs(cfg.abi), "L-SIGNAL-HOST") })
			t.Run("L-SIGNAL-SCOPE", func(t *testing.T) {
				hostSignalEffect(t, []Spec{{Profile: ProfileROv1, Net: true, ForceABI: cfg.abi}}, "L-SIGNAL-SCOPE")
			})
			t.Run("L-SIGNAL-OWN-GROUP", func(t *testing.T) {
				for _, spec := range hostPIDSpecs(cfg.abi) {
					for _, command := range []string{"trap '' USR1 && kill -USR1 0", "kill -0 $$", "timeout 1 sleep 5"} {
						start := time.Now()
						result := runJailedTimeout(t, spec, command, 4*time.Second)
						wantExit := 0
						if command == "timeout 1 sleep 5" {
							wantExit = 124
						}
						if result.setupErr != nil || result.exit != wantExit || result.stderr != "" || time.Since(start) > 4*time.Second {
							t.Fatalf("SETUP: own-group control %q: %+v elapsed=%s", command, result, time.Since(start))
						}
					}
				}
			})
			t.Run("L-ASYNC-OWNER", func(t *testing.T) { hostAsyncEffect(t, hostPIDSpecs(cfg.abi), "L-ASYNC-OWNER") })
			t.Run("L-ASYNC-SCOPE", func(t *testing.T) {
				hostAsyncEffect(t, []Spec{{Profile: ProfileROv1, Net: true, ForceABI: cfg.abi}}, "L-ASYNC-SCOPE")
			})
			if os.Getenv("SSHGATE_TEST_USER_RETUNE_PHASE") != "" || os.Geteuid() == 0 && os.Getenv("SSHGATE_JAIL_CI") == "1" {
				t.Run("L-SCHED-USER", func(t *testing.T) { legUserScheduler(t, cfg.abi) })
			} else if os.Geteuid() != 0 {
				t.Log("MUTATE-OMITTED(root): L-SCHED-USER")
			} else {
				t.Log("MUTATE-OMITTED(ci-only): L-SCHED-USER")
			}
			t.Run("L-RETUNE", func(t *testing.T) { hostRetuneEffect(t, cfg.abi) })
			if os.Geteuid() == 0 && os.Getenv("SSHGATE_JAIL_CI") == "1" {
				t.Run("L-RETUNE-SETPARAM", func(t *testing.T) { hostRetuneSetparam(t, cfg.abi) })
			} else if os.Geteuid() != 0 {
				t.Log("MUTATE-OMITTED(root): L-RETUNE-SETPARAM")
			} else {
				t.Log("MUTATE-OMITTED(ci-only): L-RETUNE-SETPARAM")
			}

			t.Run("L-SESSION", func(t *testing.T) {
				changed := false
				for _, spec := range hostPIDSpecs(cfg.abi) {
					out := requireProbeOutput(t, runP12(t, spec, "exec "+buildProbe(t)+" session 0", nil), "session")
					var pid, sid, group int
					if _, err := fmt.Sscanf(out, "session=%d:%d:%d", &pid, &sid, &group); err != nil {
						t.Fatal("SETUP:", out)
					}
					parentSID, err := unix.Getsid(0)
					mutationSetup(t, err)
					changed = changed || pid != sid || pid != group || sid == parentSID || group == unix.Getpgrp()
				}
				mutationEffect(t, "L-SESSION", "session", changed)
			})
			t.Run("L-LIFECYCLE", func(t *testing.T) { hostLifecycle(t, cfg.abi) })
		})
	}
}

func hostSignalEffect(t *testing.T, specs []Spec, leg string) {
	probe := buildProbe(t)
	delivered := false
	for _, spec := range specs {
		for _, nr := range []int{62, 200, 234, 129, 297, 424} {
			control := exec.Command("sleep", "30")
			mutationSetup(t, control.Start())
			output, err := exec.Command(probe, "signal-one", strconv.Itoa(nr), strconv.Itoa(control.Process.Pid)).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "signal=ok\n") {
				control.Process.Kill()
				control.Wait()
				t.Fatalf("SETUP: signal %d: %v %s", nr, err, output)
			}
			mutationSetup(t, waitSignalVictim(control))
			victim := exec.Command("sleep", "30")
			mutationSetup(t, victim.Start())
			result := runP12(t, spec, fmt.Sprintf("%s signal-one %d %d", probe, nr, victim.Process.Pid), nil)
			out := requireProbeOutput(t, result, "signal")
			done := make(chan error, 1)
			go func() { done <- victim.Wait() }()
			select {
			case <-done:
				delivered = true
			case <-time.After(30 * time.Millisecond):
				victim.Process.Kill()
				<-done
			}
			if !strings.Contains(out, "signal=1\n") && !strings.Contains(out, "signal=ok\n") {
				t.Fatalf("unexpected signal %d errno: %s", nr, out)
			}
		}
	}
	mutationEffect(t, leg, "signal", delivered)
}
func waitSignalVictim(command *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if exitCodeOf(err) != 128+int(unix.SIGUSR1) {
			return fmt.Errorf("signal victim status: %v", err)
		}
		return nil
	case <-time.After(time.Second):
		command.Process.Kill()
		<-done
		return fmt.Errorf("signal victim survived control")
	}
}
func hostAsyncEffect(t *testing.T, specs []Spec, leg string) {
	probe := buildProbe(t)
	delivered, badErrno := false, false
	for _, spec := range specs {
		for _, confined := range []bool{false, true} {
			victim := exec.Command(probe, "async-victim", "0")
			reader, err := victim.StdoutPipe()
			mutationSetup(t, err)
			mutationSetup(t, victim.Start())
			scan := bufio.NewScanner(reader)
			if !scan.Scan() || scan.Text() != "READY" {
				victim.Process.Kill()
				victim.Wait()
				t.Fatal("SETUP: SIGIO victim readiness")
			}
			command := probe + " async-owner " + strconv.Itoa(victim.Process.Pid)
			var out string
			if confined {
				out = requireProbeOutput(t, runP12(t, spec, command, nil), "owner")
				badErrno = badErrno || !strings.Contains(out, "owner=1\n")
			} else {
				data, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
				mutationSetup(t, err)
				out = string(data)
			}
			received := make(chan bool, 1)
			go func() { received <- scan.Scan() && scan.Text() == "SIGIO" }()
			var got bool
			select {
			case got = <-received:
			case <-time.After(100 * time.Millisecond):
				victim.Process.Kill()
				got = <-received
			}
			victim.Process.Kill()
			victim.Wait()
			if !confined && !got {
				t.Fatalf("SETUP: async SIGIO control: %s", out)
			}
			if confined {
				delivered = delivered || got
			}
		}
		out := requireProbeOutput(t, runP12(t, spec, probe+" async-errno "+strconv.Itoa(os.Getpid()), nil), append(strings.Fields(strings.Repeat("setown ", 5)+strings.Repeat("ioctl ", 3)), "setown_ex", "clear", "setsig")...)
		badErrno = badErrno || strings.Count(out, "setown=1\n") != 5 || !strings.Contains(out, "setown_ex=1\n") || strings.Count(out, "ioctl=1\n") != 3
		if !strings.Contains(out, "clear=ok\n") || !strings.Contains(out, "setsig=ok\n") {
			t.Fatalf("async zero-owner/setsig controls: %s", out)
		}
	}
	mutationEffect(t, leg, "errno", badErrno)
	mutationEffect(t, leg, "signal", delivered)
}
func startRetuneVictim(t *testing.T) *exec.Cmd {
	t.Helper()
	if os.Geteuid() != 0 {
		return startSleeper(t)
	}
	victim := exec.Command(buildProbe(t), "retune-victim", "drop")
	var diagnostic bytes.Buffer
	victim.Stderr = &diagnostic
	reader, err := victim.StdoutPipe()
	mutationSetup(t, err)
	mutationSetup(t, victim.Start())
	t.Cleanup(func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	})
	scan := bufio.NewScanner(reader)
	if !scan.Scan() || scan.Text() != "READY" {
		_ = victim.Process.Kill()
		_ = victim.Wait()
		t.Fatalf("SETUP: retune victim readiness: %v %s", scan.Err(), diagnostic.String())
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", victim.Process.Pid))
	mutationSetup(t, err)
	for _, field := range []string{"Uid", "CapPrm", "CapEff", "CapInh", "CapBnd", "CapAmb"} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			values := strings.Fields(line)
			if len(values) == 0 || values[0] != field+":" {
				continue
			}
			expected := 2
			if field == "Uid" {
				expected = 5
			}
			if len(values) != expected {
				t.Fatalf("SETUP: retune victim malformed %s", line)
			}
			for _, value := range values[1:] {
				n, err := strconv.ParseUint(value, 16, 64)
				if err != nil || n != 0 {
					t.Fatalf("SETUP: retune victim nonzero %s", line)
				}
			}
			found = true
		}
		if !found {
			t.Fatalf("SETUP: retune victim missing %s", field)
		}
	}
	return victim
}

func initializeRetuneVictim(t *testing.T, victim *exec.Cmd, targetCPU int) schedulerState {
	t.Helper()
	pid := victim.Process.Pid
	mutationSetup(t, unix.Setpriority(unix.PRIO_PROCESS, pid, 18))
	_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, 1, uintptr(pid), 2<<13|4)
	if errno != 0 {
		t.Fatalf("SETUP: initial ioprio: %v", errno)
	}
	var available, pinned unix.CPUSet
	mutationSetup(t, unix.SchedGetaffinity(0, &available))
	for cpu := 0; cpu < 1024; cpu++ {
		if cpu != targetCPU && available.IsSet(cpu) {
			pinned.Set(cpu)
			break
		}
	}
	if pinned.Count() != 1 {
		t.Fatal("SETUP: retune affinity requires at least two available CPUs")
	}
	mutationSetup(t, unix.SchedSetaffinity(pid, &pinned))
	limit := unix.Rlimit{Cur: 64, Max: 64}
	mutationSetup(t, unix.Prlimit(pid, unix.RLIMIT_NOFILE, &limit, nil))
	var priority int32
	_, _, errno = unix.Syscall(unix.SYS_SCHED_SETSCHEDULER, uintptr(pid), 0, uintptr(unsafe.Pointer(&priority)))
	if errno != 0 {
		t.Fatalf("SETUP: initial scheduler policy: %v", errno)
	}
	initial := readScheduler(t, pid)
	if initial.nice != 2 || initial.io != 2<<13|4 || initial.policy != 0 || initial.nofile != 64 || initial.affinity != pinned {
		t.Fatalf("SETUP: retune victim initial state: %+v", initial)
	}
	return initial
}

func retuneFieldChanged(handler string, before, after schedulerState) bool {
	switch handler {
	case "nice":
		return before.nice != after.nice
	case "ioprio":
		return before.io != after.io
	case "policy", "schedattr":
		return before.policy != after.policy
	case "affinity":
		return before.affinity != after.affinity
	case "prlimit":
		return before.nofile != after.nofile
	default:
		panic("unknown retune handler: " + handler)
	}
}

func hostRetuneEffect(t *testing.T, abi int) {
	probe := buildProbe(t)
	changed, badErrno := false, false
	var available unix.CPUSet
	mutationSetup(t, unix.SchedGetaffinity(0, &available))
	if available.Count() < 2 {
		t.Fatal("SETUP: retune affinity requires at least two available CPUs")
	}
	targetCPU := 0
	for !available.IsSet(targetCPU) {
		targetCPU++
	}
	for _, handler := range []string{"nice", "ioprio", "policy", "schedattr", "affinity", "prlimit"} {
		command := func(pid int) string { return fmt.Sprintf("%s retune-one %s %d %d", probe, handler, pid, targetCPU) }
		control := startRetuneVictim(t)
		initial := initializeRetuneVictim(t, control, targetCPU)
		output, err := exec.Command("/bin/sh", "-c", command(control.Process.Pid)).CombinedOutput()
		if err != nil || string(output) != "retune=ok\n" || !retuneFieldChanged(handler, initial, readScheduler(t, control.Process.Pid)) {
			t.Fatalf("SETUP: %s control did not change its field: %v %s", handler, err, output)
		}
		for _, spec := range hostPIDSpecs(abi) {
			victim := startRetuneVictim(t)
			before := initializeRetuneVictim(t, victim, targetCPU)
			out := requireProbeOutput(t, runP12(t, spec, command(victim.Process.Pid), nil), "retune")
			badErrno = badErrno || out != "retune=1\n"
			changed = before != readScheduler(t, victim.Process.Pid) || changed
		}
	}
	for _, spec := range hostPIDSpecs(abi) {
		victim := startRetuneVictim(t)
		expected := append([]string{"query"}, strings.Fields(strings.Repeat("retune ", 54))...)
		out := requireProbeOutput(t, runP12(t, spec, probe+" retune-errno "+strconv.Itoa(victim.Process.Pid), nil), expected...)
		badErrno = badErrno || strings.Count(out, "retune=1\n") != 54
		if !strings.Contains(out, "query=ok\n") {
			t.Fatalf("SETUP: prlimit query control: %s", out)
		}
		for _, item := range []struct {
			command string
			fields  []string
		}{
			{probe + " scheduler 0", []string{"prlimit", "nice", "ioprio", "policy", "affinity", "schedattr", "state"}},
			{probe + " raw 141 1 0 19", []string{"raw"}},
			{probe + " raw 251 2 0 24576", []string{"raw"}},
		} {
			out := requireProbeOutput(t, runP12(t, spec, item.command, nil), item.fields...)
			if strings.Contains(out, "=1\n") {
				t.Fatalf("SETUP: self/group retune control: %s", out)
			}
		}
	}
	mutationEffect(t, "L-RETUNE", "errno", badErrno)
	mutationEffect(t, "L-RETUNE", "retuned", changed)
}

func readRealtimePriority(t *testing.T, pid int) int32 {
	t.Helper()
	var priority int32
	_, _, errno := unix.Syscall(unix.SYS_SCHED_GETPARAM, uintptr(pid), uintptr(unsafe.Pointer(&priority)), 0)
	if errno != 0 {
		t.Fatalf("SETUP: observe realtime priority: %v", errno)
	}
	return priority
}

func hostRetuneSetparam(t *testing.T, abi int) {
	if os.Geteuid() != 0 || os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Fatal("SETUP: realtime retune requires root disposable CI")
	}
	probe := buildProbe(t)
	victim := func() *exec.Cmd {
		command := startRetuneVictim(t)
		priority := int32(2)
		_, _, errno := unix.Syscall(unix.SYS_SCHED_SETSCHEDULER, uintptr(command.Process.Pid), 2, uintptr(unsafe.Pointer(&priority)))
		if errno != 0 {
			t.Fatalf("SETUP: prepare SCHED_RR victim (requires CAP_SYS_NICE): %v", errno)
		}
		if readScheduler(t, command.Process.Pid).policy != 2 || readRealtimePriority(t, command.Process.Pid) != 2 {
			t.Fatal("SETUP: realtime victim not SCHED_RR priority 2")
		}
		return command
	}
	control := victim()
	output, err := exec.Command(probe, "retune-one", "param", strconv.Itoa(control.Process.Pid)).CombinedOutput()
	if err != nil || string(output) != "retune=ok\n" || readRealtimePriority(t, control.Process.Pid) != 1 {
		t.Fatalf("SETUP: sched_setparam control did not lower priority 2 to 1: %v %s", err, output)
	}
	changed, badErrno := false, false
	for _, spec := range hostPIDSpecs(abi) {
		target := victim()
		out := requireProbeOutput(t, runP12(t, spec, fmt.Sprintf("%s retune-one param %d", probe, target.Process.Pid), nil), "retune")
		priority := readRealtimePriority(t, target.Process.Pid)
		if priority != 1 && priority != 2 {
			t.Fatalf("SETUP: unexpected realtime priority %d", priority)
		}
		if readScheduler(t, target.Process.Pid).policy != 2 {
			t.Fatal("SETUP: sched_setparam unexpectedly changed policy")
		}
		changed = priority == 1 || changed
		badErrno = out != "retune=1\n" || badErrno
	}
	mutationEffect(t, "L-RETUNE-SETPARAM", "errno", badErrno)
	mutationEffect(t, "L-RETUNE-SETPARAM", "retuned", changed)
}

func TestRetuneFieldIsolation(t *testing.T) {
	baseline := schedulerState{}
	for _, handler := range []string{"nice", "ioprio", "policy", "schedattr", "affinity", "prlimit"} {
		after := baseline
		switch handler {
		case "nice":
			after.nice = 1
		case "ioprio":
			after.io = 1
		case "policy", "schedattr":
			after.policy = 3
		case "affinity":
			after.affinity.Set(0)
		case "prlimit":
			after.nofile = 7
		}
		for _, other := range []string{"nice", "ioprio", "policy", "schedattr", "affinity", "prlimit"} {
			want := handler == other || (handler == "policy" || handler == "schedattr") && (other == "policy" || other == "schedattr")
			if retuneFieldChanged(other, baseline, after) != want {
				t.Fatalf("%s observation counted %s change", other, handler)
			}
		}
	}
}

func hostLifecycle(t *testing.T, abi int) {
	alive := false
	for _, spec := range hostPIDSpecs(abi) {
		for _, mode := range []string{"normal", "cancel", "term", "nested", "forking"} {
			ctx, cancel := context.WithCancel(context.Background())
			// Two distinct detached generations retain stdout after their shell exits.
			command := "p=/dev/shm/lifecycle-$$; mkfifo $p; exec 3<>$p; rm $p; setsid sh -c 'echo CHILD=$$; echo ready >&3; sleep 8' & sh -c \"setsid sh -c 'echo CHILD=\\$\\$; echo ready >&3; sleep 8' &\"; read ready <&3; read ready <&3; "
			if mode == "nested" || mode == "forking" {
				command = "p=/dev/shm/lifecycle-$$; mkfifo $p; exec 3<>$p; rm $p; " + buildProbe(t) + " lifecycle-" + mode + " 0 & read ready <&3; read ready <&3; "
			}
			if mode == "normal" || mode == "nested" || mode == "forking" {
				command += "sleep .2"
				if mode == "forking" {
					command += "; echo TEARDOWN"
				}
			} else {
				command += "sleep 8"
			}
			jailed, err := spec.Command(ctx, command)
			mutationSetup(t, err)
			out := &lifecycleOutput{ready: make(chan struct{}, 1)}
			var diagnostic bytes.Buffer
			jailed.Cmd.Stdout = out
			jailed.Cmd.Stderr = &diagnostic
			jailed.Cmd.Cancel = func() error { return jailed.Cmd.Process.Signal(syscall.SIGTERM) }
			jailed.Cmd.WaitDelay = 500 * time.Millisecond
			start := time.Now()
			mutationSetup(t, jailed.Cmd.Start())
			_ = jailed.Started()
			if mode == "cancel" || mode == "term" {
				select {
				case <-out.ready:
				case <-time.After(5 * time.Second):
					jailed.Cmd.Process.Kill()
					jailed.Cmd.Wait()
					t.Fatal("SETUP: lifecycle readiness")
				}
				if mode == "cancel" {
					cancel()
				} else {
					mutationSetup(t, jailed.Cmd.Process.Signal(syscall.SIGTERM))
				}
			}
			_ = jailed.Cmd.Wait()
			cancel()
			if _, err := jailed.Status(); err != nil {
				t.Fatalf("SETUP: lifecycle jail: %v %s", err, diagnostic.String())
			}
			if strings.Count(out.String(), "CHILD=") != 2 {
				t.Fatalf("SETUP: lifecycle children: %q %s", out.String(), diagnostic.String())
			}
			remained := false
			for _, line := range strings.Fields(out.String()) {
				if !strings.HasPrefix(line, "CHILD=") && !strings.HasPrefix(line, "SPAWN=") {
					continue
				}
				pid, err := strconv.Atoi(strings.SplitN(line, "=", 2)[1])
				mutationSetup(t, err)
				if unix.Kill(pid, 0) == nil {
					remained = true
					_ = unix.Kill(pid, unix.SIGKILL)
				}
			}
			if mode == "forking" {
				beforeTeardown, _, hasTeardown := strings.Cut(out.String(), "TEARDOWN\n")
				if spawned := strings.Count(beforeTeardown, "SPAWN="); !hasTeardown || spawned < 3 || spawned >= 32 {
					t.Fatalf("SETUP: repeated creation missing: %q", out.String())
				}
				// r11 bounds cleanup, not success against continued creation.
				alive = alive || time.Since(start) > 6*time.Second
			} else {
				alive = alive || remained || time.Since(start) > 2*time.Second
			}
		}
	}
	mutationEffect(t, "L-LIFECYCLE", "alive", alive)
}

type lifecycleOutput struct {
	buffer bytes.Buffer
	ready  chan struct{}
}

func (out *lifecycleOutput) String() string { return out.buffer.String() }

func (out *lifecycleOutput) Write(p []byte) (int, error) {
	n, err := out.buffer.Write(p)
	if strings.Count(out.String(), "CHILD=") >= 2 {
		select {
		case out.ready <- struct{}{}:
		default:
		}
	}
	return n, err
}

func exitStopVictim(t *testing.T) int {
	t.Helper()
	command := exec.Command("/bin/sh", "-c", "exit 0")
	command.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	mutationSetup(t, command.Start())
	pid := command.Process.Pid
	t.Cleanup(func() {
		_ = unix.PtraceCont(pid, 0)
		var status unix.WaitStatus
		_, _ = unix.Wait4(pid, &status, 0, nil)
		command.Process.Release()
	})
	var status unix.WaitStatus
	_, err := unix.Wait4(pid, &status, 0, nil)
	mutationSetup(t, err)
	if !status.Stopped() {
		t.Fatal("SETUP: missing initial ptrace stop")
	}
	mutationSetup(t, unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACEEXIT))
	mutationSetup(t, unix.PtraceCont(pid, 0))
	_, err = unix.Wait4(pid, &status, 0, nil)
	mutationSetup(t, err)
	if !status.Stopped() || status.TrapCause() != unix.PTRACE_EVENT_EXIT {
		t.Fatalf("SETUP: missing exit stop: %v", status)
	}
	return pid
}
func residentPages(t *testing.T, pid int) uint64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	mutationSetup(t, err)
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatal("SETUP: statm", string(data))
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	mutationSetup(t, err)
	return pages
}
func hostMrelease(t *testing.T, abi int) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	probe := buildProbe(t)
	changed, badErrno := false, false
	// An exit ptrace stop occurs before exit_mm. SIGNAL_GROUP_EXIT makes that
	// private mm releasable while the tracer holds the process at the exit stop.
	for _, spec := range hostPIDSpecs(abi) {
		control := exitStopVictim(t)
		before := residentPages(t, control)
		if before == 0 {
			t.Fatal("SETUP: exit-stop victim has no resident pages")
		}
		data, err := exec.Command(probe, "mrelease", strconv.Itoa(control)).CombinedOutput()
		if err != nil || !strings.Contains(string(data), "mrelease=ok\n") || residentPages(t, control) >= before {
			t.Fatalf("SETUP: memory-release control: %v %s", err, data)
		}
		target := exitStopVictim(t)
		before = residentPages(t, target)
		if before == 0 {
			t.Fatal("SETUP: target has no resident pages")
		}
		output := requireProbeOutput(t, runP12(t, spec, probe+" mrelease "+strconv.Itoa(target), nil), "mrelease")
		badErrno = badErrno || !strings.Contains(output, "mrelease=1\n")
		changed = changed || residentPages(t, target) < before
	}
	mutationEffect(t, "L-PROCESS-MRELEASE", "errno", badErrno)
	mutationEffect(t, "L-PROCESS-MRELEASE", "memory", changed)
}
