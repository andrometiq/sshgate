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
					result := runP12(t, spec, "trap '' USR1; kill -USR1 0; kill -0 $$; timeout 1 sleep 5; test $? -eq 124", nil)
					if result.setupErr != nil || result.exit != 0 {
						t.Fatalf("own-group controls: %+v", result)
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
			t.Run("L-SESSION", func(t *testing.T) {
				changed := false
				for _, spec := range hostPIDSpecs(cfg.abi) {
					out := requireProbeOutput(t, runP12(t, spec, "exec "+buildProbe(t)+" session 0", nil))
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
			out := requireProbeOutput(t, result)
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
				out = requireProbeOutput(t, runP12(t, spec, command, nil))
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
		out := requireProbeOutput(t, runP12(t, spec, probe+" async-errno "+strconv.Itoa(os.Getpid()), nil))
		badErrno = badErrno || strings.Count(out, "setown=1\n") != 5 || !strings.Contains(out, "setown_ex=1\n") || strings.Count(out, "ioctl=1\n") != 3
		if !strings.Contains(out, "clear=ok\n") || !strings.Contains(out, "setsig=ok\n") {
			t.Fatalf("async zero-owner/setsig controls: %s", out)
		}
	}
	mutationEffect(t, leg, "errno", badErrno)
	mutationEffect(t, leg, "signal", delivered)
}
func hostRetuneEffect(t *testing.T, abi int) {
	probe := buildProbe(t)
	changed, badErrno := false, false
	control := startSleeper(t)
	initial := readScheduler(t, control.Process.Pid)
	output, err := exec.Command(probe, "scheduler", strconv.Itoa(control.Process.Pid)).CombinedOutput()
	if err != nil || initial == readScheduler(t, control.Process.Pid) {
		t.Fatalf("SETUP: retune control: %v %s", err, output)
	}
	for _, spec := range hostPIDSpecs(abi) {
		victim := startSleeper(t)
		before := readScheduler(t, victim.Process.Pid)
		out := requireProbeOutput(t, runP12(t, spec, probe+" retune-errno "+strconv.Itoa(victim.Process.Pid), nil))
		badErrno = badErrno || strings.Count(out, "retune=1\n") != 54
		if !strings.Contains(out, "query=ok\n") {
			t.Fatalf("prlimit query control: %s", out)
		}
		out = requireProbeOutput(t, runP12(t, spec, probe+" scheduler "+strconv.Itoa(victim.Process.Pid), nil))
		changed = changed || before != readScheduler(t, victim.Process.Pid)
		// PGRP zero reaches the confined session only; PROCESS zero covers self.
		for _, command := range []string{probe + " scheduler 0", probe + " raw 141 1 0 19", probe + " raw 251 2 0 24576"} {
			out = requireProbeOutput(t, runP12(t, spec, command, nil))
			if strings.Contains(out, "=1\n") {
				t.Fatalf("self/group retune control: %s", out)
			}
		}
	}
	mutationEffect(t, "L-RETUNE", "errno", badErrno)
	mutationEffect(t, "L-RETUNE", "retuned", changed)
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
			if err := jailed.Status(); err != nil {
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
		output := requireProbeOutput(t, runP12(t, spec, probe+" mrelease "+strconv.Itoa(target), nil))
		badErrno = badErrno || !strings.Contains(output, "mrelease=1\n")
		changed = changed || residentPages(t, target) < before
	}
	mutationEffect(t, "L-PROCESS-MRELEASE", "errno", badErrno)
	mutationEffect(t, "L-PROCESS-MRELEASE", "memory", changed)
}
