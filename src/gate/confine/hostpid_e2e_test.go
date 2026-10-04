//go:build linux && jail_e2e

package confine

import (
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
				p := newProof(t, "L-SIGNAL-OWN-GROUP")
				var results []JailedResult
				for _, spec := range hostPIDSpecs(cfg.abi) {
					for _, command := range []string{"setsid sh -c \"trap '' USR1 && kill -USR1 0\"", "kill -0 $$", "timeout 1 sleep 5"} {
						start := time.Now()
						wantExit := 0
						if command == "timeout 1 sleep 5" {
							wantExit = 124
						}
						result := runJailed(t, p, spec, RunPlan{Mode: Execute, Timeout: 4 * time.Second, Ops: []ProofOp{{Name: "control", Command: command, Outcomes: []OpOutcome{{Exit: wantExit}}}}})
						results = append(results, result)
						if result.setupErr != nil || result.exit != wantExit || result.stderr != "" || time.Since(start) > 4*time.Second {
							t.Fatalf("SETUP: own-group control %q: %+v elapsed=%s", command, result, time.Since(start))
						}
					}
				}
				p.Jailed("probe", results...)
				p.Finish()
			})
			t.Run("L-ASYNC-OWNER", func(t *testing.T) { hostAsyncEffect(t, hostPIDSpecs(cfg.abi), "L-ASYNC-OWNER") })
			t.Run("L-ASYNC-SCOPE", func(t *testing.T) {
				hostAsyncEffect(t, []Spec{{Profile: ProfileROv1, Net: true, ForceABI: cfg.abi}}, "L-ASYNC-SCOPE")
			})
			if os.Getenv("SSHGATE_TEST_USER_RETUNE_PHASE") != "" || os.Geteuid() == 0 && os.Getenv("SSHGATE_JAIL_CI") == "1" {
				t.Run("L-SCHED-USER", func(t *testing.T) { legUserScheduler(t, cfg.abi) })
			} else {
				t.Run("L-SCHED-USER", func(t *testing.T) {
					p := newProof(t, "L-SCHED-USER")
					if os.Geteuid() != 0 {
						p.Omit("root-only")
					} else {
						p.Omit("ci-only")
					}
				})
			}
			t.Run("L-RETUNE", func(t *testing.T) { hostRetuneEffect(t, cfg.abi) })
			if os.Geteuid() == 0 && os.Getenv("SSHGATE_JAIL_CI") == "1" {
				t.Run("L-RETUNE-SETPARAM", func(t *testing.T) { hostRetuneSetparam(t, cfg.abi) })
			} else {
				t.Run("L-RETUNE-SETPARAM", func(t *testing.T) {
					p := newProof(t, "L-RETUNE-SETPARAM")
					if os.Geteuid() != 0 {
						p.Omit("root-only")
					} else {
						p.Omit("ci-only")
					}
				})
			}

			t.Run("L-SESSION", func(t *testing.T) {
				p := newProof(t, "L-SESSION")
				var results []JailedResult
				changed := false
				for _, spec := range hostPIDSpecs(cfg.abi) {
					result := runM2Probe(t, p, spec, buildProbe(t)+" session $$", "session")
					results = append(results, result)
					out := result.stdout
					var pid, sid, group int
					if _, err := fmt.Sscanf(out, "session=%d:%d:%d", &pid, &sid, &group); err != nil || pid <= 0 || sid <= 0 || group <= 0 || out != fmt.Sprintf("session=%d:%d:%d\n", pid, sid, group) {
						t.Fatal("SETUP:", out)
					}
					parentSID, err := unix.Getsid(0)
					mutationSetup(t, err)
					changed = changed || pid != sid || pid != group || sid == parentSID || group == unix.Getpgrp()
				}
				p.Jailed("probe", results...)
				mutationEffect(t, "L-SESSION", "session", changed)
				p.Finish()
			})
			t.Run("L-LIFECYCLE", func(t *testing.T) { hostLifecycle(t, cfg.abi) })
			t.Run("L-NUMA-MIGRATE-PAGES", func(t *testing.T) { p := newProof(t, "L-NUMA-MIGRATE-PAGES"); p.Residual("R-NUMA-EFFECT") })
			t.Run("L-NUMA-MOVE-PAGES", func(t *testing.T) { p := newProof(t, "L-NUMA-MOVE-PAGES"); p.Residual("R-NUMA-EFFECT") })
		})
	}
}

func hostSignalEffect(t *testing.T, specs []Spec, leg string) {
	p := newProof(t, leg)
	probe, binary := buildProbe(t), buildM2Recipient(t)
	delivered := false
	var results []JailedResult
	for index, spec := range specs {
		for _, nr := range []int{62, 200, 234, 129, 297, 424} {
			control := newM2Recipient(t, binary, syscall.SIGUSR1)
			mark := control.Mark()
			output, err := exec.Command(probe, "signal-one", strconv.Itoa(nr), strconv.Itoa(control.command.Process.Pid)).CombinedOutput()
			if err != nil || string(output) != "signal=ok\n" {
				t.Fatalf("SETUP: signal control %d: %v %s", nr, err, output)
			}
			if records := m2Seal(t, control, mark); records[0] != "signal=pending" {
				t.Fatal("SETUP: signal control did not arrive")
			}
			mutationSetup(t, control.Stop())
			victim := newM2Recipient(t, binary, syscall.SIGUSR1)
			p.ObserveWith(fmt.Sprintf("recipient-%d-%d", index, nr), victim)
			mark = victim.Mark()
			result := runM2Probe(t, p, spec, fmt.Sprintf("%s signal-one %d %d", probe, nr, victim.command.Process.Pid), "signal")
			results = append(results, result)
			if result.stdout != "signal=1\n" && result.stdout != "signal=ok\n" {
				t.Fatalf("UNEXPECTED: signal %d: %s", nr, result.stdout)
			}
			records := m2Seal(t, victim, mark)
			delivered = delivered || records[0] == "signal=pending"
		}
	}
	p.Control("facility", ControlResult{Valid: true})
	p.Jailed("probe", results...)
	sealM2Processes(t, p)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: true})
	mutationEffect(t, leg, "signal", delivered)
	p.Finish()
}
func hostAsyncEffect(t *testing.T, specs []Spec, leg string) {
	p := newProof(t, leg)
	probe, binary := buildProbe(t), buildM2Recipient(t)
	delivered, badErrno := false, false
	var results []JailedResult
	for index, spec := range specs {
		control := newM2Recipient(t, binary, syscall.SIGIO)
		mark := control.Mark()
		output, err := exec.Command(probe, "async-owner", strconv.Itoa(control.command.Process.Pid)).CombinedOutput()
		if err != nil || string(output) != "owner=ok\n" {
			t.Fatalf("SETUP: async control: %v %s", err, output)
		}
		if records := m2Seal(t, control, mark); records[0] != "sigio=pending" {
			t.Fatal("SETUP: SIGIO control did not arrive")
		}
		mutationSetup(t, control.Stop())
		victim := newM2Recipient(t, binary, syscall.SIGIO)
		p.ObserveWith(fmt.Sprintf("sigio-%d", index), victim)
		mark = victim.Mark()
		result := runM2Probe(t, p, spec, probe+" async-owner "+strconv.Itoa(victim.command.Process.Pid), "owner")
		results = append(results, result)
		badErrno = badErrno || result.stdout != "owner=1\n"
		records := m2Seal(t, victim, mark)
		delivered = delivered || records[0] == "sigio=pending"
		result = runM2Probe(t, p, spec, probe+" async-errno "+strconv.Itoa(os.Getpid()), append(strings.Fields(strings.Repeat("setown ", 5)+strings.Repeat("ioctl ", 3)), "setown_ex", "clear", "setsig")...)
		results = append(results, result)
		out := result.stdout
		badErrno = badErrno || strings.Count(out, "setown=1\n") != 5 || !strings.Contains(out, "setown_ex=1\n") || strings.Count(out, "ioctl=1\n") != 3
		if !strings.Contains(out, "clear=ok\n") || !strings.Contains(out, "setsig=ok\n") {
			t.Fatalf("UNEXPECTED: async clear/setsig controls: %s", out)
		}
	}
	p.Control("facility", ControlResult{Valid: true})
	p.Jailed("probe", results...)
	sealM2Processes(t, p)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: true})
	mutationEffect(t, leg, "errno", badErrno)
	mutationEffect(t, leg, "signal", delivered)
	p.Finish()
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
	p := newProof(t, "L-RETUNE")
	var results []JailedResult
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
		control := startRetuneVictim(t, p)
		initial := initializeRetuneVictim(t, control, targetCPU)
		output, err := exec.Command("/bin/sh", "-c", command(control.Process.Pid)).CombinedOutput()
		if err != nil || string(output) != "retune=ok\n" || !retuneFieldChanged(handler, initial, readScheduler(t, control.Process.Pid)) {
			t.Fatalf("SETUP: %s control did not change its field: %v %s", handler, err, output)
		}
		for index, spec := range hostPIDSpecs(abi) {
			victim := startRetuneVictim(t, p)
			initializeRetuneVictim(t, victim, targetCPU)
			observer := &m2StateObserver{sample: func() string { return fmt.Sprint(readScheduler(t, victim.Process.Pid)) }}
			p.ObserveWith(fmt.Sprintf("retune-%s-%d", handler, index), observer)
			mark := observer.Mark()
			result := runM2Probe(t, p, spec, command(victim.Process.Pid), "retune")
			results = append(results, result)
			out := result.stdout
			records := m2Seal(t, observer, mark)
			badErrno = badErrno || out != "retune=1\n"
			changed = records[0] != records[1] || changed
		}
	}
	for _, spec := range hostPIDSpecs(abi) {
		victim := startRetuneVictim(t, p)
		expected := append([]string{"query"}, strings.Fields(strings.Repeat("retune ", 54))...)
		result := runM2Probe(t, p, spec, probe+" retune-errno "+strconv.Itoa(victim.Process.Pid), expected...)
		results = append(results, result)
		out := result.stdout
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
			result := runM2Probe(t, p, spec, item.command, item.fields...)
			results = append(results, result)
			out := result.stdout
			if strings.Contains(out, "=1\n") {
				t.Fatalf("SETUP: self/group retune control: %s", out)
			}
		}
	}
	p.Control("facility", ControlResult{Valid: true})
	p.Jailed("probe", results...)
	sealM2Processes(t, p)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: true})
	mutationEffect(t, "L-RETUNE", "errno", badErrno)
	mutationEffect(t, "L-RETUNE", "retuned", changed)
	p.Finish()
}

func hostRetuneSetparam(t *testing.T, abi int) {
	p := newProof(t, "L-RETUNE-SETPARAM")
	var results []JailedResult
	if os.Geteuid() != 0 || os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Fatal("SETUP: realtime retune requires root disposable CI")
	}
	probe := buildProbe(t)
	victim := func() *exec.Cmd {
		command := startRetuneVictim(t, p)
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
	for index, spec := range hostPIDSpecs(abi) {
		target := victim()
		observer := &m2StateObserver{sample: func() string { return fmt.Sprint(readRealtimePriority(t, target.Process.Pid)) }}
		p.ObserveWith(fmt.Sprintf("param-%d", index), observer)
		mark := observer.Mark()
		result := runM2Probe(t, p, spec, fmt.Sprintf("%s retune-one param %d", probe, target.Process.Pid), "retune")
		results = append(results, result)
		out := result.stdout
		records := m2Seal(t, observer, mark)
		priority64, err := strconv.ParseInt(records[1], 10, 32)
		mutationSetup(t, err)
		priority := int32(priority64)
		if priority != 1 && priority != 2 {
			t.Fatalf("SETUP: unexpected realtime priority %d", priority)
		}
		if readScheduler(t, target.Process.Pid).policy != 2 {
			t.Fatal("SETUP: sched_setparam unexpectedly changed policy")
		}
		changed = priority == 1 || changed
		badErrno = out != "retune=1\n" || badErrno
	}
	p.Control("facility", ControlResult{Valid: true})
	p.Jailed("probe", results...)
	sealM2Processes(t, p)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: true})
	mutationEffect(t, "L-RETUNE-SETPARAM", "errno", badErrno)
	mutationEffect(t, "L-RETUNE-SETPARAM", "retuned", changed)
	p.Finish()
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
	p := newProof(t, "L-LIFECYCLE")
	m2LifecycleControl(t)
	alive := false
	var results []JailedResult
	for index, spec := range hostPIDSpecs(abi) {
		for _, mode := range []string{"normal", "cancel", "term", "nested", "forking"} {
			command := "p=/dev/shm/lifecycle-$$; mkfifo $p; exec 3<>$p; rm $p; setsid sh -c 'echo CHILD=$$; echo ready >&3; sleep 8' & sh -c \"setsid sh -c 'echo CHILD=\\$\\$; echo ready >&3; sleep 8' &\"; read ready <&3; read ready <&3; "
			if mode == "nested" || mode == "forking" {
				command = "p=/dev/shm/lifecycle-$$; mkfifo $p; exec 3<>$p; rm $p; " + buildProbe(t) + " lifecycle-" + mode + " 0 & read ready <&3; read ready <&3; "
			}
			cancelling := mode == "cancel" || mode == "term"
			if cancelling {
				command += "echo READY; sleep 8"
			} else {
				command += "sleep .2"
				if mode == "forking" {
					command += "; echo TEARDOWN"
				}
			}
			observer := &m2LifecycleObserver{}
			p.ObserveWith(fmt.Sprintf("descendants-%d-%s", index, mode), observer)
			mark := observer.Mark()
			start := time.Now()
			var result JailedResult
			if mode == "cancel" {
				var jailed *Jailed
				result = runJailed(t, p, spec, RunPlan{Mode: Cancelled, Command: command, ReadyPoint: "probe", CancelAfterReady: true, ExpectExit: 143, Timeout: 10 * time.Second,
					Configure: func(j *Jailed) { jailed = j }, AfterReady: func() { observer.capture(t, jailed.Cmd.Process.Pid) }, CleanupEvidence: func() error { return observer.inspect() },
				})
			} else {
				result = runM2Lifecycle(t, p, spec, command, mode)
			}
			results = append(results, result)
			if err := validateM2LifecycleReport(result.stdout, mode); err != nil {
				t.Fatal("SETUP:", err)
			}
			observer.addReport(t, result.stdout)
			m2Seal(t, observer, mark)
			if mode == "forking" {
				alive = alive || time.Since(start) > 6*time.Second
			} else {
				alive = alive || observer.remained || time.Since(start) > 2*time.Second
			}
		}
	}
	p.Control("facility", ControlResult{Valid: true, Detail: "unjailed descendants survive their exited parent"})
	p.Jailed("probe", results...)
	sealM2Processes(t, p)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: true})
	mutationEffect(t, "L-LIFECYCLE", "alive", alive)
	p.Finish()
}

func hostMrelease(t *testing.T, abi int) {
	p := newProof(t, "L-PROCESS-MRELEASE")
	var results []JailedResult
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	probe := buildProbe(t)
	changed, badErrno := false, false
	// An exit ptrace stop occurs before exit_mm. SIGNAL_GROUP_EXIT makes that
	// private mm releasable while the tracer holds the process at the exit stop.
	for index, spec := range hostPIDSpecs(abi) {
		control := exitStopVictim(t, p)
		before := residentPages(t, control)
		if before == 0 {
			t.Fatal("SETUP: exit-stop victim has no resident pages")
		}
		data, err := exec.Command(probe, "mrelease", strconv.Itoa(control)).CombinedOutput()
		if err != nil || !strings.Contains(string(data), "mrelease=ok\n") || residentPages(t, control) >= before {
			t.Fatalf("SETUP: memory-release control: %v %s", err, data)
		}
		target := exitStopVictim(t, p)
		before = residentPages(t, target)
		if before == 0 {
			t.Fatal("SETUP: target has no resident pages")
		}
		observer := &m2StateObserver{sample: func() string { return strconv.FormatUint(residentPages(t, target), 10) }}
		p.ObserveWith(fmt.Sprintf("memory-%d", index), observer)
		mark := observer.Mark()
		result := runM2Probe(t, p, spec, probe+" mrelease "+strconv.Itoa(target), "mrelease")
		results = append(results, result)
		output := result.stdout
		records := m2Seal(t, observer, mark)
		after, err := strconv.ParseUint(records[1], 10, 64)
		mutationSetup(t, err)
		badErrno = badErrno || !strings.Contains(output, "mrelease=1\n")
		changed = changed || after < before
	}
	p.Control("facility", ControlResult{Valid: true})
	p.Jailed("probe", results...)
	sealM2Processes(t, p)
	p.Observed("effects", Observation{Conclusive: true, Sealed: true, Valid: true})
	mutationEffect(t, "L-PROCESS-MRELEASE", "errno", badErrno)
	mutationEffect(t, "L-PROCESS-MRELEASE", "memory", changed)
	p.Finish()
}
