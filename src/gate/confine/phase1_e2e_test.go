//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"fmt"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestJailMatrixPhase1(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: cfg.abi, Net: true}
			t.Run("L-FAULT-private", func(t *testing.T) { legPhase1Fault(t, spec, "private") })
			t.Run("L-FAULT-setattr", func(t *testing.T) { legPhase1Fault(t, spec, "setattr") })
			t.Run("L-FAULT-devnodes", func(t *testing.T) { legPhase1Fault(t, spec, "devnodes") })
			t.Run("L-FAULT-covers", func(t *testing.T) { legPhase1Fault(t, spec, "covers") })
			t.Run("L-FAULT-scratch", func(t *testing.T) { legPhase1Fault(t, spec, "scratch") })
			t.Run("L-CLONE-USER", func(t *testing.T) { legPhase1Clone(t, spec, "USER") })
			t.Run("L-CLONE-MNT", func(t *testing.T) { legPhase1Clone(t, spec, "MNT") })
			t.Run("L-DEV-OPEN", func(t *testing.T) {
				p := newProof(t, "L-DEV-OPEN")
				probe := buildProbe(t)
				pty, _ := openPty(t)
				opened, aborted := 0, false
				for i, path := range []string{"/dev/ptmx", pty, "/dev/fuse"} {
					name := []string{"ptmx", "pty", "fuse"}[i]
					control, err := exec.Command(probe, "phase1-open", path).CombinedOutput()
					p.Control(name, ControlResult{Valid: err == nil && string(control) == "open=ok\n", Detail: fmt.Sprintf("device open %s: %s %v", path, control, err)})
					plan := RunPlan{Mode: Execute, Ops: []ProofOp{{Name: name, Command: probe + " phase1-open " + path, Outcomes: []OpOutcome{{Stdout: "open=13\n", Exit: 1}}}}}
					if jailmut.On("P-NODEV") {
						if jailmut.On("P-SELFCHECK-MOUNTS") {
							plan.Ops[0].Outcomes = []OpOutcome{{Stdout: "open=ok\n"}}
						} else {
							plan = RunPlan{Mode: SetupAbort, Stage: "selfcheck", Command: probe + " phase1-open " + path}
							aborted = true
						}
					}
					result := runJailed(t, p, spec, plan)
					p.Jailed(name, result)
					if result.stdout == "open=ok\n" {
						opened++
					}
				}
				p.Observed("devices", Observation{Conclusive: true, Sealed: true, Valid: opened == 0 || opened == 3, Detail: fmt.Sprintf("opened %d of 3 devices", opened)})
				mutationAbort(t, "L-DEV-OPEN", "selfcheck", aborted)
				mutationEffect(t, "L-DEV-OPEN", "opened", opened == 3)
				p.Finish()
			})
			t.Run("L-DEVNODE-WRITE", func(t *testing.T) {
				p := newProof(t, "L-DEVNODE-WRITE")
				probe := buildProbe(t)
				nullDenied, reportsMatch := false, true
				for _, node := range []string{"null", "urandom", "full", "zero"} {
					path := "/dev/" + node
					out, err := exec.Command(probe, "device-write", path).CombinedOutput()
					expected, code := "open=ok\nwrite=ok\n", 0
					if node == "full" {
						expected, code = "open=ok\nwrite=28\n", 3
					}
					p.Control(node, ControlResult{Valid: string(out) == expected && exitCodeOf(err) == code, Detail: fmt.Sprintf("device %s: %s %v", node, out, err)})
					want := OpOutcome{Stdout: "open=13\n", Exit: 1}
					if node == "null" && !jailmut.On("P-DEV-SIX") {
						want = OpOutcome{Stdout: "open=ok\nwrite=ok\n"}
					}
					result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: node, Command: probe + " device-write " + path, Outcomes: []OpOutcome{want}}}})
					p.Jailed(node, result)
					reportsMatch = reportsMatch && result.stdout == want.Stdout
					if node == "null" {
						nullDenied = result.stdout == "open=13\n"
					}
				}
				p.Observed("devices", Observation{Conclusive: true, Sealed: true, Valid: reportsMatch, Detail: "all four complete device-write reports validated"})
				mutationEffect(t, "L-DEVNODE-WRITE", "null-denied", nullDenied)
				p.Finish()
			})
			t.Run("L-READS-WORK", func(t *testing.T) { legPhase1Reads(t, spec) })
			t.Run("L-TTY-STATE", func(t *testing.T) { legPhase1TTY(t, spec) })
			t.Run("L-SCRATCH-FILL", func(t *testing.T) {
				p := newProof(t, "L-SCRATCH-FILL")
				probe := buildProbe(t)
				out, err := exec.Command(probe, "phase1-fill", t.TempDir()+"/fill-control").CombinedOutput()
				p.Control("fill", ControlResult{Valid: err == nil && string(out) == "open=ok\nfill=ok\n", Detail: fmt.Sprintf("fill: %s %v", out, err)})
				want := OpOutcome{Stdout: "open=ok\nfill=28\n", Exit: 3}
				if jailmut.On("P-SCRATCH-SIZE") {
					want = OpOutcome{Stdout: "open=ok\nfill=ok\n"}
				}
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "fill", Command: probe + " phase1-fill /dev/shm/fill", Outcomes: []OpOutcome{want}}}})
				p.Jailed("fill", result)
				p.Observed("fill", Observation{Conclusive: true, Sealed: true, Valid: result.stdout == want.Stdout, Detail: "complete fill operation report"})
				mutationEffect(t, "L-SCRATCH-FILL", "filled", result.stdout == "open=ok\nfill=ok\n")
				p.Finish()
			})
			t.Run("L-SCRATCH-PRIVATE", func(t *testing.T) {
				p := newProof(t, "L-SCRATCH-PRIVATE")
				file, err := os.CreateTemp("/dev/shm", "sshgate-private-")
				mutationSetup(t, err)
				defer os.Remove(file.Name())
				_, err = file.WriteString("host-canary")
				mutationSetup(t, err)
				mutationSetup(t, file.Close())
				control, err := os.ReadFile(file.Name())
				p.Control("canary", ControlResult{Valid: err == nil && string(control) == "host-canary", Detail: fmt.Sprintf("canary: %q %v", control, err)})
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "private", Command: "test ! -e " + file.Name() + " && printf private > " + file.Name(), Outcomes: []OpOutcome{{}}}}})
				p.Jailed("private", result)
				after, err := os.ReadFile(file.Name())
				p.Observed("canary", Observation{Conclusive: err == nil, Sealed: true, Valid: string(after) == "host-canary", Detail: fmt.Sprintf("host canary: %q %v", after, err)})
				p.Finish()
			})
			t.Run("L-SCRATCH-NOEXEC", func(t *testing.T) {
				p := newProof(t, "L-SCRATCH-NOEXEC")
				controlPath := t.TempDir() + "/execute"
				data, err := os.ReadFile("/bin/true")
				mutationSetup(t, err)
				mutationSetup(t, os.WriteFile(controlPath, data, 0700))
				probe := buildProbe(t)
				out, err := exec.Command(probe, "phase1-exec", controlPath).CombinedOutput()
				p.Control("exec", ControlResult{Valid: err == nil && len(out) == 0, Detail: fmt.Sprintf("exec: %s %v", out, err)})
				command := "cp /bin/true /dev/shm/execute && " + probe + " phase1-exec /dev/shm/execute"
				plan := RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "exec", Command: command, Outcomes: []OpOutcome{{Stdout: "exec=13\n", Exit: 1}}}}}
				if jailmut.On("P-SCRATCH-FLAGS") {
					if jailmut.On("P-SELFCHECK-MOUNTS") {
						plan.Ops[0].Validate = nil
						plan.Ops[0].Outcomes = []OpOutcome{{}}
					} else {
						plan = RunPlan{Mode: SetupAbort, Stage: "selfcheck", Command: command}
					}
				}
				result := runJailed(t, p, spec, plan)
				p.Jailed("exec", result)
				p.Observed("exec", Observation{Conclusive: true, Sealed: true, Valid: plan.Mode == SetupAbort || result.stdout == "exec=13\n" || result.stdout == "", Detail: "validated execution or setup denial"})
				mutationAbort(t, "L-SCRATCH-NOEXEC", "selfcheck", plan.Mode == SetupAbort)
				mutationEffect(t, "L-SCRATCH-NOEXEC", "executed", plan.Mode == Execute && result.exit == 0)
				p.Finish()
			})
			t.Run("L-RL-FSIZE", func(t *testing.T) {
				p := newProof(t, "L-RL-FSIZE")
				probe := buildProbe(t)
				out, err := exec.Command(probe, "phase1-fsize", t.TempDir()+"/control").CombinedOutput()
				p.Control("fsize", ControlResult{Valid: err == nil && string(out) == "open=ok\nseek=ok\nwrite=ok\n", Detail: fmt.Sprintf("fsize: %s %v", out, err)})
				want := OpOutcome{Stdout: "open=ok\nseek=ok\nwrite=27\n", Exit: 3}
				if jailmut.On("P-RL-FSIZE") {
					want = OpOutcome{Stdout: "open=ok\nseek=ok\nwrite=ok\n"}
				}
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "fsize", Command: probe + " phase1-fsize /dev/shm/fsize", Outcomes: []OpOutcome{want}}}})
				p.Jailed("fsize", result)
				p.Observed("fsize", Observation{Conclusive: true, Sealed: true, Valid: result.stdout == want.Stdout, Detail: "complete write report"})
				mutationEffect(t, "L-RL-FSIZE", "limit", result.exit == 0)
				p.Finish()
			})
			t.Run("L-RL-CORE", func(t *testing.T) { legPhase1Core(t, spec) })
			if (os.Getenv("SSHGATE_JAIL_CI") == "1" && os.Getuid() == 0) || os.Getenv("SSHGATE_TEST_USER_RETUNE_PHASE") != "" {
				t.Run("L-RL-NPROC", func(t *testing.T) { legPhase1Nproc(t, spec) })
			} else {
				t.Run("L-RL-NPROC", func(t *testing.T) {
					p := newProof(t, "L-RL-NPROC")
					if os.Getuid() != 0 {
						p.Omit("root-only")
					} else {
						p.Omit("ci-only")
					}
				})
			}
			t.Run("L-FDS", func(t *testing.T) { legPhase1FD(t, spec) })
		})
	}
}

func legPhase1Fault(t *testing.T, spec Spec, stage string) {
	p := newProof(t, "L-FAULT-"+stage)
	control := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}})
	p.Control("intact", ControlResult{Valid: control.stdout == "CONTROL_RAN", Jailed: &control, Detail: "intact setup reaches exec"})
	spec.InjectFailAt = stage
	plan := RunPlan{Mode: SetupAbort, Stage: stage, Errno: syscall.EIO, Command: "printf COMMAND_RAN"}
	if jailmut.On("P-FAULT-" + stage) {
		plan = RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "attempt", Command: "printf COMMAND_RAN", Outcomes: []OpOutcome{{Stdout: "COMMAND_RAN"}}}}}
	}
	result := runJailed(t, p, spec, plan)
	p.Jailed("attempt", result)
	mutationEffect(t, "L-FAULT-"+stage, "reached-exec", plan.Mode == Execute)
	p.Finish()
}

func legPhase1Reads(t *testing.T, spec Spec) {
	p := newProof(t, "L-READS-WORK")
	var ops []ProofOp
	for i, command := range []string{"cat /etc/hostname", "id", "ls /", "echo RAN"} {
		ops = append(ops, ProofOp{Name: fmt.Sprintf("read%d", i), Command: command, Validate: func(stdout, stderr string, exit int) error {
			if exit != 0 || stderr != "" || stdout == "" {
				return fmt.Errorf("read report exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
			}
			return nil
		}})
	}
	ops[3].Validate = nil
	ops[3].Outcomes = []OpOutcome{{Stdout: "RAN\n"}}
	p.Jailed("reads", runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: ops}))
	p.Finish()
}

func legPhase1Core(t *testing.T, spec Spec) {
	p := newProof(t, "L-RL-CORE")
	var limit unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &limit))
	want := min(uint64(1), limit.Max)
	p.Control("limit", ControlResult{Valid: limit.Cur != want || limit.Max != want, Detail: fmt.Sprintf("inherited core limit %d:%d; jailed target %d", limit.Cur, limit.Max, want)})
	probe := buildProbe(t)
	soft, hard := uint64(0), uint64(0)
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "limit", Command: probe + " core-limit unused", Validate: func(stdout, stderr string, exit int) error {
		n, err := fmt.Sscanf(stdout, "core=%d:%d\n", &soft, &hard)
		if err != nil || n != 2 || stdout != fmt.Sprintf("core=%d:%d\n", soft, hard) || exit != 0 || stderr != "" {
			return fmt.Errorf("core report %q %q exit %d: %v", stdout, stderr, exit, err)
		}
		return nil
	}}}})
	p.Jailed("limit", result)
	p.Observed("limit", Observation{Conclusive: true, Sealed: true, Valid: (soft == want && hard == want) || (jailmut.On("P-RL-CORE") && soft == limit.Cur && hard == limit.Max), Detail: fmt.Sprintf("core=%d:%d", soft, hard)})
	mutationEffect(t, "L-RL-CORE", "limit", soft != want || hard != want)
	p.Finish()
}

func legPhase1Nproc(t *testing.T, spec Spec) {
	runDisposableIdentity(t, "L-RL-NPROC", []string{"limit"}, func(phase, probe string, uid uint32) {
		control := func() ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, probe, "phase1-forks", "unused").CombinedOutput()
		}
		if phase == "control" {
			out, err := control()
			if err != nil || string(out) != "children=257\nfork=ok\n" {
				t.Fatalf("SETUP: fork control: %s %v", out, err)
			}
			return
		}
		p := newProof(t, "L-RL-NPROC")
		out, err := control()
		p.Control("forks", ControlResult{Valid: err == nil && string(out) == "children=257\nfork=ok\n", Detail: fmt.Sprintf("fork control: %s %v", out, err)})
		count := 0
		result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "forks", Command: probe + " phase1-forks unused", Validate: func(stdout, stderr string, exit int) error {
			var code string
			n, err := fmt.Sscanf(stdout, "children=%d\nfork=%s\n", &count, &code)
			valid := count >= 1 && count <= 256 && code == "11" && exit == 1
			if jailmut.On("P-RL-NPROC") {
				valid = count == 257 && code == "ok" && exit == 0
			}
			if err != nil || n != 2 || !valid || stderr != "" || stdout != fmt.Sprintf("children=%d\nfork=%s\n", count, code) {
				return fmt.Errorf("fork result: %q %q exit=%d: %v", stdout, stderr, exit, err)
			}
			return nil
		}}}})
		p.Jailed("forks", result)
		p.Observed("forks", Observation{Conclusive: true, Sealed: true, Valid: count >= 1 && count <= 257, Detail: fmt.Sprintf("children=%d; probe reaped every child before returning", count)})
		mutationEffect(t, "L-RL-NPROC", "limit", count > 256)
		p.Finish()
	})
}

func legPhase1FD(t *testing.T, spec Spec) {
	p := newProof(t, "L-FDS")
	file, err := os.CreateTemp(t.TempDir(), "leak")
	mutationSetup(t, err)
	defer file.Close()
	probe := buildProbe(t)
	control := exec.Command(probe, "phase1-fd", "7")
	control.ExtraFiles = []*os.File{nil, nil, nil, nil, file}
	out, err := control.CombinedOutput()
	data, readErr := os.ReadFile(file.Name())
	p.Control("fd", ControlResult{Valid: err == nil && string(out) == "write=ok\n" && readErr == nil && string(data) == "leak", Detail: fmt.Sprintf("fd control: %q file=%q %v %v", out, data, err, readErr)})
	mutationSetup(t, file.Truncate(0))
	_, err = file.Seek(0, 0)
	mutationSetup(t, err)
	want := OpOutcome{Stdout: "write=9\n", Exit: 1}
	if jailmut.On("P-FDS") {
		want = OpOutcome{Stdout: "write=ok\n"}
	}
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "fd", Command: probe + " phase1-fd 7", Outcomes: []OpOutcome{want}}}, Configure: func(j *Jailed) { j.Cmd.ExtraFiles = append(j.Cmd.ExtraFiles, nil, nil, file) }})
	p.Jailed("fd", result)
	data, err = os.ReadFile(file.Name())
	p.Observed("fd", Observation{Conclusive: err == nil, Sealed: true, Valid: (len(data) == 0 || string(data) == "leak") && (string(data) == "leak") == (result.exit == 0), Detail: fmt.Sprintf("fd file=%q %v", data, err)})
	mutationEffect(t, "L-FDS", "inherited-write", string(data) == "leak")
	p.Finish()
}

func legPhase1Clone(t *testing.T, spec Spec, namespace string) {
	p := newProof(t, "L-CLONE-"+namespace)
	control := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}, Configure: func(j *Jailed) { j.Cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS }})
	p.Control("intact", ControlResult{Valid: control.stdout == "CONTROL_RAN", Jailed: &control, Detail: "intact namespaces reached exec"})
	before, err := os.ReadFile("/proc/self/mountinfo")
	mutationSetup(t, err)
	plan := RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "attempt", Command: "printf ran", Outcomes: []OpOutcome{{Stdout: "ran"}}}}}
	marker := ""
	if namespace == "USER" && jailmut.On("P-CLONE-USER") {
		marker = "clone"
		plan = RunPlan{Mode: LaunchFailure, Errno: syscall.EPERM, Command: "printf ran"}
		if os.Geteuid() == 0 {
			plan = RunPlan{Mode: ControlledHang, After: 5 * time.Second, Command: "printf ran", Release: func() error { killMappingWaiters(t); return nil }}
		}
	} else if namespace == "MNT" && jailmut.On("P-CLONE-MNT") {
		marker = "nsverify"
		if jailmut.On("P-NSVERIFY") {
			marker = "private"
		}
		plan = RunPlan{Mode: SetupAbort, Stage: marker, Errno: syscall.EPERM, Command: "printf ran"}
	}
	result := runJailed(t, p, spec, plan)
	p.Jailed("attempt", result)
	after, err := os.ReadFile("/proc/self/mountinfo")
	p.Observed("mounts", Observation{Conclusive: err == nil, Sealed: true, Valid: bytes.Equal(before, after), Detail: "host mountinfo unchanged after launcher completed"})
	if marker != "" {
		mutationAbort(t, "L-CLONE-"+namespace, marker, true)
	}
	p.Finish()
}

func legPhase1TTY(t *testing.T, spec Spec) {
	p := newProof(t, "L-TTY-STATE")
	probe := buildProbe(t)
	path, fd := openPty(t)
	termios, winsize := ttyState(t, fd)
	const success = "open=ok\nexclusive=ok\nget-termios=ok\ntermios=ok\nget-winsize=ok\nwinsize=ok\n"
	out, err := exec.Command(probe, "phase1-tty", path).CombinedOutput()
	mutationSetup(t, err)
	if string(out) != success {
		t.Fatalf("SETUP: tty control: %s", out)
	}
	exclusive, err := unix.IoctlGetInt(fd, unix.TIOCGEXCL)
	mutationSetup(t, err)
	afterTermios, afterWinsize := ttyState(t, fd)
	if exclusive != 1 || afterTermios.Lflag != termios.Lflag^unix.ECHO || afterWinsize.Row != winsize.Row+1 {
		t.Fatal("SETUP: tty control did not change all fields")
	}
	mutationSetup(t, unix.IoctlSetInt(fd, unix.TIOCNXCL, 0))
	mutationSetup(t, unix.IoctlSetTermios(fd, unix.TCSETS, &termios))
	mutationSetup(t, unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &winsize))
	p.Control("tty", ControlResult{Valid: exclusive == 1 && afterTermios.Lflag == termios.Lflag^unix.ECHO && afterWinsize.Row == winsize.Row+1, Detail: "outside tty control changed exclusive, termios and winsize; restored before run"})
	want := OpOutcome{Stdout: "open=13\n", Exit: 1}
	if jailmut.On("P-NODEV") && jailmut.On("P-SELFCHECK-MOUNTS") {
		abi := spec.ForceABI
		if abi == 0 {
			var errno unix.Errno
			abi, errno = probeLandlockABI()
			if errno != 0 {
				mutationSetup(t, errno)
			}
		}
		if abi >= 5 && !jailmut.On("P-LL-IOCTL-DEV") {
			want = OpOutcome{Stdout: "open=ok\nexclusive=13\nget-termios=13\n", Exit: 3}
		} else {
			want = OpOutcome{Stdout: success}
		}
	}
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "tty", Command: probe + " phase1-tty " + path, Outcomes: []OpOutcome{want}}}})
	p.Jailed("tty", result)
	exclusive, err = unix.IoctlGetInt(fd, unix.TIOCGEXCL)
	mutationSetup(t, err)
	afterTermios, afterWinsize = ttyState(t, fd)
	changed := exclusive != 0 || afterTermios != termios || afterWinsize != winsize
	if changed && (exclusive != 1 || afterTermios.Lflag != termios.Lflag^unix.ECHO || afterWinsize.Row != winsize.Row+1) {
		t.Fatal("SETUP: incomplete tty effect")
	}
	p.Observed("tty", Observation{Conclusive: true, Sealed: true, Valid: changed == (want.Stdout == success), Detail: "outside exclusive, termios and winsize read after ioctl probe completed"})
	mutationEffect(t, "L-TTY-STATE", "tty-exclusive", changed)
	p.Finish()
}

// killMappingWaiters kills this process's not-yet-execed children blocked on the
// uid_map synchronisation pipe, which releases a parent stuck in vfork.
func killMappingWaiters(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	mutationSetup(t, err)
	killed := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
		wchan, _ := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", pid))
		if len(fields) > 1 && fields[1] == strconv.Itoa(os.Getpid()) && string(wchan) == "pipe_read" {
			mutationSetup(t, unix.Kill(pid, unix.SIGKILL))
			killed++
		}
	}
	if killed != 1 {
		t.Fatalf("SETUP: expected one mapping waiter, killed %d", killed)
	}
}
