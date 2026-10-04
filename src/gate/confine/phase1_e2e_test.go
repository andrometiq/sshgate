//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
			t.Run("L-FAULT-private", func(t *testing.T) { legFault(t, spec, "private") })
			t.Run("L-FAULT-setattr", func(t *testing.T) { legFault(t, spec, "setattr") })
			t.Run("L-FAULT-devnodes", func(t *testing.T) { legFault(t, spec, "devnodes") })
			t.Run("L-FAULT-covers", func(t *testing.T) { legFault(t, spec, "covers") })
			t.Run("L-FAULT-scratch", func(t *testing.T) { legFault(t, spec, "scratch") })
			t.Run("L-CLONE-USER", func(t *testing.T) { legPhase1Clone(t, spec, "USER") })
			t.Run("L-CLONE-MNT", func(t *testing.T) { legPhase1Clone(t, spec, "MNT") })
			t.Run("L-DEV-OPEN", func(t *testing.T) {
				probe := buildProbe(t)
				pty, _ := openPty(t)
				opened := 0
				for _, path := range []string{"/dev/ptmx", pty, "/dev/fuse"} {
					control, err := exec.Command(probe, "phase1-open", path).CombinedOutput()
					mutationSetup(t, err)
					if string(control) != "open=ok\n" {
						t.Fatalf("SETUP: device open control %s: %s", path, control)
					}
					result := runP12(t, spec, probe+" phase1-open "+path, nil)
					if phase1Abort(t, "L-DEV-OPEN", result) {
						return
					}
					if result.setupErr != nil || result.stderr != "" {
						t.Fatalf("SETUP: device open: %+v", result)
					}
					switch {
					case result.exit == 0 && result.stdout == "open=ok\n":
						opened++
					case result.exit == 1 && result.stdout == "open=13\n":
					default:
						t.Fatalf("SETUP: incomplete or unexpected device open: %+v", result)
					}
				}
				if opened != 0 && opened != 3 {
					t.Fatalf("SETUP: mixed device open outcomes: %d of 3", opened)
				}
				mutationEffect(t, "L-DEV-OPEN", "opened", opened == 3)
			})
			t.Run("L-DEVNODE-WRITE", func(t *testing.T) {
				probe := buildProbe(t)
				for _, node := range []string{"null", "urandom", "full", "zero"} {
					path := "/dev/" + node
					control := exec.Command(probe, "device-write", path)
					out, err := control.Output()
					expected := "open=ok\nwrite=ok\n"
					code := 0
					if node == "full" {
						expected = "open=ok\nwrite=28\n"
						code = 3
					}
					if string(out) != expected || exitCodeOf(err) != code {
						t.Fatalf("SETUP: device control %s: %s %v", node, out, err)
					}
					result := runP12(t, spec, probe+" device-write "+path, nil)
					if result.setupErr != nil || result.stderr != "" {
						t.Fatalf("SETUP: %+v", result)
					}
					if node == "null" {
						if result.stdout == "open=13\n" && result.exit == 1 {
							mutationEffect(t, "L-DEVNODE-WRITE", "null-denied", true)
						} else if result.stdout != "open=ok\nwrite=ok\n" || result.exit != 0 {
							t.Fatalf("SETUP: null operation %+v", result)
						}
					} else if result.stdout != "open=13\n" || result.exit != 1 {
						unexpected(t, "device %s not denied: %+v", node, result)
					}
				}
			})
			t.Run("L-READS-WORK", func(t *testing.T) { legReadsWork(t, spec) })
			t.Run("L-TTY-STATE", func(t *testing.T) { legPhase1TTY(t, spec) })
			t.Run("L-SCRATCH-FILL", func(t *testing.T) {
				probe := buildProbe(t)
				out, err := exec.Command(probe, "phase1-fill", t.TempDir()+"/fill-control").CombinedOutput()
				mutationSetup(t, err)
				if string(out) != "open=ok\nfill=ok\n" {
					t.Fatalf("SETUP: fill control: %s", out)
				}
				result := runP12(t, spec, probe+" phase1-fill /dev/shm/fill", nil)
				phase1ProbeResult(t, result, []string{"open=ok"}, "fill", unix.ENOSPC)
				mutationEffect(t, "L-SCRATCH-FILL", "filled", strings.Contains(result.stdout, "fill=ok\n"))
			})
			t.Run("L-SCRATCH-PRIVATE", func(t *testing.T) {
				file, err := os.CreateTemp("/dev/shm", "sshgate-private-")
				mutationSetup(t, err)
				defer os.Remove(file.Name())
				_, err = file.WriteString("host-canary")
				mutationSetup(t, err)
				mutationSetup(t, file.Close())
				control, err := os.ReadFile(file.Name())
				mutationSetup(t, err)
				if string(control) != "host-canary" {
					t.Fatal("SETUP: scratch control unreadable")
				}
				result := runP12(t, spec, "test ! -e "+file.Name()+" && printf private > "+file.Name(), nil)
				phase1Success(t, result)
				after, err := os.ReadFile(file.Name())
				mutationSetup(t, err)
				if string(after) != "host-canary" {
					unexpected(t, "host scratch canary changed")
					t.FailNow()
				}
			})
			t.Run("L-SCRATCH-NOEXEC", func(t *testing.T) {
				result := runP12(t, spec, "cp /bin/true /dev/shm/execute && /dev/shm/execute", nil)
				if phase1Abort(t, "L-SCRATCH-NOEXEC", result) {
					return
				}
				if result.exit != 0 && (result.exit != 126 || !strings.Contains(result.stderr, "Permission denied")) {
					t.Fatalf("SETUP: %+v", result)
				}
				mutationEffect(t, "L-SCRATCH-NOEXEC", "executed", result.exit == 0)
			})
			t.Run("L-RL-FSIZE", func(t *testing.T) {
				probe := buildProbe(t)
				dir := t.TempDir()
				control := exec.Command(probe, "phase1-fsize", dir+"/control")
				out, err := control.CombinedOutput()
				mutationSetup(t, err)
				if string(out) != "open=ok\nseek=ok\nwrite=ok\n" {
					t.Fatalf("SETUP: fsize control: %s", out)
				}
				result := runP12(t, spec, probe+" phase1-fsize /dev/shm/fsize", nil)
				phase1ProbeResult(t, result, []string{"open=ok", "seek=ok"}, "write", unix.EFBIG)
				mutationEffect(t, "L-RL-FSIZE", "limit", strings.Contains(result.stdout, "write=ok\n"))
			})
			t.Run("L-RL-CORE", func(t *testing.T) { legPhase1Core(t, spec) })
			if (os.Getenv("SSHGATE_JAIL_CI") == "1" && os.Getuid() == 0) || os.Getenv("SSHGATE_TEST_USER_RETUNE_PHASE") != "" {
				t.Run("L-RL-NPROC", func(t *testing.T) { legPhase1Nproc(t, spec) })
			} else {
				t.Log("MUTATE-OMITTED(root/ci-only): L-RL-NPROC")
			}
			t.Run("L-FDS", func(t *testing.T) { legPhase1FD(t, spec) })
		})
	}
}

func phase1Success(t *testing.T, result jailResult) {
	t.Helper()
	if result.setupErr != nil || result.exit != 0 || result.stderr != "" {
		t.Fatalf("SETUP: %+v", result)
	}
}
func phase1Abort(t *testing.T, leg string, result jailResult) bool {
	t.Helper()
	if result.setupErr == nil {
		return false
	}
	var setup *SetupError
	if !errors.As(result.setupErr, &setup) || setup.Stage != "selfcheck" || setup.Errno != 0 || result.exit != ExitSetupFailed || result.stdout != "" {
		t.Fatalf("SETUP: %+v", result)
	}
	mutationAbort(t, leg, "selfcheck", true)
	return true
}
func phase1ProbeResult(t *testing.T, result jailResult, prefix []string, op string, denied unix.Errno) {
	t.Helper()
	if result.setupErr != nil || result.stderr != "" {
		t.Fatalf("SETUP: %+v", result)
	}
	expected := strings.Join(prefix, "\n") + "\n" + op + "="
	switch result.stdout {
	case expected + "ok\n":
		if result.exit != 0 {
			t.Fatalf("SETUP: success output with exit %d", result.exit)
		}
	case expected + strconv.Itoa(int(denied)) + "\n":
		if result.exit != 3 {
			t.Fatalf("SETUP: denied output with exit %d", result.exit)
		}
	default:
		t.Fatalf("SETUP: incomplete or unexpected probe: %+v", result)
	}
}
func legPhase1Core(t *testing.T, spec Spec) {
	var limit unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &limit))
	want := min(uint64(1), limit.Max)
	if limit.Cur == want && limit.Max == want {
		t.Fatal("SETUP: inherited core limits already equal jail limits")
	}
	probe := buildProbe(t)
	result := runP12(t, spec, probe+" core-limit unused", nil)
	phase1Success(t, result)
	var soft, hard uint64
	n, err := fmt.Sscanf(result.stdout, "core=%d:%d\n", &soft, &hard)
	if err != nil || n != 2 {
		t.Fatalf("SETUP: malformed core limits: %+v", result)
	}
	mutationEffect(t, "L-RL-CORE", "limit", soft != want || hard != want)
}
func legPhase1Nproc(t *testing.T, spec Spec) {
	runDisposableIdentity(t, "L-RL-NPROC", []string{"limit"}, func(phase, probe string, uid uint32) {
		if phase == "control" {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, probe, "phase1-forks", "unused").CombinedOutput()
			mutationSetup(t, err)
			if string(out) != "children=257\nfork=ok\n" {
				t.Fatalf("SETUP: fork control: %s", out)
			}
			return
		}
		result := runP12(t, spec, probe+" phase1-forks unused", nil)
		if result.setupErr != nil || result.stderr != "" {
			t.Fatalf("SETUP: %+v", result)
		}
		var count int
		var code string
		n, err := fmt.Sscanf(result.stdout, "children=%d\nfork=%s\n", &count, &code)
		expectedExit := 1
		if code == "ok" {
			expectedExit = 0
		}
		if err != nil || n != 2 || count < 1 || count > 257 || (code != "ok" && code != "11") || result.exit != expectedExit {
			t.Fatalf("SETUP: fork result: %+v", result)
		}
		mutationEffect(t, "L-RL-NPROC", "limit", count > 256)
	})
}

func legPhase1FD(t *testing.T, spec Spec) {
	file, err := os.CreateTemp(t.TempDir(), "leak")
	mutationSetup(t, err)
	defer file.Close()
	probe := buildProbe(t)
	control := exec.Command(probe, "phase1-fd", "7")
	control.ExtraFiles = []*os.File{nil, nil, nil, nil, file}
	out, err := control.CombinedOutput()
	mutationSetup(t, err)
	if string(out) != "write=ok\n" {
		t.Fatalf("SETUP: inherited fd control: %s", out)
	}
	mutationSetup(t, file.Truncate(0))
	_, err = file.Seek(0, 0)
	mutationSetup(t, err)
	result := runP12(t, spec, probe+" phase1-fd 7", func(j *Jailed) {
		j.Cmd.ExtraFiles = append(j.Cmd.ExtraFiles, nil, nil, file)
	})
	if result.setupErr != nil || result.stderr != "" {
		t.Fatalf("SETUP: %+v", result)
	}
	if !((result.stdout == "write=9\n" && result.exit == 1) || (result.stdout == "write=ok\n" && result.exit == 0)) {
		t.Fatalf("SETUP: inherited fd probe: %+v", result)
	}
	data, err := os.ReadFile(file.Name())
	mutationSetup(t, err)
	if (len(data) != 0 && string(data) != "leak") || (string(data) == "leak") != (result.exit == 0) {
		t.Fatalf("SETUP: inherited fd observation %q %+v", data, result)
	}
	mutationEffect(t, "L-FDS", "inherited-write", string(data) == "leak")
}

func legPhase1Clone(t *testing.T, spec Spec, namespace string) {
	control := runP12(t, spec, "printf CONTROL_RAN", func(j *Jailed) {
		j.Cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS
	})
	phase1Success(t, control)
	if control.stdout != "CONTROL_RAN" {
		t.Fatalf("SETUP: intact namespace control did not execute: %+v", control)
	}
	before, err := os.ReadFile("/proc/self/mountinfo")
	mutationSetup(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	jailed, err := spec.Command(ctx, "printf ran")
	mutationSetup(t, err)
	defer jailed.Abort()
	var stdout, stderr bytes.Buffer
	jailed.Cmd.Stdout = &stdout
	jailed.Cmd.Stderr = &stderr
	started := make(chan error, 1)
	go func() { started <- jailed.Cmd.Start() }()
	select {
	case err = <-started:
	case <-time.After(5 * time.Second):
		// Without CLONE_NEWUSER, Go launches with vfork yet still makes the child wait
		// for the parent's uid_map write, so a root launcher deadlocks in clone
		// (syscall/exec_linux.go). Non-root never gets here: clone(CLONE_NEWNS) is EPERM.
		if namespace != "USER" || os.Geteuid() != 0 {
			t.Fatal("SETUP: clone start hung")
		}
		killMappingWaiters(t)
		select {
		case err = <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("SETUP: hung clone was not released")
		}
		if err == nil {
			_ = jailed.Cmd.Wait()
		}
		if stdout.Len() != 0 {
			t.Fatalf("SETUP: hung clone ran the command: %s", stdout.String())
		}
		mutationAbort(t, "L-CLONE-USER", "clone", true)
		return
	}
	if err != nil {
		if namespace != "USER" || !errors.Is(err, syscall.EPERM) {
			t.Fatalf("SETUP: clone start %v", err)
		}
		mutationAbort(t, "L-CLONE-USER", "clone", true)
		return
	}
	_ = jailed.Started()
	_ = jailed.Cmd.Wait()
	_, setupErr := jailed.Status()
	after, err := os.ReadFile("/proc/self/mountinfo")
	mutationSetup(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("SETUP: host mounts changed")
	}
	if setupErr == nil {
		if stdout.String() != "ran" {
			t.Fatalf("SETUP: missing command output: %s", stderr.String())
		}
		return
	}
	var setup *SetupError
	if !errors.As(setupErr, &setup) || stdout.Len() != 0 || setup.Errno != unix.EPERM || (setup.Stage != "nsverify" && setup.Stage != "private") {
		t.Fatalf("SETUP: %v", setupErr)
	}
	mutationAbort(t, "L-CLONE-"+namespace, setup.Stage, true)
}
func legPhase1TTY(t *testing.T, spec Spec) {
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
	result := runP12(t, spec, probe+" phase1-tty "+path, nil)
	if result.setupErr != nil || result.stderr != "" {
		t.Fatalf("SETUP: %+v", result)
	}
	switch result.stdout {
	case "open=13\n":
		if result.exit != 1 {
			t.Fatalf("SETUP: %+v", result)
		}
	// Landlock IOCTL_DEV (ABI >= 5) denies every device ioctl, TCGETS included.
	case "open=ok\nexclusive=13\nget-termios=13\n",
		"open=ok\nexclusive=13\nget-termios=ok\ntermios=13\nget-winsize=ok\nwinsize=13\n":
		if result.exit != 3 {
			t.Fatalf("SETUP: %+v", result)
		}
	case success:
		if result.exit != 0 {
			t.Fatalf("SETUP: %+v", result)
		}
	default:
		t.Fatalf("SETUP: incomplete or unexpected tty probe: %+v", result)
	}
	exclusive, err = unix.IoctlGetInt(fd, unix.TIOCGEXCL)
	mutationSetup(t, err)
	afterTermios, afterWinsize = ttyState(t, fd)
	changed := exclusive != 0 || afterTermios != termios || afterWinsize != winsize
	if changed && (exclusive != 1 || afterTermios.Lflag != termios.Lflag^unix.ECHO || afterWinsize.Row != winsize.Row+1) {
		t.Fatal("SETUP: incomplete tty effect")
	}
	mutationEffect(t, "L-TTY-STATE", "tty-exclusive", changed)
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
