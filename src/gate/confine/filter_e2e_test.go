//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestJailMatrixP15(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, Net: true, ForceABI: cfg.abi}
			t.Run("L-FCNTL-PIPESZ", func(t *testing.T) { legPipeSize(t, spec) })
			t.Run("L-FCNTL-RWHINT", func(t *testing.T) { legRWHint(t, spec) })
			t.Run("L-FLOCK-EX", func(t *testing.T) { legFlock(t, spec) })
			t.Run("L-CRASH-NO-HELPER", func(t *testing.T) { legCrashNoHelper(t, spec) })
			t.Run("L-CRASH-LOWER-PIPE", func(t *testing.T) { legCrashLowerPipe(t, spec) })
			t.Run("L-RLIMIT-CORE-LOCK", func(t *testing.T) { legCoreLock(t, spec) })
			t.Run("L-SC-SYNC-ERRNO", func(t *testing.T) { legSyncErrno(t, spec, false) })
			t.Run("L-SC-SYNCFS-ERRNO", func(t *testing.T) { legSyncErrno(t, spec, true) })
			t.Run("L-LISTEN", func(t *testing.T) { legListen(t, spec) })
			t.Run("L-INET-DENY", func(t *testing.T) { legInet(t, spec, false) })
			t.Run("L-INET-GRANT", func(t *testing.T) { legInet(t, spec, true) })
			t.Run("L-SOCK-SWEEP", func(t *testing.T) { legSocketSweep(t, spec, false) })
			t.Run("L-SOCK-SWEEP-GRANT", func(t *testing.T) { legSocketSweep(t, spec, true) })
			t.Run("L-SS-FALLBACK", func(t *testing.T) { legSSFallback(t, spec) })
			t.Run("L-SOCKDIAG", func(t *testing.T) { legSockdiag(t, spec) })
			t.Run("L-SOCKDIAG-AUTOLOAD", func(t *testing.T) { legSockdiagModule(t, spec) })
			t.Run("L-SOCKPAIR-SWEEP", func(t *testing.T) { legSocketpair(t, spec) })
			t.Run("L-NS-CREATE", func(t *testing.T) { legNamespaceCalls(t, spec) })
			t.Run("L-KEYRING", func(t *testing.T) { legKeyring(t, spec) })
			t.Run("L-IOURING", func(t *testing.T) { legIOUring(t, spec) })
			t.Run("L-SIGNAL", func(t *testing.T) { legSignal(t, spec) })
			t.Run("L-IPC-SYSV", func(t *testing.T) { legSysV(t, spec) })
			t.Run("L-SCHED", func(t *testing.T) { legScheduler(t, spec) })
			t.Run("L-UNIX-CONNECT", func(t *testing.T) { legUnixConnect(t, spec, false) })
			t.Run("L-UNIX-ABSTRACT", func(t *testing.T) { legUnixConnect(t, spec, true) })
			t.Run("L-IOCTL", func(t *testing.T) { legIoctlFilter(t, spec) })
			t.Run("L-META-ERRNO", func(t *testing.T) { legMetadataErrno(t, spec) })
			t.Run("L-DGRAM-SEND", func(t *testing.T) { legDatagram(t, spec, false) })
			t.Run("L-DGRAM-ABSTRACT", func(t *testing.T) { legDatagram(t, spec, true) })
			t.Run("L-SC-CEILING", func(t *testing.T) { legCeiling(t, spec) })
		})
	}
}

func filterFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(homeDir(t), ".sshgate-filter-")
	mutationSetup(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

type probeExitMode int

const (
	probeExitMixed probeExitMode = iota
	probeExitAnyFailure
	probeExitObservations
)

func requireProbeOutput(t *testing.T, result jailResult, expected ...string) string {
	t.Helper()
	return requireProbeOutputMode(t, result, probeExitMixed, expected...)
}

func requireProbeOutputMode(t *testing.T, result jailResult, mode probeExitMode, expected ...string) string {
	t.Helper()
	if err := validateProbeOutput(result, expected, mode); err != nil {
		t.Fatalf("SETUP: probe: %v: %+v", err, result)
	}
	return result.stdout
}

// A predecessor>field contract requires field only after predecessor succeeds.
// Repeating a field declares the exact number of reports for a syscall sweep.
func validateProbeOutput(result jailResult, expected []string, mode probeExitMode) error {
	if result.setupErr != nil || result.exit != 0 && result.exit != 1 && result.exit != 3 {
		return fmt.Errorf("abnormal probe termination")
	}
	if result.stderr != "" || result.stdout == "" || !strings.HasSuffix(result.stdout, "\n") || len(expected) == 0 {
		return fmt.Errorf("diagnostic, empty, unterminated or undeclared probe output")
	}
	counts := make(map[string]int)
	success := make(map[string]bool)
	succeeded, failed := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(result.stdout, "\n"), "\n") {
		field, value, found := strings.Cut(line, "=")
		if !found || field == "" || value == "" {
			return fmt.Errorf("malformed operation line %q", line)
		}
		switch field {
		case "size", "before", "after", "state", "session", "attempts", "target", "bytes", "uring-complete":
			// These fields carry observations rather than syscall results.
		default:
			if value != "ok" {
				errno, err := strconv.Atoi(value)
				if err != nil || errno < 0 || errno > 4095 || (errno == 0 && mode != probeExitObservations) {
					return fmt.Errorf("malformed syscall result %q", line)
				}
				if errno != 0 {
					failed++
				} else {
					succeeded++
				}
			} else {
				succeeded++
			}
		}
		counts[field]++
		success[field] = success[field] || value == "ok"
	}
	want := make(map[string]int)
	for _, field := range expected {
		if predecessor, next, conditional := strings.Cut(field, ">"); conditional {
			if !success[predecessor] {
				continue
			}
			field = next
		}
		want[field]++
	}
	for field, count := range want {
		if counts[field] != count {
			return fmt.Errorf("operation %s: got %d reports, want %d", field, counts[field], count)
		}
	}
	wantExit := 0
	if mode != probeExitObservations && failed > 0 {
		wantExit = 1
		if mode == probeExitMixed && succeeded > 0 {
			wantExit = 3
		}
	}
	if result.exit != wantExit {
		return fmt.Errorf("exit %d disagrees with operation reports (want %d)", result.exit, wantExit)
	}
	return nil
}

func TestProbeOutputContract(t *testing.T) {
	for _, tc := range []struct {
		name      string
		result    jailResult
		wantError bool
	}{
		{"denied", jailResult{exit: 3, stdout: "open=ok\nioctl=1\n"}, false},
		{"allowed", jailResult{stdout: "open=ok\nioctl=ok\n"}, false},
		{"failed-after-success", jailResult{exit: 1, stdout: "open=ok\nioctl=ok\n"}, true},
		{"wrong-mixed-exit", jailResult{exit: 1, stdout: "open=ok\nioctl=1\n"}, true},
		{"zero-after-denial", jailResult{stdout: "open=ok\nioctl=1\n"}, true},
		{"crashed", jailResult{exit: 139, stdout: "open=ok\n"}, true},
		{"signal", jailResult{exit: -1, stdout: "open=ok\nioctl=1\n"}, true},
		{"partial", jailResult{exit: 1, stdout: "open=ok\n"}, true},
		{"duplicate", jailResult{exit: 3, stdout: "open=ok\nioctl=1\nioctl=1\n"}, true},
		{"stderr", jailResult{exit: 3, stdout: "open=ok\nioctl=1\n", stderr: "panic: failed\n"}, true},
		{"malformed-zero", jailResult{exit: 3, stdout: "open=ok\nioctl=0\n"}, true},
		{"malformed-errno", jailResult{exit: 3, stdout: "open=ok\nioctl=garbage\n"}, true},
		{"unterminated", jailResult{exit: 3, stdout: "open=ok\nioctl=1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateProbeOutput(tc.result, []string{"open", "ioctl"}, probeExitMixed); (err != nil) != tc.wantError {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func legPipeSize(t *testing.T, spec Spec) {
	p := newProof(t, "L-FCNTL-PIPESZ")
	var runs []JailedResult

	probe := buildProbe(t)
	r, w, err := os.Pipe()
	mutationSetup(t, err)
	defer r.Close()
	defer w.Close()
	before, err := unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	mutationSetup(t, err)
	// Shrinking avoids CAP_SYS_RESOURCE and per-user enlargement limits.
	target := before / 2
	if target < os.Getpagesize() {
		t.Fatal("SETUP: pipe has no shrinkable capacity")
	}
	control := exec.Command(probe, "pipesz", strconv.Itoa(target))
	control.Stdin = r
	out, err := m1ControlOutput(t, control)
	mutationSetup(t, err)
	changed, err := unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	mutationSetup(t, err)
	if changed == before || !strings.Contains(string(out), "pipesz=ok") {
		t.Fatal("SETUP: control pipe size unchanged")
	}
	// A fresh pipe restores the fixture without requiring enlargement privilege.
	r.Close()
	w.Close()
	r, w, err = os.Pipe()
	mutationSetup(t, err)
	defer r.Close()
	defer w.Close()
	before, err = unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	mutationSetup(t, err)
	result := runM1Filter(t, p, &runs, spec, probe+" pipesz "+strconv.Itoa(target), func(j *Jailed) { j.Cmd.Stdin = r })
	output := requireProbeOutput(t, result, "pipesz", "size")
	after, err := unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	mutationSetup(t, err)
	mutationEffect(t, "L-FCNTL-PIPESZ", "pipe-size", after != before)
	mutationEffect(t, "L-FCNTL-PIPESZ", "errno", !strings.Contains(output, "pipesz=1\n"))
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func fileHint(t *testing.T, fd int, set bool, value uint64) uint64 {
	t.Helper()
	command := uintptr(unix.F_GET_RW_HINT)
	if set {
		command = unix.F_SET_RW_HINT
	}
	_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), command, uintptr(unsafe.Pointer(&value)))
	if e != 0 {
		t.Fatalf("SETUP: file hint: %v", e)
	}
	return value
}
func legRWHint(t *testing.T, spec Spec) {
	p := newProof(t, "L-FCNTL-RWHINT")
	var runs []JailedResult

	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "owned")
	mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	fileHint(t, fd, true, 0)
	out, err := m1ControlOutput(t, exec.Command(probe, "rwhint", path))
	mutationSetup(t, err)
	if fileHint(t, fd, false, 0) != 4 {
		t.Fatalf("SETUP: owned-file control did not persist hint: %s", out)
	}
	fileHint(t, fd, true, 0)
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" rwhint "+path, nil), "open", "rwhint")
	mutationEffect(t, "L-FCNTL-RWHINT", "hint", fileHint(t, fd, false, 0) != 0)
	mutationEffect(t, "L-FCNTL-RWHINT", "errno", !strings.Contains(output, "rwhint=1\n"))
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func legFlock(t *testing.T, spec Spec) {
	p := newProof(t, "L-FLOCK-EX")
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "lock")
	mutationSetup(t, os.WriteFile(path, nil, 0600))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	outside := func() error {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			mutationSetup(t, unix.Flock(fd, unix.LOCK_UN))
		}
		if err != nil && err != unix.EAGAIN {
			t.Fatalf("SETUP: outside flock: %v", err)
		}
		return err
	}
	holder := startM1Holder(t, probe, "flock-hold", path)
	excluded := outside() == unix.EAGAIN
	control := holder.finish(t)
	mutationSetup(t, validateM1Flock(control.stdout, control.stderr, control.exit))
	p.Control("fixture", ControlResult{Valid: excluded && control.exit == 0, Detail: "unjailed holder must exclude outside lock and finish cleanly"})
	var lockErr error
	result := runJailed(t, p, spec, RunPlan{Mode: Interactive, ReadyPoint: "probe", AfterReady: func() { lockErr = outside() }, Ops: []ProofOp{{Name: "holder", Command: probe + " flock-hold " + path, Validate: validateM1Flock}}})
	p.Jailed("probe", result)
	mutationEffect(t, "L-FLOCK-EX", "exclusive-lock", lockErr != nil)
	mutationEffect(t, "L-FLOCK-EX", "errno", !strings.Contains(result.stdout, "flock=1\n"))
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true, Detail: "holder released and framed completion validated after outside lock attempt"})
	p.Finish()
}

func legCoreLock(t *testing.T, spec Spec) {
	p := newProof(t, "L-RLIMIT-CORE-LOCK")
	var runs []JailedResult

	probe := buildProbe(t)
	var inherited unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &inherited))
	want := min(uint64(1), inherited.Max)
	control, err := m1ControlOutput(t, exec.Command(probe, "rlimit-lock", "unused"))
	mutationSetup(t, err)
	if !strings.Contains(string(control), "setrlimit=ok") || !strings.Contains(string(control), "prlimit64=ok") {
		t.Fatalf("SETUP: limit control: %s", control)
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" rlimit-lock unused", nil), "getrlimit", "before", "setrlimit", "prlimit64", "getrlimit-after", "after")
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "errno", !strings.Contains(output, "setrlimit=1\n") || !strings.Contains(output, "prlimit64=1\n"))
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "limit", !strings.Contains(output, fmt.Sprintf("after=%d:%d\n", want, want)))
	// Shell and util-linux exercise the real callers in addition to raw syscall probes.
	for _, args := range [][]string{{"/bin/sh", "-c", "ulimit -Sc 0"}, {"prlimit", "--core=0:"}} {
		control, err := m1ControlOutput(t, exec.Command(args[0], args[1:]...))
		if err != nil {
			t.Fatalf("SETUP: core caller control %v: %s", err, control)
		}
	}
	shell := runM1Filter(t, p, &runs, spec, "ulimit -Sc 0", nil)
	if shell.setupErr != nil {
		t.Fatalf("SETUP: shell %v", shell.setupErr)
	}
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "shell", shell.exit == 0)
	if shell.exit != 0 && !strings.Contains(strings.ToLower(shell.stderr), "operation not permitted") {
		unexpected(t, "shell core-limit errno: %+v", shell)
	}
	command := runM1Filter(t, p, &runs, spec, "prlimit --core=0:", nil)
	if command.setupErr != nil {
		t.Fatalf("SETUP: prlimit %v", command.setupErr)
	}
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "prlimit", command.exit == 0)
	if command.exit != 0 && !strings.Contains(strings.ToLower(command.stderr), "operation not permitted") {
		unexpected(t, "prlimit core-limit errno: %+v", command)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func legSyncErrno(t *testing.T, spec Spec, syncfs bool) {
	probe := buildProbe(t)
	args := []string{"raw", "162"}
	name, field := "L-SC-SYNC-ERRNO", "raw"
	if syncfs {
		args = []string{"syncfs", filterFixture(t)}
		name, field = "L-SC-SYNCFS-ERRNO", "syncfs"
	}
	p := newProof(t, name)
	var runs []JailedResult

	control, err := m1ControlOutput(t, exec.Command(probe, args...))
	mutationSetup(t, err)
	if !strings.Contains(string(control), field+"=ok\n") {
		t.Fatalf("SETUP: sync control: %s", control)
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" "+strings.Join(args, " "), nil), field)
	mutationEffect(t, name, "errno", !strings.Contains(output, field+"=1\n"))
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Finish()
}
func legListen(t *testing.T, spec Spec) {
	p := newProof(t, "L-LISTEN")
	var runs []JailedResult

	probe := buildProbe(t)
	control, err := m1ControlOutput(t, exec.Command(probe, "listen", "unused"))
	mutationSetup(t, err)
	if !strings.Contains(string(control), "listen=ok") {
		t.Fatalf("SETUP: listen control %s", control)
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" listen unused", nil), "socket", "socket>listen")
	mutationEffect(t, "L-LISTEN", "errno", !strings.Contains(output, "listen=1\n"))
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Finish()
}
func legSockdiag(t *testing.T, spec Spec) {
	p := newProof(t, "L-SOCKDIAG")
	var runs []JailedResult
	probe := buildProbe(t)
	control, err := m1ControlOutput(t, exec.Command(probe, "socket-tuple", "16", "3", "4"))
	mutationSetup(t, err)
	p.Control("fixture", ControlResult{Valid: string(control) == "socket=ok\n", Detail: string(control)})
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" socket-tuple 16 3 4", nil), "socket")
	mutationEffect(t, "L-SOCKDIAG", "errno", output != "socket=1\n")
	p.Jailed("probe", runs...)
	p.Finish()
}

func legSocketpair(t *testing.T, spec Spec) {
	p := newProof(t, "L-SOCKPAIR-SWEEP")
	var runs []JailedResult

	probe := buildProbe(t)
	for _, kind := range []int{1, 2, 5} {
		args := fmt.Sprintf(" socketpair-tuple 1 %d", kind)
		control, err := m1ControlOutput(t, exec.Command(probe, "socketpair-tuple", "1", strconv.Itoa(kind)))
		mutationSetup(t, err)
		if !strings.Contains(string(control), "socketpair=ok") {
			t.Fatal("SETUP: socketpair control")
		}
		output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+args, nil), "socketpair")
		want := "socketpair=ok\n"
		if kind == 2 {
			want = "socketpair=1\n"
		}
		mutationEffect(t, "L-SOCKPAIR-SWEEP", "errno", !strings.Contains(output, want))
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Finish()
}
func legNamespaceCalls(t *testing.T, spec Spec) {
	p := newProof(t, "L-NS-CREATE")
	var runs []JailedResult

	probe := buildProbe(t)
	cloneAllowed, unshareAllowed := false, false
	for _, item := range []struct {
		flags  uint64
		option string
	}{{0x10000000, "-U"}, {0x20000, "-m"}, {0x40000000, "-n"}, {0x20000000, "-p"}, {0x8000000, "-i"}} {
		control, err := m1ControlOutput(t, exec.Command("unshare", "-Ur", "--", "unshare", item.option, "--", "/bin/true"))
		if err != nil {
			t.Fatalf("SETUP: unshare %s control: %v: %s", item.option, err, control)
		}
		result := runM1Filter(t, p, &runs, spec, "unshare "+item.option+" -- /bin/true", nil)
		if result.setupErr != nil {
			t.Fatalf("SETUP: unshare jail: %v", result.setupErr)
		}
		if result.exit == 0 {
			unshareAllowed = true
		} else if !strings.Contains(result.stderr, "Operation not permitted") {
			unexpected(t, "unshare %s not EPERM: %+v", item.option, result)
		}
		control, err = m1ControlOutput(t, exec.Command("unshare", "-Ur", "--", probe, "clone-ns", fmt.Sprint(item.flags)))
		if err != nil || !strings.Contains(string(control), "clone=ok\n") {
			t.Fatalf("SETUP: clone %#x control: %v: %s", item.flags, err, control)
		}
		output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, fmt.Sprintf("%s clone-ns %d", probe, item.flags), nil), "clone", "clone>wait")
		if strings.Contains(output, "clone=ok\n") {
			cloneAllowed = true
		} else if !strings.Contains(output, "clone=1\n") {
			unexpected(t, "clone %#x not EPERM: %s", item.flags, output)
		}
	}
	control, err := m1ControlOutput(t, exec.Command("unshare", "-Urn", "--", probe, "setns", "unused"))
	if err != nil || !strings.Contains(string(control), "setns=ok\n") {
		t.Fatalf("SETUP: setns control: %v: %s", err, control)
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" setns unused", nil), "open", "setns")
	if !strings.Contains(output, "setns=1\n") {
		unexpected(t, "setns(0) not EPERM: %s", output)
	}
	mutationEffect(t, "L-NS-CREATE", "clone", cloneAllowed)
	mutationEffect(t, "L-NS-CREATE", "unshare", unshareAllowed)
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Finish()
}
func legCeiling(t *testing.T, spec Spec) {
	p := newProof(t, "L-SC-CEILING")
	var runs []JailedResult

	control := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "echo CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN\n"}}}}})
	runs = append(runs, control)
	probe := buildProbe(t)
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" raw 472", nil), "raw")
	if !strings.Contains(output, "raw=38\n") {
		unexpected(t, "unknown syscall not ENOSYS: %s", output)
	}
	result := runJailed(t, p, spec, RunPlan{Mode: ExpectedSignal, Command: "exec " + probe + " x32-signal unused", Signal: syscall.SIGSYS, Validate: func(stdout, stderr string, exit int) error {
		if stdout != "x32-ready\n" || stderr != "" || exit != 128+int(syscall.SIGSYS) {
			return fmt.Errorf("x32 probe did not die cleanly of SIGSYS")
		}
		return nil
	}})
	runs = append(runs, result)

	p.Jailed("probe", runs...)
	p.Finish()
}

func legDatagram(t *testing.T, spec Spec, abstract bool) {
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "dgram")
	name := "L-DGRAM-SEND"
	if abstract {
		path = "@sshgate-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		name = "L-DGRAM-ABSTRACT"
	}
	p := newProof(t, name)
	var runs []JailedResult

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	mutationSetup(t, unix.Bind(fd, &unix.SockaddrUnix{Name: path}))
	control, err := m1ControlOutput(t, exec.Command(probe, "dgram-send", path))
	mutationSetup(t, err)
	var data [64]byte
	n, _, err := unix.Recvfrom(fd, data[:], 0)
	mutationSetup(t, err)
	if string(data[:n]) != "canary" {
		t.Fatalf("SETUP: no unjailed datagram: %s", control)
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" dgram-send "+path, nil), "socketpair", "socketpair>sendto")
	n, _, err = unix.Recvfrom(fd, data[:], 0)
	if err != nil && err != unix.EAGAIN {
		t.Fatalf("SETUP: receiver %v", err)
	}
	mutationEffect(t, name, "delivered", err == nil && n > 0)
	if !strings.Contains(output, "socketpair=1\n") && !strings.Contains(output, "sendto=13\n") && !strings.Contains(output, "sendto=1\n") && !strings.Contains(output, "sendto=ok\n") {
		unexpected(t, "unexpected datagram errno: %s", output)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func legSignal(t *testing.T, spec Spec) {
	p := newProof(t, "L-SIGNAL")
	var runs []JailedResult
	probe := buildProbe(t)
	control := startM1SignalRecipient(t)
	out, err := m1ControlOutput(t, exec.Command(probe, "signal", strconv.Itoa(control.command.Process.Pid)))
	mutationSetup(t, err)
	controlResult := control.finish(t)
	p.Control("fixture", ControlResult{Valid: string(out) == "kill=ok\n" && controlResult.exit == 0 && controlResult.stderr == "" && controlResult.stdout == "READY\nsignal=1\n", Detail: "recipient must acknowledge SIGUSR1 after producer completion"})
	target := startM1SignalRecipient(t)
	observer := &m1RecipientObserver{holder: target, t: t}
	p.ObserveWith("recipient", observer)
	mark := observer.Mark()
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" signal "+strconv.Itoa(target.command.Process.Pid), nil), "kill")
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	mutationEffect(t, "L-SIGNAL", "signal", records.Records[0] == "signal=1")
	if output != "kill=3\n" && output != "kill=1\n" && output != "kill=ok\n" {
		unexpected(t, "signal errno: %s", output)
	}
	p.Jailed("probe", runs...)
	p.Observed("effects", Observation{Valid: records.Err == nil, Sealed: records.Sealed, Conclusive: records.Conclusive})
	p.Finish()
}

func legSysV(t *testing.T, spec Spec) {
	p := newProof(t, "L-IPC-SYSV")
	var runs []JailedResult

	probe := buildProbe(t)
	control := m1ShmCreate(t)
	out, err := m1ControlOutput(t, exec.Command(probe, "shm-rmid", strconv.Itoa(control)))
	mutationSetup(t, err)
	if m1ShmExists(t, control) {
		m1ShmRemove(t, control)
		t.Fatalf("SETUP: SysV control: %s", out)
	}
	id := m1ShmCreate(t)
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" shm-rmid "+strconv.Itoa(id), nil), "shmctl")
	mutationEffect(t, "L-IPC-SYSV", "removed", !m1ShmExists(t, id))
	if !strings.Contains(output, "shmctl=22\n") && !strings.Contains(output, "shmctl=ok\n") {
		unexpected(t, "SysV errno: %s", output)
	}
	m1ShmRemove(t, id)
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()

}

type schedulerState struct {
	nice       int
	io, policy uintptr
	nofile     uint64
	affinity   unix.CPUSet
}

func readScheduler(t *testing.T, pid int) schedulerState {
	t.Helper()
	var result schedulerState
	var err error
	result.nice, err = unix.Getpriority(unix.PRIO_PROCESS, pid)
	mutationSetup(t, err)
	var errno unix.Errno
	result.io, _, errno = unix.Syscall(unix.SYS_IOPRIO_GET, 1, uintptr(pid), 0)
	if errno != 0 {
		t.Fatalf("SETUP: ioprio_get %v", errno)
	}
	result.policy, _, errno = unix.Syscall(unix.SYS_SCHED_GETSCHEDULER, uintptr(pid), 0, 0)
	if errno != 0 {
		t.Fatalf("SETUP: sched_getscheduler %v", errno)
	}
	result.nofile = readNofile(t, pid)
	mutationSetup(t, unix.SchedGetaffinity(pid, &result.affinity))
	return result
}
func legScheduler(t *testing.T, spec Spec) {
	p := newProof(t, "L-SCHED")
	var runs []JailedResult

	probe := buildProbe(t)
	var affinity unix.CPUSet
	mutationSetup(t, unix.SchedGetaffinity(0, &affinity))
	cpu := 0
	for !affinity.IsSet(cpu) {
		cpu++
	}
	callers := func(pid string) string {
		return fmt.Sprintf("renice -n 19 -p %s && ionice -c3 -p %s && chrt -b -p 0 %s && taskset -pc %d %s && prlimit --nofile=7:7 --pid %s", pid, pid, pid, cpu, pid, pid)
	}
	self := runM1Filter(t, p, &runs, spec, "nice -n 19 ionice -c3 chrt -b 0 taskset -c "+strconv.Itoa(cpu)+" prlimit --nofile=7:7 "+probe+" scheduler-state 0", nil)
	if self.setupErr != nil || self.exit != 0 || !strings.Contains(self.stdout, "state=19:24576:3:7:1\n") {
		t.Fatalf("SETUP: self retune effect control: %+v", self)
	}
	victim := startM1Holder(t, "/bin/sh", "-c", "printf 'READY\\n'; read release; printf 'DONE\\n'")
	pid := victim.command.Process.Pid
	before := readScheduler(t, pid)
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" scheduler "+strconv.Itoa(pid), nil), "prlimit", "nice", "ioprio", "policy", "affinity", "schedattr", "state")
	for _, caller := range strings.Split(callers(strconv.Itoa(pid)), " && ") {
		result := runM1Filter(t, p, &runs, spec, caller, nil)
		if result.setupErr != nil || result.exit != 0 && result.exit != 1 {
			t.Fatalf("SETUP: scheduler caller: %+v", result)
		}
	}
	mutationEffect(t, "L-SCHED", "retuned", before != readScheduler(t, pid))
	victimResult := victim.finish(t)
	if victimResult.exit != 0 || victimResult.stderr != "" || victimResult.stdout != "READY\nDONE\n" {
		t.Fatalf("SETUP: scheduler victim completion: %+v", victimResult)
	}
	if !strings.Contains(output, "=1\n") && !strings.Contains(output, "=ok\n") {
		unexpected(t, "scheduler errno: %s", output)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}
func legIOUring(t *testing.T, spec Spec) {
	p := newProof(t, "L-IOURING")
	var runs []JailedResult

	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "owned")
	mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	mutationSetup(t, err)
	defer listener.Close()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	control, err := m1ControlOutput(t, exec.Command(probe, "uring", path, port))
	mutationSetup(t, validateM1UringResult(jailResult{stdout: string(control), exit: proofExit(err)}, true))
	if err != nil || !strings.Contains(string(control), "uring-setxattr=ok\n") {
		t.Fatalf("SETUP: io_uring control (requires enabled io_uring): %v: %s", err, control)
	}
	mutationSetup(t, listener.SetDeadline(time.Now().Add(time.Second)))
	connection, err := listener.Accept()
	mutationSetup(t, err)
	connection.Close()
	value := make([]byte, 64)
	n, err := unix.Getxattr(path, "user.sshgate_uring", value)
	mutationSetup(t, err)
	if string(value[:n]) != "changed" {
		t.Fatal("SETUP: io_uring control did not set xattr")
	}
	mutationSetup(t, unix.Removexattr(path, "user.sshgate_uring"))
	spec.Net = false
	output := runM1Filter(t, p, &runs, spec, probe+" uring "+path+" "+port, nil).stdout
	mutationSetup(t, listener.SetDeadline(time.Now().Add(100*time.Millisecond)))
	connection, err = listener.Accept()
	mutationSetup(t, validateM1Accept(err, strings.Contains(output, "connect=ok\n")))
	delivered := err == nil
	if delivered {
		connection.Close()
	}
	mutationEffect(t, "L-IOURING", "connected", delivered)
	_, err = unix.Getxattr(path, "user.sshgate_uring", value)
	if err != unix.ENODATA {
		unexpected(t, "uring altered host xattr: %v", err)
	}
	if !strings.Contains(output, "io_uring_setup=1\n") && !strings.Contains(output, "io_uring_register=1\n") && !strings.Contains(output, "uring-socket-enter=1\n") && !strings.Contains(output, "uring-connect=ok\n") {
		unexpected(t, "unexpected uring errno: %s", output)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func legKeyring(t *testing.T, spec Spec) {
	if runFilterFixture(t, "SSHGATE_KEYRING_FIXTURE", nil, []string{"keyring", "errno"}) {
		return
	}
	p := newProof(t, "L-KEYRING")
	var runs []JailedResult

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	session, err := unix.KeyctlJoinSessionKeyring(fmt.Sprintf("sshgate-session-%d-%d", os.Getpid(), time.Now().UnixNano()))
	mutationSetup(t, err)
	probe := buildProbe(t)
	changed, badErrno := false, false
	prefix := fmt.Sprintf("sshgate-p15-%d-%d", os.Getpid(), time.Now().UnixNano())
	for _, op := range []string{"keyring-add", "keyring-clear", "keyring-request"} {
		ring, err := unix.AddKey("keyring", prefix+op, nil, session)
		mutationSetup(t, err)
		mutationSetup(t, unix.KeyctlSetperm(ring, 0x3f3f0000))
		t.Cleanup(func() { unix.KeyctlInt(unix.KEYCTL_UNLINK, ring, session, 0, 0) })
		description := prefix + op + "-key"
		if op == "keyring-request" {
			key, err := unix.AddKey("user", description, []byte("canary"), session)
			mutationSetup(t, err)
			t.Cleanup(func() { unix.KeyctlInt(unix.KEYCTL_UNLINK, key, session, 0, 0) })
		}
		reset := func() {
			_, err := unix.KeyctlInt(unix.KEYCTL_CLEAR, ring, 0, 0, 0)
			mutationSetup(t, err)
			if op == "keyring-clear" {
				_, err = unix.AddKey("user", description, []byte("canary"), ring)
				mutationSetup(t, err)
			}
		}
		snapshot := func() []byte {
			buffer := make([]byte, 4096)
			n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, ring, buffer, 0)
			mutationSetup(t, err)
			return buffer[:n]
		}
		reset()
		before := snapshot()
		args := []string{op, strconv.Itoa(ring), description}
		control, err := m1ControlOutput(t, exec.Command(probe, args...))
		mutationSetup(t, err)
		if bytes.Equal(before, snapshot()) {
			t.Fatalf("SETUP: keyring control did not change ring: %s", control)
		}
		reset()
		before = snapshot()
		output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" "+strings.Join(args, " "), nil), "keyring")
		changed = changed || !bytes.Equal(before, snapshot())
		badErrno = badErrno || !strings.Contains(output, "keyring=1\n")
	}
	mutationEffect(t, "L-KEYRING", "keyring", changed)
	mutationEffect(t, "L-KEYRING", "errno", badErrno)
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func legInet(t *testing.T, spec Spec, grant bool) {
	name := "L-INET-DENY"
	if grant {
		name = "L-INET-GRANT"
	}

	p := newProof(t, name)
	var runs []JailedResult

	probe := buildProbe(t)
	badConnect, badErrno := false, false
	for _, network := range []string{"tcp4", "tcp6"} {
		address := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
		operation := "dial-inet"
		if network == "tcp6" {
			address.IP = net.IPv6loopback
			operation = "dial-inet6"
		}
		listener, err := net.ListenTCP(network, address)
		mutationSetup(t, err)
		defer listener.Close()
		port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
		control, err := m1ControlOutput(t, exec.Command(probe, operation, port))
		mutationSetup(t, err)
		mutationSetup(t, listener.SetDeadline(time.Now().Add(time.Second)))
		conn, err := listener.Accept()
		mutationSetup(t, err)
		conn.Close()
		if !strings.Contains(string(control), "connect=ok") {
			t.Fatal("SETUP: inet control")
		}
		spec.Net = grant
		output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" "+operation+" "+port, nil), "socket", "socket>connect")
		mutationSetup(t, listener.SetDeadline(time.Now().Add(100*time.Millisecond)))
		conn, err = listener.Accept()
		mutationSetup(t, validateM1Accept(err, strings.Contains(output, "connect=ok\n")))
		connected := err == nil
		if connected {
			conn.Close()
		}
		if grant {
			if !connected || !strings.Contains(output, "connect=ok\n") {
				unexpected(t, "granted %s failed: %s", network, output)
			}
		} else {
			badConnect = badConnect || connected
			badErrno = badErrno || !strings.Contains(output, "socket=1\n")
		}
	}
	if !grant {
		mutationEffect(t, "L-INET-DENY", "connected", badConnect)
		mutationEffect(t, "L-INET-DENY", "errno", badErrno)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}
func legSocketSweep(t *testing.T, spec Spec, grant bool) {
	name := "L-SOCK-SWEEP"
	if grant {
		name = "L-SOCK-SWEEP-GRANT"
	}

	p := newProof(t, name)
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		p.Omit("ci-only")
		return
	}
	var runs []JailedResult

	probe := buildProbe(t)
	spec.Net = grant
	if os.Getenv("SSHGATE_JAIL_CI") == "1" {
		args := []string{"socket-tuple", "38", "5", "0"}
		if grant {
			args = []string{"socket-tuple", "2", "1", "132"}
		}
		output, err := m1ControlOutput(t, exec.Command(probe, args...))
		if err != nil || !strings.Contains(string(output), "socket=ok") {
			t.Fatalf("SETUP: socket module control: %v %s", err, output)
		}
	}
	before, err := os.ReadFile("/proc/modules")
	mutationSetup(t, err)
	// A supported forbidden tuple proves the plain-jail family deny independently of module autoload.
	control, err := m1ControlOutput(t, exec.Command(probe, "socket-tuple", "1", "1", "0"))
	mutationSetup(t, err)
	if !strings.Contains(string(control), "socket=ok") {
		t.Fatal("SETUP: socket control")
	}
	mode := "deny"
	if grant {
		mode = "grant"
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" socket-sweep "+mode, nil), "attempts")
	var attempts, denied int
	if _, err := fmt.Sscanf(strings.TrimSpace(output), "attempts=%d denied=%d", &attempts, &denied); err != nil || attempts < 20000 {
		t.Fatalf("SETUP: incomplete socket sweep: %s", output)
	}
	bad := attempts != denied
	after, err := os.ReadFile("/proc/modules")
	mutationSetup(t, err)
	mutationEffect(t, name, "tuple", bad || moduleNames(before) != moduleNames(after))
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}
func legSSFallback(t *testing.T, spec Spec) {
	p := newProof(t, "L-SS-FALLBACK")
	var runs []JailedResult

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	mutationSetup(t, err)
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	command := fmt.Sprintf("ss -H -ltn 'sport = :%d'", port)
	control, err := m1ControlOutput(t, exec.Command("/bin/sh", "-c", command))
	mutationSetup(t, err)
	if len(bytes.TrimSpace(control)) == 0 {
		t.Fatal("SETUP: ss did not show control listener")
	}
	result := runM1Filter(t, p, &runs, spec, command, nil)
	if result.setupErr != nil || result.exit != 0 || result.stdout == "" {
		t.Fatalf("SETUP: ss control: %+v", result)
	}
	output := result.stdout
	if result.exit != 0 || strings.Count(strings.TrimSpace(output), "\n") != bytes.Count(bytes.TrimSpace(control), []byte("\n")) {
		unexpected(t, "ss procfs fallback lost listener: %+v", result)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Finish()
}

func legUnixConnect(t *testing.T, spec Spec, abstract bool) {
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "stream")
	name := "L-UNIX-CONNECT"
	if abstract {
		path = "@sshgate-stream-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		name = "L-UNIX-ABSTRACT"
	}
	p := newProof(t, name)
	var runs []JailedResult

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	mutationSetup(t, err)
	defer listener.Close()
	control, err := m1ControlOutput(t, exec.Command(probe, "unix-connect", path))
	mutationSetup(t, err)
	mutationSetup(t, listener.SetDeadline(time.Now().Add(time.Second)))
	conn, err := listener.Accept()
	mutationSetup(t, err)
	conn.Close()
	if !strings.Contains(string(control), "connect=ok") {
		t.Fatal("SETUP: unix control")
	}
	output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" unix-connect "+path, nil), "socket", "socket>connect")
	mutationSetup(t, listener.SetDeadline(time.Now().Add(100*time.Millisecond)))
	conn, err = listener.Accept()
	mutationSetup(t, validateM1Accept(err, strings.Contains(output, "connect=ok\n")))
	connected := err == nil
	if connected {
		conn.Close()
	}
	mutationEffect(t, name, "connected", connected)
	if !strings.Contains(output, "socket=1\n") && !strings.Contains(output, "connect=13\n") && !strings.Contains(output, "connect=1\n") && !strings.Contains(output, "connect=ok\n") {
		unexpected(t, "unix connect errno: %s", output)
	}
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}
func legIoctlFilter(t *testing.T, spec Spec) {
	p := newProof(t, "L-IOCTL")
	var runs []JailedResult

	probe := buildProbe(t)
	requests := []uint32{0x5412, 0x541c, 0xc0506617, 0xc0406618, 0xc0406619}
	bad := false
	for _, request := range requests {
		// Both processes create a regular tmpfs file in their own /dev/shm view.
		control := exec.Command(probe, "ioctl-scratch", fmt.Sprint(request))
		var diagnostic bytes.Buffer
		control.Stderr = &diagnostic
		output, controlErr := control.Output()
		requireProbeOutput(t, jailResult{exit: exitCodeOf(controlErr), stdout: string(output), stderr: diagnostic.String()}, "open", "ioctl")
		if !strings.Contains(string(output), "open=ok\n") || !strings.Contains(string(output), "ioctl=25\n") && !strings.Contains(string(output), "ioctl=95\n") {
			t.Fatalf("SETUP: scratch ioctl control %#x: %s", request, output)
		}
		result := runM1Filter(t, p, &runs, spec, fmt.Sprintf("%s ioctl-scratch %d", probe, request), nil)
		text := requireProbeOutput(t, result, "open", "ioctl")
		if !strings.Contains(text, "open=ok\n") {
			t.Fatalf("SETUP: scratch ioctl target not opened: %s", text)
		}
		bad = bad || !strings.Contains(text, "ioctl=1\n")
	}
	// This pty belongs only to the fixture; inherited stdio never refers to an operator tty.
	_, slave := openPty(t)
	duplicate, err := unix.Dup(slave)
	mutationSetup(t, err)
	tty := os.NewFile(uintptr(duplicate), "fixture-pty")
	defer tty.Close()
	control := exec.Command(probe, "tiocsti", "unused")
	control.Stdin = tty
	var diagnostic bytes.Buffer
	control.Stderr = &diagnostic
	output, controlErr := control.Output()
	requireProbeOutput(t, jailResult{exit: exitCodeOf(controlErr), stdout: string(output), stderr: diagnostic.String()}, "tiocsti")
	if !strings.Contains(string(output), "tiocsti=ok\n") && !strings.Contains(string(output), "tiocsti=5\n") && !strings.Contains(string(output), "tiocsti=1\n") {
		t.Fatalf("SETUP: isolated pty ioctl control: %s", output)
	}
	result := runM1Filter(t, p, &runs, spec, probe+" tiocsti unused", func(j *Jailed) { j.Cmd.Stdin = tty })
	text := requireProbeOutput(t, result, "tiocsti")
	bad = bad || !strings.Contains(text, "tiocsti=1\n")
	mutationEffect(t, "L-IOCTL", "errno", bad)
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Finish()
}
func legMetadataErrno(t *testing.T, spec Spec) {
	p := newProof(t, "L-META-ERRNO")
	var runs []JailedResult

	probe := buildProbe(t)
	badErrno := false
	for _, submount := range []bool{false, true} {
		path := filepath.Join(writeSweepFixture(t, submount), "owned")
		mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
		control, err := m1ControlOutput(t, exec.Command(probe, "metadata-errno", path))
		if err != nil {
			t.Fatalf("SETUP: metadata control %s: %v: %s", path, err, control)
		}
		for _, op := range []string{"fchmod", "chmod", "chown", "setxattr", "utimensat"} {
			if !strings.Contains(string(control), op+"=ok\n") {
				t.Fatalf("SETUP: metadata %s control: %s", op, control)
			}
		}
		info, err := os.Stat(path)
		mutationSetup(t, err)
		if info.Mode().Perm() != 0640 || info.ModTime().Unix() != 1 {
			t.Fatal("SETUP: metadata control had no effect")
		}
		mutationSetup(t, os.Remove(path))
		mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
		before, err := os.Stat(path)
		mutationSetup(t, err)
		output := requireProbeOutput(t, runM1Filter(t, p, &runs, spec, probe+" metadata-errno "+path, nil), "open", "fchmod", "chmod", "chown", "setxattr", "utimensat")
		for _, op := range []string{"fchmod", "chmod", "chown", "setxattr", "utimensat"} {
			badErrno = badErrno || !strings.Contains(output, op+"=1\n")
		}
		after, err := os.Stat(path)
		mutationSetup(t, err)
		if after.Mode() != before.Mode() || after.ModTime() != before.ModTime() {
			unexpected(t, "metadata effect escaped read-only mount")
		}
		_, err = unix.Getxattr(path, "system.posix_acl_access", make([]byte, 64))
		if err != unix.ENODATA {
			unexpected(t, "metadata xattr escaped: %v", err)
		}
	}
	mutationEffect(t, "L-META-ERRNO", "errno", badErrno)
	p.Jailed("probe", runs...)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("effects", Observation{Valid: true, Sealed: true, Conclusive: true})
	p.Finish()
}

func moduleNames(data []byte) string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	sort.Strings(names)
	return strings.Join(names, "\n")
}

// Each fixture subprocess starts from clean credentials and scheduler state.
func runFilterFixture(t *testing.T, environment string, attributes *syscall.SysProcAttr, assertions []string) bool {
	t.Helper()
	if os.Getenv(environment) == "1" {
		return false
	}
	executable, err := os.Executable()
	mutationSetup(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.v", "-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$")
	command.Env = append(os.Environ(), environment+"=1")
	command.SysProcAttr = attributes
	output, err := command.CombinedOutput()
	forwardCoverProof(t, output, err)
	return true
}
