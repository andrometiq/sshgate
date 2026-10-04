//go:build linux && jail_e2e

package confine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
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
	out, err := control.CombinedOutput()
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
	result := runP12(t, spec, probe+" pipesz "+strconv.Itoa(target), func(j *Jailed) { j.Cmd.Stdin = r })
	output := requireProbeOutput(t, result, "pipesz", "size")
	after, err := unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	mutationSetup(t, err)
	mutationEffect(t, "L-FCNTL-PIPESZ", "pipe-size", after != before)
	mutationEffect(t, "L-FCNTL-PIPESZ", "errno", !strings.Contains(output, "pipesz=1\n"))
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
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "owned")
	mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	fileHint(t, fd, true, 0)
	out, err := exec.Command(probe, "rwhint", path).CombinedOutput()
	mutationSetup(t, err)
	if fileHint(t, fd, false, 0) != 4 {
		t.Fatalf("SETUP: owned-file control did not persist hint: %s", out)
	}
	fileHint(t, fd, true, 0)
	output := requireProbeOutput(t, runP12(t, spec, probe+" rwhint "+path, nil), "open", "rwhint")
	mutationEffect(t, "L-FCNTL-RWHINT", "hint", fileHint(t, fd, false, 0) != 0)
	mutationEffect(t, "L-FCNTL-RWHINT", "errno", !strings.Contains(output, "rwhint=1\n"))
}

func legFlock(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "lock")
	mutationSetup(t, os.WriteFile(path, nil, 0600))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	run := func(jailed bool) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, probe, "flock-hold", path)
		var j *Jailed
		if jailed {
			j, err = spec.Command(ctx, probe+" flock-hold "+path)
			mutationSetup(t, err)
			defer j.Abort()
			command = j.Cmd
		}
		input, err := command.StdinPipe()
		mutationSetup(t, err)
		output, err := command.StdoutPipe()
		mutationSetup(t, err)
		var diagnostic bytes.Buffer
		command.Stderr = &diagnostic
		mutationSetup(t, command.Start())
		if j != nil {
			_ = j.Started()
		}
		scanner := bufio.NewScanner(output)
		var lines []string
		ready := false
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
			if scanner.Text() == "READY" {
				ready = true
				break
			}
		}
		if !ready {
			t.Fatalf("SETUP: lock holder not ready: %s %s", strings.Join(lines, "\n"), diagnostic.String())
		}
		outside := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if outside == nil {
			mutationSetup(t, unix.Flock(fd, unix.LOCK_UN))
		}
		input.Close()
		waitErr := command.Wait()
		if j != nil {
			if _, err := j.Status(); err != nil {
				t.Fatalf("SETUP: jail %v", err)
			}
		}
		if !jailed {
			mutationSetup(t, waitErr)
		}
		return strings.Join(lines, "\n"), outside
	}
	_, err = run(false)
	if err != unix.EAGAIN {
		t.Fatalf("SETUP: unjailed holder did not exclude outside locker: %v", err)
	}
	output, err := run(true)
	mutationEffect(t, "L-FLOCK-EX", "exclusive-lock", err != nil)
	mutationEffect(t, "L-FLOCK-EX", "errno", !strings.Contains(output, "flock=1\n"))
}

func legCoreLock(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	var inherited unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &inherited))
	want := min(uint64(1), inherited.Max)
	control, err := exec.Command(probe, "rlimit-lock", "unused").CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), "setrlimit=ok") || !strings.Contains(string(control), "prlimit64=ok") {
		t.Fatalf("SETUP: limit control: %s", control)
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" rlimit-lock unused", nil), "getrlimit", "before", "setrlimit", "prlimit64", "getrlimit-after", "after")
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "errno", !strings.Contains(output, "setrlimit=1\n") || !strings.Contains(output, "prlimit64=1\n"))
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "limit", !strings.Contains(output, fmt.Sprintf("after=%d:%d\n", want, want)))
	// Shell and util-linux exercise the real callers in addition to raw syscall probes.
	for _, args := range [][]string{{"/bin/sh", "-c", "ulimit -Sc 0"}, {"prlimit", "--core=0:"}} {
		control, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("SETUP: core caller control %v: %s", err, control)
		}
	}
	shell := runP12(t, spec, "ulimit -Sc 0", nil)
	if shell.setupErr != nil {
		t.Fatalf("SETUP: shell %v", shell.setupErr)
	}
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "shell", shell.exit == 0)
	if shell.exit != 0 && !strings.Contains(strings.ToLower(shell.stderr), "operation not permitted") {
		unexpected(t, "shell core-limit errno: %+v", shell)
	}
	command := runP12(t, spec, "prlimit --core=0:", nil)
	if command.setupErr != nil {
		t.Fatalf("SETUP: prlimit %v", command.setupErr)
	}
	mutationEffect(t, "L-RLIMIT-CORE-LOCK", "prlimit", command.exit == 0)
	if command.exit != 0 && !strings.Contains(strings.ToLower(command.stderr), "operation not permitted") {
		unexpected(t, "prlimit core-limit errno: %+v", command)
	}
}

func legSyncErrno(t *testing.T, spec Spec, syncfs bool) {
	probe := buildProbe(t)
	args := []string{"raw", "162"}
	name, field := "L-SC-SYNC-ERRNO", "raw"
	if syncfs {
		args = []string{"syncfs", filterFixture(t)}
		name, field = "L-SC-SYNCFS-ERRNO", "syncfs"
	}
	control, err := exec.Command(probe, args...).CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), field+"=ok\n") {
		t.Fatalf("SETUP: sync control: %s", control)
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" "+strings.Join(args, " "), nil), field)
	mutationEffect(t, name, "errno", !strings.Contains(output, field+"=1\n"))
}
func legListen(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	control, err := exec.Command(probe, "listen", "unused").CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), "listen=ok") {
		t.Fatalf("SETUP: listen control %s", control)
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" listen unused", nil), "socket", "socket>listen")
	mutationEffect(t, "L-LISTEN", "errno", !strings.Contains(output, "listen=1\n"))
}
func legSockdiag(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	if os.Getenv("SSHGATE_JAIL_CI") == "1" {
		output, err := exec.Command(probe, "sockdiag-request", "unused").CombinedOutput()
		if err != nil || !strings.Contains(string(output), "sockdiag=ok") {
			t.Fatalf("SETUP: sockdiag module control: %v %s", err, output)
		}
	} else {
		t.Log("CONTROL-SKIPPED(ci-only): L-SOCKDIAG module control")
	}
	control, err := exec.Command(probe, "socket-tuple", "16", "3", "4").CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), "socket=ok") {
		t.Fatalf("SETUP: sockdiag control %s", control)
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" socket-tuple 16 3 4", nil), "socket")
	mutationEffect(t, "L-SOCKDIAG", "errno", !strings.Contains(output, "socket=1\n"))
}
func legSocketpair(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	for _, kind := range []int{1, 2, 5} {
		args := fmt.Sprintf(" socketpair-tuple 1 %d", kind)
		control, err := exec.Command(probe, "socketpair-tuple", "1", strconv.Itoa(kind)).CombinedOutput()
		mutationSetup(t, err)
		if !strings.Contains(string(control), "socketpair=ok") {
			t.Fatal("SETUP: socketpair control")
		}
		output := requireProbeOutput(t, runP12(t, spec, probe+args, nil), "socketpair")
		want := "socketpair=ok\n"
		if kind == 2 {
			want = "socketpair=1\n"
		}
		mutationEffect(t, "L-SOCKPAIR-SWEEP", "errno", !strings.Contains(output, want))
	}
}
func legNamespaceCalls(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	cloneAllowed, unshareAllowed := false, false
	for _, item := range []struct {
		flags  uint64
		option string
	}{{0x10000000, "-U"}, {0x20000, "-m"}, {0x40000000, "-n"}, {0x20000000, "-p"}, {0x8000000, "-i"}} {
		control, err := exec.Command("unshare", "-Ur", "--", "unshare", item.option, "--", "/bin/true").CombinedOutput()
		if err != nil {
			t.Fatalf("SETUP: unshare %s control: %v: %s", item.option, err, control)
		}
		result := runP12(t, spec, "unshare "+item.option+" -- /bin/true", nil)
		if result.setupErr != nil {
			t.Fatalf("SETUP: unshare jail: %v", result.setupErr)
		}
		if result.exit == 0 {
			unshareAllowed = true
		} else if !strings.Contains(result.stderr, "Operation not permitted") {
			unexpected(t, "unshare %s not EPERM: %+v", item.option, result)
		}
		control, err = exec.Command("unshare", "-Ur", "--", probe, "clone-ns", fmt.Sprint(item.flags)).CombinedOutput()
		if err != nil || !strings.Contains(string(control), "clone=ok\n") {
			t.Fatalf("SETUP: clone %#x control: %v: %s", item.flags, err, control)
		}
		output := requireProbeOutput(t, runP12(t, spec, fmt.Sprintf("%s clone-ns %d", probe, item.flags), nil), "clone", "clone>wait")
		if strings.Contains(output, "clone=ok\n") {
			cloneAllowed = true
		} else if !strings.Contains(output, "clone=1\n") {
			unexpected(t, "clone %#x not EPERM: %s", item.flags, output)
		}
	}
	control, err := exec.Command("unshare", "-Urn", "--", probe, "setns", "unused").CombinedOutput()
	if err != nil || !strings.Contains(string(control), "setns=ok\n") {
		t.Fatalf("SETUP: setns control: %v: %s", err, control)
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" setns unused", nil), "open", "setns")
	if !strings.Contains(output, "setns=1\n") {
		unexpected(t, "setns(0) not EPERM: %s", output)
	}
	mutationEffect(t, "L-NS-CREATE", "clone", cloneAllowed)
	mutationEffect(t, "L-NS-CREATE", "unshare", unshareAllowed)
}
func legCeiling(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	p12Control(t, spec)
	output := requireProbeOutput(t, runP12(t, spec, probe+" raw 472", nil), "raw")
	if !strings.Contains(output, "raw=38\n") {
		unexpected(t, "unknown syscall not ENOSYS: %s", output)
	}
	result := runP12(t, spec, "exec "+probe+" raw 1073741824", nil)
	if result.setupErr != nil {
		t.Fatalf("SETUP: x32 %v", result.setupErr)
	}
	if !isSeccompKill(result.exit) {
		unexpected(t, "x32 exit %d, expected SIGSYS: %+v", result.exit, result)
	}
}

func legDatagram(t *testing.T, spec Spec, abstract bool) {
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "dgram")
	name := "L-DGRAM-SEND"
	if abstract {
		path = "@sshgate-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		name = "L-DGRAM-ABSTRACT"
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	mutationSetup(t, unix.Bind(fd, &unix.SockaddrUnix{Name: path}))
	control, err := exec.Command(probe, "dgram-send", path).CombinedOutput()
	mutationSetup(t, err)
	var data [64]byte
	n, _, err := unix.Recvfrom(fd, data[:], 0)
	mutationSetup(t, err)
	if string(data[:n]) != "canary" {
		t.Fatalf("SETUP: no unjailed datagram: %s", control)
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" dgram-send "+path, nil), "socketpair", "socketpair>sendto")
	n, _, err = unix.Recvfrom(fd, data[:], 0)
	if err != nil && err != unix.EAGAIN {
		t.Fatalf("SETUP: receiver %v", err)
	}
	mutationEffect(t, name, "delivered", err == nil && n > 0)
	if !strings.Contains(output, "socketpair=1\n") && !strings.Contains(output, "sendto=13\n") && !strings.Contains(output, "sendto=1\n") && !strings.Contains(output, "sendto=ok\n") {
		unexpected(t, "unexpected datagram errno: %s", output)
	}
}

func legSignal(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	victim := func() (*exec.Cmd, chan error) {
		cmd := exec.Command("sleep", "60")
		mutationSetup(t, cmd.Start())
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() { cmd.Process.Kill() })
		return cmd, done
	}
	control, done := victim()
	out, err := exec.Command(probe, "signal", strconv.Itoa(control.Process.Pid)).CombinedOutput()
	mutationSetup(t, err)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("SETUP: signal control did not terminate: %s", out)
	}
	target, done := victim()
	output := requireProbeOutput(t, runP12(t, spec, probe+" signal "+strconv.Itoa(target.Process.Pid), nil), "kill")
	delivered := false
	select {
	case <-done:
		delivered = true
	case <-time.After(100 * time.Millisecond):
	}
	mutationEffect(t, "L-SIGNAL", "signal", delivered)
	if !strings.Contains(output, "kill=3\n") && !strings.Contains(output, "kill=1\n") && !strings.Contains(output, "kill=ok\n") {
		unexpected(t, "signal errno: %s", output)
	}
}
func legSysV(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	control := shmCreate(t)
	out, err := exec.Command(probe, "shm-rmid", strconv.Itoa(control)).CombinedOutput()
	mutationSetup(t, err)
	if shmExists(control) {
		shmRemove(control)
		t.Fatalf("SETUP: SysV control: %s", out)
	}
	id := shmCreate(t)
	defer shmRemove(id)
	output := requireProbeOutput(t, runP12(t, spec, probe+" shm-rmid "+strconv.Itoa(id), nil), "shmctl")
	mutationEffect(t, "L-IPC-SYSV", "removed", !shmExists(id))
	if !strings.Contains(output, "shmctl=22\n") && !strings.Contains(output, "shmctl=ok\n") {
		unexpected(t, "SysV errno: %s", output)
	}
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
	self := runP12(t, spec, "nice -n 19 ionice -c3 chrt -b 0 taskset -c "+strconv.Itoa(cpu)+" prlimit --nofile=7:7 "+probe+" scheduler-state 0", nil)
	if self.setupErr != nil || self.exit != 0 || !strings.Contains(self.stdout, "state=19:24576:3:7:1\n") {
		t.Fatalf("SETUP: self retune effect control: %+v", self)
	}
	victim := startSleeper(t)
	pid := victim.Process.Pid
	before := readScheduler(t, pid)
	output := requireProbeOutput(t, runP12(t, spec, probe+" scheduler "+strconv.Itoa(pid), nil), "prlimit", "nice", "ioprio", "policy", "affinity", "schedattr", "state")
	for _, caller := range strings.Split(callers(strconv.Itoa(pid)), " && ") {
		result := runP12(t, spec, caller, nil)
		if result.setupErr != nil || result.exit != 0 && result.exit != 1 {
			t.Fatalf("SETUP: scheduler caller: %+v", result)
		}
	}
	mutationEffect(t, "L-SCHED", "retuned", before != readScheduler(t, pid))
	if !strings.Contains(output, "=1\n") && !strings.Contains(output, "=ok\n") {
		unexpected(t, "scheduler errno: %s", output)
	}
}
func legIOUring(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "owned")
	mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	mutationSetup(t, err)
	defer listener.Close()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	control, err := exec.Command(probe, "uring", path, port).CombinedOutput()
	if err != nil || !strings.Contains(string(control), "uring-setxattr=ok\n") {
		t.Fatalf("SETUP: io_uring control (requires enabled io_uring): %v: %s", err, control)
	}
	listener.SetDeadline(time.Now().Add(time.Second))
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
	output := requireProbeOutput(t, runP12(t, spec, probe+" uring "+path+" "+port, nil), "uring-complete", "io_uring_setup", "io_uring_setup>eventfd", "eventfd>io_uring_register", "io_uring_register>sq-map", "sq-map>sqes-map")
	listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
	connection, err = listener.Accept()
	delivered := err == nil
	if delivered {
		connection.Close()
	}
	mutationEffect(t, "L-IOURING", "connected", delivered)
	_, err = unix.Getxattr(path, "user.sshgate_uring", value)
	if err != unix.ENODATA {
		unexpected(t, "uring altered host xattr: %v", err)
	}
	if !strings.Contains(output, "io_uring_setup=1\n") && !strings.Contains(output, "io_uring_register=1\n") && !strings.Contains(output, "io_uring_enter=1\n") && !strings.Contains(output, "uring-connect=ok\n") {
		unexpected(t, "unexpected uring errno: %s", output)
	}
}

func legKeyring(t *testing.T, spec Spec) {
	if runFilterFixture(t, "SSHGATE_KEYRING_FIXTURE", nil, []string{"keyring", "errno"}) {
		return
	}
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
		control, err := exec.Command(probe, args...).CombinedOutput()
		mutationSetup(t, err)
		if bytes.Equal(before, snapshot()) {
			t.Fatalf("SETUP: keyring control did not change ring: %s", control)
		}
		reset()
		before = snapshot()
		output := requireProbeOutput(t, runP12(t, spec, probe+" "+strings.Join(args, " "), nil), "keyring")
		changed = changed || !bytes.Equal(before, snapshot())
		badErrno = badErrno || !strings.Contains(output, "keyring=1\n")
	}
	mutationEffect(t, "L-KEYRING", "keyring", changed)
	mutationEffect(t, "L-KEYRING", "errno", badErrno)
}

func legInet(t *testing.T, spec Spec, grant bool) {
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
		control, err := exec.Command(probe, operation, port).CombinedOutput()
		mutationSetup(t, err)
		listener.SetDeadline(time.Now().Add(time.Second))
		conn, err := listener.Accept()
		mutationSetup(t, err)
		conn.Close()
		if !strings.Contains(string(control), "connect=ok") {
			t.Fatal("SETUP: inet control")
		}
		spec.Net = grant
		output := requireProbeOutput(t, runP12(t, spec, probe+" "+operation+" "+port, nil), "socket", "socket>connect")
		listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn, err = listener.Accept()
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
}
func legSocketSweep(t *testing.T, spec Spec, grant bool) {
	probe := buildProbe(t)
	spec.Net = grant
	if os.Getenv("SSHGATE_JAIL_CI") == "1" {
		args := []string{"socket-tuple", "38", "5", "0"}
		if grant {
			args = []string{"socket-tuple", "2", "1", "132"}
		}
		output, err := exec.Command(probe, args...).CombinedOutput()
		if err != nil || !strings.Contains(string(output), "socket=ok") {
			t.Fatalf("SETUP: socket module control: %v %s", err, output)
		}
	}
	before, err := os.ReadFile("/proc/modules")
	mutationSetup(t, err)
	// A supported forbidden tuple proves the plain-jail family deny independently of module autoload.
	control, err := exec.Command(probe, "socket-tuple", "1", "1", "0").CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), "socket=ok") {
		t.Fatal("SETUP: socket control")
	}
	mode := "deny"
	if grant {
		mode = "grant"
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" socket-sweep "+mode, nil), "attempts")
	var attempts, denied int
	if _, err := fmt.Sscanf(strings.TrimSpace(output), "attempts=%d denied=%d", &attempts, &denied); err != nil || attempts < 20000 {
		t.Fatalf("SETUP: incomplete socket sweep: %s", output)
	}
	bad := attempts != denied
	after, err := os.ReadFile("/proc/modules")
	mutationSetup(t, err)
	name := "L-SOCK-SWEEP"
	if grant {
		name = "L-SOCK-SWEEP-GRANT"
	}
	mutationEffect(t, name, "tuple", bad || moduleNames(before) != moduleNames(after))
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Log("CONTROL-SKIPPED(ci-only): socket module-autoload control")
	}
}
func legSSFallback(t *testing.T, spec Spec) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	mutationSetup(t, err)
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	command := fmt.Sprintf("ss -H -ltn 'sport = :%d'", port)
	control, err := exec.Command("/bin/sh", "-c", command).Output()
	mutationSetup(t, err)
	if len(bytes.TrimSpace(control)) == 0 {
		t.Fatal("SETUP: ss did not show control listener")
	}
	result := runP12(t, spec, command, nil)
	if result.setupErr != nil || result.exit != 0 || result.stdout == "" {
		t.Fatalf("SETUP: ss control: %+v", result)
	}
	output := result.stdout
	if result.exit != 0 || strings.Count(strings.TrimSpace(output), "\n") != bytes.Count(bytes.TrimSpace(control), []byte("\n")) {
		unexpected(t, "ss procfs fallback lost listener: %+v", result)
	}
}

func legUnixConnect(t *testing.T, spec Spec, abstract bool) {
	probe := buildProbe(t)
	path := filepath.Join(filterFixture(t), "stream")
	name := "L-UNIX-CONNECT"
	if abstract {
		path = "@sshgate-stream-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		name = "L-UNIX-ABSTRACT"
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	mutationSetup(t, err)
	defer listener.Close()
	control, err := exec.Command(probe, "unix-connect", path).CombinedOutput()
	mutationSetup(t, err)
	listener.SetDeadline(time.Now().Add(time.Second))
	conn, err := listener.Accept()
	mutationSetup(t, err)
	conn.Close()
	if !strings.Contains(string(control), "connect=ok") {
		t.Fatal("SETUP: unix control")
	}
	output := requireProbeOutput(t, runP12(t, spec, probe+" unix-connect "+path, nil), "socket", "socket>connect")
	listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
	conn, err = listener.Accept()
	connected := err == nil
	if connected {
		conn.Close()
	}
	mutationEffect(t, name, "connected", connected)
	if !strings.Contains(output, "socket=1\n") && !strings.Contains(output, "connect=13\n") && !strings.Contains(output, "connect=1\n") && !strings.Contains(output, "connect=ok\n") {
		unexpected(t, "unix connect errno: %s", output)
	}
}
func legIoctlFilter(t *testing.T, spec Spec) {
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
		result := runP12(t, spec, fmt.Sprintf("%s ioctl-scratch %d", probe, request), nil)
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
	result := runP12(t, spec, probe+" tiocsti unused", func(j *Jailed) { j.Cmd.Stdin = tty })
	text := requireProbeOutput(t, result, "tiocsti")
	bad = bad || !strings.Contains(text, "tiocsti=1\n")
	mutationEffect(t, "L-IOCTL", "errno", bad)
}
func legMetadataErrno(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	badErrno := false
	for _, submount := range []bool{false, true} {
		path := filepath.Join(writeSweepFixture(t, submount), "owned")
		mutationSetup(t, os.WriteFile(path, []byte("canary"), 0600))
		control, err := exec.Command(probe, "metadata-errno", path).CombinedOutput()
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
		output := requireProbeOutput(t, runP12(t, spec, probe+" metadata-errno "+path, nil), "open", "fchmod", "chmod", "chown", "setxattr", "utimensat")
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
	status := exitCodeOf(err)
	convert := exec.Command("go", "tool", "test2json", "-p", "fixture")
	convert.Stdin = bytes.NewReader(output)
	stream, convertErr := convert.Output()
	mutationSetup(t, convertErr)
	parts := strings.Split(t.Name(), "/")
	name := parts[len(parts)-1]
	leg := harness.Leg{Name: name, Names: map[string]string{"native": t.Name(), "abi1": t.Name()}}
	var observed []string
	for _, assertion := range assertions {
		if bytes.Contains(output, []byte("MUTATION-EFFECT "+name+" "+assertion)) {
			observed = append(observed, assertion)
			leg.Markers = append(leg.Markers, "MUTATION-EFFECT "+assertion)
		}
	}
	if judgeErr := harness.Judge(bytes.NewReader(stream), "", status, []harness.Leg{leg}, "native"); judgeErr != nil {
		t.Fatalf("SETUP: fixture subprocess: %v: %s", judgeErr, output)
	}
	for _, assertion := range observed {
		mutationEffect(t, name, assertion, true)
	}
	return true
}
