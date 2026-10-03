//go:build linux

package gate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// TestConfineCommandSetsCloneFlags is the clobber-guard for the executor's
// confine branch: when a confined Spec builds the Cmd, its SysProcAttr must carry the
// rung-1 clone flags and uid/gid maps. If a future refactor reintroduced the old
// unconditional `c.SysProcAttr = &SysProcAttr{Setpgid:true}` below the branch, it
// would overwrite these and the jail would silently run in the host namespaces —
// this test trips first.
func TestConfineCommandSetsCloneFlags(t *testing.T) {
	jailed, err := confine.Spec{Rung: confine.Rung1Full}.Command(context.Background(), "true")
	if err != nil {
		t.Fatalf("build jail command: %v", err)
	}
	defer jailed.Abort()

	sa := jailed.Cmd.SysProcAttr
	if sa == nil {
		t.Fatal("confined Cmd has nil SysProcAttr")
	}
	const want = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC
	if sa.Cloneflags&want != want {
		t.Errorf("Cloneflags=%#x; missing one of NEWUSER|NEWNS|NEWPID|NEWIPC (%#x)", sa.Cloneflags, want)
	}
	if !sa.Setpgid {
		t.Error("confined Cmd must still set Setpgid for the cancel semantics")
	}
	if len(sa.UidMappings) == 0 || len(sa.GidMappings) == 0 {
		t.Error("confined rung-1 Cmd must set uid/gid mappings")
	}
}

// TestConfineRung2NoCloneFlags proves rung 2 uses the uniform re-exec path
// WITHOUT namespace clone flags (Landlock + seccomp are its wall).
func TestConfineRung2NoCloneFlags(t *testing.T) {
	jailed, err := confine.Spec{Rung: confine.Rung2Landlock, ScratchDir: t.TempDir()}.
		Command(context.Background(), "true")
	if err != nil {
		t.Fatalf("build jail command: %v", err)
	}
	defer jailed.Abort()

	sa := jailed.Cmd.SysProcAttr
	if sa == nil || !sa.Setpgid {
		t.Fatal("rung-2 Cmd must set Setpgid")
	}
	if sa.Cloneflags != 0 {
		t.Errorf("rung-2 Cmd must not set clone flags, got %#x", sa.Cloneflags)
	}
}

// requireUserns skips a test that needs a rung-1 jail when the host has no
// unprivileged user namespace (so the suite is never "green by skip" silently on
// a capable host, but does not fail on a restricted CI runner).
func requireUserns(t *testing.T) {
	t.Helper()
	if !confine.Detect().Userns {
		t.Skip("host has no unprivileged userns; rung-1 ExecWithRedaction test needs it")
	}
}

// requireLandlock skips a rung-2 test when the host has no Landlock (rung 2's only
// fs wall). Rung 2 needs no userns, so these tests run on the AppArmor-clamped
// tests.yml runner where requireUserns would skip.
func requireLandlock(t *testing.T) {
	t.Helper()
	if confine.Detect().LandlockABI < 1 {
		t.Skip("host has no Landlock; rung-2 ExecWithRedaction test needs it")
	}
}

// TestExecWithRedactionConfinedNamespace observes a REAL confinement effect: a
// rung-1 jailed command runs in a fresh user namespace, so /proc/self/ns/user
// differs from the gate's own. This proves ExecWithRedaction actually entered
// the jail (not merely set SysProcAttr) — the end-to-end counterpart to the
// SysProcAttr clobber-guard above.
func TestExecWithRedactionConfinedNamespace(t *testing.T) {
	requireUserns(t)
	hostNS, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		t.Fatalf("read host user ns: %v", err)
	}
	spec := confine.Spec{Rung: confine.Rung1Full, AllowInet: true}
	res, err := ExecWithRedaction(context.Background(), "readlink /proc/self/ns/user",
		ExecOpts{Confine: &spec, CaptureLimit: 4096})
	if err != nil {
		t.Fatalf("confined exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	got := strings.TrimSpace(res.Stdout)
	if got == "" || got == hostNS {
		t.Errorf("jailed user ns = %q, host = %q; want a DIFFERENT namespace", got, hostNS)
	}
}

// TestExecWithRedactionConfinedEROFS observes the filesystem wall: a rung-1
// jailed write to a file under $HOME fails and the file is unchanged, while the
// gate itself (no Confine) could write it.
func TestExecWithRedactionConfinedEROFS(t *testing.T) {
	requireUserns(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	dir, err := os.MkdirTemp(home, ".sshgate-gatetest-")
	if err != nil {
		t.Fatalf("mkdir in home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := confine.Spec{Rung: confine.Rung1Full, AllowInet: true}
	res, err := ExecWithRedaction(context.Background(), "echo pwned > "+target,
		ExecOpts{Confine: &spec})
	if err != nil {
		t.Fatalf("confined exec returned error (nothing should abort setup here): %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("jailed write exited 0; the jail should make $HOME read-only")
	}
	b, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("re-read target: %v", rerr)
	}
	if string(b) != "orig" {
		t.Errorf("target changed to %q; the jailed write was not contained", b)
	}
}

// TestExecWithRedactionConfineFailClosed proves the fail-closed contract at the
// executor boundary: an injected setup failure makes ExecWithRedaction return
// ExitCode -1 and a wrapped *confine.SetupError (a deny), never exit 0, and the
// command never runs. It uses rung 2 (Landlock, no userns) so it runs on the
// AppArmor-clamped CI runner too — not only where a rung-1 jail is available.
func TestExecWithRedactionConfineFailClosed(t *testing.T) {
	requireLandlock(t)
	spec := confine.Spec{Rung: confine.Rung2Landlock, AllowInet: true, ScratchDir: t.TempDir(), InjectFailAt: "seccomp"}
	res, err := ExecWithRedaction(context.Background(), "echo SHOULD_NOT_RUN",
		ExecOpts{Confine: &spec, CaptureLimit: 4096})
	if res.ExitCode != -1 {
		t.Errorf("ExitCode=%d want -1 on a setup failure", res.ExitCode)
	}
	var se *confine.SetupError
	if !errors.As(err, &se) {
		t.Fatalf("err=%v; want a wrapped *confine.SetupError", err)
	}
	if se.Stage != "seccomp" {
		t.Errorf("SetupError stage=%q want %q", se.Stage, "seccomp")
	}
	if strings.Contains(res.Stdout, "SHOULD_NOT_RUN") {
		t.Errorf("command ran despite the injected setup failure (stdout=%q)", res.Stdout)
	}
}

// TestExecWithRedactionConfineClosesInheritedFDs proves the worker closes any fd
// above stderr before execve: a NON-CLOEXEC fd planted in the gate (here fd ->
// /etc/hostname) must NOT be visible to the jailed command. A writable inherited
// fd would otherwise get past both the read-only mount and Landlock. Rung 2 keeps
// the test independent of userns.
func TestExecWithRedactionConfineClosesInheritedFDs(t *testing.T) {
	requireLandlock(t)
	// Plant a non-CLOEXEC fd: syscall.Open does not add O_CLOEXEC, so it survives
	// fork+execve into the child unless the worker closes it.
	fd, err := syscall.Open("/etc/hostname", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("plant fd: %v", err)
	}
	defer syscall.Close(fd)
	if fd < 5 {
		t.Skipf("planted fd %d too low to distinguish from the jail's own fds", fd)
	}

	spec := confine.Spec{Rung: confine.Rung2Landlock, AllowInet: true, ScratchDir: t.TempDir()}
	// Control first: WITHOUT the jail the planted fd is visible to a child, so the
	// test proves the jail is what closes it (not some unrelated fd hygiene).
	ctl := exec.Command("sh", "-c", "readlink /proc/self/fd/"+strconv.Itoa(fd)+" || echo GONE")
	ctlOut, _ := ctl.CombinedOutput()
	if !strings.Contains(string(ctlOut), "hostname") {
		t.Skipf("planted fd not inherited by an ordinary child here (%q); test environment cannot show the leak", ctlOut)
	}

	res, err := ExecWithRedaction(context.Background(),
		"readlink /proc/self/fd/"+strconv.Itoa(fd)+" || echo GONE",
		ExecOpts{Confine: &spec, CaptureLimit: 4096})
	if err != nil {
		t.Fatalf("confined exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	if strings.Contains(res.Stdout, "hostname") {
		t.Errorf("planted fd leaked into the jail (stdout=%q); the worker must close fds above 2 before execve", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "GONE") {
		t.Errorf("expected the jailed readlink to fail (fd closed); stdout=%q", res.Stdout)
	}
}
