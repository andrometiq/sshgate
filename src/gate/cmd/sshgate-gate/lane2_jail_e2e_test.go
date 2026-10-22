//go:build linux && jail_e2e

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// lane2JailLeg builds the C client fixtures, a gate directory and the leg's
// ABI, and returns the fixture and gate directories.
func lane2JailLeg(t *testing.T, abi string) (dir, gateDir string) {
	t.Helper()
	dir = buildLane2Fixtures(t)
	gateDir = t.TempDir()
	withGateDir(t, gateDir)
	withReadSpec(t, abi, nil)
	return dir, gateDir
}

// lane2Nonce is the nonce of a sg-<mode>.<nonce> argument.
func lane2Nonce(mode string) string {
	_, nonce, _ := strings.Cut(mode, ".")
	return nonce
}

// lane2RanJailed reports whether the gate audited exactly one daemon read that
// ran in the read jail.
func lane2RanJailed(t *testing.T, gateDir string) bool {
	t.Helper()
	return lane2RanInJail(t, gateDir) && auditRecords(t, gateDir)[0]["net"] == false
}

// lane2RanInJail reports whether the gate audited exactly one daemon read that
// ran in the read jail, with or without network.
func lane2RanInJail(t *testing.T, gateDir string) bool {
	t.Helper()
	records := auditRecords(t, gateDir)
	return len(records) == 1 && records[0]["enforcement"] == "daemon-read" && records[0]["profile"] == confine.ProfileROv1
}

// lane2DeniedAt reports whether the gate audited exactly one read denied with
// reason.
func lane2DeniedAt(t *testing.T, gateDir, reason string) bool {
	t.Helper()
	records := auditRecords(t, gateDir)
	return len(records) == 1 && records[0]["deny_reason"] == reason
}

// lane2UnixListen listens on path.
func lane2UnixListen(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

// lane2Received is the first line of the next connection within wait, or ""
// when none arrives; healthy is false for any error but the deadline.
func lane2Received(listener interface {
	SetDeadline(time.Time) error
	Accept() (net.Conn, error)
}, wait time.Duration) (line string, healthy bool) {
	if err := listener.SetDeadline(time.Now().Add(wait)); err != nil {
		return "", false
	}
	conn, err := listener.Accept()
	if err != nil {
		return "", errors.Is(err, os.ErrDeadlineExceeded)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	text, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSuffix(text, "\n"), true
}

// lane2Dial connects to path and sends line.
func lane2Dial(path, line string) error {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(line + "\n"))
	return err
}

// legLane2PluginNoExec is G-LANE2-PLUGIN-NOEXEC: the admitted client cannot
// run its plugin; only its own inode is executable.
func legLane2PluginNoExec(t *testing.T, abi string) {
	legLane2Program(t, abi, "G-LANE2-PLUGIN-NOEXEC", "exec", "plugin-ran", "exec:EACCES\n")
}

// legLane2MemfdNoExec is G-L2-MEMFD-NOEXEC: the client cannot run a memfd copy
// of its plugin either. The filter refuses its creation; with the deny mutated
// away, Landlock may still refuse its execution, which the memfd probe
// predicts for the registry.
func legLane2MemfdNoExec(t *testing.T, abi string) {
	legLane2Program(t, abi, "G-L2-MEMFD-NOEXEC", "memfd", "memfd-ran", "memfd:EPERM\n", "memfd-exec:EACCES\n")
}

// legLane2Program: the client's plugin either ran, or the client printed one of
// the refused lines and exited 1.
func legLane2Program(t *testing.T, abi, name, mode, effect string, refused ...string) {
	p := newProof(t, name)
	dir, gateDir := lane2JailLeg(t, abi)
	mode = lane2Mode(t, mode)
	ran := "PLUGIN-RAN " + lane2Nonce(mode) + "\n"
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode).Output()
	p.Control("exec", err == nil && string(direct) == ran)
	code, out, _ := runWith(t, "systemctl status "+mode)
	p.Effect(effect, out == ran)
	p.Jailed("lane2", lane2RanJailed(t, gateDir) && (out == ran && code == 0 || slices.Contains(refused, out) && code == 1))
	p.Observed("output", out == ran || slices.Contains(refused, out))
	p.Finish()
}

// legLane2SockPin is G-L2-SOCK-PIN: from Landlock ABI 9 a daemon read reaches
// only its pinned socket. Below it the client also reaches another socket its
// user may connect to: the documented residual.
func legLane2SockPin(t *testing.T, abi string) {
	p := newProof(t, "G-L2-SOCK-PIN")
	dir, gateDir := lane2JailLeg(t, abi)
	sockets := lane2SocketDir(t)
	pinned, other := filepath.Join(sockets, "s1"), filepath.Join(sockets, "s2")
	pinnedListener, otherListener := lane2UnixListen(t, pinned), lane2UnixListen(t, other)
	plantPin(t, gateDir, pinDeny+"docker_socket="+pinned+"\n", 0o644)
	lane2FixtureFile(t, dir, "sockets", pinned, other)
	err := lane2Dial(other, "control")
	line, healthy := lane2Received(otherListener, 2*time.Second)
	p.Control("connect", err == nil && line == "control")
	mode := lane2Mode(t, "unix-2")
	code, out, _ := runWith(t, "docker ps --filter name="+mode)
	first, firstHealthy := lane2Received(pinnedListener, 2*time.Second)
	second, secondHealthy := lane2Received(otherListener, 2*time.Second)
	p.Jailed("lane2", code == 0 && first == lane2Nonce(mode) && lane2RanJailed(t, gateDir))
	p.Observed("listener", healthy && firstHealthy && secondHealthy)
	if residual := p.caseDef.ResidualABIs[p.abi]; residual != "" {
		if second != lane2Nonce(mode) {
			t.Fatalf("below Landlock ABI 9 the unpinned socket was expected to accept: %q", out)
		}
		p.Residual(residual)
		return
	}
	p.Effect("unpinned-connected", second == lane2Nonce(mode))
	if second == "" && out != "unix-1:connected\nunix-2:EACCES\n" {
		t.Fatalf("refused connect reported %q", out)
	}
	p.Finish()
}

// legLane2SockSwapAfterOpen is G-L2-SOCK-SWAP-AFTER-OPEN: a pinned socket
// replaced at its path after the jail granted it stays ungranted from Landlock
// ABI 9: the grant is on the original inode. The client signals the swap point
// by connecting once, so the swap happens after the jail is in place.
func legLane2SockSwapAfterOpen(t *testing.T, abi string) {
	p := newProof(t, "G-L2-SOCK-SWAP-AFTER-OPEN")
	dir, gateDir := lane2JailLeg(t, abi)
	path := filepath.Join(lane2SocketDir(t), "s")
	original := lane2UnixListen(t, path)
	original.SetUnlinkOnClose(false)
	plantPin(t, gateDir, pinDeny+"docker_socket="+path+"\n", 0o644)
	lane2FixtureFile(t, dir, "sockets", path)
	mode := lane2Mode(t, "unix-wait-1")
	swapped := make(chan *net.UnixListener, 1)
	go func() {
		defer close(swapped)
		if line, _ := lane2Received(original, 10*time.Second); line != lane2Nonce(mode) {
			return
		}
		if os.Remove(path) != nil {
			return
		}
		replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return
		}
		swapped <- replacement
		_ = os.WriteFile(filepath.Join(dir, "go"), nil, 0o644)
	}()
	code, out, _ := runWith(t, "docker ps --filter name="+mode)
	replacement := <-swapped
	if replacement == nil {
		t.Fatalf("SETUP: the handshake did not reach the swap: %q", out)
	}
	defer replacement.Close()
	again, healthy := lane2Received(replacement, 2*time.Second)
	err := lane2Dial(path, "control")
	control, controlHealthy := lane2Received(replacement, 2*time.Second)
	p.Control("connect", err == nil && control == "control")
	p.Jailed("lane2", code == 0 && lane2RanJailed(t, gateDir) && !strings.Contains(out, "handshake:timeout"))
	p.Observed("listener", healthy && controlHealthy)
	if residual := p.caseDef.ResidualABIs[p.abi]; residual != "" {
		if again != lane2Nonce(mode) {
			t.Fatalf("below Landlock ABI 9 the swapped socket was expected to accept: %q", out)
		}
		p.Residual(residual)
		return
	}
	p.Effect("swapped-connected", again == lane2Nonce(mode))
	if again == "" && out != "unix-again:EACCES\n" {
		t.Fatalf("refused connect reported %q", out)
	}
	p.Finish()
}

// legLane2NetOff is G-L2-NET-OFF: on a host pinned net=allow a daemon read
// still has no network. With only the gate's Net=false removed the Spec is
// refused before any clone; with both walls removed the client connects.
func legLane2NetOff(t *testing.T, abi string) {
	p := newProof(t, "G-L2-NET-OFF")
	dir, gateDir := lane2JailLeg(t, abi)
	plantPin(t, gateDir, pinAllow, 0o644)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	lane2FixtureFile(t, dir, "tcp", listener.Addr().String())
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err == nil {
		_, err = conn.Write([]byte("control\n"))
		conn.Close()
	}
	line, healthy := lane2Received(listener, 2*time.Second)
	p.Control("connect", err == nil && line == "control")
	mode := lane2Mode(t, "tcp")
	code, out, _ := runWith(t, "systemctl status "+mode)
	accepted, acceptHealthy := lane2Received(listener, 2*time.Second)
	refusedSpec := code == exitNoPermVal && out == "" && lane2DeniedAt(t, gateDir, "jail:failed:spec:EINVAL")
	p.Effect("tcp-connected", accepted == lane2Nonce(mode))
	p.Abort("spec", refusedSpec)
	p.Jailed("lane2", refusedSpec || lane2RanInJail(t, gateDir) && (out == "tcp:connected\n" || out == "tcp:EPERM\n"))
	p.Observed("listener", healthy && acceptHealthy && (accepted == "") == (out != "tcp:connected\n"))
	p.Finish()
}

// legLane2Env is G-L2-ENV: the client gets exactly Lane2Env, never the gate's
// environment.
func legLane2Env(t *testing.T, abi string) {
	p := newProof(t, "G-L2-ENV")
	dir, gateDir := lane2JailLeg(t, abi)
	mode := lane2Mode(t, "report")
	canary := "SG_ENV_CANARY=" + lane2Nonce(mode)
	t.Setenv("SG_ENV_CANARY", lane2Nonce(mode))
	t.Setenv("DOCKER_HOST", "tcp://192.0.2.1:2375")
	t.Setenv("SYSTEMD_PAGER", "cat")
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode).Output()
	var report execReport
	p.Control("env", err == nil && json.Unmarshal(direct, &report) == nil && slices.Contains(report.Env, canary))
	code, out, _ := runWith(t, "systemctl status "+mode)
	report = execReport{}
	parsed := json.Unmarshal([]byte(out), &report) == nil
	p.Effect("env-leaked", slices.Contains(report.Env, canary))
	p.Jailed("lane2", code == 0 && parsed && lane2RanJailed(t, gateDir))
	p.Observed("report", slices.Equal(report.Env, confine.Lane2Env()) || slices.Contains(report.Env, canary))
	p.Finish()
}

// withAfterAdmit sets lane2AfterAdmitHook for the leg.
func withAfterAdmit(t *testing.T, hook func(*lane2Execution)) {
	t.Helper()
	lane2AfterAdmitHook = hook
	t.Cleanup(func() { lane2AfterAdmitHook = nil })
}

// legLane2IdentityBinary is G-L2-IDENTITY-BINARY: a client replaced after
// admission is refused by the jail's identity check, so nothing runs.
func legLane2IdentityBinary(t *testing.T, abi string) {
	p := newProof(t, "G-L2-IDENTITY-BINARY")
	dir, gateDir := lane2JailLeg(t, abi)
	replacement := lane2Replacement(t, dir)
	mode := lane2Mode(t, "report")
	replaced := "REPLACED-RAN " + lane2Nonce(mode) + "\n"
	direct, err := exec.Command(replacement, "status", mode).Output()
	p.Control("exec", err == nil && string(direct) == replaced)
	withAfterAdmit(t, func(*lane2Execution) {
		if err := os.Rename(replacement, filepath.Join(dir, "systemctl")); err != nil {
			t.Error(err)
		}
	})
	code, out, _ := runWith(t, "systemctl status "+mode)
	p.Observed("output", out == "" || out == replaced)
	legLane2IdentityOutcome(t, p, gateDir, code, out == replaced, out, "replaced-ran")
}

// legLane2IdentityInterp is G-L2-IDENTITY-INTERP: an interpreter replaced
// after admission is refused the same way.
func legLane2IdentityInterp(t *testing.T, abi string) {
	p := newProof(t, "G-L2-IDENTITY-INTERP")
	dir, gateDir := lane2JailLeg(t, abi)
	host, err := filepath.EvalSymlinks(lane2HostInterp(t, filepath.Join(dir, "systemctl")))
	if err != nil {
		t.Fatal(err)
	}
	loader, err := os.ReadFile(host)
	if err != nil {
		t.Fatal(err)
	}
	loaders := filepath.Join(dir, "ld")
	if err := os.Mkdir(loaders, 0o755); err != nil || os.Chmod(loaders, 0o755) != nil {
		t.Fatal(err)
	}
	lane2Write(t, filepath.Join(loaders, "ld.so"), loader, 0o755)
	lane2Write(t, filepath.Join(loaders, ".replacement"), loader, 0o755)
	lane2BuildClient(t, filepath.Join(dir, "systemctl"), "-Wl,--dynamic-linker="+filepath.Join(loaders, "ld.so"))
	mode := lane2Mode(t, "report")
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode).Output()
	p.Control("exec", err == nil && lane2Reported(direct, mode))
	withAfterAdmit(t, func(*lane2Execution) {
		if err := os.Rename(filepath.Join(loaders, ".replacement"), filepath.Join(loaders, "ld.so")); err != nil {
			t.Error(err)
		}
	})
	code, out, _ := runWith(t, "systemctl status "+mode)
	p.Observed("output", out == "" || lane2Reported([]byte(out), mode))
	legLane2IdentityOutcome(t, p, gateDir, code, lane2Reported([]byte(out), mode), out, "replaced-ran")
}

// legLane2IdentitySocket is G-L2-IDENTITY-SOCKET: a pinned socket closed,
// unlinked and re-bound at its path after admission is refused. The admission
// reference still holds the original inode, so its number cannot be reused.
func legLane2IdentitySocket(t *testing.T, abi string) {
	p := newProof(t, "G-L2-IDENTITY-SOCKET")
	dir, gateDir := lane2JailLeg(t, abi)
	path := filepath.Join(lane2SocketDir(t), "s")
	original := lane2UnixListen(t, path)
	plantPin(t, gateDir, pinDeny+"docker_socket="+path+"\n", 0o644)
	lane2FixtureFile(t, dir, "sockets", path)
	var replacement *net.UnixListener
	withAfterAdmit(t, func(plan *lane2Execution) {
		admitted := plan.sockets[0]
		original.Close() // unlinks path
		var err error
		if replacement, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"}); err != nil {
			t.Error(err)
			return
		}
		var held, now syscall.Stat_t
		if syscall.Fstat(int(admitted.File.Fd()), &held) != nil || syscall.Stat(path, &now) != nil ||
			(confine.FileID{Dev: uint64(held.Dev), Ino: held.Ino}) != admitted.ID || held.Nlink != 0 || now.Ino == held.Ino {
			t.Errorf("the admission reference no longer holds the original socket: held %+v, now %+v", held, now)
		}
	})
	mode := lane2Mode(t, "unix-1")
	code, out, _ := runWith(t, "docker ps --filter name="+mode)
	if replacement == nil {
		t.Fatal("SETUP: the replacement listener was not bound")
	}
	defer replacement.Close()
	accepted, healthy := lane2Received(replacement, 2*time.Second)
	err := lane2Dial(path, "control")
	control, controlHealthy := lane2Received(replacement, 2*time.Second)
	p.Control("connect", err == nil && control == "control")
	p.Observed("listener", healthy && controlHealthy)
	legLane2IdentityOutcome(t, p, gateDir, code, accepted == lane2Nonce(mode), out, "replaced-accepted")
}

// legLane2IdentityOutcome finishes an identity leg: refused at lane2id with no
// output, or, under the mutation, the replaced object in use.
func legLane2IdentityOutcome(t *testing.T, p *gateProof, gateDir string, code int, replaced bool, out, effect string) {
	t.Helper()
	p.Effect(effect, replaced)
	refused := code == exitNoPermVal && out == "" && lane2DeniedAt(t, gateDir, "jail:failed:lane2id:ESTALE")
	p.Jailed("lane2", refused || replaced && lane2RanJailed(t, gateDir))
	p.Finish()
}

// The characterisation legs record what a daemon read can still do in its jail.

// legLane2Loader is C-L2-LOADER: the admitted interpreter can load another
// readable ELF (the accepted loader route, R-L2-LOADER-ROUTE). If it stops
// working, THREAT-MODEL's account of the route must change.
func legLane2Loader(t *testing.T, abi string) {
	p := newProof(t, "C-L2-LOADER")
	_, gateDir := lane2JailLeg(t, abi)
	code, out, stderr := runWith(t, "systemctl status "+lane2Mode(t, "loader"))
	if code != 0 || !strings.HasPrefix(out, "uid=") {
		t.Fatalf("the loader route did not run id: exit %d, %q %q", code, out, stderr)
	}
	p.Jailed("loader", lane2RanJailed(t, gateDir))
	p.Residual(p.caseDef.ResidualABIs[p.abi])
}

// legLane2Reexec is C-L2-REEXEC: the client may re-exec itself (the same,
// granted inode).
func legLane2Reexec(t *testing.T, abi string) {
	p := newProof(t, "C-L2-REEXEC")
	_, gateDir := lane2JailLeg(t, abi)
	mode := lane2Mode(t, "reexec")
	code, out, _ := runWith(t, "systemctl status "+mode)
	p.Jailed("reexec", code == 0 && lane2Reported([]byte(out), "sg-report."+lane2Nonce(mode)) && lane2RanJailed(t, gateDir))
	p.Finish()
}

// legLane2Outcome is a characterisation leg whose client prints want.
func legLane2Outcome(t *testing.T, abi, name, obligation, mode, want string) {
	p := newProof(t, name)
	_, gateDir := lane2JailLeg(t, abi)
	_, out, _ := runWith(t, "systemctl status "+lane2Mode(t, mode))
	p.Jailed(obligation, out == want && lane2RanJailed(t, gateDir))
	p.Finish()
}

// legLane2Abstract is C-L2-ABSTRACT: from Landlock ABI 6 the client cannot
// reach an abstract socket; below it, it can (R-L2-ABSTRACT-BELOW-ABI6).
func legLane2Abstract(t *testing.T, abi string) {
	p := newProof(t, "C-L2-ABSTRACT")
	dir, gateDir := lane2JailLeg(t, abi)
	name := "sg-abstract-" + lane2Nonce(lane2Mode(t, "x"))
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "@" + name, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	lane2FixtureFile(t, dir, "abstract", name)
	mode := lane2Mode(t, "abstract")
	_, out, _ := runWith(t, "systemctl status "+mode)
	accepted, _ := lane2Received(listener, 2*time.Second)
	if residual := p.caseDef.ResidualABIs[p.abi]; residual != "" {
		p.Jailed("abstract", out == "abstract:connected\n" && accepted == lane2Nonce(mode) && lane2RanJailed(t, gateDir))
		p.Residual(residual)
		return
	}
	p.Jailed("abstract", out == "abstract:EPERM\n" && accepted == "" && lane2RanJailed(t, gateDir))
	p.Finish()
}

// TestLane2HeldFDsClosedJailed: no admitted fd outlives a daemon read that ran
// in the jail, or one whose jail Failed at the identity check. Each row's audit
// proves the jail path ran; an Absent jail fails the test (requireJail skips,
// and the target fails on any skip).
func TestLane2HeldFDsClosedJailed(t *testing.T) {
	requireJail(t)
	buildLane2Fixtures(t)
	for _, row := range []struct {
		name   string
		change func(*confine.Spec)
		code   int
		ran    func(map[string]any) bool
	}{
		{"run", nil, exitOK, func(r map[string]any) bool {
			return r["enforcement"] == "daemon-read" && r["profile"] == confine.ProfileROv1 && r["net"] == false
		}},
		{"failed setup", func(spec *confine.Spec) { spec.InjectFailAt = "lane2id:EACCES" }, exitNoPermVal,
			func(r map[string]any) bool { return r["deny_reason"] == "jail:failed:lane2id:EACCES" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			withReadSpec(t, "native", row.change)
			lane2HeldFDsRow(t, dir, row.code, row.ran)
		})
	}
}

// lane2Contacts accepts every connection on listener, recording each one's
// first line and closing it, until the returned stop is called.
func lane2Contacts(listener *net.UnixListener) (stop func() []string) {
	lines := make(chan []string, 1)
	go func() {
		var got []string
		for {
			conn, err := listener.Accept()
			if err != nil {
				lines <- got
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, _ := bufio.NewReader(conn).ReadString('\n')
			conn.Close()
			got = append(got, strings.TrimSpace(line))
		}
	}()
	return func() []string {
		_ = listener.SetDeadline(time.Now())
		return <-lines
	}
}

// TestLane2DockerHostContact: the installed docker client contacts exactly the
// socket admission admitted. docker trims trailing white space from --host, so
// for a trusted link to "sg.sock " it would dial "sg.sock", a name another
// user may be able to create: the control shows the client doing so, and the
// gate refuses that endpoint before anything runs. For a name docker keeps,
// jailed and as the forced-Absent fallback, only the admitted listener is
// contacted.
func TestLane2DockerHostContact(t *testing.T) {
	requireJail(t)
	const client = "/usr/bin/docker"
	if _, err := os.Stat(client); err != nil {
		t.Fatalf("SETUP: docker client missing: %v", err)
	}
	previousUIDs, previousEndpoints := lane2TrustedUIDs, lane2SystemEndpoints
	lane2TrustedUIDs = []uint32{0, uint32(os.Getuid())}
	t.Cleanup(func() { lane2TrustedUIDs, lane2SystemEndpoints = previousUIDs, previousEndpoints })
	watch := func(dir, name string) func() []string {
		return lane2Contacts(lane2UnixListen(t, filepath.Join(dir, name)))
	}
	link := func(dir, name string) {
		lane2SystemEndpoints.docker = filepath.Join(dir, "docker")
		if err := os.Symlink(name, lane2SystemEndpoints.docker); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("rewritten name refused", func(t *testing.T) {
		dir := lane2SocketDir(t)
		admitted, dialed := watch(dir, "sg.sock "), watch(dir, "sg.sock")
		control := exec.Command(client, "--host=unix://"+filepath.Join(dir, "sg.sock "), "ps")
		control.Env = confine.Lane2Env()
		_ = control.Run()
		if a, d := admitted(), dialed(); len(a) != 0 || len(d) == 0 {
			t.Fatalf("CONTROL: docker did not rewrite the name: admitted %q, dialed %q", a, d)
		}
		dir = lane2SocketDir(t)
		admitted, dialed = watch(dir, "sg.sock "), watch(dir, "sg.sock")
		link(dir, "sg.sock ")
		gateDir := t.TempDir()
		withGateDir(t, gateDir)
		code, out, _ := runWith(t, "docker ps")
		if a, d := admitted(), dialed(); code != exitNoPermVal || out != "" || len(a) != 0 || len(d) != 0 || !lane2DeniedAt(t, gateDir, "lane2:admit:endpoint") {
			t.Fatalf("exit %d %q, admitted %q, dialed %q, audit %v; want refused at admission with no contact", code, out, a, d, auditRecords(t, gateDir))
		}
	})
	for _, route := range []struct {
		name   string
		change func(*confine.Spec)
		jailed bool
	}{{"jailed", nil, true}, {"fallback", func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock }, false}} {
		t.Run("admitted name "+route.name, func(t *testing.T) {
			dir := lane2SocketDir(t)
			admitted, other := watch(dir, "sg sock"), watch(dir, "sg")
			link(dir, "sg sock")
			gateDir := t.TempDir()
			withGateDir(t, gateDir)
			withReadSpec(t, "native", route.change)
			runWith(t, "docker ps") // the fake daemon answers nothing: only the contact counts
			records := auditRecords(t, gateDir)
			ran := len(records) == 1 && records[0]["enforcement"] == "daemon-read" && (records[0]["profile"] == confine.ProfileROv1) == route.jailed
			if a, o := admitted(), other(); !ran || len(a) == 0 || len(o) != 0 {
				t.Fatalf("admitted %q, other %q, audit %v; want only the admitted socket contacted on the %s route", a, o, records, route.name)
			}
		})
	}
}
