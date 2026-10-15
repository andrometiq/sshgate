//go:build linux && jail_e2e

package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// TestJailMatrixPhase3 holds the gate's daemon-read legs, run through run() at
// the native Landlock ABI and at forced ABI 1. They run in-process: the
// fixture legs need the package-var seams.
func TestJailMatrixPhase3(t *testing.T) {
	spec := readSpec(pinState{}, false, false)
	res, err := gate.ExecWithRedaction(context.Background(), ":", gate.ExecOpts{Confine: &spec})
	var setup *confine.SetupError
	if res.ExitCode != 0 && errors.As(err, &setup) && attemptClass(setup, res) == confine.Absent {
		t.Skipf("SKIP jail: %s", confine.DenyReason(confine.Absent, setup.Stage, setup.Errno))
	}
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("G-L2-ADMIT-WRITABLE-DIR", func(t *testing.T) { legLane2Admit(t, abi, "G-L2-ADMIT-WRITABLE-DIR") })
			t.Run("G-L2-ADMIT-RUNPATH-ORIGIN", func(t *testing.T) { legLane2Admit(t, abi, "G-L2-ADMIT-RUNPATH-ORIGIN") })
			t.Run("G-L2-ADMIT-RUNPATH-UNTRUSTED", func(t *testing.T) { legLane2Admit(t, abi, "G-L2-ADMIT-RUNPATH-UNTRUSTED") })
			t.Run("G-L2-ADMIT-ENDPOINT", func(t *testing.T) { legLane2AdmitEndpoint(t, abi) })
			t.Run("G-L2-INTERP-UNTRUSTED", func(t *testing.T) { legLane2InterpUntrusted(t, abi) })
			t.Run("G-L2-GRAMMAR", func(t *testing.T) { legLane2Unadmitted(t, abi, "G-L2-GRAMMAR", "--sg-unlisted", "grammar-flag") })
			t.Run("G-L2-REDIRECT", func(t *testing.T) { legLane2Unadmitted(t, abi, "G-L2-REDIRECT", "--user", "redirect-flag") })
		})
	}
}

// legLane2Unadmitted: a daemon-read line carrying flag, which the grammar (and,
// for a redirect flag, the refusal list) does not admit, is no daemon read. It
// takes the normal read path, where the jailed real systemctl runs, so the
// fixture client never sees the flag.
func legLane2Unadmitted(t *testing.T, abi, name, flag, effect string) {
	p := newProof(t, name)
	dir := buildLane2Fixtures(t)
	gateDir := t.TempDir()
	withGateDir(t, gateDir)
	withReadSpec(t, abi, nil)
	mode := lane2Mode(t, "report")
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode, flag).Output()
	p.Control("argv", err == nil && lane2Reported(direct, mode, flag))

	code, out, _ := runWith(t, "systemctl status "+mode+" "+flag)
	passed := lane2Reported([]byte(out), mode, flag)
	p.Effect(effect, passed)
	recs := auditRecords(t, gateDir)
	daemonRead := len(recs) == 1 && recs[0]["enforcement"] == "daemon-read"
	jailed := len(recs) == 1 && recs[0]["enforcement"] == "kernel" && recs[0]["profile"] == "ro-v1"
	p.Jailed("lane2", passed && code == exitOK && daemonRead || !passed && jailed)
	p.Observed("output", passed || !strings.Contains(out, mode))
	p.Finish()
}

func legLane2Admit(t *testing.T, abi, name string) {
	p := newProof(t, name)
	dir := buildLane2Fixtures(t)
	gateDir := t.TempDir()
	withGateDir(t, gateDir)
	withReadSpec(t, abi, nil)
	mode := lane2Mode(t, "report")
	effect, reason, marker := "untrusted-ran", "binary", mode
	switch name {
	case "G-L2-ADMIT-WRITABLE-DIR":
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
	case "G-L2-ADMIT-RUNPATH-ORIGIN":
		effect, reason = "lib-ran", "search-tag"
		marker = "LIB-RAN " + lane2BuildSearch(t, dir, "$ORIGIN/lib", false)
	case "G-L2-ADMIT-RUNPATH-UNTRUSTED":
		effect, reason = "lib-ran", "search-tag"
		library := filepath.Join(dir, "lib")
		marker = "LIB-RAN " + lane2BuildSearch(t, dir, library, true)
		if err := os.Chmod(library, 0777); err != nil {
			t.Fatal(err)
		}
	}
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode).CombinedOutput()
	p.Control("exec", err == nil && strings.Contains(string(direct), marker))
	code, out, stderr := runWith(t, "systemctl status "+mode)
	ran := strings.Contains(out, marker)
	p.Effect(effect, ran)
	records := auditRecords(t, gateDir)
	denied := len(records) == 1 && records[0]["deny_reason"] == "lane2:admit:"+reason
	executed := len(records) == 1 && records[0]["enforcement"] == "daemon-read"
	p.Jailed("lane2", ran && code == 0 && executed || !ran && code == exitNoPermVal && denied && strings.Contains(stderr, "nothing ran"))
	p.Observed("output", ran || out == "")
	p.Finish()
}

// legLane2AdmitEndpoint: a pinned docker_socket owned by another uid is
// refused before the client runs. The socket is 0666, so only its owner fails
// admission, and a mutated run connects as the jailed root would.
func legLane2AdmitEndpoint(t *testing.T, abi string) {
	p := newProof(t, "G-L2-ADMIT-ENDPOINT")
	if os.Geteuid() != 0 {
		p.Omit("root-only")
		return
	}
	buildLane2Fixtures(t)
	gateDir := t.TempDir()
	withGateDir(t, gateDir)
	withReadSpec(t, abi, nil)
	socketDir, err := os.MkdirTemp("", "l2-endpoint-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	path := filepath.Join(socketDir, "docker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, err := range []error{os.Chmod(socketDir, 0o755), os.Chown(path, 65534, -1), os.Chmod(path, 0o666)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	plantPin(t, gateDir, pinDeny+"docker_socket="+path+"\n", 0o644)
	// received is the line the next connection sends, or "" when none arrives.
	healthy := true
	received := func() string {
		if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			healthy = false
			return ""
		}
		conn, err := listener.Accept()
		if err != nil {
			healthy = healthy && errors.Is(err, os.ErrDeadlineExceeded)
			return ""
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		return strings.TrimSuffix(line, "\n")
	}
	control, err := net.Dial("unix", path)
	if err == nil {
		_, err = control.Write([]byte("control\n"))
		control.Close()
	}
	p.Control("connect", err == nil && received() == "control")
	mode := lane2Mode(t, "host")
	nonce := strings.TrimPrefix(mode, "sg-host.")
	code, out, stderr := runWith(t, "docker inspect "+mode)
	accepted := received() == nonce
	p.Effect("endpoint-accepted", accepted)
	records := auditRecords(t, gateDir)
	denied := len(records) == 1 && records[0]["deny_reason"] == "lane2:admit:endpoint"
	executed := len(records) == 1 && records[0]["enforcement"] == "daemon-read"
	p.Jailed("lane2", accepted && code == 0 && executed && strings.Contains(out, "HOST-CONNECTED "+nonce) ||
		!accepted && code == exitNoPermVal && denied && out == "" && strings.Contains(stderr, "nothing ran"))
	p.Observed("listener", healthy)
	p.Finish()
}

// legLane2InterpUntrusted: a trusted client whose PT_INTERP names a loader in a
// world-writable directory is refused before it runs. The effect is the
// client's own report nonce, which only a run through that loader prints.
func legLane2InterpUntrusted(t *testing.T, abi string) {
	p := newProof(t, "G-L2-INTERP-UNTRUSTED")
	dir := buildLane2Fixtures(t)
	gateDir := t.TempDir()
	withGateDir(t, gateDir)
	withReadSpec(t, abi, nil)
	host, err := filepath.EvalSymlinks(lane2HostInterp(t, filepath.Join(dir, "systemctl")))
	if err != nil {
		t.Fatal(err)
	}
	loader, err := os.ReadFile(host)
	if err != nil {
		t.Fatal(err)
	}
	loaders := filepath.Join(dir, "ld")
	if err := os.Mkdir(loaders, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loaders, 0o777); err != nil {
		t.Fatal(err)
	}
	lane2Write(t, filepath.Join(loaders, "ld.so"), loader, 0o755)
	lane2BuildClient(t, filepath.Join(dir, "systemctl"), "-Wl,--dynamic-linker="+filepath.Join(loaders, "ld.so"))
	mode := lane2Mode(t, "report")
	direct, err := exec.Command(filepath.Join(dir, "systemctl"), "status", mode).Output()
	p.Control("exec", err == nil && lane2Reported(direct, mode))
	code, out, stderr := runWith(t, "systemctl status "+mode)
	ran := lane2Reported([]byte(out), mode)
	p.Effect("interp-ran", ran)
	records := auditRecords(t, gateDir)
	single := len(records) == 1
	p.Jailed("lane2", ran && code == 0 && single && records[0]["enforcement"] == "daemon-read" && records[0]["deny_reason"] == nil ||
		!ran && code == exitNoPermVal && single && records[0]["deny_reason"] == "lane2:admit:interp" && out == "" && strings.Contains(stderr, "nothing ran"))
	p.Observed("output", ran || out == "")
	p.Finish()
}
