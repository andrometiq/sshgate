//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// lane2Listen creates a listening socket at dir/name with mode.
func lane2Listen(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// lane2SocketDir is a 0755 directory short enough for socket paths.
func lane2SocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "l2-endpoint-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLane2EndpointChecks(t *testing.T) {
	withLane2Bins(t)
	base := lane2SystemEndpoints
	euid := uint32(os.Geteuid())
	const nonRoot = 12345
	type outcome struct {
		endpoint, refusal string
		failed            bool
		held              int
	}
	admit := func(t *testing.T, client string, pin pinState, euid uint32) outcome {
		t.Helper()
		var plan lane2Execution
		defer plan.Close()
		endpoint, refusal, err := plan.admitEndpoints(client, pin, euid)
		for _, file := range plan.held {
			var held, outside syscall.Stat_t
			if syscall.Fstat(int(file.Fd()), &held) != nil || syscall.Stat(file.Name(), &outside) != nil || held.Ino != outside.Ino || held.Dev != outside.Dev {
				t.Errorf("held fd %s is not the socket at its path", file.Name())
			}
		}
		return outcome{endpoint, refusal, err != nil, len(plan.held)}
	}
	pinned := func(path string) pinState { return pinState{valid: true, pin: confine.Pin{DockerSocket: path}} }
	missing := filepath.Join(t.TempDir(), "missing")
	regular := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name   string
		setup  func(t *testing.T) (client string, pin pinState, euid uint32)
		want   outcome
		target func() string // the endpoint want names, once setup ran
	}{
		{"docker 0660 socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.docker = lane2Listen(t, lane2SocketDir(t), "docker", 0o660)
			return "docker", pinState{}, euid
		}, outcome{held: 1}, func() string { return lane2SystemEndpoints.docker }},
		{"docker 0666 socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.docker = lane2Listen(t, lane2SocketDir(t), "docker", 0o666)
			return "docker", pinState{}, euid
		}, outcome{held: 1}, func() string { return lane2SystemEndpoints.docker }},
		{"docker missing socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.docker = missing
			return "docker", pinState{}, euid
		}, outcome{refusal: "endpoint", failed: true}, nil},
		{"docker regular file", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.docker = regular
			return "docker", pinState{}, euid
		}, outcome{refusal: "endpoint", held: 1}, func() string { return regular }},
		{"docker wrong owner", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.docker = lane2Listen(t, lane2SocketDir(t), "docker", 0o666)
			lane2Untrust(t, lane2SystemEndpoints.docker)
			return "docker", pinState{}, euid
		}, outcome{refusal: "endpoint", held: 1}, func() string { return lane2SystemEndpoints.docker }},
		{"docker group-writable parent", func(t *testing.T) (string, pinState, uint32) {
			dir := lane2SocketDir(t)
			lane2SystemEndpoints.docker = lane2Listen(t, dir, "docker", 0o660)
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
			return "docker", pinState{}, euid
		}, outcome{refusal: "endpoint", held: 1}, func() string { return lane2SystemEndpoints.docker }},
		{"pinned docker_socket wins over the system socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.docker = missing
			return "docker", pinned(lane2Listen(t, lane2SocketDir(t), "pinned", 0o600)), euid
		}, outcome{held: 1}, nil},
		{"pinned docker_socket through a link is rendered resolved", func(t *testing.T) (string, pinState, uint32) {
			dir := lane2SocketDir(t)
			lane2Listen(t, dir, "pinned", 0o600)
			if err := os.Symlink("pinned", filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
			return "docker", pinned(filepath.Join(dir, "link")), euid
		}, outcome{held: 1}, nil},
		{"pinned docker_socket owned by another uid", func(t *testing.T) (string, pinState, uint32) {
			if euid != 0 {
				// A root-owned socket under root-owned directories: only the owner fails.
				const bus = "/run/dbus/system_bus_socket"
				if _, err := os.Stat(bus); err != nil {
					t.Skipf("no root-owned socket to pin: %v", err)
				}
				return "docker", pinned(bus), euid
			}
			path := lane2Listen(t, lane2SocketDir(t), "pinned", 0o666)
			if err := os.Chown(path, 65534, -1); err != nil {
				t.Fatal(err)
			}
			return "docker", pinned(path), euid
		}, outcome{refusal: "endpoint", held: 1}, nil},
		{"a damaged pin's docker_socket is not used", func(t *testing.T) (string, pinState, uint32) {
			return "docker", pinState{damaged: "x", pin: confine.Pin{DockerSocket: missing}}, euid
		}, outcome{held: 1}, func() string { return lane2SystemEndpoints.docker }},
		{"systemctl non-root reaches the bus only", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.private = regular
			return "systemctl", pinState{}, nonRoot
		}, outcome{held: 1}, nil},
		{"systemctl non-root without the bus", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.bus = missing
			return "systemctl", pinState{}, nonRoot
		}, outcome{refusal: "endpoint", failed: true}, nil},
		{"systemctl non-root bus wrong owner", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.bus = lane2Listen(t, lane2SocketDir(t), "bus", 0o666)
			lane2Untrust(t, lane2SystemEndpoints.bus)
			return "systemctl", pinState{}, nonRoot
		}, outcome{refusal: "endpoint", held: 1}, nil},
		{"systemctl root holds both sockets", func(t *testing.T) (string, pinState, uint32) {
			return "systemctl", pinState{}, 0
		}, outcome{held: 2}, nil},
		{"systemctl root with only the bus", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.private = missing
			return "systemctl", pinState{}, 0
		}, outcome{held: 1}, nil},
		{"systemctl root with the private socket absent under a writable directory", func(t *testing.T) (string, pinState, uint32) {
			dir := lane2SocketDir(t)
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
			lane2SystemEndpoints.private = filepath.Join(dir, "private")
			return "systemctl", pinState{}, 0
		}, outcome{refusal: "endpoint", held: 1}, nil},
		{"systemctl root with only the private socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.bus = missing
			return "systemctl", pinState{}, 0
		}, outcome{held: 1}, nil},
		{"systemctl root with neither socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.bus, lane2SystemEndpoints.private = missing, missing
			return "systemctl", pinState{}, 0
		}, outcome{refusal: "endpoint", failed: true}, nil},
		{"systemctl root private socket not a socket", func(t *testing.T) (string, pinState, uint32) {
			lane2SystemEndpoints.private = regular
			return "systemctl", pinState{}, 0
		}, outcome{refusal: "endpoint", held: 2}, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			lane2SystemEndpoints = base
			oldUIDs := lane2TrustedUIDs
			t.Cleanup(func() { lane2SystemEndpoints, lane2TrustedUIDs = base, oldUIDs })
			client, pin, uid := row.setup(t)
			want := row.want
			switch {
			case row.target != nil:
				want.endpoint = row.target()
			case client == "docker" && !want.failed:
				want.endpoint, _ = filepath.EvalSymlinks(pin.pin.DockerSocket)
			}
			if got := admit(t, client, pin, uid); got != want {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

// TestLane2CanonicalArgvGolden: every golden line through lane2Plan, with the
// system docker socket and with a pinned docker_socket; argv[0] is the
// matched fixed-directory name.
func TestLane2CanonicalArgvGolden(t *testing.T) {
	bin := withLane2Bins(t)
	socket := lane2Listen(t, lane2SocketDir(t), "pinned", 0o600)
	for _, pin := range []struct {
		state pinState
		host  string
	}{{pinState{}, lane2SystemEndpoints.docker}, {pinState{valid: true, pin: confine.Pin{DockerSocket: socket}}, socket}} {
		for line, golden := range lane2Golden {
			want := []string{filepath.Join(bin, strings.Fields(line)[0])}
			for _, token := range golden {
				want = append(want, strings.Replace(token, "--host=unix:///run/docker.sock", "--host=unix://"+pin.host, 1))
			}
			plan, matched, refusal := lane2Plan(line, pin.state)
			plan.Close()
			if !matched || refusal != "" || !reflect.DeepEqual(plan.argv, want) {
				t.Errorf("lane2Plan(%q) = %q, matched=%v refusal=%q; want %q", line, plan.argv, matched, refusal, want)
			}
		}
	}
}

// TestLane2HeldFDsClosed: no admitted fd outlives the read on any P3.1 path.
func TestLane2HeldFDsClosed(t *testing.T) {
	withLane2Bins(t)
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	base := lane2SystemEndpoints
	for _, row := range []struct {
		name, pin string
		setup     func()
		code      int
	}{
		{"run", "", func() {}, exitOK},
		{"admit refusal", "", func() { lane2SystemEndpoints.docker = filepath.Join(t.TempDir(), "missing") }, exitNoPermVal},
		{"confinement required", pinAllow, func() {}, exitNoPermVal},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			if row.pin != "" {
				plantPin(t, dir, row.pin, 0o644)
			}
			lane2SystemEndpoints = base
			t.Cleanup(func() { lane2SystemEndpoints = base })
			row.setup()
			runWith(t, "docker ps") // the first read opens the gate's own long-lived files
			before := count()
			if code, _, stderr := runWith(t, "docker ps"); code != row.code {
				t.Fatalf("exit = %d, want %d: %s", code, row.code, stderr)
			}
			if after := count(); after != before {
				t.Errorf("fds before %d, after %d", before, after)
			}
		})
	}
}
