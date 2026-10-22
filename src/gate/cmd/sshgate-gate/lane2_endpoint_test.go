//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"

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

// TestLane2HeldFDsClosed: no admitted fd outlives the read on the paths that
// need no jail: an admission refusal, the forced-Absent fallback and a
// cancelled session. Each row's audit proves which path ran. The jailed run
// and a Failed jail are TestLane2HeldFDsClosedJailed (jail_e2e). The client is
// the C fixture, never the race-built test binary.
func TestLane2HeldFDsClosed(t *testing.T) {
	buildLane2Fixtures(t)
	base, previousHook, previousExecute := lane2SystemEndpoints, readSpecHook, executeCommand
	for _, row := range []struct {
		name  string
		setup func()
		code  int
		ran   func(record map[string]any) bool
	}{
		{"admit refusal", func() { lane2SystemEndpoints.docker = filepath.Join(t.TempDir(), "missing") }, exitNoPermVal,
			func(r map[string]any) bool { return r["deny_reason"] == "lane2:admit:endpoint" }},
		{"absent fallback", func() { readSpecHook = func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock } }, exitOK,
			func(r map[string]any) bool {
				return r["enforcement"] == "daemon-read" && r["profile"] == nil && r["net"] == true && r["jail_absent"] != nil
			}},
		{"cancelled", func() {
			executeCommand = func(context.Context, string, gate.ExecOpts) (gate.ExecResult, error) {
				return gate.ExecResult{ExitCode: -1}, context.Canceled
			}
		}, exitCancelled, func(r map[string]any) bool { return r["deny_reason"] == "cancelled" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			t.Cleanup(func() { lane2SystemEndpoints, readSpecHook, executeCommand = base, previousHook, previousExecute })
			row.setup()
			lane2HeldFDsRow(t, dir, row.code, row.ran)
		})
	}
}

// lane2HeldFDsRow runs one daemon read twice (the first opens the gate's own
// long-lived files) and requires the second to exit code, leave the process's
// fd count unchanged and be audited as ran describes.
func lane2HeldFDsRow(t *testing.T, gateDir string, code int, ran func(map[string]any) bool) {
	t.Helper()
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	const command = "docker inspect sg-report.0"
	runWith(t, command)
	before := count()
	if got, _, stderr := runWith(t, command); got != code {
		t.Fatalf("exit = %d, want %d: %s", got, code, stderr)
	}
	if after := count(); after != before {
		t.Errorf("fds before %d, after %d", before, after)
	}
	if records := auditRecords(t, gateDir); len(records) != 2 || !ran(records[1]) {
		t.Errorf("the read did not take the row's path: audit %v", records)
	}
}

// unitLane2SpecNet is U-Lane2SpecNet: a daemon read's Spec never has network,
// whatever the pin or a grant, and keeps the strictness and accepted
// filesystems a plain read would get; a daemon-read Spec with network is
// refused at "spec" before any clone. P-L2-NET-OFF and P-L2-SPEC-NET each flip
// a row.
func unitLane2SpecNet(t *testing.T) {
	p := newProof(t, "U-Lane2SpecNet")
	withLane2Bins(t)
	plan, matched, refusal := lane2Plan("docker ps", pinState{})
	defer plan.Close()
	if !matched || refusal != "" {
		t.Fatalf("SETUP: daemon read not admitted: %q", refusal)
	}
	changed := false
	for _, pin := range []pinState{{}, {valid: true, pin: confine.Pin{Profile: confine.ProfileROv1}},
		{valid: true, pin: confine.Pin{Profile: confine.ProfileROv1, Net: true, AcceptFS: []string{"network"}}}} {
		for _, grant := range []bool{false, true} {
			requires := requiresConfinement(pin, grant)
			spec, plain := lane2Spec(pin, requires, &plan), readSpec(pin, requires, grant)
			if spec.Strict != plain.Strict || spec.Cwd != "/" || spec.Lane2 == nil || !reflect.DeepEqual(spec.AcceptFS, plain.AcceptFS) {
				t.Fatalf("pin %+v grant=%v: spec %+v", pin, grant, spec)
			}
			changed = changed || spec.Net
		}
	}
	spec := lane2Spec(pinState{}, false, &plan)
	spec.Net = true
	var setup *confine.SetupError
	err := lane2SpecRefused(spec, plan.argv)
	changed = changed || !errors.As(err, &setup) || setup.Stage != "spec"
	p.Effect("decision", changed)
	p.Control("decision", true)
	p.Finish()
}

// lane2SpecRefused builds a daemon read's jail command and aborts it without
// starting it: the error is the Spec check's verdict, before any clone.
func lane2SpecRefused(spec confine.Spec, argv []string) error {
	jailed, err := spec.Command(context.Background(), confine.EncodeArgv(argv))
	if jailed != nil {
		jailed.Abort()
	}
	return err
}

// TestLane2DockerHostExact: docker trims Unicode white space from --host and
// refuses a second "://" (docker/cli opts.ParseHost), so a docker socket whose
// resolved name it would rewrite is refused at admission. Each refused row has
// two listeners: the admitted name, and the name docker would dial instead.
func TestLane2DockerHostExact(t *testing.T) {
	withLane2Bins(t)
	base := lane2SystemEndpoints
	for _, row := range []struct {
		name     string
		admitted bool
	}{
		{"sg.sock", true}, {"sg sock", true}, {" sg.sock", true},
		{"sg.sock ", false}, {"sg.sock\t", false}, {"sg.sock\n", false}, {"sg.sock\v", false}, {"sg.sock\f", false},
		{"sg.sock\r", false}, {"sg.sock\u0085", false}, {"sg.sock\u00a0", false}, {"sg.sock\u2003", false}, {"sg.sock\u3000", false},
	} {
		t.Run(strconv.Quote(row.name), func(t *testing.T) {
			t.Cleanup(func() { lane2SystemEndpoints = base })
			dir := lane2SocketDir(t)
			admitted := lane2Listen(t, dir, row.name, 0o660)
			if !row.admitted {
				lane2Listen(t, dir, "sg.sock", 0o660)
			}
			// A trusted link to the socket, as in /run/docker.sock -> /tmp/sg.sock<space>.
			lane2SystemEndpoints.docker = filepath.Join(dir, "docker")
			if err := os.Symlink(row.name, lane2SystemEndpoints.docker); err != nil {
				t.Fatal(err)
			}
			plan, matched, refusal := lane2Plan("docker ps", pinState{})
			plan.Close()
			switch {
			case !matched:
				t.Fatal("docker ps is not a daemon read")
			case row.admitted && (refusal != "" || !slices.Contains(plan.argv, "--host=unix://"+admitted)):
				t.Errorf("refusal %q, argv %q; want admitted with --host=unix://%s", refusal, plan.argv, admitted)
			case !row.admitted && refusal != "endpoint":
				t.Errorf("refusal %q, argv %q; want endpoint", refusal, plan.argv)
			}
		})
	}
	for path, want := range map[string]bool{"/run/docker.sock": true, "/a:/b": true, "/a://b": false, "/a/b ": false, "/a/b\u2028": false} {
		if got := lane2DockerDials(path); got != want {
			t.Errorf("lane2DockerDials(%q) = %v, want %v", path, got, want)
		}
	}
}
