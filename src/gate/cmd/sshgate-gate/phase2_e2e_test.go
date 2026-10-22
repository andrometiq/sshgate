//go:build linux && jail_e2e

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// TestJailMatrixPhase2 holds the gate's read-routing legs, run through run()
// at the native Landlock ABI and at forced ABI 1.
func TestJailMatrixPhase2(t *testing.T) {
	// Skip only a host without the jail. A Failed attempt is left to the
	// legs: under a mutation (a dropped mount namespace) it is the effect.
	spec := readSpec(pinState{}, false, false)
	res, err := gate.ExecWithRedaction(context.Background(), ":", gate.ExecOpts{Confine: &spec})
	var setup *confine.SetupError
	if res.ExitCode != 0 && errors.As(err, &setup) && attemptClass(setup, res) == confine.Absent {
		t.Skipf("SKIP jail: %s", confine.DenyReason(confine.Absent, setup.Stage, setup.Errno))
	}
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("G-CONFINE-REQUIRED-ABSENT", func(t *testing.T) { legConfineRequiredAbsent(t, abi) })
			t.Run("G-CONFINE-REQUIRED-LANE2", legConfineRequiredLane2)
			t.Run("G-STRICT-UNMET-FUSE", func(t *testing.T) { legUnmetFuse(t, abi, "G-STRICT-UNMET-FUSE", pinDeny, false) })
			t.Run("G-NET-STRICT-UNMET-FUSE", func(t *testing.T) { legUnmetFuse(t, abi, "G-NET-STRICT-UNMET-FUSE", "", true) })
			t.Run("G-UNPINNED-UNMET-FUSE", func(t *testing.T) { legUnmetFuse(t, abi, "G-UNPINNED-UNMET-FUSE", "", false) })
			t.Run("G-NSDROP-MNT", func(t *testing.T) { legNSDropMnt(t, abi) })
			t.Run("G-FAULT", func(t *testing.T) { legFault(t, abi) })
			t.Run("G-FAULT-ABSENT", func(t *testing.T) { legFaultAbsent(t, abi) })
			t.Run("G-INET-DENY", func(t *testing.T) { legInet(t, abi, "G-INET-DENY") })
			t.Run("G-INET-ALLOW", func(t *testing.T) { legInet(t, abi, "G-INET-ALLOW") })
			t.Run("G-GATE-SEAL", func(t *testing.T) { legGateSeal(t, abi) })
			t.Run("G-SEAL-GUARD", func(t *testing.T) { legSealGuard(t, abi) })
			t.Run("G-JAILVERB-LABEL", func(t *testing.T) { legJailVerbLabel(t, abi) })
			t.Run("G-JAILVERB-NOEXEC", func(t *testing.T) { legJailVerbNoExec(t, abi) })
			t.Run("G-SELFTEST-JAILED", func(t *testing.T) { legSelftestJailed(t, abi) })
			t.Run("G-SELFTEST-UNJAILED", func(t *testing.T) { legSelftestUnjailed(t, abi) })
			t.Run("G-PIN-REFUSED", func(t *testing.T) { legPinRefused(t, abi) })
		})
	}
}

// withReadSpec sets the test-only Spec hook: the leg's ABI plus change.
func withReadSpec(t *testing.T, abi string, change func(*confine.Spec)) {
	t.Helper()
	readSpecHook = func(spec *confine.Spec) {
		if abi == "abi1" {
			spec.ForceABI = 1
		}
		if change != nil {
			change(spec)
		}
	}
	t.Cleanup(func() { readSpecHook = nil })
}

func withNetGrant(t *testing.T) {
	t.Helper()
	forceNetGrant = true
	t.Cleanup(func() { forceNetGrant = false })
}

// countAttempts wraps the real executor and counts jail attempts and
// unconfined runs.
func countAttempts(t *testing.T) *fakeAttempt {
	t.Helper()
	counts := &fakeAttempt{}
	previous := executeCommand
	executeCommand = func(ctx context.Context, cmd string, opts gate.ExecOpts) (gate.ExecResult, error) {
		if opts.Confine != nil {
			counts.confined++
		} else {
			counts.fallback++
		}
		return gate.ExecWithRedaction(ctx, cmd, opts)
	}
	t.Cleanup(func() { executeCommand = previous })
	return counts
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// legConfineRequiredAbsent: a read that requires confinement (a network grant)
// on an unpinned host whose jail is Absent is denied, never run outside it.
func legConfineRequiredAbsent(t *testing.T, abi string) {
	p := newProof(t, "G-CONFINE-REQUIRED-ABSENT")
	readNamedWriter(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	twin, target := filepath.Join(dir, "twin"), seedTarget(t, dir)
	if err := os.WriteFile(twin, []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stat, err := exec.LookPath("stat")
	p.Control("edit", err == nil && exec.Command(stat, twin, "edited").Run() == nil && readFile(twin) == "edited\n")

	withNetGrant(t)
	withReadSpec(t, abi, func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock })
	code, _, _ := runWith(t, "stat "+target+" edited")
	recs := auditRecords(t, dir)
	ran := readFile(target) == "edited\n"
	p.Effect("ran-unconfined", ran)
	denied := code == exitNoPermVal && len(recs) == 1 && recs[0]["deny_reason"] == "jail:absent:landlock:ENOSYS"
	p.Jailed("edit", denied && !ran || ran && code == exitOK)
	p.Observed("target", ran || readFile(target) == "orig\n")
	p.Finish()
}

// legConfineRequiredLane2: on a host pinned net=allow a daemon read requires
// confinement, so it is refused before the daemon binary runs.
// legConfineRequiredLane2: a daemon read that must run confined (here through
// a network grant) is denied on a host whose jail is Absent; only the unpinned,
// not-required case falls back to the unjailed client.
func legConfineRequiredLane2(t *testing.T) {
	p := newProof(t, "G-CONFINE-REQUIRED-LANE2")
	bin := buildLane2Fixtures(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	withNetGrant(t)
	withReadSpec(t, "native", func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock })
	mode := lane2Mode(t, "report")
	out, err := exec.Command(filepath.Join(bin, "systemctl"), "status", mode).Output()
	p.Control("lane2", err == nil && lane2Reported(out, mode))

	code, out2, _ := runWith(t, "systemctl status "+mode)
	ran := lane2Reported([]byte(out2), mode)
	p.Effect("lane2-ran", ran)
	recs := auditRecords(t, dir)
	denied := code == exitNoPermVal && out2 == "" && len(recs) == 1 && recs[0]["deny_reason"] == "jail:absent:landlock:ENOSYS"
	p.Jailed("lane2", denied || ran && code == exitOK)
	p.Observed("lane2", ran || out2 == "")
	p.Finish()
}

// legUnmetFuse: a FUSE mount the jail must cover. With the covers in place the
// probe never reaches it. With the covers removed, a strict run (pinned, or
// requiring confinement) aborts at selfcheck, and a non-strict run reaches the
// FUSE server and records the gap in label_clause_unmet.
func legUnmetFuse(t *testing.T, abi, name, pin string, grant bool) {
	tools := gateFuseNamespace(t, name)
	if tools == nil {
		return
	}
	p := newProof(t, name)
	fixture := startGateFuse(t, tools.server, filepath.Join(t.TempDir(), "fuse"))
	p.Control("facility", fixture.control(t, filepath.Join(tools.bin, "cat")))

	dir := t.TempDir()
	withGateDir(t, dir)
	if pin != "" {
		plantPin(t, dir, pin, 0o644)
	}
	mark := fixture.mark(t)
	code, out := runTestGate(t, testGateConfig{Dir: dir, ABI: abi, Grant: grant}, tools.bin, "cat fuse-ioctl "+fixture.point+"/f 0x40085301 42")
	records := fixture.seal(t, mark)
	recs := auditRecords(t, dir)
	landed := slices.Contains(records, "IOCTL 42")
	var valid bool
	switch {
	case code == exitNoPermVal:
		p.Abort("selfcheck", true)
		valid = !landed && out == "" && len(recs) == 1 && recs[0]["deny_reason"] == "jail:failed:selfcheck"
	case landed:
		p.Effect("fuse-ioctl", true)
		valid = code == exitOK && strings.Contains(out, "ioctl=ok")
		if pin == "" && !grant {
			unmet, _ := recs[0]["label_clause_unmet"].([]any)
			valid = valid && slices.ContainsFunc(unmet, func(clause any) bool { return strings.HasPrefix(fmt.Sprint(clause), "fs-view:fuse") })
		}
	default:
		valid = code == 1 && strings.Contains(out, "open=2\n") && len(records) == 1 && records[0] == ""
	}
	p.Jailed("probe", valid)
	p.Observed("effects", true)
	p.Finish()
}

// runTestGate runs one forced-command read in a separate gate process (see
// testGateEnv), with path first on PATH.
func runTestGate(t *testing.T, config testGateConfig, path, command string) (int, string) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	gate := exec.Command(os.Args[0])
	gate.Env = append(os.Environ(), testGateEnv+"="+string(raw), "PATH="+path+string(os.PathListSeparator)+os.Getenv("PATH"), "SSH_ORIGINAL_COMMAND="+command)
	out, err := gate.Output()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("SETUP: test gate: %v", err)
	}
	return code, string(out)
}

// legNSDropMnt: the gate's attempt in a jail without its own mount namespace
// is Failed at nsverify — denied even unpinned, never a classifier fallback —
// and leaves the host mounts unchanged.
func legNSDropMnt(t *testing.T, abi string) {
	p := newProof(t, "G-NSDROP-MNT")
	dir := t.TempDir()
	withGateDir(t, dir)
	withReadSpec(t, abi, nil)
	counts := countAttempts(t)
	before := readFile("/proc/self/mountinfo")
	p.Control("intact", before != "")
	code, out, _ := runWith(t, "printf ok")
	recs := auditRecords(t, dir)
	aborted := code == exitNoPermVal
	p.Abort("nsverify", aborted)
	valid := code == exitOK && out == "ok"
	if aborted {
		valid = out == "" && len(recs) == 1 && strings.HasPrefix(fmt.Sprint(recs[0]["deny_reason"]), "jail:failed:nsverify") && counts.fallback == 0
	}
	p.Jailed("attempt", valid)
	p.Observed("mounts", readFile("/proc/self/mountinfo") == before)
	p.Finish()
}

// faultStages are every stage the worker can be made to fail; with EIO each is
// Failed.
var faultStages = []string{"spec", "cmdread", "nsverify", "mounts", "private", "setattr", "devnodes", "covers", "scratch", "fds", "cwd", "nnp", "caps", "rlimits", "landlock", "seccomp", "tsync", "session", "selfcheck", "exec"}

// legFault: a Failed setup stage denies on pinned and unpinned hosts alike,
// with one attempt and no fallback.
func legFault(t *testing.T, abi string) {
	p := newProof(t, "G-FAULT")
	readNamedWriter(t)
	control := t.TempDir()
	withGateDir(t, control)
	withReadSpec(t, abi, nil)
	code, out, _ := runWith(t, "printf ok")
	p.Control("intact", code == exitOK && out == "ok")
	valid := true
	for _, stage := range faultStages {
		for _, pinned := range []bool{false, true} {
			dir := t.TempDir()
			withGateDir(t, dir)
			if pinned {
				plantPin(t, dir, pinDeny, 0o644)
			}
			withReadSpec(t, abi, func(spec *confine.Spec) { spec.InjectFailAt = stage })
			counts := countAttempts(t)
			target := seedTarget(t, dir)
			code, out, _ := runWith(t, "stat "+target+" ran")
			want := "jail:failed:" + stage + ":EIO"
			if stage == "exec" {
				want = "jail:failed:exec:ENOENT"
			}
			recs := auditRecords(t, dir)
			if code != exitNoPermVal || out != "" || readFile(target) != "orig\n" || len(recs) != 1 || recs[0]["deny_reason"] != want || counts.confined != 1 || counts.fallback != 0 {
				valid = false
				t.Errorf("stage %s pinned=%v: exit %d, audit %v, attempts %+v", stage, pinned, code, recs, counts)
			}
		}
	}
	p.Jailed("attempt", valid)
	p.Finish()
}

// legFaultAbsent: an Absent setup stage runs the read once classifier-only on
// an unpinned host, with no worker line, and denies on a pinned one.
func legFaultAbsent(t *testing.T, abi string) {
	p := newProof(t, "G-FAULT-ABSENT")
	readNamedWriter(t)
	fallback, observed := true, true
	for _, inject := range []string{"setattr:ENOSYS", "private:EPERM", "landlock:ENOSYS", "seccomp:ENOSYS"} {
		for _, pinned := range []bool{false, true} {
			dir := t.TempDir()
			withGateDir(t, dir)
			if pinned {
				plantPin(t, dir, pinDeny, 0o644)
			}
			withReadSpec(t, abi, func(spec *confine.Spec) { spec.InjectFailAt = inject })
			target := seedTarget(t, dir)
			code, _, stderr := runWith(t, "stat "+target+" edited")
			recs := auditRecords(t, dir)
			if len(recs) != 1 {
				t.Fatalf("%s pinned=%v: audit %v", inject, pinned, recs)
			}
			_, unmet := recs[0]["label_clause_unmet"]
			ok := code == exitOK && stderr == "" && recs[0]["enforcement"] == "classifier" && recs[0]["net"] == true && recs[0]["jail_absent"] == inject && !unmet
			edited := readFile(target) == "edited\n"
			if pinned {
				ok = code == exitNoPermVal && recs[0]["deny_reason"] == "jail:absent:"+inject
				edited = readFile(target) == "orig\n"
			}
			if !ok || !edited {
				t.Errorf("%s pinned=%v: exit %d, stderr %q, audit %v", inject, pinned, code, stderr, recs)
			}
			fallback, observed = fallback && ok, observed && edited
		}
	}
	p.Jailed("fallback", fallback)
	p.Observed("target", observed)
	p.Finish()
}

// buildInetProbe plants the syscall probe as `cat`, a classifier read.
func buildInetProbe(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	build := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(dir, "cat"), "../../confine/testdata/probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build INET probe: %v\n%s", err, out)
	}
	return dir
}

// accepted reports whether the listener accepts a connection within a second.
func accepted(t *testing.T, listener *net.TCPListener) bool {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

// legInet: G-INET-DENY shows an unpinned or net=deny read cannot open an
// INET socket (and connects only with the seccomp network wall removed);
// G-INET-ALLOW shows a host pinned net=allow gives reads the network.
func legInet(t *testing.T, abi, name string) {
	p := newProof(t, name)
	networks := []string{"tcp4", "tcp6"}
	if listener, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		// CI must prove both families; elsewhere tcp4 still runs.
		if os.Getenv("SSHGATE_JAIL_CI") == "1" {
			t.Fatalf("SETUP: IPv6 loopback unavailable: %v", err)
		}
		t.Logf("tcp6 not run: IPv6 loopback unavailable: %v", err)
		networks = networks[:1]
	} else {
		listener.Close()
	}
	probes := buildInetProbe(t)
	withEnv(t, "PATH", probes+string(os.PathListSeparator)+os.Getenv("PATH"))
	pins := []string{"", pinDeny}
	if name == "G-INET-ALLOW" {
		pins = []string{pinAllow}
	}
	controls, jailed, observed := true, true, true
	for _, pin := range pins {
		for _, network := range networks {
			address, operation := "127.0.0.1:0", "dial-inet"
			if network == "tcp6" {
				address, operation = "[::1]:0", "dial-inet6"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Fatalf("SETUP: listen %s: %v", network, err)
			}
			tcp := listener.(*net.TCPListener)
			port := strconv.Itoa(tcp.Addr().(*net.TCPAddr).Port)
			if name == "G-INET-DENY" {
				out, err := exec.Command(filepath.Join(probes, "cat"), operation, port).CombinedOutput()
				controls = controls && err == nil && string(out) == "socket=ok\nconnect=ok\n" && accepted(t, tcp)
			}
			dir := t.TempDir()
			withGateDir(t, dir)
			if pin != "" {
				plantPin(t, dir, pin, 0o644)
			}
			withReadSpec(t, abi, nil)
			code, out, _ := runWith(t, "cat "+operation+" "+port)
			connected := accepted(t, tcp)
			listener.Close()
			recs := auditRecords(t, dir)
			ok := len(recs) == 1 && recs[0]["enforcement"] == "kernel"
			switch {
			case name == "G-INET-ALLOW":
				ok = ok && connected && code == exitOK && out == "socket=ok\nconnect=ok\n" && recs[0]["net"] == true && recs[0]["requires_confinement"] == true
			case connected:
				p.Effect("connected", true)
				ok = ok && code == exitOK && out == "socket=ok\nconnect=ok\n"
			default:
				ok = ok && code == 1 && out == "socket=1\n" && recs[0]["net"] == false
			}
			if !ok {
				t.Errorf("%s pin=%q %s: exit %d, stdout %q, connected %v, audit %v", name, pin, network, code, out, connected, recs)
			}
			jailed, observed = jailed && ok, observed && (connected || name == "G-INET-DENY")
		}
	}
	if name == "G-INET-DENY" {
		p.Control("connect", controls)
	}
	p.Jailed("connect", jailed)
	p.Observed("listener", observed)
	p.Finish()
}
