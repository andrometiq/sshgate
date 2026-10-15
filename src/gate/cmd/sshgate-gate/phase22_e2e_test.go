//go:build linux && jail_e2e

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// TestInProcessReadLeavesDumpable: a real jailed read through run() in this
// test binary records its seal instead of sealing, so the binary can attempt
// the jail again.
func TestInProcessReadLeavesDumpable(t *testing.T) {
	requireJail(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	before := sealCalls.Load()
	code, out, _ := runWith(t, "echo jailed")
	recs := auditRecords(t, dir)
	if code != exitOK || out != "jailed\n" || len(recs) != 1 || recs[0]["enforcement"] != "kernel" {
		t.Fatalf("exit %d, stdout %q, audit %v", code, out, recs)
	}
	if calls := sealCalls.Load() - before; calls != 1 {
		t.Fatalf("recorded %d seals, want 1", calls)
	}
	if dumpable, err := confine.Dumpable(); err != nil || dumpable != 1 {
		t.Fatalf("dumpable %d, %v", dumpable, err)
	}
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// sealGate is a subprocess gate whose jailed read (`cat <fifo>`) blocks until
// the test writes to the FIFO.
type sealGate struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	fifo           *os.File
	nonce, marker  string
	cancel         context.CancelFunc
}

// startSealGate starts the gate and returns once its jailed cat has opened the
// FIFO: the read has started, so a sealing gate has sealed.
func startSealGate(t *testing.T, abi string, noSeal bool) *sealGate {
	t.Helper()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatalf("SETUP: mkfifo: %v", err)
	}
	raw, err := json.Marshal(testGateConfig{Dir: dir, ABI: abi, NoSeal: noSeal})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	g := &sealGate{nonce: "nonce-" + randomHex(t), marker: "INJECT-" + randomHex(t), cancel: cancel}
	g.cmd = exec.CommandContext(ctx, os.Args[0])
	g.cmd.Env = append(os.Environ(), testGateEnv+"="+string(raw), "SSH_ORIGINAL_COMMAND=cat "+fifo, "SSHGATE_TEST_NONCE="+g.nonce)
	g.cmd.Stdout, g.cmd.Stderr = &g.stdout, &g.stderr
	if err := g.cmd.Start(); err != nil {
		cancel()
		t.Fatalf("SETUP: start gate: %v", err)
	}
	t.Cleanup(func() {
		if g.fifo != nil {
			_ = g.fifo.Close()
		}
		cancel()
		_ = g.cmd.Wait()
	})
	// A non-blocking write open succeeds once a reader has the FIFO open.
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			g.fifo = os.NewFile(uintptr(fd), fifo)
			return g
		}
		if !errors.Is(err, unix.ENXIO) {
			t.Fatalf("SETUP: open fifo: %v", err)
		}
	}
	t.Fatalf("SETUP: the gate's jailed read never opened the FIFO; stderr %q", g.stderr.String())
	return nil
}

// probe runs the capless reader against the gate while its read is blocked.
func (g *sealGate) probe(t *testing.T) caplessReport {
	t.Helper()
	out, err := exec.Command(os.Args[0], sentinelCaplessReader, strconv.Itoa(g.cmd.Process.Pid), g.nonce, g.marker).Output()
	var report caplessReport
	if err != nil || json.Unmarshal(out, &report) != nil {
		t.Fatalf("SETUP: capless reader: %v, output %q", err, out)
	}
	want := []string{"CapInh: 0000000000000000", "CapPrm: 0000000000000000", "CapEff: 0000000000000000", "CapAmb: 0000000000000000", "NoNewPrivs: 1"}
	for _, line := range want {
		if !slices.Contains(report.Caps, line) {
			t.Fatalf("SETUP: the reader is not capless: %v", report.Caps)
		}
	}
	return report
}

// finish feeds the FIFO, waits for the gate and reports whether the jailed
// read completed with the fed bytes.
func (g *sealGate) finish(t *testing.T) bool {
	t.Helper()
	_, writeErr := g.fifo.WriteString("fifo-data\n")
	closeErr := g.fifo.Close()
	g.fifo = nil
	waitErr := g.cmd.Wait()
	g.cancel()
	if writeErr != nil || closeErr != nil || waitErr != nil {
		t.Logf("gate: write %v, close %v, wait %v, stderr %q", writeErr, closeErr, waitErr, g.stderr.String())
		return false
	}
	return strings.Contains(g.stdout.String(), "fifo-data\n")
}

// legGateSeal: while a jailed read runs, a same-uid process outside the jail
// with no capabilities reads an unsealed gate's environ and writes into its
// client stream through /proc; the sealed gate refuses both with EACCES. A
// capless root process cannot reach even an unsealed root gate, so the leg
// shows the seal in the non-root lane only.
func legGateSeal(t *testing.T, abi string) {
	p := newProof(t, "G-GATE-SEAL")
	if os.Geteuid() == 0 {
		p.Omit("nonroot-only")
		return
	}
	twin := startSealGate(t, abi, true)
	control := twin.probe(t)
	p.Control("gate-proc", control.EnvironErr == "0" && control.NonceFound && control.FDWriteErr == "0" &&
		twin.finish(t) && strings.Contains(twin.stdout.String(), twin.marker+"\n"))

	sealed := startSealGate(t, abi, false)
	attempt := sealed.probe(t)
	ran := sealed.finish(t)
	injected := strings.Contains(sealed.stdout.String(), sealed.marker)
	p.Effect("gate-environ", attempt.NonceFound)
	p.Effect("gate-fd", injected)
	p.Jailed("read", ran)
	environ := attempt.NonceFound && attempt.EnvironErr == "0" || !attempt.NonceFound && attempt.EnvironErr == "EACCES"
	fd := injected && attempt.FDWriteErr == "0" || !injected && attempt.FDWriteErr == "EACCES"
	if !environ || !fd {
		t.Logf("reader %+v, stdout %q", attempt, sealed.stdout.String())
	}
	p.Observed("gate-proc", environ && fd)
	p.Finish()
}

// legSealGuard: a second jail attempt in a gate the first read sealed is
// refused before it starts (jail:failed:sealed). Only as root does the clone
// itself succeed in a sealed process, so the leg runs in the root lane.
func legSealGuard(t *testing.T, abi string) {
	p := newProof(t, "G-SEAL-GUARD")
	if os.Geteuid() != 0 {
		p.Omit("root-only")
		return
	}
	dir := t.TempDir()
	code, out := runTestGate(t, testGateConfig{Dir: dir, ABI: abi, Repeat: true}, dir, "echo seal-guard-ran")
	recs := auditRecords(t, dir)
	runs := strings.Count(out, "seal-guard-ran\n")
	p.Control("first-read", runs >= 1 && len(recs) == 2 && recs[0]["enforcement"] == "kernel")
	p.Effect("second-ran", runs == 2)
	refused := code == exitNoPermVal && runs == 1 && recs[1]["deny_reason"] == "jail:failed:sealed"
	p.Jailed("second-read", refused || runs == 2 && code == exitOK && recs[1]["enforcement"] == "kernel")
	p.Observed("output", strings.Count(out, "\n") == runs)
	p.Finish()
}

// legJailVerbLabel: a subprocess gate pinned net=deny answers SSHGATE_JAIL
// with a kernel run whose facts would earn the read-only label with the switch
// on, and reports the not-enabled label while the switch is off.
func legJailVerbLabel(t *testing.T, abi string) {
	p := newProof(t, "G-JAILVERB-LABEL")
	dir := t.TempDir()
	writePin(t, dir, pinDeny, 0o600)
	code, out := runTestGate(t, testGateConfig{Dir: dir, ABI: abi}, dir, "SSHGATE_JAIL")
	report := decodeVerbLine(t, out)
	p.Observed("json", true)
	state := confine.LabelState{Pinned: report.Pinned, Strict: report.Pinned, Outcome: confine.RunKernel, Profile: report.Profile, ABI: report.LandlockABI, Unmet: report.Unmet}
	claimable := confine.Label(state, report.Net, true) == confine.LabelReadOnlyKernel
	abiOK := report.LandlockABI >= 1 && (abi != "abi1" || report.LandlockABI == 1)
	p.Effect("label", report.Label == confine.LabelReadOnlyKernel)
	p.Jailed("verb", code == exitOK && report.Enforcement == "kernel" && report.Pinned && !report.Net && abiOK && claimable &&
		(report.Label == confine.LabelKernelNoLabel || report.Label == confine.LabelReadOnlyKernel))
	p.Finish()
}

// legJailVerbNoExec: on a Tier-1 gate, bytes after the verb never run; the
// line is an unknown command, a write, and is denied.
func legJailVerbNoExec(t *testing.T, abi string) {
	p := newProof(t, "G-JAILVERB-NOEXEC")
	nonce := "nonce-" + randomHex(t)
	out, err := exec.Command("/bin/sh", "-c", "printf "+nonce).Output()
	p.Control("payload", err == nil && string(out) == nonce)
	dir := t.TempDir()
	code, gateOut := runTestGate(t, testGateConfig{Dir: dir, ABI: abi}, dir, "SSHGATE_JAIL printf "+nonce)
	ran := strings.Contains(gateOut, nonce)
	p.Effect("agent-bytes", ran)
	p.Jailed("verb", !ran && code == exitNoPermVal && gateOut == "" || ran && code == exitOK)
	p.Observed("output", ran || !strings.Contains(gateOut, `{"v":1,`))
	p.Finish()
}

// TestGateBinaryJailVerb drives SSHGATE_JAIL through the real (non-race) gate
// binary on a Tier-1 install: one JSON line, a kernel run, no audit record.
// The verb resets the environment: with LD_PRELOAD set, a jailed read's
// dynamic /bin/sh reports the missing preload, while the verb's does not.
func TestGateBinaryJailVerb(t *testing.T) {
	requireJail(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, out)
	}
	runGate := func(command string) (int, string, string) {
		gate := exec.Command(bin)
		gate.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+command, "LD_PRELOAD=/nonexistent")
		var stdout, stderr bytes.Buffer
		gate.Stdout, gate.Stderr = &stdout, &stderr
		err := gate.Run()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("gate: %v", err)
		}
		return code, stdout.String(), stderr.String()
	}
	const preloadError = "cannot be preloaded"

	code, out, stderr := runGate("SSHGATE_JAIL")
	report := decodeVerbLine(t, out)
	if code != exitOK || report.Enforcement != "kernel" || report.Pinned || report.Net || report.Label != confine.LabelPinToClaim {
		t.Fatalf("verb: exit %d, report %+v, stderr %q", code, report, stderr)
	}
	if strings.Contains(stderr, preloadError) || stderr != "" {
		t.Fatalf("the verb's shell saw the gate's environment: stderr %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log")); err == nil {
		t.Fatal("the verb wrote an audit record")
	}

	code, _, stderr = runGate("true")
	if code != exitOK || !strings.Contains(stderr, preloadError) {
		t.Fatalf("control: a jailed read with LD_PRELOAD set: exit %d, stderr %q", code, stderr)
	}
}

var selftestBuild struct {
	once sync.Once
	path string
	err  error
}

// buildSelftestBinary builds the gate once per test process without -race
// and with this build's mutation hooks, into the jail-visible TMPDIR: the
// rehearsal runs it under the jail's seccomp filter.
func buildSelftestBinary(t *testing.T) string {
	t.Helper()
	selftestBuild.once.Do(func() {
		dir, err := os.MkdirTemp("", "selftest-")
		if err != nil {
			selftestBuild.err = err
			return
		}
		selftestBuild.path = filepath.Join(dir, "gate")
		args := append(append([]string{"build", "-trimpath"}, jailmut.BuildFlags()...), "-o", selftestBuild.path, ".")
		build := exec.Command("go", args...)
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			selftestBuild.err = fmt.Errorf("%v\n%s", err, out)
		}
	})
	if selftestBuild.err != nil {
		t.Fatalf("SETUP: build the selftest binary: %v", selftestBuild.err)
	}
	return selftestBuild.path
}

// runRehearsal runs one rehearsal in a fresh test gate process.
func runRehearsal(t *testing.T, config testGateConfig) testRehearsal {
	t.Helper()
	config.Dir, config.SelftestBinary = shortTempDir(t), buildSelftestBinary(t)
	code, out := runTestGate(t, config, config.Dir, "")
	var result testRehearsal
	if code != 0 || json.Unmarshal([]byte(out), &result) != nil {
		t.Fatalf("SETUP: rehearsal gate: exit %d, output %q", code, out)
	}
	return result
}

// legSelftestJailed: the rehearsal engine end to end, for a net=deny and a
// net=allow candidate: fixtures, liveness, the jailed selftest, its
// attestation and every outside check pass, at the lane's ABI.
func legSelftestJailed(t *testing.T, abi string) {
	p := newProof(t, "G-SELFTEST-JAILED")
	passed := true
	for _, net := range []bool{false, true} {
		r := runRehearsal(t, testGateConfig{ABI: abi, Rehearse: &confine.Pin{Profile: confine.ProfileROv1, Net: net}})
		abiOK := r.ABI >= 1 && (abi != "abi1" || r.ABI == 1)
		if !r.Passed || !r.Strict || !abiOK || r.Net != net {
			t.Errorf("net=%v: %+v", net, r.rehearsalResult)
			passed = false
		}
	}
	p.Jailed("selftest", passed)
	p.Observed("fixtures", passed)
	p.Finish()
}

// legSelftestUnjailed: run outside the jail, the selftest refuses (77) and
// the fixtures are untouched; a direct write to them lands.
func legSelftestUnjailed(t *testing.T, abi string) {
	p := newProof(t, "G-SELFTEST-UNJAILED")
	r := runRehearsal(t, testGateConfig{ABI: abi, Rehearse: &confine.Pin{Profile: confine.ProfileROv1}, Unjailed: true})
	p.Control("write", r.Control)
	changed := false
	for _, failure := range r.Failures {
		changed = changed || strings.HasPrefix(failure, "the canary") || strings.HasPrefix(failure, "the child")
	}
	p.Effect("selftest-unjailed", changed)
	p.Jailed("selftest", r.Ran && (r.Exit == exitNoPermVal && len(r.Failures) == 0 || r.Exit == exitOK && changed))
	p.Observed("fixtures", r.Skipped == "")
	p.Finish()
}
