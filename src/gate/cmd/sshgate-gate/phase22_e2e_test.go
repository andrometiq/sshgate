//go:build linux && jail_e2e

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
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
