package tools_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// fakeStdinSSH is a Runner.SSHStdin (StdinRunner) stub. It records the streamed
// stdin bytes so tests can prove the tool streamed exactly what it hashed
// (read-once), and returns a canned success/deny result.
type fakeStdinSSH struct {
	mu       sync.Mutex
	called   bool
	gotCmd   string
	gotHost  string
	gotUser  string
	gotPort  int
	gotStdin []byte
	stdout   []byte
	stderr   []byte
	exit     int
	err      error
}

func (f *fakeStdinSSH) RunWithStdin(_ context.Context, host, user string, port int, cmd string, stdin io.Reader) ([]byte, []byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.gotCmd = cmd
	f.gotHost = host
	f.gotUser = user
	f.gotPort = port
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		f.gotStdin = b
	}
	return f.stdout, f.stderr, f.exit, f.err
}

// fakeProbeSSH is a Runner.SSH (SSHRunner) stub that dispatches on the command
// so the two distinct probes update_gate makes — SSHGATE_VERSION (pre-sign,
// running-rev banner) and "" (post-update SSHGATE_OK liveness) — can return
// different bodies.
type fakeProbeSSH struct {
	mu          sync.Mutex
	versionOut  []byte
	versionExit int
	versionErr  error
	aliveOut    []byte
	aliveErr    error
	callHistory []string
}

func (f *fakeProbeSSH) Run(_ context.Context, _, _ string, _ int, cmd string) ([]byte, []byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callHistory = append(f.callHistory, cmd)
	switch cmd {
	case "SSHGATE_VERSION":
		return f.versionOut, nil, f.versionExit, f.versionErr
	case "":
		return f.aliveOut, nil, 0, f.aliveErr
	default:
		return nil, nil, 0, nil
	}
}

func (f *fakeProbeSSH) sawCommand(cmd string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.callHistory {
		if c == cmd {
			return true
		}
	}
	return false
}

// stageGateFixture writes a plausible staged-gate fixture (a few KB — the MCP
// side does NOT ELF-check; that is the gate's job) and returns its path + the
// bytes + their lowercase SHA-256 hex.
func stageGateFixture(t *testing.T) (path string, body []byte, hexHash string) {
	t.Helper()
	body = bytes.Repeat([]byte("sshgate-gate-binary-fixture\n"), 512) // ~14 KiB
	path = filepath.Join(t.TempDir(), "sshgate-gate-linux-amd64")
	if err := os.WriteFile(path, body, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return path, body, hex.EncodeToString(sum[:])
}

// hashInWireCmd extracts the <hex> from a "…SSHGATE_UPDATE <hex>" wire command.
func hashInWireCmd(t *testing.T, wire string) string {
	t.Helper()
	const marker = "SSHGATE_UPDATE "
	i := strings.Index(wire, marker)
	if i < 0 {
		t.Fatalf("wire cmd %q has no %q", wire, marker)
	}
	return strings.TrimSpace(wire[i+len(marker):])
}

// TestUpdateGate_HappyPathReadOnce is the core success case AND the read-once
// proof: the tool hashes the staged binary ONCE, signs a commitment to that
// hash, streams the SAME buffer on stdin, and the gate confirms the same hash.
// It asserts the bytes the StdinRunner RECEIVED hash to the hash in the SIGNED
// command (what was approved == what was streamed).
func TestUpdateGate_HappyPathReadOnce(t *testing.T) {
	t.Parallel()
	stagedPath, body, wantHash := stageGateFixture(t)
	r := newRegistryWith(t, "prod", registry.Entry{
		Host: "1.2.3.4", Port: 2222, User: "ops", AddedAt: time.Now(), Fingerprint: "SHA256:hostkeyfp",
	})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_UPDATE " + wantHash, Sig: "SSHGATE_SIG:AAA:BBB"}}, authMode: "human"}
	probe := &fakeProbeSSH{
		versionOut: []byte("SSHGATE_VERSION rev=abc1234\n"), versionExit: 0,
		aliveOut: []byte("SSHGATE_OK\n"),
	}
	stdin := &fakeStdinSSH{
		stdout: []byte("SSHGATE_UPDATED sha256=" + wantHash + " size=14336 rev=deadbee\n"),
		exit:   0,
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: probe, SSHStdin: stdin, StagedGatePath: stagedPath}

	out, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"})
	if err != nil {
		t.Fatalf("UpdateGate: %v", err)
	}
	if out.NewHash != wantHash {
		t.Errorf("NewHash = %q; want %q", out.NewHash, wantHash)
	}
	if out.Size != 14336 {
		t.Errorf("Size = %d; want 14336 (from the gate marker)", out.Size)
	}
	if out.Revision != "deadbee" {
		t.Errorf("Revision = %q; want deadbee", out.Revision)
	}
	if !out.VerifiedAlive {
		t.Error("VerifiedAlive = false; want true (liveness probe returned SSHGATE_OK)")
	}
	if !stdin.called {
		t.Fatal("StdinRunner was never called")
	}
	// The stream must have gone to THIS server's connection details.
	if stdin.gotHost != "1.2.3.4" || stdin.gotPort != 2222 || stdin.gotUser != "ops" {
		t.Errorf("stream went to host=%s port=%d user=%s", stdin.gotHost, stdin.gotPort, stdin.gotUser)
	}
	// READ-ONCE: the bytes streamed must equal the staged fixture...
	if !bytes.Equal(stdin.gotStdin, body) {
		t.Error("streamed bytes != staged fixture bytes")
	}
	// ...and hash to exactly the hash embedded in the SIGNED wire command.
	streamedSum := sha256.Sum256(stdin.gotStdin)
	streamedHex := hex.EncodeToString(streamedSum[:])
	if got := hashInWireCmd(t, stdin.gotCmd); got != streamedHex || got != wantHash {
		t.Errorf("hash in signed cmd = %q; hash(streamed bytes) = %q; want both = %q", got, streamedHex, wantHash)
	}
	// The wire command must carry the signature prefix.
	if !strings.HasPrefix(stdin.gotCmd, "SSHGATE_SIG:") {
		t.Errorf("wire cmd %q lacks the SSHGATE_SIG: prefix", stdin.gotCmd)
	}
	// The sign request must commit to the same hash + the update TTL cap.
	if len(sign.gotCmds) != 1 {
		t.Fatalf("sign called with %d cmds; want 1", len(sign.gotCmds))
	}
	if sign.gotCmds[0].Cmd != "SSHGATE_UPDATE "+wantHash {
		t.Errorf("signed Cmd = %q; want SSHGATE_UPDATE %s", sign.gotCmds[0].Cmd, wantHash)
	}
	if sign.gotCmds[0].TTLSec != tools.UpdateTTLSec {
		t.Errorf("signed TTLSec = %d; want %d", sign.gotCmds[0].TTLSec, tools.UpdateTTLSec)
	}
	if sign.gotCmds[0].Host != "SHA256:hostkeyfp" {
		t.Errorf("signed Host = %q; want the registry fingerprint", sign.gotCmds[0].Host)
	}
}

// TestUpdateGate_ReadOnlyShortCircuitsBeforeSigning proves a Tier-1 read-only
// alias is refused locally BEFORE any signature is requested — no Telegram tap
// is wasted on a box that would reject every signed command.
func TestUpdateGate_ReadOnlyShortCircuitsBeforeSigning(t *testing.T) {
	t.Parallel()
	stagedPath, _, _ := stageGateFixture(t)
	r := newRegistryWith(t, "ro", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true,
	})
	sign := &fakeSign{}
	stdin := &fakeStdinSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeProbeSSH{}, SSHStdin: stdin, StagedGatePath: stagedPath}

	_, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "ro"})
	if err == nil {
		t.Fatal("expected an error for a read-only alias")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("err = %v; want a read-only remediation", err)
	}
	if sign.signCalled {
		t.Error("Sign was called for a read-only alias — must short-circuit before signing")
	}
	if stdin.called {
		t.Error("StdinRunner was called for a read-only alias")
	}
}

// TestUpdateGate_MissingStagedPathNoSigning proves an empty StagedGatePath is a
// fast, actionable failure with no signing attempt.
func TestUpdateGate_MissingStagedPathNoSigning(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	stdin := &fakeStdinSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeProbeSSH{}, SSHStdin: stdin, StagedGatePath: ""}

	_, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"})
	if err == nil {
		t.Fatal("expected an error when no staged gate binary is configured")
	}
	if !strings.Contains(err.Error(), "install-local") {
		t.Errorf("err = %v; want the actionable `make install-local` guidance", err)
	}
	if sign.signCalled {
		t.Error("Sign was called with no staged binary")
	}
}

// TestUpdateGate_MarkerHashMismatchErrors proves that if the gate somehow
// confirms a DIFFERENT hash than the one approved, the tool refuses to report
// success (defense-in-depth over the gate's own re-hash check).
func TestUpdateGate_MarkerHashMismatchErrors(t *testing.T) {
	t.Parallel()
	stagedPath, _, wantHash := stageGateFixture(t)
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_UPDATE " + wantHash, Sig: "SSHGATE_SIG:AAA:BBB"}}}
	probe := &fakeProbeSSH{versionOut: []byte("SSHGATE_VERSION rev=abc1234\n"), aliveOut: []byte("SSHGATE_OK\n")}
	// A different, well-formed 64-hex hash.
	otherHash := strings.Repeat("0", 64)
	stdin := &fakeStdinSSH{stdout: []byte("SSHGATE_UPDATED sha256=" + otherHash + " size=100 rev=x\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: probe, SSHStdin: stdin, StagedGatePath: stagedPath}

	_, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"})
	if err == nil {
		t.Fatal("expected an error on a confirmed-hash mismatch")
	}
	if !strings.Contains(err.Error(), "DIFFERENT hash") {
		t.Errorf("err = %v; want a hash-mismatch error", err)
	}
}

// TestUpdateGate_ReasonShowsRunningRevOnUnknownStaged pins the downgrade-cue
// behaviour (Finding 4): even when a raw (non-Go) staged buffer parses to an
// unknown build revision, the CmdReq.Reason must STILL carry the running rev
// (from the pre-sign SSHGATE_VERSION probe) — a stripped staged buildinfo must
// not be able to hide both revs. The exact Reason format is pinned directly in
// TestUpdateReason.
func TestUpdateGate_ReasonShowsRunningRevOnUnknownStaged(t *testing.T) {
	t.Parallel()
	stagedPath, _, wantHash := stageGateFixture(t)
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_UPDATE " + wantHash, Sig: "SSHGATE_SIG:AAA:BBB"}}}
	probe := &fakeProbeSSH{versionOut: []byte("SSHGATE_VERSION rev=abc1234\n"), versionExit: 0, aliveOut: []byte("SSHGATE_OK\n")}
	stdin := &fakeStdinSSH{stdout: []byte("SSHGATE_UPDATED sha256=" + wantHash + " size=1 rev=x\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: probe, SSHStdin: stdin, StagedGatePath: stagedPath}

	if _, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"}); err != nil {
		t.Fatalf("UpdateGate: %v", err)
	}
	if len(sign.gotCmds) != 1 {
		t.Fatalf("sign called with %d cmds; want 1", len(sign.gotCmds))
	}
	const wantReason = "rev unknown · running rev abc1234"
	if sign.gotCmds[0].Reason != wantReason {
		t.Errorf("Reason = %q; want %q (running rev must show even when the staged rev is unknown)", sign.gotCmds[0].Reason, wantReason)
	}
	if !probe.sawCommand("SSHGATE_VERSION") {
		t.Error("the pre-sign SSHGATE_VERSION probe was never consulted")
	}
}

// TestUpdateGate_VersionProbeBestEffort proves the SSHGATE_VERSION probe is
// best-effort: an old gate that predates the verb returns exit 77 (it classifies
// the unknown command as a write), yet the update still proceeds — the running
// rev is simply treated as unknown.
func TestUpdateGate_VersionProbeBestEffort(t *testing.T) {
	t.Parallel()
	stagedPath, _, wantHash := stageGateFixture(t)
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_UPDATE " + wantHash, Sig: "SSHGATE_SIG:AAA:BBB"}}}
	// Old gate: SSHGATE_VERSION is an unknown command → treated as a write → 77.
	probe := &fakeProbeSSH{versionOut: []byte("write denied\n"), versionExit: 77, aliveOut: []byte("SSHGATE_OK\n")}
	stdin := &fakeStdinSSH{stdout: []byte("SSHGATE_UPDATED sha256=" + wantHash + " size=1 rev=unknown\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: probe, SSHStdin: stdin, StagedGatePath: stagedPath}

	out, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"})
	if err != nil {
		t.Fatalf("UpdateGate must not fail on an old-gate version probe: %v", err)
	}
	if out.NewHash != wantHash {
		t.Errorf("NewHash = %q; want %q — update should have proceeded", out.NewHash, wantHash)
	}
}

// TestUpdateGate_GateRefusalExit65NoRetryAdvice proves exit 65 from the gate is
// surfaced as a DETERMINISTIC binary-check refusal (hash mismatch / non-ELF /
// wrong-arch / size) — NOT the misrouted "signature expired… retry" advice that
// gateDenyNote(65) gives an ordinary write. Retrying re-fires the scary approval
// for a request that will fail identically, so the message must NOT say
// "retry"/"expired" and must carry the gate's stderr for diagnosis.
func TestUpdateGate_GateRefusalExit65NoRetryAdvice(t *testing.T) {
	t.Parallel()
	stagedPath, _, wantHash := stageGateFixture(t)
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_UPDATE " + wantHash, Sig: "SSHGATE_SIG:AAA:BBB"}}}
	probe := &fakeProbeSSH{versionOut: []byte("SSHGATE_VERSION rev=abc1234\n"), aliveOut: []byte("SSHGATE_OK\n")}
	stdin := &fakeStdinSSH{stderr: []byte("update: binary hash mismatch"), exit: 65}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: probe, SSHStdin: stdin, StagedGatePath: stagedPath}

	_, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"})
	if err == nil {
		t.Fatal("expected an error on gate exit 65")
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	// Deterministic binary-check refusal, not a transient/retryable one.
	if !strings.Contains(msg, "gate check") {
		t.Errorf("err = %v; want a deterministic binary-check refusal", err)
	}
	if !strings.Contains(msg, "unchanged") {
		t.Errorf("err = %v; want it to state the old gate is unchanged", err)
	}
	// The gate's stderr must ride along for diagnosis.
	if !strings.Contains(msg, "hash mismatch") {
		t.Errorf("err = %v; want the gate's stderr (hash mismatch) included", err)
	}
	// It must NOT misroute to the ordinary-write "expired… retry" advice.
	if strings.Contains(low, "retry") {
		t.Errorf("err = %v; must NOT advise a retry for a deterministic refusal", err)
	}
	if strings.Contains(low, "expired") {
		t.Errorf("err = %v; must NOT claim the signature expired", err)
	}
}

// TestUpdateGate_GateRefusalExit70FsReplace proves exit 70 is surfaced as a
// filesystem-replace failure with the old gate still in place — distinct from
// the binary-check refusal (65) and never the "retry" advice.
func TestUpdateGate_GateRefusalExit70FsReplace(t *testing.T) {
	t.Parallel()
	stagedPath, _, wantHash := stageGateFixture(t)
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_UPDATE " + wantHash, Sig: "SSHGATE_SIG:AAA:BBB"}}}
	probe := &fakeProbeSSH{versionOut: []byte("SSHGATE_VERSION rev=abc1234\n"), aliveOut: []byte("SSHGATE_OK\n")}
	stdin := &fakeStdinSSH{stderr: []byte("update: replace failed"), exit: 70}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: probe, SSHStdin: stdin, StagedGatePath: stagedPath}

	_, err := runner.UpdateGate(context.Background(), tools.UpdateGateInput{Alias: "prod"})
	if err == nil {
		t.Fatal("expected an error on gate exit 70")
	}
	msg := err.Error()
	if !strings.Contains(msg, "still in place") {
		t.Errorf("err = %v; want the fs-replace-failure wording (old gate still in place)", err)
	}
	if strings.Contains(strings.ToLower(msg), "retry") {
		t.Errorf("err = %v; must NOT advise a retry", err)
	}
}
