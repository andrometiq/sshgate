package signerserver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	signerserver "github.com/karthikeyan5/sshgate/src/signer-server"
	"github.com/karthikeyan5/sshgate/src/signer-server/store"
)

// engineFixture stands up a real SQLite store, a real Signer, and the
// engine that wires them, returning the public key for gate verification.
func engineFixture(t *testing.T) (*signerserver.ApprovalEngine, *store.DB, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := signerserver.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	eng, err := signerserver.NewApprovalEngine(db, signer)
	if err != nil {
		t.Fatalf("NewApprovalEngine: %v", err)
	}
	return eng, db, pub
}

// cmdJSON mirrors the handlers package's unexported signRequestCmd wire
// shape (server, cmd, ttl_seconds) so a seeded request's Commands blob is
// byte-identical to what handleSign persists — which is exactly what the
// engine's commandsForSigning decodes.
type cmdJSON struct {
	Server     string `json:"server"`
	Cmd        string `json:"cmd"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// seedRequest inserts a pending request with the given N and one or more
// commands (cmd + ttl).
func seedRequest(t *testing.T, db *store.DB, id string, n int, cmds ...cmdJSON) {
	t.Helper()
	blob, err := json.Marshal(cmds)
	if err != nil {
		t.Fatalf("marshal commands: %v", err)
	}
	err = db.Insert(context.Background(), &store.Request{
		RequestID:         id,
		Status:            store.StatusPending,
		ClientID:          "karthi-laptop",
		Commands:          blob,
		RequiredApprovals: n,
	})
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
}

// TestEngine_1of1_ApproveSignsAndFlips proves the single-approval path:
// one approve mints signatures, flips the row to approved, records the
// approver, and the minted signatures are GATE-VALID (the Phase A golden
// assertion: gate.VerifySigned accepts them).
func TestEngine_1of1_ApproveSignsAndFlips(t *testing.T) {
	t.Parallel()
	eng, db, pub := engineFixture(t)
	ctx := context.Background()
	const cmd = "systemctl restart nginx"
	seedRequest(t, db, "r1", 1, cmdJSON{Server: "prod", Cmd: cmd, TTLSeconds: 120})

	out, err := eng.SubmitVote(ctx, "r1", "alice", store.DecisionApprove, "webauthn",
		signerserver.ApprovalPolicy{})
	if err != nil {
		t.Fatalf("SubmitVote: %v", err)
	}
	if out.Decision != signerserver.DecisionApproved {
		t.Fatalf("decision = %q; want approved", out.Decision)
	}
	if !out.Flipped {
		t.Fatalf("Flipped = false; the approving vote should have flipped the row")
	}

	got, err := db.GetByID(ctx, "r1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != store.StatusApproved {
		t.Fatalf("status = %q; want approved", got.Status)
	}
	if got.ApprovedBy != "alice" {
		t.Fatalf("ApprovedBy = %q; want alice", got.ApprovedBy)
	}
	if got.ResolvedAt == nil {
		t.Fatalf("ResolvedAt nil after approval")
	}

	// Golden: the persisted signatures verify under gate.
	assertGateValid(t, got.Signatures, pub, cmd)
}

// TestEngine_2of3_ThresholdCrossing proves the multi-approval path: the
// first approve leaves the row pending (no signatures), the second
// crosses N and flips with both approvers recorded.
func TestEngine_2of3_ThresholdCrossing(t *testing.T) {
	t.Parallel()
	eng, db, pub := engineFixture(t)
	ctx := context.Background()
	const cmd = "journalctl -u nginx -n 50"
	seedRequest(t, db, "r2", 2, cmdJSON{Server: "prod", Cmd: cmd, TTLSeconds: 90})

	// First approve: pending, no signatures, no flip.
	out1, err := eng.SubmitVote(ctx, "r2", "alice", store.DecisionApprove, "webauthn",
		signerserver.ApprovalPolicy{})
	if err != nil {
		t.Fatalf("first SubmitVote: %v", err)
	}
	if out1.Decision != signerserver.DecisionPending || out1.Flipped {
		t.Fatalf("after 1/2 approvals: decision=%q flipped=%v; want pending/false", out1.Decision, out1.Flipped)
	}
	mid, _ := db.GetByID(ctx, "r2")
	if mid.Status != store.StatusPending || len(mid.Signatures) != 0 {
		t.Fatalf("after 1/2: status=%q sigs=%q; want pending/empty", mid.Status, mid.Signatures)
	}

	// Second approve: crosses threshold, flips.
	out2, err := eng.SubmitVote(ctx, "r2", "bob", store.DecisionApprove, "totp",
		signerserver.ApprovalPolicy{})
	if err != nil {
		t.Fatalf("second SubmitVote: %v", err)
	}
	if out2.Decision != signerserver.DecisionApproved || !out2.Flipped {
		t.Fatalf("after 2/2: decision=%q flipped=%v; want approved/true", out2.Decision, out2.Flipped)
	}
	got, _ := db.GetByID(ctx, "r2")
	if got.Status != store.StatusApproved {
		t.Fatalf("status = %q; want approved", got.Status)
	}
	if got.ApprovedBy != "alice,bob" {
		t.Fatalf("ApprovedBy = %q; want alice,bob", got.ApprovedBy)
	}
	assertGateValid(t, got.Signatures, pub, cmd)
}

// TestEngine_DenyVetoOnVsOff proves the deny rule is driven entirely by
// the DenyVeto flag: on, a single deny flips to denied with no
// signatures; off, the same deny leaves the request pending.
func TestEngine_DenyVetoOnVsOff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Veto ON: deny flips to denied.
	eng, db, _ := engineFixture(t)
	seedRequest(t, db, "rd", 2, cmdJSON{Server: "prod", Cmd: "rm -rf /tmp/x", TTLSeconds: 60})
	out, err := eng.SubmitVote(ctx, "rd", "bob", store.DecisionDeny, "webauthn",
		signerserver.ApprovalPolicy{DenyVeto: true})
	if err != nil {
		t.Fatalf("SubmitVote(deny veto on): %v", err)
	}
	if out.Decision != signerserver.DecisionDenied || !out.Flipped {
		t.Fatalf("deny veto on: decision=%q flipped=%v; want denied/true", out.Decision, out.Flipped)
	}
	got, _ := db.GetByID(ctx, "rd")
	if got.Status != store.StatusDenied {
		t.Fatalf("status = %q; want denied", got.Status)
	}
	if len(got.Signatures) != 0 {
		t.Fatalf("denied request has signatures: %q", got.Signatures)
	}

	// Veto OFF: same deny leaves it pending.
	eng2, db2, _ := engineFixture(t)
	seedRequest(t, db2, "rd2", 2, cmdJSON{Server: "prod", Cmd: "rm -rf /tmp/x", TTLSeconds: 60})
	out2, err := eng2.SubmitVote(ctx, "rd2", "bob", store.DecisionDeny, "webauthn",
		signerserver.ApprovalPolicy{DenyVeto: false})
	if err != nil {
		t.Fatalf("SubmitVote(deny veto off): %v", err)
	}
	if out2.Decision != signerserver.DecisionPending || out2.Flipped {
		t.Fatalf("deny veto off: decision=%q flipped=%v; want pending/false", out2.Decision, out2.Flipped)
	}
	got2, _ := db2.GetByID(ctx, "rd2")
	if got2.Status != store.StatusPending {
		t.Fatalf("status = %q; want pending (veto off)", got2.Status)
	}
}

// TestEngine_SelfApproveOnVsOff proves the requester's own vote is
// governed by AllowSelfApprove at the engine level, end to end.
func TestEngine_SelfApproveOnVsOff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Self-approve OFF: requester's approve does not count; stays pending.
	eng, db, _ := engineFixture(t)
	seedRequest(t, db, "rs", 1, cmdJSON{Server: "prod", Cmd: "id", TTLSeconds: 60})
	out, err := eng.SubmitVote(ctx, "rs", "alice", store.DecisionApprove, "webauthn",
		signerserver.ApprovalPolicy{AllowSelfApprove: false, Requester: "alice"})
	if err != nil {
		t.Fatalf("SubmitVote(self off): %v", err)
	}
	if out.Decision != signerserver.DecisionPending || out.Flipped {
		t.Fatalf("self-approve off: decision=%q flipped=%v; want pending/false", out.Decision, out.Flipped)
	}

	// Self-approve ON: requester's approve counts; approved.
	eng2, db2, pub := engineFixture(t)
	seedRequest(t, db2, "rs2", 1, cmdJSON{Server: "prod", Cmd: "id", TTLSeconds: 60})
	out2, err := eng2.SubmitVote(ctx, "rs2", "alice", store.DecisionApprove, "webauthn",
		signerserver.ApprovalPolicy{AllowSelfApprove: true, Requester: "alice"})
	if err != nil {
		t.Fatalf("SubmitVote(self on): %v", err)
	}
	if out2.Decision != signerserver.DecisionApproved || !out2.Flipped {
		t.Fatalf("self-approve on: decision=%q flipped=%v; want approved/true", out2.Decision, out2.Flipped)
	}
	got, _ := db2.GetByID(ctx, "rs2")
	assertGateValid(t, got.Signatures, pub, "id")
}

// TestEngine_DuplicateVoteIdempotent proves a repeated vote from the same
// operator does not double-count and does not re-sign: the second call
// returns the same decision, and on an already-approved request returns
// ErrAlreadyResolved with no further mutation.
func TestEngine_DuplicateVoteIdempotent(t *testing.T) {
	t.Parallel()
	eng, db, _ := engineFixture(t)
	ctx := context.Background()
	seedRequest(t, db, "rdup", 2, cmdJSON{Server: "prod", Cmd: "uptime", TTLSeconds: 60})

	// alice approves twice while still below threshold (N=2). Both calls
	// see pending; the duplicate is collapsed by the store and does NOT
	// push the count to 2.
	if _, err := eng.SubmitVote(ctx, "rdup", "alice", store.DecisionApprove, "webauthn", signerserver.ApprovalPolicy{}); err != nil {
		t.Fatalf("first alice vote: %v", err)
	}
	out2, err := eng.SubmitVote(ctx, "rdup", "alice", store.DecisionApprove, "webauthn", signerserver.ApprovalPolicy{})
	if err != nil {
		t.Fatalf("duplicate alice vote: %v", err)
	}
	if out2.Decision != signerserver.DecisionPending {
		t.Fatalf("duplicate vote decision = %q; want pending (must not count twice)", out2.Decision)
	}
	votesList, _ := db.ListVotes(ctx, "rdup")
	if len(votesList) != 1 {
		t.Fatalf("stored votes = %d; want 1 (duplicate collapsed)", len(votesList))
	}

	// Now bob crosses the threshold.
	if _, err := eng.SubmitVote(ctx, "rdup", "bob", store.DecisionApprove, "totp", signerserver.ApprovalPolicy{}); err != nil {
		t.Fatalf("bob vote: %v", err)
	}
	approved, _ := db.GetByID(ctx, "rdup")
	if approved.Status != store.StatusApproved {
		t.Fatalf("status = %q; want approved", approved.Status)
	}
	sigBefore := string(approved.Signatures)

	// A late vote on the now-approved request is a no-op: ErrAlreadyResolved,
	// signatures unchanged.
	if _, err := eng.SubmitVote(ctx, "rdup", "carol", store.DecisionApprove, "webauthn", signerserver.ApprovalPolicy{}); !errors.Is(err, signerserver.ErrAlreadyResolved) {
		t.Fatalf("late vote err = %v; want ErrAlreadyResolved", err)
	}
	after, _ := db.GetByID(ctx, "rdup")
	if string(after.Signatures) != sigBefore {
		t.Fatalf("signatures changed after a no-op late vote")
	}
}

// TestEngine_NotFound proves a vote on a non-existent request surfaces
// store.ErrNotFound and records nothing.
func TestEngine_NotFound(t *testing.T) {
	t.Parallel()
	eng, db, _ := engineFixture(t)
	ctx := context.Background()
	if _, err := eng.SubmitVote(ctx, "ghost", "alice", store.DecisionApprove, "webauthn", signerserver.ApprovalPolicy{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SubmitVote(missing) = %v; want ErrNotFound", err)
	}
	if v, _ := db.ListVotes(ctx, "ghost"); len(v) != 0 {
		t.Fatalf("a vote was recorded for a missing request")
	}
}

// TestEngine_ThresholdRace is the near-simultaneous threshold-crossing
// proof: at N=1, many operators approve concurrently; EXACTLY ONE call
// reports Flipped=true (mints + persists signatures), every other call
// sees the same approved decision with Flipped=false, and the row ends
// with exactly one coherent, gate-valid signature set. Run with -race.
func TestEngine_ThresholdRace(t *testing.T) {
	t.Parallel()
	eng, db, pub := engineFixture(t)
	ctx := context.Background()
	const cmd = "df -h"
	// N=1 so every approving operator independently crosses the threshold
	// — the worst case for the flip race.
	seedRequest(t, db, "rrace", 1, cmdJSON{Server: "prod", Cmd: cmd, TTLSeconds: 60})

	const operators = 12
	var (
		wg        sync.WaitGroup
		flipCount atomic.Int64
		approvedN atomic.Int64
		errCount  atomic.Int64
		start     = make(chan struct{})
	)
	for i := 0; i < operators; i++ {
		op := "op-" + string(rune('a'+i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all goroutines together
			out, err := eng.SubmitVote(ctx, "rrace", op, store.DecisionApprove, "webauthn", signerserver.ApprovalPolicy{})
			if err != nil && !errors.Is(err, signerserver.ErrAlreadyResolved) {
				errCount.Add(1)
				t.Errorf("SubmitVote: %v", err)
				return
			}
			if err == nil && out.Decision == signerserver.DecisionApproved {
				approvedN.Add(1)
			}
			if out.Flipped {
				flipCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("unexpected errors during race")
	}
	// EXACTLY ONE caller performed the sign+flip side effect.
	if flipCount.Load() != 1 {
		t.Fatalf("flip count = %d; want exactly 1 (one sign+flip)", flipCount.Load())
	}

	got, err := db.GetByID(ctx, "rrace")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != store.StatusApproved {
		t.Fatalf("final status = %q; want approved", got.Status)
	}
	// Exactly one coherent signature set, and it is gate-valid.
	assertGateValid(t, got.Signatures, pub, cmd)

	// The approver recorded must be a single operator (the one whose
	// signatures landed) — exactly one signature for the single command.
	var sigs []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	}
	if err := json.Unmarshal(got.Signatures, &sigs); err != nil {
		t.Fatalf("unmarshal final signatures: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("final signature count = %d; want 1", len(sigs))
	}
}

// assertGateValid decodes the persisted []signedCmd JSON and asserts each
// signature verifies under gate.VerifySigned at a clock just inside the
// validity window, returning the expected inner command. This reuses the
// Phase A golden assertion: gate.VerifySigned is the sole proof the
// engine persisted real, gate-acceptable signatures.
func assertGateValid(t *testing.T, sigBlob []byte, pub ed25519.PublicKey, wantCmd string) {
	t.Helper()
	if len(sigBlob) == 0 {
		t.Fatalf("no signatures persisted")
	}
	var sigs []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	}
	if err := json.Unmarshal(sigBlob, &sigs); err != nil {
		t.Fatalf("unmarshal signatures: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatalf("signature list empty")
	}
	// Verify just after approval time. Approval time was time.Now() inside
	// the engine, so verify at now+1s which is inside any positive TTL.
	verifyAt := time.Now().Add(time.Second)
	for i, sc := range sigs {
		inner, err := gate.VerifySigned(sc.Sig, pub, verifyAt)
		if err != nil {
			t.Fatalf("gate.VerifySigned rejected persisted signature[%d]: %v", i, err)
		}
		if sc.Cmd != wantCmd {
			t.Fatalf("signature[%d].Cmd = %q; want %q", i, sc.Cmd, wantCmd)
		}
		if inner != wantCmd {
			t.Fatalf("gate inner cmd[%d] = %q; want %q", i, inner, wantCmd)
		}
	}
}
