// Package storetest is the conformance suite every signerkit Store
// implementation MUST pass. Its centrepiece is the single-sign guarantee
// (C10): UpdateStatus must be an ATOMIC compare-and-set gated on
// status='pending', so that for a given request at most one transition out of
// pending ever succeeds and terminal states are immutable. A read-then-write
// Store passes the interface's prose but FAILS this hammer — which is the point:
// the atomicity is a contract, not an implementation nicety.
//
// Usage from an implementation's test package:
//
//	func TestConformance(t *testing.T) {
//	    storetest.RunConcurrentFlip(t, func(t *testing.T) store.Store {
//	        db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "c.db"))
//	        if err != nil { t.Fatal(err) }
//	        t.Cleanup(func() { _ = db.Close() })
//	        return db
//	    })
//	}
package storetest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// terminalSnapshot is the tuple that must be stable once a request resolves.
type terminalSnapshot struct {
	status     store.Status
	signatures string
	approvedBy string
}

func snapshot(r *store.Request) terminalSnapshot {
	return terminalSnapshot{status: r.Status, signatures: string(r.Signatures), approvedBy: r.ApprovedBy}
}

// RunConcurrentFlip races many concurrent approve/deny transitions at a single
// pending request and asserts EXACTLY ONE wins: the row ends in one terminal
// state with one stable payload, no losing writer's payload ever lands, and a
// post-resolution UpdateStatus (a late loser) cannot overwrite the winner.
//
// Crucially it observes the row DURING the race, not only after it settles. An
// earlier version of this hammer ran every assertion after wg.Wait(), which a
// non-atomic (read-then-write / last-writer-wins) Store passed vacuously: with
// no concurrent reader, the row is simply read once the dust settles, in some
// terminal state, and the immutability re-reads that follow see nothing change
// because nobody is writing any more. To actually exercise the atomicity
// contract we (a) start a concurrent reader that snapshots the FIRST terminal
// (non-pending) state it observes and flags any later change to it, and (b)
// stagger the writers so a non-atomic Store resolves the row early and then a
// later writer clobbers the already-resolved row — a mutation the reader
// catches and the post-wait first-vs-final compare catches. An atomic CAS Store
// makes every write after the first a no-op, so the first terminal state IS the
// final one and both checks pass.
//
// newStore must return a FRESH, empty Store backed by its own storage.
func RunConcurrentFlip(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	st := newStore(t)
	ctx := context.Background()

	const rid = "r-conformance"
	if err := st.Insert(ctx, &store.Request{
		RequestID: rid,
		Status:    store.StatusPending,
		ClientID:  "conformance",
		Commands:  []byte(`[{"server":"s","cmd":"x","ttl_seconds":60}]`),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// A concurrent reader spins on GetByID for the whole race. It captures the
	// FIRST terminal (non-pending) state it observes and flags if the terminal
	// row is EVER seen to change afterwards. Under an atomic CAS Store the first
	// terminal state is final — the pending-guard makes every later write a
	// no-op — so firstTerminal never changes and mutatedAfterResolve stays
	// false. Under a read-then-write Store a late writer clobbers the resolved
	// row, which this reader observes directly. Its fields are read only after
	// the reader has been joined (happens-after), so the access is race-free.
	var (
		firstTerminal       terminalSnapshot
		sawTerminal         bool
		mutatedAfterResolve bool
	)
	readerStop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			if g, err := st.GetByID(ctx, rid); err == nil && g.Status != store.StatusPending {
				snap := snapshot(g)
				if !sawTerminal {
					firstTerminal = snap
					sawTerminal = true
				} else if snap != firstTerminal {
					mutatedAfterResolve = true
				}
			}
			select {
			case <-readerStop:
				return
			default:
			}
		}
	}()

	// Fire N writers: half race an approve (each with a DISTINCT signature blob
	// + approver), half race a deny. Exactly one transition may win the pending
	// guard. The stagger spreads the writes out so that, on a non-atomic Store,
	// writer 0 resolves the row almost immediately and each later writer lands a
	// few ms afterward — giving the reader a window to observe the first
	// resolution before a loser clobbers it. On an atomic Store the stagger is
	// harmless: whoever writes first wins and the rest are no-ops.
	const writers = 32
	const stagger = 1 * time.Millisecond
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			time.Sleep(time.Duration(i) * stagger)
			if i%2 == 0 {
				sig := []byte(fmt.Sprintf(`[{"cmd":"x","sig":"WINNER-%d"}]`, i))
				_ = st.UpdateStatus(ctx, rid, store.StatusApproved, sig, fmt.Sprintf("op-%d", i))
			} else {
				_ = st.UpdateStatus(ctx, rid, store.StatusDenied, nil, fmt.Sprintf("op-%d", i))
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// Stop the reader and join it before touching its captured state.
	close(readerStop)
	<-readerDone

	got, err := st.GetByID(ctx, rid)
	if err != nil {
		t.Fatalf("GetByID after race: %v", err)
	}
	if got.Status == store.StatusPending {
		t.Fatalf("no transition won the race — row is still pending")
	}
	if got.Status != store.StatusApproved && got.Status != store.StatusDenied {
		t.Fatalf("row resolved to unexpected status %q", got.Status)
	}
	// An approved winner must carry exactly one writer's signature blob; a
	// denied winner must carry none. (A mix would mean two writers both wrote.)
	if got.Status == store.StatusApproved && len(got.Signatures) == 0 {
		t.Fatalf("approved winner has no signatures — a partial/interleaved write?")
	}
	if got.Status == store.StatusDenied && len(got.Signatures) != 0 {
		t.Fatalf("denied winner carries signatures — a losing approve leaked in")
	}

	// The reader's mid-race observations are the teeth of this hammer. Once a
	// request resolves it is immutable; if the terminal row was seen to change
	// after it first resolved, a losing writer overwrote the winner — exactly
	// the single-sign violation a non-atomic UpdateStatus commits.
	if sawTerminal {
		if mutatedAfterResolve {
			t.Fatalf("terminal row mutated mid-race: a late writer overwrote an already-resolved row (non-atomic UpdateStatus)")
		}
		if snapshot(got) != firstTerminal {
			t.Fatalf("row changed after it first resolved: first-observed %+v != final %+v (a non-atomic UpdateStatus let a loser overwrite the winner)", firstTerminal, snapshot(got))
		}
	}

	// Single-winner: the surviving approver names exactly ONE operator, and for
	// an approved winner the persisted signature belongs to that SAME operator.
	// A read-then-write Store that let two writers interleave could leave one
	// writer's approver stamped over another writer's signature blob.
	if strings.Contains(got.ApprovedBy, ",") {
		t.Fatalf("approved_by names multiple operators %q — more than one writer's transition landed", got.ApprovedBy)
	}
	if got.Status == store.StatusApproved {
		winner := strings.TrimPrefix(got.ApprovedBy, "op-")
		if want := "WINNER-" + winner; !strings.Contains(string(got.Signatures), want) {
			t.Fatalf("winner mismatch: approved_by=%q but signatures=%q do not carry %q — approver and signature came from different writers", got.ApprovedBy, string(got.Signatures), want)
		}
	}

	// Immutability: the terminal row must not change across repeated reads.
	first := snapshot(got)
	for k := 0; k < 8; k++ {
		g, err := st.GetByID(ctx, rid)
		if err != nil {
			t.Fatalf("GetByID re-read: %v", err)
		}
		if snapshot(g) != first {
			t.Fatalf("terminal row mutated after resolution: %+v -> %+v", first, snapshot(g))
		}
	}

	// A late loser — a further UpdateStatus after resolution — MUST be a no-op:
	// the winning payload survives (terminal states are immutable).
	if err := st.UpdateStatus(ctx, rid, store.StatusApproved, []byte(`[{"cmd":"x","sig":"LATE-LOSER"}]`), "late"); err != nil {
		t.Fatalf("post-resolution UpdateStatus returned an error (should be an idempotent no-op): %v", err)
	}
	after, err := st.GetByID(ctx, rid)
	if err != nil {
		t.Fatalf("GetByID after late loser: %v", err)
	}
	if snapshot(after) != first {
		t.Fatalf("a post-resolution UpdateStatus overwrote the winner: %+v -> %+v", first, snapshot(after))
	}
}

// RunUnauditedVoteBarrier proves UpdateStatus cannot race a terminal decision
// past a prepared vote whose external audit write is still in flight. Every
// Store implementation must provide this database-level barrier; an engine-
// local mutex is insufficient for multi-replica deployments.
func RunUnauditedVoteBarrier(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	st := newStore(t)
	ctx := context.Background()
	const rid = "r-audit-barrier"
	if err := st.Insert(ctx, &store.Request{
		RequestID: rid, Status: store.StatusPending, ClientID: "conformance", Commands: []byte(`[]`),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, needsAudit, err := st.PrepareVote(ctx, &store.Vote{
		RequestID: rid, Operator: "op-deny", Decision: store.DecisionDeny, AuthnMethod: "webauthn",
	}); err != nil || !needsAudit {
		t.Fatalf("PrepareVote: needsAudit=%v err=%v", needsAudit, err)
	}
	if err := st.UpdateStatus(ctx, rid, store.StatusApproved, []byte(`[]`), "op-approve"); err != nil {
		t.Fatalf("UpdateStatus across barrier: %v", err)
	}
	got, err := st.GetByID(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusPending {
		t.Fatalf("terminal transition crossed unaudited vote: %q", got.Status)
	}
	if err := st.MarkVoteAudited(ctx, rid, "op-deny"); err != nil {
		t.Fatalf("MarkVoteAudited: %v", err)
	}
	if err := st.UpdateStatus(ctx, rid, store.StatusDenied, nil, "op-deny"); err != nil {
		t.Fatalf("UpdateStatus after audited vote: %v", err)
	}
	got, err = st.GetByID(ctx, rid)
	if err != nil || got.Status != store.StatusDenied {
		t.Fatalf("audited vote did not release barrier: status=%q err=%v", got.Status, err)
	}
}
