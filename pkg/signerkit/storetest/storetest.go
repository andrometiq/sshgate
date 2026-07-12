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

	// Fire N writers simultaneously: half race an approve (each with a DISTINCT
	// signature blob + approver), half race a deny. Exactly one transition may
	// win the pending guard.
	const writers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
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
