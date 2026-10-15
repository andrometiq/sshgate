package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

func TestReconcileClockAndCommitBarrier(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	if e.projections.work[key].Notify.Kind != ap.NotifyBurst {
		t.Fatal("post-commit Next omitted burst")
	}
	clock.Advance(5 * time.Second)
	store.fail = true
	before, _ := store.Load(key)
	due := e.projections.due[key]
	if err := e.Reconcile(); err == nil {
		t.Fatal("lost commit error")
	}
	after, _ := store.Load(key)
	if !reflect.DeepEqual(before, after) || !e.projections.due[key].Equal(due) {
		t.Fatal("failed commit published")
	}
	store.fail = false
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	after, _ = store.Load(key)
	if after.Header.Assist == nil || after.Header.Assist.State != ap.AssistUnavailable {
		t.Fatal("assist deadline not committed")
	}
	if !e.projections.due[key].Equal(after.Header.RequestExpiresAt) {
		t.Fatal("due index did not advance")
	}
	n := store.commits
	if err := e.Reconcile(); err != nil || store.commits != n {
		t.Fatal("outbox drove due retry")
	}
	clock.Advance(2 * time.Hour)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	after, _ = store.Load(key)
	if after.Header.Decision == nil || after.Header.Decision.Status != ap.ApprovalExpired || !after.Header.Decision.DecidedAt.Equal(after.Header.RequestExpiresAt) {
		t.Fatal("expiry not committed at deadline")
	}
	clock.StepWall(-3 * time.Hour)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	got, _ := e.Get(st.PrincipalA, st.ID(1))
	if got.ApprovalStatus != ap.ApprovalExpired {
		t.Fatal("wall rollback revived record")
	}
}

func TestReconcileClosesUnclaimedWindow(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	voteApprove(t, e, 1)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	rec, _ := store.Load(key)
	end, _ := ap.ClaimEnd(rec)
	clock.Advance(end.Sub(clock.Wall()))
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Load(key)
	if rec.Header.Mint == nil || rec.Header.Mint.Reason != ap.MintReasonWindowClosed || rec.Header.ClaimCount != 0 {
		t.Fatal("unclaimed window left open")
	}
}

func TestReconcileGrantElapsedExpiry(t *testing.T) {
	e, clock, _, _ := engineFixture(t)
	submitGrant(t, e, 1, st.PrincipalA)
	approve(t, e, 1)
	clock.Suspend(2 * time.Hour)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(e.projections.grants) != 0 || e.projections.total.live != 0 {
		t.Fatal("tick retained expired grant")
	}
	clock.StepWall(-3 * time.Hour)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(e.projections.grants) != 0 {
		t.Fatal("grant revived")
	}
}

func TestRunnerTicksAndJoins(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, clock, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	clock.Advance(2 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run: %v", err)
		}
	}()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-timeout.C:
			t.Fatal("one-second tick did not commit expiry")
		case <-poll.C:
			rec, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if err != nil {
				t.Fatal(err)
			}
			if rec.Header.Decision != nil {
				return
			}
		}
	}
}

func TestReconcileErasesBytesAndAdvancesHorizonWithoutCommit(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	flushRecord(t, e, 1)
	e.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, _ time.Time) ([]string, error) {
		return []string{st.Sig(p.RequestID, 1, 1)}, nil
	})
	if ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum)); err != nil || len(ans.Signatures) != 1 {
		t.Fatalf("claim: %+v %v", ans, err)
	}
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	rec, _ := store.Load(key)
	end, _ := ap.LastEnd(rec)
	clock.Advance(end.Sub(clock.Wall()))
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Load(key)
	if len(rec.Payload.Signatures) != 0 {
		t.Fatal("expired signatures retained")
	}
	horizon := end.Add(e.config.Settings.ReportHorizon)
	if !e.projections.due[key].Equal(horizon) {
		t.Fatal("report horizon missing")
	}
	n := store.commits
	clock.Advance(horizon.Sub(clock.Wall()))
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if store.commits != n || !e.projections.due[key].After(horizon) {
		t.Fatal("no-op horizon did not advance without commit")
	}
}
