package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

type auditFunc func(context.Context, ap.AuditMetadata) error

func (f auditFunc) WriteApproval(ctx context.Context, event ap.AuditMetadata) error {
	return f(ctx, event)
}

func startEngine(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run: %v", err)
		}
	})
}

func TestFlushBatchOrderingAndFailure(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	e.config.Caps.LivePerPrincipal, e.config.Caps.LiveTotal = 300, 300
	// Reverse assist deadlines relative to IDs.
	for id := 1; id <= 300; id++ {
		draft := st.JobDraft(st.ID(id), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))
		e.config.AssistTimeout = time.Duration(301-id) * time.Millisecond
		if _, err := e.Submit(context.Background(), st.PrincipalA, draft); err != nil {
			t.Fatal(err)
		}
	}
	var ids []string
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error {
		ids = append(ids, event.RequestID)
		return errors.New("sink unavailable")
	})
	if failed, err := e.flushPass(context.Background()); !failed || err != nil || len(ids) != 1 {
		t.Fatalf("failure pass: %v %v %d", failed, err, len(ids))
	}
	if len(e.projections.unflushed) != 300 {
		t.Fatal("failed sink advanced projection")
	}
	ids = nil
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error { ids = append(ids, event.RequestID); return nil })
	if failed, err := e.flushPass(context.Background()); failed || err != nil {
		t.Fatal(failed, err)
	}
	if len(ids) != 256 || len(e.projections.unflushed) != 44 {
		t.Fatalf("batch %d left %d", len(ids), len(e.projections.unflushed))
	}
	for i, id := range ids {
		if id != st.ID(300-i) {
			t.Fatalf("deadline ordering at %d: %s", i, id)
		}
	}
	if _, err := e.flushPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.projections.unflushed) != 0 {
		t.Fatal("not drained")
	}
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if ap.Unflushed(rec) {
		t.Fatal("flush not committed")
	}
}

func TestFlushSnapshotAndCommitFailure(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	voteApprove(t, e, 1)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	before, _ := store.Load(key)
	var keys []string
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error {
		keys = append(keys, event.EventKey)
		if len(keys) == 1 {
			// Sink I/O must not hold the engine lock; this appends after the snapshot.
			_, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{})
			checkCode(t, err, ap.CodeInvalidClaim)
		}
		return nil
	})
	if failed, err := e.flushPass(context.Background()); failed || err != nil {
		t.Fatal(failed, err)
	}
	after, _ := store.Load(key)
	if after.Header.AuditedThrough != before.Header.OutboxSeq || !ap.Unflushed(after) {
		t.Fatal("acknowledged an unwritten concurrent event")
	}
	if _, ok := e.projections.unflushed[key]; !ok {
		t.Fatal("lost concurrent outbox")
	}
	keys = nil
	store.fail = true
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error { keys = append(keys, event.EventKey); return nil })
	if _, err := e.flushPass(context.Background()); err == nil {
		t.Fatal("swallowed commit failure")
	}
	store.fail = false
	if _, err := e.flushPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != keys[1] {
		t.Fatalf("retry keys: %v", keys)
	}
}

func TestFlushPartialSinkFailureReplaysPrefix(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	voteApprove(t, e, 1)
	var keys []string
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error {
		keys = append(keys, event.EventKey)
		if len(keys) == 2 {
			return errors.New("sink failed")
		}
		return nil
	})
	if failed, err := e.flushPass(context.Background()); !failed || err != nil {
		t.Fatal(failed, err)
	}
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Header.AuditedThrough != 0 {
		t.Fatal("partial sink write acknowledged")
	}
	if _, err := e.flushPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if keys[0] != keys[2] {
		t.Fatal("prefix retry lost stable event key")
	}
}

func TestClaimFlushWait(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	for _, delay := range []time.Duration{time.Second, 3 * time.Second} {
		for _, grant := range []bool{false, true} {
			t.Run(fmt.Sprintf("delay=%s/grant=%v", delay, grant), func(t *testing.T) {
				e, _, _, _ := engineFixture(t)
				if grant {
					submitGrant(t, e, 2, st.PrincipalA)
					approve(t, e, 2)
					flushRecord(t, e, 2)
				}
				sum := submitJob(t, e, 1)
				if !grant {
					voteApprove(t, e, 1)
				}
				e.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, _ time.Time) ([]string, error) {
					return []string{st.Sig(p.RequestID, 1, 1)}, nil
				})
				first := true
				e.config.AuditWriter = auditFunc(func(ctx context.Context, _ ap.AuditMetadata) error {
					if first {
						first = false
						timer := time.NewTimer(delay)
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return nil
				})
				startEngine(t, e)
				start := time.Now()
				ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
				if err != nil {
					t.Fatal(err)
				}
				if delay < 2*time.Second {
					if len(ans.Signatures) != 1 || time.Since(start) > 2*time.Second {
						t.Fatalf("claim did not wait for flush: %+v", ans)
					}
				} else {
					if ans.Claim != ap.ClaimNotReady || time.Since(start) < 1900*time.Millisecond || time.Since(start) > 2800*time.Millisecond {
						t.Fatalf("wait budget: %+v %s", ans, time.Since(start))
					}
					ans, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
					if err != nil || len(ans.Signatures) != 1 {
						t.Fatalf("retry: %+v %v", ans, err)
					}
				}
			})
		}
	}
}

func TestFlusherRetryAndClockIndependence(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	e, clock, _, _ := engineFixture(t)
	submitJob(t, e, 1)
	voteApprove(t, e, 1)
	var calls atomic.Int32
	wrote := make(chan struct{}, 1)
	e.config.AuditWriter = auditFunc(func(_ context.Context, _ ap.AuditMetadata) error {
		if calls.Add(1) == 1 {
			return errors.New("once")
		}
		select {
		case wrote <- struct{}{}:
		default:
		}
		return nil
	})
	startEngine(t, e)
	select {
	case <-wrote:
	case <-time.After(1900 * time.Millisecond):
		t.Fatal("no retry without a mutation")
	}
	e.mu.Lock()
	due := e.projections.due[ap.RecordKey(st.PrincipalA, st.ID(1))]
	e.mu.Unlock()
	if !due.After(clock.Wall()) {
		t.Fatal("outbox polluted due index")
	}
}

func TestBlockedSinkDoesNotBlockClockOrClaimCancellation(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	e, clock, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	entered := make(chan struct{})
	e.config.AuditWriter = auditFunc(func(ctx context.Context, _ ap.AuditMetadata) error { close(entered); <-ctx.Done(); return ctx.Err() })
	startEngine(t, e)
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Claim(ctx, st.PrincipalA, st.ID(1), claimOf(1, sum)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(e.flushWaiters) != 0 {
		t.Fatal("canceled waiter retained")
	}
	clock.Advance(61 * time.Second)
	deadline := time.NewTimer(1800 * time.Millisecond)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("blocked sink prevented Clock")
		case <-poll.C:
			rec, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if err != nil {
				t.Fatal(err)
			}
			if rec.Header.Mint != nil && rec.Header.Mint.Reason == ap.MintReasonWindowClosed {
				return
			}
		}
	}
}

func TestAuditMetadataEventBinding(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	voteApprove(t, e, 1)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	rec, _ := store.Load(key)
	var events []ap.AuditMetadata
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error { events = append(events, event); return nil })
	if _, err := e.flushPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, event := range events {
		raw := rec.Header.Outbox[i]
		if event.EventKey != ap.EventKey(key, raw.Seq) || event.PlanHash != rec.Header.PlanHash || event.RationaleRedacted != rec.Header.RationaleRedacted || event.Replay != raw.Replay || !reflect.DeepEqual(event.Assist, raw.Assist) {
			t.Fatal("metadata differs from committed event")
		}
		if raw.Kind == ap.EventDecision && (event.DecidedAt == nil || !event.DecidedAt.Equal(rec.Header.Decision.DecidedAt)) {
			t.Fatal("decision timestamp missing")
		}
	}
	noise := auditMetadata(key, rec.Header, ap.OutboxEvent{Seq: 99, Kind: ap.EventVoteRefused, Replay: true, Detail: "stale_challenge", Operator: st.Operator, NoiseDropped: 8})
	if !strings.Contains(noise.Transition, "stale_challenge") || !strings.Contains(noise.Transition, "noise_dropped:8") || !strings.Contains(noise.Transition, st.Operator) {
		t.Fatal("audit dropped reason or fold count")
	}
}

func TestFlushNoDeadlineLast(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	e.config.Settings.Retention = 0
	e.config.Settings.MaxAge = 0
	sum := submitJob(t, e, 1)
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	if _, err := e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin}); err != nil {
		t.Fatal(err)
	}
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	if _, ok := e.projections.due[key]; ok {
		t.Fatal("fixture has a deadline")
	}
	submitJob(t, e, 2)
	var ids []string
	e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error { ids = append(ids, event.RequestID); return nil })
	if _, err := e.flushPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ids[0] != st.ID(2) || ids[len(ids)-1] != st.ID(1) {
		t.Fatalf("no-deadline ordering: %v", ids)
	}
}

func TestFlushWakeRequiresConfirmedDecisionPrefix(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	before, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	voteApprove(t, e, 1)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	waiter := &flushWaiter{ready: make(chan struct{}), users: 1}
	e.flushWaiters[key] = waiter
	command(t, e, 1, ap.Flush{Through: before.Header.OutboxSeq})
	select {
	case <-waiter.ready:
		t.Fatal("prefix before decision woke Claim")
	default:
	}
	rec, _ := store.Load(key)
	store.fail = true
	e.mu.Lock()
	_, _, err := e.commitLocked(key, &rec, ap.Flush{Through: rec.Header.OutboxSeq}, e.now(), ap.Inputs{})
	e.mu.Unlock()
	if err == nil {
		t.Fatal("commit succeeded")
	}
	select {
	case <-waiter.ready:
		t.Fatal("unconfirmed flush woke Claim")
	default:
	}
	store.fail = false
	flushRecord(t, e, 1)
	select {
	case <-waiter.ready:
	default:
		t.Fatal("confirmed flush did not wake Claim")
	}
}

func TestFlusherPostCommitNudgeAndSingleRunner(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	e, _, _, _ := engineFixture(t)
	entered := make(chan struct{}, 10)
	e.config.AuditWriter = auditFunc(func(_ context.Context, _ ap.AuditMetadata) error { entered <- struct{}{}; return nil })
	submitJob(t, e, 1)
	startEngine(t, e)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("startup outbox not flushed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("second flusher admitted")
	}
	submitJob(t, e, 2)
	select {
	case <-entered:
	case <-time.After(700 * time.Millisecond):
		t.Fatal("commit did not nudge flusher")
	}
}

func TestClaimPendingDoesNotWait(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ans, err := e.Claim(ctx, st.PrincipalA, st.ID(1), claimOf(1, sum))
	if err != nil || ans.Claim != ap.ClaimNotReady || len(e.flushWaiters) != 0 {
		t.Fatalf("pending Claim waited: %+v %v", ans, err)
	}
}

func TestDeadSinkNudgesWaitForRetryTick(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	e, _, _, _ := engineFixture(t)
	submitJob(t, e, 1)
	calls := make(chan struct{}, 100)
	e.config.AuditWriter = auditFunc(func(_ context.Context, _ ap.AuditMetadata) error { calls <- struct{}{}; return errors.New("dead sink") })
	startEngine(t, e)
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("no first attempt")
	}
	for range 100 {
		e.nudgeFlush()
	}
	select {
	case <-calls:
		t.Fatal("dead sink retried before tick")
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("dead sink not retried on tick")
	}
}

func TestCanceledFlushDoesNotAcknowledge(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { cancel(); return nil })
	if _, err := e.flushPass(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled flush: %v", err)
	}
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Header.AuditedThrough != 0 {
		t.Fatal("canceled sink call acknowledged")
	}
}

func TestClaimFlushWaitersCancelIndependently(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	e, _, _, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	e.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, _ time.Time) ([]string, error) {
		return []string{st.Sig(p.RequestID, 1, 1)}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceled := make(chan error, 1)
	completed := make(chan ap.Answer, 1)
	go func() { _, err := e.Claim(ctx, st.PrincipalA, st.ID(1), claimOf(1, sum)); canceled <- err }()
	go func() {
		ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
		if err != nil {
			t.Error(err)
		}
		completed <- ans
	}()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	for {
		e.mu.Lock()
		waiter := e.flushWaiters[key]
		ready := waiter != nil && waiter.users == 2
		e.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-poll.C:
		case <-deadline.C:
			t.Fatal("Claims did not release the store lock")
		}
	}
	cancel()
	if err := <-canceled; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	flushRecord(t, e, 1)
	var ans ap.Answer
	select {
	case ans = <-completed:
	case <-time.After(500 * time.Millisecond):
		t.Error("cancel removed another Claim's wake-up")
		ans = <-completed
	}
	if len(ans.Signatures) != 1 {
		t.Fatalf("remaining Claim: %+v", ans)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.flushWaiters) != 0 {
		t.Fatal("waiter retained")
	}
}
