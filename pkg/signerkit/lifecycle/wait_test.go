package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type waitAnswer struct {
	result WaitResult
	err    error
}

func startWait(t *testing.T, e *Engine, ids ...string) (<-chan waitAnswer, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.published.mu.Lock()
	previous := len(e.published.waiters[ap.RecordKey(st.PrincipalA, ids[0])])
	e.published.mu.Unlock()
	done := make(chan waitAnswer, 1)
	go func() { r, err := e.WaitMany(ctx, st.PrincipalA, ids, ap.AwaitMaxWait); done <- waitAnswer{r, err} }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		e.published.mu.Lock()
		registered := len(e.published.waiters[ap.RecordKey(st.PrincipalA, ids[0])]) > previous
		e.published.mu.Unlock()
		if registered {
			return done, cancel
		}
		select {
		case <-deadline.C:
			t.Fatal("waiter did not register")
		case <-time.After(time.Millisecond):
		}
	}
}

func receiveWait(t *testing.T, done <-chan waitAnswer) waitAnswer {
	t.Helper()
	select {
	case answer := <-done:
		return answer
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not return")
	}
	return waitAnswer{}
}

func TestWaitManyConfirmedCommitOnly(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	first := submitGrant(t, e, 1, st.PrincipalA)
	submitGrant(t, e, 2, st.PrincipalA)
	other := submitGrant(t, e, 3, st.PrincipalA)
	done, _ := startWait(t, e, st.ID(2), st.ID(1))
	// Neither an unrelated commit, an unchanged replay nor a failed commit wakes.
	if _, err := e.AdminCancel(other.RecordHandle, ap.AdminCancel{PlanHash: other.PlanHash, Admin: st.Operator}); err != nil {
		t.Fatal(err)
	}
	submitGrant(t, e, 1, st.PrincipalA)
	e.mu.Lock()
	store.fail = true
	e.mu.Unlock()
	if _, err := e.AdminCancel(first.RecordHandle, ap.AdminCancel{PlanHash: first.PlanHash, Admin: st.Operator}); err == nil {
		t.Fatal("expected failure")
	}
	select {
	case r := <-done:
		t.Fatalf("unconfirmed wake: %+v", r)
	case <-time.After(20 * time.Millisecond):
	}
	e.mu.Lock()
	store.fail = false
	e.mu.Unlock()
	if _, err := e.AdminCancel(first.RecordHandle, ap.AdminCancel{PlanHash: first.PlanHash, Admin: st.Operator}); err != nil {
		t.Fatal(err)
	}
	got := receiveWait(t, done)
	if got.err != nil || got.result.WaitElapsed || len(got.result.Summaries) != 2 || got.result.Summaries[0].RequestID != st.ID(2) || got.result.Summaries[1].ApprovalStatus == ap.ApprovalPending {
		t.Fatalf("bad wake: %+v", got)
	}
	e.published.mu.Lock()
	defer e.published.mu.Unlock()
	if len(e.published.waiters) != 0 {
		t.Fatal("leaked registrations")
	}
}

func TestWaitManyReadOnlyTimeoutAndIsolation(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	submitGrant(t, e, 1, st.PrincipalA)
	clock.Advance(2 * time.Hour)
	before := store.commits
	for _, wait := range []time.Duration{0, time.Millisecond} {
		r, err := e.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, wait)
		if err != nil || !r.WaitElapsed || r.Summaries[0].ApprovalStatus != ap.ApprovalPending {
			t.Fatalf("timeout changed state: %+v %v", r, err)
		}
	}
	for _, shed := range []bool{false, true} {
		if shed {
			// Exercise the same owner boundary on a shed header.
			e.mu.Lock()
			key := ap.RecordKey(st.PrincipalA, st.ID(1))
			rec, _ := e.load(key)
			rec.Header.Shed = true
			rec.Payload = nil
			err := store.MemStore.Commit(key, *rec)
			if err == nil {
				e.publishLocked(key, rec)
			}
			e.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
		foreign, err1 := e.WaitMany(context.Background(), st.PrincipalB, []string{st.ID(1)}, time.Second)
		absent, err2 := e.WaitMany(context.Background(), st.PrincipalB, []string{st.ID(999)}, time.Second)
		if !reflect.DeepEqual(foreign, absent) || err1 == nil || err2 == nil || err1.Error() != err2.Error() {
			t.Fatal("owner isolation")
		}
	}
	if store.commits != before {
		t.Fatal("wait wrote records")
	}
}

func TestWaitManyCancellationAndBounds(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	submitGrant(t, e, 1, st.PrincipalA)
	done, cancel := startWait(t, e, st.ID(1))
	cancel()
	if got := receiveWait(t, done); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("cancel: %+v", got)
	}
	if len(e.published.waiters) != 0 {
		t.Fatal("canceled waiter leaked")
	}
	for _, tc := range []struct {
		ids  []string
		wait time.Duration
	}{
		{nil, 0}, {[]string{"bad"}, 0}, {[]string{st.ID(1), st.ID(1)}, 0},
		{make([]string, 101), 0}, {[]string{st.ID(1)}, -1}, {[]string{st.ID(1)}, ap.AwaitMaxWait + 1},
	} {
		_, err := e.WaitMany(context.Background(), st.PrincipalA, tc.ids, tc.wait)
		var code *ap.CodeError
		if !errors.As(err, &code) || code.Code != ap.CodeInvalidRequest {
			t.Fatalf("bounds: %v", err)
		}
	}
	ids := make([]string, 100)
	for i := range ids {
		ids[i] = st.ID(i + 1)
		if i > 0 {
			submitGrant(t, e, i+1, st.PrincipalA)
		}
	}
	if r, err := e.WaitMany(context.Background(), st.PrincipalA, ids, 0); err != nil || len(r.Summaries) != 100 {
		t.Fatalf("100 ids: %v", err)
	}
}

func TestWaitManyBroadcastAndRemoval(t *testing.T) {
	e, clock, _, _ := engineFixture(t)
	submitJob(t, e, 1)
	cancelAdmissionRecord(t, e, 1)
	clock.Advance(25 * time.Hour)
	first, _ := startWait(t, e, st.ID(1))
	second, _ := startWait(t, e, st.ID(1))
	if answer, err := e.Delete(st.PrincipalA, st.ID(1), true); err != nil || !answer.Removed {
		t.Fatal(answer, err)
	}
	for _, done := range []<-chan waitAnswer{first, second} {
		got := receiveWait(t, done)
		var code *ap.CodeError
		if !errors.As(got.err, &code) || code.Code != ap.CodeNotFound || len(got.result.Summaries) != 0 {
			t.Fatalf("removed record: %+v", got)
		}
	}
	e.published.mu.Lock()
	defer e.published.mu.Unlock()
	if len(e.published.waiters) != 0 {
		t.Fatal("broadcast leaked registrations")
	}
}
