package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

type testNotifier struct {
	mu         sync.Mutex
	burstMu    sync.Mutex
	parts      func(Notification) ([]int64, error)
	card       func(Notification) (int64, error)
	edit       func(Notification) (EditOutcome, error)
	status     func(string)
	incomplete func(int64)
	bursts     int
}

func (n *testNotifier) Burst(_ context.Context, fn func(BurstSession) error) error {
	n.burstMu.Lock()
	defer n.burstMu.Unlock()
	n.mu.Lock()
	n.bursts++
	n.mu.Unlock()
	return fn(n)
}
func (n *testNotifier) SendParts(_ context.Context, v Notification) ([]int64, error) {
	if n.parts != nil {
		return n.parts(v)
	}
	return []int64{1, 2}, nil
}
func (n *testNotifier) SendCard(_ context.Context, v Notification) (int64, error) {
	if n.card != nil {
		return n.card(v)
	}
	return 3, nil
}
func (n *testNotifier) EditCard(_ context.Context, _ int64, v Notification) (EditOutcome, error) {
	if n.edit != nil {
		return n.edit(v)
	}
	return EditConfirmed, nil
}
func (n *testNotifier) EditStatus(_ context.Context, _ int64, state string) error {
	if n.status != nil {
		n.status(state)
	}
	return errors.New("best effort")
}
func (n *testNotifier) MarkIncomplete(_ context.Context, id int64) error {
	if n.incomplete != nil {
		n.incomplete(id)
	}
	return nil
}
func runNotifier(t *testing.T, e *Engine, n *testNotifier) {
	t.Helper()
	e.config.Notifier = n
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("actors did not join")
		}
	})
}
func receiveNotify[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("notification timed out")
	}
	var zero T
	return zero
}
func TestNotifierBurstCommitAndLatestAssist(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, _, store, _ := engineFixture(t)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	partsEntered, release := make(chan struct{}), make(chan struct{})
	cards := make(chan Notification, 1)
	n := &testNotifier{
		parts: func(v Notification) ([]int64, error) {
			rec, _ := store.Load(key)
			if len(rec.Payload.Bursts) != 1 || rec.Payload.Bursts[0].Outcome != "" {
				t.Error("parts preceded write-ahead commit")
			}
			close(partsEntered)
			<-release
			return []int64{10, 11}, nil
		},
		card: func(v Notification) (int64, error) {
			rec, _ := store.Load(key)
			if rec.Payload.Bursts[0].Outcome != ap.OutcomeSent || len(rec.Payload.CardEntries) != 1 {
				t.Error("card preceded commits")
			}
			if v.Revision != 1 || v.AssistState != ap.AssistUnavailable || !reflect.DeepEqual(v.PartMessageIDs, []int64{10, 11}) {
				t.Error("card used stale snapshot")
			}
			cards <- v
			return 12, nil
		},
	}
	// Cleanup precedes goleak's deferred check.
	t.Run("run", func(t *testing.T) {
		runNotifier(t, e, n)
		submitJob(t, e, 1)
		receiveNotify(t, partsEntered)
		command(t, e, 1, ap.AssistDone{Unavailable: "test"})
		close(release)
		receiveNotify(t, cards)
		waitNotifyRecord(t, store, func(r ap.R1) bool {
			return len(r.Payload.CardEntries) > 0 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
		})
	})
	rec, _ := store.Load(key)
	if rec.Payload.CardEntries[0].Outcome != ap.OutcomeSent {
		t.Fatal("card outcome not committed")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bursts != 1 {
		t.Fatalf("burst sessions = %d", n.bursts)
	}
}
func TestNotifierEditRetryAndReplacement(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	command(t, e, 1, ap.BurstStart{})
	command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
	command(t, e, 1, ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, 1, ap.CardDone{Handle: "abcdefghijkl", MsgID: 3})
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	edits := make(chan Notification, 3)
	cards := make(chan Notification, 1)
	attempts := 0
	n := &testNotifier{
		edit: func(v Notification) (EditOutcome, error) {
			attempts++
			edits <- v
			if attempts == 1 {
				return EditPossible, context.DeadlineExceeded
			}
			return EditFailed, errors.New("known failure")
		},
		card: func(v Notification) (int64, error) { cards <- v; return 4, nil },
	}
	t.Run("run", func(t *testing.T) {
		runNotifier(t, e, n)
		first := receiveNotify(t, edits)
		second := receiveNotify(t, edits)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("retry changed edit bytes or challenge")
		}
		replacement := receiveNotify(t, cards)
		waitNotifyRecord(t, store, func(r ap.R1) bool {
			return len(r.Payload.CardEntries) == 3 && r.Payload.CardEntries[2].Outcome == ap.OutcomeSent
		})
		if replacement.Handle == first.Handle || replacement.Challenge == first.Challenge {
			t.Fatal("replacement reused challenge")
		}
	})
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if len(rec.Payload.CardEntries) != 3 || !rec.Payload.CardEntries[1].Retired || rec.Payload.CardEntries[2].Kind != ap.CardReplacement {
		t.Fatalf("entries: %+v", rec.Payload.CardEntries)
	}
}
func TestNotifierLiveFailureMarksOnlyCommittedParts(t *testing.T) {
	for _, cardFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "parts", true: "card"}[cardFailure], func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			marked := make(chan int64, 2)
			n := &testNotifier{incomplete: func(id int64) {
				rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalError {
					t.Error("cleanup preceded error commit")
				}
				marked <- id
			}}
			n.parts = func(Notification) ([]int64, error) {
				if !cardFailure {
					return []int64{1, 2}, context.Canceled
				}
				return []int64{1, 2}, nil
			}
			n.card = func(Notification) (int64, error) { return 0, context.DeadlineExceeded }
			runNotifier(t, e, n)
			submitJob(t, e, 1)
			if receiveNotify(t, marked) != 1 || receiveNotify(t, marked) != 2 {
				t.Fatal("incomplete IDs")
			}
		})
	}
}

func waitNotifyRecord(t *testing.T, store Store, ready func(ap.R1) bool) ap.R1 {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		rec, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
		if err == nil && ready(rec) {
			return rec
		}
		select {
		case <-deadline:
			t.Fatal("record did not settle")
		case <-ticker.C:
		}
	}
}
func TestNotifierConfirmedEditAndStatus(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	command(t, e, 1, ap.BurstStart{})
	command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
	command(t, e, 1, ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, 1, ap.CardDone{Handle: "abcdefghijkl", MsgID: 3})
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	edits := make(chan Notification, 1)
	states := make(chan string, 2)
	n := &testNotifier{
		edit:   func(v Notification) (EditOutcome, error) { edits <- v; return EditConfirmed, nil },
		status: func(state string) { states <- state },
	}
	runNotifier(t, e, n)
	edit := receiveNotify(t, edits)
	waitNotifyRecord(t, store, func(r ap.R1) bool { return len(r.Payload.CardEntries) == 2 && r.Payload.CardEntries[1].Confirmed })
	rec := command(t, e, 1, ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: edit.Handle, Challenge: edit.Challenge, MsgID: 3}})
	if rec.Header.Decision == nil {
		t.Fatal("confirmed edit was not tappable")
	}
	receiveNotify(t, states)
	waitNotifyRecord(t, store, func(r ap.R1) bool { return len(r.Payload.StatusEdits) == 1 })
	e.mu.Lock()
	for range 20 {
		e.nudgeNotifyLocked(ap.RecordKey(st.PrincipalA, st.ID(1)))
	}
	e.mu.Unlock()
	select {
	case <-states:
		t.Fatal("status edit repeated")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestNotifierCommitFailureStopsDependentIO(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	store.fail = true
	called := make(chan struct{}, 1)
	e.config.Notifier = &testNotifier{parts: func(Notification) ([]int64, error) {
		called <- struct{}{}
		return nil, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	if err := receiveNotify(t, done); err == nil {
		t.Fatal("lost commit failure")
	}
	select {
	case <-called:
		t.Fatal("sent before confirmed commit")
	default:
	}
}

func TestNotifierRenotifyStopsEditRetry(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	command(t, e, 1, ap.BurstStart{})
	command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
	command(t, e, 1, ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, 1, ap.CardDone{Handle: "abcdefghijkl", MsgID: 3})
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	edits := make(chan Notification, 2)
	cards := make(chan Notification, 1)
	n := &testNotifier{
		edit: func(v Notification) (EditOutcome, error) { edits <- v; return EditPossible, nil },
		card: func(v Notification) (int64, error) { cards <- v; return 4, nil },
	}
	runNotifier(t, e, n)
	receiveNotify(t, edits)
	command(t, e, 1, ap.Renotify{})
	receiveNotify(t, cards)
	waitNotifyRecord(t, store, func(r ap.R1) bool {
		return len(r.Payload.CardEntries) == 3 && r.Payload.CardEntries[2].Outcome == ap.OutcomeSent
	})
	select {
	case <-edits:
		t.Fatal("retired edit retried")
	case <-time.After(1100 * time.Millisecond):
	}
}

func TestNotifierRecoverySupersedesEditWithoutResendingParts(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	command(t, e, 1, ap.BurstStart{})
	command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
	command(t, e, 1, ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, 1, ap.CardDone{Handle: "abcdefghijkl", MsgID: 3})
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	command(t, e, 1, ap.EditStart{Handle: "bcdefghijklm", ChalHash: ap.ChallengeHash("1123456789abcdef")})
	recovered, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	edits := make(chan Notification, 1)
	n := &testNotifier{
		parts: func(Notification) ([]int64, error) { t.Error("recovery resent parts"); return nil, nil },
		edit:  func(v Notification) (EditOutcome, error) { edits <- v; return EditConfirmed, nil },
	}
	runNotifier(t, recovered, n)
	edit := receiveNotify(t, edits)
	if edit.Handle == "bcdefghijklm" || edit.Challenge == "1123456789abcdef" {
		t.Fatal("recovery reused lost challenge")
	}
	rec := waitNotifyRecord(t, store, func(r ap.R1) bool { return len(r.Payload.CardEntries) == 3 && r.Payload.CardEntries[2].Confirmed })
	if !rec.Payload.CardEntries[1].Retired {
		t.Fatal("old edit remained valid")
	}
}
