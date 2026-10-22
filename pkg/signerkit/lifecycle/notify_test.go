package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	ar "github.com/karthikeyan5/sshgate/src/approvalreview"
	"go.uber.org/goleak"
)

type testNotifier struct {
	mu            sync.Mutex
	burstMu       sync.Mutex
	parts         func(Notification) ([]int64, error)
	card          func(Notification) (int64, error)
	edit          func(Notification) (EditOutcome, error)
	status        func(string)
	statusDisplay func(StatusDisplay)
	incomplete    func(int64)
	bursts        int
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
	if _, err := ar.PackParts(ar.View{RequestID: st.ID(1)}, v.Handle); err != nil {
		return nil, err
	}
	if n.parts != nil {
		return n.parts(v)
	}
	return []int64{1, 2}, nil
}
func (n *testNotifier) SendCard(_ context.Context, v Notification) (int64, error) {
	if _, err := ar.DecisionCard(ar.View{RequestID: st.ID(1)}, v.Handle, len(v.PartMessageIDs)); err != nil {
		return 0, err
	}
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
func (n *testNotifier) EditStatus(_ context.Context, _ int64, display StatusDisplay) error {
	if n.statusDisplay != nil {
		n.statusDisplay(display)
	}
	if n.status != nil {
		n.status(display.State)
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
	partsHandle := ap.CardHandleFor(key, 0)
	n := &testNotifier{
		parts: func(v Notification) ([]int64, error) {
			if v.Handle != partsHandle {
				t.Errorf("parts handle = %q, want %q", v.Handle, partsHandle)
			}
			rec, _ := store.Load(key)
			if len(rec.Payload.Bursts) != 1 || rec.Payload.Bursts[0].Outcome != "" {
				t.Error("parts preceded write-ahead commit")
			}
			close(partsEntered)
			<-release
			return []int64{10, 11}, nil
		},
		card: func(v Notification) (int64, error) {
			if v.Handle != partsHandle {
				t.Errorf("assist completion changed card handle: got %q, want %q", v.Handle, partsHandle)
			}
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
	original := ap.CardHandleFor(ap.RecordKey(st.PrincipalA, st.ID(1)), 0)
	submitJob(t, e, 1)
	command(t, e, 1, ap.BurstStart{})
	command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
	command(t, e, 1, ap.CardStart{Handle: original, ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, 1, ap.CardDone{Handle: original, MsgID: 3})
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
		if replacement.Handle == original || first.Handle == original || replacement.Handle == first.Handle || replacement.Challenge == first.Challenge {
			t.Fatal("replacement reused challenge")
		}
		if first.PartsHandle != original || replacement.PartsHandle != original {
			t.Fatal("edit or replacement lost the review parts handle")
		}
		answer, err := e.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: original, Challenge: "0123456789abcdef", MsgID: 3}})
		if err != nil || answer.Reason != "retired" {
			t.Fatalf("original card tap: %+v %v", answer, err)
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

func TestNotifierDerivedHandleRecoveryAndRenotify(t *testing.T) {
	for _, cut := range []string{"burst_done", "renotify_before_card", "uncertain_burst"} {
		t.Run(cut, func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			submitJob(t, e, 1)
			command(t, e, 1, ap.AssistDone{Unavailable: "test"})
			command(t, e, 1, ap.BurstStart{})
			if cut != "uncertain_burst" {
				command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{10}})
			}
			if cut == "renotify_before_card" {
				command(t, e, 1, ap.Renotify{})
			}
			recovered, err := New(e.config)
			if err != nil {
				t.Fatal(err)
			}
			cards := make(chan Notification, 1)
			parts := make(chan Notification, 1)
			n := &testNotifier{parts: func(v Notification) ([]int64, error) { parts <- v; return []int64{11}, nil }, card: func(v Notification) (int64, error) { cards <- v; return 12, nil }}
			runNotifier(t, recovered, n)
			if recovered.epoch == e.epoch {
				t.Fatal("restart reused epoch")
			}
			if cut == "uncertain_burst" {
				select {
				case <-parts:
					t.Fatal("uncertain burst resent")
				case <-cards:
					t.Fatal("uncertain burst got card")
				case <-time.After(50 * time.Millisecond):
				}
				return
			}
			card := receiveNotify(t, cards)
			gen := 0
			if cut == "renotify_before_card" {
				gen = 1
				part := receiveNotify(t, parts)
				if part.Handle != card.Handle {
					t.Fatal("parts/card differ")
				}
				oldHandle := ap.CardHandleFor(ap.RecordKey(st.PrincipalA, st.ID(1)), 0)
				answer, err := recovered.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: oldHandle, Challenge: "0123456789abcdef", MsgID: 12}})
				if err == nil && !answer.Noise {
					t.Fatalf("pre-renotify handle was accepted: %+v", answer)
				}
			} else {
				select {
				case <-parts:
					t.Fatal("recovery resent parts")
				default:
				}
			}
			want := ap.CardHandleFor(ap.RecordKey(st.PrincipalA, st.ID(1)), gen)
			if card.Handle != want || card.PartsHandle != want || !ap.ValidChallenge(card.Challenge) {
				t.Fatalf("card %+v, want %s", card, want)
			}
			waitNotifyRecord(t, store, func(r ap.R1) bool {
				return len(r.Payload.CardEntries) > 0 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
			})
		})
	}
}

func TestNotifierDerivedHandleRendererAndVote(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	cards := make(chan Notification, 2)
	n := &testNotifier{
		parts: func(n Notification) ([]int64, error) {
			view := ar.View{RequestID: st.ID(1), Reason: strings.Repeat("x", 100), Items: []ar.Item{{TextLabel: "Command", Text: strings.Repeat("x", 6000)}}}
			parts, err := ar.PackParts(view, n.Handle)
			if err != nil {
				return nil, err
			}
			if len(parts) < 2 {
				t.Error("fixture not multipart")
			}
			ids := make([]int64, len(parts))
			for i, part := range parts {
				if !strings.Contains(part, "Card: "+n.Handle) {
					t.Error("missing handle")
				}
				ids[i] = int64(i + 1)
			}
			return ids, nil
		}, card: func(n Notification) (int64, error) {
			text, err := ar.DecisionCard(ar.View{RequestID: st.ID(1)}, n.Handle, len(n.PartMessageIDs))
			if !strings.Contains(text, "Card: "+n.Handle) {
				t.Error("card handle missing")
			}
			cards <- n
			return 100, err
		},
	}
	submitJob(t, e, 1)
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	runNotifier(t, e, n)
	first := receiveNotify(t, cards)
	waitNotifyRecord(t, store, func(r ap.R1) bool {
		return len(r.Payload.CardEntries) > 0 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
	})
	if first.Handle != ap.CardHandleFor(key, 0) {
		t.Fatal("first handle not derived")
	}
	command(t, e, 1, ap.Renotify{})
	second := receiveNotify(t, cards)
	waitNotifyRecord(t, store, func(r ap.R1) bool {
		return len(r.Payload.CardEntries) == 2 && r.Payload.CardEntries[1].Outcome == ap.OutcomeSent
	})
	if second.Handle != ap.CardHandleFor(key, 1) || second.Handle == first.Handle || second.Challenge == first.Challenge {
		t.Fatal("renotify reused handle/challenge")
	}
	rec := command(t, e, 1, ap.CastVote{Operator: st.Operator, Decision: ap.VoteDeny, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: first.Handle, Challenge: first.Challenge, MsgID: 100}})
	if len(rec.Header.Votes) > 0 || rec.Header.Decision != nil {
		t.Fatal("retired handle voted")
	}
	callback := "v:a:" + second.Handle + ":" + second.Challenge
	fields := strings.Split(callback, ":")
	answer, err := e.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: fields[2], Challenge: fields[3], MsgID: 100}})
	if err != nil || answer.Code != "" {
		t.Fatalf("tap: %+v %v", answer, err)
	}
	rec, err = store.Load(key)
	if err != nil || rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalApproved {
		t.Fatalf("tap did not approve: %+v %v", rec.Header.Decision, err)
	}
}

func TestNotifierRecoveredFirstCardFreshChallenge(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	submitJob(t, e, 1)
	command(t, e, 1, ap.BurstStart{})
	cut := command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1, 2}})
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	var cards []Notification
	for range 2 {
		store := &MemStore{}
		if err := store.Commit(key, cut); err != nil {
			t.Fatal(err)
		}
		config := e.config
		config.Store = store
		recovered, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("restart", func(t *testing.T) {
			sent := make(chan Notification, 1)
			n := &testNotifier{parts: func(Notification) ([]int64, error) { t.Error("resent committed parts"); return nil, nil }, card: func(n Notification) (int64, error) { sent <- n; return 3, nil }}
			runNotifier(t, recovered, n)
			cards = append(cards, receiveNotify(t, sent))
			waitNotifyRecord(t, store, func(r ap.R1) bool {
				return len(r.Payload.CardEntries) == 1 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
			})
		})
	}
	if cards[0].Handle != ap.CardHandleFor(key, 0) || cards[1].Handle != cards[0].Handle || cards[1].Challenge == cards[0].Challenge {
		t.Fatal("recovery did not preserve handle and mint a fresh challenge")
	}
}

func TestNotifierNotExecutableReason(t *testing.T) {
	for _, reason := range []string{ap.MintReasonGrantNotLive, ap.MintReasonStaleTransferKey, ap.MintReasonReservedVerb, ap.MintReasonClockSkew, ap.MintReasonSigningFailed} {
		t.Run(reason, func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			submitJob(t, e, 1)
			rec := approve(t, e, 1)
			rec.Header.Mint = &ap.MintSlot{State: ap.MintError, Reason: reason}
			if err := store.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), rec); err != nil {
				t.Fatal(err)
			}
			recovered, err := New(e.config)
			if err != nil {
				t.Fatal(err)
			}
			displays := make(chan StatusDisplay, 2)
			runNotifier(t, recovered, &testNotifier{statusDisplay: func(display StatusDisplay) { displays <- display }})
			if got := receiveNotify(t, displays); got != (StatusDisplay{State: "not_executable", Reason: reason}) {
				t.Fatalf("status display: %+v", got)
			}
			after := waitNotifyRecord(t, store, func(r ap.R1) bool { return len(r.Payload.StatusEdits) == 1 })
			if after.Payload.StatusEdits[0].State != "not_executable" {
				t.Fatal("reason changed the durable status-edit key")
			}
		})
	}
}
