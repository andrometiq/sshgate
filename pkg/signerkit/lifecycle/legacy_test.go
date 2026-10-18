package lifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"go.uber.org/goleak"
)

type legacyAuditSink struct {
	mu            sync.Mutex
	events        []ap.AuditMetadata
	fail          bool
	answered      bool
	requireAnswer bool
}

func (s *legacyAuditSink) WriteApproval(_ context.Context, m ap.AuditMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requireAnswer && !s.answered {
		panic("audit preceded callback answer")
	}
	s.events = append(s.events, m)
	if s.fail {
		return errors.New("sink failed")
	}
	return nil
}
func legacyRequest(t *testing.T, e *Engine, ctx context.Context, uid uint32, id string, live bool) (*LegacyRequest, ap.CastVote) {
	t.Helper()
	handle, err := ap.NewCardHandle(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := ap.NewChallenge(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	r, err := e.reserveLegacyLocked(ctx, uid, id, handle, challenge)
	if r != nil {
		r.live = live
	}
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return r, ap.CastVote{Operator: "telegram:1", Decision: ap.VoteApprove, Card: &ap.CardTap{Handle: handle, Challenge: challenge}}
}
func legacyTap(t *testing.T, e *Engine, v ap.CastVote) LegacyTapResult {
	t.Helper()
	result, err := e.VoteLegacy(v, func(LegacyTapResult) {})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestLegacyDuplicatePending(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprint(live), func(t *testing.T) {
			e, _, _, _ := engineFixture(t)
			defer e.Close()
			r, v := legacyRequest(t, e, context.Background(), 7, "same", live)
			e.mu.Lock()
			_, err := e.reserveLegacyLocked(context.Background(), 7, "same", "abcdefghijkl", "0123456789abcdef")
			e.mu.Unlock()
			if err == nil || err.Error() != "telegram: request_id already pending — refusing duplicate" {
				t.Fatalf("duplicate: %v", err)
			}
			legacyRequest(t, e, context.Background(), 8, "same", false)
			e.mu.Lock()
			r.live = true
			e.mu.Unlock()
			if !legacyTap(t, e, v).Resolved {
				t.Fatal("original displaced")
			}
			legacyRequest(t, e, context.Background(), 7, "same", false)
		})
	}
}
func TestLegacyPreparingAndChallenge(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	defer e.Close()
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	r, v := legacyRequest(t, e, context.Background(), 7, "legacy", false)
	if got := legacyTap(t, e, v); got.Resolved || got.Answer != LegacyTapRefused {
		t.Fatal(got)
	}
	e.mu.Lock()
	r.live = true
	e.mu.Unlock()
	wrong := v
	card := *v.Card
	card.Challenge = "ffffffffffffffff"
	wrong.Card = &card
	if legacyTap(t, e, wrong).Resolved {
		t.Fatal("wrong challenge accepted")
	}
	if len(sink.events) != 2 {
		t.Fatal(sink.events)
	}
	for _, m := range sink.events {
		if m.Transition != "legacy_vote_refused{stale_challenge}" || !m.Replay {
			t.Fatal(m)
		}
	}
	if !legacyTap(t, e, v).Resolved {
		t.Fatal("valid tap refused")
	}
	if store.commits != 0 {
		t.Fatal("legacy journaled")
	}
}
func TestLegacyReplayAndAuditFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			defer e.Close()
			sink := &legacyAuditSink{fail: fail, requireAnswer: true}
			e.config.AuditWriter = sink
			r, v := legacyRequest(t, e, context.Background(), 7, "legacy", true)
			first := legacyTap(t, e, v)
			if !first.Resolved || first.Answer != "approved" || r.Wait() != (LegacyResult{Status: "approved", ResolvedBy: v.Operator}) {
				t.Fatal(first, r.Wait())
			}
			for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
				v.Decision = decision
				sink.answered = false
				result, err := e.VoteLegacy(v, func(got LegacyTapResult) {
					if got.Resolved || got.Answer != LegacyTapRefused {
						t.Error(got)
					}
					sink.answered = true
				})
				if err != nil || result.Resolved {
					t.Fatal(result, err)
				}
			}
			if len(sink.events) != 2 || sink.events[0].Decision != ap.VoteApprove || sink.events[1].Decision != ap.VoteDeny {
				t.Fatal(sink.events)
			}
			for _, m := range sink.events {
				if m.Transition != "legacy_vote_replay" || !m.Replay || m.RequestID != "legacy" || m.Principal != "local-uid:7" {
					t.Fatal(m)
				}
			}
			if r.Wait().Status != "approved" || store.commits != 0 {
				t.Fatal("replay changed resolution or persisted")
			}
		})
	}
}
func TestLegacyConcurrentTaps(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	e, _, _, _ := engineFixture(t)
	defer e.Close()
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	r, v := legacyRequest(t, e, context.Background(), 7, "race", true)
	start := make(chan struct{})
	results := make(chan LegacyTapResult, 2)
	for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
		go func(decision string) {
			<-start
			vote := v
			vote.Decision = decision
			result, err := e.VoteLegacy(vote, func(LegacyTapResult) {})
			if err != nil {
				t.Error(err)
			}
			results <- result
		}(decision)
	}
	close(start)
	a, b := <-results, <-results
	if a.Resolved == b.Resolved || len(sink.events) != 1 || sink.events[0].Transition != "legacy_vote_replay" {
		t.Fatal(a, b, sink.events)
	}
	if r.Wait().Status != "approved" && r.Wait().Status != "denied" {
		t.Fatal(r.Wait())
	}
}
func TestLegacyExpiryDisconnectAndClose(t *testing.T) {
	for _, mode := range []string{"deadline", "disconnect", "close", "context-deadline"} {
		t.Run(mode, func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			defer e.Close()
			sink := &legacyAuditSink{}
			e.config.AuditWriter = sink
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "context-deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer deadlineCancel()
			}
			r, v := legacyRequest(t, e, ctx, 7, "expire", true)
			switch mode {
			case "deadline":
				clock.Advance(sigwire.ApprovalWindow)
			case "context-deadline":
				<-ctx.Done()
			case "disconnect":
				cancel()
			case "close":
				e.Close()
			}
			if mode != "close" {
				if got := legacyTap(t, e, v); got.Resolved || got.Answer != LegacyTapRefused {
					t.Fatal(got)
				}
				if len(sink.events) != 1 || sink.events[0].Transition != "legacy_vote_refused{expired}" {
					t.Fatal(sink.events)
				}
			} else if _, err := e.VoteLegacy(v, func(LegacyTapResult) {}); err == nil {
				t.Fatal("tap after Close")
			}
			if r.Wait().Status != "timeout" {
				t.Fatal(r.Wait())
			}
		})
	}
	// The driver resolves a deadline with no tap or waiter intervention.
	e, clock, _, _ := engineFixture(t)
	defer e.Close()
	r, _ := legacyRequest(t, e, context.Background(), 7, "tick", true)
	clock.Advance(sigwire.ApprovalWindow)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.done:
	case <-time.After(time.Second):
		t.Fatal("deadline not driven")
	}
	ctx, cancel := context.WithCancel(context.Background())
	disconnected, _ := legacyRequest(t, e, ctx, 7, "disconnect", true)
	cancel()
	select {
	case <-disconnected.done:
	case <-time.After(time.Second):
		t.Fatal("disconnect not driven")
	}
}

func TestLegacyAuditCapsAndSummary(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprint(live), func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			defer e.Close()
			sink := &legacyAuditSink{}
			e.config.AuditWriter = sink
			r, v := legacyRequest(t, e, context.Background(), 7, "cap", true)
			original := *v.Card
			if !live {
				legacyTap(t, e, v)
			} else {
				card := *v.Card
				card.Challenge = "ffffffffffffffff"
				v.Card = &card
			}
			for i := 0; i < 40; i++ {
				legacyTap(t, e, v)
			}
			if len(sink.events) != 32 {
				t.Fatalf("lines=%d", len(sink.events))
			}
			if live {
				v.Card = &original
				legacyTap(t, e, v)
				legacyTap(t, e, v)
			}
			if len(sink.events) != 32 {
				t.Fatal("lifetime count reset at resolution")
			}
			_ = r
			_, other := legacyRequest(t, e, context.Background(), 7, "other", true)
			legacyTap(t, e, other)
			legacyTap(t, e, other)
			want := uint64(8)
			if live {
				want = 9
			}
			if !strings.Contains(sink.events[32].Transition, fmt.Sprintf("{noise_dropped:%d}", want)) {
				t.Fatal(sink.events[32])
			}
			// Another overflow is emitted by a tick when no callback follows.
			for i := 0; i < 8; i++ {
				legacyTap(t, e, v)
			}
			clock.Advance(59 * time.Second)
			e.flushLegacyAudit()
			if len(sink.events) != 33 {
				t.Fatal("summary early")
			}
			clock.Advance(time.Second)
			e.flushLegacyAudit()
			e.flushLegacyAudit()
			if len(sink.events) != 34 || sink.events[33].Transition != "legacy_audit_dropped{8}" {
				t.Fatal(sink.events)
			}
		})
	}
}
func TestLegacyTombstonesRestartUnknownAndV2(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	defer e.Close()
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	_, first := legacyRequest(t, e, context.Background(), 7, "first", true)
	legacyTap(t, e, first)
	for i := 0; i < 256; i++ {
		_, v := legacyRequest(t, e, context.Background(), 7, fmt.Sprint(i), true)
		legacyTap(t, e, v)
	}
	if len(e.legacy.tombstones) != 256 {
		t.Fatal(len(e.legacy.tombstones))
	}
	for i := 0; i < 40; i++ {
		legacyTap(t, e, first)
	}
	if len(sink.events) != 32 || sink.events[0].Transition != "legacy_vote_refused{unknown_card}" {
		t.Fatal(sink.events)
	}
	clock.Advance(time.Minute)
	legacyTap(t, e, first)
	e.flushLegacyAudit()
	sink.mu.Lock()
	lines := len(sink.events)
	// The worker may flush the dropped events before the tap reports them.
	valid := lines == 33 && sink.events[32].Transition == "legacy_vote_refused{unknown_card}{noise_dropped:8}" ||
		lines == 34 && sink.events[32].Transition == "legacy_audit_dropped{8}" && sink.events[33].Transition == "legacy_vote_refused{unknown_card}"
	sink.mu.Unlock()
	if !valid {
		t.Fatal(sink.events)
	}
	restarted, err := New(Config{Store: store, Clock: clock, Freezer: &freezer{}, SnapshotBuilder: snapshotter{}, AuditWriter: sink})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	legacyTap(t, restarted, first)
	if len(sink.events) != lines+1 || sink.events[lines].Transition != "legacy_vote_refused{unknown_card}" {
		t.Fatal(sink.events)
	}
	e.mu.Lock()
	e.projections.cards.add(first.Card.Handle, "v2-record")
	e.mu.Unlock()
	called := false
	got, err := e.VoteLegacy(first, func(LegacyTapResult) { called = true })
	if err != nil || got.Handled || called || len(sink.events) != lines+1 {
		t.Fatal(got, err, called)
	}
}

func TestLegacyDeadlineLatchesAndDenial(t *testing.T) {
	e, clock, _, _ := engineFixture(t)
	defer e.Close()
	r, v := legacyRequest(t, e, context.Background(), 7, "late", true)
	clock.Advance(sigwire.ApprovalWindow)
	if legacyTap(t, e, v).Resolved {
		t.Fatal("late approval")
	}
	clock.StepWall(-sigwire.ApprovalWindow)
	if legacyTap(t, e, v).Resolved || r.Wait().Status != "timeout" {
		t.Fatal("expiry resurrected")
	}
	denied, v := legacyRequest(t, e, context.Background(), 7, "deny", true)
	v.Decision = ap.VoteDeny
	if got := legacyTap(t, e, v); !got.Resolved || got.Answer != "denied" {
		t.Fatal(got)
	}
	clock.Advance(sigwire.ApprovalWindow)
	e.Reconcile()
	if denied.Wait().Status != "denied" {
		t.Fatal("deadline overwrote tap")
	}
}

func TestLegacySummaryDriver(t *testing.T) {
	e, clock, _, _ := engineFixture(t)
	defer e.Close()
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	_, v := legacyRequest(t, e, context.Background(), 7, "summary", true)
	legacyTap(t, e, v)
	for i := 0; i < 40; i++ {
		legacyTap(t, e, v)
	}
	clock.Advance(time.Minute)
	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()
	limit := time.After(3 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.events)
		sink.mu.Unlock()
		if n == 33 {
			break
		}
		select {
		case <-limit:
			t.Fatal("flusher never emitted legacy summary")
		case <-time.After(10 * time.Millisecond):
		}
	}
	e.Close()
	<-done
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.events[32].Transition != "legacy_audit_dropped{8}" {
		t.Fatal(sink.events[32])
	}
}

type heldLegacyAudit struct{ entered, done chan struct{} }

func (s *heldLegacyAudit) WriteApproval(ctx context.Context, _ ap.AuditMetadata) error {
	close(s.entered)
	<-ctx.Done()
	close(s.done)
	return ctx.Err()
}
func TestLegacyCloseJoinsAudit(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	defer e.Close()
	sink := &heldLegacyAudit{make(chan struct{}), make(chan struct{})}
	e.config.AuditWriter = sink
	r, v := legacyRequest(t, e, context.Background(), 7, "close-audit", true)
	legacyTap(t, e, v)
	finished := make(chan struct{})
	go func() { defer close(finished); legacyTap(t, e, v) }()
	<-sink.entered
	e.Close()
	select {
	case <-sink.done:
	default:
		t.Fatal("audit not joined")
	}
	<-finished
	if r.Wait().Status != "approved" {
		t.Fatal("Close overwrote approval")
	}
}

func TestLegacyTombstoneChallenge(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	defer e.Close()
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	r, v := legacyRequest(t, e, context.Background(), 7, "resolved", true)
	legacyTap(t, e, v)
	v.Card.Challenge = "ffffffffffffffff"
	if got := legacyTap(t, e, v); got.Resolved || got.Answer != LegacyTapRefused {
		t.Fatal(got)
	}
	if len(sink.events) != 1 || sink.events[0].Transition != "legacy_vote_refused{stale_challenge}" || r.Wait().Status != "approved" {
		t.Fatal(sink.events)
	}
}

func TestLegacyInvalidTapAndReservation(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	defer e.Close()
	r, v := legacyRequest(t, e, context.Background(), 7, "valid", true)
	for _, bad := range []ap.CastVote{{}, {Card: v.Card, Operator: "bad\noperator", Decision: ap.VoteApprove}, {Card: v.Card, Operator: v.Operator, Decision: "other"}, {Card: v.Card, Hosted: &ap.HostedTap{}, Operator: v.Operator, Decision: ap.VoteApprove}} {
		called := false
		if _, err := e.VoteLegacy(bad, func(LegacyTapResult) { called = true }); err == nil || called {
			t.Fatal("invalid tap accepted", bad)
		}
	}
	if _, err := e.VoteLegacy(v, nil); err == nil {
		t.Fatal("missing answer accepted")
	}
	e.mu.Lock()
	for _, args := range [][3]string{{"", "abcdefghijkl", "0123456789abcdef"}, {"bad-handle", "bad", "0123456789abcdef"}, {"bad-challenge", "abcdefghijkl", "bad"}, {"collision", v.Card.Handle, "0123456789abcdef"}} {
		if _, err := e.reserveLegacyLocked(context.Background(), 7, args[0], args[1], args[2]); err == nil {
			e.mu.Unlock()
			t.Fatal("invalid reservation accepted", args[0])
		}
	}
	e.projections.cards.add("abcdefghijkl", "v2")
	if _, err := e.reserveLegacyLocked(context.Background(), 7, "v2-collision", "abcdefghijkl", "0123456789abcdef"); err == nil {
		e.mu.Unlock()
		t.Fatal("v2 collision accepted")
	}
	e.mu.Unlock()
	if !legacyTap(t, e, v).Resolved || r.Wait().Status != "approved" {
		t.Fatal("invalid tap changed request")
	}
	e.mu.Lock()
	if _, err := e.reserveLegacyLocked(context.Background(), 7, "tomb-collision", v.Card.Handle, "0123456789abcdef"); err == nil {
		e.mu.Unlock()
		t.Fatal("tombstone collision accepted")
	}
	e.mu.Unlock()
	e.Close()
	e.mu.Lock()
	_, err := e.reserveLegacyLocked(context.Background(), 7, "closed", "bcdefghijklm", "0123456789abcdef")
	e.mu.Unlock()
	requireUnavailable(t, err)
}

func TestLegacyDeadlineIgnoresWallSteps(t *testing.T) {
	for _, step := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			defer e.Close()
			r, v := legacyRequest(t, e, context.Background(), 7, "wall-step", true)
			clock.StepWall(step)
			if err := e.Reconcile(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-r.done:
				t.Fatal("wall step changed legacy timeout")
			default:
			}
			if !legacyTap(t, e, v).Resolved {
				t.Fatal("wall step refused timely tap")
			}
			expired, late := legacyRequest(t, e, context.Background(), 7, "elapsed-end", true)
			clock.Advance(sigwire.ApprovalWindow)
			clock.StepWall(-sigwire.ApprovalWindow)
			if legacyTap(t, e, late).Resolved || expired.Wait().Status != "timeout" {
				t.Fatal("elapsed deadline extended")
			}
		})
	}
}

func TestLegacySurvivesV2Recovery(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, ending := range []string{"tap", "deadline", "cancel", "close"} {
		t.Run(ending, func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			defer e.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := &legacyAuditSink{}
			e.config.AuditWriter = sink
			r, vote := legacyRequest(t, e, ctx, 7, "survivor", true)
			submitJob(t, e, 1)
			clock.Advance(6 * time.Second)
			store.fail = true
			done := make(chan error, 1)
			go func() { done <- e.Run(context.Background()) }()
			if err := receiveNotify(t, done); err == nil {
				t.Fatal("missing storage failure")
			}
			select {
			case <-r.done:
				t.Fatal("v2 failure resolved legacy request")
			default:
			}
			store.fail = false
			reopened, err := New(e.config)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			e.mu.Lock()
			_, err = e.reserveLegacyLocked(ctx, 7, "survivor", "abcdefghijkl", "0123456789abcdef")
			e.mu.Unlock()
			if err == nil || err.Error() != "telegram: request_id already pending — refusing duplicate" {
				t.Fatalf("reservation lost: %v", err)
			}
			switch ending {
			case "tap":
				if !legacyTap(t, e, vote).Resolved {
					t.Fatal("callback routing lost")
				}
			case "deadline":
				clock.Advance(sigwire.ApprovalWindow)
			case "cancel":
				cancel()
			case "close":
				e.Close()
			}
			receiveNotify(t, r.done)
			want := "timeout"
			if ending == "tap" {
				want = "approved"
			}
			if ending != "close" {
				legacyTap(t, e, vote)
				sink.mu.Lock()
				count := 0
				for _, event := range sink.events {
					if event.RequestID == "survivor" {
						count++
					}
				}
				sink.mu.Unlock()
				if count == 0 {
					t.Fatal("legacy refusal audit lost after recovery")
				}
			}
			if got := r.Wait().Status; got != want {
				t.Fatalf("status = %s, want %s", got, want)
			}
		})
	}
}

func TestLegacyWallStepBeforeReservation(t *testing.T) {
	for _, step := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			defer e.Close()
			// Align the fake wall with the real context deadline before stepping it.
			clock.StepWall(time.Now().Sub(clock.Wall()))
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			clock.StepWall(step)
			r, vote := legacyRequest(t, e, ctx, 7, "pre-step", true)
			if err := e.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil {
				t.Fatal("caller deadline already ended")
			}
			if !legacyTap(t, e, vote).Resolved || r.Wait().Status != "approved" {
				t.Fatal("wall step expired live request")
			}
		})
	}
}

type blockedLegacySummary struct {
	legacyAuditSink
	entered chan struct{}
	exited  chan struct{}
}

func (s *blockedLegacySummary) WriteApproval(ctx context.Context, metadata ap.AuditMetadata) error {
	if metadata.Transition == "legacy_audit_dropped{8}" {
		close(s.entered)
		<-ctx.Done()
		close(s.exited)
		return ctx.Err()
	}
	return s.legacyAuditSink.WriteApproval(ctx, metadata)
}

func TestLegacyBlockedAuditDoesNotBlockV2Recovery(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	e, clock, store, _ := engineFixture(t)
	defer e.Close()
	sink := &blockedLegacySummary{entered: make(chan struct{}), exited: make(chan struct{})}
	e.config.AuditWriter = sink
	_, vote := legacyRequest(t, e, context.Background(), 7, "blocked-summary", true)
	legacyTap(t, e, vote)
	for i := 0; i < 40; i++ {
		legacyTap(t, e, vote)
	}
	submitJob(t, e, 1)
	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()
	clock.Advance(time.Minute)
	receiveNotify(t, sink.entered)
	e.mu.Lock()
	store.fail = true
	e.mu.Unlock()
	clock.Advance(2 * time.Hour)
	if err := receiveNotify(t, done); err == nil {
		t.Fatal("missing storage failure")
	}
	store.fail = false
	reopened, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	select {
	case <-sink.exited:
		t.Fatal("v2 recovery cancelled legacy write")
	default:
	}
	e.Close()
	select {
	case <-sink.exited:
	default:
		t.Fatal("Close did not cancel and join legacy write")
	}
}

func TestLegacyDroppedSummarySurvivesV2Recovery(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	e, clock, store, _ := engineFixture(t)
	defer e.Close()
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	_, vote := legacyRequest(t, e, context.Background(), 7, "retained-drops", true)
	legacyTap(t, e, vote)
	for i := 0; i < 40; i++ {
		legacyTap(t, e, vote)
	}
	submitJob(t, e, 1)
	clock.Advance(6 * time.Second)
	store.fail = true
	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()
	if err := receiveNotify(t, done); err == nil {
		t.Fatal("missing storage failure")
	}
	store.fail = false
	reopened, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedDone := make(chan error, 1)
	go func() { reopenedDone <- reopened.Run(context.Background()) }()
	clock.Advance(time.Minute)
	limit := time.After(5 * time.Second)
	for {
		sink.mu.Lock()
		summaries := 0
		for _, event := range sink.events {
			if event.Transition == "legacy_audit_dropped{8}" {
				summaries++
			}
		}
		sink.mu.Unlock()
		if summaries == 1 {
			break
		}
		if summaries > 1 {
			t.Fatal("duplicate dropped summary")
		}
		select {
		case <-limit:
			t.Fatal("recovery lost automatic dropped summary")
		case <-time.After(10 * time.Millisecond):
		}
	}
	reopened.Close()
	receiveNotify(t, reopenedDone)
}
