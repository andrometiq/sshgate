package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type assistBuilder struct{ fail bool }

func (b assistBuilder) BuildAssistInput(p ap.ApprovalPlanV1) (assist.Input, error) {
	if b.fail {
		return assist.Input{}, errors.New("private redactor error")
	}
	return assist.Input{Kind: p.Kind, Reason: "safe reason"}, nil
}

type assessorFunc func(context.Context, assist.Input) (ap.AssistResult, error)

func (f assessorFunc) Assess(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
	return f(ctx, in)
}
func readyAssist() ap.AssistResult {
	return ap.AssistResult{Alignment: ap.AlignmentAligned, Summary: "safe summary", Model: "test", PromptVersion: "v1", GeneratedAt: st.T0}
}
func assistRecord(t *testing.T, e *Engine, id int) ap.R1 {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.load(ap.RecordKey(st.PrincipalA, st.ID(id)))
	if err != nil || r == nil {
		t.Fatalf("record: %v", err)
	}
	return *r
}
func awaitAssist(t *testing.T, e *Engine, id int) ap.R1 {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		r := assistRecord(t, e, id)
		if r.Header.Assist != nil {
			return r
		}
		select {
		case <-deadline:
			t.Fatal("assist did not finish")
		case <-time.After(time.Millisecond):
		}
	}
}
func configureAssist(t *testing.T, e *Engine, a assist.Assessor) *assist.Pool {
	t.Helper()
	p := assist.NewPool(1, assist.Timers{Now: e.config.Clock.Wall})
	t.Cleanup(p.Close)
	e.config.AssistPool = p
	e.config.AssistInputBuilder = assistBuilder{}
	e.config.Assessor = a
	if e.legacy != nil {
		e.legacy.config.Assessor = a
	}
	return p
}

func TestAssistCommitBarrierReplayAndImmutableResult(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	configureAssist(t, e, assessorFunc(func(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		if _, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1))); err != nil {
			t.Error("provider ran before commit")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ap.AssistResult{}, ctx.Err()
		}
		return readyAssist(), nil
	}))
	store.fail = true
	d := st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0)
	if _, err := e.Submit(context.Background(), st.PrincipalA, d); err == nil {
		t.Fatal("lost commit failure")
	}
	if calls.Load() != 0 {
		t.Fatal("provider before commit")
	}
	store.fail = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Submit(ctx, st.PrincipalA, d); err != nil {
		t.Fatal(err)
	}
	<-entered
	before := assistRecord(t, e, 1)
	for range 3 {
		if _, err := e.Submit(context.Background(), st.PrincipalA, d); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	after := awaitAssist(t, e, 1)
	if calls.Load() != 1 || after.Header.Assist.State != ap.AssistReady {
		t.Fatal("not one ready attempt")
	}
	if before.Header.PlanHash != after.Header.PlanHash || before.Header.RequiredApprovals != after.Header.RequiredApprovals || !reflect.DeepEqual(before.Payload.Plan, after.Payload.Plan) || after.Header.Mint != nil {
		t.Fatal("assist changed authorization")
	}
	frozen := *after.Header.Assist
	command(t, e, 1, ap.AssistDone{Unavailable: "replacement"})
	if got := assistRecord(t, e, 1); !reflect.DeepEqual(frozen, *got.Header.Assist) {
		t.Fatal("replaced immutable assist")
	}
	decided := approve(t, e, 1)
	bound := decided.Header.Decision.AssistBound
	if bound.State != ap.AssistReady || bound.Revision != 1 || bound.Digest != frozen.Digest {
		t.Fatal("decision lost assist binding")
	}
	found := false
	for _, event := range decided.Header.Outbox {
		if event.Kind == ap.EventDecision {
			found = event.Assist != nil && *event.Assist == bound
		}
	}
	if !found {
		t.Fatal("decision event lost assist binding")
	}
}

func TestAssistBusyAndClosed(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "busy", true: "closed"}[closed], func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			entered := make(chan struct{})
			var calls atomic.Int32
			p := configureAssist(t, e, assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
				calls.Add(1)
				close(entered)
				<-ctx.Done()
				return ap.AssistResult{}, ctx.Err()
			}))
			if closed {
				p.Close()
				e.config.AssistInputBuilder = assistBuilder{fail: true}
			} else {
				submitGrant(t, e, 1, st.PrincipalA)
				<-entered
			}
			submitGrant(t, e, 2, st.PrincipalA)
			rec := assistRecord(t, e, 2)
			if closed {
				if rec.Header.Assist != nil || store.commits != 1 {
					t.Fatal("closed pool committed assist")
				}
			} else if rec.Header.Assist == nil || rec.Header.Assist.Reason != assist.ReasonBusy {
				t.Fatal("full pool did not commit busy")
			}
			p.Close()
			restarted, err := New(e.config)
			if err != nil {
				t.Fatal(err)
			}
			clock.Advance(5 * time.Second)
			if err := restarted.Reconcile(); err != nil {
				t.Fatal(err)
			}
			rec = assistRecord(t, restarted, 2)
			want := assist.ReasonBusy
			if closed {
				want = assist.ReasonDeadline
			}
			if rec.Header.Assist == nil || rec.Header.Assist.Reason != want {
				t.Fatal("recovery changed terminal result or failed deadline")
			}
			if closed && calls.Load() != 0 || !closed && calls.Load() != 1 {
				t.Fatal("recovery retried provider")
			}
		})
	}
}

func TestAssistFailureRedactionAndDeadline(t *testing.T) {
	for _, kind := range []string{"provider", "redaction", "late"} {
		t.Run(kind, func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			var calls atomic.Int32
			configureAssist(t, e, assessorFunc(func(context.Context, assist.Input) (ap.AssistResult, error) {
				calls.Add(1)
				if kind == "late" {
					clock.Advance(5 * time.Second)
					return readyAssist(), nil
				}
				return ap.AssistResult{}, errors.New("private provider error")
			}))
			e.config.AssistInputBuilder = assistBuilder{fail: kind == "redaction"}
			submitGrant(t, e, 1, st.PrincipalA)
			rec := awaitAssist(t, e, 1)
			want := map[string]string{"provider": assist.ReasonFailed, "redaction": assist.ReasonRedaction, "late": assist.ReasonDeadline}[kind]
			if rec.Header.Assist.State != ap.AssistUnavailable || rec.Header.Assist.Reason != want {
				t.Fatalf("assist: %+v", rec.Header.Assist)
			}
			if kind == "redaction" && calls.Load() != 0 {
				t.Fatal("redaction failure called provider")
			}
			approve(t, e, 1)
		})
	}
}

func TestAssistStorageFailureReachesRun(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	configureAssist(t, e, assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ap.AssistResult{}, ctx.Err()
		}
		return readyAssist(), nil
	}))
	submitGrant(t, e, 1, st.PrincipalA)
	<-entered
	e.mu.Lock()
	store.fail = true
	e.mu.Unlock()
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := e.Run(ctx); err == nil || err.Error() != "injected commit failure" {
		t.Fatalf("lost effect failure: %v", err)
	}
	requireUnavailable(t, e.Availability())
	record, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if err != nil {
		t.Fatal(err)
	}
	if record.Header.Assist != nil {
		t.Fatal("failed assist commit published")
	}
}

func TestAssistWatchdogAndInterruptedRecovery(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "watchdog", true: "interrupted"}[interrupt], func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			timer, armed, entered := make(chan time.Time, 1), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			p := assist.NewPool(1, assist.Timers{Now: clock.Wall, After: func(d time.Duration) <-chan time.Time {
				if d != 5*time.Second {
					t.Errorf("watchdog duration: %v", d)
				}
				close(armed)
				return timer
			}})
			t.Cleanup(p.Close)
			e.config.AssistPool = p
			e.config.AssistInputBuilder = assistBuilder{}
			e.config.Assessor = assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
				calls.Add(1)
				close(entered)
				<-ctx.Done()
				return ap.AssistResult{}, ctx.Err()
			})
			submitGrant(t, e, 1, st.PrincipalA)
			<-entered
			<-armed
			if interrupt {
				p.Close()
				if assistRecord(t, e, 1).Header.Assist != nil {
					t.Fatal("interrupted attempt committed")
				}
			} else {
				clock.Advance(5 * time.Second)
				if assistRecord(t, e, 1).Header.Assist != nil {
					t.Fatal("read advanced Clock")
				}
				timer <- clock.Wall()
				rec := awaitAssist(t, e, 1)
				if rec.Header.Assist.Reason != assist.ReasonDeadline {
					t.Fatal("watchdog failed")
				}
				approve(t, e, 1)
				p.Close()
			}
			restarted, err := New(e.config)
			if err != nil {
				t.Fatal(err)
			}
			clock.Advance(5 * time.Second)
			if err := restarted.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if assistRecord(t, restarted, 1).Header.Assist == nil || calls.Load() != 1 {
				t.Fatal("recovery retried or left empty slot")
			}
		})
	}
}

func TestAssistRequiresInputBuilder(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	p := assist.NewPool(1, assist.Timers{})
	defer p.Close()
	e.config.AssistPool = p
	if _, err := New(e.config); err == nil {
		t.Fatal("accepted pool without input boundary")
	}
}
