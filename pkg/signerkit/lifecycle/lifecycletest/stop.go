package lifecycletest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type assessorFunc func(context.Context, assist.Input) (ap.AssistResult, error)

func (fn assessorFunc) Assess(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
	return fn(ctx, in)
}

type assistBuilder struct{}

func (assistBuilder) BuildAssistInput(p ap.ApprovalPlanV1) (assist.Input, error) {
	return assist.Input{Kind: p.Kind, Reason: "safe reason"}, nil
}

func stopProperty(t *testing.T, factory StoreFactory) {
	for _, stage := range []string{"parts", "card", "edit", "status", "assist", "flush"} {
		for _, failed := range []bool{false, true} {
			name := stage + "/success"
			if failed {
				name = stage + "/failure"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t, factory)
				if stage == "edit" || stage == "status" {
					trace := recoveryTrace(t)
					index := 5
					if stage == "status" {
						index = len(trace) - 1
					}
					rec := trace[index]
					if err := f.store.Store.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), rec); err != nil {
						t.Fatal(err)
					}
				}
				entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				// Registered after owner cleanup below so failures always release the call.
				var calls atomic.Int32
				hold := func(ctx context.Context) error {
					if calls.Add(1) != 1 {
						return errors.New("unexpected subsequent call")
					}
					close(entered)
					<-ctx.Done()
					close(canceled)
					<-release
					if failed {
						return context.DeadlineExceeded
					}
					return nil
				}
				n := &notifier{hook: func(ctx context.Context, kind string) error {
					if kind == stage {
						return hold(ctx)
					}
					return nil
				}}
				switch stage {
				case "assist":
					f.config.AssistPool = assist.NewPool(1, assist.Timers{Now: f.clock.Wall})
					f.config.AssistInputBuilder = assistBuilder{}
					f.config.Assessor = assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
						err := hold(ctx)
						return st.Assist(f.clock.Wall()), err
					})
				case "flush":
					f.config.AuditWriter = auditFunc(func(ctx context.Context, _ ap.AuditMetadata) error { return hold(ctx) })
				default:
					f.config.Notifier = n
				}
				f.open()
				f.run()
				t.Cleanup(unblock)
				if stage != "edit" && stage != "status" {
					f.submit()
				}
				receive(t, entered)
				closed := make(chan error, 1)
				go func() { closed <- f.engine.Close() }()
				receive(t, canceled) // Effect cancellation follows the latch under the owner mutex.
				before, count := f.record(), f.store.count()
				_, err := f.engine.Submit(context.Background(), st.PrincipalA, draft(st.T0))
				requireCode(t, err, ap.CodeLifecycleUnavailable)
				_, err = f.engine.Vote(ap.CastVote{})
				requireCode(t, err, ap.CodeLifecycleUnavailable)
				_, err = f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{})
				requireCode(t, err, ap.CodeLifecycleUnavailable)
				callCounts := map[string]int{}
				for _, kind := range []string{"parts", "card", "edit", "status", "incomplete"} {
					callCounts[kind] = n.count(kind)
				}
				unblock()
				if err := receive(t, closed); err != nil {
					t.Fatal(err)
				}
				if f.store.count() != count || !reflect.DeepEqual(before, f.record()) {
					t.Fatal("commit after stop latch")
				}
				for kind, count := range callCounts {
					if n.count(kind) != count {
						t.Fatalf("%s I/O after latch", kind)
					}
				}
				if calls.Load() != 1 {
					t.Fatal("interrupted call retried")
				}
				// Recovery uses the same store and a new owner with fresh effect adapters.
				recovery := &notifier{}
				f.config.Notifier = recovery
				f.config.AssistPool = nil
				f.config.Assessor = nil
				f.config.AssistInputBuilder = nil
				if stage == "assist" {
					f.config.AssistPool = assist.NewPool(1, assist.Timers{Now: f.clock.Wall})
					f.config.AssistInputBuilder = assistBuilder{}
					f.config.Assessor = assessorFunc(func(context.Context, assist.Input) (ap.AssistResult, error) {
						calls.Add(1)
						t.Error("Startup repeated the interrupted assist attempt")
						return st.Assist(f.clock.Wall()), nil
					})
				}
				f.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return nil })
				f.open()
				if !reflect.DeepEqual(before, f.record()) {
					t.Fatal("Startup changed a non-due crash cut")
				}
				if stage == "assist" {
					f.clock.Advance(5 * time.Second)
					if err := f.engine.Reconcile(); err != nil {
						t.Fatal(err)
					}
					if f.record().Header.Assist == nil || calls.Load() != 1 {
						t.Fatal("assist recovery did not use Clock alone")
					}
				}
				f.run()
				eventually(t, func() bool {
					rec := f.record()
					return recoveredNotification(before, rec, ap.NotifyNext(before, ap.Now{Wall: f.clock.Wall()}, st.Epoch(99), ap.LocalSettings).Kind) && rec.Header.AuditedThrough == rec.Header.OutboxSeq && ap.NotifyNext(rec, ap.Now{Wall: f.clock.Wall()}, st.Epoch(99), ap.LocalSettings).Kind == ap.NotifyNone
				})
				if stage == "assist" && calls.Load() != 1 {
					t.Fatal("recovered owner repeated the provider call")
				}
				if (stage == "parts" || stage == "card") && (recovery.count("parts") != 0 || recovery.count("card") != 0) {
					t.Fatal("interrupted send repeated after Startup")
				}
				if stage == "edit" && recovery.count("edit") != 1 {
					t.Fatal("edit not superseded on restart")
				}
				if stage == "status" && recovery.count("status") != 1 {
					t.Fatal("status edit not recovered")
				}
			})
		}
	}
}

func editRetry(t *testing.T, factory StoreFactory) {
	for _, stop := range []bool{false, true} {
		name := "recovers"
		if stop {
			name = "stops"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, factory)
			rec := recoveryTrace(t)[5]
			if err := f.store.Store.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), rec); err != nil {
				t.Fatal(err)
			}
			var returned atomic.Bool
			var armedOnce sync.Once
			armed := make(chan struct{})
			f.store.afterLoad = func() {
				if returned.Load() {
					armedOnce.Do(func() { close(armed) })
				}
			}
			var calls atomic.Int32
			n := &notifier{hook: func(_ context.Context, kind string) error {
				if kind == "edit" && calls.Add(1) == 1 {
					returned.Store(true)
					return context.DeadlineExceeded
				}
				return nil
			}}
			f.config.Notifier = n
			f.open()
			f.run()
			// The actor reads again only after arming its retry timer. No test-side
			// Load is made until this synchronization point.
			receive(t, armed)
			if stop {
				count, before := f.store.count(), f.record()
				if err := f.engine.Close(); err != nil {
					t.Fatal(err)
				}
				timer := time.NewTimer(1100 * time.Millisecond)
				defer timer.Stop()
				<-timer.C
				if calls.Load() != 1 || f.store.count() != count || !reflect.DeepEqual(before, f.record()) {
					t.Fatal("retry continued after stop")
				}
				f.config.Notifier = &notifier{}
				f.open()
				f.run()
				eventually(t, func() bool {
					r := f.record()
					cards := r.Payload.CardEntries
					return len(cards) == 3 && cards[1].Retired && cards[2].Confirmed
				})
			} else {
				eventually(t, func() bool {
					r := f.record()
					cards := r.Payload.CardEntries
					return len(cards) == 2 && cards[1].Confirmed
				})
				if calls.Load() != 2 {
					t.Fatal("possible send was not retried exactly once")
				}
			}
		})
	}
}

func liveFailure(t *testing.T, factory StoreFactory) {
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, errors.New("transport failed")} {
		t.Run(failure.Error(), func(t *testing.T) {
			f := newFixture(t, factory)
			n := &notifier{hook: func(_ context.Context, kind string) error {
				if kind == "parts" {
					return failure
				}
				return nil
			}}
			f.config.Notifier = n
			f.open()
			f.submit()
			f.run()
			eventually(t, func() bool { return n.count("incomplete") == 3 })
			rec := f.record()
			if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalError || n.count("card") != 0 {
				t.Fatal("live failure treated as stop")
			}
		})
	}
}
