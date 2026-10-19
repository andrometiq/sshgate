package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

// This store deliberately continues accepting operations after the fault: the
// engine must enforce its own stop even if a store has already been reopened.
type uncertainStore struct {
	Store
	landed      bool
	calls       atomic.Int32
	entered     chan struct{}
	release     chan struct{}
	publication *publishedState
}

func (s *uncertainStore) Commit(key string, record ap.R1) error {
	s.calls.Add(1)
	if s.landed {
		if err := s.Store.Commit(key, record); err != nil {
			return err
		}
	}
	return s.fail()
}
func (s *uncertainStore) Remove(key string) error {
	s.calls.Add(1)
	if s.landed {
		if err := s.Store.Remove(key); err != nil {
			return err
		}
	}
	return s.fail()
}
func (s *uncertainStore) fail() error {
	if p := s.publication; p != nil {
		p.mu.Lock()
		p.poisonLocked(&ap.CodeError{Code: ap.CodeStorageUncertain})
		p.mu.Unlock()
		p.cancel()
	}
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	return fmt.Errorf("commit acknowledgement: %w", &ap.CodeError{Code: ap.CodeStorageUncertain})
}

func stoppedCalls(e *Engine) []func() error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return []func() error{
		e.Availability,
		func() error { _, err := e.Submit(ctx, st.PrincipalA, ap.ApprovalDraft{}); return err },
		func() error { _, err := e.Get(st.PrincipalA, st.ID(99)); return err },
		func() error { _, err := e.List(st.PrincipalB); return err },
		func() error { _, err := e.Vote(ap.CastVote{}); return err },
		func() error { _, err := e.AdminCancel("unknown", ap.AdminCancel{}); return err },
		func() error { _, err := e.Report(st.PrincipalA, st.ID(99), ap.Report{}); return err },
		func() error { _, err := e.Claim(ctx, st.PrincipalA, st.ID(99), ap.Claim{}); return err },
		func() error { return e.Revoke("absent") },
		e.Reconcile,
		func() error { _, err := e.Shed(st.PrincipalA, st.ID(99), true); return err },
		func() error { _, err := e.Delete(st.PrincipalA, st.ID(99), true); return err },
		func() error { _, err := e.WaitMany(ctx, st.PrincipalA, nil, -1); return err },
		func() error { _, err := e.WaitMany(ctx, st.PrincipalA, []string{st.ID(1)}, 0); return err },
	}
}

func assertStoppedConcurrent(t *testing.T, e *Engine, store *uncertainStore) {
	t.Helper()
	var joined sync.WaitGroup
	for range 8 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for _, call := range stoppedCalls(e) {
				var code *ap.CodeError
				if err := call(); !errors.As(err, &code) || code.Code != ap.CodeStorageUncertain {
					t.Errorf("stopped call: %v", err)
				}
			}
		}()
	}
	joined.Wait()
	if store.calls.Load() != 1 {
		t.Fatalf("post-stop writes: %d", store.calls.Load())
	}
	if e.effectContext.Err() == nil {
		t.Fatal("effects not canceled before return")
	}
	checkCode(t, e.Run(context.Background()), ap.CodeStorageUncertain)
	checkCode(t, e.Availability(), ap.CodeStorageUncertain)
}

func TestStorageUncertaintyPublicCommands(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, name := range []string{"submit", "vote", "cancel", "claim", "report", "revoke", "reconcile", "shed", "delete"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", name, landed), func(t *testing.T) {
				e, clock, base, _ := engineFixture(t)
				defer e.Close()
				var action func() error
				if name == "submit" {
					action = func() error { _, err := admissionSubmit(e, 1, st.PrincipalA); return err }
				} else if name == "revoke" {
					submitGrant(t, e, 1, st.PrincipalA)
					approve(t, e, 1)
					action = func() error { return e.Revoke("web-1") }
				} else {
					summary := submitJob(t, e, 1)
					switch name {
					case "vote":
						vote := readyCard(t, e, 1, true)
						action = func() error { _, err := e.Vote(vote); return err }
					case "cancel":
						action = func() error {
							_, err := e.AdminCancel(summary.RecordHandle, ap.AdminCancel{PlanHash: summary.PlanHash, Admin: st.Admin})
							return err
						}
					case "claim", "report":
						voteApprove(t, e, 1)
						flushRecord(t, e, 1)
						e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
							return []string{"signature"}, nil
						})
						claim := claimOf(1, summary)
						if name == "claim" {
							action = func() error {
								answer, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
								if len(answer.Signatures) != 0 {
									t.Error("uncertain signatures released")
								}
								return err
							}
						} else {
							if _, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim); err != nil {
								t.Fatal(err)
							}
							action = func() error {
								_, err := e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: claim.Token, PlanHash: summary.PlanHash, Body: finalBody(ap.StepSucceeded)})
								return err
							}
						}
					case "reconcile":
						clock.Advance(6 * time.Second)
						action = e.Reconcile
					case "shed", "delete":
						cancelAdmissionRecord(t, e, 1)
						if name == "shed" {
							action = func() error { _, err := e.Shed(st.PrincipalA, st.ID(1), true); return err }
						} else {
							clock.Advance(25 * time.Hour)
							action = func() error { _, err := e.Delete(st.PrincipalA, st.ID(1), true); return err }
						}
					}
				}
				store := &uncertainStore{Store: base, landed: landed, entered: make(chan struct{}), release: make(chan struct{}), publication: &e.published}
				defer func() {
					select {
					case <-store.release:
					default:
						close(store.release)
					}
				}()
				e.config.Store = store
				done := make(chan error, 1)
				go func() { done <- action() }()
				receiveNotify(t, store.entered)
				// Poison is published while the mutation still holds its writer lock.
				var joined sync.WaitGroup
				for range 8 {
					joined.Add(1)
					go func() {
						defer joined.Done()
						_, err := e.List(st.PrincipalB)
						var code *ap.CodeError
						if !errors.As(err, &code) || code.Code != ap.CodeStorageUncertain {
							t.Errorf("concurrent empty list: %v", err)
						}
					}()
				}
				close(store.release)
				checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
				joined.Wait()
				assertStoppedConcurrent(t, e, store)
			})
		}
	}
}

func TestStorageUncertaintyActorCommands(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	commands := []ap.Command{
		ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{1}},
		ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")},
		ap.CardDone{Handle: "abcdefghijkl", MsgID: 2},
		ap.AssistDone{Unavailable: "test unavailable"},
		ap.EditStart{Handle: "mnopqrstuvwx", ChalHash: ap.ChallengeHash("fedcba9876543210")},
		ap.EditDone{Handle: "mnopqrstuvwx"}, ap.Renotify{},
	}
	for cut := range commands {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%T/landed=%t", commands[cut], landed), func(t *testing.T) {
				e, _, base, _ := engineFixture(t)
				defer e.Close()
				submitJob(t, e, 1)
				for _, cmd := range commands[:cut] {
					command(t, e, 1, cmd)
				}
				store := &uncertainStore{Store: base, landed: landed}
				e.config.Store = store
				actor := &notifyActor{engine: e, key: ap.RecordKey(st.PrincipalA, st.ID(1))}
				done := make(chan error, 1)
				go func() { _, _, err := actor.commit(e.effectContext, commands[cut]); done <- err }()
				checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
				assertStoppedConcurrent(t, e, store)
			})
		}
	}
	for _, which := range []string{"flush", "status"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", which, landed), func(t *testing.T) {
				e, _, base, _ := engineFixture(t)
				defer e.Close()
				submitJob(t, e, 1)
				voteApprove(t, e, 1)
				key := ap.RecordKey(st.PrincipalA, st.ID(1))
				rec, err := base.Load(key)
				if err != nil {
					t.Fatal(err)
				}
				store := &uncertainStore{Store: base, landed: landed}
				e.config.Store = store
				if which == "flush" {
					e.mu.Lock()
					err = e.flushThroughLocked(context.Background(), key, rec.Header.OutboxSeq)
					e.mu.Unlock()
				} else {
					step := ap.NotifyNext(rec, e.now(), e.epoch, e.config.Settings)
					actor := &notifyActor{engine: e, key: key}
					_, _, err = actor.commit(context.Background(), ap.StatusEdited{State: step.State})
				}
				checkCode(t, err, ap.CodeStorageUncertain)
				assertStoppedConcurrent(t, e, store)
			})
		}
	}
}

func TestStorageUncertaintyJoinsInterruptedEffects(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, stage := range []string{"parts", "card", "edit", "status", "audit"} {
		for _, landed := range []bool{false, true} {
			for _, failed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/landed=%t/effect-failed=%t", stage, landed, failed), func(t *testing.T) {
					e, _, base, _ := engineFixture(t)
					submitJob(t, e, 1)
					if stage == "edit" || stage == "status" {
						prepareCloseCard(t, e)
						command(t, e, 1, ap.AssistDone{Unavailable: "test"})
					}
					if stage == "status" {
						rec, _ := base.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
						command(t, e, 1, ap.AdminCancel{Admin: st.Admin, PlanHash: rec.Header.PlanHash})
					}
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					defer e.Close()
					defer once.Do(func() { close(release) })
					var calls atomic.Int32
					hold := func() error {
						if calls.Add(1) != 1 {
							t.Error("effect called again after stop")
							return errors.New("unexpected effect")
						}
						close(entered)
						<-release
						if failed {
							return context.Canceled
						}
						return nil
					}
					n := &testNotifier{incomplete: func(int64) { t.Error("INCOMPLETE after stop") }, status: func(string) { t.Error("status after stop") }}
					switch stage {
					case "parts":
						n.parts = func(Notification) ([]int64, error) { return []int64{1}, hold() }
						n.card = func(Notification) (int64, error) { t.Error("card after stop"); return 2, nil }
					case "card":
						n.card = func(Notification) (int64, error) { return 2, hold() }
					case "edit":
						n.edit = func(Notification) (EditOutcome, error) { return EditConfirmed, hold() }
					case "status":
						e.config.Notifier = &closeStatusNotifier{testNotifier: n, status: hold}
					case "audit":
						e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return hold() })
					}
					if stage != "status" && stage != "audit" {
						e.config.Notifier = n
					}
					done := make(chan error, 1)
					go func() { done <- e.Run(context.Background()) }()
					receiveNotify(t, entered)
					store := &uncertainStore{Store: base, landed: landed}
					e.mu.Lock()
					e.config.Store = store
					e.mu.Unlock()
					_, err := admissionSubmit(e, 2, st.PrincipalA)
					checkCode(t, err, ap.CodeStorageUncertain)
					checkCode(t, e.Availability(), ap.CodeStorageUncertain)
					select {
					case <-done:
						t.Fatal("Run returned before interrupted effect joined")
					default:
					}
					once.Do(func() { close(release) })
					checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
					assertStoppedConcurrent(t, e, store)
					if calls.Load() != 1 {
						t.Fatal("additional effect call")
					}
				})
			}
		}
	}
}

func TestStorageUncertaintyAssistCallbackDoesNotSelfJoin(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			e, _, base, _ := engineFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			configureAssist(t, e, assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return readyAssist(), nil
			}))
			submitJob(t, e, 1)
			receiveNotify(t, entered)
			store := &uncertainStore{Store: base, landed: landed}
			e.mu.Lock()
			e.config.Store = store
			e.mu.Unlock()
			done := make(chan error, 1)
			go func() { done <- e.Run(context.Background()) }()
			close(release)
			checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
			assertStoppedConcurrent(t, e, store)
		})
	}
}

func TestStorageUncertaintyDriverDoesNotSelfJoin(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, actor := range []string{"notifier", "flusher"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", actor, landed), func(t *testing.T) {
				e, _, base, _ := engineFixture(t)
				defer e.Close()
				submitJob(t, e, 1)
				var calls atomic.Int32
				if actor == "notifier" {
					e.config.Notifier = &testNotifier{parts: func(Notification) ([]int64, error) { calls.Add(1); return nil, nil }}
				} else {
					e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { calls.Add(1); return nil })
				}
				store := &uncertainStore{Store: base, landed: landed}
				e.config.Store = store
				done := make(chan error, 1)
				go func() { done <- e.Run(context.Background()) }()
				checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
				assertStoppedConcurrent(t, e, store)
				if actor == "notifier" && calls.Load() != 0 {
					t.Fatal("unconfirmed burst was sent")
				}
				if actor == "flusher" && calls.Load() == 0 {
					t.Fatal("flusher never wrote before its failed acknowledgement")
				}
			})
		}
	}
}

type uncertainReadStore struct{ Store }

func (s uncertainReadStore) Load(string) (ap.R1, error) {
	return ap.R1{}, &ap.CodeError{Code: ap.CodeStorageUncertain}
}

func TestStorageUncertaintyReadLatchesAcrossStoreRecovery(t *testing.T) {
	e, _, base, _ := engineFixture(t)
	defer e.Close()
	submitJob(t, e, 1)
	e.config.Store = uncertainReadStore{Store: base}
	// Readers use the published view; a writer's Load observes this store fault.
	summary, err := e.Get(st.PrincipalA, st.ID(1))
	if err != nil || summary.ApprovalStatus != ap.ApprovalPending {
		t.Fatal("published read touched storage", summary, err)
	}
	_, err = admissionSubmit(e, 2, st.PrincipalA)
	checkCode(t, err, ap.CodeStorageUncertain)
	// Clearing the store cannot revive an old generation or its projections.
	e.config.Store = base
	_, err = e.List(st.PrincipalB)
	checkCode(t, err, ap.CodeStorageUncertain)
	checkCode(t, e.Availability(), ap.CodeStorageUncertain)
	checkCode(t, e.Run(context.Background()), ap.CodeStorageUncertain)
}

func TestStorageUncertaintyWakesWaitAndClaim(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			e, _, base, _ := engineFixture(t)
			defer e.Close()
			summary := submitJob(t, e, 1)
			voteApprove(t, e, 1)
			waiting, cancel := startWait(t, e, st.ID(1))
			defer cancel()
			claimed := make(chan error, 1)
			go func() {
				_, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, summary))
				claimed <- err
			}()
			deadline := time.After(5 * time.Second)
			for {
				e.mu.Lock()
				registered := len(e.flushWaiters) > 0
				e.mu.Unlock()
				if registered {
					break
				}
				select {
				case <-deadline:
					t.Fatal("claim did not wait for flush")
				case <-time.After(time.Millisecond):
				}
			}
			store := &uncertainStore{Store: base, landed: landed}
			e.mu.Lock()
			e.config.Store = store
			e.mu.Unlock()
			_, err := admissionSubmit(e, 2, st.PrincipalA)
			checkCode(t, err, ap.CodeStorageUncertain)
			checkCode(t, receiveWait(t, waiting).err, ap.CodeStorageUncertain)
			checkCode(t, receiveNotify(t, claimed), ap.CodeStorageUncertain)
			assertStoppedConcurrent(t, e, store)
		})
	}
}
