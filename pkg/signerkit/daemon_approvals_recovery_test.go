package signerkit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	lt "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

type supervisedFaultStore struct {
	lt.FaultStore
	reopens      atomic.Int32
	closed       atomic.Int32
	beforeReopen func()
}

func (s *supervisedFaultStore) Reopen() error {
	s.reopens.Add(1)
	if s.beforeReopen != nil {
		s.beforeReopen()
	}
	return nil
}
func (s *supervisedFaultStore) Close() error { s.closed.Add(1); return nil }

type recoveryHarness struct {
	runtime                 *ApprovalRuntime
	store                   *supervisedFaultStore
	clock                   *elapsedtest.Fake
	waits                   chan time.Duration
	advance                 chan struct{}
	rebuilding, finishBuild chan struct{}
}

func newRecoveryHarness(t *testing.T, seed *ap.R1, configure func(*lc.Config, int)) *recoveryHarness {
	t.Helper()
	h := &recoveryHarness{store: &supervisedFaultStore{FaultStore: lt.FaultStore{Store: &lc.MemStore{}}}, clock: elapsedtest.NewFake(st.T0), waits: make(chan time.Duration, 1), advance: make(chan struct{}), rebuilding: make(chan struct{}), finishBuild: make(chan struct{})}
	if seed != nil {
		if err := h.store.Store.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), *seed); err != nil {
			t.Fatal(err)
		}
	}
	config := runtimeConfig(t, h.store)
	generation := 0
	config.NewEngine = func(store lc.Store) (*lc.Engine, error) {
		generation++
		if generation == 2 {
			close(h.rebuilding)
			<-h.finishBuild
			return nil, errors.New("injected reconstruction failure after Reopen")
		}
		c := lc.Config{Store: store, Clock: h.clock, Freezer: runtimeFreezer{}, SnapshotBuilder: runtimeSnapshot{}, LegacyService: config.Legacy}
		if configure != nil {
			configure(&c, generation)
		}
		return lc.New(c)
	}
	var err error
	h.runtime, err = NewApprovalRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	h.runtime.wait = func(ctx context.Context, delay time.Duration) bool {
		select {
		case h.waits <- delay:
		case <-ctx.Done():
			return false
		}
		select {
		case <-h.advance:
			return true
		case <-ctx.Done():
			return false
		}
	}
	t.Cleanup(func() {
		select {
		case <-h.finishBuild:
		default:
			close(h.finishBuild)
		}
		h.runtime.Close()
	})
	return h
}
func (h *recoveryHarness) start(t *testing.T) {
	startRuntime(t, h.runtime)
	t.Cleanup(func() {
		select {
		case <-h.finishBuild:
		default:
			close(h.finishBuild)
		}
	})
}
func (h *recoveryHarness) record(t *testing.T) ap.R1 {
	t.Helper()
	r, err := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Eight long-lived callers cross both reconstruction attempts and publication.
func (h *recoveryHarness) recover(t *testing.T, old *lc.Engine, release func()) *lc.Engine {
	t.Helper()
	var callers sync.WaitGroup
	rounds := make([]chan bool, 8)
	checked := make(chan struct{}, 8)
	for i := range rounds {
		rounds[i] = make(chan bool)
		callers.Add(1)
		go func(round <-chan bool) {
			defer callers.Done()
			for published := range round {
				for _, call := range []func() error{
					old.Availability,
					func() error { _, err := old.List(st.PrincipalB); return err },
					func() error { _, err := old.Get(st.PrincipalA, st.ID(1)); return err },
					func() error { _, err := old.Vote(ap.CastVote{}); return err },
					func() error {
						_, err := old.Submit(context.Background(), st.PrincipalA, ap.ApprovalDraft{})
						return err
					},
					func() error {
						_, err := old.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{})
						return err
					},
					func() error { _, err := old.WaitMany(context.Background(), st.PrincipalB, nil, 0); return err },
					func() error { return old.Revoke("absent") },
					old.Reconcile,
					func() error { _, err := old.AdminCancel("unknown", ap.AdminCancel{}); return err },
					func() error { _, err := old.Report(st.PrincipalA, st.ID(1), ap.Report{}); return err },
					func() error { _, err := old.Shed(st.PrincipalA, st.ID(1), true); return err },
					func() error { _, err := old.Delete(st.PrincipalA, st.ID(1), true); return err },
				} {
					var code *ap.CodeError
					if err := call(); !errors.As(err, &code) || code.Code != ap.CodeStorageUncertain {
						t.Errorf("stale operation: %v", err)
					}
				}
				current, err := h.runtime.Current()
				if published {
					if err != nil || current == old {
						t.Errorf("publication: %p %v", current, err)
					}
				} else {
					var code *ap.CodeError
					if current != nil || !errors.As(err, &code) || code.Code != ap.CodeStorageUncertain {
						t.Errorf("recovery availability: %p %v", current, err)
					}
				}
				checked <- struct{}{}
			}
		}(rounds[i])
	}
	defer func() {
		for _, round := range rounds {
			close(round)
		}
		callers.Wait()
	}()
	check := func(published bool) {
		for _, round := range rounds {
			round <- published
		}
		for range rounds {
			runtimeReceive(t, checked)
		}
	}
	check(false)
	if release != nil {
		synctest.Wait()
		if h.store.reopens.Load() != 1 {
			t.Fatal("Reopen before old effects joined")
		}
		release()
	}
	if delay := runtimeReceive(t, h.waits); delay != time.Second {
		t.Fatal(delay)
	}
	stoppedWrites := h.store.Writes()
	check(false)
	if h.store.Writes() != stoppedWrites {
		t.Fatal("stale calls wrote after stop")
	}
	h.advance <- struct{}{}
	runtimeReceive(t, h.rebuilding)
	check(false) // Store is usable, but there is not yet an authoritative generation.
	close(h.finishBuild)
	if delay := runtimeReceive(t, h.waits); delay != 2*time.Second {
		t.Fatal(delay)
	}
	check(false) // Failed reconstruction must not downgrade storage_uncertain.
	h.advance <- struct{}{}
	synctest.Wait()
	check(true)
	current, err := h.runtime.Current()
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func applyRuntimeFixture(t *testing.T, rec ap.R1, command ap.Command) ap.R1 {
	t.Helper()
	next, answer := ap.Apply(&rec, command, ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings, Minted: []string{st.Sig(st.ID(1), 1, 1)}})
	if answer.Code != "" || !answer.Changed {
		t.Fatalf("fixture %T: %+v", command, answer)
	}
	return next
}

func TestApprovalRuntimeActorFaultMatrix(t *testing.T) {
	defer goleak.VerifyNone(t)
	trace := lt.RecoveryTrace(t)
	for _, stage := range []struct {
		name string
		seed int
	}{
		{"burst_start", 0}, {"burst_done", 0}, {"card_start", 2}, {"card_done", 2}, {"edit_start", 5}, {"edit_done", 5}, {"status", len(trace) - 1}, {"flush", len(trace) - 1},
	} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", stage.name, landed), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var h *recoveryHarness
					var first, recovered *lt.Notifier
					h = newRecoveryHarness(t, &trace[stage.seed], func(c *lc.Config, generation int) {
						n := lt.NewNotifier(func(_ context.Context, kind string) error {
							if generation == 1 && ((stage.name == "burst_done" && kind == "parts") || (stage.name == "card_done" && kind == "card") || (stage.name == "edit_done" && kind == "edit")) {
								h.store.Arm(landed)
							}
							return nil
						})
						if generation == 1 {
							first = n
						} else {
							recovered = n
						}
						if stage.name == "flush" {
							c.AuditWriter = lt.AuditFunc(func(context.Context, ap.AuditMetadata) error { return nil })
						} else {
							c.Notifier = n
						}
					})
					old, _ := h.runtime.Current()
					if stage.name != "burst_done" && stage.name != "card_done" && stage.name != "edit_done" {
						h.store.Arm(landed)
					}
					h.start(t)
					synctest.Wait()
					runtimeCode(t, old.Availability(), ap.CodeStorageUncertain)
					before := h.record(t)
					h.recover(t, old, nil)
					after := h.record(t)
					if stage.name == "burst_start" && first.Count("parts") != 0 {
						t.Fatal("send before confirmed write-ahead")
					}
					if stage.name == "card_start" && first.Count("card") != 0 {
						t.Fatal("card before confirmed write-ahead")
					}
					if stage.name == "edit_start" && first.Count("edit") != 0 {
						t.Fatal("edit before confirmed write-ahead")
					}
					if stage.name == "flush" {
						if after.Header.AuditedThrough != after.Header.OutboxSeq {
							t.Fatal("outbox not recovered")
						}
					} else {
						next := ap.NotifyNext(before, ap.Now{Wall: st.T0}, st.Epoch(99), ap.LocalSettings)
						wantParts, wantCards := 0, 0
						if next.Kind == ap.NotifyBurst {
							wantParts, wantCards = 1, 1
						}
						if next.Kind == ap.NotifyCard {
							wantCards = 1
						}
						if recovered.Count("parts") != wantParts || recovered.Count("card") != wantCards {
							t.Fatalf("send replay/recovery: next=%s parts=%d cards=%d", next.Kind, recovered.Count("parts"), recovered.Count("card"))
						}
						if next.Kind == ap.NotifyEdit && recovered.Count("edit") != 1 {
							t.Fatal("edit not superseded")
						}
						if next.Kind == ap.NotifyStatus && recovered.Count("status") != 1 {
							t.Fatal("status not recovered")
						}
					}
					if err := st.CheckTransition(&before, after, ap.Now{Wall: st.T0}); err != nil {
						t.Fatal(err)
					}
				})
			})
		}
	}
}

func TestApprovalRuntimeHeldEffects(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, stage := range []string{"parts", "card", "edit", "status", "assist", "audit"} {
		for _, landed := range []bool{false, true} {
			for _, effectFails := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/landed=%t/effectFails=%t", stage, landed, effectFails), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						trace := lt.RecoveryTrace(t)
						seed := trace[0]
						if stage == "edit" {
							seed = trace[5]
						}
						if stage == "status" {
							seed = trace[len(trace)-1]
						}
						entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
						var once sync.Once
						unblock := func() { once.Do(func() { close(release) }) }
						var calls atomic.Int32
						var exited atomic.Bool
						hold := func(ctx context.Context) error {
							if calls.Add(1) != 1 {
								t.Error("old effect called again")
								return errors.New("unexpected call")
							}
							close(entered)
							<-ctx.Done()
							close(canceled)
							<-release
							exited.Store(true)
							if effectFails {
								return context.DeadlineExceeded
							}
							return nil
						}
						var oldNotifier, recovered *lt.Notifier
						var freshAssist atomic.Int32
						var auditMu sync.Mutex
						var oldAudit, newAudit []ap.AuditMetadata
						var seedPtr *ap.R1 = &seed
						if stage == "assist" {
							seedPtr = nil
						}
						h := newRecoveryHarness(t, seedPtr, func(c *lc.Config, generation int) {
							c.Notifier = lt.NewNotifier(func(ctx context.Context, kind string) error {
								if generation == 1 && kind == stage {
									return hold(ctx)
								}
								return nil
							})
							if generation != 1 {
								recovered = c.Notifier.(*lt.Notifier)
							} else {
								oldNotifier = c.Notifier.(*lt.Notifier)
							}
							c.AuditWriter = lt.AuditFunc(func(ctx context.Context, event ap.AuditMetadata) error {
								auditMu.Lock()
								if generation == 1 {
									oldAudit = append(oldAudit, event)
								} else {
									newAudit = append(newAudit, event)
								}
								auditMu.Unlock()
								if generation == 1 && stage == "audit" {
									return hold(ctx)
								}
								return nil
							})
							c.AssistPool = assist.NewPool(1, assist.Timers{Now: c.Clock.Wall})
							c.AssistInputBuilder = lt.AssistBuilder{}
							c.Assessor = lt.AssessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
								if generation == 1 && stage == "assist" {
									return st.Assist(st.T0), hold(ctx)
								}
								if generation != 1 {
									freshAssist.Add(1)
								}
								return st.Assist(st.T0), nil
							})
						})
						h.store.beforeReopen = func() {
							if h.store.reopens.Load() > 1 && !exited.Load() {
								t.Error("Reopen while effect remains active")
							}
						}
						old, _ := h.runtime.Current()
						h.start(t)
						t.Cleanup(unblock)
						if stage == "assist" {
							if _, err := old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))); err != nil {
								t.Fatal(err)
							}
						}
						runtimeReceive(t, entered)
						synctest.Wait() // Drain unrelated acknowledgements before arming the Submit fault.
						h.store.Arm(landed)
						_, err := old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(2), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)))
						runtimeCode(t, err, ap.CodeStorageUncertain)
						runtimeReceive(t, canceled)
						_, loadErr := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(2)))
						if (loadErr == nil) != landed {
							t.Fatalf("Submit fault landed on another operation: %v", loadErr)
						}
						before := h.record(t)
						writes := h.store.Writes()
						oldCalls := map[string]int{}
						for _, kind := range []string{"parts", "card", "edit", "status", "incomplete"} {
							oldCalls[kind] = oldNotifier.Count(kind)
						}
						// Releasing a canceled effect, even with success, cannot commit its result.
						current := h.recover(t, old, func() {
							unblock()
							synctest.Wait()
							if h.store.Writes() != writes {
								t.Error("interrupted effect committed after stop")
							}
						})
						if calls.Load() != 1 {
							t.Fatal("old effect retried")
						}
						for kind, count := range oldCalls {
							if oldNotifier.Count(kind) != count {
								t.Fatalf("%s call after stop latch", kind)
							}
						}
						after := h.record(t)
						if err := st.CheckTransition(&before, after, ap.Now{Wall: st.T0}); err != nil {
							t.Fatal(err)
						}
						if stage == "parts" || stage == "card" {
							// Request 2 may have landed and legitimately starts one fresh burst.
							want := 0
							if landed {
								want = 1
							}
							if recovered.Count("parts") != want || recovered.Count("card") != want {
								t.Fatalf("uncertain send replayed: parts=%d card=%d want=%d before=%+v after=%+v", recovered.Count("parts"), recovered.Count("card"), want, before.Payload.Bursts, after.Payload.Bursts)
							}
						}
						if stage == "edit" && recovered.Count("edit") != 1 {
							t.Fatal("unfinished edit not superseded")
						}
						if stage == "status" && recovered.Count("status") < 1 {
							t.Fatal("status not recovered")
						}
						if stage == "audit" {
							auditMu.Lock()
							if len(oldAudit) != 1 || !slices.ContainsFunc(newAudit, func(event ap.AuditMetadata) bool { return reflect.DeepEqual(oldAudit[0], event) }) {
								t.Error("outbox replay lost duplicate-identifiable event")
							}
							auditMu.Unlock()
						}
						if after.Header.AuditedThrough != after.Header.OutboxSeq {
							t.Fatal("outbox not drained")
						}
						if stage == "assist" {
							if freshAssist.Load() != 0 {
								t.Fatal("abandoned assist retried by provider")
							}
							h.clock.Advance(6 * time.Second)
							if err := current.Reconcile(); err != nil {
								t.Fatal(err)
							}
							if h.record(t).Header.Assist == nil {
								t.Fatal("Clock did not fill abandoned assist")
							}
						}
						beforeFresh := freshAssist.Load()
						if _, err := current.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(3), ap.CoordinatorExecutor, h.clock.Wall(), st.Write("true", 60))); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						if freshAssist.Load() != beforeFresh+1 {
							t.Fatal("replacement lacks fresh assist capacity")
						}
						fresh, err := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(3)))
						if err != nil || fresh.Header.Assist == nil {
							t.Fatalf("fresh assist result: %v", err)
						}
					})
				})
			}
		}
	}
}

func TestApprovalRuntimeAssistCommitFault(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				entered := make(chan struct{})
				var calls atomic.Int32
				h := newRecoveryHarness(t, nil, func(c *lc.Config, generation int) {
					c.AssistPool = assist.NewPool(1, assist.Timers{Now: c.Clock.Wall})
					c.AssistInputBuilder = lt.AssistBuilder{}
					c.Assessor = lt.AssessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
						calls.Add(1)
						if generation == 1 {
							close(entered)
							select {
							case <-release:
							case <-ctx.Done():
							}
						}
						return st.Assist(st.T0), nil
					})
				})
				old, _ := h.runtime.Current()
				h.start(t)
				if _, err := old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))); err != nil {
					t.Fatal(err)
				}
				runtimeReceive(t, entered)
				h.store.Arm(landed)
				close(release)
				synctest.Wait()
				runtimeCode(t, old.Availability(), ap.CodeStorageUncertain)
				current := h.recover(t, old, nil)
				if calls.Load() != 1 {
					t.Fatal("assist replayed")
				}
				if got := h.record(t).Header.Assist != nil; got != landed {
					t.Fatal("assist durability cut changed")
				}
				h.clock.Advance(6 * time.Second)
				if err := current.Reconcile(); err != nil {
					t.Fatal(err)
				}
				if h.record(t).Header.Assist == nil || calls.Load() != 1 {
					t.Fatal("abandoned assist not settled by Clock")
				}
			})
		})
	}
}

func TestApprovalRuntimeCommandFaultMatrix(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, name := range []string{"submit", "vote", "cancel", "claim", "report", "revoke", "reconcile", "shed", "delete"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", name, landed), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					trace := lt.RecoveryTrace(t)
					seed := trace[0]
					switch name {
					case "vote":
						seed = trace[12]
					case "claim", "report":
						seed = trace[len(trace)-1]
						seed = applyRuntimeFixture(t, seed, ap.Flush{Through: seed.Header.OutboxSeq})
						if name == "report" {
							seed = applyRuntimeFixture(t, seed, ap.Claim{Token: st.Token(st.ID(1)), PlanHash: seed.Header.PlanHash})
						}
					case "shed", "delete":
						seed = applyRuntimeFixture(t, seed, ap.AssistDone{Unavailable: "test unavailable"})
						seed = applyRuntimeFixture(t, seed, ap.AdminCancel{PlanHash: seed.Header.PlanHash, Admin: st.Admin})
						seed = applyRuntimeFixture(t, seed, ap.Flush{Through: seed.Header.OutboxSeq})
						if name == "delete" {
							seed = applyRuntimeFixture(t, seed, ap.ShedRecord{Pressure: true})
						}
					case "revoke":
						var answer ap.Answer
						seed, answer = ap.Apply(nil, st.SubmitOf(st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0), st.PrincipalA, st.T0, time.Hour), ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
						if answer.Code != "" {
							t.Fatal(answer)
						}
						for _, cmd := range []ap.Command{ap.AssistDone{Unavailable: "test unavailable"}, ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{1}}, ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")}, ap.CardDone{Handle: "abcdefghijkl", MsgID: 4}} {
							seed = applyRuntimeFixture(t, seed, cmd)
						}
					}
					var seedPtr *ap.R1 = &seed
					if name == "submit" {
						seedPtr = nil
					}
					var mints atomic.Int32
					h := newRecoveryHarness(t, seedPtr, func(c *lc.Config, _ int) {
						c.Minter = lt.MintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
							return []string{st.Sig(st.ID(1), 1, int(mints.Add(1)))}, nil
						})
					})
					old, _ := h.runtime.Current()
					if name == "revoke" {
						_, err := old.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: "abcdefghijkl", Challenge: "0123456789abcdef", MsgID: 4}})
						if err != nil {
							t.Fatal(err)
						}
					}
					if name == "revoke" {
						if _, err := old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(2), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))); err != nil {
							t.Fatal(err)
						}
						covered, err := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(2)))
						if err != nil || covered.Header.Decision == nil || !strings.HasPrefix(covered.Header.Decision.DecidedBy, ap.GrantDecidedPrefix) {
							t.Fatal("fixture grant was not live before stop")
						}
					}
					h.start(t)
					synctest.Wait()
					if name == "reconcile" {
						h.clock.Advance(6 * time.Second)
					}
					if name == "delete" {
						h.clock.Advance(25 * time.Hour)
					}
					claim := ap.Claim{Token: st.Token(st.ID(1)), PlanHash: seed.Header.PlanHash}
					beforeFault, beforeError := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
					h.store.Arm(landed)
					var err error
					switch name {
					case "submit":
						_, err = old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)))
					case "vote":
						_, err = old.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: "yzabcdefghij", Challenge: "1234567890abcdef", MsgID: 8}})
					case "cancel":
						summary, getErr := old.Get(st.PrincipalA, st.ID(1))
						if getErr != nil {
							t.Fatal(getErr)
						}
						_, err = old.AdminCancel(summary.RecordHandle, ap.AdminCancel{PlanHash: seed.Header.PlanHash, Admin: st.Admin})
					case "claim":
						var answer ap.Answer
						answer, err = old.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
						if len(answer.Signatures) != 0 {
							t.Fatal("uncertain signatures released")
						}
					case "report":
						_, err = old.Report(st.PrincipalA, st.ID(1), ap.Report{Token: claim.Token, PlanHash: claim.PlanHash, Body: ap.FinalReport{Class: ap.ClassSucceeded, ResultDigest: strings.Repeat("a", 64), Steps: []ap.StepReport{{Ordinal: 1, Status: ap.StepSucceeded}}, ExecutedOrdinals: []int{1}}})
					case "revoke":
						err = old.Revoke("web-1")
					case "reconcile":
						err = old.Reconcile()
					case "shed":
						_, err = old.Shed(st.PrincipalA, st.ID(1), true)
					case "delete":
						_, err = old.Delete(st.PrincipalA, st.ID(1), true)

					}
					runtimeCode(t, err, ap.CodeStorageUncertain)
					afterFault, afterError := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
					unchanged := reflect.DeepEqual(beforeFault, afterFault) && errors.Is(afterError, beforeError)
					if unchanged == landed {
						t.Fatal("fault did not produce the requested durability cut")
					}
					stoppedWrites := h.store.Writes()

					current := h.recover(t, old, nil)
					if name != "reconcile" && name != "delete" && h.store.Writes() != stoppedWrites {
						t.Fatal("reconstruction changed non-due durable facts")
					}
					if name == "submit" || name == "delete" {
						_, err := current.Get(st.PrincipalA, st.ID(1))
						exists := landed
						if name == "delete" {
							exists = !landed
						}
						if exists {
							if err != nil {
								t.Fatal(err)
							}
						} else {
							runtimeCode(t, err, ap.CodeNotFound)
						}
					}
					if name == "claim" {
						before := mints.Load()
						answer, err := current.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
						if err != nil || len(answer.Signatures) != 1 {
							t.Fatalf("recovered claim: %+v %v", answer, err)
						}
						want := before + 1
						if landed {
							want = before
						}
						if mints.Load() != want || answer.Signatures[0] != st.Sig(st.ID(1), 1, int(want)) {
							t.Fatal("mint replay/identity mismatch")
						}
					}
					if name == "revoke" {
						// Even an unlanded revoke cannot revive a grant from the old epoch.
						_, err := current.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(3), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)))
						if err != nil {
							t.Fatal(err)
						}
						rec, err := h.store.Load(ap.RecordKey(st.PrincipalA, st.ID(3)))
						if err != nil || rec.Header.Decision != nil {
							t.Fatal("old generation grant survived")
						}
					}
				})
			})
		}
	}
}

func TestApprovalRuntimeParentCancellationAndConcurrentClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parentCancel=%t", parentCancel), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				notifier := &heldApprovalNotifier{entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
				h := newRecoveryHarness(t, nil, func(c *lc.Config, _ int) { c.Notifier = notifier })
				t.Cleanup(func() {
					select {
					case <-notifier.release:
					default:
						close(notifier.release)
					}
				})
				old, _ := h.runtime.Current()
				_, err := old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)))
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- h.runtime.Run(ctx) }()
				runtimeReceive(t, notifier.entered)
				if parentCancel {
					cancel()
					runtimeReceive(t, notifier.canceled)
				}
				var closes sync.WaitGroup
				for range 8 {
					closes.Add(1)
					go func() {
						defer closes.Done()
						if err := h.runtime.Close(); err != nil {
							t.Error(err)
						}
					}()
				}
				runtimeReceive(t, notifier.canceled)
				runtimeCode(t, old.Availability(), ap.CodeLifecycleUnavailable)
				if h.store.closed.Load() != 0 {
					t.Fatal("store closed before effect joined")
				}
				select {
				case <-done:
					t.Fatal("Run returned before join")
				default:
				}
				close(notifier.release)
				closes.Wait()
				if err := runtimeReceive(t, done); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if h.store.closed.Load() != 1 || h.store.reopens.Load() != 1 {
					t.Fatal("shutdown reopened or closed storage more than once")
				}
				if err := h.runtime.Run(context.Background()); err == nil {
					t.Fatal("Run after Close accepted")
				}
			})
		})
	}
	// Run and Close may race before either establishes ownership of the loop.
	synctest.Test(t, func(t *testing.T) {
		h := newRecoveryHarness(t, nil, nil)
		start := make(chan struct{})
		var joined sync.WaitGroup
		for i := 0; i < 9; i++ {
			joined.Add(1)
			go func(i int) {
				defer joined.Done()
				<-start
				if i == 0 {
					_ = h.runtime.Run(context.Background())
				} else {
					if err := h.runtime.Close(); err != nil {
						t.Error(err)
					}
				}
			}(i)
		}
		close(start)
		joined.Wait()
		if h.store.closed.Load() != 1 {
			t.Fatal("concurrent startup/close leaked store")
		}
	})
}
