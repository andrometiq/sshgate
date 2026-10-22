package lifecycle

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

func requireUnavailable(t *testing.T, err error) {
	t.Helper()
	var code *ap.CodeError
	if !errors.As(err, &code) || code.Code != ap.CodeLifecycleUnavailable {
		t.Fatalf("want lifecycle_unavailable, got %v", err)
	}
}

func prepareCloseCard(t *testing.T, e *Engine) {
	command(t, e, 1, ap.BurstStart{})
	command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1, 2}})
	command(t, e, 1, ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, 1, ap.CardDone{Handle: "abcdefghijkl", MsgID: 3})
}

func TestCloseInterruptedEffects(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, stage := range []string{"parts", "card", "edit", "status", "flush", "incomplete"} {
		for _, failed := range []bool{false, true} {
			name := stage + "/success"
			if failed {
				name = stage + "/failure"
			}
			t.Run(name, func(t *testing.T) {
				e, _, store, _ := engineFixture(t)
				submitJob(t, e, 1)
				if stage == "edit" || stage == "status" {
					prepareCloseCard(t, e)
					command(t, e, 1, ap.AssistDone{Unavailable: "test"})
				}
				if stage == "status" {
					rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
					command(t, e, 1, ap.AdminCancel{Admin: st.Admin, PlanHash: rec.Header.PlanHash})
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				defer releaseOnce.Do(func() { close(release) })
				calls := 0
				hold := func() error {
					calls++
					if calls != 1 {
						t.Error("further I/O after stop")
						return errors.New("unexpected call")
					}
					close(entered)
					<-release
					if failed {
						return context.Canceled
					}
					return nil
				}
				n := &testNotifier{incomplete: func(int64) { t.Error("unexpected INCOMPLETE edit") }}
				switch stage {
				case "parts":
					n.parts = func(Notification) ([]int64, error) { return []int64{1}, hold() }
					n.card = func(Notification) (int64, error) { t.Error("card after stop"); return 3, nil }
				case "card":
					n.card = func(Notification) (int64, error) { return 3, hold() }
				case "edit":
					n.edit = func(Notification) (EditOutcome, error) {
						err := hold()
						if err != nil {
							return EditFailed, err
						}
						return EditConfirmed, nil
					}
				case "incomplete":
					n.parts = func(Notification) ([]int64, error) { return []int64{1, 2}, context.DeadlineExceeded }
					n.incomplete = func(int64) { _ = hold() }
				case "flush":
					e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return hold() })
					n = nil
				}
				e.config.Notifier = n
				if stage == "status" {
					e.config.Notifier = &closeStatusNotifier{testNotifier: n, status: hold}
				}
				if n == nil {
					e.config.Notifier = nil
				}
				runDone := make(chan error, 1)
				go func() { runDone <- e.Run(context.Background()) }()
				receiveNotify(t, entered)
				done := make(chan error, 1)
				go func() { done <- e.Close() }()
				receiveNotify(t, e.effectContext.Done())
				before, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				select {
				case <-done:
					t.Fatal("Close returned before I/O joined")
				case <-time.After(25 * time.Millisecond):
				}
				requireUnavailable(t, e.Reconcile())
				releaseOnce.Do(func() { close(release) })
				if err := receiveNotify(t, done); err != nil {
					t.Fatal(err)
				}
				receiveNotify(t, runDone)
				after, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				if !reflect.DeepEqual(before, after) {
					t.Fatal("interrupted effect changed record")
				}
				if calls != 1 {
					t.Fatalf("calls=%d", calls)
				}
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCloseAssistBeforeRun(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			configureAssist(t, e, assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
				close(entered)
				<-ctx.Done()
				<-release
				if failed {
					return ap.AssistResult{}, context.Canceled
				}
				return readyAssist(), nil
			}))
			submitJob(t, e, 1)
			receiveNotify(t, entered)
			done := make(chan error, 1)
			go func() { done <- e.Close() }()
			receiveNotify(t, e.effectContext.Done())
			select {
			case <-done:
				t.Fatal("Close did not join provider")
			case <-time.After(25 * time.Millisecond):
			}
			releaseOnce.Do(func() { close(release) })
			receiveNotify(t, done)
			rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if rec.Header.Assist != nil {
				t.Fatal("interrupted assist committed")
			}
			requireUnavailable(t, e.Run(context.Background()))
		})
	}
}

func TestCloseWaitersAndClaim(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, _, _, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	approve(t, e, 1)
	waiting, cancel := startWait(t, e, st.ID(1))
	defer cancel()
	claimDone := make(chan error, 1)
	go func() {
		_, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
		claimDone <- err
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
			t.Fatal("Claim did not wait")
		case <-time.After(time.Millisecond):
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel waiters promptly")
	}
	requireUnavailable(t, receiveWait(t, waiting).err)
	requireUnavailable(t, receiveNotify(t, claimDone))
	e.published.mu.Lock()
	publishedWaiters := len(e.published.waiters)
	e.published.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if publishedWaiters != 0 || len(e.flushWaiters) != 0 {
		t.Fatal("waiters not joined")
	}
}

func TestCloseLatchWithoutCancellation(t *testing.T) {
	e, _, store, f := engineFixture(t)
	submitJob(t, e, 1)
	before, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	e.mu.Lock()
	e.published.mu.Lock()
	e.published.stopping = true
	e.published.mu.Unlock()
	_, _, err := e.commitLocked(ap.RecordKey(st.PrincipalA, st.ID(1)), &before, ap.AssistDone{Unavailable: "test"}, e.now(), ap.Inputs{})
	e.mu.Unlock()
	requireUnavailable(t, err)
	calls := f.calls
	_, err = e.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(2), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)))
	requireUnavailable(t, err)
	if calls != f.calls {
		t.Fatal("freezer I/O after latch")
	}
	n := &testNotifier{incomplete: func(int64) { t.Error("I/O after latch") }}
	e.config.Notifier = n
	requireUnavailable(t, (&notifyActor{engine: e, key: ap.RecordKey(st.PrincipalA, st.ID(1))}).incomplete(context.Background(), []int64{1}))
	after, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("commit after latch")
	}
	e.Close()
}

func TestLifecycleNoDirectTimeReads(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var production []string
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			production = append(production, file)
		}
	}
	elapsedtest.AssertNoDirectTimeReads(t, production, "reconcile.go:newReconcileTicker", "flush.go:newClaimFlushTimer", "notify.go:newEditRetryTimer", "wait.go:newWaitTimer")
}

func TestCloseEditRetryTimer(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	prepareCloseCard(t, e)
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	attempted := make(chan struct{}, 2)
	armed := make(chan struct{})
	var returned atomic.Bool
	var once sync.Once
	e.config.Store = &observedLoadStore{Store: store, loaded: func() {
		if returned.Load() {
			once.Do(func() { close(armed) })
		}
	}}
	e.config.Notifier = &testNotifier{edit: func(Notification) (EditOutcome, error) {
		attempted <- struct{}{}
		returned.Store(true)
		return EditPossible, context.DeadlineExceeded
	}}
	runDone := make(chan error, 1)
	go func() { runDone <- e.Run(context.Background()) }()
	receiveNotify(t, attempted)
	// The next read follows arming the retry timer.
	receiveNotify(t, armed)
	e.mu.Lock()
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	before, _ := store.Load(key)
	e.mu.Unlock()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	receiveNotify(t, runDone)
	after, _ := store.Load(key)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("retry stop committed")
	}
	select {
	case <-attempted:
		t.Fatal("retry after close")
	case <-time.After(1100 * time.Millisecond):
	}
}

func TestRunCancellationLatchesBeforeEffects(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, _, _, _ := engineFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for {
		e.mu.Lock()
		if e.running {
			break
		}
		e.mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("Run did not start")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	// Run cannot establish the latch while this test owns the store lock.
	if e.effectContext.Err() != nil {
		e.mu.Unlock()
		t.Fatal("caller canceled effects before latch")
	}
	e.mu.Unlock()
	if err := receiveNotify(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if e.Availability() == nil || e.effectContext.Err() == nil {
		t.Fatal("Run failed to stop owner")
	}
	requireUnavailable(t, e.Run(context.Background()))
}

func TestLiveContextErrorsRemainFailures(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			marked := make(chan struct{}, 1)
			e.config.Notifier = &testNotifier{parts: func(Notification) ([]int64, error) { return []int64{1}, failure }, incomplete: func(int64) { marked <- struct{}{} }}
			done := make(chan error, 1)
			go func() { done <- e.Run(context.Background()) }()
			submitJob(t, e, 1)
			receiveNotify(t, marked)
			rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalError {
				t.Fatal("live failure was treated as interruption")
			}
			e.Close()
			receiveNotify(t, done)
		})
	}
}

func TestCloseRefusesPublicCalls(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	submitJob(t, e, 1)
	e.Close()
	_, err := e.Get(st.PrincipalA, st.ID(1))
	requireUnavailable(t, err)
	_, err = e.List(st.PrincipalB)
	requireUnavailable(t, err)
	_, err = e.Vote(ap.CastVote{})
	requireUnavailable(t, err)
	_, err = e.AdminCancel("missing", ap.AdminCancel{})
	requireUnavailable(t, err)
	_, err = e.Report(st.PrincipalA, st.ID(1), ap.Report{})
	requireUnavailable(t, err)
	_, err = e.Shed(st.PrincipalA, st.ID(1), true)
	requireUnavailable(t, err)
	_, err = e.Delete(st.PrincipalA, st.ID(1), true)
	requireUnavailable(t, err)
	requireUnavailable(t, e.Revoke("missing"))
	_, err = e.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, time.Second)
	requireUnavailable(t, err)
	_, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{})
	requireUnavailable(t, err)
}

func TestCallerCancellationDoesNotReachActorBeforeLatch(t *testing.T) {
	defer goleak.VerifyNone(t)
	e, _, _, _ := engineFixture(t)
	entered, canceled := make(chan struct{}), make(chan struct{})
	e.config.Notifier = &contextNotifier{entered: entered, canceled: canceled}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	submitJob(t, e, 1)
	receiveNotify(t, entered)
	e.mu.Lock()
	cancel()
	select {
	case <-canceled:
		t.Error("caller canceled actor before stop latch")
	case <-time.After(25 * time.Millisecond):
	}
	e.mu.Unlock()
	receiveNotify(t, done)
	e.Close()
}

type contextNotifier struct {
	testNotifier
	entered, canceled chan struct{}
}

func (n *contextNotifier) Burst(ctx context.Context, fn func(BurstSession) error) error { return fn(n) }
func (n *contextNotifier) SendParts(ctx context.Context, _ Notification) ([]int64, error) {
	close(n.entered)
	<-ctx.Done()
	close(n.canceled)
	return []int64{1}, ctx.Err()
}

type observedLoadStore struct {
	Store
	loaded func()
}

func (s *observedLoadStore) Load(key string) (ap.R1, error) {
	r, err := s.Store.Load(key)
	s.loaded()
	return r, err
}

type closeStatusNotifier struct {
	*testNotifier
	status func() error
}

func (n *closeStatusNotifier) EditStatus(context.Context, int64, StatusDisplay) error {
	return n.status()
}

func TestStopLatchBeforeIO(t *testing.T) {
	for _, effect := range []string{"notifier", "audit"} {
		t.Run(effect, func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			submitJob(t, e, 1)
			prepareCloseCard(t, e)
			rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			command(t, e, 1, ap.AdminCancel{Admin: st.Admin, PlanHash: rec.Header.PlanHash})
			// The load holds the owner mutex. Stop here without canceling the context
			// to isolate the latch check between the read and the next external call.
			e.config.Store = &observedLoadStore{Store: store, loaded: func() { e.published.mu.Lock(); e.published.stopping = true; e.published.mu.Unlock() }}
			if effect == "notifier" {
				e.config.Notifier = &testNotifier{status: func(string) { t.Error("transport call after latch") }}
				requireUnavailable(t, (&notifyActor{engine: e, key: ap.RecordKey(st.PrincipalA, st.ID(1))}).run(context.Background()))
			} else {
				e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { t.Error("audit call after latch"); return nil })
				_, err := e.flushPass(context.Background())
				requireUnavailable(t, err)
			}
			e.Close()
		})
	}
}
