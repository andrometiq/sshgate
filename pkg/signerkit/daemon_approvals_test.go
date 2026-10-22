package signerkit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"go.uber.org/goleak"
)

type runtimeStore struct {
	lifecycle.MemStore
	fail   atomic.Bool
	landed bool
	reopen func() error
	close  func() error
}

func (s *runtimeStore) Reopen() error {
	if s.reopen != nil {
		return s.reopen()
	}
	return nil
}
func (s *runtimeStore) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}
func (s *runtimeStore) Commit(key string, rec ap.R1) error {
	if s.fail.Swap(false) {
		if s.landed {
			if err := s.MemStore.Commit(key, rec); err != nil {
				return err
			}
		}
		return &ap.CodeError{Code: ap.CodeStorageUncertain}
	}
	return s.MemStore.Commit(key, rec)
}

type runtimeFreezer struct{}

func (runtimeFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	return ap.FreezeDraft(d, ap.FreezeInputs{RequesterPrincipal: principal, RequesterSub: sub, Now: now, Validity: time.Hour})
}

type runtimeSnapshot struct{}

func (runtimeSnapshot) BuildSnapshot(context.Context, ap.ApprovalPlanV1) ([]byte, string, error) {
	return st.Review, "test approval", nil
}
func runtimeConfig(t *testing.T, store RecoverableStore) ApprovalRuntimeConfig {
	t.Helper()
	legacy, err := lifecycle.NewLegacyService(lifecycle.LegacyConfig{Clock: elapsed.Real()})
	if err != nil {
		t.Fatal(err)
	}
	return ApprovalRuntimeConfig{Store: store, Legacy: legacy, NewEngine: func(store lifecycle.Store) (*lifecycle.Engine, error) {
		return lifecycle.New(lifecycle.Config{Store: store, Clock: elapsed.Real(), Freezer: runtimeFreezer{}, SnapshotBuilder: runtimeSnapshot{}, LegacyService: legacy})
	}}
}
func runtimeReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("runtime timed out")
	}
	var zero T
	return zero
}
func runtimeCode(t *testing.T, err error, code ap.Code) {
	t.Helper()
	var coded *ap.CodeError
	if !errors.As(err, &coded) || coded.Code != code {
		t.Fatalf("error %v, want %s", err, code)
	}
}
func startRuntime(t *testing.T, r *ApprovalRuntime) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	t.Cleanup(func() { r.Close(); runtimeReceive(t, done) })
}

func TestApprovalRuntimeAutomaticRecovery(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, landed := range []bool{false, true} {
		t.Run(map[bool]string{false: "not_landed", true: "landed"}[landed], func(t *testing.T) {
			store := &runtimeStore{landed: landed}
			r, err := NewApprovalRuntime(runtimeConfig(t, store))
			if err != nil {
				t.Fatal(err)
			}
			waits := make(chan time.Duration, 1)
			release := make(chan struct{})
			r.wait = func(ctx context.Context, delay time.Duration) bool {
				waits <- delay
				select {
				case <-release:
					return true
				case <-ctx.Done():
					return false
				}
			}
			old, _ := r.Current()
			startRuntime(t, r)
			store.fail.Store(true)
			draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, time.Now().UTC(), st.Write("w", 60))
			_, err = old.Submit(context.Background(), st.PrincipalA, draft)
			runtimeCode(t, err, ap.CodeStorageUncertain)
			if delay := runtimeReceive(t, waits); delay != time.Second {
				t.Fatal(delay)
			}
			var readers sync.WaitGroup
			for i := 0; i < 8; i++ {
				readers.Add(1)
				go func() {
					defer readers.Done()
					for j := 0; j < 20; j++ {
						runtimeCode(t, r.Status(), ap.CodeStorageUncertain)
						_, err := old.List("empty")
						runtimeCode(t, err, ap.CodeStorageUncertain)
						_, err = old.Vote(ap.CastVote{})
						runtimeCode(t, err, ap.CodeStorageUncertain)
					}
				}()
			}
			readers.Wait()
			close(release)
			deadline := time.After(5 * time.Second)
			for r.Status() != nil {
				select {
				case <-deadline:
					t.Fatal("did not recover")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			current, _ := r.Current()
			if current == old {
				t.Fatal("generation reused")
			}
			if r.Legacy() != r.config.Legacy {
				t.Fatal("legacy owner replaced")
			}
			runtimeCode(t, old.Availability(), ap.CodeStorageUncertain)
			_, err = current.Get(st.PrincipalA, draft.RequestID)
			if landed {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				runtimeCode(t, err, ap.CodeNotFound)
			}
		})
	}
}

func TestApprovalRuntimeInitialFailureBackoffAndClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	var closes atomic.Int32
	store := &runtimeStore{reopen: func() error { return errors.New("reload failed") }, close: func() error { closes.Add(1); return nil }}
	r, err := NewApprovalRuntime(runtimeConfig(t, store))
	if err != nil {
		t.Fatal(err)
	}
	runtimeCode(t, r.Status(), ap.CodeLifecycleUnavailable)
	waits := make(chan time.Duration)
	advance := make(chan struct{})
	r.wait = func(ctx context.Context, d time.Duration) bool {
		select {
		case waits <- d:
		case <-ctx.Done():
			return false
		}
		select {
		case <-advance:
			return true
		case <-ctx.Done():
			return false
		}
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	for _, want := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
		if got := runtimeReceive(t, waits); got != want*time.Second {
			t.Fatalf("delay %v", got)
		}
		advance <- struct{}{}
	}
	r.Close()
	runtimeReceive(t, done)
	r.Close()
	if closes.Load() != 1 {
		t.Fatal("store not closed exactly once")
	}
}

func TestServiceCloseDuringApprovalReconstruction(t *testing.T) {
	defer goleak.VerifyNone(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var released atomic.Bool
	store := &runtimeStore{reopen: func() error {
		if calls.Add(1) == 1 {
			return errors.New("initial failure")
		}
		return nil
	}, close: func() error { released.Store(true); return nil }}
	config := runtimeConfig(t, store)
	factory := config.NewEngine
	made := make(chan *lifecycle.Engine, 1)
	config.NewEngine = func(s lifecycle.Store) (*lifecycle.Engine, error) {
		close(entered)
		<-release
		e, err := factory(s)
		made <- e
		return e, err
	}
	r, err := NewApprovalRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	r.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	service := &Service{}
	if err := service.AttachApprovals(r); err != nil {
		t.Fatal(err)
	}
	if err := service.AttachApprovals(r); err == nil {
		t.Fatal("duplicate attach accepted")
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	runtimeReceive(t, entered)
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	for {
		r.mu.Lock()
		stopped := r.closed
		r.mu.Unlock()
		if stopped {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if released.Load() {
		t.Fatal("storage released during construction")
	}
	close(release)
	if err := runtimeReceive(t, closed); err != nil {
		t.Fatal(err)
	}
	runtimeReceive(t, done)
	e := runtimeReceive(t, made)
	runtimeCode(t, e.Availability(), ap.CodeLifecycleUnavailable)
	if !released.Load() {
		t.Fatal("storage ownership leaked")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.AttachApprovals(r); err == nil {
		t.Fatal("attach after close accepted")
	}
}

func TestApprovalMinterCustodyAndDecisionTime(t *testing.T) {
	key, _ := goldenSignerKey()
	service := &Service{daemon: &Daemon{Key: key, NowFunc: func() time.Time { return st.T0.Add(365 * 24 * time.Hour) }}}
	now := st.T0
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, now, st.Write("w", 60))
	plan, err := (runtimeFreezer{}).Freeze(context.Background(), draft, st.PrincipalA, "", now)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := service.ApprovalMinter().Mint(context.Background(), plan, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(signatures) != 1 {
		t.Fatal(signatures)
	}
	_, payload, err := sigwire.DecodeSigned(signatures[0])
	if err != nil {
		t.Fatal(err)
	}
	if payload.TS != now.Unix() || payload.Exp != now.Unix()+60 || payload.Cmd != plan.CommandJob.Steps[0].ExactCommand {
		t.Fatal(payload)
	}
	if err := service.Lock("test", Operator{}); err != nil {
		t.Fatal(err)
	}
	if signatures, err := service.ApprovalMinter().Mint(context.Background(), plan, now); err == nil || len(signatures) != 0 {
		t.Fatal("locked custody signed")
	}
	if err := service.Unlock(Operator{}); err != nil {
		t.Fatal(err)
	}
	plan.CommandJob.Steps[0].ExactCommand = "SSHGATE_XFER_SEND forbidden"
	if signatures, err := service.ApprovalMinter().Mint(context.Background(), plan, now); err == nil || len(signatures) != 0 {
		t.Fatal("corrupt plan signed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ApprovalMinter().Mint(ctx, plan, now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type heldApprovalNotifier struct{ entered, release, canceled chan struct{} }

func (n *heldApprovalNotifier) Burst(ctx context.Context, f func(lifecycle.BurstSession) error) error {
	return f(n)
}
func (n *heldApprovalNotifier) SendParts(ctx context.Context, _ lifecycle.Notification) ([]int64, error) {
	close(n.entered)
	<-ctx.Done()
	close(n.canceled)
	<-n.release
	return nil, ctx.Err()
}
func (*heldApprovalNotifier) SendCard(context.Context, lifecycle.Notification) (int64, error) {
	return 0, errors.New("unexpected card")
}
func (*heldApprovalNotifier) EditCard(context.Context, int64, lifecycle.Notification) (lifecycle.EditOutcome, error) {
	return lifecycle.EditFailed, nil
}
func (*heldApprovalNotifier) EditStatus(context.Context, int64, lifecycle.StatusDisplay) error {
	return nil
}
func (*heldApprovalNotifier) MarkIncomplete(context.Context, int64) error { return nil }

func TestServiceCloseJoinsApprovalSendWithoutPolicyJournal(t *testing.T) {
	defer goleak.VerifyNone(t)
	var storageClosed atomic.Bool
	store := &runtimeStore{close: func() error { storageClosed.Store(true); return nil }}
	config := runtimeConfig(t, store)
	clock := elapsedtest.NewFake(time.Now().UTC())
	notifier := &heldApprovalNotifier{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	config.NewEngine = func(s lifecycle.Store) (*lifecycle.Engine, error) {
		return lifecycle.New(lifecycle.Config{
			Store: s, Clock: clock, Freezer: runtimeFreezer{}, SnapshotBuilder: runtimeSnapshot{}, Notifier: notifier, LegacyService: config.Legacy,
		})
	}
	r, err := NewApprovalRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := r.Current()
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, clock.Wall(), st.Write("w", 60))
	if _, err := e.Submit(context.Background(), st.PrincipalA, draft); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	service := &Service{}
	if err := service.AttachApprovals(r); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	runtimeReceive(t, notifier.entered)
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	runtimeReceive(t, notifier.canceled)
	_, err = e.Vote(ap.CastVote{})
	runtimeCode(t, err, ap.CodeLifecycleUnavailable)
	select {
	case <-closed:
		t.Fatal("Close returned before send joined")
	default:
	}
	if storageClosed.Load() {
		t.Fatal("store closed before send joined")
	}
	close(notifier.release)
	if err := runtimeReceive(t, closed); err != nil {
		t.Fatal(err)
	}
	runtimeReceive(t, done)
	if !storageClosed.Load() {
		t.Fatal("store leaked")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

type runtimeLegacyNotifier struct {
	artifact         *lifecycle.PreparedLegacyApproval
	entered, release chan struct{}
}

func (*runtimeLegacyNotifier) Destination() lifecycle.LegacyDestination {
	return lifecycle.LegacyDestination{ChatID: 1}
}
func (n *runtimeLegacyNotifier) Prepared(string) (*lifecycle.PreparedLegacyApproval, error) {
	return n.artifact, nil
}
func (n *runtimeLegacyNotifier) Deliver(ctx context.Context, _ *lifecycle.PreparedLegacyApproval) (lifecycle.LegacyDelivery, error) {
	close(n.entered)
	select {
	case <-n.release:
		return lifecycle.LegacyDelivery{AllDelivered: true}, nil
	case <-ctx.Done():
		return lifecycle.LegacyDelivery{}, ctx.Err()
	}
}
func (*runtimeLegacyNotifier) EditStatus(context.Context, *lifecycle.PreparedLegacyApproval, string) error {
	return nil
}

func TestApprovalRuntimeLegacyDeliverySurvivesRepeatedRecovery(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	store := &runtimeStore{}
	notifier := &runtimeLegacyNotifier{entered: make(chan struct{}), release: make(chan struct{})}
	legacy, err := lifecycle.NewLegacyService(lifecycle.LegacyConfig{Clock: elapsed.Real(), LegacyNotifier: notifier})
	if err != nil {
		t.Fatal(err)
	}
	config := ApprovalRuntimeConfig{Store: store, Legacy: legacy}
	config.NewEngine = func(s lifecycle.Store) (*lifecycle.Engine, error) {
		return lifecycle.New(lifecycle.Config{Store: s, Clock: elapsed.Real(), Freezer: runtimeFreezer{}, SnapshotBuilder: runtimeSnapshot{}, LegacyService: legacy})
	}
	r, err := NewApprovalRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	r.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	startRuntime(t, r)
	instance := lifecycle.LegacyInstance{ID: st.Epoch(1), UID: 7, RequestID: "legacy-pending"}
	reservation, err := legacy.ReserveLegacy(context.Background(), instance, []byte("snapshot"), assist.Input{})
	if err != nil {
		t.Fatal(err)
	}
	notifier.artifact, err = lifecycle.NewPreparedLegacyApproval(lifecycle.LegacyPreparedData{Instance: instance.ID, Snapshot: reservation.Snapshot(), Context: reservation.RenderContext(), Payload: []lifecycle.LegacyMessage{{Bytes: []byte("approve?"), ApproveLabel: "approve", DenyLabel: "deny"}}})
	if err != nil {
		t.Fatal(err)
	}
	delivered := make(chan error, 1)
	go func() { delivered <- legacy.DeliverLegacy(reservation, notifier.artifact) }()
	runtimeReceive(t, notifier.entered)
	for i := 1; i <= 2; i++ {
		old, err := r.Current()
		if err != nil {
			t.Fatal(err)
		}
		store.fail.Store(true)
		_, err = old.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(i), ap.CoordinatorExecutor, time.Now().UTC(), st.Write("w", 60)))
		runtimeCode(t, err, ap.CodeStorageUncertain)
		deadline := time.After(5 * time.Second)
		for {
			current, err := r.Current()
			if err == nil && current != old {
				break
			}
			select {
			case <-deadline:
				t.Fatal("recovery timed out")
			default:
				time.Sleep(time.Millisecond)
			}
		}
		duplicate := instance
		duplicate.ID = st.Epoch(i + 1)
		if _, err := r.Legacy().ReserveLegacy(context.Background(), duplicate, []byte("snapshot"), assist.Input{}); err == nil {
			t.Fatal("legacy reservation lost")
		}
	}
	close(notifier.release)
	if err := runtimeReceive(t, delivered); err != nil {
		t.Fatal(err)
	}
	render := reservation.RenderContext()
	vote := ap.CastVote{Operator: "telegram:1", Decision: ap.VoteApprove, Card: &ap.CardTap{Handle: render.Handle, Challenge: render.Challenge}}
	result, err := r.Legacy().VoteLegacy(vote, func(lifecycle.LegacyTapResult) {})
	if err != nil || !result.Resolved {
		t.Fatalf("legacy vote: %+v %v", result, err)
	}
	result, err = r.Legacy().VoteLegacy(vote, func(lifecycle.LegacyTapResult) {})
	if err != nil || result.Resolved {
		t.Fatalf("legacy replay: %+v %v", result, err)
	}
	if result := reservation.Request().Wait(); result.Status != "approved" {
		t.Fatal(result)
	}
}
