// Package lifecycletest runs the store-independent R1 lifecycle conformance
// checks. Executor (R2) and legacy transport properties belong to their owners.
package lifecycletest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

// StoreFactory returns an empty, exclusively owned store for each invocation.
// Register resource cleanup with t.Cleanup; the suite closes every engine before
// cleanup. Recovery reuses the store, discarding all engine memory.
type StoreFactory func(t *testing.T) lc.Store

// Run exercises the real engine, including Startup, over each supplied store.
func Run(t *testing.T, factory StoreFactory) {
	t.Helper()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	t.Run("ReplayAndIsolation", func(t *testing.T) { replay(t, factory) })
	t.Run("ClockFacts", func(t *testing.T) { clockFacts(t, factory) })
	t.Run("CrashPrefixes", func(t *testing.T) { crashPrefixes(t, factory) })
	t.Run("Stop", func(t *testing.T) { stopProperty(t, factory) })
	t.Run("Grants", func(t *testing.T) { grants(t, factory) })
	t.Run("EditRetry", func(t *testing.T) { editRetry(t, factory) })
	t.Run("LiveFailureContrast", func(t *testing.T) { liveFailure(t, factory) })
	t.Run("FlushRecovery", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { flushRecovery(t, factory) })
	})
	t.Run("Schedules", func(t *testing.T) { schedules(t, factory) })
	t.Run("ReleaseSkew", func(t *testing.T) { releaseSkew(t, factory) })
}

type checkedStore struct {
	lc.Store
	clock        *elapsedtest.Fake
	mu           sync.Mutex
	commits      int
	reservations map[string]int
	afterLoad    func()
}

func (s *checkedStore) Load(key string) (ap.R1, error) {
	rec, err := s.Store.Load(key)
	if s.afterLoad != nil {
		s.afterLoad()
	}
	return rec, err
}

func (s *checkedStore) Commit(key string, rec ap.R1) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var before *ap.R1
	old, err := s.Store.Load(key)
	if err == nil {
		before = &old
	} else if !errors.Is(err, lc.ErrNotFound) {
		return err
	}
	now := ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}
	if err := st.CheckTransition(before, rec, now); err != nil {
		return fmt.Errorf("SA-11 transition: %w", err)
	}
	reservation := ap.R1Reservation(rec)
	if original, ok := s.reservations[key]; ok && !rec.Header.Shed && reservation != original {
		return errors.New("SA-11 reservation changed")
	}
	if err := s.Store.Commit(key, rec); err != nil {
		return err
	}
	saved, err := s.Store.Load(key)
	if err != nil {
		return err
	}
	encoded, err := ap.Canonical(rec)
	if err != nil {
		return err
	}
	persisted, err := ap.Canonical(saved)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, persisted) {
		return errors.New("store changed committed record")
	}
	if before == nil {
		s.reservations[key] = reservation
	}
	s.commits++
	return nil
}
func (s *checkedStore) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.commits }

type fixture struct {
	t      *testing.T
	store  *checkedStore
	clock  *elapsedtest.Fake
	engine *lc.Engine
	config lc.Config
}

func newFixture(t *testing.T, factory StoreFactory) *fixture {
	t.Helper()
	clock := elapsedtest.NewFake(st.T0)
	store := &checkedStore{Store: factory(t), clock: clock, reservations: map[string]int{}}
	return &fixture{t: t, store: store, clock: clock, config: lc.Config{Store: store, Clock: clock, Freezer: freezer{}, SnapshotBuilder: snapshotter{}}}
}
func (f *fixture) open() {
	f.t.Helper()
	var err error
	f.engine, err = lc.New(f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	engine := f.engine
	f.t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			f.t.Error(err)
		}
	})
}
func (f *fixture) run() {
	f.t.Helper()
	engine := f.engine
	done := make(chan error, 1)
	go func() { done <- engine.Run(context.Background()) }()
	f.t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			f.t.Error(err)
		}
		err := receive(f.t, done)
		var code *ap.CodeError
		if err != nil && !errors.Is(err, context.Canceled) && !(errors.As(err, &code) && code.Code == ap.CodeLifecycleUnavailable) {
			f.t.Errorf("Run: %v", err)
		}
	})
}
func (f *fixture) record() ap.R1 {
	f.t.Helper()
	rec, err := f.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if err != nil {
		f.t.Fatal(err)
	}
	return rec
}
func (f *fixture) submit() ap.Summary {
	f.t.Helper()
	summary, err := f.engine.Submit(context.Background(), st.PrincipalA, draft(f.clock.Wall()))
	if err != nil {
		f.t.Fatal(err)
	}
	return summary
}
func draft(now time.Time) ap.ApprovalDraft {
	return st.JobDraft(st.ID(1), ap.CoordinatorExecutor, now, st.Write("touch /tmp/example", 60))
}

type freezer struct{}

func (freezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	return st.Freeze(d, principal, now, time.Hour), nil
}

type snapshotter struct{}

func (snapshotter) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	return st.Review, p.Rationale, nil
}

type auditFunc func(context.Context, ap.AuditMetadata) error

func (fn auditFunc) WriteApproval(ctx context.Context, m ap.AuditMetadata) error { return fn(ctx, m) }

type mintFunc func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error)

func (fn mintFunc) Mint(ctx context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	return fn(ctx, p, at)
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("effect did not finish")
	}
	var zero T
	return zero
}
func eventually(t *testing.T, check func() bool) {
	t.Helper()
	eventuallyWithin(t, 5*time.Second, check)
}
func eventuallyWithin(t *testing.T, limit time.Duration, check func() bool) {
	t.Helper()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("condition did not become true")
		case <-ticker.C:
		}
	}
}
func requireCode(t *testing.T, err error, code ap.Code) {
	t.Helper()
	var ce *ap.CodeError
	if !errors.As(err, &ce) || ce.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
