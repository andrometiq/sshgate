//go:build linux

package executor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// Service.mu owns this store just as it owns the production store.
type waiterStore struct {
	jobs         map[string]ap.R2
	loads        int
	commits      int
	listErr      error
	beforeCommit func(ap.R2) error
	beforeList   func()
}

func (m *waiterStore) Load(id string) (ap.R2, error) {
	m.loads++
	j, ok := m.jobs[id]
	if !ok {
		return j, securestate.ErrNotFound
	}
	return j, nil
}
func (m *waiterStore) List() ([]JobFile, error) {
	if m.beforeList != nil {
		m.beforeList()
	}
	var files []JobFile
	for id := range m.jobs {
		files = append(files, JobFile{RequestID: id})
	}
	return files, m.listErr
}
func (m *waiterStore) Commit(j ap.R2) error {
	if m.beforeCommit != nil {
		if err := m.beforeCommit(j); err != nil {
			return err
		}
	}
	m.jobs[j.RequestID] = j
	m.commits++
	return nil
}

type waitSignerFake struct {
	submitSignerFake
	wait func(context.Context, []string, time.Duration) ([]ap.Summary, error)
}

func (f waitSignerFake) Wait(ctx context.Context, ids []string, duration time.Duration) ([]ap.Summary, error) {
	return f.wait(ctx, ids, duration)
}
func waiterService(t *testing.T, count int, clients ...SubmitSigner) (*Service, *waiterStore) {
	t.Helper()
	store := &waiterStore{jobs: make(map[string]ap.R2)}
	for i := 1; i <= count; i++ {
		job := storeJob(t, i, false)
		job.SignerAck = job.DraftHash
		store.jobs[job.RequestID] = job
	}
	servers, err := registry.New(t.TempDir() + "/servers.json")
	if err != nil {
		t.Fatal(err)
	}
	target := storeJob(t, 999, false).Draft.CommandJob.Steps[0].Target
	if err := servers.Add("server", registry.Entry{Host: target.ResolvedHost, Port: target.ResolvedPort, User: target.ResolvedUser, Fingerprint: target.TrustedHostFingerprint, AddedAt: target.AddedAt}); err != nil {
		t.Fatal(err)
	}
	var client SubmitSigner = &waitSignerFake{}
	if len(clients) != 0 {
		client = clients[0]
	}
	s, err := NewService(Config{Store: store, Servers: servers, Signer: client, Clock: elapsedtest.NewFake(st.T0)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, store
}
func receiveWait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("waiter did not progress")
		var zero T
		return zero
	}
}
func drainNudge(s *Service, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.jobNudges[id]:
	default:
	}
}

func TestWaiterBatchesAndClose(t *testing.T) {
	// Synthetic persisted jobs exercise batching, not admission or contention.
	s, store := waiterService(t, 201)
	calls := make(chan []string, 4)
	release := make(chan struct{})
	var mu sync.Mutex
	active := 0
	*s.waitSigner.(*waitSignerFake) = waitSignerFake{wait: func(ctx context.Context, ids []string, d time.Duration) ([]ap.Summary, error) {
		if len(ids) > 100 || len(ids) == 0 || d != 55*time.Second {
			t.Error("invalid WaitMany bounds", len(ids), d)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > ap.AwaitMaxWait+sign.ApprovalWaitGrace {
			t.Error("unbounded wait")
		}
		mu.Lock()
		active++
		mu.Unlock()
		calls <- append([]string(nil), ids...)
		select {
		case <-ctx.Done():
		case <-release:
		}
		mu.Lock()
		active--
		mu.Unlock()
		return nil, ctx.Err()
	}}
	s.startWaiter()
	s.startWaiter()
	seen := map[string]bool{}
	for batch := range 3 {
		for _, id := range receiveWait(t, calls) {
			if seen[id] {
				t.Error("duplicate watch", id)
			}
			seen[id] = true
		}
		if batch < 2 {
			release <- struct{}{}
		}
	}
	if len(seen) != 201 {
		t.Fatal("jobs omitted", len(seen))
	}
	s.Close()
	mu.Lock()
	defer mu.Unlock()
	if active != 0 {
		t.Fatal("Close did not join waits")
	}
	if store.commits != 0 {
		t.Fatal("waiter wrote durable state")
	}
}

func TestWaiterMembershipAndNudges(t *testing.T) {
	s, store := waiterService(t, 4)
	unacked := store.jobs[st.ID(2)]
	unacked.SignerAck = ""
	store.jobs[unacked.RequestID] = unacked
	final := store.jobs[st.ID(3)]
	final.Outcome = &ap.JobOutcome{Kind: "denied"}
	store.jobs[final.RequestID] = final
	reporting := store.jobs[st.ID(4)]
	result := ap.NoOutputResult(ap.StepExpiredUnexecuted, "")
	reporting.Steps[0].Result = &result
	store.jobs[reporting.RequestID] = reporting
	calls := make(chan []string, 8)
	release := make(chan struct{})
	*s.waitSigner.(*waitSignerFake) = waitSignerFake{wait: func(ctx context.Context, ids []string, _ time.Duration) ([]ap.Summary, error) {
		calls <- append([]string(nil), ids...)
		select {
		case <-ctx.Done():
		case <-release:
		}
		return nil, ctx.Err()
	}}
	s.startWaiter()
	first := receiveWait(t, calls)
	if len(first) != 1 || first[0] != st.ID(1) {
		t.Fatal("watched unacknowledged or final job", first)
	}
	s.mu.Lock()
	if len(s.jobNudges[st.ID(1)]) != 1 || len(s.jobNudges[st.ID(2)]) != 1 || len(s.jobNudges[st.ID(4)]) != 1 {
		t.Error("startup omitted nudges")
	}
	for range 1000 {
		s.nudgeLocked(st.ID(1))
	}
	if len(s.jobNudges[st.ID(1)]) != 1 {
		t.Error("nudges did not coalesce")
	}
	unacked.SignerAck = unacked.DraftHash
	store.jobs[unacked.RequestID] = unacked
	s.jobCommittedLocked(unacked)
	s.mu.Unlock()
	release <- struct{}{}
	next := receiveWait(t, calls)
	if len(next) != 2 {
		t.Fatal("newly acknowledged job delayed by old wait", next)
	}
	s.Close()
	drainNudge(s, st.ID(1))
	s.mu.Lock()
	s.nudgeLocked(st.ID(1))
	pending := len(s.jobNudges[st.ID(1)])
	s.mu.Unlock()
	if pending != 0 {
		t.Fatal("nudge after owner stop")
	}
}

func TestWaiterReplyOnlyNudgesRequestedJobs(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			s, store := waiterService(t, 1)
			ids, err := s.refreshWaiter()
			if err != nil {
				t.Fatal(err)
			}
			drainNudge(s, st.ID(1))
			ctx, cancel := context.WithCancel(s.effects)
			defer cancel()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			*s.waitSigner.(*waitSignerFake) = waitSignerFake{wait: func(context.Context, []string, time.Duration) ([]ap.Summary, error) {
				close(entered)
				<-release
				if failed {
					return nil, errors.New("busy")
				}
				return []ap.Summary{{RequestID: st.ID(999), ApprovalStatus: ap.ApprovalApproved}}, nil
			}}
			go func() { defer close(done); s.waitBatch(ctx, s.waitSigner, ids) }()
			receiveWait(t, entered)
			close(release)
			s.mu.Lock()
			flag := s.jobNudges[st.ID(1)]
			s.mu.Unlock()
			receiveWait(t, flag)
			cancel()
			receiveWait(t, done)
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.jobNudges[st.ID(999)] != nil || store.commits != 0 {
				t.Fatal("Wait reply changed authority or durable state")
			}
		})
	}
}

func TestWaiterLateReplyAndStoreFailure(t *testing.T) {
	s, _ := waiterService(t, 1)
	ids, _ := s.refreshWaiter()
	drainNudge(s, st.ID(1))
	ctx, cancel := context.WithCancel(s.effects)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	signer := waitSignerFake{wait: func(context.Context, []string, time.Duration) ([]ap.Summary, error) {
		close(entered)
		<-release
		return nil, nil
	}}
	go func() { defer close(done); s.waitBatch(ctx, signer, ids) }()
	receiveWait(t, entered)
	cancel()
	close(release)
	receiveWait(t, done)
	s.mu.Lock()
	pending := len(s.jobNudges[st.ID(1)])
	s.mu.Unlock()
	if pending != 0 {
		t.Fatal("cancelled batch nudged after reply")
	}
	failed, failedStore := waiterService(t, 0)
	failedStore.listErr = errors.New("store unavailable")
	*failed.waitSigner.(*waitSignerFake) = signer
	failed.startWaiter()
	if err := receiveWait(t, failed.fatal); err == nil {
		t.Fatal("store failure hidden")
	}
}

func TestWaiterFiltersAndTick(t *testing.T) {
	s, store := waiterService(t, 2)
	job := store.jobs[st.ID(2)]
	job.Draft.CommandJob = nil
	store.jobs[job.RequestID] = job
	calls := make(chan struct{}, 1)
	*s.waitSigner.(*waitSignerFake) = waitSignerFake{wait: func(ctx context.Context, ids []string, _ time.Duration) ([]ap.Summary, error) {
		if len(ids) != 1 || ids[0] != st.ID(1) {
			t.Error("non-command job watched", ids)
		}
		calls <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	s.startWaiter()
	receiveWait(t, calls)
	drainNudge(s, st.ID(1))
	s.mu.Lock()
	flag := s.jobNudges[st.ID(1)]
	foreign := s.jobNudges[st.ID(2)]
	s.mu.Unlock()
	if foreign != nil {
		t.Fatal("non-command job nudged")
	}
	receiveWait(t, flag)
	s.Close()
	if store.commits != 0 {
		t.Fatal("tick committed state")
	}
}

func TestWaiterFailureBackoff(t *testing.T) {
	s, _ := waiterService(t, 1)
	calls := make(chan time.Time, 4)
	*s.waitSigner.(*waitSignerFake) = waitSignerFake{wait: func(ctx context.Context, _ []string, _ time.Duration) ([]ap.Summary, error) {
		select {
		case calls <- time.Now():
		case <-ctx.Done():
		}
		return nil, errors.New("busy")
	}}
	s.startWaiter()
	first := receiveWait(t, calls)
	second := receiveWait(t, calls)
	third := receiveWait(t, calls)
	s.Close()
	if second.Sub(first) < 250*time.Millisecond || third.Sub(second) < 500*time.Millisecond {
		t.Fatal("retry did not back off")
	}
}

func TestWaiterProjectionAvoidsReloadingRetainedBodies(t *testing.T) {
	s, store := waiterService(t, 2)
	settled := store.jobs[st.ID(2)]
	settled.Outcome = &ap.JobOutcome{Kind: ap.OutcomeDenied}
	store.jobs[settled.RequestID] = settled
	if _, err := s.refreshWaiter(); err != nil {
		t.Fatal(err)
	}
	if store.loads != 2 {
		t.Fatal("startup did not load persisted jobs", store.loads)
	}
	for range 5 {
		if _, err := s.refreshWaiter(); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	s.jobCommittedLocked(store.jobs[st.ID(1)])
	s.mu.Unlock()
	if _, err := s.refreshWaiter(); err != nil {
		t.Fatal(err)
	}
	if store.loads != 2 {
		t.Fatal("tick or commit reloaded retained bodies", store.loads)
	}
	if s.jobNudges[settled.RequestID] != nil {
		t.Fatal("settled job retained a nudge flag")
	}
	s.mu.Lock()
	finished := store.jobs[st.ID(1)]
	finished.Outcome = &ap.JobOutcome{Kind: ap.OutcomeDenied}
	store.jobs[finished.RequestID] = finished
	s.jobCommittedLocked(finished)
	s.mu.Unlock()
	ids, err := s.refreshWaiter()
	if err != nil || len(ids) != 0 || len(s.jobNudges) != 0 {
		t.Fatal("final commit left a watch or nudge", ids, err)
	}
}
