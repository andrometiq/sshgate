package assist

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type assessorFunc func(context.Context, Input) (approvalplan.AssistResult, error)

func (f assessorFunc) Assess(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
	return f(ctx, in)
}
func goodResult(in Input) approvalplan.AssistResult {
	effects := make([]string, len(in.Commands))
	for i := range effects {
		effects[i] = "Runs a command."
	}
	return approvalplan.AssistResult{Alignment: approvalplan.AlignmentAligned, Summary: "Removes a temporary file.", Effects: effects, Model: "test", PromptVersion: PromptVersion, GeneratedAt: time.Now().UTC()}
}
func goodAssessor(_ context.Context, in Input) (approvalplan.AssistResult, error) {
	return goodResult(in), nil
}

// far is a deadline no test reaches, for tests where the deadline is not under test.
func far() time.Time { return time.Now().Add(time.Hour) }

func withResult(edit func(*approvalplan.AssistResult)) Assessor {
	return assessorFunc(func(_ context.Context, in Input) (approvalplan.AssistResult, error) {
		r := goodResult(in)
		edit(&r)
		return r, nil
	})
}

func TestRunTerminalResults(t *testing.T) {
	in := Input{Kind: approvalplan.KindCommandJob, Reason: "clean up", Commands: []string{"rm /tmp/a", "rm /tmp/b"}}
	for _, tc := range []struct {
		name  string
		a     Assessor
		ready bool
	}{
		{"ready", assessorFunc(goodAssessor), true},
		{"provider digest ignored", withResult(func(r *approvalplan.AssistResult) { r.InputDigest = Input{Reason: "other"}.Digest() }), true},
		{"nil", nil, false},
		{"error", assessorFunc(func(context.Context, Input) (approvalplan.AssistResult, error) {
			return approvalplan.AssistResult{}, errors.New("https://private Bearer secret")
		}), false},
		{"panic", assessorFunc(func(context.Context, Input) (approvalplan.AssistResult, error) {
			panic("https://private Bearer secret")
		}), false},
		{"invalid", withResult(func(r *approvalplan.AssistResult) { r.Alignment = "authorize" }), false},
		{"model answers not_assessed", withResult(func(r *approvalplan.AssistResult) { r.Alignment = approvalplan.AlignmentNotAssessed }), false},
		{"extra effect", withResult(func(r *approvalplan.AssistResult) { r.Effects = append(r.Effects, "Also this.") }), false},
		{"missing effect", withResult(func(r *approvalplan.AssistResult) { r.Effects = r.Effects[:1] }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Run(context.Background(), tc.a, in, far(), Timers{})
			if (s.State == approvalplan.AssistReady) != tc.ready {
				t.Fatalf("%+v", s)
			}
			if tc.ready && (s.Result.InputDigest != in.Digest() || s.Result.Alignment != approvalplan.AlignmentAligned) {
				t.Fatalf("result not bound to its input: %+v", s.Result)
			}
			if !tc.ready && (s.Result != nil || s.Reason != ReasonFailed) {
				t.Fatalf("unsafe failure: %+v", s)
			}
		})
	}
}

func TestRunForcesLegacyNotAssessed(t *testing.T) {
	in := Input{Kind: approvalplan.KindCommandJob, Reason: approvalplan.LegacyRationaleText, Commands: []string{"uptime"}, legacy: true}
	s := Run(context.Background(), assessorFunc(goodAssessor), in, far(), Timers{})
	if s.State != approvalplan.AssistReady || s.Result.Alignment != approvalplan.AlignmentNotAssessed {
		t.Fatalf("legacy alignment not forced: %+v", s)
	}
	in.legacy = false
	if s = Run(context.Background(), assessorFunc(goodAssessor), in, far(), Timers{}); s.Result.Alignment != approvalplan.AlignmentAligned {
		t.Fatalf("reason text alone forced not_assessed: %+v", s.Result)
	}
}

func TestRunDeadlineCancelsJoinsDropsLate(t *testing.T) {
	var now atomic.Int64
	base := time.Now()
	fire := make(chan time.Time, 1)
	timerReady := make(chan time.Duration, 1)
	timers := Timers{Now: func() time.Time { return base.Add(time.Duration(now.Load())) }, After: func(d time.Duration) <-chan time.Time { timerReady <- d; return fire }}
	started, joined := make(chan struct{}), make(chan struct{})
	assessor := assessorFunc(func(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
		close(started)
		<-ctx.Done()
		defer close(joined)
		return goodResult(in), nil
	})
	result := make(chan Snapshot, 1)
	go func() { result <- Run(context.Background(), assessor, Input{}, base.Add(5*time.Second), timers) }()
	<-started
	if d := <-timerReady; d != 5*time.Second {
		t.Fatalf("watchdog duration %v", d)
	}
	now.Store(int64(5 * time.Second))
	fire <- base.Add(5 * time.Second)
	s := <-result
	if s.State != approvalplan.AssistUnavailable || s.Reason != approvalplan.AssistDeadlineReason || s.Result != nil {
		t.Fatalf("late result accepted: %+v", s)
	}
	select {
	case <-joined:
	default:
		t.Fatal("Run did not join")
	}
}

func TestRunExpiredOrCanceledNeverCallsProvider(t *testing.T) {
	var calls atomic.Int32
	a := assessorFunc(func(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
		calls.Add(1)
		return goodResult(in), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Run(ctx, a, Input{}, far(), Timers{})
	Run(context.Background(), a, Input{}, time.Now(), Timers{})
	if calls.Load() != 0 {
		t.Fatal("started expired/canceled job")
	}
}

func TestRunCompletionAtDeadlineIsDropped(t *testing.T) {
	base := time.Now()
	var now atomic.Int64
	a := assessorFunc(func(_ context.Context, in Input) (approvalplan.AssistResult, error) {
		now.Store(int64(5 * time.Second))
		return goodResult(in), nil
	})
	s := Run(context.Background(), a, Input{}, base.Add(5*time.Second), Timers{Now: func() time.Time { return base.Add(time.Duration(now.Load())) }, After: func(time.Duration) <-chan time.Time { return make(chan time.Time) }})
	if s.Reason != approvalplan.AssistDeadlineReason {
		t.Fatalf("%+v", s)
	}
}

func TestPoolFullNeverQueues(t *testing.T) {
	pool := NewPool(2, Timers{})
	defer pool.Close()
	a := assessorFunc(func(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
		<-ctx.Done()
		return goodResult(in), nil
	})
	for range 2 {
		if pool.TrySubmit(context.Background(), a, Input{}, far(), func(Snapshot) {}) != Accepted {
			t.Fatal("not admitted")
		}
	}
	start := time.Now()
	if pool.TrySubmit(context.Background(), a, Input{}, far(), func(Snapshot) { t.Error("full callback") }) != Full {
		t.Fatal("queued full job")
	}
	if time.Since(start) > time.Second {
		t.Fatal("full submission blocked")
	}
}

// The deadline is an hour away, so only Close's cancellation can end the jobs.
func TestPoolCloseCancelsRunningJobs(t *testing.T) {
	pool := NewPool(2, Timers{})
	var canceled atomic.Int32
	started := make(chan struct{}, 2)
	a := assessorFunc(func(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			canceled.Add(1)
		}
		return goodResult(in), nil
	})
	for range 2 {
		if pool.TrySubmit(context.Background(), a, Input{}, far(), func(s Snapshot) { t.Errorf("an interrupted job handed the engine %+v", s) }) != Accepted {
			t.Fatal("not admitted")
		}
	}
	<-started
	<-started
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel running jobs")
	}
	if canceled.Load() != 2 {
		t.Fatalf("%d of 2 providers saw cancellation", canceled.Load())
	}
	if pool.TrySubmit(context.Background(), a, Input{}, far(), func(Snapshot) { t.Error("closed callback") }) != Closed {
		t.Fatal("submission after Close was not Closed")
	}
}

func TestPoolCallerCancelReportsCanceled(t *testing.T) {
	pool := NewPool(1, Timers{})
	defer pool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	a := assessorFunc(func(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
		close(started)
		<-ctx.Done()
		return goodResult(in), nil
	})
	snapshots := make(chan Snapshot, 1)
	if pool.TrySubmit(ctx, a, Input{}, far(), func(s Snapshot) { snapshots <- s }) != Accepted {
		t.Fatal("not admitted")
	}
	<-started
	cancel()
	if s := <-snapshots; s.State != approvalplan.AssistUnavailable || s.Reason != ReasonCanceled {
		t.Fatalf("%+v", s)
	}
}

func waitClosing(t *testing.T, pool *Pool) {
	t.Helper()
	for start := time.Now(); time.Since(start) < 5*time.Second; time.Sleep(time.Millisecond) {
		pool.mu.Lock()
		closing := pool.closed
		pool.mu.Unlock()
		if closing {
			return
		}
	}
	t.Fatal("Close never began")
}

// A full pool whose Close is in progress answers Closed, never Full (C-67).
func TestPoolClosedBeatsFull(t *testing.T) {
	pool := NewPool(1, Timers{})
	entered, release := make(chan struct{}), make(chan struct{})
	if pool.TrySubmit(context.Background(), assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) { close(entered); <-release }) != Accepted {
		t.Fatal("not admitted")
	}
	<-entered
	if pool.TrySubmit(context.Background(), assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) {}) != Full {
		t.Fatal("pool not full")
	}
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	waitClosing(t, pool)
	results := make(chan Result, 16)
	var submitters sync.WaitGroup
	for range 16 {
		submitters.Go(func() {
			results <- pool.TrySubmit(context.Background(), assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) { t.Error("closing callback") })
		})
	}
	submitters.Wait()
	close(results)
	for result := range results {
		if result != Closed {
			t.Fatalf("closing full pool answered %s", result)
		}
	}
	close(release)
	<-closed
}

func TestPoolConcurrentClose(t *testing.T) {
	for range 20 {
		pool := NewPool(3, Timers{})
		var workers sync.WaitGroup
		for range 30 {
			workers.Go(func() {
				pool.TrySubmit(context.Background(), assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) {})
			})
		}
		workers.Go(pool.Close)
		workers.Wait()
		if pool.TrySubmit(context.Background(), nil, Input{}, time.Now(), func(Snapshot) { t.Error("closed callback") }) != Closed {
			t.Fatal("not closed")
		}
	}
}

func TestPoolNilContextLeavesPoolUsable(t *testing.T) {
	pool := NewPool(1, Timers{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		func() {
			defer func() {
				if recover() == nil {
					t.Error("nil context accepted")
				}
			}()
			var nilCtx context.Context
			pool.TrySubmit(nilCtx, assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) {})
		}()
		if pool.TrySubmit(context.Background(), assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) {}) != Accepted {
			t.Error("pool unusable after a nil context")
		}
		pool.Close()
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("nil context wedged the pool")
	}
}

func TestPoolSaturationAllJobsFinishAtWatchdog(t *testing.T) {
	base := time.Now()
	var elapsed atomic.Int64
	fire := make(chan time.Time)
	armed := make(chan struct{}, 2)
	pool := NewPool(2, Timers{Now: func() time.Time { return base.Add(time.Duration(elapsed.Load())) }, After: func(time.Duration) <-chan time.Time { armed <- struct{}{}; return fire }})
	defer pool.Close()
	a := assessorFunc(func(ctx context.Context, in Input) (approvalplan.AssistResult, error) {
		<-ctx.Done()
		return goodResult(in), nil
	})
	snapshots := make(chan Snapshot, 12)
	results := make(chan Result, 12)
	var submitters sync.WaitGroup
	for range 12 {
		submitters.Go(func() {
			result := pool.TrySubmit(context.Background(), a, Input{}, base.Add(5*time.Second), func(s Snapshot) { snapshots <- s })
			if result == Full {
				snapshots <- unavailable(ReasonBusy)
			}
			results <- result
		})
	}
	submitters.Wait()
	accepted, full := 0, 0
	for range 12 {
		switch <-results {
		case Accepted:
			accepted++
		case Full:
			full++
		default:
			t.Fatal("unexpected closed pool")
		}
	}
	if accepted != 2 || full != 10 {
		t.Fatalf("admission accepted=%d full=%d", accepted, full)
	}
	for range 2 {
		<-armed
	}
	start := time.Now()
	elapsed.Store(int64(5 * time.Second))
	close(fire)
	for range 12 {
		select {
		case s := <-snapshots:
			if s.State != approvalplan.AssistUnavailable || (s.Reason != ReasonBusy && s.Reason != ReasonDeadline) {
				t.Fatalf("%+v", s)
			}
		case <-time.After(time.Second):
			t.Fatal("pool left a queued or unjoined job")
		}
	}
	pool.Close()
	if time.Since(start) > time.Second {
		t.Fatal("watchdog completion took too long")
	}
}

func TestPoolCloseJoinsAcceptedCallbacks(t *testing.T) {
	pool := NewPool(1, Timers{})
	callbackStarted := make(chan struct{})
	release := make(chan struct{})
	if pool.TrySubmit(context.Background(), assessorFunc(goodAssessor), Input{}, far(), func(Snapshot) { close(callbackStarted); <-release }) != Accepted {
		t.Fatal("not accepted")
	}
	<-callbackStarted
	// A rejected submission must not enter a callback that could escape Close.
	if pool.TrySubmit(context.Background(), nil, Input{}, time.Now(), func(Snapshot) { t.Error("full callback") }) != Full {
		t.Fatal("not full during callback")
	}
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before callback finished")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join callback")
	}
}
