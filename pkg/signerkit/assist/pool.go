package assist

import (
	"context"
	"sync"
	"time"
)

type Result string

const (
	Accepted Result = "accepted"
	Full     Result = "full"
	Closed   Result = "closed"
)

// Pool admits at most n jobs, including their completion callbacks, with no queue.
// Callbacks must return and must not call Close on their own pool.
type Pool struct {
	mu            sync.Mutex
	closed        bool
	active, limit int
	timers        Timers
	ctx           context.Context
	cancel        context.CancelFunc
	jobs          sync.WaitGroup
}

func NewPool(n int, t Timers) *Pool {
	if n < 1 {
		panic("assist: pool size must be positive")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{limit: n, timers: t, ctx: ctx, cancel: cancel}
}

// TrySubmit never queues. Full means the caller commits unavailable
// ReasonBusy (E68). Closed is an interruption: the caller commits nothing and
// Clock fills the slot at assist_deadline (SA-8 step 2).
//
// For Accepted work done runs once with Run's snapshot, unless Close began
// before Run returned: that job is interrupted too, and done is not called, so
// a pool stop can never hand the engine a committable snapshot. A snapshot
// from the caller's own ctx ending is ReasonCanceled; the caller judges it by
// its stopping latch (SA-8 step 4). done may run while Close waits for it.
func (p *Pool) TrySubmit(ctx context.Context, a Assessor, in Input, deadline time.Time, done func(Snapshot)) Result {
	jobCtx, cancel := context.WithCancel(ctx)
	p.mu.Lock()
	if p.closed || p.active == p.limit {
		closed := p.closed
		p.mu.Unlock()
		cancel()
		if closed {
			return Closed
		}
		return Full
	}
	p.active++
	p.jobs.Add(1)
	p.mu.Unlock()
	stop := context.AfterFunc(p.ctx, cancel)
	in = in.clone()
	go func() {
		defer p.jobs.Done()
		defer func() {
			p.mu.Lock()
			p.active--
			p.mu.Unlock()
		}()
		snapshot := Run(jobCtx, a, in, deadline, p.timers)
		stop()
		cancel()
		p.mu.Lock()
		interrupted := p.closed
		p.mu.Unlock()
		if !interrupted {
			done(snapshot)
		}
	}()
	return Accepted
}

// Close stops admission, cancels active work and joins providers and callbacks.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	p.mu.Unlock()
	p.jobs.Wait()
}
