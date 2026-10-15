package lifecycle

import (
	"context"
	"errors"
	"slices"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Run drives the due index and one independent outbox flusher. It returns
// storage failures to the owner and joins the flusher on cancellation.
func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("lifecycle: Run already active")
	}
	e.running = true
	e.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	flushed := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); flushed <- e.runFlusher(ctx) }()
	defer func() {
		cancel()
		<-joined
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()
	ticker := newReconcileTicker()
	defer ticker.Stop()
	for {
		select {
		case err := <-flushed:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := e.Reconcile(); err != nil {
				return err
			}
		}
	}
}

// Reconcile advances due records using one injected clock reading. Outbox
// retries are independent: an unaudited event never makes a record due.
func (e *Engine) Reconcile() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	e.projections.expireGrants(now)
	keys := make([]string, 0)
	for key, due := range e.projections.due {
		if !now.Wall.Before(due) {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a, b string) int {
		if order := e.projections.due[a].Compare(e.projections.due[b]); order != 0 {
			return order
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	for _, key := range keys {
		if err := e.reconcileLocked(key, now); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) reconcileLocked(key string, now ap.Now) error {
	rec, err := e.load(key)
	if err != nil {
		return err
	}
	if rec == nil {
		return keyError()
	}
	work := ap.Next(*rec, now, e.epoch, e.config.Settings, e.projections.grants[key] != nil)
	if work.Clock {
		after, answer, err := e.commitLocked(key, rec, ap.Tick{}, now, ap.Inputs{})
		if err != nil {
			return err
		}
		if err := answerError(answer); err != nil {
			return err
		}
		rec = &after
	}
	// A report horizon can pass without a commit; it must still leave the index.
	e.projections.schedule(key, *rec, now, e.epoch, e.config.Settings)
	return nil
}

// This timer only wakes the runner; its timestamps never enter lifecycle state.
func newReconcileTicker() *time.Ticker { return time.NewTicker(time.Second) }
