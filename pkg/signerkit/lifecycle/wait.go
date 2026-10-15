package lifecycle

import (
	"context"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// WaitResult contains committed summaries in request order. WaitElapsed is a
// nonterminal polling outcome; it never changes an approval record.
type WaitResult struct {
	Summaries   []ap.Summary
	WaitElapsed bool
}

// WaitMany waits for a confirmed change to any requested record. A zero budget
// reads immediately. Missing and foreign IDs both answer not_found.
func (e *Engine) WaitMany(ctx context.Context, principal string, requestIDs []string, wait time.Duration) (WaitResult, error) {
	if len(requestIDs) == 0 || len(requestIDs) > ap.AwaitMaxIDs || wait < 0 || wait > ap.AwaitMaxWait {
		return WaitResult{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	keys := make([]string, len(requestIDs))
	seen := make(map[string]bool, len(keys))
	for i, id := range requestIDs {
		if !ap.ValidRequestID(id) || seen[id] {
			return WaitResult{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		seen[id] = true
		keys[i] = ap.RecordKey(principal, id)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return WaitResult{}, err
	}
	summaries, err := e.waitSummariesLocked(keys)
	if err != nil {
		return WaitResult{}, err
	}
	if wait == 0 {
		return WaitResult{Summaries: summaries, WaitElapsed: true}, nil
	}
	ready := make(chan struct{}, 1)
	if e.waiters == nil {
		e.waiters = make(map[string]map[chan struct{}]struct{})
	}
	for _, key := range keys {
		if e.waiters[key] == nil {
			e.waiters[key] = make(map[chan struct{}]struct{})
		}
		e.waiters[key][ready] = struct{}{}
	}
	defer func() {
		for _, key := range keys {
			delete(e.waiters[key], ready)
			if len(e.waiters[key]) == 0 {
				delete(e.waiters, key)
			}
		}
	}()
	timer := newWaitTimer(wait)
	defer timer.Stop()
	e.mu.Unlock()
	elapsed := false
	select {
	case <-ready:
	case <-timer.C:
		elapsed = true
	case <-ctx.Done():
	}
	e.mu.Lock()
	if err := ctx.Err(); err != nil {
		return WaitResult{}, err
	}
	// A confirmed commit racing the timer wins over the polling timeout.
	select {
	case <-ready:
		elapsed = false
	default:
	}
	summaries, err = e.waitSummariesLocked(keys)
	if err != nil {
		return WaitResult{}, err
	}
	return WaitResult{Summaries: summaries, WaitElapsed: elapsed}, nil
}

func (e *Engine) waitSummariesLocked(keys []string) ([]ap.Summary, error) {
	summaries := make([]ap.Summary, 0, len(keys))
	now := e.now()
	for _, key := range keys {
		rec, err := e.load(key)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return nil, &ap.CodeError{Code: ap.CodeNotFound}
		}
		summaries = append(summaries, e.view(key, *rec, now))
	}
	return summaries, nil
}

func (e *Engine) wakeWaitersLocked(key string) {
	for ready := range e.waiters[key] {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
}

// This timer bounds polling only and confers no authority.
func newWaitTimer(wait time.Duration) *time.Timer { return time.NewTimer(wait) }
