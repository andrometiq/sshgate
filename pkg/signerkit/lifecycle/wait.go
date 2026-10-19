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
	e.published.mu.Lock()
	defer e.published.mu.Unlock()
	if err := e.published.availabilityLocked(); err != nil {
		return WaitResult{}, err
	}
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
	if err := ctx.Err(); err != nil {
		return WaitResult{}, err
	}
	records, err := e.published.captureLocked(keys)
	if err != nil {
		return WaitResult{}, err
	}
	if wait == 0 {
		e.published.mu.Unlock()
		summaries, err := e.publishedViews(records)
		e.published.mu.Lock()
		if stopped := e.published.availabilityLocked(); stopped != nil {
			return WaitResult{}, stopped
		}
		return WaitResult{Summaries: summaries, WaitElapsed: true}, err
	}
	e.waitJoined.Add(1)
	defer e.waitJoined.Done()
	ready := make(chan struct{}, 1)
	if e.published.waiters == nil {
		e.published.waiters = make(map[string]map[chan struct{}]struct{})
	}
	for _, key := range keys {
		if e.published.waiters[key] == nil {
			e.published.waiters[key] = make(map[chan struct{}]struct{})
		}
		e.published.waiters[key][ready] = struct{}{}
	}

	timer := newWaitTimer(wait)
	defer timer.Stop()
	e.published.mu.Unlock()
	elapsed := false
	select {
	case <-e.effectContext.Done():
	case <-ready:
	case <-timer.C:
		elapsed = true
	case <-ctx.Done():
	}
	e.published.mu.Lock()
	for _, key := range keys {
		delete(e.published.waiters[key], ready)
		if len(e.published.waiters[key]) == 0 {
			delete(e.published.waiters, key)
		}
	}
	if err := e.published.availabilityLocked(); err != nil {
		return WaitResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return WaitResult{}, err
	}
	// A confirmed commit racing the timer wins over the polling timeout.
	select {
	case <-ready:
		elapsed = false
	default:
	}
	records, err = e.published.captureLocked(keys)
	if err != nil {
		return WaitResult{}, err
	}
	e.published.mu.Unlock()
	summaries, err := e.publishedViews(records)
	e.published.mu.Lock()
	if stopped := e.published.availabilityLocked(); stopped != nil {
		return WaitResult{}, stopped
	}
	return WaitResult{Summaries: summaries, WaitElapsed: elapsed}, err
}

// This timer bounds polling only and confers no authority.
func newWaitTimer(wait time.Duration) *time.Timer { return time.NewTimer(wait) }
