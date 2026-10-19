package lifecycle

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// publishedState belongs to one generation. Its lock never covers storage or
// adapters. Records are owned immutable copies, separate from mutation inputs.
// Lock order: Engine.mu, FileStore.operation, publishedState.mu, FileStore.mu.
type publishedState struct {
	mu          sync.RWMutex
	records     map[string]*ap.R1
	quarantined map[string]bool
	grants      map[string]bool
	epoch       string
	settings    ap.Settings
	stopping    bool
	stopCause   error
	cancel      context.CancelFunc
	waiters     map[string]map[chan struct{}]struct{}
}

func (p *publishedState) availabilityLocked() error {
	if p.stopCause != nil {
		return p.stopCause
	}
	if p.stopping {
		return unavailable()
	}
	return nil
}

func (p *publishedState) poisonLocked(err error) {
	p.stopCause, p.stopping = err, true
	p.records, p.grants, p.quarantined = nil, nil, nil
	for key := range p.waiters {
		p.wakeLocked(key)
	}
}

func (p *publishedState) wakeLocked(key string) {
	for ready := range p.waiters[key] {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
}

func copyPublishedRecord(record ap.R1) (*ap.R1, error) {
	// Store.Commit validates before publication; this copy only obtains ownership.
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	var owned ap.R1
	if err := json.Unmarshal(data, &owned); err != nil {
		return nil, err
	}
	return &owned, nil
}

// publishLocked runs after the confirmed write and writer projection update.
func (e *Engine) publishLocked(key string, record *ap.R1) {
	p := &e.published
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.availabilityLocked() != nil {
		return
	}
	if record == nil {
		delete(p.records, key)
	} else {
		p.records[key] = record
	}
	e.publishGrantsLocked()
	p.wakeLocked(key)
}

// Startup has no readers yet, so records load without a per-record grant pass.
func (p *publishedState) loadLocked(key string, record *ap.R1) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.availabilityLocked() == nil {
		p.records[key] = record
	}
}

func (e *Engine) publishStartupGrants() {
	e.published.mu.Lock()
	defer e.published.mu.Unlock()
	if e.published.availabilityLocked() == nil {
		e.publishGrantsLocked()
	}
}

// The grant set is bounded by the live cap; record maps are never copied.
func (e *Engine) publishGrantsLocked() {
	p := &e.published
	for key := range p.grants {
		if e.projections.grants[key] == nil {
			delete(p.grants, key)
			p.wakeLocked(key)
		}
	}
	for key := range e.projections.grants {
		if !p.grants[key] {
			p.grants[key] = true
			p.wakeLocked(key)
		}
	}
}

func (e *Engine) expireGrantsLocked(now ap.Now) {
	e.projections.expireGrants(now)
	e.published.mu.Lock()
	defer e.published.mu.Unlock()
	if e.published.availabilityLocked() == nil {
		e.publishGrantsLocked()
	}
}

type publishedRecord struct {
	key       string
	record    *ap.R1
	grantLive bool
}

func (p *publishedState) captureLocked(keys []string) ([]publishedRecord, error) {
	if err := p.availabilityLocked(); err != nil {
		return nil, err
	}
	records := make([]publishedRecord, 0, len(keys))
	for _, key := range keys {
		if p.quarantined[key] {
			return nil, keyError()
		}
		record := p.records[key]
		if record == nil {
			return nil, &ap.CodeError{Code: ap.CodeNotFound}
		}
		records = append(records, publishedRecord{key, record, p.grants[key]})
	}
	return records, nil
}

func (e *Engine) publishedViews(records []publishedRecord) ([]ap.Summary, error) {
	now := e.now()
	out := make([]ap.Summary, 0, len(records))
	for _, record := range records {
		out = append(out, ap.View(*record.record, now, e.published.epoch, e.published.settings, record.grantLive))
	}
	if err := e.Availability(); err != nil {
		return nil, err
	}
	return out, nil
}

// Get reads the last published commit, without waiting for the mutation owner.
func (e *Engine) Get(principal, requestID string) (ap.Summary, error) {
	p := &e.published
	p.mu.RLock()
	records, err := p.captureLocked([]string{ap.RecordKey(principal, requestID)})
	p.mu.RUnlock()
	if err != nil {
		return ap.Summary{}, err
	}
	summaries, err := e.publishedViews(records)
	if err != nil {
		return ap.Summary{}, err
	}
	return summaries[0], nil
}

// List captures ownership and grant membership in the same publication cut.
func (e *Engine) List(principal string) ([]ap.Summary, error) {
	p := &e.published
	p.mu.RLock()
	if err := p.availabilityLocked(); err != nil {
		p.mu.RUnlock()
		return nil, err
	}
	records := make([]publishedRecord, 0)
	for key, record := range p.records {
		if record.Header.Principal == principal {
			records = append(records, publishedRecord{key, record, p.grants[key]})
		}
	}
	p.mu.RUnlock()
	slices.SortFunc(records, func(a, b publishedRecord) int {
		return strings.Compare(a.key, b.key)
	})
	return e.publishedViews(records)
}
