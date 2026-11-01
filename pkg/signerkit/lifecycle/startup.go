package lifecycle

import (
	"crypto/rand"
	"fmt"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// startup is shared by process start and reopen: no prior engine memory survives.
func (e *Engine) startup() error {
	entries, err := e.config.Store.List()
	if err != nil {
		return err
	}
	e.epoch, err = ap.NewEpoch(rand.Reader)
	if err != nil {
		return err
	}
	e.published.epoch = e.epoch
	now := e.now()
	for _, entry := range entries {
		if !validKey(entry.Key) || entry.EncodedSize < 0 {
			return keyError()
		}
		if _, exists := e.projections.records[entry.Key]; exists {
			return keyError()
		}
		if _, exists := e.projections.quarantined[entry.Key]; exists {
			return keyError()
		}
		if entry.Quarantined {
			e.projections.quarantined[entry.Key] = entry.EncodedSize
			e.published.quarantined[entry.Key] = true
			e.projections.total.records++
			e.projections.total.full++
			e.projections.total.live++
			e.projections.total.reserved += entry.EncodedSize
			continue
		}
		rec, err := e.load(entry.Key)
		if err != nil {
			return err
		}
		if rec == nil {
			return fmt.Errorf("lifecycle: listed record missing")
		}
		if futureDated(*rec, now.Wall) {
			e.futureDatedAtStartup++
		}
		e.projections.update(entry.Key, nil, *rec, now, e.epoch, e.config.Settings)
		e.published.loadLocked(entry.Key, rec)
	}
	e.publishStartupGrants()
	// Build every index before any recovery commit can publish dependent work.
	for _, entry := range entries {
		if !entry.Quarantined {
			if err := e.reconcileLocked(entry.Key, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// futureStampMargin is E59's threshold for a stamp reported as future-dated.
const futureStampMargin = 5 * time.Minute

// futureDated reports a record whose creation or decision stamp is more than
// the margin ahead of the wall clock: a clock that moved back while stopped.
func futureDated(rec ap.R1, wall time.Time) bool {
	limit := wall.Add(futureStampMargin)
	if rec.Header.CreatedAt.After(limit) {
		return true
	}
	return rec.Header.Decision != nil && rec.Header.Decision.DecidedAt.After(limit)
}

// FutureDatedAtStartup is E59's "future-dated stamps found at Startup": the
// records this generation loaded with a stamp more than 5 min ahead. It is
// reported only; Startup changes nothing because of it.
func (e *Engine) FutureDatedAtStartup() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.futureDatedAtStartup
}
