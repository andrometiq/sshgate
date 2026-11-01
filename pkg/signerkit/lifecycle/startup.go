package lifecycle

import (
	"crypto/rand"
	"fmt"

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
		if futureDated(*rec, now, e.config.Settings) {
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

// futureDated is SA-1 rule 3's Startup report: an approved record with an
// open window (live by the retention class: mint slot empty or still holding
// bytes, before claim_end) whose decided_at is more than ReleaseSkew (3.2's
// threshold) ahead of the wall clock.
func futureDated(rec ap.R1, now ap.Now, settings ap.Settings) bool {
	end, isApproved := ap.ClaimEnd(rec)
	if !isApproved || !now.Wall.Before(end) || ap.Class(rec, now, settings, false) != ap.ClassLive {
		return false
	}
	return rec.Header.Decision.DecidedAt.After(now.Wall.Add(ap.ReleaseSkew))
}

// FutureDatedAtStartup is E59's "future-dated stamps found at Startup": the
// approved records with an open window this generation loaded with decided_at
// more than 5 s ahead. It is reported only; Startup changes nothing because of it.
func (e *Engine) FutureDatedAtStartup() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.futureDatedAtStartup
}
