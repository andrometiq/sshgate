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
		e.projections.update(entry.Key, nil, *rec, now, e.epoch, e.config.Settings)
	}
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
