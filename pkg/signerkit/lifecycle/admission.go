package lifecycle

import (
	"errors"
	"slices"
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Caps bounds admitted work; later transitions retain their full reservation.
type Caps struct {
	LivePerPrincipal int
	LiveTotal        int
	FullRecords      int
	RecordsTotal     int
	PayloadBytes     int64
}

func (c *Caps) defaults() error {
	for _, limit := range []struct {
		value    *int
		fallback int
	}{
		{&c.LivePerPrincipal, ap.LocalLivePerPrincipal}, {&c.LiveTotal, ap.LocalLiveTotal},
		{&c.FullRecords, ap.LocalFullRecords}, {&c.RecordsTotal, ap.LocalRecordsTotal},
	} {
		if *limit.value < 0 {
			return errors.New("lifecycle: negative admission cap")
		}
		if *limit.value == 0 {
			*limit.value = limit.fallback
		}
	}
	if c.PayloadBytes < 0 {
		return errors.New("lifecycle: negative payload budget")
	}
	if c.PayloadBytes == 0 {
		c.PayloadBytes = ap.LocalPayloadBudget
	}
	return nil
}

func (e *Engine) liveFull(principal string) bool {
	c := e.config.Caps
	return e.projections.total.live >= c.LiveTotal || e.projections.principals[principal].live >= c.LivePerPrincipal
}

func (e *Engine) admitLocked(candidate ap.R1, now ap.Now) error {
	principal := candidate.Header.Principal
	if e.liveFull(principal) {
		// X5: the tick may not yet have committed a just-ended window.
		for _, key := range e.dueKeys(now) {
			rec, err := e.load(key)
			if err != nil {
				return err
			}
			if rec == nil {
				return keyError()
			}
			after, answer, err := e.commitLocked(key, rec, ap.Tick{}, now, ap.Inputs{})
			if err != nil {
				return err
			}
			if err := answerError(answer); err != nil {
				return err
			}
			e.projections.schedule(key, after, now, e.epoch, e.config.Settings)
		}
	}
	if e.liveFull(principal) {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	reservation := int64(ap.R1Reservation(candidate))
	caps := e.config.Caps
	payloadFull := func() bool {
		return e.projections.total.full >= caps.FullRecords || reservation > caps.PayloadBytes-e.projections.total.reserved
	}
	countFull := func() bool { return e.projections.total.records >= caps.RecordsTotal }
	if !payloadFull() && !countFull() {
		return nil
	}
	// Ages and pressure order use the committed decision, never creation time.
	type decidedRecord struct {
		key string
		at  time.Time
	}
	var candidates []decidedRecord
	for key := range e.projections.records {
		rec, err := e.load(key)
		if err != nil {
			return err
		}
		if rec == nil {
			return keyError()
		}
		if rec.Header.Decision != nil {
			candidates = append(candidates, decidedRecord{key, rec.Header.Decision.DecidedAt})
		}
	}
	slices.SortFunc(candidates, func(a, b decidedRecord) int {
		if order := a.at.Compare(b.at); order != 0 {
			return order
		}
		return strings.Compare(a.key, b.key)
	})
	for _, candidate := range candidates {
		if !payloadFull() && !countFull() {
			return nil
		}
		rec, err := e.load(candidate.key)
		if err != nil {
			return err
		}
		if rec == nil {
			return keyError()
		}
		if payloadFull() {
			after, answer, err := e.commitLocked(candidate.key, rec, ap.ShedRecord{Pressure: true}, now, ap.Inputs{})
			if err != nil {
				return err
			}
			if err := answerError(answer); err != nil {
				return err
			}
			rec = &after
		}
		if countFull() {
			_, answer, err := e.commitLocked(candidate.key, rec, ap.Delete{Pressure: true}, now, ap.Inputs{})
			if err != nil {
				return err
			}
			if err := answerError(answer); err != nil {
				return err
			}
		}
	}
	if payloadFull() || countFull() {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	return nil
}

// Shed and Delete are owner-scoped reclamation commands. The pure transition
// enforces audit, liveness and replay protection even under pressure.
func (e *Engine) Shed(principal, requestID string, pressure bool) (ap.Answer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reclaimLocked(ap.RecordKey(principal, requestID), ap.ShedRecord{Pressure: pressure})
}

func (e *Engine) Delete(principal, requestID string, pressure bool) (ap.Answer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reclaimLocked(ap.RecordKey(principal, requestID), ap.Delete{Pressure: pressure})
}

func (e *Engine) reclaimLocked(key string, cmd ap.Command) (ap.Answer, error) {
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	rec, err := e.load(key)
	if err != nil {
		return ap.Answer{}, err
	}
	if rec == nil {
		return ap.Answer{}, &ap.CodeError{Code: ap.CodeNotFound}
	}
	now := e.now()
	e.projections.expireGrants(now)
	_, answer, err := e.commitLocked(key, rec, cmd, now, ap.Inputs{})
	if err != nil {
		return ap.Answer{}, err
	}
	return answer, answerError(answer)
}
