package lifecycle

import (
	"errors"

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
	// Keep skipped candidates out of this pass, then restore them from the
	// confirmed projections. Apply remains the authority for eligibility,
	// including Clock, audit gates, live grants and the replay floor.
	var visited []string
	defer func() {
		for _, key := range visited {
			e.projections.indexReclamation(key)
		}
	}()
	for payloadFull() || countFull() {
		queue := &e.projections.shedCandidates
		if countFull() {
			queue = &e.projections.deleteCandidates
		}
		if queue.Len() == 0 {
			break
		}
		candidate := queue.candidates[0]
		visited = append(visited, candidate.key)
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
		e.projections.shedCandidates.remove(candidate.key)
		e.projections.deleteCandidates.remove(candidate.key)
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
	e.expireGrantsLocked(now)
	_, answer, err := e.commitLocked(key, rec, cmd, now, ap.Inputs{})
	if err != nil {
		return ap.Answer{}, err
	}
	return answer, answerError(answer)
}
