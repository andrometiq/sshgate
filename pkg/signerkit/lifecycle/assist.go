package lifecycle

import (
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// startAssistLocked is called only after a new Submit's confirmed commit.
// The engine owns the pool and cancels it at Close.
func (e *Engine) startAssistLocked(key string, rec ap.R1) (ap.R1, error) {
	if e.config.AssistPool == nil || rec.Header.Assist != nil || rec.Payload == nil {
		return rec, nil
	}
	input, inputErr := e.config.AssistInputBuilder.BuildAssistInput(rec.Payload.Plan)
	assessor := e.config.Assessor
	if inputErr != nil {
		assessor = nil
		input = assist.Input{}
	}
	result := e.config.AssistPool.TrySubmit(e.effectContext, assessor, input, rec.Header.AssistDeadline, func(snapshot assist.Snapshot) {
		if inputErr != nil && snapshot.Reason == assist.ReasonFailed {
			snapshot.Reason = assist.ReasonRedaction
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.availabilityLocked() != nil {
			return
		}
		if _, err := e.finishAssistLocked(key, snapshot); err != nil {
			// Storage errors belong to the owner, never to the advisory result.
			select {
			case e.effectErrors <- err:
			default:
			}
		}
	})
	if result == assist.Full {
		return e.finishAssistLocked(key, assist.Snapshot{Reason: assist.ReasonBusy})
	}
	return rec, nil
}

func (e *Engine) finishAssistLocked(key string, snapshot assist.Snapshot) (ap.R1, error) {
	rec, err := e.load(key)
	if err != nil {
		return ap.R1{}, err
	}
	if rec == nil {
		return ap.R1{}, nil
	}
	after, answer, err := e.commitLocked(key, rec, ap.AssistDone{Result: snapshot.Result, Unavailable: snapshot.Reason}, e.now(), ap.Inputs{})
	if err != nil {
		return ap.R1{}, err
	}
	return after, answerError(answer)
}
