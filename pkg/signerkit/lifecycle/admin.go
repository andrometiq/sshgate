package lifecycle

import (
	"github.com/karthikeyan5/sshgate/internal/faultpoint"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// ResolveAdmin maps an operator's record handle, or a request_id that matches
// exactly one record, to that record's handle (E64 addressing). Operators are
// not principals, so the lookup spans every principal; it changes nothing.
func (e *Engine) ResolveAdmin(id string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.availabilityLocked(); err != nil {
		return "", err
	}
	key, err := e.resolveAdminLocked(id)
	if err != nil {
		return "", err
	}
	return ap.RecordHandle(key), nil
}

func (e *Engine) resolveAdminLocked(id string) (string, error) {
	switch {
	case ap.ValidRecordHandle(id):
		return e.projections.handles.resolve(id)
	case ap.ValidRequestID(id):
		return e.projections.requestIDs.resolve(id)
	}
	return "", &ap.CodeError{Code: ap.CodeInvalidRequest, Msg: "expected a record handle or request_id"}
}

// Renotify applies /renotify (SA-4 notify step 5) to one record handle. The
// commit, judged after Clock, is the durable resend authorization; the actor
// drives the new burst from the committed renotify_gen.
func (e *Engine) Renotify(handle string) (ap.Answer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	if !ap.ValidRecordHandle(handle) {
		return ap.Answer{}, &ap.CodeError{Code: ap.CodeInvalidRequest, Msg: "expected a record handle"}
	}
	key, err := e.projections.handles.resolve(handle)
	if err != nil {
		return ap.Answer{}, err
	}
	faultpoint.Exit("renotify.before-commit")
	answer, err := e.mutateLocked(key, ap.Renotify{})
	if err == nil && answer.Changed && answer.Reason == "" {
		// The actor cannot append the burst before this lock is released.
		faultpoint.Exit("renotify.after-commit")
	}
	return answer, err
}
