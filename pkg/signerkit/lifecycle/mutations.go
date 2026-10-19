package lifecycle

import (
	"context"
	"errors"
	"slices"
	"strings"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Vote accepts an authenticated local operator's card tap. The adapter checks
// the operator identity; local policy flags are authoritative here.
func (e *Engine) Vote(vote ap.CastVote) (ap.Answer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	if vote.Card == nil || vote.Hosted != nil {
		return ap.Answer{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	key, err := e.projections.cards.resolve(vote.Card.Handle)
	if err != nil {
		return ap.Answer{}, err
	}
	vote.Flags = ap.LocalVoteFlags
	return e.mutateLocked(key, vote)
}

// AdminCancel accepts an authenticated admin's snapshot-bound cancellation.
// The handle identifies a record across principals without a bare request ID.
func (e *Engine) AdminCancel(handle string, cancel ap.AdminCancel) (ap.Answer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	key, err := e.projections.handles.resolve(handle)
	if err != nil {
		return ap.Answer{}, err
	}
	return e.mutateLocked(key, cancel)
}

// Report acknowledges a final report only after its commit is confirmed.
func (e *Engine) Report(principal, requestID string, report ap.Report) (ap.Answer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mutateLocked(ap.RecordKey(principal, requestID), report)
}

func (e *Engine) mutateLocked(key string, command ap.Command) (ap.Answer, error) {
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	before, err := e.load(key)
	if err != nil {
		return ap.Answer{}, err
	}
	_, answer, err := e.commitLocked(key, before, command, e.now(), ap.Inputs{})
	if err != nil {
		return ap.Answer{}, err
	}
	return answer, answerError(answer)
}

// Revoke is alias-global de-escalation. Each live grant is a separate commit;
// retrying after a store failure safely finishes any remaining grants.
// The answer never discloses which principals held a grant.
func (e *Engine) Revoke(alias string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.availabilityLocked(); err != nil {
		return err
	}
	keys := make([]string, 0, len(e.projections.grants))
	for key := range e.projections.grants {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		before, err := e.load(key)
		if err != nil {
			return err
		}
		if before == nil {
			return keyError()
		}
		if before.Header.GrantAlias != alias {
			continue
		}
		_, answer, err := e.commitLocked(key, before, ap.Revoke{}, e.now(), ap.Inputs{})
		if err != nil {
			return err
		}
		if err := answerError(answer); err != nil {
			return err
		}
	}
	return nil
}

// StaleEnrollmentError carries the digests observed at the custody boundary.
// An unavailable enrollment has an empty digest; later reads must not replace this evidence.
type StaleEnrollmentError struct {
	Digests ap.XferDigests
}

func (*StaleEnrollmentError) Error() string { return ap.MintReasonStaleTransferKey }

// Claim is the only operation returning signatures. Every impure input and the
// mint itself are resolved under the single writer lock, after Apply's guards.
func (e *Engine) Claim(ctx context.Context, principal, requestID string, claim ap.Claim) (ap.Answer, error) {
	e.mu.Lock()
	key := ap.RecordKey(principal, requestID)
	answer, err := e.claimLocked(ctx, principal, key, claim)
	if err != nil || answer.Claim != ap.ClaimNotReady {
		e.mu.Unlock()
		return answer, err
	}
	rec, err := e.load(key)
	if err != nil || rec == nil || rec.Header.Decision == nil {
		e.mu.Unlock()
		return answer, err
	}
	waiter := e.flushWaiters[key]
	if waiter == nil {
		waiter = &flushWaiter{ready: make(chan struct{})}
		e.flushWaiters[key] = waiter
	}
	e.waitJoined.Add(1)
	defer e.waitJoined.Done()
	waiter.users++
	e.mu.Unlock()
	timer := newClaimFlushTimer()
	defer timer.Stop()
	select {
	case <-e.effectContext.Done():
	case <-ctx.Done():
	case <-waiter.ready:
	case <-timer.C:
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	waiter.users--
	if waiter.users == 0 && e.flushWaiters[key] == waiter {
		delete(e.flushWaiters, key)
	}
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	if err := ctx.Err(); err != nil {
		return ap.Answer{}, err
	}
	return e.claimLocked(ctx, principal, key, claim)
}

func (e *Engine) claimLocked(ctx context.Context, principal, key string, claim ap.Claim) (ap.Answer, error) {
	if err := e.availabilityLocked(); err != nil {
		return ap.Answer{}, err
	}
	before, err := e.load(key)
	if err != nil {
		return ap.Answer{}, err
	}
	now := e.now()
	in := ap.Inputs{}
	_, answer, err := e.commitLocked(key, before, claim, now, in)
	if err != nil {
		return ap.Answer{}, err
	}
	if !answer.MintRequired {
		return answer, answerError(answer)
	}

	// Resolve the deciding grant, never a different grant that now covers the plan.
	if id, ok := strings.CutPrefix(before.Header.Decision.DecidedBy, ap.GrantDecidedPrefix); ok {
		e.expireGrantsLocked(now)
		grantKey := ap.RecordKey(principal, id)
		grant, err := e.load(grantKey)
		if err != nil {
			return ap.Answer{}, err
		}
		in.Grant = &ap.GrantRef{}
		if grant != nil {
			in.Grant.Record = *grant
			in.Grant.Live = e.projections.grants[grantKey] != nil
		}
	}
	if transfer := before.Payload.Plan.Transfer; transfer != nil {
		if e.config.XferDigests == nil {
			return ap.Answer{}, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
		}
		digests, err := e.config.XferDigests.Current(ctx, *transfer)
		if err != nil {
			return ap.Answer{}, err
		}
		in.XferDigests = &digests
	}
	// Re-evaluate resolved authorization before calling the signer.
	_, answer, err = e.commitLocked(key, before, claim, now, in)
	if err != nil {
		return ap.Answer{}, err
	}
	if !answer.MintRequired {
		return answer, answerError(answer)
	}
	if e.config.Minter == nil {
		return ap.Answer{}, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
	}
	in.Minted, err = e.config.Minter.Mint(ctx, before.Payload.Plan, before.Header.Decision.DecidedAt)
	in.MintFailed = err != nil
	var stale *StaleEnrollmentError
	if errors.As(err, &stale) && before.Payload.Plan.Transfer != nil {
		in.XferDigests = &stale.Digests
	}
	if in.Minted == nil && !in.MintFailed {
		in.Minted = []string{}
	}
	_, answer, err = e.commitLocked(key, before, claim, now, in)
	if err != nil {
		return ap.Answer{}, err
	}
	return answer, answerError(answer)
}
