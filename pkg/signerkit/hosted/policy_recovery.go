package hosted

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	policyRecoveryPageSize    = 64
	policyRecoveryMaxAttempts = 8
	policyRecoveryAttemptMax  = 30 * time.Second
	policyRecoveryBackoffBase = 250 * time.Millisecond
	policyRecoveryBackoffMax  = 30 * time.Second
	policyRosterSweepInterval = 30 * time.Second
)

type policyMintAttemptError struct{ cause error }

func (err *policyMintAttemptError) Error() string {
	return "policy materialization attempt: " + err.cause.Error()
}
func (err *policyMintAttemptError) Unwrap() error { return err.cause }

func sleepPolicyContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RosterSweep read-only enumerates the complete current-roster candidate set,
// then gives every candidate its own version-CAS transaction. An unaudited vote
// defers only its own row to the next sweep.
func (engine *PolicyEngine) RosterSweep(ctx context.Context) error {
	result, err := engine.store.ReconcilePendingAttainability(ctx, engine.authorityID, engine.now().UTC())
	if err != nil {
		return err
	}
	candidates := result.UnattainableCandidates
	if len(candidates) == 0 && len(result.Unattainable) != 0 {
		// Compatibility for store fakes written against the pre-R67 result shape.
		versions, listErr := engine.pendingVersions(ctx)
		if listErr != nil {
			return listErr
		}
		for _, key := range result.Unattainable {
			if version, ok := versions[key]; ok {
				candidates = append(candidates, policystore.AttainabilityCandidate{Key: key, StateVersion: version})
			}
		}
	}
	var sweepErr error
	for _, candidate := range candidates {
		_, err := engine.store.StageQuorumUnattainable(ctx, candidate.Key, candidate.StateVersion, engine.now().UTC())
		if err == nil || errors.Is(err, policystore.ErrStaleVersion) || errors.Is(err, policystore.ErrConflict) || errors.Is(err, policystore.ErrUnauditedVote) {
			continue
		}
		sweepErr = errors.Join(sweepErr, fmt.Errorf("roster stage %s/%s: %w", candidate.Key.Principal, candidate.Key.RequestID, err))
	}
	return sweepErr
}

func (engine *PolicyEngine) pendingVersions(ctx context.Context) (map[policystore.Key]uint64, error) {
	versions := make(map[policystore.Key]uint64)
	var cursor *policystore.PendingCursor
	for {
		page, err := engine.store.ListPending(ctx, engine.authorityID, cursor, policyRecoveryPageSize)
		if err != nil {
			return nil, err
		}
		for _, request := range page.Requests {
			versions[request.Key()] = request.StateVersion
		}
		if page.Next == nil {
			return versions, nil
		}
		cursor = page.Next
	}
}

// RecoverOnce makes one cursor-bounded pass over unaudited votes and external
// request work. It is intentionally not a snapshot and has no cadence promise.
func (engine *PolicyEngine) RecoverOnce(ctx context.Context) error {
	var passErr error
	if err := engine.recoverVotes(ctx); err != nil {
		passErr = errors.Join(passErr, err)
	}
	var cursor *policystore.RecoveryCursor
	for {
		page, err := engine.store.ListRecovery(ctx, engine.authorityID, engine.now().UTC(), cursor, policyRecoveryPageSize)
		if err != nil {
			return errors.Join(passErr, err)
		}
		for _, request := range page.Requests {
			if err := engine.recoverRequest(ctx, request); err != nil && !benignPolicyRecoveryError(err) {
				passErr = errors.Join(passErr, fmt.Errorf("recover %s/%s: %w", request.Principal, request.RequestID, err))
			}
		}
		if page.Next == nil {
			return passErr
		}
		cursor = page.Next
	}
}

func (engine *PolicyEngine) recoverRequest(ctx context.Context, listed *policystore.Request) error {
	lease, err := engine.store.AcquireRecoveryLease(ctx, listed.Key(), engine.workerID, engine.now().UTC(), policyRecoveryLeaseTTL)
	if err != nil {
		return err
	}
	request := cloneRecoveryLease(listed, lease)
	operations := engine.store.Fenced(lease)
	if request.State == policystore.StatePending {
		tally, tallyErr := engine.recoveryTally(ctx, request)
		if tallyErr != nil {
			return tallyErr
		}
		return engine.claimTally(ctx, request, tally, operations, true)
	}
	var lastErr error
	for attempt := 0; attempt < policyRecoveryMaxAttempts; attempt++ {
		attemptContext, cancel, err := engine.recoveryAttemptContext(ctx, lease)
		if err != nil {
			return err
		}
		lastErr = engine.advance(attemptContext, request, operations, true)
		cancel()
		if lastErr == nil || benignPolicyRecoveryError(lastErr) {
			return lastErr
		}
		if fresh, fetchErr := engine.store.GetByReviewID(ctx, listed.ReviewID); fetchErr == nil {
			request = fresh
		}
		if attempt+1 == policyRecoveryMaxAttempts {
			break
		}
		if err := engine.waitRecoveryBackoff(ctx, lease, attempt); err != nil {
			return err
		}
	}
	var mintErr *policyMintAttemptError
	if !errors.As(lastErr, &mintErr) {
		// Audit uncertainty and infrastructure failures retain the lease for
		// expiry/takeover; inventing a milestone would lose forensic work.
		return lastErr
	}
	fresh, err := engine.store.GetByReviewID(ctx, listed.ReviewID)
	if err != nil {
		return errors.Join(lastErr, err)
	}
	if fresh.State != policystore.StateApprovedMaterializing || !fresh.PreMintAudited {
		return lastErr
	}
	staged, err := operations.StageMaterializationError(ctx, requestWorkLease(fresh), policywire.ErrorPolicyMaterializationFailed, engine.now().UTC())
	if err != nil {
		return errors.Join(lastErr, err)
	}
	if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
		return err
	}
	if staged.RecoveryLeaseOwner != "" || staged.RecoveryLeaseUntil != 0 {
		return fmt.Errorf("%w: exhaustion staging retained recovery lease", policystore.ErrCorrupt)
	}
	return nil
}

func (engine *PolicyEngine) recoveryTally(ctx context.Context, request *policystore.Request) (policystore.TallyResult, error) {
	tally := policystore.TallyResult{Required: int(request.RequiredApprovals), Eligible: int(request.EligibleVoterCount.Value)}
	var cursor *policystore.VoteCursor
	for {
		page, err := engine.store.ListVotes(ctx, request.Key(), cursor, policyRecoveryPageSize)
		if err != nil {
			return policystore.TallyResult{}, err
		}
		for _, vote := range page.Votes {
			if !vote.Audited {
				tally.Unaudited++
				continue
			}
			if vote.Decision == policystore.DecisionApprove {
				tally.Approvals++
			} else if vote.Decision == policystore.DecisionDeny {
				tally.Denials++
			}
		}
		if page.Next == nil {
			break
		}
		cursor = page.Next
	}
	tally.ApprovalReached = tally.Approvals >= tally.Required
	tally.DenialReached = (request.DenyVeto && tally.Denials > 0) ||
		tally.Approvals+(tally.Eligible-tally.Approvals-tally.Denials-tally.Unaudited) < tally.Required
	return tally, nil
}

func cloneRecoveryLease(request *policystore.Request, lease policystore.Lease) *policystore.Request {
	copy := *request
	copy.RecoveryLeaseOwner = lease.Owner
	copy.RecoveryLeaseGeneration = lease.Generation
	copy.RecoveryLeaseUntil = lease.Until.Unix()
	return &copy
}

func (engine *PolicyEngine) recoverVotes(ctx context.Context) error {
	var cursor *policystore.RecoveryCursor
	var passErr error
	for {
		page, err := engine.store.ListUnauditedVotes(ctx, engine.authorityID, cursor, policyRecoveryPageSize)
		if err != nil {
			return errors.Join(passErr, err)
		}
		for index := 0; index < len(page.Votes); {
			key := page.Votes[index].Key()
			end := index + 1
			for end < len(page.Votes) && page.Votes[end].Key() == key {
				end++
			}
			if err := engine.recoverVoteGroup(ctx, key, page.Votes[index:end]); err != nil && !benignPolicyRecoveryError(err) {
				passErr = errors.Join(passErr, fmt.Errorf("recover votes %s/%s: %w", key.Principal, key.RequestID, err))
			}
			index = end
		}
		if page.Next == nil {
			return passErr
		}
		cursor = page.Next
	}
}

func (engine *PolicyEngine) recoverVoteGroup(ctx context.Context, key policystore.Key, listed []*policystore.Vote) error {
	request, err := engine.findPendingRequest(ctx, key)
	if err != nil {
		return err
	}
	lease, err := engine.store.AcquireRecoveryLease(ctx, key, engine.workerID, engine.now().UTC(), policyRecoveryLeaseTTL)
	if err != nil {
		return err
	}
	request = cloneRecoveryLease(request, lease)
	operations := engine.store.Fenced(lease)
	var lastErr error
	var tally policystore.TallyResult
	for attempt := 0; attempt < policyRecoveryMaxAttempts; attempt++ {
		attemptContext, cancel, err := engine.recoveryAttemptContext(ctx, lease)
		if err != nil {
			return err
		}
		lastErr = nil
		for _, vote := range listed {
			if vote.Audited {
				continue
			}
			if err := engine.emitVote(attemptContext, request, vote); err != nil {
				lastErr = err
				break
			}
			if err := engine.faultAfter(PolicyFaultAfterVoteAudit); err != nil {
				lastErr = err
				break
			}
			tally, err = operations.PublishVoteAudit(attemptContext, key, vote.Operator, vote.AuditStateVersion)
			if err != nil {
				lastErr = err
				break
			}
			vote.Audited = true
			if err := engine.faultAfter(PolicyFaultAfterVoteAcknowledged); err != nil {
				lastErr = err
				break
			}
		}
		cancel()
		if lastErr == nil {
			fresh, fetchErr := engine.store.GetByReviewID(ctx, request.ReviewID)
			if fetchErr != nil {
				return fetchErr
			}
			return engine.claimTally(ctx, fresh, tally, operations, true)
		}
		if attempt+1 == policyRecoveryMaxAttempts {
			return lastErr
		}
		if err := engine.waitRecoveryBackoff(ctx, lease, attempt); err != nil {
			return err
		}
	}
	return lastErr
}

func (engine *PolicyEngine) findPendingRequest(ctx context.Context, key policystore.Key) (*policystore.Request, error) {
	var cursor *policystore.PendingCursor
	for {
		page, err := engine.store.ListPending(ctx, engine.authorityID, cursor, policyRecoveryPageSize)
		if err != nil {
			return nil, err
		}
		for _, request := range page.Requests {
			if request.Key() == key {
				return request, nil
			}
		}
		if page.Next == nil {
			return nil, policystore.ErrNotFound
		}
		cursor = page.Next
	}
}

func (engine *PolicyEngine) recoveryAttemptContext(parent context.Context, lease policystore.Lease) (context.Context, context.CancelFunc, error) {
	remainder := lease.Until.Sub(engine.now().UTC())
	if remainder <= 0 {
		return nil, nil, policystore.ErrLeaseLost
	}
	budget := min(remainder, policyRecoveryAttemptMax)
	context, cancel := context.WithTimeout(parent, budget)
	return context, cancel, nil
}

func (engine *PolicyEngine) waitRecoveryBackoff(ctx context.Context, lease policystore.Lease, attempt int) error {
	delay := policyRecoveryBackoffBase << attempt
	if delay > policyRecoveryBackoffMax {
		delay = policyRecoveryBackoffMax
	}
	delay = engine.jitter(delay)
	if delay < 0 {
		delay = 0
	}
	remainder := lease.Until.Sub(engine.now().UTC())
	if remainder <= 0 {
		return policystore.ErrLeaseLost
	}
	if delay > remainder {
		delay = remainder
	}
	return engine.sleep(ctx, delay)
}

func benignPolicyRecoveryError(err error) bool {
	return errors.Is(err, policystore.ErrUnavailable) || errors.Is(err, policystore.ErrLeaseLost) ||
		errors.Is(err, policystore.ErrStaleVersion) || errors.Is(err, policystore.ErrConflict) ||
		errors.Is(err, policystore.ErrUnauditedVote) || errors.Is(err, policystore.ErrNotFound)
}
