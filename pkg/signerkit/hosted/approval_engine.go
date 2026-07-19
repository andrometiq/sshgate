package hosted

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// approval_engine.go is the impure half of Phase C: it reads the store,
// records a vote, recomputes the PURE Decide() over the full vote set,
// and — when the vote crosses a terminal threshold — performs the
// side effects:
//
//   - a threshold-crossing APPROVE mints signatures via the Phase-A
//     Signer (stamped at approval time) and flips the row to approved
//     with UpdateStatus(approved, signatures, approvers);
//   - a deny meeting the deny rule flips the row to denied via
//     UpdateStatus(denied).
//
// Concurrency guard: UpdateStatus updates only WHERE status='pending'
// (its existing idempotency hook). Two operators casting the final
// approve near-simultaneously both observe threshold-met and both call
// UpdateStatus; exactly ONE UPDATE matches the pending row and wins, the
// other is a no-op. We mint signatures BEFORE the flip on each path, but
// only the winner's signatures are persisted (the loser's flip affects
// zero rows), so the request ends with exactly one set of signatures and
// the daemon polls back a single coherent approval.

// ErrAlreadyResolved is returned by SubmitVote when the request is no
// longer pending (a vote after a terminal decision). The vote is NOT
// recorded and no side effect runs — the spec's "a vote after a
// terminal decision is a no-op", surfaced to the caller as a typed
// error so the HTTP layer can answer 409/200 as it sees fit.
var ErrAlreadyResolved = errors.New("hosted: request already resolved")

// ErrRequestNotFound is the hosted API's public missing-request sentinel.
// Store implementation sentinels stay behind the persistence seam (C12).
var ErrRequestNotFound = errors.New("hosted: request not found")

// VoteOutcome is what SubmitVote returns: the recomputed decision after
// the vote, plus whether THIS call was the one that performed the
// terminal side effect (minted signatures / flipped the row). Exactly
// one concurrent caller gets Flipped=true on the threshold-crossing
// vote; the rest see the same terminal Decision with Flipped=false.
type VoteOutcome struct {
	Decision ApprovalDecision
	Flipped  bool
}

// HostedCore is the shared signerkit core the hosted approval engine depends
// on. It replaces the branch's own signerserver.Signer (deleted in the phase-5
// one-codebase port): sign-at-approval now routes through the SAME custody
// choke point as the local socket path (SignApproved → signBytes), so Lock,
// RotateTo, and the crypto.Signer seam govern hosted signing for free; and the
// human's decision is recorded on the required audit sink (Verdict), fail-
// closed. *signerkit.Service satisfies this interface.
type HostedCore interface {
	// SignApproved mints gate-valid envelopes for an approved request at
	// approval time, routed through the custody choke point.
	SignApproved(cmds []signerkit.HostedSignCommand, approvedAt time.Time) ([]signerkit.HostedSignResult, error)
	// Verdict records a single operator's resolution on the required audit
	// sink. Emitted BEFORE any state flip; a sink error aborts the vote
	// (C5 hosted fail-closed).
	Verdict(ctx context.Context, e signerkit.AuditVerdict) error
}

// ApprovalEngine ties the pure state machine to the store and the shared
// signerkit core. It holds no mutable state of its own; all state lives in the
// store, and the only synchronisation is the store's pending-guarded
// UpdateStatus. Safe for concurrent use.
type ApprovalEngine struct {
	Store store.Store
	Core  HostedCore
}

// NewApprovalEngine constructs an engine. Both dependencies are required: an
// engine without a Store cannot read votes, and one without the signerkit core
// can neither mint on approval nor record the verdict. It refuses a nil
// dependency so the misconfiguration fails at construction, not at the first
// vote.
func NewApprovalEngine(st store.Store, core HostedCore) (*ApprovalEngine, error) {
	if st == nil {
		return nil, errors.New("hosted: NewApprovalEngine: nil Store")
	}
	if core == nil {
		return nil, errors.New("hosted: NewApprovalEngine: nil core")
	}
	return &ApprovalEngine{Store: st, Core: core}, nil
}

// SubmitVote records one operator's vote and advances the request's
// state machine. policy carries the per-server flags (DenyVeto,
// AllowSelfApprove, Requester) — the mechanism's inputs, never defaulted
// here. RequiredApprovals in policy is IGNORED in favour of the stored
// request's required_approvals column, so the threshold cannot be
// changed out from under a request mid-flight by passing a different N;
// the column is the source of truth (settable beforehand via
// SetRequiredApprovals).
//
// authnMethod is recorded on the vote for the audit trail (e.g.
// "webauthn", "totp"); it does not affect the decision.
//
// Flow:
//  1. Read the request. ErrNotFound -> store.ErrNotFound. Non-pending
//     -> ErrAlreadyResolved (vote is a no-op).
//  2. PrepareVote claims an immutable, initially-unaudited vote. An
//     opposite-decision duplicate is rejected without an audit write.
//  3. Audit the canonical stored vote, then MarkVoteAudited. ListVotes cannot
//     see a prepared vote before this completes, so audit failure is fail-closed.
//  3. ListVotes, Decide over the full set using the STORED N.
//  4. On DecisionApproved: mint signatures (approval time = now), then
//     UpdateStatus(approved, sigs, approvers). On DecisionDenied:
//     UpdateStatus(denied). The pending-guard makes the flip race-safe.
func (e *ApprovalEngine) SubmitVote(
	ctx context.Context,
	requestID string,
	operator string,
	decision store.Decision,
	authnMethod string,
	policy ApprovalPolicy,
) (VoteOutcome, error) {
	if requestID == "" {
		return VoteOutcome{}, errors.New("hosted: SubmitVote: empty request_id")
	}
	if operator == "" {
		return VoteOutcome{}, errors.New("hosted: SubmitVote: empty operator")
	}
	if !decision.IsValid() {
		return VoteOutcome{}, fmt.Errorf("hosted: SubmitVote: invalid decision %q", decision)
	}

	req, err := e.Store.GetByID(ctx, requestID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return VoteOutcome{}, ErrRequestNotFound
		}
		return VoteOutcome{}, fmt.Errorf("load request: %w", err)
	}
	if req.Status != store.StatusPending {
		// Vote after a terminal decision: no-op. Do not record.
		return VoteOutcome{}, ErrAlreadyResolved
	}

	// Claim the immutable vote before touching the external audit sink. The
	// store persists it as unaudited and hides it from ListVotes until the
	// audit succeeds. This two-phase protocol closes both bad orderings:
	// audit-first could record a losing opposite-decision race, while
	// vote-first previously let a sink failure leave a countable unaudited row.
	prepared, needsAudit, err := e.Store.PrepareVote(ctx, &store.Vote{
		RequestID:   requestID,
		Operator:    operator,
		Decision:    decision,
		AuthnMethod: authnMethod,
		TS:          time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, store.ErrRequestResolved) {
			return VoteOutcome{}, ErrAlreadyResolved
		}
		if errors.Is(err, store.ErrNotFound) {
			return VoteOutcome{}, ErrRequestNotFound
		}
		return VoteOutcome{}, fmt.Errorf("prepare vote: %w", err)
	}

	if needsAudit {
		// Always audit the canonical stored decision/authentication metadata,
		// never the retry's input. Thus even concurrent opposite-decision calls
		// can produce at most the winner's decision in the audit stream.
		if err := e.Core.Verdict(ctx, signerkit.AuditVerdict{
			Time:      prepared.TS,
			RequestID: requestID,
			Operator: signerkit.Operator{
				ID:          prepared.Operator,
				DisplayName: prepared.Operator,
				Verified:    true,
				AuthnMethod: prepared.AuthnMethod,
			},
			CommandSHA256: commandsSHA256(req.Commands),
			Approved:      prepared.Decision == store.DecisionApprove,
		}); err != nil {
			return VoteOutcome{}, fmt.Errorf("audit verdict (fail-closed): %w", err)
		}
		if err := e.Store.MarkVoteAudited(ctx, requestID, operator); err != nil {
			return VoteOutcome{}, fmt.Errorf("mark vote audited: %w", err)
		}
	}

	// Recompute the decision over the FULL vote set, using the request's
	// stored N (not whatever was passed in policy).
	effPolicy := policy
	effPolicy.RequiredApprovals = req.RequiredApprovals
	// The machine-plane bearer identity stored with the request is the only
	// authoritative requester. Never trust a caller-supplied policy.Requester:
	// doing so lets route wiring accidentally disable the self-approval ban.
	effPolicy.Requester = req.ClientID

	voteRows, err := e.Store.ListVotes(ctx, requestID)
	if err != nil {
		return VoteOutcome{}, fmt.Errorf("list votes: %w", err)
	}
	votes := derefVotes(voteRows)

	switch Decide(effPolicy, votes) {
	case DecisionApproved:
		flipped, err := e.approve(ctx, req, effPolicy, votes)
		if err != nil {
			return VoteOutcome{}, err
		}
		return e.persistedOutcome(ctx, requestID, DecisionApproved, flipped)

	case DecisionDenied:
		flipped, err := e.deny(ctx, requestID)
		if err != nil {
			return VoteOutcome{}, err
		}
		return e.persistedOutcome(ctx, requestID, DecisionDenied, flipped)

	default:
		return VoteOutcome{Decision: DecisionPending, Flipped: false}, nil
	}
}

// persistedOutcome prevents a losing approve-vs-deny racer from reporting a
// decision that contradicts the immutable stored terminal state.
func (e *ApprovalEngine) persistedOutcome(ctx context.Context, requestID string, attempted ApprovalDecision, flipped bool) (VoteOutcome, error) {
	if flipped {
		return VoteOutcome{Decision: attempted, Flipped: true}, nil
	}
	got, err := e.Store.GetByID(ctx, requestID)
	if err != nil {
		return VoteOutcome{}, err
	}
	switch got.Status {
	case store.StatusApproved:
		return VoteOutcome{Decision: DecisionApproved, Flipped: false}, nil
	case store.StatusDenied:
		return VoteOutcome{Decision: DecisionDenied, Flipped: false}, nil
	default:
		return VoteOutcome{Decision: DecisionPending, Flipped: false}, nil
	}
}

// approve mints signatures and flips the row. It returns flipped=true
// only if THIS call's UpdateStatus matched the pending row (i.e. this
// caller won the race). Minting before the flip is intentional and
// safe: a losing flip affects zero rows, so the loser's freshly-minted
// (but unstored) signatures are simply discarded.
func (e *ApprovalEngine) approve(ctx context.Context, req *store.Request, policy ApprovalPolicy, votes []store.Vote) (bool, error) {
	cmds, err := commandsForSigning(req.Commands)
	if err != nil {
		return false, err
	}

	approvedAt := time.Now().UTC()
	results, err := e.Core.SignApproved(cmds, approvedAt)
	if err != nil {
		return false, fmt.Errorf("sign on approval: %w", err)
	}
	sigBlob, err := json.Marshal(results)
	if err != nil {
		return false, fmt.Errorf("marshal signatures: %w", err)
	}

	approvers := ApprovingOperators(policy, votes)
	approvedBy := strings.Join(approvers, ",")

	flipped, err := e.flip(ctx, req.RequestID, store.StatusApproved, sigBlob, approvedBy)
	if err != nil {
		return false, fmt.Errorf("flip to approved: %w", err)
	}
	return flipped, nil
}

// deny flips the row to denied (no signatures). Returns flipped=true if
// this call won the pending-guard race.
func (e *ApprovalEngine) deny(ctx context.Context, requestID string) (bool, error) {
	flipped, err := e.flip(ctx, requestID, store.StatusDenied, nil, "")
	if err != nil {
		return false, fmt.Errorf("flip to denied: %w", err)
	}
	return flipped, nil
}

// flip wraps UpdateStatus + a read-back to determine whether THIS call
// was the one that moved the row out of pending. UpdateStatus is
// idempotent (only fires WHERE status='pending') and does not surface
// rows-affected, so we re-read and compare: if the row now holds the
// status we wrote AND the approver/signature payload is ours, we treat
// this caller as the winner. For correctness of the side-effect-once
// guarantee, all we strictly need is that AT MOST ONE caller observes
// flipped=true for a given terminal transition; the read-back gives us
// that because only the winning UPDATE's payload lands in the row.
func (e *ApprovalEngine) flip(ctx context.Context, requestID string, status store.Status, sigs []byte, approvedBy string) (bool, error) {
	if err := e.Store.UpdateStatus(ctx, requestID, status, sigs, approvedBy); err != nil {
		return false, err
	}
	// Determine winner by re-reading. The first UPDATE to match the
	// pending row wins; later ones affect zero rows. We can't read
	// rows-affected through the Store interface, so we infer the winner
	// from whether the persisted payload matches what we wrote. This is
	// best-effort signalling for callers/tests; the SAFETY guarantee
	// (exactly one set of signatures persisted) is provided by the
	// pending-guard itself, independent of this read-back.
	got, err := e.Store.GetByID(ctx, requestID)
	if err != nil {
		return false, err
	}
	if got.Status != status {
		// Someone else flipped it to a DIFFERENT terminal status (e.g.
		// a deny raced an approve). We are not the winner.
		return false, nil
	}
	switch status {
	case store.StatusApproved:
		return string(got.Signatures) == string(sigs) && got.ApprovedBy == approvedBy, nil
	default:
		// For denied (and any non-signature terminal), the winner is
		// whoever's transition landed; since the payload is empty we
		// cannot distinguish duplicate deny callers by payload, so we
		// report flipped=true for the status-match. Concurrent identical
		// denies are harmless (idempotent), so over-reporting flipped
		// here is acceptable — there is no second side effect to guard.
		return true, nil
	}
}

// commandsForSigning decodes the stored commands blob (JSON
// []signRequestCmd) into the shared core's HostedSignCommand shape. The stored
// blob is exactly what handleSign persisted (validated, canonical JSON), so the
// cmd + ttl_seconds + host_key_fp fields are present.
func commandsForSigning(blob []byte) ([]signerkit.HostedSignCommand, error) {
	var stored []signRequestCmd
	if err := json.Unmarshal(blob, &stored); err != nil {
		return nil, fmt.Errorf("decode stored commands: %w", err)
	}
	if len(stored) == 0 {
		return nil, errors.New("hosted: stored request has no commands to sign")
	}
	out := make([]signerkit.HostedSignCommand, len(stored))
	for i, c := range stored {
		out[i] = signerkit.HostedSignCommand{Cmd: c.Cmd, TTLSeconds: c.TTLSeconds, HostKeyFP: c.HostKeyFP}
	}
	return out, nil
}

// commandsSHA256 returns the hex SHA-256 of the stored commands blob — a
// stable identifier for exactly what a vote resolves, recorded on the audit
// verdict in place of the raw command bytes.
func commandsSHA256(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// derefVotes flattens []*store.Vote (the store's return shape) to
// []store.Vote (the pure mechanism's input shape).
func derefVotes(rows []*store.Vote) []store.Vote {
	out := make([]store.Vote, 0, len(rows))
	for _, v := range rows {
		if v != nil {
			out = append(out, *v)
		}
	}
	return out
}
