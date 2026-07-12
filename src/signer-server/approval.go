package signerserver

import "github.com/karthikeyan5/sshgate/pkg/signerkit/store"

// approval.go is the approval state machine: a PURE mechanism that maps
// (required_approvals N, the vote set, policy flags) to a decision. It
// owns NO product policy — it does not decide what N should be, whether
// self-approval is allowed, or whether a single deny vetoes. Those are
// inputs (ApprovalPolicy), supplied by the caller per server config, and
// the mechanism must produce a correct result for EVERY combination.
//
// There is no HTTP, no auth, and no I/O here. The wiring that reads the
// store, calls this function, and (on a threshold-crossing approve)
// drives the Signer + UpdateStatus lives in approval_engine.go. Keeping
// the mechanism pure makes it exhaustively unit-testable and means the
// concurrency guard (UpdateStatus's WHERE status='pending') is the ONLY
// place that needs to be race-safe.

// ApprovalDecision is the computed state of a request given its votes.
// It is distinct from store.Status (the persisted column): the state
// machine speaks pending/approved/denied; the store additionally has
// timeout/error states that are set by other code paths.
type ApprovalDecision string

const (
	// DecisionPending: the threshold is not yet met and no veto fired.
	DecisionPending ApprovalDecision = "pending"
	// DecisionApproved: enough distinct, eligible operators approved.
	DecisionApproved ApprovalDecision = "approved"
	// DecisionDenied: the deny rule fired (deny_veto on and >=1 deny).
	DecisionDenied ApprovalDecision = "denied"
)

// ApprovalPolicy carries the per-server policy FLAGS the mechanism needs.
// None of these have defaults baked into the mechanism: the caller (the
// product/config layer) supplies them, and Decide handles every variant.
type ApprovalPolicy struct {
	// RequiredApprovals is N: the number of DISTINCT approving operators
	// required to reach DecisionApproved. N <= 0 is treated as 1 by
	// Decide (a request always needs at least one approval to be
	// approvable); this is a safety floor, not a policy default — a
	// zero N would mean "auto-approve with no votes", which the
	// mechanism refuses to express.
	RequiredApprovals int

	// DenyVeto models the deny rule as a single clear flag. When true, a
	// single eligible deny vote drives the request to DecisionDenied
	// (one operator can veto). When false, deny votes are recorded but
	// do not by themselves deny the request — it can still reach
	// DecisionApproved if enough approvals accrue.
	DenyVeto bool

	// AllowSelfApprove governs whether the requester's OWN vote counts.
	// When false, the requester's vote (matched by Requester) is ignored
	// for BOTH the approve tally and the deny rule — a requester can
	// neither approve nor veto their own request. When true, the
	// requester is treated like any other operator.
	AllowSelfApprove bool

	// Requester is the identity of the operator who submitted the
	// request. It is compared against each vote's operator to apply
	// AllowSelfApprove. Empty means "no requester identity supplied", in
	// which case no vote is ever treated as a self-vote.
	Requester string
}

// Decide computes the decision for a request from its policy and the
// full vote set. It is pure and deterministic: same inputs -> same
// output, no clock, no randomness, no I/O.
//
// Algorithm:
//
//  1. Collapse votes to one-per-operator. The store already enforces
//     one row per (request_id, operator), but Decide does not trust its
//     input: if the same operator appears twice, the FIRST occurrence
//     wins (votes are immutable and append-only, so the earliest is the
//     real one; ListVotes returns oldest-first).
//  2. Drop the requester's self-vote entirely when AllowSelfApprove is
//     false — it counts for neither approve nor deny.
//  3. Apply the deny rule: if DenyVeto and at least one eligible deny
//     remains, the decision is DecisionDenied. Deny is evaluated BEFORE
//     approve so a veto wins a tie (a request that simultaneously has
//     enough approvals AND an eligible veto is DENIED — the safe
//     direction).
//  4. Otherwise, if the count of DISTINCT eligible APPROVE operators is
//     >= N, the decision is DecisionApproved.
//  5. Otherwise DecisionPending.
//
// "A vote after a terminal decision is a no-op" is a property of this
// function by construction: Decide is a pure fold over the whole vote
// set, so it always returns the same terminal decision once the
// terminal condition is met, regardless of additional votes appended
// afterward. The engine layer enforces the once-only side effects.
func Decide(policy ApprovalPolicy, votes []store.Vote) ApprovalDecision {
	n := policy.RequiredApprovals
	if n <= 0 {
		n = 1
	}

	// Collapse to one decision per operator, first-occurrence-wins.
	seen := make(map[string]store.Decision, len(votes))
	for _, v := range votes {
		if _, dup := seen[v.Operator]; dup {
			continue
		}
		seen[v.Operator] = v.Decision
	}

	approvers := 0
	hasEligibleDeny := false
	for operator, decision := range seen {
		// Skip the requester's own vote unless self-approval is allowed.
		if !policy.AllowSelfApprove && policy.Requester != "" && operator == policy.Requester {
			continue
		}
		switch decision {
		case store.DecisionApprove:
			approvers++
		case store.DecisionDeny:
			hasEligibleDeny = true
		}
	}

	// Deny rule first: a veto wins ties, the safe direction.
	if policy.DenyVeto && hasEligibleDeny {
		return DecisionDenied
	}
	if approvers >= n {
		return DecisionApproved
	}
	return DecisionPending
}

// ApprovingOperators returns the sorted-by-first-vote list of distinct
// operators whose eligible vote was an approve, under the given policy.
// The engine uses it to populate the approved_by audit field; exposing
// it here keeps the "who counted" logic next to the "what was decided"
// logic so the two cannot drift. The order is the order operators first
// appear in votes (oldest-first when votes come from ListVotes).
func ApprovingOperators(policy ApprovalPolicy, votes []store.Vote) []string {
	seen := make(map[string]store.Decision, len(votes))
	order := make([]string, 0, len(votes))
	for _, v := range votes {
		if _, dup := seen[v.Operator]; dup {
			continue
		}
		seen[v.Operator] = v.Decision
		order = append(order, v.Operator)
	}
	out := make([]string, 0, len(order))
	for _, operator := range order {
		if !policy.AllowSelfApprove && policy.Requester != "" && operator == policy.Requester {
			continue
		}
		if seen[operator] == store.DecisionApprove {
			out = append(out, operator)
		}
	}
	return out
}
