package approvalplan

// Policy is what Decide needs: the quorum N, the two flags, and the
// requester whose own vote the self-approval flag governs. Build it with
// EffectivePolicy, never from a caller's values.
type Policy struct {
	RequiredApprovals int
	DenyVeto          bool
	AllowSelfApprove  bool
	Requester         string
}

// VoteFlags are the only policy values a Vote's caller supplies: the
// server's configured deny-veto and self-approval flags (SA-4 Vote).
type VoteFlags struct {
	DenyVeto         bool
	AllowSelfApprove bool
}

// LocalVoteFlags is the local signer's fixed policy: veto on, self-approval
// off (E6). With N = 1 every eligible vote decides.
var LocalVoteFlags = VoteFlags{DenyVeto: true}

// EffectivePolicy builds the vote policy inside the Vote's own commit (SA-4,
// r5.4): N is the record's frozen required_approvals and the requester is the
// record key's authenticated principal (the hosted client_id or the local
// local-uid). sub_principal never enters it.
func EffectivePolicy(rec R1, flags VoteFlags) Policy {
	return Policy{
		RequiredApprovals: rec.Header.RequiredApprovals,
		DenyVeto:          flags.DenyVeto,
		AllowSelfApprove:  flags.AllowSelfApprove,
		Requester:         rec.Header.Principal,
	}
}

// Decide is a stdlib port of the hosted Decide (pkg/signerkit/hosted/
// approval.go): one vote per operator, first occurrence wins; the
// requester's own vote is dropped unless self-approval is allowed; an
// eligible deny under veto denies (a veto wins a tie); otherwise N distinct
// eligible approvers approve. N ≤ 0 is treated as 1.
func Decide(p Policy, votes []Vote) ApprovalStatus {
	approvers, deny := tally(p, votes)
	if p.DenyVeto && deny {
		return ApprovalDenied
	}
	if len(approvers) >= max(p.RequiredApprovals, 1) {
		return ApprovalApproved
	}
	return ApprovalPending
}

// ApprovingOperators lists the distinct operators whose eligible vote is an
// approve, in first-vote order. Approval attribution uses the first quorum.
func ApprovingOperators(p Policy, votes []Vote) []string {
	approvers, _ := tally(p, votes)
	return approvers
}

func tally(p Policy, votes []Vote) (approvers []string, eligibleDeny bool) {
	seen := make(map[string]bool, len(votes))
	for _, v := range votes {
		if seen[v.Operator] {
			continue
		}
		seen[v.Operator] = true
		if !p.AllowSelfApprove && p.Requester != "" && v.Operator == p.Requester {
			continue
		}
		switch v.Decision {
		case VoteApprove:
			approvers = append(approvers, v.Operator)
		case VoteDeny:
			eligibleDeny = true
		}
	}
	return approvers, eligibleDeny
}

// VoteRoom is SA-3's room rule for a vote not yet in the set: a vote that
// decides or counts is always accepted; any other vote only while, after it,
// |votes| + need + 1 ≤ VoteCap(rec), where need is the approvals still
// missing under the effective policy. So the set always has room for every
// vote that can still change the outcome, whatever the flags become.
func VoteRoom(rec R1, flags VoteFlags, v Vote) bool {
	p := EffectivePolicy(rec, flags)
	votes := rec.Header.Votes
	after := append(votes[:len(votes):len(votes)], v)
	before := len(ApprovingOperators(p, votes))
	if Decide(p, after) != ApprovalPending || len(ApprovingOperators(p, after)) > before {
		return true
	}
	need := max(p.RequiredApprovals, 1) - before
	return len(after)+need+1 <= VoteCap(rec)
}
