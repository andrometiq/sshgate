package signerserver_test

import (
	"testing"
	"time"

	signerserver "github.com/karthikeyan5/sshgate/src/signer-server"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// votes builds a vote slice from compact (operator, decision) pairs.
func votes(pairs ...[2]string) []store.Vote {
	out := make([]store.Vote, 0, len(pairs))
	base := time.Unix(1_700_000_000, 0).UTC()
	for i, p := range pairs {
		out = append(out, store.Vote{
			Operator: p[0],
			Decision: store.Decision(p[1]),
			TS:       base.Add(time.Duration(i) * time.Second),
		})
	}
	return out
}

func ap(op string) [2]string { return [2]string{op, "approve"} }
func dn(op string) [2]string { return [2]string{op, "deny"} }

// TestDecide_Matrix exhaustively exercises the pure state machine across
// N, deny_veto, self_approve, and duplicate/requester variants. Each row
// is independent of any store, signer, or HTTP — this is the mechanism
// proof.
func TestDecide_Matrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		policy signerserver.ApprovalPolicy
		votes  []store.Vote
		want   signerserver.ApprovalDecision
	}{
		// --- 1-of-1 ---
		{
			name:   "1of1 no votes -> pending",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 1},
			votes:  votes(),
			want:   signerserver.DecisionPending,
		},
		{
			name:   "1of1 one approve -> approved",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 1},
			votes:  votes(ap("alice")),
			want:   signerserver.DecisionApproved,
		},

		// --- 2-of-3 ---
		{
			name:   "2of3 one approve -> pending",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2},
			votes:  votes(ap("alice")),
			want:   signerserver.DecisionPending,
		},
		{
			name:   "2of3 two approve -> approved",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2},
			votes:  votes(ap("alice"), ap("bob")),
			want:   signerserver.DecisionApproved,
		},
		{
			name:   "2of3 three approve -> approved (overshoot fine)",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2},
			votes:  votes(ap("alice"), ap("bob"), ap("carol")),
			want:   signerserver.DecisionApproved,
		},

		// --- duplicate votes collapse ---
		{
			name:   "duplicate approve from one operator counts once -> pending at N=2",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2},
			votes:  votes(ap("alice"), ap("alice")),
			want:   signerserver.DecisionPending,
		},
		{
			name:   "duplicate first-wins: approve then deny from same op stays approve",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 1, DenyVeto: true},
			votes:  votes(ap("alice"), dn("alice")),
			want:   signerserver.DecisionApproved,
		},

		// --- deny veto ON ---
		{
			name:   "deny_veto on, one deny -> denied",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2, DenyVeto: true},
			votes:  votes(ap("alice"), dn("bob")),
			want:   signerserver.DecisionDenied,
		},
		{
			name:   "deny_veto on, veto wins tie even at threshold",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2, DenyVeto: true},
			votes:  votes(ap("alice"), ap("bob"), dn("carol")),
			want:   signerserver.DecisionDenied,
		},

		// --- deny veto OFF ---
		{
			name:   "deny_veto off, one deny does not deny -> still pending",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2, DenyVeto: false},
			votes:  votes(ap("alice"), dn("bob")),
			want:   signerserver.DecisionPending,
		},
		{
			name:   "deny_veto off, enough approves despite a deny -> approved",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 2, DenyVeto: false},
			votes:  votes(ap("alice"), ap("bob"), dn("carol")),
			want:   signerserver.DecisionApproved,
		},

		// --- self-approve OFF ---
		{
			name: "self_approve off, requester's approve ignored -> pending",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 1, AllowSelfApprove: false, Requester: "alice",
			},
			votes: votes(ap("alice")),
			want:  signerserver.DecisionPending,
		},
		{
			name: "self_approve off, requester deny ignored under veto -> not denied, pending",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 1, DenyVeto: true, AllowSelfApprove: false, Requester: "alice",
			},
			votes: votes(dn("alice")),
			want:  signerserver.DecisionPending,
		},
		{
			name: "self_approve off, requester+other -> only other counts -> approved at N=1",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 1, AllowSelfApprove: false, Requester: "alice",
			},
			votes: votes(ap("alice"), ap("bob")),
			want:  signerserver.DecisionApproved,
		},
		{
			name: "self_approve off, requester+other at N=2 -> pending (requester doesn't count)",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 2, AllowSelfApprove: false, Requester: "alice",
			},
			votes: votes(ap("alice"), ap("bob")),
			want:  signerserver.DecisionPending,
		},

		// --- self-approve ON ---
		{
			name: "self_approve on, requester's approve counts -> approved at N=1",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 1, AllowSelfApprove: true, Requester: "alice",
			},
			votes: votes(ap("alice")),
			want:  signerserver.DecisionApproved,
		},
		{
			name: "self_approve on, requester deny vetoes own request",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 1, DenyVeto: true, AllowSelfApprove: true, Requester: "alice",
			},
			votes: votes(dn("alice")),
			want:  signerserver.DecisionDenied,
		},

		// --- N floor: non-positive N treated as 1 (never auto-approve) ---
		{
			name:   "N=0 floored to 1: no votes -> pending (not auto-approved)",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 0},
			votes:  votes(),
			want:   signerserver.DecisionPending,
		},
		{
			name:   "N=0 floored to 1: one approve -> approved",
			policy: signerserver.ApprovalPolicy{RequiredApprovals: 0},
			votes:  votes(ap("alice")),
			want:   signerserver.DecisionApproved,
		},

		// --- no requester identity supplied: no self-vote logic applies ---
		{
			name: "empty requester, self_approve off: nobody is the requester, vote counts",
			policy: signerserver.ApprovalPolicy{
				RequiredApprovals: 1, AllowSelfApprove: false, Requester: "",
			},
			votes: votes(ap("alice")),
			want:  signerserver.DecisionApproved,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := signerserver.Decide(tc.policy, tc.votes)
			if got != tc.want {
				t.Fatalf("Decide = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestApprovingOperators verifies the "who counted" list respects
// self-approve eligibility and first-vote ordering, and excludes deniers.
func TestApprovingOperators(t *testing.T) {
	t.Parallel()

	// Self-approve off: requester excluded; order is first-vote order.
	got := signerserver.ApprovingOperators(
		signerserver.ApprovalPolicy{AllowSelfApprove: false, Requester: "alice"},
		votes(ap("bob"), ap("alice"), dn("carol"), ap("dave")),
	)
	want := []string{"bob", "dave"}
	if len(got) != len(want) {
		t.Fatalf("ApprovingOperators = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ApprovingOperators[%d] = %q; want %q (full %v)", i, got[i], want[i], got)
		}
	}

	// Self-approve on: requester's approve is included.
	got2 := signerserver.ApprovingOperators(
		signerserver.ApprovalPolicy{AllowSelfApprove: true, Requester: "alice"},
		votes(ap("alice"), ap("bob")),
	)
	if len(got2) != 2 || got2[0] != "alice" || got2[1] != "bob" {
		t.Fatalf("ApprovingOperators(self on) = %v; want [alice bob]", got2)
	}
}
