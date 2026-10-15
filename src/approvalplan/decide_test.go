package approvalplan_test

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

const requester = "client-1"

var hostedSettings = ap.Settings{Hosted: true, ReportHorizon: ap.ReportHorizonDefault, Retention: 7 * 24 * time.Hour}

// hosted is a pending hosted record frozen with quorum n, assist ready.
type hosted struct {
	// fast skips the per-commit transition check in long vote loops; the
	// final record is still checked.
	fast bool
	t    *testing.T
	rec  ap.R1
	now  ap.Now
	in   ap.Inputs
}

func newHosted(t *testing.T, n int, sub string) *hosted {
	t.Helper()
	now := ap.Now{Wall: st.T0}
	d := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("w", 60))
	cmd := st.SubmitOf(d, requester, st.T0, ap.ValidityDefault)
	cmd.Plan.RequesterSub, cmd.RequiredApprovals, cmd.Allowance = sub, n, ap.HostedSkew
	in := ap.Inputs{Epoch: st.Epoch(1), Settings: hostedSettings}
	rec, ans := ap.Apply(nil, cmd, now, in)
	if ans.Code != "" {
		t.Fatalf("submit: %+v", ans)
	}
	h := &hosted{t: t, rec: rec, now: now, in: in}
	t.Cleanup(func() {
		if err := st.CheckRecord(h.rec); err != nil {
			t.Errorf("final record: %v", err)
		}
	})
	result := st.Assist(st.T0)
	h.do(ap.AssistDone{Result: &result})
	return h
}

func (h *hosted) do(cmd ap.Command) ap.Answer {
	h.t.Helper()
	h.now.Wall = h.now.Wall.Add(time.Millisecond)
	after, ans := ap.Apply(&h.rec, cmd, h.now, h.in)
	if ans.Changed {
		if !h.fast {
			if err := st.CheckTransition(&h.rec, after, h.now); err != nil {
				h.t.Fatalf("%T: %v", cmd, err)
			}
		}
		h.rec = after
	}
	return ans
}

// vote posts a vote with a challenge bound to the current view.
func (h *hosted) vote(operator, decision string, flags ap.VoteFlags) ap.Answer {
	h.t.Helper()
	v := ap.View(h.rec, h.now, h.in.Epoch, h.in.Settings, false)
	tap := &ap.HostedTap{PlanHash: v.PlanHash, Revision: v.AssistRevision, Digest: h.rec.Header.Assist.Digest, Actions: ap.ActionsAt(v.AssistRevision)}
	return h.do(ap.CastVote{Operator: operator, Decision: decision, Authn: "totp", Flags: flags, Hosted: tap})
}

func (h *hosted) status() ap.ApprovalStatus {
	if d := h.rec.Header.Decision; d != nil {
		return d.Status
	}
	return ap.ApprovalPending
}

// The effective vote policy (r5.4): N and the requester come from the
// record, only the two flags from the caller, and sub_principal never
// enters it.
func TestEffectivePolicy(t *testing.T) {
	for _, sub := range []string{"", "local-uid:1000"} {
		h := newHosted(t, 2, sub)
		h.vote("alice", ap.VoteApprove, ap.VoteFlags{})
		if h.status() != ap.ApprovalPending {
			t.Fatal("one approve of two decided")
		}
		h.vote("bob", ap.VoteApprove, ap.VoteFlags{})
		if d := h.rec.Header.Decision; d == nil || d.Status != ap.ApprovalApproved || d.DecidedBy != "alice,bob" {
			t.Fatalf("sub %q: decision %+v", sub, d)
		}

		h = newHosted(t, 2, sub)
		h.vote(requester, ap.VoteApprove, ap.VoteFlags{DenyVeto: true})
		h.vote(requester+"x", ap.VoteApprove, ap.VoteFlags{DenyVeto: true})
		if h.status() != ap.ApprovalPending || len(h.rec.Header.Votes) != 2 {
			t.Fatalf("sub %q: the requester's own approve counted", sub)
		}
		h = newHosted(t, 1, sub)
		h.vote(requester, ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
		if h.status() != ap.ApprovalPending {
			t.Fatalf("sub %q: the requester's own deny vetoed", sub)
		}
		h.vote(requester+"x", ap.VoteApprove, ap.VoteFlags{DenyVeto: true})
		if h.status() != ap.ApprovalApproved {
			t.Fatal("N=1 first counting approve did not decide")
		}
		h = newHosted(t, 2, sub)
		h.vote(requester, ap.VoteApprove, ap.VoteFlags{AllowSelfApprove: true})
		h.vote("bob", ap.VoteApprove, ap.VoteFlags{AllowSelfApprove: true})
		if h.status() != ap.ApprovalApproved {
			t.Fatal("with self-approval on, the requester's approve did not count")
		}
	}
}

// A generated corpus: Apply's decision always equals Decide under the
// effective policy, and differs from a policy built from raw caller values
// whenever those would decide differently.
func TestDecisionIsEffectivePolicy(t *testing.T) {
	rnd := rand.New(rand.NewPCG(7, 7))
	differs := 0
	for range 200 {
		n := 1 + rnd.IntN(3)
		h := newHosted(t, n, "")
		h.fast = true
		for i := 0; i < 12 && h.status() == ap.ApprovalPending; i++ {
			flags := ap.VoteFlags{DenyVeto: rnd.IntN(2) == 0, AllowSelfApprove: rnd.IntN(2) == 0}
			op := []string{requester, "alice", "bob", "carol", "dave"}[rnd.IntN(5)]
			if h.vote(op, []string{ap.VoteApprove, ap.VoteDeny}[rnd.IntN(2)], flags).Noise {
				continue
			}
			want := ap.Decide(ap.EffectivePolicy(h.rec, flags), h.rec.Header.Votes)
			if h.status() != want {
				t.Fatalf("decision %s, Decide says %s", h.status(), want)
			}
			raw := ap.Decide(ap.Policy{DenyVeto: flags.DenyVeto, AllowSelfApprove: flags.AllowSelfApprove}, h.rec.Header.Votes)
			if raw != want {
				differs++
			}
		}
	}
	if differs == 0 {
		t.Fatal("the corpus never separated the effective policy from raw flags")
	}
}

func ops(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%03d", prefix, i)
	}
	return out
}

// The vote room rule (r5.6) on the review's worked example.
func TestVoteRoom(t *testing.T) {
	off := ap.VoteFlags{}
	h := newHosted(t, ap.MaxRequiredApprovals, "")
	h.fast = true
	for _, op := range ops("d", 63) {
		if ans := h.vote(op, ap.VoteDeny, off); ans.Noise {
			t.Fatalf("deny %s refused", op)
		}
	}
	seq := h.rec.Header.OutboxSeq
	if ans := h.vote(requester, ap.VoteApprove, off); !ans.Noise || ans.Reason != "set_full" || h.rec.Header.OutboxSeq != seq+1 {
		t.Fatalf("the 64th non-counting vote: %+v", ans)
	}
	for i, op := range ops("a", 256) {
		if ans := h.vote(op, ap.VoteApprove, off); ans.Noise {
			t.Fatalf("approve %d refused", i)
		}
	}
	if h.status() != ap.ApprovalApproved || len(h.rec.Header.Votes) != 319 {
		t.Fatalf("status %s with %d votes", h.status(), len(h.rec.Header.Votes))
	}

	h = newHosted(t, ap.MaxRequiredApprovals, "")
	h.fast = true
	h.vote(requester, ap.VoteApprove, off)
	accepted := 1
	for _, op := range ops("d", 63) {
		if !h.vote(op, ap.VoteDeny, off).Noise {
			accepted++
		}
	}
	if accepted != 63 {
		t.Fatalf("with the requester first, %d non-counting votes were accepted", accepted)
	}

	on := ap.VoteFlags{AllowSelfApprove: true}
	h = newHosted(t, ap.MaxRequiredApprovals, "")
	h.fast = true
	for _, op := range ops("d", 63) {
		h.vote(op, ap.VoteDeny, on)
	}
	if ans := h.vote(requester, ap.VoteApprove, on); ans.Noise {
		t.Fatal("a counting vote was refused for room")
	}
	for _, op := range ops("a", 255) {
		h.vote(op, ap.VoteApprove, on)
	}
	if h.status() != ap.ApprovalApproved {
		t.Fatal("255 approves plus the requester's did not decide")
	}

	h = newHosted(t, ap.MaxRequiredApprovals, "")
	h.fast = true
	h.vote(requester, ap.VoteApprove, on)
	for _, op := range ops("d", 63) {
		h.vote(op, ap.VoteDeny, on)
	}
	if len(h.rec.Header.Votes) != 64 {
		t.Fatalf("%d votes", len(h.rec.Header.Votes))
	}
	if ans := h.vote("late-deny", ap.VoteDeny, off); !ans.Noise {
		t.Fatal("a non-counting vote at |votes| + need = VoteCap was accepted")
	}
	for i, op := range ops("a", 256) {
		if ans := h.vote(op, ap.VoteApprove, off); ans.Noise {
			t.Fatalf("approve %d refused after the flag change", i)
		}
	}
	if h.status() != ap.ApprovalApproved || len(h.rec.Header.Votes) != 320 {
		t.Fatalf("status %s with %d votes", h.status(), len(h.rec.Header.Votes))
	}

	h = newHosted(t, 5, "")
	h.vote("v", ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
	if h.status() != ap.ApprovalDenied {
		t.Fatal("deny-veto did not decide on the first eligible deny")
	}

	bad := h.rec
	bad.Header.RequiredApprovals = ap.MaxRequiredApprovals + 1
	if _, err := ap.EncodeR1(bad); err == nil {
		t.Fatal("a record with required_approvals 257 encoded")
	}
}

// The room property over generated vote sequences, flags and flag changes.
func TestVoteRoomProperty(t *testing.T) {
	for _, n := range []int{1, 2, 63, 64, 65, 255, 256} {
		rnd := rand.New(rand.NewPCG(uint64(n), 3))
		pool := append(ops("o", n+70), requester)
		for run := range 3 {
			h := newHosted(t, n, "")
			h.fast = n > 2
			flags := ap.VoteFlags{AllowSelfApprove: rnd.IntN(2) == 0}
			for i := 0; h.status() == ap.ApprovalPending && i < 3*n+200; i++ {
				if rnd.IntN(40) == 0 {
					flags.AllowSelfApprove = !flags.AllowSelfApprove
				}
				op := pool[rnd.IntN(len(pool))]
				decision := ap.VoteDeny
				if rnd.IntN(3) == 0 {
					decision = ap.VoteApprove
				}
				before := h.rec
				v := ap.Vote{Operator: op, Decision: decision, TS: h.now.Wall}
				p := ap.EffectivePolicy(before, flags)
				after := append(append([]ap.Vote(nil), before.Header.Votes...), v)
				counts := len(ap.ApprovingOperators(p, after)) > len(ap.ApprovingOperators(p, before.Header.Votes))
				decides := ap.Decide(p, after) != ap.ApprovalPending
				ans := h.vote(op, decision, flags)
				if ans.Reason == "set_full" && (counts || decides) {
					t.Fatalf("N=%d run %d: a vote that counts or decides was refused", n, run)
				}
				if len(h.rec.Header.Votes) > ap.VoteCap(h.rec) {
					t.Fatalf("N=%d: %d votes over the cap", n, len(h.rec.Header.Votes))
				}
				if ap.Decide(ap.EffectivePolicy(h.rec, flags), h.rec.Header.Votes) == ap.ApprovalApproved && h.status() != ap.ApprovalApproved {
					t.Fatalf("N=%d: quorum reached but not approved", n)
				}
			}
		}
	}
	if !strings.Contains(fmt.Sprint(ap.LocalVoteFlags), "true") {
		t.Fatal("local flags must keep the veto on")
	}
}
