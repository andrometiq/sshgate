package approvalplan_test

import (
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// TestViewAuthMode is ruling 16: auth_mode says how an approved record was
// authorized and is absent from every other decision, a deny included even
// though its decided_by names the denier.
func TestViewAuthMode(t *testing.T) {
	r := newRig(t)

	pending := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	if got := r.view(pending).AuthMode; got != "" {
		t.Errorf("pending auth_mode = %q; want absent", got)
	}

	human := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(human)
	if got := r.view(human).AuthMode; got != "human" {
		t.Errorf("human-approved auth_mode = %q; want human", got)
	}

	denied := r.submit(st.ID(3), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.AssistArrives(denied, false)
	r.s.Reconcile(denied)
	if ans := r.s.Tap(denied, ap.VoteDeny, st.Operator, true); ans.Code != "" || ans.Noise {
		t.Fatalf("deny: %+v", ans)
	}
	if d := r.rec(denied).Header.Decision; d == nil || d.Status != ap.ApprovalDenied || d.DecidedBy != st.Operator {
		t.Fatalf("deny decision %+v; want denied by %s", d, st.Operator)
	}
	if got := r.view(denied).AuthMode; got != "" {
		t.Errorf("denied auth_mode = %q; want absent", got)
	}

	canceled := r.submit(st.ID(4), ap.CoordinatorExecutor, st.Write("w", 60))
	if ans := r.s.Cancel(canceled); ans.Code != "" {
		t.Fatalf("cancel: %+v", ans)
	}
	if got := r.view(canceled).AuthMode; got != "" {
		t.Errorf("canceled auth_mode = %q; want absent", got)
	}

	grant := r.grant(st.ID(5), st.PrincipalA, time.Hour)
	if got := r.view(grant).AuthMode; got != "human" {
		t.Errorf("human-approved grant record auth_mode = %q; want human", got)
	}
	if !r.covered(6, st.PrincipalA) {
		t.Fatal("the live grant did not cover the write")
	}
	if got, want := r.view(ap.RecordKey(st.PrincipalA, st.ID(6))).AuthMode, ap.GrantDecidedPrefix+st.ID(5); got != want {
		t.Errorf("grant-covered auth_mode = %q; want %q", got, want)
	}

	r.clock.Advance(ap.ValidityDefault + time.Second)
	r.s.Reconcile(pending)
	if d := r.rec(pending).Header.Decision; d == nil || d.Status != ap.ApprovalExpired {
		t.Fatalf("expiry decision %+v", d)
	}
	if got := r.view(pending).AuthMode; got != "" {
		t.Errorf("expired auth_mode = %q; want absent", got)
	}
}
