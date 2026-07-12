package tools

import "testing"

// TestNewDenial_ShapePinned pins the closed verdict_class + required_action
// enums and the retryable flag for every #26-core Denial class. It is a
// white-box test (package tools) so it reaches the unexported newDenial
// constructor directly — the single source of truth all refusal branches build
// from. If a class's action/retryable ever drifts, this fails loudly.
func TestNewDenial_ShapePinned(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class      string
		wantAction string
		wantRetry  bool
	}{
		{VerdictReadOnlyServer, ActionRephraseAsRead, false},
		{VerdictNoSignerConfigured, ActionEscalateToHuman, false},
		{VerdictApprovalDenied, ActionStopDoNotRetry, false},
		{VerdictApprovalTimeout, ActionRetry, true},
		{VerdictSignerUnreachable, ActionEscalateToHuman, false},
		{VerdictSignerPermission, ActionEscalateToHuman, false},
		{VerdictUnknown, ActionStopDoNotRetry, false},
		{VerdictBadSignature, ActionRetry, true},
		{VerdictMissingSignature, ActionEscalateToHuman, false}, // M1: exit 77 is NOT retryable
		{VerdictRevealNeedsReason, ActionProvideReason, false},
	}
	if len(cases) != 10 {
		t.Fatalf("expected 10 verdict classes pinned; got %d", len(cases))
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.class, func(t *testing.T) {
			t.Parallel()
			d := newDenial(tc.class)
			if d == nil {
				t.Fatalf("newDenial(%q) = nil; want a Denial", tc.class)
			}
			if d.VerdictClass != tc.class {
				t.Errorf("VerdictClass=%q; want %q", d.VerdictClass, tc.class)
			}
			if d.RequiredAction != tc.wantAction {
				t.Errorf("RequiredAction=%q; want %q", d.RequiredAction, tc.wantAction)
			}
			if d.Retryable != tc.wantRetry {
				t.Errorf("Retryable=%v; want %v", d.Retryable, tc.wantRetry)
			}
			// retryable must be true ONLY for the "retry" action — the whole
			// point of the flag is that an agent never auto-resubmits a
			// stop/escalate/rephrase/provide-reason verdict.
			if (d.RequiredAction == ActionRetry) != d.Retryable {
				t.Errorf("retryable/action mismatch: action=%q retryable=%v", d.RequiredAction, d.Retryable)
			}
			if d.Summary == "" {
				t.Error("Summary is empty; want a one-line class-level summary")
			}
			if len(d.HowTo) == 0 {
				t.Error("HowTo is empty; want at least one concrete step")
			}
		})
	}
}

// TestNewDenial_UnknownClass confirms an unrecognised class yields nil (callers
// treat that as "no structured denial", prose-only).
func TestNewDenial_UnknownClass(t *testing.T) {
	t.Parallel()
	if d := newDenial("not_a_real_class"); d != nil {
		t.Errorf("newDenial(bogus) = %+v; want nil", d)
	}
}

// TestDenialForGateExit pins the exit-code → verdict-class mapping, including
// the M1 correction (77 = missing_signature, escalate, NOT retryable).
func TestDenialForGateExit(t *testing.T) {
	t.Parallel()
	if d := denialForGateExit(77); d == nil || d.VerdictClass != VerdictMissingSignature || d.Retryable {
		t.Errorf("denialForGateExit(77) = %+v; want missing_signature, retryable=false", d)
	}
	if d := denialForGateExit(65); d == nil || d.VerdictClass != VerdictBadSignature || !d.Retryable {
		t.Errorf("denialForGateExit(65) = %+v; want bad_signature, retryable=true", d)
	}
	if d := denialForGateExit(0); d != nil {
		t.Errorf("denialForGateExit(0) = %+v; want nil", d)
	}
	if d := denialForGateExit(1); d != nil {
		t.Errorf("denialForGateExit(1) = %+v; want nil", d)
	}
}
