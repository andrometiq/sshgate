package approvalplan

import (
	"errors"
	"testing"
)

func TestCodesClosedSet(t *testing.T) {
	retryable := map[Code]bool{
		CodeStorageUncertain: true, CodeBusy: true, CodeLifecycleUnavailable: true,
		CodeQueueFull: true, CodeSubmitWindowAhead: true,
	}
	if len(AllCodes) != 16 {
		t.Fatalf("%d codes, want 16", len(AllCodes))
	}
	seen := map[Code]bool{}
	for _, c := range AllCodes {
		if seen[c] || !c.Valid() {
			t.Fatalf("%q duplicated or invalid", c)
		}
		seen[c] = true
		if c.Retryable() != retryable[c] {
			t.Errorf("%s: Retryable() = %v", c, c.Retryable())
		}
	}
	if Code("not_ready").Valid() || Code("").Valid() {
		t.Fatal("not_ready is a Claim status, not a code")
	}
	for _, s := range []ClaimStatus{ClaimSignatures, ClaimNotReady, ClaimDenied, ClaimCanceled, ClaimExpired, ClaimError, ClaimExecutionReported, ClaimMaterializationError} {
		if !s.Valid() {
			t.Errorf("%s invalid", s)
		}
	}
}

func TestCodeErrorWrapsAField(t *testing.T) {
	err := within("command_job", within("steps[2]", invalid("route", "bad")))
	var ce *CodeError
	if !errors.As(err, &ce) || ce.Field != "command_job.steps[2].route" || ce.Code != CodeInvalidRequest {
		t.Fatalf("%#v", err)
	}
	if within("x", nil) != nil {
		t.Fatal("within(nil) must stay nil")
	}
	if ce.Error() != "approvalplan: invalid_request: command_job.steps[2].route: bad" {
		t.Fatalf("Error() = %q", ce.Error())
	}
}
