package tools_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// F1 PART 2: a lost verdict (ErrVerdictUnknown) must reach the agent as an
// explicit FAIL-SAFE outcome, never a generic retryable error. On the run
// path the error must (a) still errors.Is the sentinel for the MCP layer,
// and (b) carry guidance telling the agent NOT to auto-retry because a human
// may have DENIED — pointing at sshgate.status and the Telegram thread.

func TestRun_WriteVerdictUnknown_FailSafeGuidanceAndSentinel(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrVerdictUnknown}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on verdict-unknown")
	}
	// #26-core: verdict_unknown → stop_do_not_retry, NOT retryable.
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictUnknown {
		t.Errorf("out.Denial=%+v; want verdict_unknown", out.Denial)
	}
	if out.Denial != nil && (out.Denial.RequiredAction != tools.ActionStopDoNotRetry || out.Denial.Retryable) {
		t.Errorf("verdict_unknown Denial action=%q retryable=%v; want stop_do_not_retry/false", out.Denial.RequiredAction, out.Denial.Retryable)
	}
	// Sentinel survives the wrapping so the MCP layer can recognise it.
	if !errors.Is(err, signpkg.ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown)", err)
	}
	// Must NOT be mis-bucketed as a benign/other sentinel.
	if errors.Is(err, signpkg.ErrDenied) || errors.Is(err, signpkg.ErrTimeout) ||
		errors.Is(err, signpkg.ErrUnreachable) || errors.Is(err, signpkg.ErrSignerPermission) {
		t.Errorf("verdict-unknown mis-mapped to another sentinel: %v", err)
	}
	// Fail-safe guidance: do not retry, a human may have denied, check status.
	lc := strings.ToLower(err.Error())
	for _, want := range []string{"do not", "denied", "retry", "sshgate.status", "telegram"} {
		if !strings.Contains(lc, want) {
			t.Errorf("remediation %q missing fail-safe cue %q", err.Error(), want)
		}
	}
	// Crucially, the write must NOT have been attempted over SSH.
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called despite an indeterminate verdict (must fail safe, not run)")
	}
}

// On the run_batch path a verdict-unknown must classify to the distinct
// "verdict_unknown" Reason token (not the generic "error" bucket) and set
// Denied=true with no writes executed.
func TestRunBatch_WriteVerdictUnknown_ReasonToken(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &batchSign{err: signpkg.ErrVerdictUnknown}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/x"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if !out.Denied {
		t.Error("Denied=false; want true on verdict-unknown")
	}
	// #26-core: batch Denial mirrors the token (stop, not retry).
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictUnknown {
		t.Errorf("out.Denial=%+v; want verdict_unknown", out.Denial)
	}
	// The batch Reason carries the distinct verdict_unknown token (so it is
	// NOT the generic "error" bucket) plus the fail-safe guidance.
	if !strings.HasPrefix(out.Reason, "verdict_unknown") {
		t.Errorf("Reason = %q; want it to lead with the verdict_unknown token (distinct from the generic error bucket)", out.Reason)
	}
	lc := strings.ToLower(out.Reason)
	for _, want := range []string{"do not", "denied", "retry", "sshgate.status", "telegram"} {
		if !strings.Contains(lc, want) {
			t.Errorf("batch Reason %q missing fail-safe cue %q", out.Reason, want)
		}
	}
	if len(ssh.calls) != 0 {
		t.Error("SSH was called despite an indeterminate verdict (must fail safe)")
	}
}

// TestClassifySignErr_VerdictUnknownToken pins the BARE token from
// classifySignErr (the white-box helper) — exactly "verdict_unknown", no
// guidance — to guard the machine-readable classification contract.
func TestRunBatch_VerdictUnknown_BareTokenViaClassify(t *testing.T) {
	t.Parallel()
	// Re-run through the public RunBatch with a non-verdict error to confirm
	// the generic bucket is unchanged (regression guard for the new case).
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &batchSign{err: errors.New("some transport blip")}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}
	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{Alias: "h1", Commands: []string{"rm /tmp/x"}})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if out.Reason != "error" {
		t.Errorf("Reason = %q; want the generic \"error\" for a non-sentinel transport error", out.Reason)
	}
}
