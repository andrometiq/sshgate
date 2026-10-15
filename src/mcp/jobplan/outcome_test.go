package jobplan

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

func TestStepOutcomeTable(t *testing.T) {
	kinds := []StepKind{UnsignedRead, SignedWrite, SignedReveal, AdminRevoke, AdminUpdate, XferSend, XferRecv}
	jail := "gate: read jail unavailable: jail probe failed\n"
	after := "gate: read jail unavailable: the jail failed after the read may have started (setattr: function not implemented); its result is not trusted\n"
	rows := []struct {
		name   string
		exit   int
		stderr string
		err    error
		status approvalplan.StepStatus
	}{
		{"success", 0, "", nil, approvalplan.StepSucceeded},
		{"ordinary", 3, "", nil, approvalplan.StepFailed},
		{"signature", 65, "", nil, approvalplan.StepFailed},
		{"filesystem", 70, "", nil, approvalplan.StepFailed},
		{"denied", 77, "", nil, approvalplan.StepFailed},
		{"jail", 77, jail, nil, approvalplan.StepFailed},
		{"after_start", 77, after, nil, approvalplan.StepFailed},
		{"both_lines", 77, jail + after, nil, approvalplan.StepFailed},
		{"ordinary_with_line", 3, jail, nil, approvalplan.StepFailed},
		{"success_with_line", 0, after, nil, approvalplan.StepSucceeded},
		{"not_started", 0, jail, &gatessh.PhasedError{Class: "failed_not_started"}, approvalplan.StepFailedNotStarted},
		{"guard", 0, jail, &gatessh.PhasedError{Class: "guard_refused"}, approvalplan.StepExpiredUnexecuted},
		{"uncertain", 0, jail, &gatessh.PhasedError{Class: "indeterminate"}, approvalplan.StepIndeterminate},
		{"unknown_error", 0, jail, errors.New("SSHGATE_SIG:secret payload command"), approvalplan.StepIndeterminate},
		{"unknown_class", 0, jail, &gatessh.PhasedError{Class: "unknown", Detail: "SSHGATE_SIG:secret"}, approvalplan.StepIndeterminate},
		{"missing_exit", -1, jail, nil, approvalplan.StepIndeterminate},
	}
	for _, kind := range kinds {
		for _, earlier := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/earlier=%t/%s", kind, earlier, row.name), func(t *testing.T) {
					got := StepOutcome(kind, earlier, PhasedResult{Stderr: []byte(row.stderr), ExitCode: row.exit, Err: row.err})
					want := row.status
					if kind == UnsignedRead && row.name == "jail" {
						want = approvalplan.StepFailedNotStarted
					}
					if got.Status != want {
						t.Fatalf("status %s; want %s", got.Status, want)
					}
					signed := kind == SignedWrite || kind == SignedReveal
					isJail := row.err == nil && row.exit == 77 && row.stderr != "" && (signed || kind == UnsignedRead)
					signature := row.err == nil && signed && (row.exit == 65 || row.exit == 77 && !isJail)
					if got.Retryable != (signature && !earlier) {
						t.Fatalf("retry: %+v", got)
					}
					if (got.Annotation == "gate refused (signature)") != signature {
						t.Fatalf("signature annotation: %+v", got)
					}
					if (got.VerdictClass == "read_jail_unavailable") != isJail {
						t.Fatalf("jail remediation: %+v", got)
					}
					if isJail && !strings.Contains(got.Message, "doctor") {
						t.Fatalf("missing remediation: %+v", got)
					}
					if (row.name == "after_start" || row.name == "both_lines") && (kind == UnsignedRead || signed) && !strings.Contains(got.Annotation, "not trusted") {
						t.Fatalf("lost P2 warning: %+v", got)
					}
					if strings.Contains(fmt.Sprintf("%+v", got), "SSHGATE_SIG:") {
						t.Fatal("raw error leaked")
					}
					ordinals := approvalplan.ExecutedOrdinals([]approvalplan.StepStatus{got.Status})
					expected := []int{}
					if want == approvalplan.StepSucceeded || want == approvalplan.StepFailed || want == approvalplan.StepIndeterminate {
						expected = []int{1}
					}
					if !reflect.DeepEqual(ordinals, expected) {
						t.Fatalf("executed %v; want %v", ordinals, expected)
					}
				})
			}
		}
	}
}

func TestNoDirectTimeReads(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	elapsedtest.AssertNoDirectTimeReads(t, files)
}

func TestToolExitTexts(t *testing.T) {
	rows := []struct {
		kind    StepKind
		exit    int
		message string
	}{
		{XferSend, 65, "the source gate refused the transfer send (exit 65): the signed leg failed to parse, or the source file was empty or over the size cap; nothing was sealed."},
		{XferSend, 70, "the source gate could not read the source file or its transfer keys (exit 70): check src_path and that the source gate holds its xfer keys."},
		{XferSend, 77, "the source gate denied the signed send (exit 77): read-only / no signer pubkey / missing signature — check sshgate.status."},
		{XferRecv, 65, "the destination gate refused the transfer receive (exit 65): the signed leg failed to parse, the envelope was empty/oversize/malformed, or the crypto binding/attestation failed; nothing was written."},
		{XferRecv, 70, "the destination gate could not load its transfer keys or write the destination file (exit 70): check dest_path is writable and that the destination gate holds its xfer keys."},
		{XferRecv, 77, "the destination gate denied the signed receive (exit 77): read-only / no signer pubkey / missing signature — check sshgate.status."},
		{AdminUpdate, 65, fmt.Sprintf("tools: gate refused the update — the streamed binary failed a gate check (hash mismatch / not an ELF / wrong architecture / size violation); the old gate is unchanged. Do NOT re-run without first fixing the staged binary (re-run `make install-local`). (exit=%d stdout=%q stderr=%q)", 65, "out", "err")},
		{AdminUpdate, 70, fmt.Sprintf("tools: gate could not replace its binary (filesystem error) — the old gate is still in place; check ~/.sshgate-gate on the server (disk space / permissions). (exit=%d stdout=%q stderr=%q)", 70, "out", "err")},
		{AdminUpdate, 77, fmt.Sprintf("tools: the server denied the signed update (read-only / no signer pubkey / missing signature) — check sshgate.status. (exit=%d stdout=%q stderr=%q)", 77, "out", "err")},
		{AdminRevoke, 77, `tools: gate did not confirm revoke (stdout="out" stderr="err" exit=77)`},
		{AdminUpdate, 3, `tools: gate refused the update (exit=3 stdout="out" stderr="err")`},
		{XferSend, 3, "the source gate refused the transfer send (exit 3)."},
		{XferRecv, 3, "the destination gate refused the transfer receive (exit 3)."},
	}
	for _, row := range rows {
		for _, earlier := range []bool{false, true} {
			got := StepOutcome(row.kind, earlier, PhasedResult{Stdout: []byte(" out\n"), Stderr: []byte(" err\n"), ExitCode: row.exit})
			if got.Message != row.message || got.Retryable || got.VerdictClass != "" {
				t.Fatalf("%s/%d: %+v; want %q", row.kind, row.exit, got, row.message)
			}
		}
	}
}
