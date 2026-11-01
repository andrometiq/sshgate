// Package jobplan maps execution results for synchronous and asynchronous jobs.
package jobplan

import (
	"errors"
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// StepKind refines a route by admin verb or transfer leg.
type StepKind string

const (
	UnsignedRead StepKind = "unsigned_read"
	SignedWrite  StepKind = "signed_write"
	SignedReveal StepKind = "signed_reveal"
	AdminRevoke  StepKind = "admin_revoke"
	AdminUpdate  StepKind = "admin_update"
	XferSend     StepKind = "xfer_send"
	XferRecv     StepKind = "xfer_recv"
)

// PhasedResult holds the return values of RunPhased.
type PhasedResult struct {
	Stdout, Stderr []byte
	ExitCode       int
	Err            error
}

// Outcome carries execution certainty and tool-independent remediation.
// VerdictClass is mapped to the surface's Denial; Message is per-step text.
type Outcome struct {
	Status       approvalplan.StepStatus
	Annotation   string
	VerdictClass string
	Message      string
	Retryable    bool
}

const (
	ReadJailAfterStart = "gate reported read jail unavailable after the read may have started; its result is not trusted (counted as executed)"
	ReadJailRefused    = "gate refused the read: read jail unavailable"
	ReadJailSigned     = "gate reported read jail unavailable (unverified on a signed route; counted as executed)"
)

// ReadJailRemediation recognizes only the runner's durable annotations.
func ReadJailRemediation(annotation string) (string, bool) {
	switch annotation {
	case ReadJailAfterStart, ReadJailRefused, ReadJailSigned:
		return "Ask a human to run `~/.sshgate-gate/gate doctor` on the host; do not auto-retry.", true
	default:
		return "", false
	}
}

// StepOutcome never uses stderr as evidence that a signed step did not run.
// EarlierExecuted limits signature retry advice to the first executed step.
func StepOutcome(kind StepKind, earlierExecuted bool, phased PhasedResult) Outcome {
	if phased.Err != nil {
		outcome := Outcome{Status: approvalplan.StepIndeterminate, Annotation: "SSH execution indeterminate"}
		var phase *gatessh.PhasedError
		if errors.As(phased.Err, &phase) && phase != nil {
			switch phase.Class {
			case "failed_not_started":
				outcome.Status = approvalplan.StepFailedNotStarted
				outcome.Annotation = "SSH command not started"
			case "guard_refused":
				outcome.Status = approvalplan.StepExpiredUnexecuted
				outcome.Annotation = "signature window closed before dispatch"
				outcome.VerdictClass = "expired_unexecuted"
			}
		}
		return outcome
	}
	if phased.ExitCode < 0 {
		return Outcome{Status: approvalplan.StepIndeterminate, Annotation: "SSH execution indeterminate"}
	}
	outcome := Outcome{Status: approvalplan.StepSucceeded}
	if phased.ExitCode == 0 {
		return outcome
	}
	outcome.Status = approvalplan.StepFailed
	exit := phased.ExitCode
	stderr := string(phased.Stderr)
	if (kind == UnsignedRead || kind == SignedWrite || kind == SignedReveal) && exit == 77 && strings.Contains(stderr, "gate: read jail unavailable") {
		outcome.VerdictClass = "read_jail_unavailable"
		switch {
		case strings.Contains(stderr, "the jail failed after the read may have started"):
			outcome.Annotation = ReadJailAfterStart
		case kind == UnsignedRead:
			outcome.Status = approvalplan.StepFailedNotStarted
			outcome.Annotation = ReadJailRefused
		default:
			outcome.Annotation = ReadJailSigned
		}
		outcome.Message, _ = ReadJailRemediation(outcome.Annotation)
		return outcome
	}
	switch kind {
	case SignedWrite, SignedReveal:
		if exit == 65 || exit == 77 {
			outcome.Annotation = "gate refused (signature)"
			outcome.VerdictClass = "bad_signature"
			if exit == 77 {
				outcome.VerdictClass = "missing_signature"
			}
			outcome.Message = "Check sshgate.status and the host's signature configuration."
			outcome.Retryable = !earlierExecuted
			if outcome.Retryable {
				outcome.Message += " Retry once."
			}
		}
	case AdminRevoke:
		outcome.Message = fmt.Sprintf("tools: gate did not confirm revoke (stdout=%q stderr=%q exit=%d)", strings.TrimSpace(string(phased.Stdout)), strings.TrimSpace(stderr), exit)
	case AdminUpdate:
		outcome.Message = updateExitNote(exit, strings.TrimSpace(string(phased.Stdout)), strings.TrimSpace(stderr))
	case XferSend:
		outcome.Message = xferSendExitNote(exit)
	case XferRecv:
		outcome.Message = xferRecvExitNote(exit)
	}
	return outcome
}

func xferSendExitNote(exit int) string {
	switch exit {
	case 65:
		return "the source gate refused the transfer send (exit 65): the signed leg failed to parse, or the source file was empty or over the size cap; nothing was sealed."
	case 70:
		return "the source gate could not read the source file or its transfer keys (exit 70): check src_path and that the source gate holds its xfer keys."
	case 77:
		return "the source gate denied the signed send (exit 77): read-only / no signer pubkey / missing signature — check sshgate.status."
	default:
		return fmt.Sprintf("the source gate refused the transfer send (exit %d).", exit)
	}
}

// xferRecvExitNote maps a non-zero RECV-leg gate exit to remediation. Codes per
// P3 spec §1.7: 65 = data/crypto refusal (parse / binding / attestation / cap),
// 70 = fs/key error, 77 = read-only/unsigned.
func xferRecvExitNote(exit int) string {
	switch exit {
	case 65:
		return "the destination gate refused the transfer receive (exit 65): the signed leg failed to parse, the envelope was empty/oversize/malformed, or the crypto binding/attestation failed; nothing was written."
	case 70:
		return "the destination gate could not load its transfer keys or write the destination file (exit 70): check dest_path is writable and that the destination gate holds its xfer keys."
	case 77:
		return "the destination gate denied the signed receive (exit 77): read-only / no signer pubkey / missing signature — check sshgate.status."
	default:
		return fmt.Sprintf("the destination gate refused the transfer receive (exit %d).", exit)
	}
}

// These texts mirror the update tool; A13b pins drift at adoption.
func updateExitNote(exit int, outStr, errStr string) string {
	switch exit {
	case 65:
		return fmt.Sprintf(
			"tools: gate refused the update — the streamed binary failed a gate check (hash mismatch / not an ELF / wrong architecture / size violation); the old gate is unchanged. Do NOT re-run without first fixing the staged binary (re-run `make install-local`). (exit=%d stdout=%q stderr=%q)",
			exit, outStr, errStr)
	case 70:
		return fmt.Sprintf(
			"tools: gate could not replace its binary (filesystem error) — the old gate is still in place; check ~/.sshgate-gate on the server (disk space / permissions). (exit=%d stdout=%q stderr=%q)",
			exit, outStr, errStr)
	case 77:
		return fmt.Sprintf(
			"tools: the server denied the signed update (read-only / no signer pubkey / missing signature) — check sshgate.status. (exit=%d stdout=%q stderr=%q)",
			exit, outStr, errStr)
	default:
		return fmt.Sprintf(
			"tools: gate refused the update (exit=%d stdout=%q stderr=%q)",
			exit, outStr, errStr)
	}
}
