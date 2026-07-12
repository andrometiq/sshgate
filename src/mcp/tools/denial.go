package tools

// Denial is the structured, agent-parseable "why the command did not run and
// what to do about it". It carries the verdict CLASS and the remedy only —
// never classifier internals or parse reasoning (that is #22 territory). Nil on
// success (or on a non-verdict infra error); non-nil = a verdict/refusal the
// agent must act on. Purely additive and migration-neutral: it is built from
// string inputs (alias, exit code, error sentinel, tier bool), so the #22
// string→argv classifier migration leaves this object and its call sites
// untouched.
type Denial struct {
	VerdictClass   string   `json:"verdict_class"`   // stable enum, verdict_class* consts
	Summary        string   `json:"summary"`         // one-line, CLASS-level "what happened" (never per-segment reasoning)
	RequiredAction string   `json:"required_action"` // stable enum, action* consts
	Retryable      bool     `json:"retryable"`       // explicit; true only for approval_timeout / bad_signature
	HowTo          []string `json:"how_to"`          // ordered concrete steps referencing only real surfaces
}

// verdict_class values (closed, stable enum). Each maps 1:1 from a refusal
// branch in run.go / run_batch.go.
const (
	VerdictReadOnlyServer     = "read_only_server"
	VerdictNoSignerConfigured = "no_signer_configured"
	VerdictApprovalDenied     = "approval_denied"
	VerdictApprovalTimeout    = "approval_timeout"
	VerdictSignerUnreachable  = "signer_unreachable"
	VerdictSignerPermission   = "signer_permission"
	VerdictUnknown            = "verdict_unknown"
	VerdictBadSignature       = "bad_signature"
	VerdictMissingSignature   = "missing_signature"
	VerdictRevealNeedsReason  = "reveal_needs_reason"
)

// required_action values (closed enum). A Denial carries exactly one.
const (
	ActionRephraseAsRead  = "rephrase_as_read"
	ActionEscalateToHuman = "escalate_to_human"
	ActionStopDoNotRetry  = "stop_do_not_retry"
	ActionRetry           = "retry"
	ActionProvideReason   = "provide_reason"
)

// newDenial returns the fully-populated Denial for a verdict class. The Summary
// and HowTo are CLASS-level static text — they name real tools/surfaces
// (sshgate.status, /sshgate:setup, run/run_batch resubmit) and never echo the
// classifier's per-segment reasoning, so the object stays #22-migration-stable.
// An unrecognised class returns nil (callers treat that as "no structured
// denial", falling back to the prose error only).
func newDenial(class string) *Denial {
	switch class {
	case VerdictReadOnlyServer:
		return &Denial{
			VerdictClass:   VerdictReadOnlyServer,
			Summary:        "This is a write to a read-only (Tier-1) server; writes are refused at the gate before any approval.",
			RequiredAction: ActionRephraseAsRead,
			Retryable:      false,
			HowTo: []string{
				"If you meant this as a READ, simplify it (drop any redirect, compound, or uncommon tool) and resubmit run/run_batch.",
				"If it is genuinely a write, a human must re-provision the server as signed-write (Tier-2) — there is no agent path.",
			},
		}
	case VerdictNoSignerConfigured:
		return &Denial{
			VerdictClass:   VerdictNoSignerConfigured,
			Summary:        "No Telegram signer is configured (Tier-1 / pre-setup), so this write cannot be approved.",
			RequiredAction: ActionEscalateToHuman,
			Retryable:      false,
			HowTo: []string{
				"A human runs /sshgate:setup to install a signer.",
				"Check sshgate.status to confirm the signer is configured, then retry.",
			},
		}
	case VerdictApprovalDenied:
		return &Denial{
			VerdictClass:   VerdictApprovalDenied,
			Summary:        "The write was not approved — a human may have denied it.",
			RequiredAction: ActionStopDoNotRetry,
			Retryable:      false,
			HowTo: []string{
				"Do NOT resubmit this write.",
				"Ask the human why it was denied and propose an alternative.",
			},
		}
	case VerdictApprovalTimeout:
		return &Denial{
			VerdictClass:   VerdictApprovalTimeout,
			Summary:        "The approval request timed out before a human responded.",
			RequiredAction: ActionRetry,
			Retryable:      true,
			HowTo: []string{
				"Resubmit the same run/run_batch call ONCE so a fresh approval prompt is sent.",
				"If it times out again, confirm with the human before retrying further.",
			},
		}
	case VerdictSignerUnreachable:
		return &Denial{
			VerdictClass:   VerdictSignerUnreachable,
			Summary:        "The signer socket is present but not accepting connections — the signer daemon may be down.",
			RequiredAction: ActionEscalateToHuman,
			Retryable:      false,
			HowTo: []string{
				"A human checks `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.",
				"Retry once the signer is back up (confirm with sshgate.status).",
			},
		}
	case VerdictSignerPermission:
		return &Denial{
			VerdictClass:   VerdictSignerPermission,
			Summary:        "The signer socket exists but this session lacks permission to reach it (not yet in the sshgatesigner group).",
			RequiredAction: ActionEscalateToHuman,
			Retryable:      false,
			HowTo: []string{
				"Log out and back in, then relaunch Claude Code so the session picks up sshgatesigner group membership.",
				"Run /mcp to confirm the sshgate server is live, then retry.",
			},
		}
	case VerdictUnknown:
		return &Denial{
			VerdictClass:   VerdictUnknown,
			Summary:        "The signer reached a decision but its response did not arrive — a human may have DENIED this write.",
			RequiredAction: ActionStopDoNotRetry,
			Retryable:      false,
			HowTo: []string{
				"Do NOT auto-retry.",
				"Check sshgate.status and the Telegram approval thread to confirm the verdict before resubmitting.",
			},
		}
	case VerdictBadSignature:
		return &Denial{
			VerdictClass:   VerdictBadSignature,
			Summary:        "The gate rejected the signature as expired or invalid — usually clock skew or a stale approval.",
			RequiredAction: ActionRetry,
			Retryable:      true,
			HowTo: []string{
				"Resubmit the run/run_batch call ONCE to obtain a fresh signature.",
				"If it fails again, check the host clock and sshgate.status.",
			},
		}
	case VerdictMissingSignature:
		return &Denial{
			VerdictClass:   VerdictMissingSignature,
			Summary:        "The gate refused the write: the server has no signer pubkey (read-only / Tier-1) or the signature was stripped.",
			RequiredAction: ActionEscalateToHuman,
			Retryable:      false,
			HowTo: []string{
				"Check sshgate.status to see whether the server is Tier-1 or has a signer.",
				"Re-tiering a read-only server to signed-write is a manual human step (there is no in-place flip); do NOT auto-retry.",
			},
		}
	case VerdictRevealNeedsReason:
		return &Denial{
			VerdictClass:   VerdictRevealNeedsReason,
			Summary:        "A SECRET-REVEAL requires a non-empty reason for the human approver.",
			RequiredAction: ActionProvideReason,
			Retryable:      false,
			HowTo: []string{
				"Resubmit run with reveal=true and a non-empty reason explaining why the raw secret must be exposed.",
			},
		}
	default:
		return nil
	}
}
