package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/src/classify"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// RunBatchInput is the JSON input to the sshgate.run_batch tool.
//
// StopOnError controls whether the sequence aborts at the first non-zero
// exit. A pointer lets the caller distinguish "explicitly set" from "not
// provided". When nil, the default depends on the BATCH CLASS: a batch
// containing ANY write defaults to true (stop-on-error — write ordering
// usually matters, so aborting on the first failure is safest), while an
// ALL-READ batch defaults to false (continue-on-error — reads are
// independent diagnostics that legitimately exit non-zero, e.g. an absent
// file or an empty crontab, and one failure should not skip the rest). An
// explicit caller value always wins, in both directions.
type RunBatchInput struct {
	Alias       string   `json:"alias" jsonschema:"registered server alias"`
	Commands    []string `json:"commands" jsonschema:"shell commands to run on the remote host, in order"`
	StopOnError *bool    `json:"stop_on_error,omitempty" jsonschema:"abort the sequence at the first non-zero exit. When omitted the default is chosen by batch class: true for a batch containing any write (ordering matters), false (continue) for an all-read batch. Set explicitly to override."`
	// MaxOutputBytes optionally overrides the per-command output byte cap for
	// THIS batch. Each command's stdout and stderr is independently truncated
	// to this many bytes (a truncation marker naming the dropped/total byte
	// counts is appended and is NOT counted against the budget). Absent (nil)
	// uses the server default (256 KiB); 0 disables the cap (unlimited).
	MaxOutputBytes *int `json:"max_output_bytes,omitempty" jsonschema:"optional per-command output byte cap; each command's stdout/stderr is truncated independently with a marker. Absent uses the server default (262144); 0 = unlimited."`
}

// CommandResult is the per-command outcome inside a RunBatchOutput.
type CommandResult struct {
	Command  string `json:"command"`
	Kind     string `json:"kind"` // "read" | "write"
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	// Skipped is true when stop_on_error=true and a previous command
	// exited non-zero (so this one never ran).
	Skipped bool `json:"skipped"`
	// Revealed mirrors RunOutput.Revealed: true iff this command ran as a
	// SECRET-REVEAL. run_batch NEVER reveals by design (bulk reveal is
	// forbidden), so this is always false today — the field exists so the
	// live-log hook treats batch and single-command results uniformly and
	// stays correct if a batch reveal path is ever (wrongly) added.
	Revealed bool `json:"revealed,omitempty"`
	// Reason (#26, W2-4) names WHY this command classified as a write — the
	// friendlier-denial aid from classify.Explain. Set on write results only;
	// empty on reads. Advisory MCP-side surfacing (the gate re-classifies with
	// classify.Classify).
	Reason string `json:"reason,omitempty"`
}

// RunBatchOutput is the structured result returned to the MCP client.
type RunBatchOutput struct {
	Server  string          `json:"server"`
	Results []CommandResult `json:"results"`
	// Approved is true iff a sign request was made and approved (i.e.
	// the batch contained at least one write that ran).
	Approved bool `json:"approved"`
	// Denied is true when approval was denied / timed out / the daemon
	// was unreachable. In that case Results is empty and Reason carries
	// a short machine-readable string.
	Denied bool   `json:"denied,omitempty"`
	Reason string `json:"reason,omitempty"`
	// AuthMode (F4) reports HOW the batch's writes were authorised — "human"
	// (one real-time tap) or "grant:<id>" (a standing-grant auto-sign); empty
	// for a read-only batch or an old signer. The ONE sign request covers all
	// writes, so a single batch-level value applies to every write result;
	// reads carry no auth mode.
	AuthMode string `json:"auth_mode,omitempty"`
}

// BatchWriteTTLSec is the per-command TTL used when building a bulk
// sign request. The spec uses 60s for bulk; the signer caps this
// against sigwire.MaxSigValidity server-side anyway.
const BatchWriteTTLSec = 60

// RunBatch executes a sequence of commands against the alias's host.
//
// Semantics (locked by Task 2.3):
//   - Classify each command locally.
//   - All reads → execute directly, no sign call.
//   - Any writes → ONE sign request covering all writes (reads stay
//     unsigned). Reads execute in place; writes execute with their
//     signed wire prefix in the original positional order.
//   - StopOnError=true aborts at the first non-zero exit and marks the
//     remainder Skipped=true. When the caller omits it, the default is
//     chosen by batch class: true for a batch containing any write
//     (ordering matters), false for an all-read batch (reads are
//     independent diagnostics). An explicit value always wins.
//   - StopOnError=false runs every command regardless of prior exits.
//   - Denial / timeout / unreachable: no writes run; the output has
//     Denied=true and Reason∈{"denied","timeout","unreachable"}.
//     Results is empty in that case (the spec's "in that case Results
//     is empty" — we don't surface partial reads to keep the contract
//     simple and predictable).
//   - Empty Commands → empty Results, no calls.
func (r *Runner) RunBatch(ctx context.Context, in RunBatchInput) (RunBatchOutput, error) {
	if r.Servers == nil {
		return RunBatchOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RunBatchOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return RunBatchOutput{}, errors.New("tools: SSH is nil")
	}
	if in.Alias == "" {
		return RunBatchOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return RunBatchOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	out := RunBatchOutput{Server: in.Alias}
	if len(in.Commands) == 0 {
		return out, nil
	}

	// Classify all commands up front so we can decide whether to
	// solicit approval. Explain also yields the #26 friendlier-denial reason
	// per command (same Kind as Classify; the gate re-classifies with Classify).
	kinds := make([]classify.Kind, len(in.Commands))
	reasons := make([]classify.Reason, len(in.Commands))
	for i, c := range in.Commands {
		if strings.TrimSpace(c) == "" {
			return RunBatchOutput{}, fmt.Errorf("tools: commands[%d] is empty", i)
		}
		kinds[i], reasons[i] = classify.Explain(c)
	}

	// Build the (compact) list of writes plus their positions in the
	// original sequence. Reads stay in place; writes get a signature.
	var writeCmds []signpkg.CmdReq
	var writeIdx []int
	for i, cmd := range in.Commands {
		if kinds[i] == classify.KindWrite {
			// Spec defines CmdReq.Server as the registered alias
			// (recorded in the signer audit log), not the
			// underlying hostname. Passing the alias keeps audit-log
			// archaeology stable across hostname changes.
			//
			// Host binds each signature to this server's TOFU-pinned host
			// key, read from the trusted registry entry IN CODE (never an
			// agent parameter), so the gate can enforce the per-server
			// binding and a bulk approval cannot be replayed on another host.
			writeCmds = append(writeCmds, signpkg.CmdReq{
				Server: in.Alias,
				Cmd:    cmd,
				TTLSec: BatchWriteTTLSec,
				Host:   entry.Fingerprint,
			})
			writeIdx = append(writeIdx, i)
		}
	}

	// Slot per-position signatures so step 2 can look up by index.
	signedByIdx := make(map[int]string)
	if len(writeCmds) > 0 {
		// Read-only servers have no signer pubkey on the host, so every
		// write gate-rejects (exit 77). Refuse BEFORE soliciting an
		// approval so we never waste a Telegram tap on a guaranteed
		// no-op; surface the upgrade path instead.
		if entry.ReadOnly {
			// Name why the FIRST write classified as a write (#26) so a
			// misclassified read in the batch gets the rephrase nudge too.
			return RunBatchOutput{}, readOnlyWriteErr(in.Alias, reasons[writeIdx[0]].String())
		}
		// A write before /sshgate:setup cannot succeed (no key, no
		// signer): surface the same actionable "run /sshgate:setup"
		// guidance the read path uses.
		if err := r.checkKeyReady(); err != nil {
			return RunBatchOutput{}, err
		}
		reqID, err := newRequestID()
		if err != nil {
			return RunBatchOutput{}, fmt.Errorf("tools: request id: %w", err)
		}
		res, err := r.Sign.Sign(ctx, reqID, writeCmds)
		if err != nil {
			// Map the sentinel to a short Reason; the tool layer
			// returns the structured Denied result rather than a Go
			// error so the model can read the reason cleanly. The
			// human-facing remediation rides in out.Reason too.
			out.Reason = r.classifySignErrReason(err)
			out.Denied = true
			return out, nil
		}
		if len(res.Signed) != len(writeCmds) {
			return RunBatchOutput{}, fmt.Errorf("tools: expected %d signatures; got %d", len(writeCmds), len(res.Signed))
		}
		for i, s := range res.Signed {
			signedByIdx[writeIdx[i]] = s.Sig + " " + writeCmds[i].Cmd
		}
		// AuthMode (F4) reports HOW the batch's writes were authorised — "human"
		// (one tap) or "grant:<id>" (auto-signed). It rides up into each write
		// result's live-log entry. Reads have no auth mode.
		out.AuthMode = res.AuthMode
		out.Approved = true
	}

	// Default StopOnError is chosen by batch class: a batch with ANY write
	// stops on error (write ordering matters); an ALL-READ batch continues
	// on error (reads are independent diagnostics that legitimately exit
	// non-zero — an absent file, an empty crontab — so one failure should
	// not skip the rest). writeCmds is already computed above, so
	// len(writeCmds)==0 is exactly "all reads". An explicit caller value
	// always wins, in both directions.
	stopOnError := len(writeCmds) > 0
	if in.StopOnError != nil {
		stopOnError = *in.StopOnError
	}

	// Resolve the output cap once for the whole batch (explicit override,
	// else the Runner default). Applied per-command to the structured
	// stdout/stderr below.
	cap := r.effectiveOutputCap(in.MaxOutputBytes)

	out.Results = make([]CommandResult, len(in.Commands))
	aborted := false
	for i, cmd := range in.Commands {
		out.Results[i].Command = cmd
		out.Results[i].Kind = kindLabel(kinds[i])
		if kinds[i] == classify.KindWrite {
			out.Results[i].Reason = reasons[i].String()
		}
		if aborted {
			out.Results[i].Skipped = true
			continue
		}
		wireCmd := cmd
		if w, ok := signedByIdx[i]; ok {
			wireCmd = w
		}
		stdout, stderr, exit, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, wireCmd)
		outStr, _ := capOutput(string(stdout), cap)
		errStr, _ := capOutput(string(stderr), cap)
		out.Results[i].Stdout = outStr
		out.Results[i].Stderr = errStr
		out.Results[i].ExitCode = exit
		if err != nil {
			// SSH transport-layer error: surface as the rest of the
			// batch being aborted. We keep what we have so the caller
			// sees the partial state plus the wrapped error.
			return out, fmt.Errorf("ssh exec [%d]: %w", i, err)
		}
		// A gate deny (exit 77/65) comes back as err=nil with a raw
		// non-zero exit. Annotate the well-known codes into the result's
		// Stderr (write-only) so the model sees remediation, not a bare
		// non-zero exit.
		if kinds[i] == classify.KindWrite {
			if note := gateDenyNote(exit); note != "" {
				out.Results[i].Stderr = appendNote(out.Results[i].Stderr, note)
			}
		}
		if exit != 0 && stopOnError {
			aborted = true
		}
	}
	return out, nil
}

// classifySignErr maps a sign-layer error to one of {"denied",
// "timeout", "permission", "unreachable", "verdict_unknown", "error"} for
// the structured output.
func classifySignErr(err error) string {
	switch {
	case errors.Is(err, signpkg.ErrDenied):
		return "denied"
	case errors.Is(err, signpkg.ErrTimeout):
		return "timeout"
	case errors.Is(err, signpkg.ErrSignerPermission):
		return "permission"
	case errors.Is(err, signpkg.ErrUnreachable):
		return "unreachable"
	case errors.Is(err, signpkg.ErrVerdictUnknown):
		// FAIL-SAFE token: the signer decided but the response was lost.
		// Distinct from the generic "error" bucket so the agent does NOT
		// treat it as a retryable transport blip (a human may have denied).
		return "verdict_unknown"
	default:
		return "error"
	}
}

// classifySignErrReason produces the Reason string carried in a denied
// RunBatchOutput. For denial/timeout it keeps the short machine-readable
// token; for the actionable cases (permission, Tier-1-vs-dead-daemon)
// it returns the full remediation sentence the run path uses so the
// model gets the same guidance regardless of which tool was called.
func (r *Runner) classifySignErrReason(err error) string {
	switch {
	case errors.Is(err, signpkg.ErrVerdictUnknown):
		// FAIL-SAFE: keep the machine-readable token AND spell out the
		// do-not-retry guidance so the agent treats a lost verdict as a
		// possible human DENY, not a retryable error.
		return "verdict_unknown: the signer reached a decision but the response did not arrive — a human may have DENIED this. Do NOT auto-retry. Check sshgate.status and the Telegram approval thread before resubmitting."
	case errors.Is(err, signpkg.ErrSignerPermission):
		return fmt.Sprintf(
			"signer socket %s is present but not accessible (permission denied) — your shell/session is not yet in the sshgatesigner group. Log out and back in, then relaunch Claude Code, before writes will work.",
			r.SignerSockPath)
	case errors.Is(err, signpkg.ErrUnreachable):
		if r.signerSocketPresent() {
			return fmt.Sprintf(
				"signer socket %s is present but not accepting connections — check `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.",
				r.SignerSockPath)
		}
		return "no signer configured (Tier-1 read-only). Writes need a Telegram signer — a human runs /sshgate:setup to install one, then re-tiers each read-only server. " + retierManualPath("<alias>")
	default:
		return classifySignErr(err)
	}
}

// kindLabel returns the JSON-side string for a classifier Kind. For
// the batch path KindUnknown should never reach here (we rejected
// blanks upstream), but if it ever did we'd label it "unknown" rather
// than panic.
func kindLabel(k classify.Kind) string {
	switch k {
	case classify.KindRead:
		return "read"
	case classify.KindWrite:
		return "write"
	default:
		return "unknown"
	}
}
