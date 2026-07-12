package tools

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// RunInput is the JSON input to the sshgate.run tool. Schema:
//
//	{
//	  "type":"object",
//	  "required":["alias","command"],
//	  "properties":{
//	    "alias":{"type":"string"},
//	    "command":{"type":"string"},
//	    "reveal":{"type":"boolean"},
//	    "reason":{"type":"string"}
//	  }
//	}
type RunInput struct {
	Alias   string `json:"alias" jsonschema:"registered server alias (run sshgate.list_servers to see options)"`
	Command string `json:"command" jsonschema:"shell command to run on the remote host"`
	// Reveal requests a SECRET-REVEAL for THIS single command: its output is
	// run un-redacted so raw secret values reach you. It always requires a
	// separate, explicit human approval and forces the signed path even for a
	// read. It is single-command only (run_batch never reveals) and REQUIRES a
	// non-empty reason. Use it sparingly — the raw secret then reaches the AI
	// provider and the approval chat. Default false.
	Reveal bool `json:"reveal,omitempty" jsonschema:"request SECRET-REVEAL: run this one command's output WITHOUT redaction (raw secrets reach the agent). Requires reason. Single command only. Default false."`
	// Reason is the mandatory human-readable justification shown in the
	// reveal approval. Required when reveal is true; ignored otherwise.
	Reason string `json:"reason,omitempty" jsonschema:"why this secret must be revealed (required when reveal=true; shown to the human approver)"`
	// MaxOutputBytes optionally overrides the per-command output byte cap for
	// THIS call. Each of stdout and stderr is independently truncated to this
	// many bytes (a truncation marker naming the dropped/total byte counts is
	// appended and is NOT counted against the budget). Absent (nil) uses the
	// server default (256 KiB); 0 disables the cap (unlimited output). Raise
	// it only when you genuinely need the full output of a large read.
	MaxOutputBytes *int `json:"max_output_bytes,omitempty" jsonschema:"optional per-command output byte cap; each of stdout/stderr is truncated independently with a marker. Absent uses the server default (262144); 0 = unlimited."`
}

// RunOutput is the structured result. The MCP server layer also
// surfaces it as a TextContent block so older clients can see it.
type RunOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	// Kind is "read" or "write" — Claude can see whether the command
	// was routed through the approval flow.
	Kind string `json:"kind"`
	// Approved is true when a sign request was made and approved (i.e.
	// for writes). Reads are always direct, never solicited approval.
	Approved bool `json:"approved"`
	// Revealed is true when this command ran as a SECRET-REVEAL (its output
	// bypassed the gate's redactor). It is an indicator only — the raw output
	// already reached the agent — so downstream audit surfaces (the live log)
	// can record THAT a reveal happened while blanking the raw secret. Never
	// set on the read or ordinary-write paths.
	Revealed bool `json:"revealed,omitempty"`
	// AuthMode (F4) records HOW a write was authorised, threaded up from the
	// signer's socket response: "human" = a real-time Telegram tap;
	// "grant:<id>" = a standing-grant auto-sign; "" for reads (and an old
	// signer that omits it). It is metadata for the MCP live-log's
	// human-vs-grant distinction, not a secret. Never set on the read path.
	AuthMode string `json:"auth_mode,omitempty"`
	// Reason (#26, W2-4) names WHY a command was classified as a write — the
	// friendlier-denial aid from classify.Explain (e.g. "segment 2 `rm x`:
	// `rm` is not a recognized read utility"). Set on the write route only;
	// empty on reads and on the reveal route (a reveal is intentional, not a
	// misclassification). It is advisory MCP-side surfacing — the gate's
	// security decision stays on classify.Classify.
	Reason string `json:"reason,omitempty"`
	// Denial (#26-core) is the structured, agent-parseable verdict CLASS +
	// remedy when a command did not run and the agent must act (rephrase,
	// escalate, stop, retry once, or provide a reason). Nil on success and on
	// non-verdict infra errors. Additive and migration-neutral — see denial.go.
	// It is SET on every recognised refusal return; the MCP handler preserves
	// it even on the Go-error path (server.go runHandler) so it is not lost.
	Denial *Denial `json:"denial,omitempty"`
}

// SignClient is the subset of sign.Client that Runner needs. It
// exists so tests can inject a fake without standing up the
// signer socket.
type SignClient interface {
	// Sign returns a SignResult (the signed wire strings + the F4 auth-mode
	// marker reporting human-vs-grant) on approval, or a sentinel error.
	Sign(ctx context.Context, requestID string, cmds []signpkg.CmdReq) (signpkg.SignResult, error)
	// RequestGrant asks the signer to mint a standing grant (one human
	// approval → auto-sign matching writes for the window). Returns the
	// grant id + Unix expiry on approval.
	RequestGrant(ctx context.Context, requestID, alias, scope string, commands []string, durationSec int64) (grantID string, expiryUnix int64, err error)
	// RevokeGrant drops the standing grant for alias (de-escalation; no
	// approval needed).
	RevokeGrant(ctx context.Context, requestID, alias string) error
	// ListGrants reports the signer's in-memory LIVE standing grants
	// (optionally filtered to alias). Read-only: no approval, no backend.
	// Used to reconcile true grant state after a request_grant timeout.
	ListGrants(ctx context.Context, requestID, alias string) ([]signpkg.GrantInfo, error)
}

// SSHRunner is the subset of ssh.Client that Runner needs. It
// exists so tests can inject a fake without standing up an SSH
// server.
type SSHRunner interface {
	Run(ctx context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error)
}

// StdinRunner is the subset of ssh.Client that update_gate needs to stream
// the new gate binary on the SSH session's stdin. Kept separate from SSHRunner
// so the many SSHRunner fakes need no update.
type StdinRunner interface {
	RunWithStdin(ctx context.Context, host, user string, port int, cmd string, stdin io.Reader) ([]byte, []byte, int, error)
}

// TransferClient is the subset of sign.Client the transfer tool needs. It is
// kept SEPARATE from SignClient (rather than adding Transfer there) so the many
// SignClient fakes in the test tree need no update — the same StdinRunner
// precedent that avoided touching every SSHRunner fake.
type TransferClient interface {
	// Transfer requests a box→box SECRET TRANSFER approval (one human tap →
	// two signed, host-bound legs). The MCP passes fingerprints from its
	// trusted registry; the signer sources the pubkeys + mints the xferID.
	Transfer(ctx context.Context, requestID string, req signpkg.TransferReq) (signpkg.TransferResult, error)
}

// Runner is the sshgate.run tool implementation. All fields must be
// non-nil before calling Run; the MCP entry point sets them at
// startup.
type Runner struct {
	Servers *registry.Servers
	Sign    SignClient
	SSH     SSHRunner

	// SSHStdin streams the new gate binary on the SSH session's stdin. It is
	// used ONLY by update_gate (the one gated command that carries channel
	// stdin); every other path uses SSH. Production wires the same
	// *ssh.Client into both fields. A nil SSHStdin disables update_gate.
	SSHStdin StdinRunner

	// Xfer requests a box→box SECRET TRANSFER approval (one human tap → two
	// signed, host-bound legs). Used ONLY by the transfer tool. Production
	// wires the same *signpkg.Client already assigned to Sign. A nil Xfer
	// disables transfer.
	Xfer TransferClient

	// StagedGatePath is the absolute path to the operator's locally-staged
	// gate binary (what `make install-local` writes to
	// ~/.config/sshgate/bin/sshgate-gate-linux-amd64, or $SSHGATE_GATE_BIN).
	// update_gate reads it ONCE, hashes that buffer, and streams that same
	// buffer — the agent never supplies bytes or a hash (R5). Set by main; an
	// empty value disables update_gate with an actionable error.
	StagedGatePath string

	// KeyPath is the absolute path to the SSH private key used by the
	// SSH client. It is stored here so the run/run_batch paths can
	// produce an actionable "run /sshgate:setup" error when the key
	// file is absent, rather than surfacing an opaque open-failure.
	// Must match the path configured on the SSH field's underlying
	// client. Zero value disables the pre-flight check (tests that do
	// not care about this error shape may leave it empty).
	KeyPath string

	// WriteTTLSec is the signature validity window for writes,
	// passed to the daemon as ttl_seconds. Zero means
	// DefaultWriteTTLSec.
	WriteTTLSec int64

	// AddServerCfg holds local-path overrides (gate binary, signing
	// pubkey, SSHGate dedicated pubkey) for the shared provisioning
	// machinery. Tests inject this; production leaves it zero.
	AddServerCfg AddServerConfig

	// SignerSockPath is the absolute path to the signer Unix
	// socket. Status() dials this path to report signer reachability;
	// other tools route through Sign (which carries its own SocketPath).
	// Production wires the same path into both.
	SignerSockPath string

	// DefaultMaxOutputBytes is the default per-command output byte cap
	// applied to the STRUCTURED run/run_batch stdout and stderr (each
	// stream capped independently) when a call does not override it
	// (RunInput/RunBatchInput.MaxOutputBytes == nil). The truncation marker
	// is appended OUTSIDE this budget. Zero means uncapped — the value tests
	// leave when they do not set it, so their exact-output assertions are
	// unaffected; production wires DefaultOutputCapBytes. This cap lives in
	// the tools layer ONLY: it never reaches ssh.Client, so the update_gate
	// readback and the box→box transfer envelope are never touched.
	DefaultMaxOutputBytes int
}

// DefaultWriteTTLSec is the default sig-validity window for writes —
// long enough to cover dial+exec, well under sigwire.MaxSigValidity. Kept
// tight (60s) to shrink the window in which an approved signature could be
// replayed between the human's approval and gate execution; the gate still
// independently caps every window at sigwire.MaxSigValidity. Matches
// BatchWriteTTLSec so single and bulk writes share the same default window.
const DefaultWriteTTLSec = 60

// Run resolves the alias from the registry, classifies the command,
// and dispatches:
//   - read  → SSH directly with the literal command;
//   - write → Sign (one-cmd request), then SSH with the signed
//     wire prefix.
//
// Errors from Sign and SSH are wrapped (errors.Is preserves the
// sentinel). Unknown aliases produce a friendly error mentioning the
// alias by name.
func (r *Runner) Run(ctx context.Context, in RunInput) (RunOutput, error) {
	if r.Servers == nil {
		return RunOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RunOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return RunOutput{}, errors.New("tools: SSH is nil")
	}
	if strings.TrimSpace(in.Command) == "" {
		return RunOutput{}, errors.New("tools: command is empty")
	}
	if in.Alias == "" {
		return RunOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return RunOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	// Resolve the output cap once for this call (explicit override, else the
	// Runner default). Applied to the STRUCTURED stdout/stderr below.
	cap := r.effectiveOutputCap(in.MaxOutputBytes)

	// SECRET-REVEAL is signed-only: a reveal must carry a human approval that
	// the signer turns into a reveal=true signature, so it ALWAYS routes
	// through the sign path — even when the command classifies as a read (a
	// reveal of `cat secret.env` would otherwise run direct/unsigned and the
	// gate would never honour the flag). The reason is mandatory: reject here,
	// before any Telegram tap, so the agent always supplies a justification the
	// human can weigh.
	if in.Reveal {
		if strings.TrimSpace(in.Reason) == "" {
			return RunOutput{Denial: newDenial(VerdictRevealNeedsReason)},
				errors.New("tools: reveal requires a non-empty reason (a SECRET-REVEAL exposes raw secret values to the agent; the human approver needs to know why)")
		}
		// The reveal route is intentional, not a misclassification — no reason.
		return r.runWrite(ctx, in.Alias, entry, in.Command, true, in.Reason, "", cap)
	}

	// Explain returns the SAME Kind as Classify plus the first write reason
	// (#26). The gate's own decision path still runs classify.Classify; this is
	// an MCP-side surfacing only.
	kind, reason := classify.Explain(in.Command)
	rs := reason.String()
	switch kind {
	case classify.KindUnknown:
		// The classifier reports KindUnknown only for empty/whitespace
		// input — already handled above.
		return RunOutput{}, fmt.Errorf("tools: could not classify command %q", in.Command)
	case classify.KindRead:
		return r.runRead(ctx, entry, in.Command, cap)
	case classify.KindWrite:
		return r.runWrite(ctx, in.Alias, entry, in.Command, false, "", rs, cap)
	default:
		return RunOutput{}, fmt.Errorf("tools: unexpected classification %v", kind)
	}
}

func (r *Runner) runRead(ctx context.Context, e registry.Entry, cmd string, cap int) (RunOutput, error) {
	if err := r.checkKeyReady(); err != nil {
		return RunOutput{Kind: "read"}, err
	}
	stdout, stderr, exit, err := r.SSH.Run(ctx, e.Host, e.User, e.Port, cmd)
	outStr, _ := capOutput(string(stdout), cap)
	errStr, _ := capOutput(string(stderr), cap)
	if err != nil {
		return RunOutput{Stdout: outStr, Stderr: errStr, ExitCode: exit, Kind: "read"},
			fmt.Errorf("ssh exec: %w", err)
	}
	return RunOutput{
		Stdout:   outStr,
		Stderr:   errStr,
		ExitCode: exit,
		Kind:     "read",
		Approved: false,
	}, nil
}

// checkKeyReady returns an actionable error when Runner.KeyPath is set
// but the key file does not exist yet. This surfaces a "run
// /sshgate:setup" prompt to the model rather than an opaque
// open-failure from deep inside the SSH client.
func (r *Runner) checkKeyReady() error {
	if r.KeyPath == "" {
		return nil // pre-flight check disabled (tests or legacy callers)
	}
	if _, err := os.Stat(r.KeyPath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("tools: SSHGate has no SSH key yet — run /sshgate:setup to create it")
	}
	return nil
}

// runWrite runs a write through the sign path. classifyReason is the
// friendlier-denial string from classify.Explain (#26): it is threaded onto
// every RunOutput this returns and into the Tier-1 read-only refusal. Empty on
// the reveal route (a reveal is intentional, not a misclassification).
func (r *Runner) runWrite(ctx context.Context, alias string, e registry.Entry, cmd string, reveal bool, reason, classifyReason string, cap int) (RunOutput, error) {
	// Read-only servers have no signer pubkey on the host, so the gate
	// rejects every write (exit 77). Soliciting an approval first would
	// waste a real Telegram tap on a guaranteed no-op — short-circuit
	// with an actionable upgrade path instead.
	if e.ReadOnly {
		return RunOutput{Kind: "write", Reason: classifyReason, Denial: newDenial(VerdictReadOnlyServer)},
			readOnlyWriteErr(alias, classifyReason)
	}
	// A write before /sshgate:setup cannot succeed (no key, no signer):
	// surface the same actionable "run /sshgate:setup" guidance the read
	// path uses rather than a deeper, opaque failure.
	if err := r.checkKeyReady(); err != nil {
		return RunOutput{Kind: "write", Reason: classifyReason, Denial: newDenial(VerdictNoSignerConfigured)}, err
	}
	ttl := r.WriteTTLSec
	if ttl <= 0 {
		ttl = DefaultWriteTTLSec
	}
	reqID, err := newRequestID()
	if err != nil {
		return RunOutput{Kind: "write", Reason: classifyReason}, fmt.Errorf("tools: request id: %w", err)
	}
	// Spec defines CmdReq.Server as the registered alias (recorded in
	// the signer audit log), not the underlying hostname. Passing
	// the alias keeps audit-log archaeology stable across hostname
	// changes and matches the format the audit-log examples use.
	//
	// Host binds the signature to THIS server's TOFU-pinned host key. It is
	// read from the trusted registry entry IN CODE — the agent supplies only
	// (alias, command) and can never influence which host the approval binds
	// to. The gate self-derives its own host fingerprint and rejects a
	// signature whose binding names a different server (confused-deputy guard).
	// Reveal/Reason ride along ONLY on this single-command sign request — a
	// reveal is single-command by construction (run_batch carries no reveal).
	// The signer copies Reveal into the SIGNED payload; the gate enforces it.
	res, err := r.Sign.Sign(ctx, reqID, []signpkg.CmdReq{{Server: alias, Cmd: cmd, TTLSec: ttl, Host: e.Fingerprint, Reveal: reveal, Reason: reason}})
	if err != nil {
		// Preserve the sentinel for the MCP layer, but enrich the
		// message with actionable remediation (permission vs Tier-1 vs
		// dead daemon). r.remediateSignErr keeps errors.Is intact.
		return RunOutput{Kind: "write", Reason: classifyReason, Denial: r.denialForSignErr(err)}, r.remediateSignErr(err)
	}
	if len(res.Signed) != 1 {
		return RunOutput{Kind: "write", Reason: classifyReason}, fmt.Errorf("tools: expected 1 signature; got %d", len(res.Signed))
	}
	wireCmd := res.Signed[0].Sig + " " + cmd
	// authMode (F4) reports HOW the signer authorised this write — "human"
	// (real-time tap) or "grant:<id>" (standing-grant auto-sign); "" for an
	// old signer. It rides up into the live log's human-vs-grant field.
	authMode := res.AuthMode

	stdout, stderr, exit, err := r.SSH.Run(ctx, e.Host, e.User, e.Port, wireCmd)
	outStr, _ := capOutput(string(stdout), cap)
	errStr, _ := capOutput(string(stderr), cap)
	if err != nil {
		return RunOutput{Stdout: outStr, Stderr: errStr, ExitCode: exit, Kind: "write", Approved: true, Revealed: reveal, AuthMode: authMode, Reason: classifyReason},
			fmt.Errorf("ssh exec: %w", err)
	}
	// A gate deny comes back as err=nil with a raw non-zero exit. Annotate
	// the well-known gate codes so the model gets remediation rather than
	// a bare "exit 77/65".
	if note := gateDenyNote(exit); note != "" {
		return RunOutput{Stdout: outStr, Stderr: errStr, ExitCode: exit, Kind: "write", Approved: true, Revealed: reveal, AuthMode: authMode, Reason: classifyReason, Denial: denialForGateExit(exit)},
			fmt.Errorf("tools: %s", note)
	}
	return RunOutput{
		Stdout:   outStr,
		Stderr:   errStr,
		ExitCode: exit,
		Kind:     "write",
		Approved: true,
		Revealed: reveal,
		AuthMode: authMode,
		Reason:   classifyReason,
	}, nil
}

// readOnlyWriteErr is the actionable error for a write aimed at a
// server registered read-only (tier-1, no signer pubkey on the host). When
// reason is non-empty (#26), it names WHY the command classified as a write and
// nudges the agent to rephrase a genuine read — so a misclassified read on a
// Tier-1 host gets the friendlier guidance rather than only the re-provision
// path. Callers with no classification context pass "".
func readOnlyWriteErr(alias, reason string) error {
	base := fmt.Sprintf(
		"tools: server %q is registered read-only — writes are denied at the gate (no signer pubkey was pushed). %s",
		alias, retierManualPath(alias))
	if reason == "" {
		return fmt.Errorf("%s", base)
	}
	return fmt.Errorf(
		"%s — this command was classified as a write because: %s. If you intended a READ, rephrase (drop the redirect/compound/uncommon tool). For a genuine write, re-provision the server as signed-write (above).",
		base, reason)
}

// remediateSignErr enriches a sign-layer error with actionable
// remediation while preserving the underlying sentinel so the MCP layer
// (and tests) can still errors.Is() it. The signer socket path is
// stat'd to distinguish a never-configured Tier-1 install from a
// present-but-dead daemon.
func (r *Runner) remediateSignErr(err error) error {
	switch {
	case errors.Is(err, signpkg.ErrVerdictUnknown):
		// FAIL-SAFE: the signer reached a decision but its response never
		// arrived (the connection dropped/timed out after the request was
		// sent). A human may have DENIED this write — auto-retrying could
		// re-attempt something a human explicitly refused. Tell the agent to
		// STOP and verify out-of-band before resubmitting. Sentinel preserved.
		return fmt.Errorf(
			"tools: the signer reached a decision but the response did not arrive — a human may have DENIED this write. Do NOT auto-retry. Check sshgate.status and the Telegram approval thread to confirm the verdict before resubmitting: %w",
			err)
	case errors.Is(err, signpkg.ErrSignerPermission):
		return fmt.Errorf(
			"tools: signer socket %s is present but not accessible (permission denied) — your shell/session is not yet in the sshgatesigner group. Log out and back in, then relaunch Claude Code, before writes will work: %w",
			r.SignerSockPath, err)
	case errors.Is(err, signpkg.ErrUnreachable):
		if r.signerSocketPresent() {
			return fmt.Errorf(
				"tools: signer socket %s is present but not accepting connections — check `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`: %w",
				r.SignerSockPath, err)
		}
		return fmt.Errorf(
			"tools: no signer configured (Tier-1 read-only). Writes need a Telegram signer — a human runs /sshgate:setup to install one, then re-tiers each read-only server. %s: %w",
			retierManualPath("<alias>"), err)
	default:
		// Denials, timeouts, daemon errors: wrap once, preserve sentinel.
		return fmt.Errorf("tools: sign: %w", err)
	}
}

// denialForSignErr maps a sign-layer sentinel to its structured Denial
// (#26-core), parallel to remediateSignErr's prose mapping. It reuses
// signerSocketPresent to split ErrUnreachable into "daemon down" (socket
// present) vs "no signer / Tier-1" (socket absent), matching the prose. A
// non-sentinel (generic daemon) error yields nil — no structured verdict, prose
// only. Retryable/action live in newDenial: only approval_timeout is retryable
// among these (approval_denied / verdict_unknown are stop_do_not_retry).
func (r *Runner) denialForSignErr(err error) *Denial {
	switch {
	case errors.Is(err, signpkg.ErrVerdictUnknown):
		return newDenial(VerdictUnknown)
	case errors.Is(err, signpkg.ErrSignerPermission):
		return newDenial(VerdictSignerPermission)
	case errors.Is(err, signpkg.ErrUnreachable):
		if r.signerSocketPresent() {
			return newDenial(VerdictSignerUnreachable)
		}
		return newDenial(VerdictNoSignerConfigured)
	case errors.Is(err, signpkg.ErrDenied):
		return newDenial(VerdictApprovalDenied)
	case errors.Is(err, signpkg.ErrTimeout):
		return newDenial(VerdictApprovalTimeout)
	default:
		return nil
	}
}

// denialForGateExit maps a well-known gate deny exit code to its structured
// Denial (#26-core), parallel to gateDenyNote's prose. 77 = missing signature /
// read-only host (escalate_to_human, NOT retryable — the MCP already signed a
// Tier-2 write, so 77 means tier mismatch / stripped sig, and re-soliciting a
// fresh tap would loop); 65 = bad/expired signature (retry once). Any other exit
// is not a gate deny and yields nil.
func denialForGateExit(exit int) *Denial {
	switch exit {
	case 77:
		return newDenial(VerdictMissingSignature)
	case 65:
		return newDenial(VerdictBadSignature)
	default:
		return nil
	}
}

// signerSocketPresent reports whether the signer socket file exists on
// disk. An empty SignerSockPath (tests / legacy callers) reports false
// so the Tier-1 message is used.
func (r *Runner) signerSocketPresent() bool {
	if r.SignerSockPath == "" {
		return false
	}
	_, err := os.Stat(r.SignerSockPath)
	return err == nil
}

// gateDenyNote returns a remediation string for the well-known gate
// deny exit codes, or "" for any other exit. The gate returns these on
// a WRITE with err=nil and a raw non-zero exit:
//   - 77: missing signature / read-only (no signer pubkey on host).
//   - 65: bad / expired signature (clock skew or stale approval).
//
// The string carries no package prefix so callers can embed it in an
// error ("tools: <note>") or in a result's Stderr verbatim.
func gateDenyNote(exit int) string {
	switch exit {
	case 77:
		return "gate denied this write (exit 77): the server has no signer pubkey (read-only / Tier-1) OR the signature was missing. Check sshgate.status. " + retierManualPath("<alias>")
	case 65:
		return "gate rejected the signature (exit 65): expired or invalid — usually clock skew or a stale approval; retry."
	default:
		return ""
	}
}

// appendNote joins a remediation note onto an existing stderr block,
// inserting a newline separator only when stderr is non-empty so the
// note is always on its own line.
func appendNote(stderr, note string) string {
	if stderr == "" {
		return note
	}
	if strings.HasSuffix(stderr, "\n") {
		return stderr + note
	}
	return stderr + "\n" + note
}

// newRequestID returns a short random identifier prefixed with "r_"
// (matching the audit-log naming convention in the spec). 12 bytes
// of entropy is ~96 bits — plenty for correlating a sign request
// over the socket within a session.
func newRequestID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "r_" + base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
