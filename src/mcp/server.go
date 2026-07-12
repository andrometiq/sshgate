package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp/livelog"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// isCleanShutdown reports whether err is one of the expected
// transport-closing signals: stdin EOF, ctx cancellation, or the
// SDK's ErrConnectionClosed sentinel. Any of these is a clean
// shutdown of the MCP session, not a runtime failure.
func isCleanShutdown(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, mcpsdk.ErrConnectionClosed) {
		return true
	}
	// The SDK wraps EOF into "server is closing: EOF" via the
	// jsonrpc2 error chain — we accept the textual form as a
	// last-resort match because the wrapper does not always
	// preserve io.EOF.
	if msg := err.Error(); strings.Contains(msg, "server is closing") || strings.Contains(msg, "EOF") {
		return true
	}
	return false
}

// Version is the SSHGate MCP server's reported version string. It
// flows into the JSON-RPC initialize response and from there into
// Claude Code's session log.
//
// It is a var, not a const, so the build stamps it from the single
// VERSION file at link time via -ldflags
// "-X github.com/karthikeyan5/sshgate/src/mcp.Version=<VERSION>"
// (Makefile MCP_VERSION_FLAGS). Unstamped builds — `go test`, a plain
// `go build` — keep the "dev" default; a wrong -X symbol path is
// silently ignored by the linker, so `make verify-versions` builds and
// runs the binary to prove the stamp actually landed. This keeps the
// handshake version in lockstep with VERSION and forbids the old drift
// (a hardcoded 0.2.0 while VERSION said 0.1.4). TestVersionDefault guards
// that the source default stays "dev".
var Version = "dev"

// ServerName MUST equal the .mcp.json key. Claude Code routes tool
// names by "mcp__<ServerName>__<tool>" — a mismatch causes silent
// drops (plugin.md §3.1).
const ServerName = "sshgate"

// ToolName is the un-namespaced tool name registered with the SDK.
// Claude Code's surface name is "mcp__sshgate__run".
const ToolName = "run"

// ToolNameRunBatch is the un-namespaced batch tool name. Claude Code's
// surface name is "mcp__sshgate__run_batch".
const ToolNameRunBatch = "run_batch"

// ToolNameListServers lists registered server aliases with their
// connection details. Claude Code's surface name is
// "mcp__sshgate__list_servers".
const ToolNameListServers = "list_servers"

// ToolNameStatus reports signer-socket and per-server reachability.
// Claude Code's surface name is "mcp__sshgate__status".
const ToolNameStatus = "status"

// ToolNamePing probes reachability of ONE named server (READ-class, no
// approval, no signer) — a targeted alternative to status's fan-out.
// Claude Code's surface name is "mcp__sshgate__ping".
const ToolNamePing = "ping"

// ToolNameRevokeServer tears down a registered server: signs and ships
// SSHGATE_REVOKE, lets gate strip itself from authorized_keys and
// remove ~/.sshgate-gate/, then removes the alias from the registry. Claude
// Code's surface name is "mcp__sshgate__revoke_server".
const ToolNameRevokeServer = "revoke_server"

// ToolNameRequestGrant requests a STANDING GRANT on a server: ONE human
// Telegram approval lets the signer auto-sign matching writes for the
// window without further taps. Claude Code's surface name is
// "mcp__sshgate__request_grant".
const ToolNameRequestGrant = "request_grant"

// ToolNameRevokeGrant drops a server's standing grant (de-escalation; no
// approval). Claude Code's surface name is "mcp__sshgate__revoke_grant".
const ToolNameRevokeGrant = "revoke_grant"

// ToolNameListGrants reports the signer's in-memory LIVE standing grants
// (read-only; no approval). It lets the agent reconcile true grant state
// after a request_grant whose verdict-write was lost (the phantom-live
// grant). Claude Code's surface name is "mcp__sshgate__list_grants".
const ToolNameListGrants = "list_grants"

// ToolNameUpdateGate requests a SIGNED, in-place update of the gate binary on
// an already-registered server: the MCP hashes the operator's locally-staged
// gate binary and asks for a signature bound to that exact SHA-256, which the
// operator must approve via a distinct, scary "GATE BINARY UPDATE" Telegram
// banner. The agent supplies only the alias — never bytes or a hash — and
// provisioning stays human-only, so this does not expand the agent's reach.
// Claude Code's surface name is "mcp__sshgate__update_gate".
const ToolNameUpdateGate = "update_gate"

// ToolNameTransfer moves a secret file host→host, end-to-end encrypted through
// the gate: the source gate seals the value, the MCP relays only ciphertext,
// the destination gate opens it — the plaintext never reaches the agent. It
// takes ONE human Telegram approval of a distinct "SECRET TRANSFER" banner.
// Claude Code's surface name is "mcp__sshgate__transfer".
const ToolNameTransfer = "transfer"

// serverInstructions is the MCP server-level prompt surfaced to the agent
// at initialize. It teaches the agent how the gate's read/write split
// behaves so it doesn't accidentally turn cheap inventory reads into
// approval-gated writes.
const serverInstructions = `SSHGate runs commands on registered servers through a security gate.

READ commands run immediately, no approval. WRITE commands require a human Telegram approval tap.

The gate FAILS CLOSED: a command is treated as a read ONLY when every part of it is a recognized read. Anything it cannot confirm — an uncommon/unknown utility, a redirect (>), or any segment that writes — makes the WHOLE command count as a write and routes it to approval. Guidance:
- Prefer ONE simple command per call, using common read tools (ls, cat, stat, df, du, free, uptime, ps, ss, ip, journalctl, systemctl list-units / status). A simple pipe between read tools (e.g. "ps aux | grep x") is fine.
- For inventory/diagnostics, send SEPARATE read calls instead of chaining with &&, ||, ';', or wrapping in test/sh -c — a compound that includes any non-read or unknown segment will be classified a write and need a tap.
- If a command you intended as a read is refused as a write, simplify it (drop the redirect/compound/uncommon tool) rather than retrying.
- For genuine writes, batch them into run_batch so all writes in a task share ONE approval tap, and always show the user the planned writes first.
- Writes to a read-only (Tier-1) server are refused locally before any tap.
- Every write result now carries a "reason" naming the segment/rule that made it a write. If a command you meant as a read shows a write reason, rephrase per the reason — this now covers sed scripts, uncommon tools, redirects and substitutions, not just the cases listed above.`

// Server is the MCP front-end. It owns a single tool implementation
// (the Runner) and is configured by main. Logger is the operator-side
// log target; it MUST write to stderr (stdout is the JSON-RPC
// channel).
//
// LiveLog is the Tier-6b MCP-side rolling live log (the convenience /
// `tail -f` view). It is OPTIONAL — a nil LiveLog is a valid no-op (Log
// does nothing), so tests and a "disabled" config both leave it nil. It
// is NOT the system of record; that is the gate-side authoritative log.
type Server struct {
	Runner  *tools.Runner
	Logger  *log.Logger
	LiveLog *livelog.Log

	// RedactSalt + RedactRules scrub a secret embedded in the COMMAND
	// STRING before it is written to the Tier-6b live log (F5). The salt is
	// a per-process random 32 bytes generated ONCE at startup; the ruleset
	// is rules.Combined() compiled ONCE at startup (the MCP is a
	// long-running daemon — never compile per-command). Both are wired by
	// main. A zero salt + nil rules is a valid no-op: RedactString
	// fast-paths nil rules and logs the command verbatim, so a Server built
	// without them (older tests) still works.
	RedactSalt  [32]byte
	RedactRules []redact.Rule
}

// redactCommand scrubs a command string about to be written to the live
// log, reusing the server's per-process salt + compiled ruleset. FAIL-OPEN:
// if RedactString reports an internal error, the raw command is logged
// rather than the audit line being dropped. A benign command (no secret
// pattern) and a server with no ruleset wired both return the input
// unchanged.
func (s *Server) redactCommand(cmd string) string {
	red, ok := redact.RedactString(cmd, s.RedactSalt, s.RedactRules)
	if !ok {
		return cmd
	}
	return red
}

// Serve runs the MCP server over the provided stdio pipes. It
// returns nil on clean shutdown (ctx cancelled or stdin EOF) and a
// non-nil error otherwise.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Runner == nil {
		return errors.New("mcp: Runner is nil")
	}
	if s.Logger == nil {
		return errors.New("mcp: Logger is nil")
	}

	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    ServerName,
		Version: Version,
	}, &mcpsdk.ServerOptions{Instructions: serverInstructions})

	// Register the run tool using the generic AddTool helper so the
	// SDK derives the input schema from RunInput automatically.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolName,
		Description: "Run a shell command on a registered server. Read commands run directly; write commands request human approval (a Telegram tap) before running.",
	}, s.runHandler)

	// run_batch — same approval engine, but one Telegram tap covers
	// the whole batch of writes (reads stay direct).
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameRunBatch,
		Description: "Run a sequence of shell commands on a registered server. Reads run directly; all writes are bundled into a single approval (one Telegram tap). stop_on_error defaults to true for a batch containing any write (ordering matters) and to continue-on-error for an all-read batch; set stop_on_error explicitly to override.",
	}, s.runBatchHandler)

	// Provisioning is intentionally NOT exposed to the agent: server
	// registration + gate install is a human-only action, performed via
	// the standalone `sshgate` CLI (`sshgate pubkey` + `sshgate add`). The
	// install logic lives in tools.Provision, driven by that CLI.

	// list_servers — returns every registered alias with its host/port/user.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameListServers,
		Description: "List every registered SSHGate server (alias, host, port, user, added_at). Output is sorted alphabetically by alias.",
	}, s.listServersHandler)

	// status — health probe of signer and every registered server.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameStatus,
		Description: "Report signer-socket reachability and per-server SSH reachability (via the SSHGATE_OK probe), plus each server's read_only tier. Server probes run in parallel with a short timeout.",
	}, s.statusHandler)

	// ping — reachability of ONE named server. READ-class by construction
	// (empty SSHGATE_OK probe, no signer, no approval, no tap); use it to
	// check a single box without status's fan-out across every server.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNamePing,
		Description: "Check whether ONE registered server is reachable (single SSH dial + SSHGATE_OK probe, short 5s timeout). Read-only: runs immediately, never requests approval and never involves the signer. Unlike status, it probes only the alias you name instead of fanning out across every server. Returns reachability, round-trip ms, and the server's read_only tier.",
	}, s.pingHandler)

	// revoke_server — signs SSHGATE_REVOKE, ships it, removes the alias
	// from the registry once gate confirms the on-host teardown.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameRevokeServer,
		Description: "Revoke a registered server. Signs SSHGATE_REVOKE (one approval), gate strips its authorized_keys line and removes ~/.sshgate-gate/, MCP removes the alias. Backup kept at ~/.ssh/authorized_keys.sshgate-revoke-backup.",
	}, s.revokeServerHandler)

	// request_grant — REQUESTS a standing grant. It needs a human Telegram
	// approval of a distinct "STANDING GRANT" message; the agent cannot
	// self-grant. Once approved, matching writes auto-sign for the window.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name: ToolNameRequestGrant,
		Description: "Request a STANDING GRANT on a server so matching writes auto-sign for a window (1-24h) without a tap each. " +
			"This REQUIRES a human to approve a distinct \"STANDING GRANT\" Telegram message — you CANNOT create a grant yourself; you only request one. " +
			"scope=\"commands\" auto-signs ONLY the exact command strings you list (exact match, no patterns) — prefer this. " +
			"scope=\"all\" auto-signs EVERY write on the alias — use it ONLY for a throwaway/dedicated target, never a server holding anything that matters. " +
			"The grant dies on signer restart and can be revoked with revoke_grant. Always show the user the exact scope + commands before requesting.",
	}, s.requestGrantHandler)

	// revoke_grant — drops a standing grant. Pure de-escalation: it only
	// shrinks capability, so it needs no approval and is always safe.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameRevokeGrant,
		Description: "Revoke (drop) a server's standing grant so writes prompt for approval again. De-escalation only — always safe, needs no approval, and is a no-op if no grant exists.",
	}, s.revokeGrantHandler)

	// list_grants — reports the signer's in-memory LIVE standing grants.
	// READ-ONLY: no approval, no capability granted, no key material — it
	// only reports state. Use it to reconcile after a request_grant timeout:
	// if the verdict-write was lost the grant can be live while the agent saw
	// only an error, and this is the way to re-learn its id / scope / expiry.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameListGrants,
		Description: "List live standing grants the signer currently holds (optionally filtered to one alias). Read-only, no approval, always safe. Use it to reconcile after a request_grant timeout — a grant can be live even though you saw an error, and this re-learns its grant_id, scope, and expiry. Expired grants are never listed; grants die on signer restart.",
	}, s.listGrantsHandler)

	// update_gate — REQUESTS a SIGNED, in-place update of the gate binary on an
	// already-registered server. The MCP hashes the operator's locally-staged
	// gate binary; the operator must approve a distinct, alarming "GATE BINARY
	// UPDATE" Telegram banner bound to that exact SHA-256. The agent supplies
	// ONLY the alias — never binary bytes or a hash. It does not expand the
	// agent's reach: no new server is onboarded (provisioning stays human-only),
	// and a standing grant can never auto-sign it, so the agent can never cause
	// arbitrary code to run.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name: ToolNameUpdateGate,
		Description: "Request a SIGNED, in-place update of the gate binary on an already-registered server. " +
			"You supply ONLY the alias — never binary bytes or a hash: the MCP reads the operator's locally-staged gate binary, computes its SHA-256, and requests a signature bound to that exact hash. " +
			"A human MUST approve a distinct, scary \"GATE BINARY UPDATE\" Telegram banner showing that hash + build revision; a standing grant can NEVER auto-sign it. " +
			"The gate re-hashes the bytes it receives and refuses on mismatch, so an approval authorizes exactly that one binary. " +
			"This does not expand your reach — no new server is onboarded (provisioning stays the human-only sshgate CLI). Read-only (Tier-1) servers are refused before any tap.",
	}, s.updateGateHandler)

	// transfer — moves a secret file host→host, END-TO-END ENCRYPTED through the
	// gate. The source gate seals the value to the destination's registered key,
	// the MCP relays ONLY the ciphertext (SEND stdout → RECV stdin), and the
	// destination gate opens it — the plaintext NEVER reaches the agent. One
	// human Telegram approval of a distinct "SECRET TRANSFER" banner covers both
	// signed, host-bound legs; a standing grant can never auto-sign it.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name: ToolNameTransfer,
		Description: "Move a secret file from one registered server to another, END-TO-END ENCRYPTED through the gate. " +
			"You supply ONLY the source/destination aliases + absolute paths (and an optional octal mode, default 0600) — never keys, fingerprints, or an id. " +
			"The source gate encrypts the value to the destination's registered key; this tool relays ONLY the ciphertext; the destination gate decrypts and writes it. The secret value NEVER reaches you or any log — you get metadata only (xfer id, byte count). " +
			"A human MUST approve a distinct \"SECRET TRANSFER\" Telegram banner (both source and destination must be registered for transfer); a standing grant can NEVER auto-sign it. Read-only (Tier-1) servers are refused before any tap.",
	}, s.transferHandler)

	t := &mcpsdk.IOTransport{
		Reader: readerCloser{in},
		Writer: writerCloser{out},
	}
	if err := server.Run(ctx, t); err != nil {
		if isCleanShutdown(err) {
			return nil
		}
		return err
	}
	return nil
}

// runHandler is the typed tool handler bound to ToolName. It
// delegates to the Runner and surfaces any error as an MCP tool
// error (which the SDK packs into IsError=true on the result).
func (s *Server) runHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunInput) (*mcpsdk.CallToolResult, tools.RunOutput, error) {
	out, err := s.Runner.Run(ctx, in)
	if err != nil {
		// Log to stderr so an operator running the binary by hand sees
		// the failure; the model gets the structured tool error from
		// the SDK.
		s.Logger.Printf("run alias=%s err=%v", in.Alias, err)
		// #26-core: a RECOGNISED verdict/refusal carries a structured Denial.
		// Preserve it AND the IsError semantics + prose text: return err=nil so
		// the SDK does not discard `out` (server.go SetError path drops the 2nd
		// return on err!=nil); set IsError + the error text on the result
		// ourselves, and let the SDK marshal `out` (Denial included) into
		// StructuredContent. True infra errors (out.Denial==nil) keep the
		// current text-only IsError path.
		if out.Denial != nil {
			res := &mcpsdk.CallToolResult{
				IsError: true,
				Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: err.Error()}},
			}
			return res, out, nil
		}
		return nil, tools.RunOutput{}, err
	}
	s.Logger.Printf("run alias=%s kind=%s approved=%v exit=%d", in.Alias, out.Kind, out.Approved, out.ExitCode)
	// Tier 6b — append the full command + full output to the MCP-side
	// rolling live log (the convenience surface). nil LiveLog is a no-op.
	//
	// EXCEPTION: a SECRET-REVEAL bypasses the gate's redactor, so out.Stdout/
	// Stderr carry the RAW secret. The live log's job is accountability — to
	// record THAT a reveal ran (command, classification, exit, revealed:true)
	// — NOT to be a secret store. So for a revealed command we blank the raw
	// output here and never persist it. Reveal's accepted exposure is the
	// agent + transcript + approval chat, not this on-disk log.
	stdout, stderr := out.Stdout, out.Stderr
	if out.Revealed {
		stdout, stderr = "", ""
	}
	s.LiveLog.Log(livelog.Entry{
		Server: in.Alias,
		// Redact a secret embedded in the command STRING before it lands in
		// the at-rest live log (F5). Fail-open; benign commands pass through.
		Command:        s.redactCommand(in.Command),
		Classification: out.Kind,
		ExitCode:       out.ExitCode,
		Approved:       out.Approved,
		// AuthMode (F4) is the single human-vs-grant surface: "human" for a
		// real-time tap, "grant:<id>" for a standing-grant auto-sign, "" for a
		// read. It is metadata, NOT secret output, so it is KEPT even for a
		// revealed write (whose stdout/stderr were blanked above).
		AuthMode: out.AuthMode,
		Revealed: out.Revealed,
		Stdout:   stdout,
		Stderr:   stderr,
	})
	// Also pack a TextContent block so older MCP clients (without
	// structured content support) see a human-readable result.
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRunSummary(out)}},
	}, out, nil
}

// runBatchHandler is the typed tool handler for run_batch. The Runner
// returns a structured RunBatchOutput either way (approved, denied,
// timed-out, or unreachable) — only a true infrastructure error (nil
// runner, unknown alias, etc.) is surfaced as a Go error.
func (s *Server) runBatchHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunBatchInput) (*mcpsdk.CallToolResult, tools.RunBatchOutput, error) {
	out, err := s.Runner.RunBatch(ctx, in)
	if err != nil {
		// NOTE: a batch that hit an SSH TRANSPORT error returns here, BEFORE
		// the live-log loop below, so its partial results are not live-logged.
		// This is intentional: the live log is a convenience surface, and the
		// gate-side Tier-6a log on the host is the authoritative record of
		// whatever actually executed. We do not restructure to live-log
		// partials — keeping the error path simple is worth more than the
		// transient convenience view of an aborted batch.
		s.Logger.Printf("run_batch alias=%s err=%v", in.Alias, err)
		// #26-core: mirror runHandler — a recognised refusal (read-only host,
		// missing signer) carries a structured Denial on the Go-error path.
		// Preserve it while keeping IsError + prose text (see runHandler).
		if out.Denial != nil {
			res := &mcpsdk.CallToolResult{
				IsError: true,
				Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: err.Error()}},
			}
			return res, out, nil
		}
		return nil, tools.RunBatchOutput{}, err
	}
	s.Logger.Printf("run_batch alias=%s n=%d approved=%v denied=%v reason=%s", in.Alias, len(out.Results), out.Approved, out.Denied, out.Reason)
	// Tier 6b — append one live-log entry per command result (full output).
	// Skipped commands (stop_on_error) and a wholly-denied batch (empty
	// Results) simply produce fewer/no entries. nil LiveLog is a no-op.
	for _, r := range out.Results {
		if r.Skipped {
			continue
		}
		// run_batch NEVER reveals (bulk reveal is forbidden), so r.Revealed is
		// always false today; we still honour it so a revealed result would
		// blank its raw output, mirroring the single-command hook above.
		stdout, stderr := r.Stdout, r.Stderr
		if r.Revealed {
			stdout, stderr = "", ""
		}
		// AuthMode (F4) applies only to a WRITE: the one batch sign request
		// authorised the writes, so each write carries the batch-level
		// auth_mode ("human" / "grant:<id>"); the reads ran direct, never
		// part of the approval, so they carry no auth mode — mirroring the
		// Approved logic on the line below.
		authMode := ""
		if r.Kind == "write" {
			authMode = out.AuthMode
		}
		s.LiveLog.Log(livelog.Entry{
			Server: out.Server,
			// Redact a secret embedded in the command STRING (F5). Fail-open.
			Command:        s.redactCommand(r.Command),
			Classification: r.Kind,
			ExitCode:       r.ExitCode,
			// A read inside an approved batch is correctly Approved:false — the
			// single bulk approval only authorised the batch's WRITES; the reads
			// ran direct and were never part of the human tap.
			Approved: out.Approved && r.Kind == "write",
			AuthMode: authMode,
			Revealed: r.Revealed,
			Stdout:   stdout,
			Stderr:   stderr,
		})
	}
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRunBatchSummary(out)}},
	}, out, nil
}

// formatRunSummary returns a short human-readable summary of out for
// fallback TextContent. Stdout/stderr are truncated to keep the
// chat-side log compact; structured content carries the full output.
func formatRunSummary(out tools.RunOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s exit=%d", out.Kind, out.ExitCode)
	if out.Kind == "write" {
		fmt.Fprintf(&b, " approved=%v", out.Approved)
		if out.Reason != "" {
			fmt.Fprintf(&b, "\nreason: %s", out.Reason)
		}
	}
	if out.Stdout != "" {
		fmt.Fprintf(&b, "\n--- stdout ---\n%s", truncate(out.Stdout, 2000))
	}
	if out.Stderr != "" {
		fmt.Fprintf(&b, "\n--- stderr ---\n%s", truncate(out.Stderr, 2000))
	}
	// #26-core: echo the one-line denial summary for text-only clients.
	// Strictly appended; structured content carries the full Denial object.
	if out.Denial != nil {
		fmt.Fprintf(&b, "\ndenial: %s", out.Denial.Summary)
	}
	return b.String()
}

// formatRunBatchSummary renders a short human summary of a batch
// outcome for the fallback TextContent block. Structured content
// carries the full per-command stdout/stderr/exit.
func formatRunBatchSummary(out tools.RunBatchOutput) string {
	var b strings.Builder
	if out.Denied {
		fmt.Fprintf(&b, "batch denied (%s) on %s", out.Reason, out.Server)
		// #26-core: echo the one-line denial summary (strictly appended).
		if out.Denial != nil {
			fmt.Fprintf(&b, "\ndenial: %s", out.Denial.Summary)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "batch on %s: %d command(s), approved=%v", out.Server, len(out.Results), out.Approved)
	for i, r := range out.Results {
		fmt.Fprintf(&b, "\n[%d] %s exit=%d", i, r.Kind, r.ExitCode)
		if r.Skipped {
			fmt.Fprintf(&b, " (skipped)")
		}
		// #26: name why a write classified as a write, so a misclassified
		// read is easy to spot and rephrase.
		if r.Kind == "write" && r.Reason != "" {
			fmt.Fprintf(&b, "\n     reason: %s", r.Reason)
		}
		// A gate deny (exit 77/65) on a write annotates the result's
		// Stderr with remediation; echo it into the fallback summary so
		// the model sees it even without structured-content support.
		if note := gateDenyNoteFor(r); note != "" {
			fmt.Fprintf(&b, "\n     %s", note)
		}
	}
	// #26-core: a per-command gate deny sets a batch-level Denial while the
	// batch otherwise ran (Denied=false, Results populated). Echo its summary.
	if out.Denial != nil {
		fmt.Fprintf(&b, "\ndenial: %s", out.Denial.Summary)
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[...truncated]"
}

// gateDenyNoteFor returns a short remediation line for a write command
// result whose exit code is a well-known gate deny (77 = missing sig /
// read-only, 65 = bad/expired sig), or "" otherwise. Reads never carry
// these codes, so the annotation is write-only. The run_batch layer
// already folds the full note into the result's Stderr; this keeps the
// fallback TextContent summary actionable too.
func gateDenyNoteFor(r tools.CommandResult) string {
	if r.Kind != "write" {
		return ""
	}
	switch r.ExitCode {
	case 77:
		return "gate denied (exit 77): no signer pubkey (read-only / Tier-1) or missing signature — check sshgate.status. Re-tiering a read-only server is a manual human step (there is no in-place flip, #17, and no signed remote revoke works on a Tier-1 gate): on the host, swap SSHGate's forced command=\"...\" line back to the plain `sshgate pubkey` line, drop the alias from the registry (~/.config/sshgate/servers.json), then re-run `sshgate add <alias> <user@host>` at the desired tier (run /sshgate:setup first if no signer is configured yet)."
	case 65:
		return "gate rejected the signature (exit 65): expired or invalid — usually clock skew or a stale approval; retry."
	default:
		return ""
	}
}

// revokeServerHandler is the typed handler for sshgate.revoke_server.
// Sign denials/timeouts and SSH/registry errors surface as MCP tool
// errors (IsError=true) so Claude can see exactly why the revoke
// failed; on success the structured RevokeServerOutput carries the
// confirmation message printed by gate.
func (s *Server) revokeServerHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RevokeServerInput) (*mcpsdk.CallToolResult, tools.RevokeServerOutput, error) {
	out, err := s.Runner.RevokeServer(ctx, in)
	if err != nil {
		s.Logger.Printf("revoke_server alias=%s err=%v", in.Alias, err)
		return nil, out, err
	}
	s.Logger.Printf("revoke_server alias=%s remote_cleaned=%v registry_removed=%v",
		out.Alias, out.RemoteCleaned, out.RegistryRemoved)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRevokeServerSummary(out)}},
	}, out, nil
}

// formatRevokeServerSummary renders a short human summary for the
// fallback TextContent block. Structured output carries the full
// RevokeServerOutput.
func formatRevokeServerSummary(out tools.RevokeServerOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "revoked %s: remote_cleaned=%v registry_removed=%v",
		out.Alias, out.RemoteCleaned, out.RegistryRemoved)
	if out.Message != "" {
		fmt.Fprintf(&b, "\ngate: %s", out.Message)
	}
	return b.String()
}

// updateGateHandler is the typed handler for sshgate.update_gate. Sign
// denials/timeouts (a human refused the update, or the signer was
// unreachable), a missing staged binary, a read-only alias, an SSH failure,
// and a marker/hash mismatch all surface as MCP tool errors (IsError=true) so
// Claude sees exactly why the update did not happen; on success the structured
// UpdateGateOutput carries the installed hash + size + revision.
func (s *Server) updateGateHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.UpdateGateInput) (*mcpsdk.CallToolResult, tools.UpdateGateOutput, error) {
	out, err := s.Runner.UpdateGate(ctx, in)
	if err != nil {
		s.Logger.Printf("update_gate alias=%s err=%v", in.Alias, err)
		return nil, out, err
	}
	s.Logger.Printf("update_gate alias=%s new_hash=%s size=%d rev=%s verified_alive=%v",
		out.Alias, out.NewHash, out.Size, out.Revision, out.VerifiedAlive)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatUpdateGateSummary(out)}},
	}, out, nil
}

// formatUpdateGateSummary renders a short human summary for the fallback
// TextContent block. Structured output carries the full UpdateGateOutput.
func formatUpdateGateSummary(out tools.UpdateGateOutput) string {
	return fmt.Sprintf("updated gate on %s: sha256=%s size=%d rev=%s verified_alive=%v",
		out.Alias, out.NewHash, out.Size, out.Revision, out.VerifiedAlive)
}

// transferHandler is the typed handler for sshgate.transfer. A sign
// denial/timeout (a human refused, or the signer was unreachable), an
// unregistered/read-only alias, an SSH failure, and a marker/xferID mismatch
// all surface as MCP tool errors (IsError=true) so Claude sees exactly why the
// transfer did not happen; on success the structured TransferOutput carries
// METADATA ONLY (xfer id, byte count, mode, auth mode).
//
// CONFIDENTIALITY. This handler NEVER calls s.LiveLog.Log (exactly like
// updateGateHandler — only runHandler/runBatchHandler feed the live log), so
// neither the envelope (ciphertext) nor any plaintext ever reaches the Tier-6b
// live log. s.Logger records METADATA ONLY. The guarantee is NOT redaction (an
// opaque blob has no pattern to scrub) — it is NOT surfacing the envelope or
// plaintext at all: not in the result, not in RunOutput, not in the live log,
// not in s.Logger.
func (s *Server) transferHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.TransferInput) (*mcpsdk.CallToolResult, tools.TransferOutput, error) {
	out, err := s.Runner.Transfer(ctx, in)
	if err != nil {
		// Metadata only — the aliases are non-secret; the error string never
		// carries the envelope or plaintext (the tool guarantees it).
		s.Logger.Printf("transfer src=%s dest=%s err=%v", in.SrcAlias, in.DestAlias, err)
		return nil, out, err
	}
	// METADATA ONLY — never the envelope, never the secret. Mirrors update_gate.
	s.Logger.Printf("transfer src=%s dest=%s xfer=%s bytes=%d auth=%s", out.SrcAlias, out.DestAlias, out.XferID, out.Bytes, out.AuthMode)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatTransferSummary(out)}},
	}, out, nil
}

// formatTransferSummary renders a short human summary for the fallback
// TextContent block. METADATA ONLY — no stdout, no envelope, no plaintext.
func formatTransferSummary(out tools.TransferOutput) string {
	return fmt.Sprintf("transferred %s:%s → %s:%s (xfer=%s bytes=%d mode=%s auth=%s)",
		out.SrcAlias, out.SrcPath, out.DestAlias, out.DestPath, out.XferID, out.Bytes, out.Mode, out.AuthMode)
}

// requestGrantHandler is the typed handler for sshgate.request_grant. A
// denial/timeout from the human (or a validation error) surfaces as an
// MCP tool error so Claude sees exactly why the grant was not minted; on
// approval the structured RequestGrantOutput carries the grant id +
// expiry.
func (s *Server) requestGrantHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RequestGrantInput) (*mcpsdk.CallToolResult, tools.RequestGrantOutput, error) {
	out, err := s.Runner.RequestGrant(ctx, in)
	if err != nil {
		s.Logger.Printf("request_grant alias=%s scope=%s err=%v", in.Alias, in.Scope, err)
		return nil, tools.RequestGrantOutput{}, err
	}
	s.Logger.Printf("request_grant alias=%s scope=%s grant_id=%s expiry=%d",
		out.Alias, out.Scope, out.GrantID, out.ExpiryUnix)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRequestGrantSummary(out)}},
	}, out, nil
}

// formatRequestGrantSummary renders a short human summary for the
// fallback TextContent block.
func formatRequestGrantSummary(out tools.RequestGrantOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "standing grant minted on %s: scope=%s grant_id=%s", out.Alias, out.Scope, out.GrantID)
	if out.Scope == "commands" {
		for _, c := range out.Commands {
			fmt.Fprintf(&b, "\n  - %s", c)
		}
	}
	fmt.Fprintf(&b, "\nexpires_unix=%d (auto-signs matching writes until then; dies on signer restart)", out.ExpiryUnix)
	return b.String()
}

// revokeGrantHandler is the typed handler for sshgate.revoke_grant. Only
// a true infrastructure error (nil dependency, transport failure)
// surfaces as a Go error; a successful revoke carries Revoked=true.
func (s *Server) revokeGrantHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RevokeGrantInput) (*mcpsdk.CallToolResult, tools.RevokeGrantOutput, error) {
	out, err := s.Runner.RevokeGrant(ctx, in)
	if err != nil {
		s.Logger.Printf("revoke_grant alias=%s err=%v", in.Alias, err)
		return nil, tools.RevokeGrantOutput{}, err
	}
	s.Logger.Printf("revoke_grant alias=%s revoked=%v", out.Alias, out.Revoked)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: fmt.Sprintf("standing grant on %s revoked (writes will prompt again)", out.Alias)}},
	}, out, nil
}

// listGrantsHandler is the typed handler for sshgate.list_grants. It is
// read-only — only a true infrastructure error (nil dependency, transport
// failure, or a too-old daemon) surfaces as a Go error; a successful read
// carries the live grants in the structured ListGrantsOutput.
func (s *Server) listGrantsHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.ListGrantsInput) (*mcpsdk.CallToolResult, tools.ListGrantsOutput, error) {
	out, err := s.Runner.ListGrants(ctx, in)
	if err != nil {
		s.Logger.Printf("list_grants alias=%s err=%v", in.Alias, err)
		return nil, tools.ListGrantsOutput{}, err
	}
	s.Logger.Printf("list_grants alias=%s grants=%d", in.Alias, len(out.Grants))
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatListGrantsSummary(out)}},
	}, out, nil
}

// formatListGrantsSummary renders a short human summary for the fallback
// TextContent block. Structured content carries the full ListGrantsOutput.
func formatListGrantsSummary(out tools.ListGrantsOutput) string {
	if len(out.Grants) == 0 {
		return "no live standing grants"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d live grant(s):", len(out.Grants))
	for _, g := range out.Grants {
		fmt.Fprintf(&b, "\n  %s  scope=%s grant_id=%s expires_unix=%d", g.Alias, g.Scope, g.GrantID, g.ExpiryUnix)
		if g.Scope == "commands" {
			for _, c := range g.Commands {
				fmt.Fprintf(&b, "\n    - %s", c)
			}
		}
	}
	return b.String()
}

// listServersHandler is the typed handler for sshgate.list_servers.
// The structured ListServersOutput carries the alphabetically-sorted
// registry contents; the TextContent fallback is a one-line summary.
func (s *Server) listServersHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.ListServersInput) (*mcpsdk.CallToolResult, tools.ListServersOutput, error) {
	out, err := s.Runner.ListServers(ctx, in)
	if err != nil {
		s.Logger.Printf("list_servers err=%v", err)
		return nil, tools.ListServersOutput{}, err
	}
	s.Logger.Printf("list_servers total=%d", out.Total)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatListServersSummary(out)}},
	}, out, nil
}

// statusHandler is the typed handler for sshgate.status. Per-target
// failures are returned as part of the structured output; only a true
// configuration error (nil dependency) surfaces as an MCP tool error.
func (s *Server) statusHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.StatusInput) (*mcpsdk.CallToolResult, tools.StatusOutput, error) {
	out, err := s.Runner.Status(ctx, in)
	if err != nil {
		s.Logger.Printf("status err=%v", err)
		return nil, tools.StatusOutput{}, err
	}
	s.Logger.Printf("status signer_reachable=%v servers=%d", out.SignerSocket.Reachable, len(out.Servers))
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatStatusSummary(out)}},
	}, out, nil
}

// pingHandler is the typed handler for sshgate.ping. Only a true
// configuration error (nil dependency) or an unknown alias surfaces as an
// MCP tool error; a reachable/unreachable verdict for a known alias is
// carried in the structured PingOutput. It is READ-class: the handler never
// engages the signer and never solicits an approval.
func (s *Server) pingHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.PingInput) (*mcpsdk.CallToolResult, tools.PingOutput, error) {
	out, err := s.Runner.Ping(ctx, in)
	if err != nil {
		s.Logger.Printf("ping alias=%s err=%v", in.Alias, err)
		return nil, tools.PingOutput{}, err
	}
	s.Logger.Printf("ping alias=%s reachable=%v ping_ms=%d", in.Alias, out.Reachable, out.PingMS)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatPingSummary(out)}},
	}, out, nil
}

// formatPingSummary renders a one-line human summary for the fallback
// TextContent block. Structured content carries the full PingOutput.
func formatPingSummary(out tools.PingOutput) string {
	if out.Reachable {
		return fmt.Sprintf("%s: ok %dms%s", out.Alias, out.PingMS, tierTag(out.ReadOnly))
	}
	return fmt.Sprintf("%s: DOWN %s%s", out.Alias, out.Error, tierTag(out.ReadOnly))
}

// formatListServersSummary returns a compact human listing for the
// fallback TextContent block. Structured content carries the full
// ListServersOutput.
func formatListServersSummary(out tools.ListServersOutput) string {
	if out.Total == 0 {
		return "no registered servers"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d server(s):", out.Total)
	for _, s := range out.Servers {
		fmt.Fprintf(&b, "\n  %s  %s@%s:%d%s", s.Alias, s.User, s.Host, s.Port, tierTag(s.ReadOnly))
	}
	return b.String()
}

// formatStatusSummary renders a short health summary for the fallback
// TextContent block. Structured content carries the full StatusOutput.
func formatStatusSummary(out tools.StatusOutput) string {
	var b strings.Builder
	switch {
	case out.SignerSocket.Reachable:
		fmt.Fprintf(&b, "signer: reachable (%s)", out.SignerSocket.Path)
	case !out.SignerSocket.Configured:
		// Tier 1: no signer daemon installed. This is the expected
		// read-only state, not a failure to debug (audit M4).
		fmt.Fprintf(&b, "signer: not configured (%s) — read-only / Tier 1; writes are denied at the gate. Run /sshgate:setup to add a Telegram signer.", out.SignerSocket.Path)
	case out.SignerSocket.Permission:
		// Socket present but the dial was permission-denied: the MCP
		// process is not in the sshgatesigner group. NOT a dead daemon —
		// the fix is a fresh login + Claude Code relaunch, not systemctl.
		fmt.Fprintf(&b, "signer: socket present but NOT ACCESSIBLE (%s) — permission denied; your shell/session is not in the sshgatesigner group. Log out and back in, relaunch Claude Code (a side-terminal newgrp is not enough), then run /mcp to confirm. This is NOT a dead daemon.", out.SignerSocket.Path)
	default:
		// Configured (socket file present) but the dial failed — a real
		// Tier-2 daemon problem worth surfacing.
		fmt.Fprintf(&b, "signer: UNREACHABLE (%s): %s", out.SignerSocket.Path, out.SignerSocket.Error)
	}
	for _, sv := range out.Servers {
		if sv.Reachable {
			fmt.Fprintf(&b, "\n  %s: ok %dms%s", sv.Alias, sv.PingMS, tierTag(sv.ReadOnly))
		} else {
			fmt.Fprintf(&b, "\n  %s: DOWN %s%s", sv.Alias, sv.Error, tierTag(sv.ReadOnly))
		}
	}
	return b.String()
}

// tierTag returns " [read-only]" for a Tier-1 server and "" for a
// signed-write one, so the human-readable fallback summaries surface a
// server's tier alongside its reachability (W3-7). The structured
// output carries the same information as the read_only boolean.
func tierTag(readOnly bool) string {
	if readOnly {
		return " [read-only]"
	}
	return ""
}

// readerCloser / writerCloser adapt plain io.Reader / io.Writer to
// the io.ReadCloser / io.WriteCloser expected by mcpsdk.IOTransport.
// Close is a no-op — the caller (typically main) owns the stdio
// pipes and is responsible for closing them on shutdown.
type readerCloser struct{ io.Reader }

func (readerCloser) Close() error { return nil }

type writerCloser struct{ io.Writer }

func (writerCloser) Close() error { return nil }
