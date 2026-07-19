package signerkit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// MaxGrantDuration is the hard ceiling on a standing grant's lifetime.
// A request for a longer window is rejected at creation; the signer will
// never auto-sign past a grant's expiry, and the gate still independently
// caps every individual signature at sigwire.MaxSigValidity regardless.
const MaxGrantDuration = 24 * time.Hour

// maxXferLabelLen caps the display label on a register_xfer_key request. It is
// validated in handleRegisterXferKey BEFORE the human prompt so an oversized
// label can never reach the approval banner (bannerLabel) or the registry
// (XferRegistry.Register stores it verbatim). It complements — does not replace
// — bannerLabel's control-char rejection. The CLI also caps friendlier-side.
const maxXferLabelLen = 64

// grant is a standing grant: in-memory signer state recorded after ONE
// human approval that lets matching (alias, command) sign requests
// auto-approve WITHOUT prompting during the window. It never appears on
// the wire and the gate is unaware of it — auto-signed signatures are
// byte-identical to human-approved ones. Grants are in-memory only, so a
// signer restart drops every grant.
//
//   - scope == "all"      → any command on alias auto-signs.
//   - scope == "commands" → only an EXACT string in commands auto-signs.
//
// Fields are written once at creation (under grantsMu.Lock) and read-only
// thereafter, so a snapshot copied out under RLock is safe to inspect
// without further locking.
type grant struct {
	id       string
	alias    string
	scope    string
	commands []string
	expiry   time.Time
}

// Daemon is the signer core. It owns the signing identity, the pluggable
// approval Backend, and the audit log. One Daemon instance serves an
// arbitrary number of concurrent connections; HandleSignRequest is safe for
// concurrent calls because:
//
//   - Key / Signer are read-only after construction.
//   - The mutable custody state (Lock/Unlock/RotateTo — see custody.go) is
//     guarded by custodyMu and only ever read through signBytes.
//   - Backend.Request is documented as concurrency-safe.
//   - AuditLog.Write is mutex-protected.
//
// Signing identity (resolved per-signature inside signBytes, see custody.go):
// a RotateTo target wins, else the exported Signer (crypto.Signer — a
// KMS/HSM/agent-backed key never held in process memory), else the exported
// Key (the legacy raw Ed25519 key); all three nil ⇒ ErrNoSigner. Pinning
// crypto.Hash(0) keeps the file-key path byte-identical to the pre-seam
// ed25519.Sign call (RFC 8032 determinism).
//
// NowFunc is the injected clock used to compute the signed payload's
// TS / Exp fields. Tests inject a fixed clock; main wiring leaves it
// nil, in which case the daemon falls back to time.Now.
type Daemon struct {
	Key ed25519.PrivateKey
	// Signer, when non-nil, is the crypto.Signer identity used to mint every
	// signature — it wins over Key (C7). It lets the raw key live in a KMS/HSM
	// or ssh-agent and never enter process memory. New(Config) sets it; a
	// struct-literal Daemon may set either Signer or Key. Read-only after
	// construction; RotateTo installs a live replacement without touching it.
	Signer  crypto.Signer
	Backend Backend
	Audit   *AuditLog
	NowFunc func() time.Time

	// custody state: the in-memory kill-switch (Lock) and rotation (RotateTo)
	// installed after construction. It BREAKS the historical "Key is read-only
	// after construction" concurrency argument, so every field here is written
	// only under custodyMu.Lock and read only under custodyMu.RLock, exclusively
	// through resolveSigner/signBytes (custody.go). It is process-memory only:
	// a signer restart clears the lock and any rotation, reverting to the
	// constructed Signer/Key (same posture as grants).
	custodyMu sync.RWMutex
	// lifecycleMu serializes the complete transition→audit sequence. Audit is
	// still best-effort/fail-open, but concurrent Lock/Unlock/Rotate calls can
	// never be recorded in a different order from the states they installed.
	lifecycleMu sync.Mutex
	locked      bool
	lockReason  string
	rotSigner   crypto.Signer
	// lifecycleSink receives Lock/Unlock/RotateTo audit events for a Daemon
	// constructed by New(Config). It is deliberately separate from Audit: the
	// socket path still needs the concrete *AuditLog, while custody controls must
	// reach any configured AuditSink. auditLifecycle uses this sink first and
	// falls back to Audit only for legacy struct-literal Daemons, so a local
	// *AuditLog wired into both fields is never double-written.
	lifecycleSink AuditSink

	// grants is the in-memory standing-grant table, keyed by server
	// alias (one grant per alias — a new grant for an alias replaces the
	// old). It is lazily initialised on first create so a Daemon built as
	// a struct literal (cmd/main, tests) needs no extra wiring. All access
	// goes through grantsMu: reads (matchGrant) take RLock, create/revoke
	// take Lock. The table is process-memory only — it is never persisted,
	// so a signer restart drops every grant (the "stop the signer kills
	// grants" property).
	grants   map[string]grant
	grantsMu sync.RWMutex

	// RedactSalt + RedactRules scrub a secret embedded in the COMMAND
	// STRING before it is recorded in the signer audit log (F5). The salt is
	// a per-process random 32 bytes generated ONCE at startup; the ruleset
	// is rules.Combined() compiled ONCE at startup (the signer is a
	// long-running daemon — never compile per-request). Both are wired by
	// cmd/main. A zero salt + nil rules is a valid no-op: RedactString
	// fast-paths nil rules and records the command verbatim, so a Daemon
	// built without them still works.
	RedactSalt  [32]byte
	RedactRules []redact.Rule

	// XferRegistry is the per-server box→box transfer key registry — the trust
	// anchor for the SECRET-TRANSFER feature. When a transfer is approved the
	// daemon sources the recipient's box public key and the sender's identity
	// public key ONLY from here (Lookup), NEVER from the MCP request, which is
	// the whole anti-MITM guarantee. It is wired by cmd/main from
	// <keydir>/xfer-registry.json (missing file → empty registry). A Daemon
	// built without it (tests, legacy config) is nil; handleTransfer /
	// handleRegisterXferKey fail closed on nil rather than nil-panicking.
	XferRegistry *XferRegistry
}

// transferRequest is the wire-format "transfer" request: one human approval
// mints the two host-bound signed legs of a box→box secret transfer. The MCP
// sends paths + fingerprints + display aliases ONLY — it never sends the
// pubkeys and never sends an xferID; the daemon sources both from its own
// registry and mints the xferID, which is the entire anti-MITM guarantee.
// Fields disjoint from signRequest, so it has its own DisallowUnknownFields
// decode (like grantRequest).
type transferRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	SrcAlias  string `json:"src_alias"` // display only
	SrcFP     string `json:"src_fp"`    // registry key for id_pub + SEND leg Host + RECV srcID
	SrcPath   string `json:"src_path"`  // path on the source gate to read
	DestAlias string `json:"dest_alias"`
	DestFP    string `json:"dest_fp"`   // registry key for box_pub + RECV leg Host + destID
	DestPath  string `json:"dest_path"` // path on the destination gate to write
	Mode      string `json:"mode"`      // octal file mode ("0600" in P2)
	TTLSec    int64  `json:"ttl_seconds"`
	// ProtoVersion: see signRequest — known to the strict decoder, checked in
	// the lenient peek, omitempty preserves the legacy wire shape.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// transferLeg is one signed leg {cmd, sig} of a transfer.
type transferLeg struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// transferResponse is the wire-format "transfer" response. On approval XferID +
// both legs are set; AuthMode is always "human" on approval (a standing grant
// can never cover a transfer). Error is set only on status "error".
type transferResponse struct {
	RequestID    string       `json:"request_id"`
	Status       string       `json:"status"`
	AuthMode     string       `json:"auth_mode,omitempty"`
	XferID       string       `json:"xfer_id,omitempty"`
	Send         *transferLeg `json:"send,omitempty"`
	Recv         *transferLeg `json:"recv,omitempty"`
	Error        string       `json:"error,omitempty"`
	ProtoVersion int          `json:"proto_version,omitempty"`
}

// registerXferKeyRequest is the wire-format "register_xfer_key" request: a
// human-only, always-prompt registration of a server's box→box transfer keys
// into the signer registry. There is NO MCP tool for it (mirrors provisioning);
// the caller is the human-only sshgate CLI over the signer socket. Fields
// disjoint from other kinds, its own DisallowUnknownFields decode.
type registerXferKeyRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	HostFP    string `json:"host_fp"`
	Label     string `json:"label"`
	BoxPub    string `json:"box_pub"` // canonical PublicText
	IDPub     string `json:"id_pub"`  // canonical PublicText
	// ProtoVersion: see signRequest.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// registerXferKeyResponse is the wire-format "register_xfer_key" response.
type registerXferKeyResponse struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ProtoVersion int    `json:"proto_version,omitempty"`
}

// signRequest is the wire-format request sent over the Unix socket.
type signRequest struct {
	Kind      string           `json:"kind"`
	RequestID string           `json:"request_id"`
	Commands  []signRequestCmd `json:"commands"`
	// ProtoVersion is the client's sigwire.ProtoVersion. The strict per-kind
	// decoder must KNOW the field (it uses DisallowUnknownFields), even though
	// the authoritative version check already happened in the lenient
	// kindPeek pre-pass. omitempty keeps a legacy (no-version) request's wire
	// shape byte-identical.
	ProtoVersion int `json:"proto_version,omitempty"`
}

type signRequestCmd struct {
	Server string `json:"server"`
	Cmd    string `json:"cmd"`
	TTLSec int64  `json:"ttl_seconds"`
	// Host is the target server's SSH host-key fingerprint
	// ("SHA256:..."), supplied by the MCP from its TRUSTED registry (never
	// an agent parameter). The daemon copies it verbatim into the signed
	// payload's Host field so the gate can enforce the per-server binding.
	// omitempty keeps the wire shape unchanged for any legacy caller that
	// does not send it.
	Host string `json:"host,omitempty"`
	// Reveal requests a SECRET-REVEAL: when true, the daemon copies it into
	// the signed payload's Reveal field so the gate runs the command output
	// WITHOUT the redactor. Reason is the mandatory human justification (the
	// MCP enforces non-empty Reason for reveal=true and shows it in the
	// approval UX). Both omitempty so an ordinary write's wire shape is
	// unchanged. Reason is NOT signed — it exists only for the human approval
	// decision and audit; the gate-enforced capability is the signed Reveal
	// bool.
	Reveal bool   `json:"reveal,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// signResponse is the wire-format response. Status is one of "approved",
// "denied", "timeout", "error". Signatures is populated only on
// approved; Error is populated only on error.
//
// AuthMode (F4) reports HOW the request was authorised — "human" for a
// real-time Telegram tap, "grant:<id>" for a standing-grant auto-sign,
// empty for any non-approved outcome. It rides the gate-INVISIBLE
// MCP↔signer socket RPC, NOT the signed payload: a grant signature is
// byte-identical to a human one by design, so the gate neither sees nor
// could see this. omitempty keeps a legacy (no-auth_mode) response's wire
// shape byte-identical, and an old signer that omits it unmarshals to "".
type signResponse struct {
	RequestID    string            `json:"request_id"`
	Status       string            `json:"status"`
	AuthMode     string            `json:"auth_mode,omitempty"`
	Signatures   []signResponseSig `json:"signatures,omitempty"`
	Error        string            `json:"error,omitempty"`
	ProtoVersion int               `json:"proto_version,omitempty"`
}

// authMode derives the F4 auth-mode marker. It is the SINGLE source of truth
// shared by the socket response (respond) and the audit log (audit), so the
// two can never drift. It is gated on the APPROVAL STATE — NOT on ApprovedBy
// alone — because the real Telegram backend sets Result.ApprovedBy to the
// DENIER's name on a DENY too (callbackApprover returns a non-empty
// "@user"/"id:N" for both approve and deny). Keying on non-emptiness alone
// (the old behaviour) therefore stamped auth_mode="human" on a real DENY,
// corrupting the F4 forensics into implying the write was authorised. The mock
// backend masked this by leaving ApprovedBy empty on deny.
//
//   - approved==false → "" (denied / timeout / error / a read — NOTHING was
//     authorised, regardless of any approver name the backend carries).
//   - "grant:<id>"    → returned verbatim (a standing-grant auto-sign).
//   - any other non-empty value → "human" (a real-time tap; the approver name
//     lives in approved_by, the HOW is just "human").
//   - approved==true but empty approvedBy → "" (no authoriser recorded).
//
// Callers pass approved==true for both "approved" and "approved-undelivered"
// (both are decided approvals carrying the approver/grant id), so an
// approved-undelivered still records human/grant; all the non-approved
// outcomes record "".
func authMode(approved bool, approvedBy string) string {
	if !approved {
		return ""
	}
	if strings.HasPrefix(approvedBy, "grant:") {
		return approvedBy
	}
	if approvedBy != "" {
		return "human"
	}
	return ""
}

type signResponseSig struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// kindPeek decodes the routing/diagnostic fields of a request line,
// WITHOUT DisallowUnknownFields, so HandleSignRequest can dispatch to the
// right typed decoder. The per-kind decoder then re-decodes the same line
// with DisallowUnknownFields, so an unknown field is still rejected for the
// kind it belongs to.
//
// ProtoVersion and RequestID are read here LENIENTLY on purpose:
//   - ProtoVersion must be checked BEFORE any strict per-kind decode,
//     because those decoders use DisallowUnknownFields — a naive strict
//     check would have an old daemon reject the proto_version field itself
//     and re-create the build-skew outage this guards against.
//   - RequestID is pulled out so a malformed-peek / version-mismatch error
//     can echo a correlatable id instead of "" (closing the empty-id
//     masking at the source).
type kindPeek struct {
	Kind         string `json:"kind"`
	ProtoVersion int    `json:"proto_version"`
	RequestID    string `json:"request_id"`
}

// grantRequest is the wire-format "request_grant" request: a human
// approval mints a standing grant. Fields disjoint from signRequest, so
// it has its own struct (and its own DisallowUnknownFields decode).
type grantRequest struct {
	Kind        string   `json:"kind"`
	RequestID   string   `json:"request_id"`
	Alias       string   `json:"alias"`
	Scope       string   `json:"scope"`
	Commands    []string `json:"commands,omitempty"`
	DurationSec int64    `json:"duration_seconds"`
	// ProtoVersion: see signRequest — known to the strict decoder, checked in
	// the lenient peek, omitempty preserves the legacy wire shape.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// grantResponse is the wire-format "request_grant" response. On approval
// GrantID + ExpiryUnix are set; Error is set only on status "error".
type grantResponse struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	GrantID      string `json:"grant_id,omitempty"`
	ExpiryUnix   int64  `json:"expiry_unix,omitempty"`
	Error        string `json:"error,omitempty"`
	ProtoVersion int    `json:"proto_version,omitempty"`
}

// revokeGrantRequest is the wire-format "revoke_grant" request: drop a
// standing grant for alias. Revoke is de-escalation (it only SHRINKS
// capability), so it needs no human approval — it never reaches the
// backend.
type revokeGrantRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	Alias     string `json:"alias"`
	// ProtoVersion: see signRequest — known to the strict decoder, checked in
	// the lenient peek, omitempty preserves the legacy wire shape.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// revokeGrantResponse is the wire-format "revoke_grant" response.
type revokeGrantResponse struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ProtoVersion int    `json:"proto_version,omitempty"`
}

// listGrantsRequest is the wire-format "list_grants" request: a READ-ONLY
// query of the daemon's in-memory live-grant table. It needs no human
// approval and never reaches the backend (like revoke_grant). Alias is an
// optional filter (empty = all live grants). It exists so the MCP can
// re-learn true grant state after a request_grant whose verdict-write was
// lost (the phantom-live-grant race).
type listGrantsRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	Alias     string `json:"alias,omitempty"`
	// ProtoVersion: see signRequest — known to the strict decoder, checked in
	// the lenient peek, omitempty preserves the legacy wire shape.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// grantInfo is one live grant reported by list_grants. It echoes the
// agent's own grant request back (scope/commands) plus the daemon-minted
// grant_id and the absolute expiry — no key material, no capability.
type grantInfo struct {
	Alias      string   `json:"alias"`
	Scope      string   `json:"scope"`
	Commands   []string `json:"commands,omitempty"`
	GrantID    string   `json:"grant_id"`
	ExpiryUnix int64    `json:"expiry_unix"`
}

// listGrantsResponse is the wire-format "list_grants" response. Status is
// "ok" on a successful read or "error" on a malformed request. Grants
// carries the live (unexpired) grants matching the optional alias filter.
type listGrantsResponse struct {
	RequestID    string      `json:"request_id"`
	Status       string      `json:"status"`
	Grants       []grantInfo `json:"grants,omitempty"`
	Error        string      `json:"error,omitempty"`
	ProtoVersion int         `json:"proto_version,omitempty"`
}

// HandleSignRequest implements the one-request-per-connection protocol:
// read one JSON line, dispatch to the Backend, sign each command on
// approval, write one JSON line back. The function always writes a
// response and always records an audit event (the "error" status
// covers malformed input so operators can spot mischief at the
// protocol layer).
//
// The returned error is non-nil only on a hard I/O failure where no
// response was written (e.g. read EOF before any bytes, or a write
// failed mid-response). All protocol- and policy-level outcomes are
// represented in the JSON response and the audit log; they do not
// surface as a Go error.
func (d *Daemon) HandleSignRequest(ctx context.Context, conn io.ReadWriter) error {
	line, err := lineframe.Read(conn, policywire.MaxSocketFrameBytes)
	if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
		// Read errored before we got any input — there's no request
		// ID we can pin the error to, so surface to the caller.
		return fmt.Errorf("read request: %w", err)
	}

	// Peek the kind so we can dispatch to the right typed decoder. The
	// peek is lenient (no DisallowUnknownFields); each per-kind decoder
	// below re-decodes the same line strictly, so an unknown field is
	// still rejected for the kind it belongs to (e.g. the daemon_reject
	// "unknown extra json field" case still fails on the sign path).
	var peek kindPeek
	if jerr := json.Unmarshal(line, &peek); jerr != nil {
		// Malformed: respond with "error", audit with "error". Echo
		// peek.RequestID (it may have decoded even when another field
		// didn't) so a correlatable id is returned when available.
		return d.respondError(conn, peek.RequestID, fmt.Sprintf("malformed request: %v", jerr))
	}
	// Protocol-version skew guard. This runs in the LENIENT pre-pass, BEFORE
	// any strict per-kind decode, so an old daemon's DisallowUnknownFields
	// can't reject the proto_version field itself and re-create the outage.
	// proto_version == 0 (absent) ⇒ accept as legacy.
	if peek.ProtoVersion != 0 && peek.ProtoVersion != sigwire.ProtoVersion {
		return d.respondError(conn, peek.RequestID, fmt.Sprintf(
			"proto_version mismatch: client v%d vs daemon v%d — signer and MCP are different builds; rebuild and restart both",
			peek.ProtoVersion, sigwire.ProtoVersion))
	}
	switch peek.Kind {
	case "request_grant":
		return d.handleRequestGrant(ctx, conn, line)
	case "revoke_grant":
		return d.handleRevokeGrant(conn, line)
	case "list_grants":
		return d.handleListGrants(conn, line)
	case "transfer":
		return d.handleTransfer(ctx, conn, line)
	case "register_xfer_key":
		return d.handleRegisterXferKey(ctx, conn, line)
	case "sign", "":
		// "" falls through to the sign decoder, which rejects it as an
		// unsupported kind — preserving the existing error wording.
	default:
		return d.respondError(conn, peek.Kind, fmt.Sprintf("unsupported kind %q", peek.Kind))
	}

	var req signRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		// Malformed: respond with "error", audit with "error".
		return d.respondError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.Kind != "sign" {
		return d.respondError(conn, req.RequestID, fmt.Sprintf("unsupported kind %q", req.Kind))
	}
	if req.RequestID == "" {
		return d.respondError(conn, "", "missing request_id")
	}
	if len(req.Commands) == 0 {
		return d.respondError(conn, req.RequestID, "no commands in request")
	}

	apReq := ApprovalRequest{
		RequestID: req.RequestID,
		Submitted: d.now(),
		Commands:  make([]CommandReq, len(req.Commands)),
	}
	for i, c := range req.Commands {
		if c.Cmd == "" {
			return d.respondError(conn, req.RequestID, fmt.Sprintf("commands[%d].cmd is empty", i))
		}
		// Sign-path REJECT of any SSHGATE_XFER_* verb (the load-bearing
		// confused-deputy guard). A transfer leg names a recipient box key
		// SOURCED FROM THE SIGNER'S REGISTRY; if a caller could hand-craft
		// {kind:"sign", commands:[{cmd:"SSHGATE_XFER_SEND <attacker-box-pub> …"}]}
		// it would get a human tap on an opaque banner and have the master key
		// sign a leg whose recipient came from the AGENT — exactly the hole this
		// feature closes. Transfers MUST go through the dedicated "transfer" kind
		// (handleTransfer), where the signer sources the pubkeys itself. This
		// check is before matchGrant, so a standing grant can never reach it
		// either. isAdminVerb already forces a human prompt for these, but that
		// is not enough — we reject them outright on this path.
		if isTransferVerb(c.Cmd) {
			return d.respondError(conn, req.RequestID, fmt.Sprintf(
				"commands[%d] is a transfer verb; transfers must use the \"transfer\" request kind, not \"sign\"", i))
		}
		ttl := c.TTLSec
		if ttl <= 0 {
			return d.respondError(conn, req.RequestID, fmt.Sprintf("commands[%d].ttl_seconds must be > 0", i))
		}
		// Compare in int64 SECONDS — never multiply attacker-controlled
		// seconds into an int64-ns time.Duration (Duration(ttl)*Second),
		// which overflows NEGATIVE for ttl > ~9.2e9 and would let the master
		// key sign a never-expiring token. (The gate re-checks authoritatively
		// in verify.go; this is the signer-side cap.)
		if ttl > int64(sigwire.MaxSigValidity/time.Second) {
			return d.respondError(conn, req.RequestID, fmt.Sprintf("commands[%d].ttl_seconds %d exceeds max %d", i, ttl, int64(sigwire.MaxSigValidity/time.Second)))
		}
		apReq.Commands[i] = CommandReq{Server: c.Server, Cmd: c.Cmd, TTLSec: ttl, Reveal: c.Reveal, Reason: c.Reason, HostKeyFP: c.Host}
	}

	// Lone-admin-verb invariant: an SSHGATE_ admin verb (SSHGATE_UPDATE /
	// SSHGATE_REVOKE) MUST be the ONLY command in a sign request. Reject a
	// request that bundles an admin verb with any sibling command BEFORE any
	// prompting or signing. Rationale: an admin verb correctly forces a human
	// prompt (matchGrant carve-out), but the update approval banner renders only
	// the update command — a crafted multi-command request could therefore hide
	// sibling writes/reveals behind a clean "GATE UPDATE" banner and get them all
	// signed under one tap (signAll signs every command). Enforcing "admin verb ⇒
	// sole command" closes that approval-smuggling hole structurally, at the
	// request layer, independent of any banner-rendering detail. update_gate and
	// revoke_server each send exactly one admin command, so no legitimate caller
	// is affected.
	if len(req.Commands) > 1 {
		for i, c := range req.Commands {
			if isAdminVerb(c.Cmd) {
				return d.respondError(conn, req.RequestID, fmt.Sprintf(
					"commands[%d] is an SSHGATE_ admin verb; an admin verb must be the sole command in a sign request", i))
			}
		}
	}

	// Standing-grant auto-approve: if EVERY command matches a live grant
	// for its alias (and NONE is a reveal — reveals always prompt), skip
	// the human prompt entirely and synthesise an approval. respond then
	// signs a NORMAL per-command payload (byte-identical to a
	// human-approved one), so the gate never learns a grant was involved.
	if id, ok := d.matchGrant(req.Commands); ok {
		return d.respond(conn, req, Result{Status: StatusApproved, ApprovedBy: "grant:" + id})
	}

	resultCh, err := d.Backend.Request(ctx, apReq)
	if err != nil {
		return d.respondError(conn, req.RequestID, fmt.Sprintf("backend: %v", err))
	}

	var result Result
	select {
	case r, ok := <-resultCh:
		if !ok {
			result = Result{Status: StatusTimeout}
		} else {
			result = r
		}
	case <-ctx.Done():
		result = Result{Status: StatusTimeout}
	}

	return d.respond(conn, req, result)
}

// respond produces the appropriate signed-or-not response based on the
// backend's verdict, writes it, and records the audit event. The
// response/audit pair is intentionally produced inside one function so
// the two cannot drift.
func (d *Daemon) respond(conn io.Writer, req signRequest, result Result) error {
	// AuthMode (F4) is derived from the SAME helper the audit uses, gated on
	// the APPROVAL STATE (not ApprovedBy alone — the real Telegram backend
	// carries the denier's name on a DENY too), so the socket response and the
	// audit row never disagree on how a write was authorised. It is empty for
	// denied/timeout/error, "human" for a real-time tap, and "grant:<id>" for a
	// standing-grant auto-sign.
	resp := signResponse{RequestID: req.RequestID, Status: result.Status.String(), AuthMode: authMode(result.Status == StatusApproved, result.ApprovedBy), ProtoVersion: sigwire.ProtoVersion}

	if result.Status == StatusApproved {
		// Two paths:
		//   1. Remote-signing backend (HostedServerBackend): the server
		//      holds the key and returned the wire-formatted signatures
		//      in Result.Signatures. We validate length + per-entry Cmd
		//      match (defence against a server that returns signatures
		//      for the wrong commands) and pass through verbatim.
		//   2. Local-signing backend (Telegram / Stub / Mock without
		//      pre-canned sigs): Result.Signatures is nil, so we sign
		//      with d.Key.
		var sigs []signResponseSig
		if len(result.Signatures) > 0 {
			if len(result.Signatures) != len(req.Commands) {
				return d.respondError(conn, req.RequestID, fmt.Sprintf("remote signature count mismatch: got %d, want %d", len(result.Signatures), len(req.Commands)))
			}
			sigs = make([]signResponseSig, len(result.Signatures))
			for i, s := range result.Signatures {
				if s.Cmd != req.Commands[i].Cmd {
					return d.respondError(conn, req.RequestID, fmt.Sprintf("remote signature cmd mismatch at index %d", i))
				}
				sigs[i] = signResponseSig{Cmd: s.Cmd, Sig: s.Sig}
			}
		} else {
			localSigs, err := d.signAll(req.Commands)
			if err != nil {
				// A signing failure is a "we ran into the kernel's RNG
				// being broken" event — surface as error.
				return d.respondError(conn, req.RequestID, fmt.Sprintf("sign: %v", err))
			}
			sigs = localSigs
		}
		resp.Signatures = sigs
	}

	if err := writeJSONLine(conn, resp); err != nil {
		// Audit-on-write-failure: the daemon decided a verdict but the
		// MCP never received the response line, so from the operator's
		// perspective the action was not delivered. Record this asymmetry
		// explicitly with an "<verdict>-undelivered" status rather than
		// folding it into the bare verdict — daemon.md §5.1/§6 treat the
		// audit log as authoritative; a row that says "approved" must imply
		// "signatures left the daemon", and (F1) the SAME distinction must
		// hold for denied/timeout so a write-lost DENY is visibly logged as
		// such, not as an ordinary delivered "denied".
		auditStatus := undeliveredStatus(result.Status)
		if auditErr := d.audit(req, auditStatus, result.ApprovedBy); auditErr != nil {
			// Surface the audit error to operators rather than dropping
			// it on the floor; the write-response error is the more
			// useful one for the caller, so it stays the return value.
			fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", auditErr)
		}
		return fmt.Errorf("write response: %w", err)
	}
	return d.audit(req, result.Status.String(), result.ApprovedBy)
}

// undeliveredStatus maps a resolved verdict to its "<verdict>-undelivered"
// audit status, used when the response write fails after the daemon already
// decided. Mirrors the original approved-undelivered marker for ALL verdicts
// (F1) so a write-lost denied/timeout is logged distinctly from a delivered
// one. An unknown/error status keeps its own string (no -undelivered suffix:
// there is no decided verdict to strand).
func undeliveredStatus(s ResultStatus) string {
	switch s {
	case StatusApproved:
		return "approved-undelivered"
	case StatusDenied:
		return "denied-undelivered"
	case StatusTimeout:
		return "timeout-undelivered"
	default:
		return s.String()
	}
}

// respondError writes an {status: error} response with the given
// reason, records an audit event with status "error", and returns nil
// to the caller (the protocol level always writes a line; the caller
// only sees a non-nil error on hard I/O failure).
func (d *Daemon) respondError(conn io.Writer, reqID, reason string) error {
	resp := signResponse{RequestID: reqID, Status: "error", Error: reason, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		if auditErr := d.audit(signRequest{RequestID: reqID}, "error", ""); auditErr != nil {
			fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", auditErr)
		}
		return fmt.Errorf("write error response: %w", err)
	}
	return d.audit(signRequest{RequestID: reqID}, "error", "")
}

// handleRequestGrant processes a "request_grant" request: validate, route
// the human approval through the backend's DISTINCT grant-approval UX,
// and on approval store an in-memory standing grant. Every grant request
// produces exactly one audit row (matching the daemon's "every request is
// audited" contract).
func (d *Daemon) handleRequestGrant(ctx context.Context, conn io.ReadWriter, line []byte) error {
	var req grantRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		return d.respondGrantError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.RequestID == "" {
		return d.respondGrantError(conn, "", "missing request_id")
	}
	if req.Alias == "" {
		return d.respondGrantError(conn, req.RequestID, "missing alias")
	}
	switch req.Scope {
	case "all":
		if len(req.Commands) != 0 {
			return d.respondGrantError(conn, req.RequestID, "scope \"all\" must not carry a commands list")
		}
	case "commands":
		if len(req.Commands) == 0 {
			return d.respondGrantError(conn, req.RequestID, "scope \"commands\" requires a non-empty commands list")
		}
		for i, c := range req.Commands {
			if c == "" {
				return d.respondGrantError(conn, req.RequestID, fmt.Sprintf("commands[%d] is empty", i))
			}
		}
	default:
		return d.respondGrantError(conn, req.RequestID, fmt.Sprintf("invalid scope %q (must be \"all\" or \"commands\")", req.Scope))
	}
	if req.DurationSec <= 0 {
		return d.respondGrantError(conn, req.RequestID, "duration_seconds must be > 0")
	}
	// Compare in int64 SECONDS — never multiply attacker-controlled
	// seconds into a time.Duration (overflows negative for huge values).
	if req.DurationSec > int64(MaxGrantDuration/time.Second) {
		return d.respondGrantError(conn, req.RequestID, fmt.Sprintf("duration_seconds %d exceeds the 24h grant ceiling (%d)", req.DurationSec, int64(MaxGrantDuration/time.Second)))
	}
	duration := time.Duration(req.DurationSec) * time.Second

	resultCh, err := d.Backend.RequestGrant(ctx, GrantApprovalRequest{
		RequestID: req.RequestID,
		Alias:     req.Alias,
		Scope:     req.Scope,
		Commands:  req.Commands,
		Duration:  duration,
	})
	if err != nil {
		return d.respondGrantError(conn, req.RequestID, fmt.Sprintf("backend: %v", err))
	}

	var result Result
	select {
	case r, ok := <-resultCh:
		if !ok {
			result = Result{Status: StatusTimeout}
		} else {
			result = r
		}
	case <-ctx.Done():
		result = Result{Status: StatusTimeout}
	}

	if result.Status != StatusApproved {
		resp := grantResponse{RequestID: req.RequestID, Status: result.Status.String(), ProtoVersion: sigwire.ProtoVersion}
		if err := writeJSONLine(conn, resp); err != nil {
			d.auditGrant(req, result.Status.String(), result.ApprovedBy)
			return fmt.Errorf("write grant response: %w", err)
		}
		d.auditGrant(req, result.Status.String(), result.ApprovedBy)
		return nil
	}

	// Approved: mint the standing grant under Lock.
	gid, err := newGrantID()
	if err != nil {
		return d.respondGrantError(conn, req.RequestID, fmt.Sprintf("grant id: %v", err))
	}
	expiry := d.now().Add(duration)
	d.grantsMu.Lock()
	if d.grants == nil {
		d.grants = make(map[string]grant)
	}
	d.grants[req.Alias] = grant{
		id:       gid,
		alias:    req.Alias,
		scope:    req.Scope,
		commands: append([]string(nil), req.Commands...),
		expiry:   expiry,
	}
	d.grantsMu.Unlock()

	resp := grantResponse{RequestID: req.RequestID, Status: "approved", GrantID: gid, ExpiryUnix: expiry.Unix(), ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		// Approved + stored but the response did not reach the MCP.
		// Record the asymmetry distinctly, mirroring the sign path's
		// "approved-undelivered".
		d.auditGrant(req, "approved-undelivered", result.ApprovedBy)
		return fmt.Errorf("write grant response: %w", err)
	}
	d.auditGrant(req, "approved", result.ApprovedBy)
	return nil
}

// handleRevokeGrant processes a "revoke_grant" request: drop the standing
// grant for the alias. Revoke is de-escalation — it only ever shrinks
// capability — so it needs NO human approval and never touches the
// backend. Revoking a non-existent grant is a successful no-op.
func (d *Daemon) handleRevokeGrant(conn io.ReadWriter, line []byte) error {
	var req revokeGrantRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		return d.respondRevokeGrantError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.RequestID == "" {
		return d.respondRevokeGrantError(conn, "", "missing request_id")
	}
	if req.Alias == "" {
		return d.respondRevokeGrantError(conn, req.RequestID, "missing alias")
	}

	d.grantsMu.Lock()
	if d.grants != nil {
		delete(d.grants, req.Alias)
	}
	d.grantsMu.Unlock()

	resp := revokeGrantResponse{RequestID: req.RequestID, Status: "approved", ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditRevokeGrant(req, "approved")
		return fmt.Errorf("write revoke-grant response: %w", err)
	}
	d.auditRevokeGrant(req, "approved")
	return nil
}

// respondGrantError writes a grant "error" response and audits it.
func (d *Daemon) respondGrantError(conn io.Writer, reqID, reason string) error {
	resp := grantResponse{RequestID: reqID, Status: "error", Error: reason, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditGrant(grantRequest{RequestID: reqID}, "error", "")
		return fmt.Errorf("write grant error response: %w", err)
	}
	d.auditGrant(grantRequest{RequestID: reqID}, "error", "")
	return nil
}

// handleListGrants processes a "list_grants" request: a READ-ONLY query of
// the in-memory standing-grant table. Like revoke_grant it needs NO human
// approval and never touches the backend — it only reports state, it grants
// no capability and leaks no key material. It exists so the MCP can re-learn
// the daemon's authoritative grant state after a request_grant whose
// verdict-write was lost (phantom-live grant).
//
// It RLocks d.grantsMu, iterates the table, SKIPS any grant whose expiry is
// at-or-before now() (a dead grant is never reported), applies the optional
// alias filter, and copies the commands slice defensively. Every request
// produces exactly one audit row, matching the daemon's "every request is
// audited" contract.
func (d *Daemon) handleListGrants(conn io.ReadWriter, line []byte) error {
	var req listGrantsRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		return d.respondListGrantsError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.RequestID == "" {
		return d.respondListGrantsError(conn, "", "missing request_id")
	}

	now := d.now()
	var out []grantInfo
	d.grantsMu.RLock()
	for alias, g := range d.grants {
		if req.Alias != "" && alias != req.Alias {
			continue
		}
		// Never report a dead/phantom-expired grant. Mirrors matchGrant's
		// expiry guard: at-or-before now() is dead.
		if !g.expiry.After(now) {
			continue
		}
		out = append(out, grantInfo{
			Alias:      g.alias,
			Scope:      g.scope,
			Commands:   append([]string(nil), g.commands...),
			GrantID:    g.id,
			ExpiryUnix: g.expiry.Unix(),
		})
	}
	d.grantsMu.RUnlock()

	resp := listGrantsResponse{RequestID: req.RequestID, Status: "ok", Grants: out, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditListGrants(req, "list_grants")
		return fmt.Errorf("write list-grants response: %w", err)
	}
	d.auditListGrants(req, "list_grants")
	return nil
}

// respondListGrantsError writes a list-grants "error" response and audits it.
func (d *Daemon) respondListGrantsError(conn io.Writer, reqID, reason string) error {
	resp := listGrantsResponse{RequestID: reqID, Status: "error", Error: reason, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditListGrants(listGrantsRequest{RequestID: reqID}, "error")
		return fmt.Errorf("write list-grants error response: %w", err)
	}
	d.auditListGrants(listGrantsRequest{RequestID: reqID}, "error")
	return nil
}

// auditListGrants writes one audit row for a list_grants request. The
// "command" slot carries a synthetic descriptor so a grep over the audit
// log surfaces the read-only query alongside per-command signing. A
// read-only "list_grants" status is fine — no verdict was rendered.
func (d *Daemon) auditListGrants(req listGrantsRequest, status string) {
	desc := "list_grants"
	if req.Alias != "" {
		desc = fmt.Sprintf("list_grants alias=%s", req.Alias)
	}
	var servers []string
	if req.Alias != "" {
		servers = []string{req.Alias}
	}
	ev := AuditEvent{
		TS:        d.now().UTC(),
		RequestID: req.RequestID,
		Status:    status,
		Commands:  []string{desc},
		Servers:   servers,
	}
	if err := d.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", err)
	}
}

// respondRevokeGrantError writes a revoke-grant "error" response and audits it.
func (d *Daemon) respondRevokeGrantError(conn io.Writer, reqID, reason string) error {
	resp := revokeGrantResponse{RequestID: reqID, Status: "error", Error: reason, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditRevokeGrant(revokeGrantRequest{RequestID: reqID}, "error")
		return fmt.Errorf("write revoke-grant error response: %w", err)
	}
	d.auditRevokeGrant(revokeGrantRequest{RequestID: reqID}, "error")
	return nil
}

// auditGrant writes one audit row for a grant request. The "command"
// slot carries a synthetic descriptor so a grep over the audit log
// surfaces grant issuance alongside per-command signing.
func (d *Daemon) auditGrant(req grantRequest, status, approvedBy string) {
	desc := fmt.Sprintf("request_grant alias=%s scope=%s", req.Alias, req.Scope)
	ev := AuditEvent{
		TS:         d.now().UTC(),
		RequestID:  req.RequestID,
		Status:     status,
		Commands:   []string{desc},
		Servers:    []string{req.Alias},
		ApprovedBy: approvedBy,
	}
	if err := d.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", err)
	}
}

// auditRevokeGrant writes one audit row for a revoke-grant request.
func (d *Daemon) auditRevokeGrant(req revokeGrantRequest, status string) {
	desc := fmt.Sprintf("revoke_grant alias=%s", req.Alias)
	ev := AuditEvent{
		TS:        d.now().UTC(),
		RequestID: req.RequestID,
		Status:    status,
		Commands:  []string{desc},
		Servers:   []string{req.Alias},
	}
	if err := d.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", err)
	}
}

// handleTransfer processes a "transfer" request: validate, source the recipient
// box key + sender id key FROM THE SIGNER REGISTRY (never the request), mint a
// fresh xferID, build the two leg Cmd strings, route ONE human approval through
// the backend's distinct SECRET-TRANSFER UX, and on approval sign both legs —
// each host-bound to its own gate (SEND=src_fp, RECV=dest_fp). Mirrors
// handleRequestGrant's shape (no auto path — a standing grant can never cover a
// transfer). Every request produces exactly one audit row (metadata only).
func (d *Daemon) handleTransfer(ctx context.Context, conn io.ReadWriter, line []byte) error {
	var req transferRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		return d.respondTransferError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.RequestID == "" {
		return d.respondTransferError(conn, "", "missing request_id")
	}
	// Fail-CLOSED nil-guard: a Daemon built without a registry (tests, legacy
	// config) has no trust anchor, so it must refuse transfers with a clear
	// error rather than nil-panic in Lookup below.
	if d.XferRegistry == nil {
		return d.respondTransferError(conn, req.RequestID, "transfers unavailable: signer has no transfer registry configured")
	}

	// Field validation (fail closed, clear errors). Reuse the xferwire field
	// rules so the daemon's checks and the codec's anchored parse agree.
	if !xferwire.ValidFingerprint(req.SrcFP) {
		return d.respondTransferError(conn, req.RequestID, "invalid src_fp")
	}
	if !xferwire.ValidFingerprint(req.DestFP) {
		return d.respondTransferError(conn, req.RequestID, "invalid dest_fp")
	}
	if req.SrcFP == req.DestFP {
		return d.respondTransferError(conn, req.RequestID, "src_fp and dest_fp must differ (no self-transfer)")
	}
	if !xferwire.ValidPath(req.SrcPath) {
		return d.respondTransferError(conn, req.RequestID, "invalid src_path")
	}
	if !xferwire.ValidPath(req.DestPath) {
		return d.respondTransferError(conn, req.RequestID, "invalid dest_path")
	}
	if !xferwire.ValidMode(req.Mode) {
		return d.respondTransferError(conn, req.RequestID, fmt.Sprintf("invalid mode %q (allowed: 0600)", req.Mode))
	}
	ttl := req.TTLSec
	if ttl <= 0 {
		return d.respondTransferError(conn, req.RequestID, "ttl_seconds must be > 0")
	}
	// Compare in int64 SECONDS — never multiply attacker-controlled seconds into
	// a time.Duration (overflows negative for huge values). The gate re-checks
	// authoritatively; this is the signer-side cap.
	if ttl > int64(sigwire.MaxSigValidity/time.Second) {
		return d.respondTransferError(conn, req.RequestID, fmt.Sprintf("ttl_seconds %d exceeds max %d", ttl, int64(sigwire.MaxSigValidity/time.Second)))
	}

	// THE anti-MITM invariant: box_pub and id_pub come ONLY from the registry,
	// keyed by the fingerprints, NEVER from the request. An unregistered fp
	// fails the lookup; a registered fp yields a HUMAN-registered key.
	boxPub, _, destLabel, ok := d.XferRegistry.Lookup(req.DestFP) // recipient box key
	if !ok {
		return d.respondTransferError(conn, req.RequestID, "dest server not registered for transfer")
	}
	_, idPub, srcLabel, ok := d.XferRegistry.Lookup(req.SrcFP) // sender identity key
	if !ok {
		return d.respondTransferError(conn, req.RequestID, "src server not registered for transfer")
	}

	// Mint a fresh signer-side xferID (the agent never supplies it, so it cannot
	// correlate/replay a stale leg across transfers).
	xferID, err := newXferID()
	if err != nil {
		return d.respondTransferError(conn, req.RequestID, fmt.Sprintf("xfer id: %v", err))
	}

	// Build both leg Cmd strings (injection-safe codec). The recipient box key
	// and sender id key are the registry-sourced pubkeys.
	sendCmd, err := xferwire.EncodeSend(boxPub, xferID, req.DestFP, req.SrcPath)
	if err != nil {
		return d.respondTransferError(conn, req.RequestID, fmt.Sprintf("build send leg: %v", err))
	}
	recvCmd, err := xferwire.EncodeRecv(idPub, xferID, req.SrcFP, req.DestFP, req.Mode, req.DestPath)
	if err != nil {
		return d.respondTransferError(conn, req.RequestID, fmt.Sprintf("build recv leg: %v", err))
	}

	// One human approval. The banner labels come from the REGISTRY, not the MCP
	// alias, so a lying MCP cannot mislabel src/dest.
	resultCh, err := d.Backend.RequestTransfer(ctx, TransferApprovalRequest{
		RequestID: req.RequestID,
		XferID:    xferID,
		SrcLabel:  srcLabel,
		SrcFP:     req.SrcFP,
		SrcPath:   req.SrcPath,
		DestLabel: destLabel,
		DestFP:    req.DestFP,
		DestPath:  req.DestPath,
		Mode:      req.Mode,
	})
	if err != nil {
		return d.respondTransferError(conn, req.RequestID, fmt.Sprintf("backend: %v", err))
	}

	var result Result
	select {
	case r, ok := <-resultCh:
		if !ok {
			result = Result{Status: StatusTimeout}
		} else {
			result = r
		}
	case <-ctx.Done():
		result = Result{Status: StatusTimeout}
	}

	if result.Status != StatusApproved {
		resp := transferResponse{RequestID: req.RequestID, Status: result.Status.String(), ProtoVersion: sigwire.ProtoVersion}
		if err := writeJSONLine(conn, resp); err != nil {
			d.auditTransfer(req, xferID, undeliveredStatus(result.Status), result.ApprovedBy)
			return fmt.Errorf("write transfer response: %w", err)
		}
		d.auditTransfer(req, xferID, result.Status.String(), result.ApprovedBy)
		return nil
	}

	// Approved: sign both legs, each with its own Host binding.
	send, recv, err := d.signTransferLegs(sendCmd, req.SrcFP, recvCmd, req.DestFP, ttl)
	if err != nil {
		// Post-approval failure (fold-in b): the human APPROVED but signing the
		// legs failed, so audit "approved-error" (not the bare "error" that
		// respondTransferError records) so the F4 auth-mode still records the
		// human tap, matching the "approved-undelivered" precedent.
		resp := transferResponse{RequestID: req.RequestID, Status: "error", Error: fmt.Sprintf("sign: %v", err), ProtoVersion: sigwire.ProtoVersion}
		if werr := writeJSONLine(conn, resp); werr != nil {
			d.auditTransfer(req, xferID, "approved-error", result.ApprovedBy)
			return fmt.Errorf("write transfer response: %w", werr)
		}
		d.auditTransfer(req, xferID, "approved-error", result.ApprovedBy)
		return nil
	}
	resp := transferResponse{
		RequestID:    req.RequestID,
		Status:       "approved",
		AuthMode:     authMode(true, result.ApprovedBy),
		XferID:       xferID,
		Send:         send,
		Recv:         recv,
		ProtoVersion: sigwire.ProtoVersion,
	}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditTransfer(req, xferID, "approved-undelivered", result.ApprovedBy)
		return fmt.Errorf("write transfer response: %w", err)
	}
	d.auditTransfer(req, xferID, "approved", result.ApprovedBy)
	return nil
}

// signTransferLegs signs the two transfer legs with d.Key, each host-bound to
// its own gate (SEND=srcFP, RECV=destFP). It is the per-command host-stamping
// signAll already does, specialised to exactly two commands under one approval.
// Reveal is never set. No new SigPayload field — both legs ride inside
// SigPayload.Cmd like SSHGATE_UPDATE, so payload_golden_test.go stays byte-safe.
func (d *Daemon) signTransferLegs(sendCmd, sendFP, recvCmd, recvFP string, ttl int64) (send, recv *transferLeg, err error) {
	now := d.now().Unix()
	signOne := func(cmd, host string) (*transferLeg, error) {
		nonce, err := newNonce()
		if err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		payload := sigwire.SigPayload{
			Cmd:   cmd,
			TS:    now,
			Exp:   now + ttl,
			Nonce: nonce,
			Host:  host,
		}
		signedBytes, err := jsonMarshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		// Route through the single custody choke point (C1/C3/C7): Lock
		// refuses the leg here, and the crypto.Signer seam (crypto.Hash(0))
		// keeps the file-key bytes identical to the old ed25519.Sign call.
		sig, err := d.signBytes(signedBytes)
		if err != nil {
			return nil, err
		}
		wire, err := sigwire.EncodeSigned(sig, payload)
		if err != nil {
			return nil, fmt.Errorf("encode: %w", err)
		}
		return &transferLeg{Cmd: cmd, Sig: wire}, nil
	}
	if send, err = signOne(sendCmd, sendFP); err != nil {
		return nil, nil, err
	}
	if recv, err = signOne(recvCmd, recvFP); err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

// respondTransferError writes a transfer "error" response and audits it.
func (d *Daemon) respondTransferError(conn io.Writer, reqID, reason string) error {
	resp := transferResponse{RequestID: reqID, Status: "error", Error: reason, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditTransfer(transferRequest{RequestID: reqID}, "", "error", "")
		return fmt.Errorf("write transfer error response: %w", err)
	}
	d.auditTransfer(transferRequest{RequestID: reqID}, "", "error", "")
	return nil
}

// auditTransfer writes one audit row for a transfer request. METADATA ONLY —
// never the plaintext value (which the signer never sees anyway): source/dest
// fingerprints, the minted xferID, and the mode. The "command" slot carries a
// synthetic descriptor so a grep over the audit log surfaces transfers.
func (d *Daemon) auditTransfer(req transferRequest, xferID, status, approvedBy string) {
	desc := fmt.Sprintf("transfer src=%s dest=%s xfer=%s mode=%s", req.SrcFP, req.DestFP, xferID, req.Mode)
	var servers []string
	if req.SrcFP != "" || req.DestFP != "" {
		servers = []string{req.SrcFP, req.DestFP}
	}
	ev := AuditEvent{
		TS:         d.now().UTC(),
		RequestID:  req.RequestID,
		Status:     status,
		Commands:   []string{desc},
		Servers:    servers,
		ApprovedBy: approvedBy,
		AuthMode:   authMode(strings.HasPrefix(status, "approved"), approvedBy),
	}
	if err := d.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", err)
	}
}

// handleRegisterXferKey processes a "register_xfer_key" request: the human-only,
// always-prompt registration of a server's box→box transfer keys. It mirrors
// handleRequestGrant's STRUCTURAL always-prompt — it unconditionally routes
// through Backend.RequestRegisterKey (a human tap) and mutates the registry ONLY
// after StatusApproved. There is no auto path and no MCP tool. One audit row per
// request (metadata only — key text is public, but we log a compact descriptor).
func (d *Daemon) handleRegisterXferKey(ctx context.Context, conn io.ReadWriter, line []byte) error {
	var req registerXferKeyRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		return d.respondRegisterXferKeyError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.RequestID == "" {
		return d.respondRegisterXferKeyError(conn, "", "missing request_id")
	}
	if d.XferRegistry == nil {
		return d.respondRegisterXferKeyError(conn, req.RequestID, "registration unavailable: signer has no transfer registry configured")
	}
	if !xferwire.ValidFingerprint(req.HostFP) {
		return d.respondRegisterXferKeyError(conn, req.RequestID, "invalid host_fp")
	}
	// Validate the key material BEFORE prompting so a malformed key never wastes
	// a human tap (and can never land in the registry).
	if _, err := xfer.ParseBoxPublicText(req.BoxPub); err != nil {
		return d.respondRegisterXferKeyError(conn, req.RequestID, "invalid box_pub")
	}
	if _, err := xfer.ParseIDPublicText(req.IDPub); err != nil {
		return d.respondRegisterXferKeyError(conn, req.RequestID, "invalid id_pub")
	}
	// Authoritative label-length cap BEFORE the prompt (fold-in a): an oversized
	// label must never reach the human tap or the registry. Generic error text —
	// never echo the label back.
	if len(req.Label) > maxXferLabelLen {
		return d.respondRegisterXferKeyError(conn, req.RequestID, "invalid label")
	}

	resultCh, err := d.Backend.RequestRegisterKey(ctx, RegisterApprovalRequest{
		RequestID: req.RequestID,
		HostFP:    req.HostFP,
		Label:     req.Label,
		BoxPub:    req.BoxPub,
		IDPub:     req.IDPub,
	})
	if err != nil {
		return d.respondRegisterXferKeyError(conn, req.RequestID, fmt.Sprintf("backend: %v", err))
	}

	var result Result
	select {
	case r, ok := <-resultCh:
		if !ok {
			result = Result{Status: StatusTimeout}
		} else {
			result = r
		}
	case <-ctx.Done():
		result = Result{Status: StatusTimeout}
	}

	if result.Status != StatusApproved {
		resp := registerXferKeyResponse{RequestID: req.RequestID, Status: result.Status.String(), ProtoVersion: sigwire.ProtoVersion}
		if err := writeJSONLine(conn, resp); err != nil {
			d.auditRegisterXferKey(req, undeliveredStatus(result.Status), result.ApprovedBy)
			return fmt.Errorf("write register-xfer-key response: %w", err)
		}
		d.auditRegisterXferKey(req, result.Status.String(), result.ApprovedBy)
		return nil
	}

	// Approved: mutate the registry (persisted atomically at 0600). Overwrite is
	// an authorised rotation — this write is human-approved.
	if err := d.XferRegistry.Register(req.HostFP, req.Label, req.BoxPub, req.IDPub); err != nil {
		// Post-approval failure (fold-in b): the human APPROVED but the registry
		// write failed, so audit "approved-error" (not the bare "error" that
		// respondRegisterXferKeyError records) — the F4 auth-mode then still
		// records the human tap, matching the "approved-undelivered" precedent.
		// respondRegisterXferKeyError hardcodes "error" + empty approvedBy, so we
		// write the error response inline here.
		resp := registerXferKeyResponse{RequestID: req.RequestID, Status: "error", Error: fmt.Sprintf("register: %v", err), ProtoVersion: sigwire.ProtoVersion}
		if werr := writeJSONLine(conn, resp); werr != nil {
			d.auditRegisterXferKey(req, "approved-error", result.ApprovedBy)
			return fmt.Errorf("write register-xfer-key response: %w", werr)
		}
		d.auditRegisterXferKey(req, "approved-error", result.ApprovedBy)
		return nil
	}
	resp := registerXferKeyResponse{RequestID: req.RequestID, Status: "approved", ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditRegisterXferKey(req, "approved-undelivered", result.ApprovedBy)
		return fmt.Errorf("write register-xfer-key response: %w", err)
	}
	d.auditRegisterXferKey(req, "approved", result.ApprovedBy)
	return nil
}

// respondRegisterXferKeyError writes a register-xfer-key "error" response and
// audits it.
func (d *Daemon) respondRegisterXferKeyError(conn io.Writer, reqID, reason string) error {
	resp := registerXferKeyResponse{RequestID: reqID, Status: "error", Error: reason, ProtoVersion: sigwire.ProtoVersion}
	if err := writeJSONLine(conn, resp); err != nil {
		d.auditRegisterXferKey(registerXferKeyRequest{RequestID: reqID}, "error", "")
		return fmt.Errorf("write register-xfer-key error response: %w", err)
	}
	d.auditRegisterXferKey(registerXferKeyRequest{RequestID: reqID}, "error", "")
	return nil
}

// auditRegisterXferKey writes one audit row for a register_xfer_key request. The
// key text is public; the descriptor records the host fp + label so a grep
// surfaces trust-anchor changes.
func (d *Daemon) auditRegisterXferKey(req registerXferKeyRequest, status, approvedBy string) {
	desc := fmt.Sprintf("register_xfer_key host=%s label=%s", req.HostFP, req.Label)
	var servers []string
	if req.HostFP != "" {
		servers = []string{req.HostFP}
	}
	ev := AuditEvent{
		TS:         d.now().UTC(),
		RequestID:  req.RequestID,
		Status:     status,
		Commands:   []string{desc},
		Servers:    servers,
		ApprovedBy: approvedBy,
		AuthMode:   authMode(strings.HasPrefix(status, "approved"), approvedBy),
	}
	if err := d.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", err)
	}
}

// matchGrant reports whether EVERY command in cmds is covered by a live
// standing grant for its alias, returning the matched grant id for the
// audit trail. It is the auto-approve gate: when ok is true the daemon
// signs without prompting.
//
// Security-critical guards, in order:
//
//   - REVEAL ALWAYS PROMPTS. If ANY command is a SECRET-REVEAL, the whole
//     request falls through to the human prompt — a grant NEVER
//     auto-signs a reveal. This is checked first/outermost so no later
//     logic can accidentally auto-approve a reveal.
//   - NO PARTIAL AUTO-APPROVE. A single command that does not match a
//     live grant fails the whole request (returns ok=false), so the
//     human prompt covers the full set rather than a subset.
//   - EXACT-STRING SCOPE. For scope=="commands", c.Cmd must equal a
//     stored command string exactly — no prefix/substring/argument
//     tolerance. scope=="all" matches any command on that alias.
//   - EXPIRY. A grant whose expiry is at-or-before now() is dead and
//     matches nothing (the signer never auto-signs past a grant window).
//   - PER-ALIAS. Each command is checked against the grant for ITS OWN
//     alias (c.Server), so a grant for alias X can never auto-sign a
//     command aimed at alias Y.
//
// The returned id is the grant matched by the FIRST command. run /
// run_batch always target a single alias, so all commands share one
// grant and the first id is the right audit anchor; if a future
// multi-alias request had every command covered by its own alias's
// grant, recording the first is still an accurate "auto-approved under a
// grant" marker.
func (d *Daemon) matchGrant(cmds []signRequestCmd) (id string, ok bool) {
	// Reveal + admin-verb short-circuit FIRST: a reveal OR an administrative
	// verb (SSHGATE_UPDATE / SSHGATE_REVOKE / any SSHGATE_ gate verb) anywhere
	// forces a human prompt. A grant must NEVER auto-sign an admin verb: the
	// gate dispatches on the command prefix regardless of which signer path
	// minted the signature, so this carve-out is the ONLY control that stops a
	// scope=all grant from silently authorizing a gate replacement or teardown
	// (see docs/proposed/sshgate-update-verb-2026-07.md Finding 1). Checked
	// first/outermost, like the reveal guard, so no later grant logic can
	// re-admit it; it fails safe (over-prompt, never under-prompt).
	for _, c := range cmds {
		if c.Reveal || isAdminVerb(c.Cmd) {
			return "", false
		}
	}
	if len(cmds) == 0 {
		return "", false
	}

	d.grantsMu.RLock()
	defer d.grantsMu.RUnlock()
	if d.grants == nil {
		return "", false
	}

	now := d.now()
	var firstID string
	for i, c := range cmds {
		g, exists := d.grants[c.Server]
		if !exists {
			return "", false
		}
		if !g.expiry.After(now) {
			// Expired (or exactly at expiry): dead grant, prompt.
			return "", false
		}
		if !grantCovers(g, c.Cmd) {
			return "", false
		}
		if i == 0 {
			firstID = g.id
		}
	}
	return firstID, true
}

// isAdminVerb reports whether cmd is (or would dispatch to) an SSHGate
// administrative gate verb — SSHGATE_REVOKE (gate teardown) or
// SSHGATE_UPDATE (in-place gate-binary replacement). It matches the bare
// "SSHGATE_" prefix: the gate keys its admin dispatch on this prefix
// (main.go), no legitimate shell command begins with it, and a stray match
// only forces a human prompt (fail-safe). It is the guard that keeps a
// standing grant from ever auto-signing a gate-control verb; the human tap
// (and, for updates, the scary approval banner) is then mandatory.
func isAdminVerb(cmd string) bool {
	return strings.HasPrefix(cmd, "SSHGATE_")
}

// isTransferVerb reports whether cmd is a box→box transfer verb
// (SSHGATE_XFER_SEND / SSHGATE_XFER_RECV, or any future SSHGATE_XFER_*). These
// are rejected on the generic sign path (they must go through the dedicated
// "transfer" kind) and are a strict subset of isAdminVerb (so matchGrant also
// refuses to auto-sign them). It keys on the shared xferwire.VerbPrefix so the
// signer and the gate can never disagree on what counts as a transfer verb.
func isTransferVerb(cmd string) bool {
	return strings.HasPrefix(cmd, xferwire.VerbPrefix)
}

// grantCovers reports whether grant g authorises command cmd. scope=="all"
// covers everything on the alias; scope=="commands" covers ONLY an exact
// string match (no patterns, no argument tolerance).
func grantCovers(g grant, cmd string) bool {
	switch g.scope {
	case "all":
		return true
	case "commands":
		for _, allowed := range g.commands {
			if allowed == cmd {
				return true
			}
		}
		return false
	default:
		// Unknown scope never auto-approves (defensive; create-time
		// validation already rejects anything but all/commands).
		return false
	}
}

// signAll signs each command in cmds with d.Key and returns the wire-
// encoded signed strings. Each signature uses an independent random
// nonce.
func (d *Daemon) signAll(cmds []signRequestCmd) ([]signResponseSig, error) {
	out := make([]signResponseSig, len(cmds))
	now := d.now().Unix()
	for i, c := range cmds {
		nonce, err := newNonce()
		if err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		payload := sigwire.SigPayload{
			Cmd:   c.Cmd,
			TS:    now,
			Exp:   now + c.TTLSec,
			Nonce: nonce,
			// Bind the signature to the target's pinned host key. The MCP
			// sourced this from its trusted registry; the gate enforces it.
			Host: c.Host,
			// Carry the SECRET-REVEAL capability INTO the signed bytes. Only a
			// human-approved request reaches here, so signing reveal=true means
			// the gate will run that one command's output un-redacted. The
			// agent never sets this — it is authorised by the approval the
			// signer is responding to.
			Reveal: c.Reveal,
		}
		// Sign the exact bytes that DecodeSigned will reconstruct on
		// the verifier side; sigwire.EncodeSigned + verify.go both go
		// through json.Marshal of SigPayload, so the byte sequence is
		// stable.
		signedBytes, err := jsonMarshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		// Route through the single custody choke point (C1/C3/C7): Lock
		// refuses the signature here, and the crypto.Signer seam
		// (crypto.Hash(0)) keeps the file-key bytes byte-identical to the
		// old ed25519.Sign call (the phase-0 envelope goldens prove it).
		sig, err := d.signBytes(signedBytes)
		if err != nil {
			return nil, err
		}
		wire, err := sigwire.EncodeSigned(sig, payload)
		if err != nil {
			return nil, fmt.Errorf("encode: %w", err)
		}
		out[i] = signResponseSig{Cmd: c.Cmd, Sig: wire}
	}
	return out, nil
}

// audit writes a single AuditEvent for req with status / approvedBy.
// d.Audit MUST be non-nil; the daemon contract is "every request
// produces an audit row." Tests that want a no-op sink should
// construct one via signer.NewMemAuditLog rather than passing
// nil — that keeps the audit code path on every test.
func (d *Daemon) audit(req signRequest, status, approvedBy string) error {
	cmds := make([]string, len(req.Commands))
	servers := make([]string, len(req.Commands))
	for i, c := range req.Commands {
		// Redact a secret embedded in the command STRING before persisting it
		// (F5). The audit log carries the full command text of every approval
		// request; a `printf 'PASSWORD=...'` would otherwise land verbatim.
		// Fail-OPEN: on an internal redactor error, record the raw command
		// rather than drop the audit line. Benign commands pass through, and a
		// Daemon with no ruleset wired (nil) records verbatim too.
		red, ok := redact.RedactString(c.Cmd, d.RedactSalt, d.RedactRules)
		if !ok {
			red = c.Cmd
		}
		cmds[i] = red
		servers[i] = c.Server
	}
	ev := AuditEvent{
		TS:         d.now().UTC(),
		RequestID:  req.RequestID,
		Status:     status,
		Commands:   cmds,
		Servers:    servers,
		ApprovedBy: approvedBy,
		// First-class auth_mode (F4-B4): same helper as the socket response so
		// the authoritative log carries both WHO (approved_by) and HOW
		// (auth_mode) and the two never drift. Gated on the APPROVAL STATE via
		// the already-mapped status string: an approval is "approved" OR
		// "approved-undelivered" (HasPrefix "approved"), so an approved-
		// undelivered still records human/grant, while denied/denied-undelivered
		// /timeout/timeout-undelivered/error all record "" — even though the
		// real Telegram backend hands the denier's name through approvedBy.
		AuthMode: authMode(strings.HasPrefix(status, "approved"), approvedBy),
	}
	if err := d.Audit.Write(ev); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}

func (d *Daemon) now() time.Time {
	if d.NowFunc != nil {
		return d.NowFunc()
	}
	return time.Now()
}

// randRead is the entropy source used by newNonce. It is a package-level
// var (not a direct call to rand.Read) solely so in-package tests can
// substitute a failing reader to exercise the nonce-error branch of
// signAll. Production code never reassigns it; the default is the
// crypto/rand reader and the attack surface is unchanged.
var randRead = rand.Read

// newNonce returns a 16-byte URL-safe-base64 random string. 128 bits
// of entropy is plenty for replay-protection within the 5-minute
// validity window.
func newNonce() (string, error) {
	var buf [16]byte
	if _, err := randRead(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// newGrantID returns a short random grant identifier prefixed "g_". It
// is used purely as an audit anchor (ApprovedBy = "grant:<id>") — it is
// never security-bearing, so 96 bits of entropy is ample. Uses the same
// randRead seam as newNonce so a broken RNG surfaces as an error.
func newGrantID() (string, error) {
	var buf [12]byte
	if _, err := randRead(buf[:]); err != nil {
		return "", err
	}
	return "g_" + base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// newXferID returns a 16-byte (128-bit) URL-safe-base64 random transfer id.
// It is minted by the SIGNER on every transfer approval — the agent never
// supplies it — so an old, already-attested envelope cannot be replayed under a
// fresh approval. Uses the same randRead seam as newNonce so a broken RNG
// surfaces as an error. The RawURLEncoding alphabet ([A-Za-z0-9_-]) is exactly
// what xferwire.ValidXferID accepts.
func newXferID() (string, error) {
	var buf [16]byte
	if _, err := randRead(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// writeJSONLine marshals v and writes it followed by a newline.
//
// Immediately before the write it RESETS the connection's write deadline to
// now + sigwire.ResponseWriteGrace (see setWriteGrace). serveOne bounds the
// approval WAIT to SignerHandlerTimeout - ResponseWriteGrace, so a verdict
// that resolves at the wait deadline would otherwise have ~zero budget left
// to write its response line — the verdict would race the connection to
// teardown and the MCP would see a bare EOF / i-o-timeout with no sentinel
// (F1: verdict-undelivered). The reset hands every response write a fresh,
// non-racing budget regardless of how long the wait took. Centralised here
// so no verdict/error write site (respond, respondError, the grant/revoke
// paths) can be missed. It no-ops for non-deadline writers, so test fakes
// that pass a *bytes.Buffer are unaffected.
func writeJSONLine(w io.Writer, v any) error {
	setWriteGrace(w)
	b, err := jsonMarshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// setWriteGrace resets w's write deadline to now + sigwire.ResponseWriteGrace
// when w is a deadline-capable connection. The response helpers take a plain
// io.Writer (so tests can pass a *bytes.Buffer), hence the type assertion:
// it applies the fresh write budget to a real *net.Conn and is a no-op for
// anything that does not expose SetDeadline.
func setWriteGrace(w io.Writer) {
	if c, ok := w.(interface{ SetDeadline(time.Time) error }); ok {
		_ = c.SetDeadline(time.Now().Add(sigwire.ResponseWriteGrace))
	}
}

// jsonMarshal is a thin alias kept so the daemon imports encoding/json
// in exactly one place, easing future swaps if needed.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Compile-time assertion that *Daemon implements RequestHandler.
var _ RequestHandler = (*Daemon)(nil)
