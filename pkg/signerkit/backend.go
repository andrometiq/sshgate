package signerkit

import (
	"context"
	"time"

	"github.com/karthikeyan5/sshgate/src/policywire"
)

// ApprovalRequest is the unit of work submitted to a Backend. The
// RequestID is opaque to the backend — the daemon generates it and uses
// it both to correlate the result and as the audit-log key. Submitted is
// the wall-clock timestamp at which the daemon received the request from
// the MCP; backends include it in their UI when relevant.
type ApprovalRequest struct {
	RequestID string
	Commands  []CommandReq
	Submitted time.Time
}

// GrantApprovalRequest is the unit of work submitted to a Backend's
// RequestGrant: a request for the human to mint a STANDING GRANT. Unlike
// an ApprovalRequest (which approves specific commands once), approving a
// grant authorises the signer to auto-sign matching commands for the
// whole Duration WITHOUT further taps — so the backend MUST render it
// with a distinct, scary UX that makes that consequence unmistakable.
//
//   - Scope == "all"      → any command on Alias auto-signs.
//   - Scope == "commands" → only the exact strings in Commands auto-sign.
//
// Duration is the requested window; the signer caps it at 24h before
// calling and records expiry = now + Duration on approval. RequestID
// correlates the result and keys the audit row, exactly like
// ApprovalRequest.
type GrantApprovalRequest struct {
	RequestID string
	Alias     string
	Scope     string
	Commands  []string
	Duration  time.Duration
}

// TransferApprovalRequest is the unit of work submitted to a Backend's
// RequestTransfer: a request for the human to approve a box→box SECRET
// TRANSFER. Approving it lets the signer mint the two host-bound signed legs
// (SEND on the source gate, RECV on the destination gate) under ONE tap — so
// the backend MUST render it with a distinct, alarming UX naming the
// consequence (a secret file moving across hosts).
//
// SECURITY. SrcLabel/DestLabel come from the SIGNER's registry, NOT the MCP's
// alias, so a lying MCP cannot mislabel the destination in the banner. The two
// fingerprints, paths, and mode are the banner's factual content; the backend
// shape-validates each so a smuggled newline cannot forge a banner line.
// XferID is the signer-minted transfer id (shown so the operator can
// cross-reference the audit). No key material is ever carried here.
type TransferApprovalRequest struct {
	RequestID string
	XferID    string
	SrcLabel  string
	SrcFP     string
	SrcPath   string
	DestLabel string
	DestFP    string
	DestPath  string
	Mode      string
}

// RegisterApprovalRequest is the unit of work submitted to a Backend's
// RequestRegisterKey: a request for the human to approve REGISTERING a server's
// box→box transfer keys into the signer's registry. It is the human-only
// control that populates the transfer trust anchor; there is deliberately no
// MCP tool for it, and even this human path always prompts. Label is the
// display name; BoxPub/IDPub are the canonical PublicText key lines the operator
// confirms.
type RegisterApprovalRequest struct {
	RequestID string
	HostFP    string
	Label     string
	BoxPub    string
	IDPub     string
}

// BaseManifestApprovalRequest is the dedicated, always-human-reviewed policy
// unit submitted only through BaseManifestApprovalBackend. Payload is the
// exact canonical BaseManifest payload; it must never be re-marshaled before
// review or signing. ExpectedHeadDigest is empty only for Bootstrap.
//
// This type is deliberately disjoint from ApprovalRequest and carries no
// command-signing TTL, grant scope, or sigwire payload.
type BaseManifestApprovalRequest struct {
	RequestID           string
	HostKeyFP           string
	ExpectedSignerKeyID string
	Payload             []byte
	ExpectedHeadDigest  string
	Bootstrap           bool
	Submitted           time.Time
}

// BaseManifestResultKind makes the custody boundary non-zero and explicit. A
// handler must switch on it and fail closed on BaseManifestResultInvalid.
type BaseManifestResultKind uint8

const (
	BaseManifestResultInvalid BaseManifestResultKind = iota
	// BaseManifestResultLocalDecision means the backend returned only the
	// human decision; the local daemon materializes an approval through its
	// own custody method.
	BaseManifestResultLocalDecision
	// BaseManifestResultRemoteEnvelope means a hosted authority returned the
	// approved ManifestEnvelope. Invalid/empty remote material never falls
	// through to local custody.
	BaseManifestResultRemoteEnvelope
)

// BaseManifestApprovalResult is one human policy decision. Kind is the
// explicit custody boundary. Non-approved results never carry an envelope.
type BaseManifestApprovalResult struct {
	Status           policywire.Status
	ErrorCode        policywire.ErrorCode
	Retryable        bool
	ApprovedBy       string
	Kind             BaseManifestResultKind
	ManifestEnvelope []byte
}

// CommandReq is a single command awaiting approval. Server is the human-
// readable alias from the MCP's registry (e.g. "prod-db"); Cmd is the
// literal shell command line; TTLSec is the spec's signature validity
// window (`exp - ts`), bounded by sigwire.MaxSigValidity (5 minutes).
//
// Reveal marks this as a SECRET-REVEAL: if approved, the gate runs the
// command's output WITHOUT the redactor (raw secrets flow to the agent). The
// approval UX MUST render reveal distinctly and scarily. Reason is the
// mandatory human-readable justification the operator sees; it is required
// (enforced MCP-side) whenever Reveal is true, and shown in the approval
// message so the human knows WHY raw secrets are being requested. Both are
// zero for ordinary writes.
type CommandReq struct {
	Server string
	Cmd    string
	TTLSec int64
	Reveal bool
	Reason string
	// HostKeyFP is the target server's SSH host-key fingerprint
	// ("SHA256:..."), sourced by the MCP from its TRUSTED registry (never an
	// agent parameter). A remote-signing backend (HostedServerBackend) carries
	// it over the machine wire so the hosted signer can bind the minted
	// SigPayload.Host to the executing gate — the gate fail-closes a Host-less
	// or mismatched write (gate.ErrHostMismatch). Local-signing backends ignore
	// it (the local daemon binds Host from its own socket signRequestCmd.Host).
	HostKeyFP string
}

// ResultStatus is the outcome of an ApprovalRequest. The zero value is
// StatusApproved deliberately: this is a "secure by default" inversion
// avoided here — callers MUST check the explicit value, never rely on
// the zero. (We accept the zero-is-approved risk because StubBackend
// returns StatusDenied as a constant and the daemon checks the status
// explicitly before signing.)
type ResultStatus int

const (
	// StatusApproved means the human (or the stub policy) authorised
	// signing every command in the request.
	StatusApproved ResultStatus = iota
	// StatusDenied means the human explicitly rejected the request.
	StatusDenied
	// StatusTimeout means no decision arrived within the backend's
	// implementation-defined wait window.
	StatusTimeout
)

// String returns the lowercase wire-format spelling of the status:
// "approved", "denied", "timeout". Used by the audit log and the
// socket response encoder; keep it stable.
func (s ResultStatus) String() string {
	switch s {
	case StatusApproved:
		return "approved"
	case StatusDenied:
		return "denied"
	case StatusTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// SignedCmd is a single pre-signed command produced by a remote-signing
// backend. Cmd is the literal shell command line (must match the
// corresponding ApprovalRequest.Commands[i].Cmd verbatim); Sig is the
// fully-formed "SSHGATE_SIG:..." wire string the daemon will return to
// the MCP without further processing.
type SignedCmd struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"` // "SSHGATE_SIG:..." full wire string
}

// Result is the resolution of a single ApprovalRequest. ApprovedBy is
// populated when the backend can identify the approver (e.g. Telegram's
// from.id) — used purely for the audit log. Stub and mock leave it
// empty.
type Result struct {
	Status     ResultStatus
	ApprovedBy string
	// Signatures, when non-nil, contains pre-signed wire strings for each
	// command in the original ApprovalRequest. Set by remote-signing
	// backends (HostedServerBackend). Local-signing backends leave nil.
	Signatures []SignedCmd
}

// Backend abstracts the approval-channel mechanism (Telegram in v1.2,
// hosted HTTPS server in v2, plus the test-only Stub and Mock).
//
// Implementations MUST be safe for concurrent calls: the daemon serves
// multiple sign requests in parallel.
//
// Request submits the approval request and returns a channel that will
// yield exactly one Result. On a hard error during submission, Request
// returns the error and no channel; once a channel has been returned,
// the daemon's only contract with the caller is to read one Result from
// it. Implementations decide their own timeout policy independent of
// ctx; they SHOULD honour ctx cancellation by yielding StatusTimeout (or
// a more specific status if defined later).
type Backend interface {
	Request(ctx context.Context, req ApprovalRequest) (<-chan Result, error)

	// RequestGrant submits a STANDING-GRANT approval request and returns
	// a channel yielding exactly one Result, with the same contract and
	// concurrency guarantees as Request. The Result's Signatures field is
	// unused for grants (the daemon mints per-command signatures later, on
	// demand). A backend that cannot safely render the distinct grant UX
	// MUST fail closed by returning an error (the hosted backend does this
	// until its web UI carries the grant banner).
	RequestGrant(ctx context.Context, req GrantApprovalRequest) (<-chan Result, error)

	// RequestTransfer submits a box→box SECRET-TRANSFER approval request and
	// returns a channel yielding exactly one Result, same contract and
	// concurrency as Request. The Result's Signatures field is unused (the
	// daemon mints the two host-bound legs locally on approval). A backend that
	// cannot render the distinct, alarming transfer banner MUST fail closed by
	// returning an error (the hosted/Tier-3 backend does — transfers are
	// Tier-2/local-signer only in P2).
	RequestTransfer(ctx context.Context, req TransferApprovalRequest) (<-chan Result, error)

	// RequestRegisterKey submits an XFER-KEY REGISTER approval request (populate
	// the signer's transfer trust anchor) and returns a channel yielding exactly
	// one Result, same contract and concurrency as Request. It is always a human
	// prompt — there is no auto path and no MCP tool. A backend that cannot
	// render the distinct register banner MUST fail closed by returning an error.
	RequestRegisterKey(ctx context.Context, req RegisterApprovalRequest) (<-chan Result, error)
}

// BaseManifestApprovalBackend is an additive optional capability. Keeping it
// separate preserves the public Backend contract and makes unsupported
// backends fail closed before any policy mint. Implementations must be safe
// for concurrent calls and deliver one result without stranding a producer if
// ctx is canceled.
type BaseManifestApprovalBackend interface {
	RequestBaseManifest(ctx context.Context, req BaseManifestApprovalRequest) (<-chan BaseManifestApprovalResult, error)
}
