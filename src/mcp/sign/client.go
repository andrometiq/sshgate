package sign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// ErrDenied is returned by Sign when signer replied with
// status="denied".
var ErrDenied = errors.New("sign: denied by operator")

// ErrTimeout is returned by Sign when signer replied with
// status="timeout" (or the Client.Timeout elapsed before a reply).
var ErrTimeout = errors.New("sign: approval timed out")

// ErrUnreachable is returned by Sign when the signer socket file
// is missing, refusing connections, or unreachable for some other
// transport-layer reason.
var ErrUnreachable = errors.New("sign: signer unreachable")

// ErrSignerPermission is returned by Sign when the signer socket file
// is present but the dial is refused with a permission error (EACCES /
// EPERM). The socket is mode 0660 owned by the sshgatesigner group; a
// shell/session that has not yet picked up that group membership hits
// this — the daemon is alive, the caller just lacks access. Distinct
// from ErrUnreachable so the user gets "log out and back in" guidance
// instead of "the daemon is dead".
var ErrSignerPermission = errors.New("sign: signer socket permission denied")

// ErrVerdictUnknown is returned when the request was FULLY WRITTEN but the
// response read then failed with EOF or a net/deadline timeout while the
// caller's context was still live. The signer may already have reached a
// verdict (including a human DENY) that simply did not make it back over the
// socket — the outcome is INDETERMINATE. It is deliberately distinct from
// the transport sentinels so the run/run_batch layer can fail SAFE: do NOT
// auto-retry (a retry could re-attempt a write a human denied); surface the
// audit/Telegram thread to the human instead. Contrast a genuine
// malformed/partial reply or an unreachable daemon, which stay their own
// (retryable-or-diagnosable) errors.
var ErrVerdictUnknown = errors.New("sign: verdict undelivered (signer decided but the response did not arrive)")

// Client is the signer socket client. SocketPath is the absolute
// path to the Unix socket; Timeout is the total per-request budget
// (dial + write + read). It must exceed the signer daemon's handler
// timeout so the daemon's authoritative verdict wins the race rather
// than the client abandoning early (which would strand an approved
// signature). Defaults to sigwire.ClientSignTimeout when zero.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// CmdReq is a single command in a sign request. Server is the alias
// from the MCP registry (recorded in the audit log); Cmd is the
// literal shell command; TTLSec is the signature validity window in
// seconds (bounded by sigwire.MaxSigValidity on the daemon side); Host
// is the target's TOFU-pinned SSH host-key fingerprint ("SHA256:..."),
// sourced by the caller from the trusted registry (never an agent
// parameter), which the daemon copies into the signed payload's Host
// field so the gate can enforce the per-server binding.
type CmdReq struct {
	Server string
	Cmd    string
	TTLSec int64
	Host   string
	// Reveal requests a SECRET-REVEAL: the daemon signs reveal=true into the
	// payload so the gate runs this one command's output WITHOUT the redactor.
	// Reason is the mandatory human justification shown in the approval UX
	// (the caller enforces non-empty Reason for reveal=true). Both are zero for
	// ordinary writes. Reveal is single-command only — there is no batch reveal.
	Reveal bool
	Reason string
}

// Signed is one signed result returned from signer on approval.
// Cmd is the original command (echoed back so the caller can match
// signatures to requests in order); Sig is the wire-encoded
// "SSHGATE_SIG:<sigB64>:<payloadB64>" string ready to prefix on the
// remote command line.
type Signed struct {
	Cmd string
	Sig string
}

// signRequestCmd is the JSON shape of a single command on the wire.
// It must mirror signer's signRequestCmd exactly.
type signRequestCmd struct {
	Server string `json:"server"`
	Cmd    string `json:"cmd"`
	TTLSec int64  `json:"ttl_seconds"`
	Host   string `json:"host,omitempty"`
	Reveal bool   `json:"reveal,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type signRequest struct {
	Kind      string           `json:"kind"`
	RequestID string           `json:"request_id"`
	Commands  []signRequestCmd `json:"commands"`
	// ProtoVersion stamps the socket-RPC shape version. It MUST mirror the
	// daemon's signRequest field exactly and is SET to sigwire.ProtoVersion
	// on every request. The daemon checks it in its lenient peek before any
	// strict decode; omitempty keeps a legacy (unset) request byte-identical.
	ProtoVersion int `json:"proto_version,omitempty"`
}

type signResponseSig struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

type signResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	// AuthMode (F4) mirrors the daemon's signResponse field: "human" for a
	// real-time Telegram tap, "grant:<id>" for a standing-grant auto-sign,
	// empty for any non-approved outcome. It rides the gate-INVISIBLE socket
	// RPC, never the signed payload. Decoded with plain json.Unmarshal (no
	// DisallowUnknownFields), so an OLD signer that omits the field unmarshals
	// to "" and is handled as "unknown" rather than erroring (forward-compat).
	AuthMode     string            `json:"auth_mode,omitempty"`
	Signatures   []signResponseSig `json:"signatures,omitempty"`
	Error        string            `json:"error,omitempty"`
	ProtoVersion int               `json:"proto_version,omitempty"`
}

// SignResult is the outcome of a successful Sign: the signed wire strings
// plus the F4 AuthMode marker reporting HOW the request was authorised
// ("human" | "grant:<id>" | "" for an old signer that omits it). Bundling
// them in one struct keeps the Sign signature stable as the socket RPC
// gains gate-invisible metadata.
type SignResult struct {
	Signed   []Signed
	AuthMode string
}

// Sign sends a sign request for cmds and returns a SignResult (the signed
// wire strings + the F4 auth-mode marker) on approval, or one of {ErrDenied,
// ErrTimeout, ErrUnreachable, ErrSignerPermission, fmt.Errorf("...")} on any
// other outcome (with a zero SignResult).
//
// The request body is constructed locally (so the daemon never has
// to trust the wire-level shape from the MCP).
func (c *Client) Sign(ctx context.Context, requestID string, cmds []CmdReq) (SignResult, error) {
	if c.SocketPath == "" {
		return SignResult{}, fmt.Errorf("sign: SocketPath is empty")
	}
	if requestID == "" {
		return SignResult{}, fmt.Errorf("sign: requestID is empty")
	}
	if len(cmds) == 0 {
		return SignResult{}, fmt.Errorf("sign: no commands")
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = sigwire.ClientSignTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialWithCtx(dialCtx, c.SocketPath)
	if err != nil {
		return SignResult{}, classifyDialError(err)
	}
	defer conn.Close()

	// Apply the overall deadline to the connection.
	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	// Propagate ctx cancellation: close the conn so any blocked
	// Read/Write returns immediately. The watcher exits when the
	// connection closes (the deferred Close above).
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	body := signRequest{
		Kind:         "sign",
		RequestID:    requestID,
		Commands:     make([]signRequestCmd, len(cmds)),
		ProtoVersion: sigwire.ProtoVersion,
	}
	for i, cmd := range cmds {
		body.Commands[i] = signRequestCmd{Server: cmd.Server, Cmd: cmd.Cmd, TTLSec: cmd.TTLSec, Host: cmd.Host, Reveal: cmd.Reveal, Reason: cmd.Reason}
	}
	wire, err := json.Marshal(body)
	if err != nil {
		return SignResult{}, fmt.Errorf("sign: marshal: %w", err)
	}
	wire = append(wire, '\n')
	if _, err := conn.Write(wire); err != nil {
		return SignResult{}, fmt.Errorf("sign: write: %w", err)
	}

	line, err := lineframe.Read(conn, policywire.MaxSocketFrameBytes)
	if err != nil {
		// If ctx is the root cause, surface it verbatim so callers
		// can distinguish cancellation from a malformed reply.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SignResult{}, fmt.Errorf("sign: %w", ctxErr)
		}
		// The request was fully written above; a CLEAN EOF (no bytes) or a
		// net/deadline timeout here means the daemon may have decided a
		// verdict (incl. a human DENY) that never reached us — the outcome
		// is INDETERMINATE. Return ErrVerdictUnknown so the run/run_batch
		// layer fails SAFE and does NOT auto-retry. A non-empty EOF frame is
		// returned without a framing error and the typed JSON decoder below
		// decides whether it is complete or malformed.
		if isVerdictLost(err, len(line)) {
			return SignResult{}, fmt.Errorf("%w: %v", ErrVerdictUnknown, err)
		}
		return SignResult{}, fmt.Errorf("sign: read response: %w", err)
	}

	var resp signResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return SignResult{}, fmt.Errorf("sign: malformed response: %w", err)
	}
	// A daemon error response can legitimately carry an EMPTY request_id —
	// it is set before the daemon has parsed/echoed our id (a malformed
	// request, or a backend-send failure reported with no id). Surface the
	// real reason from resp.Error rather than the opaque correlation
	// mismatch below, which would mask why the request failed. We only
	// treat a NON-EMPTY mismatched id as a true correlation error (the
	// concurrency/correlation guarantee is unchanged for that case).
	if resp.RequestID == "" && resp.Status == "error" {
		if resp.Error == "" {
			return SignResult{}, fmt.Errorf("sign: daemon reported error (no detail)")
		}
		return SignResult{}, fmt.Errorf("sign: daemon error: %s", resp.Error)
	}
	if resp.RequestID != requestID {
		return SignResult{}, fmt.Errorf("sign: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "approved":
		out := make([]Signed, len(resp.Signatures))
		for i, s := range resp.Signatures {
			out[i] = Signed{Cmd: s.Cmd, Sig: s.Sig}
		}
		// resp.AuthMode is "" for an old signer that omits the field — that is
		// "unknown", handled gracefully, NOT an error.
		return SignResult{Signed: out, AuthMode: resp.AuthMode}, nil
	case "denied":
		return SignResult{}, ErrDenied
	case "timeout":
		return SignResult{}, ErrTimeout
	case "error":
		if resp.Error == "" {
			return SignResult{}, fmt.Errorf("sign: daemon reported error (no detail)")
		}
		return SignResult{}, fmt.Errorf("sign: daemon error: %s", resp.Error)
	default:
		return SignResult{}, fmt.Errorf("sign: unknown status %q", resp.Status)
	}
}

// dialWithCtx wraps net.Dialer.DialContext with a "unix" network so
// ctx cancellation aborts the dial.
//
// It is a package-level var (not a plain func) solely so in-package
// tests can substitute a dialer that returns a controlled net.Conn —
// e.g. one whose Write fails — to exercise transport error paths that
// are not deterministically reproducible against a real socket. Tests
// restore the original via defer. Production callers always use the
// default below; no public API or env var is involved, so production
// behaviour and attack surface are unchanged.
var dialWithCtx = func(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// classifyDialError maps a dial failure to a sentinel:
//   - ErrUnreachable when the socket file is missing or the kernel
//     returned "connection refused" (no daemon listening);
//   - ErrSignerPermission when the dial is refused with a permission
//     error (EACCES / EPERM) — the socket is present but the caller's
//     session is not yet in the sshgatesigner group.
//
// Any other error (e.g. ctx cancellation) is wrapped without a
// sentinel.
func classifyDialError(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: socket missing: %v", ErrUnreachable, err)
	}
	// ENOENT on the socket path comes back as *net.OpError wrapping
	// *os.PathError on some kernels — check the message as a fallback.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && errors.Is(pathErr.Err, fs.ErrNotExist) {
		return fmt.Errorf("%w: socket missing: %v", ErrUnreachable, err)
	}
	// Permission denied on the 0660 socket: the daemon is alive but the
	// caller's session has not picked up the sshgatesigner group yet.
	// This must be detected BEFORE the *net.OpError catch-all below,
	// because an EACCES dial also surfaces as an *net.OpError — without
	// this branch it would be mis-reported as "unreachable" (a dead
	// daemon). We match both the portable fs.ErrPermission and an
	// unwrapped syscall.Errno of EACCES/EPERM.
	if errors.Is(err, fs.ErrPermission) || isPermErrno(err) {
		return fmt.Errorf("%w: %v", ErrSignerPermission, err)
	}
	// ECONNREFUSED indicates the socket file exists but no process
	// is listening — classify as unreachable.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("%w: dial: %v", ErrUnreachable, err)
	}
	return fmt.Errorf("sign: dial: %w", err)
}

// isPermErrno unwraps err to a syscall.Errno and reports whether it is
// EACCES or EPERM. fs.ErrPermission does not always match an EACCES
// that arrives wrapped in *net.OpError → *os.SyscallError, so we check
// the raw errno as a belt-and-braces fallback.
func isPermErrno(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EACCES || errno == syscall.EPERM
	}
	return false
}

// isVerdictLost reports whether a read error that occurred AFTER the request
// was fully written means the verdict is indeterminate (signer decided but
// the response did not arrive). nRead is how many bytes the bounded framer returned
// before the error. True for a CLEAN EOF (nRead==0 — the peer closed with no
// reply at all), a net timeout (the client's own read deadline fired while
// the daemon was wedged), or os.ErrDeadlineExceeded. A PARTIAL line
// (nRead>0 with EOF) is a genuine malformed/truncated reply, not a lost
// verdict — bytes DID come back — so the framer sends them to typed decoding.
// Likewise any other read error (e.g. connection reset) is not verdict-lost.
func isVerdictLost(err error, nRead int) bool {
	if errors.Is(err, io.EOF) {
		return nRead == 0
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}
