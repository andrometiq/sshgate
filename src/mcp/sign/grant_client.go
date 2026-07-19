package sign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// grantRequest is the JSON shape of a request_grant request on the wire.
// It must mirror signer's grantRequest exactly.
type grantRequest struct {
	Kind        string   `json:"kind"`
	RequestID   string   `json:"request_id"`
	Alias       string   `json:"alias"`
	Scope       string   `json:"scope"`
	Commands    []string `json:"commands,omitempty"`
	DurationSec int64    `json:"duration_seconds"`
	// ProtoVersion mirrors signer's grantRequest field and is SET to
	// sigwire.ProtoVersion on every request; omitempty preserves the legacy
	// wire shape. See client.go signRequest for the full rationale.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// grantResponse mirrors signer's grantResponse.
type grantResponse struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	GrantID      string `json:"grant_id,omitempty"`
	ExpiryUnix   int64  `json:"expiry_unix,omitempty"`
	Error        string `json:"error,omitempty"`
	ProtoVersion int    `json:"proto_version,omitempty"`
}

// revokeGrantRequest is the JSON shape of a revoke_grant request.
type revokeGrantRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	Alias     string `json:"alias"`
	// ProtoVersion mirrors signer's revokeGrantRequest field; SET on every
	// request, omitempty preserves the legacy wire shape.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// revokeGrantResponse mirrors signer's revokeGrantResponse.
type revokeGrantResponse struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ProtoVersion int    `json:"proto_version,omitempty"`
}

// listGrantsRequest is the JSON shape of a list_grants request. It must
// mirror signer's listGrantsRequest exactly. Alias is the optional filter
// (omitempty: empty = all live grants).
type listGrantsRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	Alias     string `json:"alias,omitempty"`
	// ProtoVersion mirrors signer's listGrantsRequest field; SET on every
	// request, omitempty preserves the legacy wire shape.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// GrantInfo is one live standing grant reported by ListGrants. It is the
// tools-layer-facing type (exported) carrying the daemon's authoritative
// grant state: the agent's own scope/commands echoed back plus the
// daemon-minted grant_id and the absolute expiry. No key material.
type GrantInfo struct {
	Alias      string   `json:"alias"`
	Scope      string   `json:"scope"`
	Commands   []string `json:"commands,omitempty"`
	GrantID    string   `json:"grant_id"`
	ExpiryUnix int64    `json:"expiry_unix"`
}

// listGrantsResponse mirrors signer's listGrantsResponse.
type listGrantsResponse struct {
	RequestID    string      `json:"request_id"`
	Status       string      `json:"status"`
	Grants       []GrantInfo `json:"grants,omitempty"`
	Error        string      `json:"error,omitempty"`
	ProtoVersion int         `json:"proto_version,omitempty"`
}

// RequestGrant asks the signer to mint a STANDING GRANT for alias: on a
// single human Telegram approval of a distinct "STANDING GRANT" message,
// the signer records {alias, scope, commands, expiry} in memory and
// thereafter auto-signs matching writes WITHOUT further taps until the
// window elapses. The agent can only REQUEST a grant; only the human
// approving the scary message creates one.
//
// scope is "all" (any command on alias) or "commands" (only the exact
// strings in commands). durationSec is the requested window; the signer
// caps it at 24h. On approval RequestGrant returns the grant id and the
// Unix expiry. On any other outcome it returns one of {ErrDenied,
// ErrTimeout, ErrUnreachable, ErrSignerPermission, fmt.Errorf("...")}.
func (c *Client) RequestGrant(ctx context.Context, requestID, alias, scope string, commands []string, durationSec int64) (grantID string, expiryUnix int64, err error) {
	if c.SocketPath == "" {
		return "", 0, fmt.Errorf("request_grant: SocketPath is empty")
	}
	if requestID == "" {
		return "", 0, fmt.Errorf("request_grant: requestID is empty")
	}

	body := grantRequest{
		Kind:         "request_grant",
		RequestID:    requestID,
		Alias:        alias,
		Scope:        scope,
		Commands:     commands,
		DurationSec:  durationSec,
		ProtoVersion: sigwire.ProtoVersion,
	}
	line, err := c.roundtrip(ctx, requestID, body, "request_grant")
	if err != nil {
		return "", 0, err
	}

	var resp grantResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return "", 0, fmt.Errorf("request_grant: malformed response: %w", err)
	}
	// A daemon error response can legitimately carry an EMPTY request_id —
	// it is set before the daemon has parsed/echoed our id (a malformed
	// request, or a missing-request_id / backend failure reported with no
	// id). Surface the real reason rather than the opaque correlation
	// mismatch below, which would mask why the request failed. A NON-EMPTY
	// mismatched id is still a true correlation error. Mirrors Sign's 2b
	// fix in client.go so the daemon-error contract is uniform across
	// Sign/RequestGrant/RevokeGrant.
	if resp.RequestID == "" && resp.Status == "error" {
		if resp.Error == "" {
			return "", 0, fmt.Errorf("request_grant: daemon reported error (no detail)")
		}
		return "", 0, fmt.Errorf("request_grant: daemon error: %s", resp.Error)
	}
	if resp.RequestID != requestID {
		return "", 0, fmt.Errorf("request_grant: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "approved":
		if resp.GrantID == "" {
			return "", 0, fmt.Errorf("request_grant: approved but empty grant_id")
		}
		return resp.GrantID, resp.ExpiryUnix, nil
	case "denied":
		return "", 0, ErrDenied
	case "timeout":
		return "", 0, ErrTimeout
	case "error":
		if resp.Error == "" {
			return "", 0, fmt.Errorf("request_grant: daemon reported error (no detail)")
		}
		return "", 0, fmt.Errorf("request_grant: daemon error: %s", resp.Error)
	default:
		return "", 0, fmt.Errorf("request_grant: unknown status %q", resp.Status)
	}
}

// RevokeGrant drops the standing grant for alias on the signer. Revoke is
// de-escalation — it only ever shrinks capability — so it needs no human
// approval and never prompts. Revoking a non-existent grant is a
// successful no-op. Returns nil on success or one of {ErrUnreachable,
// ErrSignerPermission, fmt.Errorf("...")} on a transport/daemon error.
func (c *Client) RevokeGrant(ctx context.Context, requestID, alias string) error {
	if c.SocketPath == "" {
		return fmt.Errorf("revoke_grant: SocketPath is empty")
	}
	if requestID == "" {
		return fmt.Errorf("revoke_grant: requestID is empty")
	}

	body := revokeGrantRequest{
		Kind:         "revoke_grant",
		RequestID:    requestID,
		Alias:        alias,
		ProtoVersion: sigwire.ProtoVersion,
	}
	line, err := c.roundtrip(ctx, requestID, body, "revoke_grant")
	if err != nil {
		return err
	}

	var resp revokeGrantResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("revoke_grant: malformed response: %w", err)
	}
	// See RequestGrant: an empty-request_id error response carries the real
	// reason; surface it instead of the opaque correlation mismatch. A
	// non-empty mismatched id is still a correlation error.
	if resp.RequestID == "" && resp.Status == "error" {
		if resp.Error == "" {
			return fmt.Errorf("revoke_grant: daemon reported error (no detail)")
		}
		return fmt.Errorf("revoke_grant: daemon error: %s", resp.Error)
	}
	if resp.RequestID != requestID {
		return fmt.Errorf("revoke_grant: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "approved":
		return nil
	case "error":
		if resp.Error == "" {
			return fmt.Errorf("revoke_grant: daemon reported error (no detail)")
		}
		return fmt.Errorf("revoke_grant: daemon error: %s", resp.Error)
	default:
		return fmt.Errorf("revoke_grant: unknown status %q", resp.Status)
	}
}

// ListGrants asks the signer to report its in-memory LIVE standing grants
// (optionally filtered to alias). It is READ-ONLY: no human approval, no
// backend, no capability granted — it exists so the agent can re-learn true
// grant state after a request_grant whose verdict never arrived (the
// phantom-live grant). alias == "" lists every live grant. Returns the live
// grants on success or one of {ErrUnreachable, ErrSignerPermission,
// fmt.Errorf("...")} on a transport/daemon error.
//
// An OLD daemon that predates list_grants answers "unsupported kind" (with
// the kind echoed as the request_id); ListGrants detects that and surfaces a
// clear "daemon too old" message rather than an opaque correlation mismatch.
func (c *Client) ListGrants(ctx context.Context, requestID, alias string) ([]GrantInfo, error) {
	if c.SocketPath == "" {
		return nil, fmt.Errorf("list_grants: SocketPath is empty")
	}
	if requestID == "" {
		return nil, fmt.Errorf("list_grants: requestID is empty")
	}

	body := listGrantsRequest{
		Kind:         "list_grants",
		RequestID:    requestID,
		Alias:        alias,
		ProtoVersion: sigwire.ProtoVersion,
	}
	line, err := c.roundtrip(ctx, requestID, body, "list_grants")
	if err != nil {
		return nil, err
	}

	var resp listGrantsResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("list_grants: malformed response: %w", err)
	}
	// Old-daemon forward-compat: a daemon that predates list_grants hits its
	// switch default and replies status="error" with an "unsupported kind"
	// reason (request_id echoed as the kind, so it would otherwise look like a
	// correlation mismatch). Detect that FIRST and give an actionable rebuild
	// hint. Checked before the empty-id carve-out and the correlation compare
	// so neither masks the real cause.
	if resp.Status == "error" && strings.Contains(resp.Error, "unsupported kind") {
		return nil, fmt.Errorf("list_grants: daemon too old to list grants (rebuild/restart the signer): %s", resp.Error)
	}
	// See RequestGrant: an empty-request_id error response carries the real
	// reason; surface it instead of the opaque correlation mismatch. A
	// non-empty mismatched id is still a correlation error.
	if resp.RequestID == "" && resp.Status == "error" {
		if resp.Error == "" {
			return nil, fmt.Errorf("list_grants: daemon reported error (no detail)")
		}
		return nil, fmt.Errorf("list_grants: daemon error: %s", resp.Error)
	}
	if resp.RequestID != requestID {
		return nil, fmt.Errorf("list_grants: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "ok":
		return resp.Grants, nil
	case "error":
		if resp.Error == "" {
			return nil, fmt.Errorf("list_grants: daemon reported error (no detail)")
		}
		return nil, fmt.Errorf("list_grants: daemon error: %s", resp.Error)
	default:
		return nil, fmt.Errorf("list_grants: unknown status %q", resp.Status)
	}
}

// roundtrip performs the dial → deadline → ctx-watcher → write-one-line →
// read-one-line dance shared by RequestGrant and RevokeGrant. It mirrors
// Sign's transport scaffold exactly (Sign predates this helper and is
// left untouched). label prefixes error messages. The returned line is
// the raw JSON response (with an optional framing newline — caller unmarshals).
func (c *Client) roundtrip(ctx context.Context, requestID string, body any, label string) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = sigwire.ClientSignTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialWithCtx(dialCtx, c.SocketPath)
	if err != nil {
		return nil, classifyDialError(err)
	}
	defer conn.Close()

	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	wire, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal: %w", label, err)
	}
	wire = append(wire, '\n')
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("%s: write: %w", label, err)
	}

	line, err := lineframe.Read(conn, policywire.MaxSocketFrameBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%s: %w", label, ctxErr)
		}
		// The request was fully written above; a clean EOF or net/deadline
		// timeout means the daemon may have decided a verdict (incl. a human
		// DENY of the grant) that never reached us — INDETERMINATE. Return
		// ErrVerdictUnknown so the caller fails SAFE rather than re-requesting
		// a grant a human may have denied. Mirrors Sign's read path; a
		// partial/malformed line stays the generic read-response error.
		if isVerdictLost(err, len(line)) {
			return nil, fmt.Errorf("%w: %v", ErrVerdictUnknown, err)
		}
		return nil, fmt.Errorf("%s: read response: %w", label, err)
	}
	return line, nil
}
