package sign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// registerXferKeyRequest is the JSON shape of a "register_xfer_key" request on
// the wire. It MUST mirror signer's registerXferKeyRequest exactly. It carries
// the host fingerprint + display label + the two canonical PUBLIC key lines;
// there is no private material and no MCP tool — the only caller is the
// human-only sshgate CLI over the signer socket (registration is always-prompt,
// human-only; see daemon.handleRegisterXferKey).
type registerXferKeyRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	HostFP    string `json:"host_fp"`
	Label     string `json:"label"`
	BoxPub    string `json:"box_pub"`
	IDPub     string `json:"id_pub"`
	// ProtoVersion mirrors signer's field and is SET to sigwire.ProtoVersion on
	// every request; omitempty preserves the legacy wire shape. See client.go
	// signRequest for the full rationale.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// registerXferKeyResponse mirrors signer's registerXferKeyResponse.
type registerXferKeyResponse struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ProtoVersion int    `json:"proto_version,omitempty"`
}

// RegisterXferKeyReq is the CLI-facing input to RegisterXferKey. HostFP is the
// fingerprint the transfer legs bind to (sourced by the caller from provisioning
// state — ProvisionOutput.Fingerprint or servers.json Entry.Fingerprint, NEVER
// re-derived or operator-supplied); BoxPub/IDPub are the canonical PublicText
// lines the gate produced (validated by the caller before dialing).
type RegisterXferKeyReq struct{ HostFP, Label, BoxPub, IDPub string }

// RegisterXferKey asks the signer to REGISTER a server's box→box transfer keys
// into its registry. It always prompts a human (a distinct "REGISTER TRANSFER
// KEYS" Telegram tap); the daemon writes the registry ONLY on approval, and a
// re-register overwrites the existing entry as an authorised rotation. On
// approval it returns nil; on any other outcome it returns one of {ErrDenied,
// ErrTimeout, ErrUnreachable, ErrSignerPermission, ErrVerdictUnknown,
// fmt.Errorf("...")}. The caller (the sshgate CLI) MUST interpret a non-approval
// honestly — never silently orphan a freshly-added server, print the retry
// command instead.
func (c *Client) RegisterXferKey(ctx context.Context, requestID string, req RegisterXferKeyReq) error {
	if c.SocketPath == "" {
		return fmt.Errorf("register_xfer_key: SocketPath is empty")
	}
	if requestID == "" {
		return fmt.Errorf("register_xfer_key: requestID is empty")
	}

	body := registerXferKeyRequest{
		Kind:      "register_xfer_key",
		RequestID: requestID,
		HostFP:    req.HostFP,
		Label:     req.Label,
		BoxPub:    req.BoxPub,
		IDPub:     req.IDPub,
		// Stamp the proto version like transfer_client.go so a version-stamped
		// daemon does not reject us in its skew pre-pass.
		ProtoVersion: sigwire.ProtoVersion,
	}
	line, err := c.roundtrip(ctx, requestID, body, "register_xfer_key")
	if err != nil {
		return err
	}

	var resp registerXferKeyResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("register_xfer_key: malformed response: %w", err)
	}
	// An empty-request_id error response carries the real reason; surface it
	// instead of the opaque correlation mismatch. Mirrors Transfer/RequestGrant.
	if resp.RequestID == "" && resp.Status == "error" {
		if resp.Error == "" {
			return fmt.Errorf("register_xfer_key: daemon reported error (no detail)")
		}
		return fmt.Errorf("register_xfer_key: daemon error: %s", resp.Error)
	}
	if resp.RequestID != requestID {
		return fmt.Errorf("register_xfer_key: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "approved":
		return nil
	case "denied":
		return ErrDenied
	case "timeout":
		return ErrTimeout
	case "error":
		if resp.Error == "" {
			return fmt.Errorf("register_xfer_key: daemon reported error (no detail)")
		}
		return fmt.Errorf("register_xfer_key: daemon error: %s", resp.Error)
	default:
		return fmt.Errorf("register_xfer_key: unknown status %q", resp.Status)
	}
}
