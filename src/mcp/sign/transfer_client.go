package sign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// transferRequest is the JSON shape of a "transfer" request on the wire. It
// must mirror signer's transferRequest exactly. It carries ONLY paths +
// fingerprints + display aliases — never the pubkeys and never an xferID; the
// signer sources both from its own registry, which is the entire anti-MITM
// guarantee.
type transferRequest struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	SrcAlias  string `json:"src_alias"`
	SrcFP     string `json:"src_fp"`
	SrcPath   string `json:"src_path"`
	DestAlias string `json:"dest_alias"`
	DestFP    string `json:"dest_fp"`
	DestPath  string `json:"dest_path"`
	Mode      string `json:"mode"`
	TTLSec    int64  `json:"ttl_seconds"`
	// ProtoVersion mirrors signer's transferRequest field and is SET to
	// sigwire.ProtoVersion on every request; omitempty preserves the legacy
	// wire shape. See client.go signRequest for the full rationale.
	ProtoVersion int `json:"proto_version,omitempty"`
}

// transferLeg mirrors signer's transferLeg: one signed leg {cmd, sig}.
type transferLeg struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// transferResponse mirrors signer's transferResponse.
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

// TransferReq is the tools-layer-facing input to Transfer. The caller (the P3
// transfer tool) sources SrcFP/DestFP from the MCP's TRUSTED registry (the same
// registry run_batch/update_gate read), NEVER an agent parameter. The aliases
// are display-only. The pubkeys and the xferID are deliberately ABSENT — the
// signer supplies them.
type TransferReq struct {
	SrcAlias  string
	SrcFP     string
	SrcPath   string
	DestAlias string
	DestFP    string
	DestPath  string
	Mode      string
	TTLSec    int64
}

// TransferResult is the outcome of a successful Transfer: the signer-minted
// transfer id, the two host-bound signed legs (SEND for the source gate, RECV
// for the destination gate), and the F4 AuthMode marker (always "human" on a
// transfer approval — a standing grant can never cover a transfer).
type TransferResult struct {
	XferID   string
	Send     Signed
	Recv     Signed
	AuthMode string
}

// Transfer asks the signer to approve a box→box SECRET TRANSFER and, on a single
// human Telegram approval of a distinct "SECRET TRANSFER" banner, returns the
// two signed legs. The MCP sends paths + fingerprints + aliases only; the signer
// sources the recipient box key and sender identity key from ITS OWN registry
// and mints the xferID, so a rogue agent can neither substitute a recipient key
// nor correlate a stale leg. On any non-approval outcome it returns one of
// {ErrDenied, ErrTimeout, ErrUnreachable, ErrSignerPermission, ErrVerdictUnknown,
// fmt.Errorf("...")}.
func (c *Client) Transfer(ctx context.Context, requestID string, req TransferReq) (TransferResult, error) {
	if c.SocketPath == "" {
		return TransferResult{}, fmt.Errorf("transfer: SocketPath is empty")
	}
	if requestID == "" {
		return TransferResult{}, fmt.Errorf("transfer: requestID is empty")
	}

	body := transferRequest{
		Kind:      "transfer",
		RequestID: requestID,
		SrcAlias:  req.SrcAlias,
		SrcFP:     req.SrcFP,
		SrcPath:   req.SrcPath,
		DestAlias: req.DestAlias,
		DestFP:    req.DestFP,
		DestPath:  req.DestPath,
		Mode:      req.Mode,
		TTLSec:    req.TTLSec,
		// Stamp the proto version exactly like grant_client.go:101 so a
		// version-stamped daemon does not reject us in its skew pre-pass.
		ProtoVersion: sigwire.ProtoVersion,
	}
	line, err := c.roundtrip(ctx, requestID, body, "transfer")
	if err != nil {
		return TransferResult{}, err
	}

	var resp transferResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return TransferResult{}, fmt.Errorf("transfer: malformed response: %w", err)
	}
	// An empty-request_id error response carries the real reason; surface it
	// instead of the opaque correlation mismatch. Mirrors Sign/RequestGrant.
	if resp.RequestID == "" && resp.Status == "error" {
		if resp.Error == "" {
			return TransferResult{}, fmt.Errorf("transfer: daemon reported error (no detail)")
		}
		return TransferResult{}, fmt.Errorf("transfer: daemon error: %s", resp.Error)
	}
	if resp.RequestID != requestID {
		return TransferResult{}, fmt.Errorf("transfer: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "approved":
		if resp.Send == nil || resp.Recv == nil {
			return TransferResult{}, fmt.Errorf("transfer: approved but a leg is missing")
		}
		if resp.XferID == "" {
			return TransferResult{}, fmt.Errorf("transfer: approved but empty xfer_id")
		}
		return TransferResult{
			XferID:   resp.XferID,
			Send:     Signed{Cmd: resp.Send.Cmd, Sig: resp.Send.Sig},
			Recv:     Signed{Cmd: resp.Recv.Cmd, Sig: resp.Recv.Sig},
			AuthMode: resp.AuthMode,
		}, nil
	case "denied":
		return TransferResult{}, ErrDenied
	case "timeout":
		return TransferResult{}, ErrTimeout
	case "error":
		if resp.Error == "" {
			return TransferResult{}, fmt.Errorf("transfer: daemon reported error (no detail)")
		}
		return TransferResult{}, fmt.Errorf("transfer: daemon error: %s", resp.Error)
	default:
		return TransferResult{}, fmt.Errorf("transfer: unknown status %q", resp.Status)
	}
}
