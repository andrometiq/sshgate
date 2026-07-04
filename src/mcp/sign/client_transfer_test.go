package sign_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// TestTransfer_Approved: the client marshals the "transfer" kind with NO
// pubkeys and NO xferID (the anti-MITM guarantee — the signer supplies both),
// stamps the proto version, and on approval parses both legs + the xferID +
// auth_mode.
func TestTransfer_Approved(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"tx1","status":"approved","auth_mode":"human","xfer_id":"XID123","send":{"cmd":"SSHGATE_XFER_SEND a b c d","sig":"SSHGATE_SIG:s1:p1"},"recv":{"cmd":"SSHGATE_XFER_RECV a b c d e f","sig":"SSHGATE_SIG:s2:p2"}}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	res, err := c.Transfer(context.Background(), "tx1", sign.TransferReq{
		SrcAlias: "src", SrcFP: "SHA256:src", SrcPath: "/a",
		DestAlias: "dst", DestFP: "SHA256:dst", DestPath: "/b",
		Mode: "0600", TTLSec: 60,
	})
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if res.XferID != "XID123" {
		t.Errorf("XferID = %q; want XID123", res.XferID)
	}
	if res.AuthMode != "human" {
		t.Errorf("AuthMode = %q; want human", res.AuthMode)
	}
	if res.Send.Sig != "SSHGATE_SIG:s1:p1" || res.Recv.Sig != "SSHGATE_SIG:s2:p2" {
		t.Errorf("legs wrong: %+v", res)
	}

	// The request the client actually sent must carry the "transfer" kind,
	// the fps/paths/aliases — and NO pubkeys, NO xfer_id.
	select {
	case req := <-gotReq:
		if req["kind"] != "transfer" {
			t.Errorf("kind = %v; want transfer", req["kind"])
		}
		if req["request_id"] != "tx1" {
			t.Errorf("request_id = %v", req["request_id"])
		}
		if req["src_fp"] != "SHA256:src" || req["dest_fp"] != "SHA256:dst" {
			t.Errorf("fps not forwarded: %v", req)
		}
		for _, banned := range []string{"box_pub", "id_pub", "xfer_id", "send", "recv"} {
			if _, present := req[banned]; present {
				t.Errorf("request must NOT carry %q (signer sources it): %v", banned, req)
			}
		}
		if _, ok := req["proto_version"]; !ok {
			t.Error("request missing proto_version")
		}
	default:
		t.Error("server received no request")
	}
}

// TestTransfer_Denied maps a denied verdict to ErrDenied.
func TestTransfer_Denied(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"tx2","status":"denied"}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Transfer(context.Background(), "tx2", sign.TransferReq{SrcFP: "a", DestFP: "b", TTLSec: 60})
	if !errors.Is(err, sign.ErrDenied) {
		t.Errorf("err = %v; want ErrDenied", err)
	}
}

// TestTransfer_DaemonError surfaces a daemon error string (with empty
// request_id, the empty-id carve-out path).
func TestTransfer_DaemonError(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":"dest server not registered for transfer"}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Transfer(context.Background(), "tx3", sign.TransferReq{SrcFP: "a", DestFP: "b", TTLSec: 60})
	if err == nil || !contains(err.Error(), "not registered") {
		t.Errorf("err = %v; want a daemon-error surfacing 'not registered'", err)
	}
}

// TestTransfer_ApprovedMissingLeg: an "approved" response missing a leg is an
// error (never a half transfer).
func TestTransfer_ApprovedMissingLeg(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"tx4","status":"approved","xfer_id":"X","send":{"cmd":"c","sig":"s"}}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Transfer(context.Background(), "tx4", sign.TransferReq{SrcFP: "a", DestFP: "b", TTLSec: 60})
	if err == nil {
		t.Error("Transfer accepted an approved response missing a leg")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
