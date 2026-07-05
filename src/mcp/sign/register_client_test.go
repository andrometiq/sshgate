package sign_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// TestRegisterXferKey_Approved: the client marshals the "register_xfer_key" kind
// with the exact fp/label/box_pub/id_pub, stamps the proto version, and returns
// nil on approval.
func TestRegisterXferKey_Approved(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"reg1","status":"approved"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RegisterXferKey(context.Background(), "reg1", sign.RegisterXferKeyReq{
		HostFP: "SHA256:hostfp", Label: "prod-host",
		BoxPub: "sshgate-xfer-box-x25519 AAAA", IDPub: "sshgate-xfer-id-ed25519 BBBB",
	})
	if err != nil {
		t.Fatalf("RegisterXferKey: %v", err)
	}

	select {
	case req := <-gotReq:
		if req["kind"] != "register_xfer_key" {
			t.Errorf("kind = %v; want register_xfer_key", req["kind"])
		}
		if req["request_id"] != "reg1" {
			t.Errorf("request_id = %v", req["request_id"])
		}
		if req["host_fp"] != "SHA256:hostfp" {
			t.Errorf("host_fp = %v", req["host_fp"])
		}
		if req["label"] != "prod-host" {
			t.Errorf("label = %v", req["label"])
		}
		if req["box_pub"] != "sshgate-xfer-box-x25519 AAAA" || req["id_pub"] != "sshgate-xfer-id-ed25519 BBBB" {
			t.Errorf("box/id pub not forwarded verbatim: %v", req)
		}
		if _, ok := req["proto_version"]; !ok {
			t.Error("request missing proto_version")
		}
	default:
		t.Error("server received no request")
	}
}

func TestRegisterXferKey_Denied(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"reg2","status":"denied"}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RegisterXferKey(context.Background(), "reg2", sign.RegisterXferKeyReq{HostFP: "SHA256:x"})
	if !errors.Is(err, sign.ErrDenied) {
		t.Errorf("err = %v; want ErrDenied", err)
	}
}

func TestRegisterXferKey_Timeout(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"reg3","status":"timeout"}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RegisterXferKey(context.Background(), "reg3", sign.RegisterXferKeyReq{HostFP: "SHA256:x"})
	if !errors.Is(err, sign.ErrTimeout) {
		t.Errorf("err = %v; want ErrTimeout", err)
	}
}

// TestRegisterXferKey_DaemonError surfaces the daemon's error string via the
// empty-request_id carve-out.
func TestRegisterXferKey_DaemonError(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"","status":"error","error":"invalid label"}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RegisterXferKey(context.Background(), "reg4", sign.RegisterXferKeyReq{HostFP: "SHA256:x"})
	if err == nil || !strings.Contains(err.Error(), "invalid label") {
		t.Errorf("err = %v; want the daemon 'invalid label' reason surfaced", err)
	}
}

// TestRegisterXferKey_RequestIDMismatch: a non-empty mismatched id is a
// correlation error.
func TestRegisterXferKey_RequestIDMismatch(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"WRONG","status":"approved"}`
	})
	defer stop()
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	err := c.RegisterXferKey(context.Background(), "reg5", sign.RegisterXferKeyReq{HostFP: "SHA256:x"})
	if err == nil || !strings.Contains(err.Error(), "request_id") {
		t.Errorf("err = %v; want a request_id correlation error", err)
	}
}
