package signer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestDaemon_ProtoVersionMismatch covers the F6 build-skew guard: a request
// stamped with a proto_version that does not match the daemon's
// sigwire.ProtoVersion must be rejected in the LENIENT kindPeek pre-pass
// (before any strict per-kind decode), with a clear "rebuild both" error
// AND the request_id echoed from the peek (not "") so the failure is
// correlatable.
func TestDaemon_ProtoVersionMismatch(t *testing.T) {
	t.Parallel()
	// A backend that is never armed: a correct daemon rejects on version
	// BEFORE ever reaching the backend. If the version check regressed, the
	// un-armed mock would hang until the package timeout — a loud failure.
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()

	req := `{"kind":"sign","proto_version":999,"request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest returned hard error; want a written error response: %v", err)
	}

	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error", resp.Status)
	}
	if resp.RequestID != "r1" {
		t.Errorf("RequestID = %q; want it echoed as r1 (a correlatable id, not empty)", resp.RequestID)
	}
	for _, want := range []string{"proto_version mismatch", "v999", "v1", "rebuild"} {
		if !strings.Contains(resp.Error, want) {
			t.Errorf("Error = %q; want it to contain %q", resp.Error, want)
		}
	}

	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "error" {
		t.Errorf("audit = %+v; want one error row", got)
	}
}

// TestDaemon_ProtoVersionMatchSigns confirms a request carrying the CURRENT
// proto_version is accepted and signed normally — the field is a known,
// strictly-decoded field on the sign path, not an unknown-field rejection.
func TestDaemon_ProtoVersionMatchSigns(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()
	mock.Approve("r_pv", "operator")

	req := `{"kind":"sign","proto_version":` + itoa(sigwire.ProtoVersion) + `,"request_id":"r_pv","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "approved" {
		t.Errorf("Status = %q; want approved for a matching proto_version", resp.Status)
	}
}

// TestDaemon_LegacyNoProtoVersionSigns is the backward-compatibility pin: a
// request with NO proto_version field (absent ⇒ 0 ⇒ accept-as-legacy) must
// sign exactly as before the version stamp existed.
func TestDaemon_LegacyNoProtoVersionSigns(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()
	mock.Approve("r_legacy", "operator")

	// Note: this is byte-for-byte the legacy wire shape (no proto_version).
	req := `{"kind":"sign","request_id":"r_legacy","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "approved" {
		t.Errorf("Status = %q; want approved for a legacy (no proto_version) request", resp.Status)
	}
}

// TestDaemon_GrantProtoVersionMismatch confirms the version guard fires for
// the request_grant kind too (the peek runs before the kind switch) — and
// echoes the request_id.
func TestDaemon_GrantProtoVersionMismatch(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	req := `{"kind":"request_grant","proto_version":999,"request_id":"g_pv","alias":"prod","scope":"all","duration_seconds":3600}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error", resp.Status)
	}
	if resp.RequestID != "g_pv" {
		t.Errorf("RequestID = %q; want it echoed as g_pv", resp.RequestID)
	}
	if !strings.Contains(resp.Error, "proto_version mismatch") {
		t.Errorf("Error = %q; want a proto_version mismatch reason", resp.Error)
	}
}

// TestDaemon_MalformedPeekEchoesRequestID covers the F6 sharpening of the
// malformed-peek path: when the peek decode itself fails but a request_id
// is still recoverable from the (lenient) peek, the daemon echoes it
// instead of "". Here the line is valid JSON for the lenient peek (so the
// id IS recoverable) but is NOT valid for the strict sign decoder.
//
// We use a NUMERIC kind so the peek's json.Unmarshal into kindPeek fails
// (Kind is a string) yet request_id is a plain string the lenient decoder
// would have parsed — proving the daemon now pulls the id out of the peek
// struct even on the malformed path.
func TestDaemon_MalformedPeekEchoesRequestID(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	// kind is a number ⇒ kindPeek.Kind (string) fails to unmarshal ⇒
	// malformed-peek path. request_id is a string ⇒ peek.RequestID is set.
	req := `{"kind":123,"request_id":"r_mal","commands":[]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error", resp.Status)
	}
	if !strings.Contains(resp.Error, "malformed") {
		t.Errorf("Error = %q; want a malformed-request reason", resp.Error)
	}
	if resp.RequestID != "r_mal" {
		t.Errorf("RequestID = %q; want it echoed as r_mal (recovered from the lenient peek, not empty)", resp.RequestID)
	}
}

// itoa is a tiny local int→string so the test does not pull in strconv just
// for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
