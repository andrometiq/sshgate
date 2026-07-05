package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// This internal-package test file covers the two P4 daemon fold-ins:
//   (a) the authoritative label-length cap in handleRegisterXferKey (rejected
//       BEFORE the human prompt), and
//   (b) the "approved-error" audit status for a post-approval failure of register
//       (registry write) and transfer (leg signing).
// It lives in package signer so it can reach the randRead seam + readAuditEvents.

// registerSpy wraps a Backend and records whether RequestRegisterKey was called,
// returning a fast timeout so a test never hangs if the pre-prompt cap regresses.
type registerSpy struct {
	backend.Backend
	registerCalls int
}

func (s *registerSpy) RequestRegisterKey(_ context.Context, _ backend.RegisterApprovalRequest) (<-chan backend.Result, error) {
	s.registerCalls++
	ch := make(chan backend.Result, 1)
	ch <- backend.Result{Status: backend.StatusTimeout}
	return ch, nil
}

// freshXferPubText returns a valid (box, id) canonical PublicText pair.
func freshXferPubText(t *testing.T) (boxText, idText string) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatal(err)
	}
	return bk.PublicText(), ik.PublicText()
}

func driveRegisterInternal(t *testing.T, d *Daemon, reqID, fp, label, box, id string) (status, errMsg string) {
	t.Helper()
	body := map[string]any{
		"kind": "register_xfer_key", "request_id": reqID, "host_fp": fp,
		"label": label, "box_pub": box, "id_pub": id,
	}
	raw, _ := json.Marshal(body)
	conn := &rwBuf{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(register): %v", err)
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Status, resp.Error
}

// TestRegisterLabelCap_OverLongRejectedBeforePrompt: a 65-char label is rejected
// with "invalid label" BEFORE the backend prompt is reached.
func TestRegisterLabelCap_OverLongRejectedBeforePrompt(t *testing.T) {
	spy := &registerSpy{Backend: backend.NewMockBackend()}
	reg, err := LoadXferRegistry(filepath.Join(t.TempDir(), "reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := &Daemon{Key: priv, Backend: spy, Audit: audit, XferRegistry: reg, NowFunc: func() time.Time { return time.Unix(1000, 0) }}

	box, id := freshXferPubText(t)
	fp := "SHA256:cap-host-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	status, errMsg := driveRegisterInternal(t, d, "cap_over", fp, strings.Repeat("x", 65), box, id)
	if status != "error" || !strings.Contains(errMsg, "invalid label") {
		t.Fatalf("over-long label: status=%q err=%q; want error/invalid label", status, errMsg)
	}
	if spy.registerCalls != 0 {
		t.Error("backend prompt was reached for an over-long label; the cap must fire BEFORE the prompt")
	}
	if _, _, _, ok := reg.Lookup(fp); ok {
		t.Error("over-long label landed in the registry")
	}
}

// TestRegisterLabelCap_AtLimitPassesToPrompt: a 64-char label passes the cap and
// reaches the prompt (the spy records the call and returns timeout).
func TestRegisterLabelCap_AtLimitPassesToPrompt(t *testing.T) {
	spy := &registerSpy{Backend: backend.NewMockBackend()}
	reg, err := LoadXferRegistry(filepath.Join(t.TempDir(), "reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := &Daemon{Key: priv, Backend: spy, Audit: audit, XferRegistry: reg, NowFunc: func() time.Time { return time.Unix(1000, 0) }}

	box, id := freshXferPubText(t)
	fp := "SHA256:cap-host-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	status, _ := driveRegisterInternal(t, d, "cap_at", fp, strings.Repeat("x", 64), box, id)
	if spy.registerCalls != 1 {
		t.Errorf("64-char label: backend called %d times; want 1 (it must reach the prompt)", spy.registerCalls)
	}
	if status == "error" {
		t.Errorf("64-char label was rejected as error; the cap must allow exactly 64")
	}
}

// auditRowFor returns the (status, authMode) of the audit row for reqID.
func auditRowFor(t *testing.T, path, reqID string) (status, authMode string) {
	t.Helper()
	for _, ev := range readAuditEvents(t, path) {
		if ev.RequestID == reqID {
			return ev.Status, ev.AuthMode
		}
	}
	t.Fatalf("no audit row for %q", reqID)
	return "", ""
}

// TestRegisterApprovedError: an APPROVED registration whose registry write fails
// audits "approved-error" (not the bare "error") with auth_mode still human.
func TestRegisterApprovedError(t *testing.T) {
	regDir := t.TempDir()
	reg, err := LoadXferRegistry(filepath.Join(regDir, "reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	mock := backend.NewMockBackend()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := &Daemon{Key: priv, Backend: mock, Audit: audit, XferRegistry: reg, NowFunc: func() time.Time { return time.Unix(1000, 0) }}

	// Make the registry dir unwritable so the post-approval persist fails.
	if err := os.Chmod(regDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(regDir, 0o700) })

	box, id := freshXferPubText(t)
	fp := "SHA256:ae-host-cccccccccccccccccccccccccccccccc"
	mock.Approve("reg_ae", "operator")
	status, _ := driveRegisterInternal(t, d, "reg_ae", fp, "label", box, id)
	if status != "error" {
		t.Fatalf("post-approval registry failure: status=%q; want error", status)
	}
	rowStatus, authMode := auditRowFor(t, auditPath, "reg_ae")
	if rowStatus != "approved-error" {
		t.Errorf("audit status = %q; want approved-error", rowStatus)
	}
	if authMode != "human" {
		t.Errorf("audit auth_mode = %q; want human (the human approved)", authMode)
	}
}

// TestTransferApprovedError: an APPROVED transfer whose leg signing fails (the
// randRead seam breaks the nonce) audits "approved-error" with auth_mode human.
func TestTransferApprovedError(t *testing.T) {
	// Not t.Parallel(): mutates the package-level randRead var.
	orig := randRead
	defer func() { randRead = orig }()

	reg, err := LoadXferRegistry(filepath.Join(t.TempDir(), "reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	mock := backend.NewMockBackend()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := &Daemon{Key: priv, Backend: mock, Audit: audit, XferRegistry: reg, NowFunc: func() time.Time { return time.Unix(1000, 0) }}

	srcFP := "SHA256:te-src-dddddddddddddddddddddddddddddddd"
	destFP := "SHA256:te-dst-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	box1, id1 := freshXferPubText(t)
	box2, id2 := freshXferPubText(t)
	if err := reg.Register(srcFP, "src", box1, id1); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(destFP, "dst", box2, id2); err != nil {
		t.Fatal(err)
	}

	mock.Approve("xfer_ae", "operator")
	// Break the nonce RNG so signTransferLegs fails AFTER approval — but let the
	// FIRST randRead succeed so newXferID (called BEFORE the prompt) still mints an
	// id; only the leg-signing nonce (2nd+ call) fails, exercising the
	// post-approval path.
	var calls int
	randRead = func(b []byte) (int, error) {
		calls++
		if calls == 1 {
			return orig(b)
		}
		return 0, errors.New("rng exhausted")
	}

	body := map[string]any{
		"kind": "transfer", "request_id": "xfer_ae",
		"src_alias": "s", "src_fp": srcFP, "src_path": "/a",
		"dest_alias": "d", "dest_fp": destFP, "dest_path": "/b",
		"mode": "0600", "ttl_seconds": 60,
	}
	raw, _ := json.Marshal(body)
	conn := &rwBuf{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(transfer): %v", err)
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp)
	if resp.Status != "error" {
		t.Fatalf("post-approval sign failure: status=%q; want error", resp.Status)
	}
	rowStatus, authMode := auditRowFor(t, auditPath, "xfer_ae")
	if rowStatus != "approved-error" {
		t.Errorf("audit status = %q; want approved-error", rowStatus)
	}
	if authMode != "human" {
		t.Errorf("audit auth_mode = %q; want human", authMode)
	}
}
