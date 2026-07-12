package signerkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestSignAll_NonceFailure swaps the package-level randRead seam for a
// reader that always errors, then drives an approved request through the
// daemon. The local-signing path must surface the entropy failure as a
// "sign: nonce" error response (NOT a panic, NOT a silent unsigned
// approval). This is the one branch of signAll that is otherwise
// unreachable without breaking the kernel RNG, so it needs the seam.
//
// The seam is an in-package var override, restored via defer, so neither
// production behavior nor the public API changes.
func TestSignAll_NonceFailure(t *testing.T) {
	// Not t.Parallel(): mutates the package-level randRead var.
	orig := randRead
	defer func() { randRead = orig }()
	randRead = func([]byte) (int, error) {
		return 0, errors.New("rng exhausted")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatalf("mem audit: %v", err)
	}
	defer audit.Close()

	mock := NewMockBackend()
	mock.Approve("r_nonce", "karthi")
	d := &Daemon{
		Key:     priv,
		Backend: mock,
		Audit:   audit,
		NowFunc: func() time.Time { return time.Unix(1000, 0) },
	}

	req := `{"kind":"sign","request_id":"r_nonce","commands":[{"server":"prod","cmd":"echo hi","ttl_seconds":60}]}`
	out := &bytes.Buffer{}
	conn := &rwBuf{in: bytes.NewReader([]byte(req + "\n")), out: out}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest returned hard error: %v", err)
	}

	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, out.String())
	}
	if resp.Status != "error" {
		t.Fatalf("Status = %q; want error", resp.Status)
	}
	if !bytes.Contains([]byte(resp.Error), []byte("sign: nonce")) {
		t.Errorf("Error = %q; want it to mention %q", resp.Error, "sign: nonce")
	}
}

// rwBuf is a tiny in-package read/write conn used by the seam test. It
// mirrors the external memConn but lives here so the internal test does
// not depend on the external test package.
type rwBuf struct {
	in  *bytes.Reader
	out *bytes.Buffer
}

func (r *rwBuf) Read(p []byte) (int, error)  { return r.in.Read(p) }
func (r *rwBuf) Write(p []byte) (int, error) { return r.out.Write(p) }

// TestVerbClassifiers_TransferVerbsAreAdminVerbs pins the §4a invariant: every
// SSHGATE_XFER_* verb is BOTH a transfer verb (rejected on the sign path) AND an
// admin verb (so matchGrant's short-circuit refuses to auto-sign it from a
// standing grant). isAdminVerb must therefore stay a superset of isTransferVerb.
func TestVerbClassifiers_TransferVerbsAreAdminVerbs(t *testing.T) {
	for _, cmd := range []string{
		"SSHGATE_XFER_SEND a b c d",
		"SSHGATE_XFER_RECV a b c d e f",
		"SSHGATE_XFER_FUTURE x",
	} {
		if !isTransferVerb(cmd) {
			t.Errorf("isTransferVerb(%q) = false; want true", cmd)
		}
		if !isAdminVerb(cmd) {
			t.Errorf("isAdminVerb(%q) = false; want true (a grant must never auto-sign a transfer)", cmd)
		}
	}
	// A plain command is neither.
	if isTransferVerb("systemctl restart nginx") {
		t.Error("isTransferVerb matched a plain command")
	}
	// A non-transfer admin verb (SSHGATE_UPDATE) is an admin verb but NOT a
	// transfer verb — the sign-path reject must not swallow it.
	if isTransferVerb("SSHGATE_UPDATE deadbeef") {
		t.Error("isTransferVerb matched SSHGATE_UPDATE")
	}
	if !isAdminVerb("SSHGATE_UPDATE deadbeef") {
		t.Error("isAdminVerb(SSHGATE_UPDATE) = false; want true")
	}
}
