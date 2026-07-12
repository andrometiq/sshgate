package signerkit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"
)

// hosted_sign_test.go covers the in-package seams the external signer_test
// (signerserver_test) cannot reach: the randRead entropy seam and the custody
// Lock. Both are the whole reason sign-at-approval was routed through the
// shared core in the phase-5 port — so they must actually cover the hosted
// path, not only the local socket path.

func newHostedTestService(t *testing.T) (*Service, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	svc, err := New(Config{Signer: priv, Audit: NewAppendOnlySink(io.Discard)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, priv
}

// TestSignApproved_NonceFailure proves the hosted sign path surfaces an entropy
// failure as an error rather than a panic or an unsigned envelope — it uses the
// same randRead seam signAll does.
func TestSignApproved_NonceFailure(t *testing.T) {
	// Not t.Parallel(): mutates the package-level randRead var.
	orig := randRead
	defer func() { randRead = orig }()
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy down") }

	svc, _ := newHostedTestService(t)
	if _, err := svc.SignApproved([]HostedSignCommand{{Cmd: "id", TTLSeconds: 60, HostKeyFP: "SHA256:x"}}, time.Now()); err == nil {
		t.Fatalf("SignApproved: expected nonce failure to surface as an error, got nil")
	}
}

// TestSignApproved_LockRefuses proves the custody Lock covers the hosted sign
// path (C1): a locked signer refuses to mint even a valid, host-bound command,
// returning ErrLocked. This is the property the one-codebase port buys "for
// free" by routing hosted signing through signBytes.
func TestSignApproved_LockRefuses(t *testing.T) {
	t.Parallel()
	svc, _ := newHostedTestService(t)

	if err := svc.Lock("maintenance", Operator{ID: "root"}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	_, err := svc.SignApproved([]HostedSignCommand{{Cmd: "df -h", TTLSeconds: 60, HostKeyFP: "SHA256:x"}}, time.Now())
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("SignApproved under Lock: err = %v; want ErrLocked", err)
	}

	// After Unlock the same command mints successfully.
	if err := svc.Unlock(Operator{ID: "root"}); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	res, err := svc.SignApproved([]HostedSignCommand{{Cmd: "df -h", TTLSeconds: 60, HostKeyFP: "SHA256:x"}}, time.Now())
	if err != nil {
		t.Fatalf("SignApproved after Unlock: %v", err)
	}
	if len(res) != 1 || res[0].Sig == "" {
		t.Fatalf("SignApproved after Unlock returned %+v; want one signed result", res)
	}
}
