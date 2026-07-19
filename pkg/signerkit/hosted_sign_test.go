package signerkit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
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

func TestSignApproved_BatchIsAtomicAcrossRotation(t *testing.T) {
	priv1, pub1 := goldenSignerKey()
	priv2, pub2 := altSignerKey()
	blocked := newBlockingSigner(priv1)
	svc, err := New(Config{Signer: blocked, Audit: NewAppendOnlySink(io.Discard)})
	if err != nil {
		t.Fatal(err)
	}

	type batchResult struct {
		rows []HostedSignResult
		err  error
	}
	batchDone := make(chan batchResult, 1)
	go func() {
		rows, err := svc.SignApproved([]HostedSignCommand{
			{Cmd: "id", TTLSeconds: 60, HostKeyFP: "SHA256:x"},
			{Cmd: "uptime", TTLSeconds: 60, HostKeyFP: "SHA256:x"},
		}, time.Unix(1_700_000_000, 0))
		batchDone <- batchResult{rows: rows, err: err}
	}()
	<-blocked.entered

	rotateDone := make(chan error, 1)
	go func() {
		rotateDone <- svc.RotateToWithAudit(priv2, "batch boundary", Operator{ID: "op"})
	}()
	select {
	case err := <-rotateDone:
		t.Fatalf("RotateTo crossed an in-flight hosted batch: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(blocked.release)
	batch := <-batchDone
	if batch.err != nil || len(batch.rows) != 2 {
		t.Fatalf("SignApproved: rows=%+v err=%v", batch.rows, batch.err)
	}
	for i, row := range batch.rows {
		sig, payload, err := sigwire.DecodeSigned(row.Sig)
		if err != nil {
			t.Fatalf("decode result %d: %v", i, err)
		}
		msg, err := jsonMarshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(pub1, msg, sig) || ed25519.Verify(pub2, msg, sig) {
			t.Fatalf("batch result %d did not stay on pre-rotation key", i)
		}
	}
	if err := <-rotateDone; err != nil {
		t.Fatal(err)
	}

	after, err := svc.SignApproved([]HostedSignCommand{{Cmd: "whoami", TTLSeconds: 60, HostKeyFP: "SHA256:x"}}, time.Unix(1_700_000_001, 0))
	if err != nil {
		t.Fatal(err)
	}
	sig, payload, err := sigwire.DecodeSigned(after[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := jsonMarshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub2, msg, sig) {
		t.Fatal("post-batch signature did not use rotated key")
	}
}
