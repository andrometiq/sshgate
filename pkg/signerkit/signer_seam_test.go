package signerkit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// signer_seam_test.go proves the crypto.Signer seam (C7) is byte-deterministic
// for a file key: a signature minted through Daemon.Signer (crypto.Signer) is
// byte-identical to one minted through the legacy Daemon.Key path, which is in
// turn byte-identical to the frozen phase-0 envelope golden. The whole point of
// pinning opts=crypto.Hash(0) is that pure Ed25519 ignores the rand argument
// and is deterministic (RFC 8032), so the seam cannot silently perturb the wire
// envelope every gate verifies.

// TestSignerSeam_FileKeyViaSignerMatchesKeyGolden drives the Host-bound golden
// request through a Daemon configured with Signer (crypto.Signer) instead of
// Key, and asserts the emitted envelope equals wantSignHostGolden — the exact
// string the Key path froze in envelope_golden_test.go.
func TestSignerSeam_FileKeyViaSignerMatchesKeyGolden(t *testing.T) {
	// Not t.Parallel(): swaps the package-level randRead seam.
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	priv, _ := goldenSignerKey()
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatalf("mem audit: %v", err)
	}
	t.Cleanup(func() { audit.Close() })

	mock := NewMockBackend()
	// crypto.Signer path: set Signer (ed25519.PrivateKey satisfies
	// crypto.Signer), leave Key nil — so resolveSigner takes the Signer branch.
	d := &Daemon{
		Signer:  priv,
		Backend: mock,
		Audit:   audit,
		NowFunc: goldenNow,
	}
	mock.Approve("r_seam", "operator")

	body := `{"kind":"sign","request_id":"r_seam","commands":[{"server":"prod","cmd":"` +
		goldenCmd + `","ttl_seconds":60,"host":"` + goldenHostFP + `"}]}`
	var resp signRespGolden
	if err := json.Unmarshal([]byte(driveGolden(t, d, body)), &resp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}
	if resp.Status != "approved" || len(resp.Signatures) != 1 {
		t.Fatalf("status=%q sigs=%d; want approved/1", resp.Status, len(resp.Signatures))
	}
	if got := resp.Signatures[0].Sig; got != wantSignHostGolden {
		t.Errorf("crypto.Signer(file key) envelope != Key golden — the seam perturbed the wire:\n got  %q\n want %q", got, wantSignHostGolden)
	}
}

// TestSignerSeam_SignBytesKeyEqualsSigner is the tight, direct proof at the
// signBytes level: the Key path, the Signer path, and a raw ed25519.Sign all
// produce the same bytes over the same message.
func TestSignerSeam_SignBytesKeyEqualsSigner(t *testing.T) {
	t.Parallel()
	priv, _ := goldenSignerKey()
	msg := []byte("the exact bytes DecodeSigned reconstructs on the verifier side")

	dKey := &Daemon{Key: priv}
	dSigner := &Daemon{Signer: priv}

	sigKey, err := dKey.signBytes(msg)
	if err != nil {
		t.Fatalf("signBytes via Key: %v", err)
	}
	sigSigner, err := dSigner.signBytes(msg)
	if err != nil {
		t.Fatalf("signBytes via Signer: %v", err)
	}
	if !bytes.Equal(sigKey, sigSigner) {
		t.Errorf("signBytes(Key) != signBytes(Signer):\n Key    %x\n Signer %x", sigKey, sigSigner)
	}
	// Both must equal the raw ed25519.Sign — the deterministic reference the
	// pre-seam code used directly.
	if want := ed25519.Sign(priv, msg); !bytes.Equal(sigKey, want) {
		t.Errorf("signBytes(Key) drifted from ed25519.Sign:\n got  %x\n want %x", sigKey, want)
	}
}
