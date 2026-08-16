package signerkit

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/policy"
)

const policyTestHost = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func policyTestPayload(t testing.TB) []byte {
	t.Helper()
	payload, err := policy.MarshalBaseManifest(policy.BaseManifest{
		Schema:     policy.SchemaV1,
		Host:       policyTestHost,
		Epoch:      1,
		MissAction: policy.MissActionClassifier,
		Growth:     policy.GrowthNone,
		Revision:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestBaseManifestCustodySnapshotAndMaterialization(t *testing.T) {
	privateKey, publicKey := goldenSignerKey()
	d := &Daemon{Signer: privateKey}

	snapshot, keyID, err := d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	wantKeyID, err := policy.SignerKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != wantKeyID || !bytes.Equal(snapshot, publicKey) {
		t.Fatalf("snapshot = %x/%s; want %x/%s", snapshot, keyID, publicKey, wantKeyID)
	}
	// The caller receives a copy, not mutable custody state.
	snapshot[0] ^= 0xff
	again, _, err := d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, publicKey) {
		t.Fatal("mutating returned snapshot changed custody public key")
	}

	payload := policyTestPayload(t)
	got, err := d.MaterializeBaseManifest(keyID, policyTestHost, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.SignerKeyID != keyID || !bytes.Equal(got.PublicKey, publicKey) {
		t.Fatalf("materialization key = %x/%s", got.PublicKey, got.SignerKeyID)
	}
	manifest, err := policy.VerifyBaseManifest(got.Envelope, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Host != policyTestHost {
		t.Fatalf("manifest host = %q", manifest.Host)
	}
	returnedPayload, _, err := policy.DecodeBaseManifestEnvelope(got.Envelope)
	if err != nil || !bytes.Equal(returnedPayload, payload) {
		t.Fatalf("returned payload changed: %q, %v", returnedPayload, err)
	}
}

func TestBaseManifestCustodyFailsOnRotationLockAndWrongHost(t *testing.T) {
	privateKey, _ := goldenSignerKey()
	rotatedKey, _ := altSignerKey()
	d := &Daemon{Signer: privateKey}
	_, frozenID, err := d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RotateTo(rotatedKey); err != nil {
		t.Fatal(err)
	}
	if _, err := d.MaterializeBaseManifest(frozenID, policyTestHost, policyTestPayload(t)); !errors.Is(err, ErrSignerKeyChanged) {
		t.Fatalf("post-rotation error = %v; want ErrSignerKeyChanged", err)
	}

	d = &Daemon{Signer: privateKey}
	_, frozenID, err = d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Lock("operator stop", Operator{}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.MaterializeBaseManifest(frozenID, policyTestHost, policyTestPayload(t)); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked materialization error = %v; want ErrLocked", err)
	}
	if err := d.Unlock(Operator{}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.MaterializeBaseManifest(frozenID, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", policyTestPayload(t)); err == nil {
		t.Fatal("wrong expected host accepted")
	}
}

type lyingPolicySigner struct {
	publicKey ed25519.PublicKey
	signature []byte
}

func (s lyingPolicySigner) Public() crypto.PublicKey { return s.publicKey }
func (s lyingPolicySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return append([]byte(nil), s.signature...), nil
}

type wrongPublicTypeSigner struct{ key ed25519.PrivateKey }

func (s wrongPublicTypeSigner) Public() crypto.PublicKey {
	return []byte(s.key.Public().(ed25519.PublicKey))
}
func (s wrongPublicTypeSigner) Sign(r io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, message, opts)
}

func TestBaseManifestCustodyRejectsHostileSignerResultAndPublicType(t *testing.T) {
	_, publicKey := goldenSignerKey()
	liar := lyingPolicySigner{publicKey: publicKey, signature: make([]byte, ed25519.SignatureSize)}
	d := &Daemon{Signer: liar}
	_, keyID, err := d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.MaterializeBaseManifest(keyID, policyTestHost, policyTestPayload(t)); !errors.Is(err, policy.ErrBadSignature) {
		t.Fatalf("hostile signer error = %v; want policy.ErrBadSignature", err)
	}

	privateKey, _ := goldenSignerKey()
	d = &Daemon{Signer: wrongPublicTypeSigner{key: privateKey}}
	if _, _, err := d.SnapshotBaseManifestSigner(); !errors.Is(err, ErrInvalidSignerPublicKey) {
		t.Fatalf("wrong Public type error = %v; want ErrInvalidSignerPublicKey", err)
	}
}

func TestBaseManifestCustodyHoldsLockAcrossExternalSign(t *testing.T) {
	privateKey, publicKey := goldenSignerKey()
	blocked := newBlockingSigner(privateKey)
	d := &Daemon{Signer: blocked}
	_, keyID, err := d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}

	payload := policyTestPayload(t)
	materialized := make(chan BaseManifestMaterialization, 1)
	mintErr := make(chan error, 1)
	go func() {
		result, err := d.MaterializeBaseManifest(keyID, policyTestHost, payload)
		materialized <- result
		mintErr <- err
	}()
	<-blocked.entered

	rotatedKey, _ := altSignerKey()
	rotated := make(chan error, 1)
	go func() { rotated <- d.RotateTo(rotatedKey) }()
	select {
	case err := <-rotated:
		t.Fatalf("RotateTo returned while policy Sign held custody lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(blocked.release)
	if err := <-mintErr; err != nil {
		t.Fatal(err)
	}
	result := <-materialized
	if _, err := policy.VerifyBaseManifest(result.Envelope, publicKey); err != nil {
		t.Fatalf("in-flight materialization did not stay on frozen key: %v", err)
	}
	if err := <-rotated; err != nil {
		t.Fatal(err)
	}
}

func TestBaseManifestCustodyGuardHoldsRotationAcrossCommit(t *testing.T) {
	privateKey, publicKey := goldenSignerKey()
	d := &Daemon{Signer: privateKey}
	_, keyID, err := d.SnapshotBaseManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		committed <- d.WithBaseManifestSignerIfCurrent(keyID, publicKey, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	rotatedKey, _ := altSignerKey()
	rotated := make(chan error, 1)
	go func() { rotated <- d.RotateTo(rotatedKey) }()
	select {
	case err := <-rotated:
		t.Fatalf("rotation crossed custody-guarded commit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if err := <-rotated; err != nil {
		t.Fatal(err)
	}
	if err := d.WithBaseManifestSignerIfCurrent(keyID, publicKey, func() error { return nil }); !errors.Is(err, ErrSignerKeyChanged) {
		t.Fatalf("stale pair guard = %v; want ErrSignerKeyChanged", err)
	}
	if err := d.WithBaseManifestSignerIfCurrent(keyID, publicKey, nil); err == nil {
		t.Fatal("nil custody commit callback accepted")
	}
}
