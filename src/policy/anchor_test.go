package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
)

func TestEncodeBaseAnchorVerifiedFormat(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	manifest := BaseManifest{
		Schema:     SchemaV1,
		Host:       validHost(),
		Epoch:      3,
		MissAction: MissActionClassifier,
		Growth:     GrowthNone,
		Revision:   7,
	}
	envelope, err := SignBaseManifest(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := EncodeBaseAnchor(envelope, publicKey, validHost())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchor) != anchorSize || !bytes.Equal(anchor[:len(anchorDomain)], []byte(anchorDomain)) {
		t.Fatalf("anchor shape = %x", anchor)
	}
	offset := len(anchorDomain)
	if got := binary.BigEndian.Uint64(anchor[offset : offset+8]); got != manifest.Epoch {
		t.Fatalf("anchor epoch = %d; want %d", got, manifest.Epoch)
	}
	offset += 8
	if got := binary.BigEndian.Uint64(anchor[offset : offset+8]); got != manifest.Revision {
		t.Fatalf("anchor revision = %d; want %d", got, manifest.Revision)
	}
	offset += 8
	payload, _, err := DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := BaseManifestPayloadDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(anchor[offset:], digest[:]) {
		t.Fatalf("anchor digest = %x; want %x", anchor[offset:], digest)
	}
	decoded, err := decodeAnchor(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Version != (PolicyVersion{Epoch: 3, Revision: 7}) || decoded.Digest != digest {
		t.Fatalf("decoded anchor = %#v", decoded)
	}
}

func TestEncodeBaseAnchorRejectsUnverifiedInputs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignBaseManifest(privateKey, BaseManifest{
		Schema: SchemaV1, Host: validHost(), Epoch: 1, Revision: 1,
		MissAction: MissActionClassifier, Growth: GrowthNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeBaseAnchor(envelope, otherPublic, validHost()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong-key error = %v; want ErrBadSignature", err)
	}
	if _, err := EncodeBaseAnchor(envelope, publicKey, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"); err == nil {
		t.Fatal("wrong host accepted")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)/2] ^= 1
	if _, err := EncodeBaseAnchor(tampered, publicKey, validHost()); err == nil {
		t.Fatal("tampered envelope accepted")
	}
}
