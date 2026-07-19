package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	anchorDomain  = "SSHGATE_POLICY_ANCHOR_V1\x00"
	anchorSize    = len(anchorDomain) + 8 + 8 + sha256.Size
	maxAnchorSize = 256
)

// PolicyVersion is ordered lexicographically by Epoch then Revision. A new
// epoch may restart Revision at one.
type PolicyVersion struct {
	Epoch    uint64
	Revision uint64
}

// LoadedBase is one verified, host-bound policy snapshot.
type LoadedBase struct {
	Manifest BaseManifest
	Digest   [sha256.Size]byte
	Version  PolicyVersion
}

type policyAnchor struct {
	Version PolicyVersion
	Digest  [sha256.Size]byte
}

// EncodeBaseAnchor verifies the canonical base-manifest envelope, Ed25519
// signature, expected host, and domain-separated digest before emitting the
// exact protected anchor bytes consumed by Store. There is intentionally no
// exported unchecked anchor constructor.
func EncodeBaseAnchor(envelope []byte, publicKey ed25519.PublicKey, expectedHost string) ([]byte, error) {
	verified, err := verifyBaseEnvelope(envelope, publicKey, expectedHost)
	if err != nil {
		return nil, err
	}
	return encodeAnchor(policyAnchor{Version: verified.Version, Digest: verified.Digest}), nil
}

func verifyBaseEnvelope(envelope []byte, publicKey ed25519.PublicKey, expectedHost string) (LoadedBase, error) {
	manifest, err := VerifyBaseManifest(envelope, publicKey)
	if err != nil {
		return LoadedBase{}, fmt.Errorf("policy: verify base manifest: %w", err)
	}
	if manifest.Host != expectedHost {
		return LoadedBase{}, fmt.Errorf("policy: manifest host %q does not match expected host %q", manifest.Host, expectedHost)
	}
	payload, _, err := DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		return LoadedBase{}, fmt.Errorf("policy: decode verified manifest: %w", err)
	}
	digest, err := BaseManifestPayloadDigest(payload)
	if err != nil {
		return LoadedBase{}, fmt.Errorf("policy: digest verified manifest: %w", err)
	}
	return LoadedBase{
		Manifest: manifest,
		Digest:   digest,
		Version:  PolicyVersion{Epoch: manifest.Epoch, Revision: manifest.Revision},
	}, nil
}

func encodeAnchor(anchor policyAnchor) []byte {
	out := make([]byte, anchorSize)
	offset := copy(out, anchorDomain)
	binary.BigEndian.PutUint64(out[offset:offset+8], anchor.Version.Epoch)
	offset += 8
	binary.BigEndian.PutUint64(out[offset:offset+8], anchor.Version.Revision)
	offset += 8
	copy(out[offset:], anchor.Digest[:])
	return out
}

func decodeAnchor(raw []byte) (policyAnchor, error) {
	if len(raw) != anchorSize || !bytes.Equal(raw[:len(anchorDomain)], []byte(anchorDomain)) {
		return policyAnchor{}, errors.New("non-canonical anchor")
	}
	offset := len(anchorDomain)
	anchor := policyAnchor{}
	anchor.Version.Epoch = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	anchor.Version.Revision = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	copy(anchor.Digest[:], raw[offset:])
	if anchor.Version.Epoch == 0 || anchor.Version.Revision == 0 {
		return policyAnchor{}, errors.New("zero epoch or revision")
	}
	if anchor.Digest == ([sha256.Size]byte{}) {
		return policyAnchor{}, errors.New("zero digest")
	}
	return anchor, nil
}
