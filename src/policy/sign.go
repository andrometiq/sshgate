package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	baseManifestDomain      = "sshgate-policy\x00base-manifest-v1\x00"
	permitCertificateDomain = "sshgate-policy\x00permit-certificate-v1\x00"
	baseDigestDomain        = "sshgate-policy\x00base-manifest-digest-v1\x00"
	signerKeyIDDomain       = "sshgate-policy-key-id-v1\x00"
)

// SignerKeyID returns the frozen policy-authority identifier for an exact raw
// Ed25519 public key. It is domain-separated from policy payload digests and
// encoded as 64 lowercase hexadecimal characters for the policy wire.
func SignerKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: Ed25519 public key is %d bytes; want %d", ErrBadSignature, len(publicKey), ed25519.PublicKeySize)
	}
	material := make([]byte, 0, len(signerKeyIDDomain)+len(publicKey))
	material = append(material, signerKeyIDDomain...)
	material = append(material, publicKey...)
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:]), nil
}

var (
	// ErrBadSignature marks an invalid Ed25519 key or signature.
	ErrBadSignature = errors.New("policy: bad signature")
)

// BaseManifestSigningBytes returns the exact, domain-separated bytes a policy
// signer must sign. The payload must already be a valid canonical base
// manifest, preventing the signer from minting opaque or ambiguous payloads.
func BaseManifestSigningBytes(payload []byte) ([]byte, error) {
	if _, err := ParseBaseManifest(payload); err != nil {
		return nil, err
	}
	return signingBytes(baseManifestDomain, SchemaV1, payload), nil
}

// PermitCertificateSigningBytes returns the exact, domain-separated bytes a
// policy signer must sign. It is cryptographically disjoint from base
// manifests and ordinary command signatures.
func PermitCertificateSigningBytes(payload []byte) ([]byte, error) {
	if _, err := ParsePermitCertificate(payload); err != nil {
		return nil, err
	}
	return signingBytes(permitCertificateDomain, SchemaV1, payload), nil
}

// BaseManifestDigest returns the domain-separated digest to which permit
// certificates bind. It digests the exact canonical manifest payload.
func BaseManifestDigest(m BaseManifest) ([sha256.Size]byte, error) {
	payload, err := MarshalBaseManifest(m)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return BaseManifestPayloadDigest(payload)
}

// BaseManifestPayloadDigest returns the domain-separated digest of a
// canonical manifest payload.
func BaseManifestPayloadDigest(payload []byte) ([sha256.Size]byte, error) {
	if _, err := ParseBaseManifest(payload); err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(signingBytes(baseDigestDomain, SchemaV1, payload)), nil
}

// SignBaseManifest validates and signs m, returning the canonical JSON
// {payload_b64,signature_b64} envelope.
func SignBaseManifest(privateKey ed25519.PrivateKey, m BaseManifest) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key is %d bytes; want %d", ErrBadSignature, len(privateKey), ed25519.PrivateKeySize)
	}
	payload, err := MarshalBaseManifest(m)
	if err != nil {
		return nil, err
	}
	message := signingBytes(baseManifestDomain, SchemaV1, payload)
	return EncodeBaseManifestEnvelope(payload, ed25519.Sign(privateKey, message))
}

// SignPermitCertificate validates and signs c, returning its canonical JSON
// envelope.
func SignPermitCertificate(privateKey ed25519.PrivateKey, c PermitCertificate) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key is %d bytes; want %d", ErrBadSignature, len(privateKey), ed25519.PrivateKeySize)
	}
	payload, err := MarshalPermitCertificate(c)
	if err != nil {
		return nil, err
	}
	message := signingBytes(permitCertificateDomain, SchemaV1, payload)
	return EncodePermitCertificateEnvelope(payload, ed25519.Sign(privateKey, message))
}

// EncodeBaseManifestEnvelope combines a canonical manifest payload and an
// already-produced signature. This is the custody-neutral seam for remote or
// hardware signers.
func EncodeBaseManifestEnvelope(payload, signature []byte) ([]byte, error) {
	if _, err := ParseBaseManifest(payload); err != nil {
		return nil, err
	}
	return encodeEnvelope(payload, signature)
}

// EncodePermitCertificateEnvelope combines a canonical permit payload and an
// already-produced signature.
func EncodePermitCertificateEnvelope(payload, signature []byte) ([]byte, error) {
	if _, err := ParsePermitCertificate(payload); err != nil {
		return nil, err
	}
	return encodeEnvelope(payload, signature)
}

// DecodeBaseManifestEnvelope strictly decodes the outer envelope but does not
// parse or trust the payload. Use VerifyBaseManifest at an enforcement
// boundary. This function exists for custody transports that need raw bytes.
func DecodeBaseManifestEnvelope(envelope []byte) (payload, signature []byte, err error) {
	return decodeEnvelope(envelope)
}

// DecodePermitCertificateEnvelope strictly decodes the outer envelope but
// does not parse or trust the payload.
func DecodePermitCertificateEnvelope(envelope []byte) (payload, signature []byte, err error) {
	return decodeEnvelope(envelope)
}

// VerifyBaseManifest checks envelope shape and signature before strictly
// decoding the canonical payload.
func VerifyBaseManifest(envelope []byte, publicKey ed25519.PublicKey) (BaseManifest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return BaseManifest{}, fmt.Errorf("%w: Ed25519 public key is %d bytes; want %d", ErrBadSignature, len(publicKey), ed25519.PublicKeySize)
	}
	payload, signature, err := decodeEnvelope(envelope)
	if err != nil {
		return BaseManifest{}, err
	}
	if !ed25519.Verify(publicKey, signingBytes(baseManifestDomain, SchemaV1, payload), signature) {
		return BaseManifest{}, ErrBadSignature
	}
	return ParseBaseManifest(payload)
}

// VerifyPermitCertificate checks envelope shape and signature before strictly
// decoding the canonical payload.
func VerifyPermitCertificate(envelope []byte, publicKey ed25519.PublicKey) (PermitCertificate, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return PermitCertificate{}, fmt.Errorf("%w: Ed25519 public key is %d bytes; want %d", ErrBadSignature, len(publicKey), ed25519.PublicKeySize)
	}
	payload, signature, err := decodeEnvelope(envelope)
	if err != nil {
		return PermitCertificate{}, err
	}
	if !ed25519.Verify(publicKey, signingBytes(permitCertificateDomain, SchemaV1, payload), signature) {
		return PermitCertificate{}, ErrBadSignature
	}
	return ParsePermitCertificate(payload)
}

func signingBytes(domain string, schema uint64, payload []byte) []byte {
	message := make([]byte, 0, len(domain)+16+len(payload))
	message = append(message, domain...)
	var field [8]byte
	binary.BigEndian.PutUint64(field[:], schema)
	message = append(message, field[:]...)
	binary.BigEndian.PutUint64(field[:], uint64(len(payload)))
	message = append(message, field[:]...)
	message = append(message, payload...)
	return message
}

func encodeEnvelope(payload, signature []byte) ([]byte, error) {
	if err := checkPayloadSize(payload); err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature is %d bytes; want %d", ErrInvalidEnvelope, len(signature), ed25519.SignatureSize)
	}
	w := signedEnvelopeWire{
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		SignatureB64: base64.StdEncoding.EncodeToString(signature),
	}
	out, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %v", ErrInvalidEnvelope, err)
	}
	if len(out) > MaxPolicyEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope is %d bytes; maximum is %d", ErrTooLarge, len(out), MaxPolicyEnvelopeBytes)
	}
	return out, nil
}

func decodeEnvelope(envelope []byte) ([]byte, []byte, error) {
	if len(envelope) == 0 {
		return nil, nil, fmt.Errorf("%w: empty", ErrInvalidEnvelope)
	}
	if len(envelope) > MaxPolicyEnvelopeBytes {
		return nil, nil, fmt.Errorf("%w: envelope is %d bytes; maximum is %d", ErrTooLarge, len(envelope), MaxPolicyEnvelopeBytes)
	}
	var w signedEnvelopeWire
	if err := decodeCanonicalJSON(envelope, &w); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if w.PayloadB64 == "" || w.SignatureB64 == "" {
		return nil, nil, fmt.Errorf("%w: payload_b64 and signature_b64 are required", ErrInvalidEnvelope)
	}
	if base64.StdEncoding.DecodedLen(len(w.PayloadB64)) > MaxPolicyPayloadBytes {
		return nil, nil, fmt.Errorf("%w: encoded payload exceeds %d decoded bytes", ErrTooLarge, MaxPolicyPayloadBytes)
	}
	payload, err := base64.StdEncoding.DecodeString(w.PayloadB64)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != w.PayloadB64 {
		return nil, nil, fmt.Errorf("%w: payload_b64 is not canonical standard base64", ErrInvalidEnvelope)
	}
	if err := checkPayloadSize(payload); err != nil {
		return nil, nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(w.SignatureB64)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != w.SignatureB64 {
		return nil, nil, fmt.Errorf("%w: signature_b64 is not canonical standard base64", ErrInvalidEnvelope)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%w: signature is %d bytes; want %d", ErrInvalidEnvelope, len(signature), ed25519.SignatureSize)
	}
	canonical, err := json.Marshal(w)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: re-marshal: %v", ErrInvalidEnvelope, err)
	}
	if !bytes.Equal(envelope, canonical) {
		return nil, nil, fmt.Errorf("%w: signed envelope", ErrNotCanonical)
	}
	return payload, signature, nil
}
