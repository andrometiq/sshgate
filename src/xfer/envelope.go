package xfer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"golang.org/x/crypto/nacl/box"
)

// Version is the current envelope wire version. Bump it only for a
// breaking change to the sealed bytes, attestation message, or wire
// encoding; supportedVersion decides what Open will accept.
const Version = 1

// supportedVersion reports whether v is a version this build can open.
func supportedVersion(v int) bool { return v == Version }

// attestDomain is the fixed, NUL-terminated domain-separation tag that
// prefixes every attestation message. It keeps an attestation over a
// transfer from ever being mistaken for a signature over anything else.
const attestDomain = "sshgate/xfer/attest/v1\x00"

// Envelope is the opaque unit that transits the MCP as ciphertext. It
// carries the encrypted secret (Sealed) and a separate ed25519 attestation
// (Attest) proving which source identity sealed THIS content for THIS
// transfer. It deliberately carries NO sender public key: Open trusts only
// the expected sender key passed in as a parameter.
type Envelope struct {
	Version int
	XferID  string
	DestID  string
	Sealed  []byte
	Attest  []byte
}

// Seal encrypts plaintext to recipientBoxPub and attests it with senderID.
//
//   - Sealed = box.SealAnonymous(plaintext, recipientBoxPub): ephemeral
//     X25519 + XSalsa20-Poly1305; only the holder of the matching box
//     private key can open it, and the sender is anonymous at this layer.
//   - Attest = ed25519.Sign(senderID, attestMessage(Version, xferID,
//     destID, sha256(plaintext))): provenance that only senderID's holder
//     could have produced over exactly this content and this transfer.
//
// It never logs, prints, or embeds plaintext or key material in an error.
func Seal(plaintext []byte, recipientBoxPub *[32]byte, senderID ed25519.PrivateKey, xferID, destID string) (Envelope, error) {
	if recipientBoxPub == nil {
		return Envelope{}, errors.New("seal: nil recipient box key")
	}
	if len(senderID) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("seal: invalid sender identity key")
	}
	sealed, err := box.SealAnonymous(nil, plaintext, recipientBoxPub, rand.Reader)
	if err != nil {
		// Generic: never surface plaintext or key bytes.
		return Envelope{}, errors.New("seal: encryption failed")
	}
	h := sha256.Sum256(plaintext)
	attest := ed25519.Sign(senderID, attestMessage(Version, xferID, destID, h))
	return Envelope{
		Version: Version,
		XferID:  xferID,
		DestID:  destID,
		Sealed:  sealed,
		Attest:  attest,
	}, nil
}

// Open decrypts and authenticates env for the recipient identified by
// (recipientBoxPub, recipientBoxPriv), verifying provenance against
// expectedSenderIDPub and the transfer binding against
// (expectXferID, expectDestID).
//
// Every check is fail-closed: any that does not pass returns (nil, error)
// with a generic message and no partial output. The order matters — cheap
// structural checks first, then the AEAD open, then the size cap on
// plaintext, then the attestation.
//
// maxPlaintext is the maximum plaintext length the caller will accept; it
// bounds both a pre-open ciphertext-size sanity cap (Sealed may exceed the
// plaintext by at most box.AnonymousOverhead) and the post-open plaintext.
func Open(env Envelope, recipientBoxPub, recipientBoxPriv *[32]byte, expectedSenderIDPub ed25519.PublicKey, expectXferID, expectDestID string, maxPlaintext int64) ([]byte, error) {
	if !supportedVersion(env.Version) {
		return nil, errors.New("open: unsupported envelope version")
	}
	if recipientBoxPub == nil || recipientBoxPriv == nil {
		return nil, errors.New("open: nil recipient box key")
	}
	if len(expectedSenderIDPub) != ed25519.PublicKeySize {
		return nil, errors.New("open: invalid sender identity key")
	}
	if maxPlaintext < 0 {
		return nil, errors.New("open: invalid maxPlaintext")
	}
	// Anti cross-transfer replay/rebind: the envelope must name exactly the
	// transfer the caller expects.
	if env.XferID != expectXferID || env.DestID != expectDestID {
		return nil, errors.New("open: transfer binding mismatch")
	}
	if len(env.Sealed) == 0 {
		return nil, errors.New("open: empty ciphertext")
	}
	// Pre-open sanity cap: reject anything that could not possibly decrypt
	// to <= maxPlaintext, so we never hand an oversized blob to the AEAD.
	sealCap := maxPlaintext
	if sealCap <= math.MaxInt64-int64(box.AnonymousOverhead) {
		sealCap += int64(box.AnonymousOverhead)
	}
	if int64(len(env.Sealed)) > sealCap {
		return nil, errors.New("open: ciphertext exceeds maximum")
	}
	plaintext, ok := box.OpenAnonymous(nil, env.Sealed, recipientBoxPub, recipientBoxPriv)
	if !ok {
		return nil, errors.New("open: authentication failed")
	}
	if int64(len(plaintext)) > maxPlaintext {
		return nil, errors.New("open: plaintext exceeds maximum")
	}
	h := sha256.Sum256(plaintext)
	// Provenance: only expectedSenderIDPub's holder could have signed THIS
	// content for THIS transfer. Uses the expected (validated) binding
	// values, not any attacker-supplied ones.
	if !ed25519.Verify(expectedSenderIDPub, attestMessage(env.Version, expectXferID, expectDestID, h), env.Attest) {
		return nil, errors.New("open: attestation invalid")
	}
	return plaintext, nil
}

// attestMessage builds the canonical, domain-separated, length-prefixed
// byte string that the sender signs and the recipient verifies.
//
// Wire (no field is ambiguous under concatenation):
//
//	"sshgate/xfer/attest/v1\x00"   fixed domain tag (24 bytes incl. NUL)
//	version                        uint64, big-endian (8 bytes)
//	len(xferID)                    uint32, big-endian (4 bytes)
//	xferID                         bytes
//	len(destID)                    uint32, big-endian (4 bytes)
//	destID                         bytes
//	ptHash                         32 bytes (SHA-256 of the plaintext)
func attestMessage(version int, xferID, destID string, ptHash [32]byte) []byte {
	out := make([]byte, 0, len(attestDomain)+8+4+len(xferID)+4+len(destID)+32)
	out = append(out, attestDomain...)
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(version))
	out = append(out, num[:]...)
	out = appendLenPrefixed(out, xferID)
	out = appendLenPrefixed(out, destID)
	out = append(out, ptHash[:]...)
	return out
}

// appendLenPrefixed appends a uint32 big-endian length followed by the raw
// bytes of s.
func appendLenPrefixed(dst []byte, s string) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	dst = append(dst, l[:]...)
	dst = append(dst, s...)
	return dst
}

// wireEnvelope is the JSON shape Envelope marshals to. []byte fields encode
// as standard base64 by encoding/json, which is the idiomatic self-
// describing form. Field names are stable; keep them if you touch this.
type wireEnvelope struct {
	Version int    `json:"v"`
	XferID  string `json:"xfer_id"`
	DestID  string `json:"dest_id"`
	Sealed  []byte `json:"sealed"`
	Attest  []byte `json:"attest"`
}

// Marshal encodes the envelope to its stable, versioned byte form.
func (e Envelope) Marshal() ([]byte, error) {
	return json.Marshal(wireEnvelope{
		Version: e.Version,
		XferID:  e.XferID,
		DestID:  e.DestID,
		Sealed:  e.Sealed,
		Attest:  e.Attest,
	})
}

// Unmarshal decodes an envelope produced by Marshal. It rejects empty,
// short, or structurally invalid input, and any unknown JSON field. It does
// NOT decide version support (Open does) — but it does require the two
// cryptographic fields to be present and the attestation to be the right
// length, so obvious garbage is rejected early.
func Unmarshal(data []byte) (Envelope, error) {
	if len(data) == 0 {
		return Envelope{}, errors.New("unmarshal: empty input")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w wireEnvelope
	if err := dec.Decode(&w); err != nil {
		return Envelope{}, errors.New("unmarshal: malformed envelope")
	}
	// Reject trailing data after the JSON object.
	if dec.More() {
		return Envelope{}, errors.New("unmarshal: trailing data after envelope")
	}
	if len(w.Sealed) == 0 {
		return Envelope{}, errors.New("unmarshal: missing sealed ciphertext")
	}
	if len(w.Attest) != ed25519.SignatureSize {
		return Envelope{}, errors.New("unmarshal: attestation has wrong length")
	}
	return Envelope{
		Version: w.Version,
		XferID:  w.XferID,
		DestID:  w.DestID,
		Sealed:  w.Sealed,
		Attest:  w.Attest,
	}, nil
}
