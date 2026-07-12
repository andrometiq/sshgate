package signerserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// Signer is the server-side signing engine: it owns the hosted signer's
// Ed25519 master private key and mints SSHGATE_SIG envelopes that
// gate.VerifySigned accepts. It is the piece the v2 scaffold was missing
// — without it the server can insert a pending row and serve back
// whatever JSON it was handed, but it cannot actually sign anything.
//
// A Signer is constructed once at server startup from a key file (see
// LoadSigningKey) and is safe for concurrent use: the private key is
// read-only after construction and ed25519.Sign / crypto/rand are both
// goroutine-safe.
//
// The Signer deliberately REUSES src/sigwire verbatim — sigwire.SigPayload
// for the canonical payload shape and sigwire.EncodeSigned for the wire
// envelope — so the bytes the server signs and emits are byte-identical
// to what the v1 local signer (src/signer/daemon.go signAll) produces and
// what gate (src/gate/verify.go) verifies. There is exactly one envelope
// definition in the tree; this type does not reimplement it.
type Signer struct {
	key ed25519.PrivateKey
}

// SignResult is one signed command produced by Signer.Sign. The JSON
// tags MUST match the poll-response signature shape that the daemon's
// HostedServerBackend expects (src/signer/backend/hosted.go signedSig:
// {cmd, sig}) so the daemon's respond() pass-through accepts the
// signatures verbatim. handlers.go's signedCmd carries the same tags;
// keeping them aligned is enforced by TestSigner_WireShapeMatchesHosted.
type SignResult struct {
	// Cmd is the inner command string, echoed back so the daemon can
	// per-index match it against the request (defence against a server
	// that signs the wrong command for a slot).
	Cmd string `json:"cmd"`

	// Sig is the full SSHGATE_SIG:<sigB64>:<payloadB64> envelope as
	// produced by sigwire.EncodeSigned. This is the string gate
	// receives on the SSH command line.
	Sig string `json:"sig"`
}

// SignCommand is one command to sign: the inner command plus its
// requested validity window in seconds. It mirrors the server's
// signRequestCmd / the daemon's CommandReq (server is irrelevant to
// signing and is intentionally omitted here).
type SignCommand struct {
	Cmd        string
	TTLSeconds int64
}

// Sign produces a signed envelope for each command in cmds, stamped at
// approvedAt (the moment the human approved — NEVER submit time, so the
// 5-minute validity window is measured from the approval, not from when
// the request landed on the server).
//
// For each command:
//
//   - TS  = approvedAt (Unix seconds)
//   - Exp = TS + TTLSeconds
//   - Nonce = a fresh 16-byte crypto/rand value (distinct per command,
//     even for two identical commands in the same batch)
//
// It then signs ed25519.Sign(key, json.Marshal(SigPayload)) and wraps
// the result with sigwire.EncodeSigned — the exact same recipe as the
// v1 local signer, so the output verifies under gate.VerifySigned.
//
// Validity enforcement: gate rejects any envelope whose Exp-TS exceeds
// sigwire.MaxSigValidity (the 5-minute cap in src/gate/verify.go). Sign
// REJECTS such a request up front rather than minting a signature gate
// would refuse — see validateTTL. A non-positive TTL is also rejected.
//
// On any error Sign returns nil and the error; it never returns a
// partially-filled slice, so callers cannot accidentally ship a subset.
func (s *Signer) Sign(cmds []SignCommand, approvedAt time.Time) ([]SignResult, error) {
	if s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil, errors.New("signer: not initialised with a valid key")
	}
	if len(cmds) == 0 {
		return nil, errors.New("signer: no commands to sign")
	}

	ts := approvedAt.Unix()
	out := make([]SignResult, len(cmds))
	for i, c := range cmds {
		if c.Cmd == "" {
			return nil, fmt.Errorf("signer: commands[%d].cmd is empty", i)
		}
		if err := validateTTL(i, c.TTLSeconds); err != nil {
			return nil, err
		}

		nonce, err := newSignerNonce()
		if err != nil {
			return nil, fmt.Errorf("signer: nonce for commands[%d]: %w", i, err)
		}

		payload := sigwire.SigPayload{
			Cmd:   c.Cmd,
			TS:    ts,
			Exp:   ts + c.TTLSeconds,
			Nonce: nonce,
		}

		// Sign the exact bytes gate will reconstruct on the verify side.
		// Both ends go through encoding/json on the same struct, so the
		// byte sequence is stable — this is the contract sigwire +
		// gate.VerifySigned rely on.
		signedBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("signer: marshal payload for commands[%d]: %w", i, err)
		}
		sig := ed25519.Sign(s.key, signedBytes)

		wire, err := sigwire.EncodeSigned(sig, payload)
		if err != nil {
			return nil, fmt.Errorf("signer: encode envelope for commands[%d]: %w", i, err)
		}

		out[i] = SignResult{Cmd: c.Cmd, Sig: wire}
	}
	return out, nil
}

// PublicKey returns the Ed25519 public half of the signing key. The gate
// is provisioned with this so it can verify the server's signatures; the
// golden round-trip test uses it to prove the produced envelopes verify.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// validateTTL enforces the same bounds the daemon enforces before
// dispatch and that gate enforces on verify: TTL > 0 and the validity
// window (which equals TTLSeconds, since Exp-TS == TTLSeconds) must not
// exceed sigwire.MaxSigValidity. gate's cap is `validity > MaxSigValidity`
// (strictly greater is rejected), so a TTL exactly equal to the cap is
// allowed.
//
// Decision: we REJECT an over-long TTL rather than silently clamping it.
// Clamping would hand the operator a shorter-lived signature than they
// asked for without telling them — an honest failure is preferable to a
// surprising one, and it matches the daemon's reject-on-over-TTL
// behaviour (src/signer/daemon.go), keeping the two signing paths
// consistent.
func validateTTL(i int, ttl int64) error {
	if ttl <= 0 {
		return fmt.Errorf("signer: commands[%d].ttl_seconds must be > 0, got %d", i, ttl)
	}
	maxSecs := int64(sigwire.MaxSigValidity / time.Second)
	if ttl > maxSecs {
		return fmt.Errorf("signer: commands[%d].ttl_seconds %d exceeds max %d", i, ttl, maxSecs)
	}
	return nil
}

// signerNonceRead is the entropy source for newSignerNonce. It is a
// package-level var solely so a test can substitute a failing reader to
// exercise the nonce-error branch; production never reassigns it and the
// default is the crypto/rand reader, so the attack surface is unchanged.
// (Same pattern as src/signer/daemon.go's randRead.)
var signerNonceRead = rand.Read

// newSignerNonce returns a 16-byte URL-safe-base64 random string — 128
// bits of entropy, identical in shape to the v1 signer's nonce
// (src/signer/daemon.go newNonce), which is plenty for replay protection
// within the 5-minute validity window.
func newSignerNonce() (string, error) {
	var buf [16]byte
	if _, err := signerNonceRead(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// LoadSigningKey reads an Ed25519 private key from path and returns a
// Signer wrapping it. The file must contain the 64-byte raw binary key
// (the format ed25519.NewKeyFromSeed / signer.GenerateKeyPair writes).
//
// LoadSigningKey REFUSES to load if any group or world permission bit is
// set (mask 0o077) — the private master key must be readable only by its
// owner. This mirrors the v1 signer.LoadKey 0600 reflex and the
// panic-on-empty-API-key reflex in NewServer: a server that holds
// signing capability must fail closed on an insecure or missing key
// rather than start in a degraded state.
//
// Errors are wrapped with %w; callers may use errors.Is(err,
// fs.ErrNotExist) to detect a missing file specifically.
func LoadSigningKey(path string) (*Signer, error) {
	if path == "" {
		return nil, errors.New("signer: key path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("signer: stat private key: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("signer: private key path %s is a directory", path)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return nil, fmt.Errorf("signer: private key %s has insecure mode %#o (group/world bits must be off)", path, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signer: read private key: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: private key %s is %d bytes; want %d (raw Ed25519)", path, len(data), ed25519.PrivateKeySize)
	}
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(key, data)
	return &Signer{key: key}, nil
}

// NewSigner wraps an already-loaded Ed25519 private key in a Signer. It
// is the in-memory constructor used by tests (and any future caller that
// holds the key from a source other than a file, e.g. a KMS). It refuses
// a wrong-sized key so a misconstructed Signer fails at build time, not
// at first signature.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: key is %d bytes; want %d (raw Ed25519)", len(key), ed25519.PrivateKeySize)
	}
	k := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(k, key)
	return &Signer{key: k}, nil
}
