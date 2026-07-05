package xfer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Public-half text encoding.
//
// Both public halves are encoded for the provisioning readback as a single
// line: a fixed type tag, a space, then the standard-base64 of the raw
// public key bytes. The tag makes the two key kinds impossible to confuse
// and lets Parse* refuse a mismatched line. This form is stable and
// round-trippable; keep it byte-for-byte if you ever touch it.
const (
	boxPubTag = "sshgate-xfer-box-x25519"
	idPubTag  = "sshgate-xfer-id-ed25519"
)

// BoxKey is an X25519 keypair used to encrypt a transfer TO a recipient.
// The public half is what a sender seals to; the private half decrypts and
// is the secret material a gate holds at rest. Only the 32-byte scalar
// (the private half) is persisted; the public half is re-derived on load,
// so the two can never drift.
type BoxKey struct {
	priv *[32]byte
	pub  *[32]byte
}

// IDKey is an ed25519 keypair used to ATTEST the source of a transfer
// (provenance). The private half signs the envelope attestation; the
// public half is what a recipient verifies against.
type IDKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// GenerateBoxKey creates a fresh X25519 keypair via nacl/box.GenerateKey.
func GenerateBoxKey() (*BoxKey, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate box key: %w", err)
	}
	return &BoxKey{priv: priv, pub: pub}, nil
}

// GenerateIDKey creates a fresh ed25519 identity keypair.
func GenerateIDKey() (*IDKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate id key: %w", err)
	}
	return &IDKey{priv: priv, pub: pub}, nil
}

// Public returns the X25519 public half. The returned pointer aliases the
// key's internal array; callers must not mutate it.
func (k *BoxKey) Public() *[32]byte { return k.pub }

// Private returns the X25519 private half. The returned pointer aliases the
// key's internal array; callers must not mutate it, log it, or copy it into
// an error.
func (k *BoxKey) Private() *[32]byte { return k.priv }

// BoxPublicText renders the stable single-line text encoding of an X25519 box
// public half (raw 32 bytes) WITHOUT needing a BoxKey value. It is the single
// canonical renderer that BoxKey.PublicText delegates to, so the signer's
// per-server registry (which holds only the raw recipient key it must place on
// a transfer leg) and the provisioning readback emit byte-identical text. Keep
// it in lockstep with ParseBoxPublicText.
func BoxPublicText(pub *[32]byte) string {
	return boxPubTag + " " + base64.StdEncoding.EncodeToString(pub[:])
}

// IDPublicText renders the stable single-line text encoding of an ed25519
// identity public half (raw bytes) WITHOUT needing an IDKey value. Canonical
// sibling of BoxPublicText; IDKey.PublicText delegates to it.
func IDPublicText(pub ed25519.PublicKey) string {
	return idPubTag + " " + base64.StdEncoding.EncodeToString(pub)
}

// PublicText returns the stable single-line text encoding of the box public
// half for the provisioning readback.
func (k *BoxKey) PublicText() string {
	return BoxPublicText(k.pub)
}

// Public returns the ed25519 identity public half.
func (k *IDKey) Public() ed25519.PublicKey { return k.pub }

// Private returns the ed25519 identity private half. Never log or wrap this
// into an error.
func (k *IDKey) Private() ed25519.PrivateKey { return k.priv }

// PublicText returns the stable single-line text encoding of the identity
// public half for the provisioning readback.
func (k *IDKey) PublicText() string {
	return IDPublicText(k.pub)
}

// ParseBoxPublicText decodes a box public half produced by
// BoxKey.PublicText. It rejects a line with the wrong tag or a wrong-length
// key.
func ParseBoxPublicText(s string) (*[32]byte, error) {
	raw, err := parsePublicText(s, boxPubTag)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("box public key is %d bytes, want 32", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return &out, nil
}

// ParseIDPublicText decodes an identity public half produced by
// IDKey.PublicText. It rejects a line with the wrong tag or a wrong-length
// key.
func ParseIDPublicText(s string) (ed25519.PublicKey, error) {
	raw, err := parsePublicText(s, idPubTag)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("id public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, raw)
	return out, nil
}

func parsePublicText(s, wantTag string) ([]byte, error) {
	fields := splitOneSpace(s)
	if len(fields) != 2 {
		return nil, errors.New("public key text is not a \"<tag> <base64>\" line")
	}
	if fields[0] != wantTag {
		return nil, fmt.Errorf("public key tag %q, want %q", fields[0], wantTag)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	return raw, nil
}

// splitOneSpace splits on the FIRST single space only, trimming a trailing
// newline. It deliberately does not tolerate extra whitespace so the wire
// form stays canonical.
func splitOneSpace(s string) []string {
	// Trim a single trailing newline that a readback file might carry.
	if n := len(s); n > 0 && s[n-1] == '\n' {
		s = s[:n-1]
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// Save writes the X25519 private half (raw 32 bytes) to path at mode 0600
// via an atomic same-directory replace. The public half is not written; it
// is re-derived on load.
func (k *BoxKey) Save(path string) error {
	return atomicWriteFile(path, k.priv[:], 0o600)
}

// Save writes the ed25519 private key (raw 64 bytes) to path at mode 0600
// via an atomic same-directory replace.
func (k *IDKey) Save(path string) error {
	return atomicWriteFile(path, k.priv, 0o600)
}

// LoadBoxKey reads an X25519 private half from path and re-derives the
// public half. It refuses to load a private key file that is readable or
// writable by group or other (mode must have no bits set below 0700 that
// touch group/other) — the same posture LoadPubKey enforces for the trust
// anchor, tightened because this file IS secret material.
func LoadBoxKey(path string) (*BoxKey, error) {
	data, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("box private key is %d bytes, want 32", len(data))
	}
	var priv [32]byte
	copy(priv[:], data)
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, errors.New("derive box public key: invalid private key")
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return &BoxKey{priv: &priv, pub: &pub}, nil
}

// LoadIDKey reads an ed25519 private key from path and derives the public
// half. It enforces the same group/other permission rejection as
// LoadBoxKey.
func LoadIDKey(path string) (*IDKey, error) {
	data, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("id private key is %d bytes, want %d", len(data), ed25519.PrivateKeySize)
	}
	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(priv, data)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("id private key: unexpected public-key type")
	}
	return &IDKey{priv: priv, pub: pub}, nil
}

// readPrivateFile stats path, rejects a group/other-readable or -writable
// mode, and returns the file bytes. A private key must be 0600 (or tighter,
// e.g. 0400): any bit in the low six positions is a rejection.
func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	mode := info.Mode().Perm()
	// Reject any group (0070) or other (0007) bit — read, write, or exec.
	if mode&0o077 != 0 {
		return nil, fmt.Errorf("private key %s has insecure mode %#o (group/other bits must be off)", path, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	return data, nil
}

// atomicWriteFile writes body to path via a same-directory temp file that is
// fsync'd, chmod'd to mode, then renamed over path; the parent directory is
// fsync'd so the rename survives a crash. It mirrors src/gate.AtomicReplace
// but is kept local so this package does not pull in the gate package's
// dependency graph.
func atomicWriteFile(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}
