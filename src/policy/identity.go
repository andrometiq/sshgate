package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// CodecShellExactV1 identifies the pre-argv-exec policy identity. It binds
	// exact source bytes; it does not promise identical shell effects.
	CodecShellExactV1 = "shell-exact-v1"

	// MaxLiteralBytes matches the current hosted signer's command bound. The
	// bound is checked before a literal is copied or decoded.
	MaxLiteralBytes = 16 << 10
)

var (
	// ErrInvalidIdentity marks an invalid or internally inconsistent command
	// identity.
	ErrInvalidIdentity = errors.New("policy: invalid command identity")
	// ErrTooLarge marks a policy object that exceeds a fixed allocation bound.
	ErrTooLarge = errors.New("policy: object too large")
)

var shellExactDigestDomain = []byte("sshgate-policy\x00shell-exact-v1\x00")

// CommandIdentity is a codec-neutral, collision-resistant command identity.
// Literal is retained and compared in addition to Digest so a digest collision
// cannot broaden a permit.
type CommandIdentity struct {
	Codec   string
	Literal []byte
	Digest  [sha256.Size]byte
}

// NewShellExactIdentity returns the shell-exact-v1 identity for literal.
// Literal is copied. No trimming, parsing, normalization, or UTF-8 conversion
// is performed.
func NewShellExactIdentity(literal []byte) (CommandIdentity, error) {
	if err := validateLiteral(literal); err != nil {
		return CommandIdentity{}, err
	}
	clone := append([]byte(nil), literal...)
	return CommandIdentity{
		Codec:   CodecShellExactV1,
		Literal: clone,
		Digest:  ShellExactDigest(clone),
	}, nil
}

// ShellExactDigest returns the domain-separated shell-exact-v1 digest for
// literal. The caller should use NewShellExactIdentity when accepting a new
// policy entry because this low-level function intentionally hashes any byte
// slice, including an invalid empty or NUL-bearing literal.
func ShellExactDigest(literal []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(shellExactDigestDomain)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(literal)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(literal)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// Validate checks the codec, literal bounds, and digest/literal consistency.
func (i CommandIdentity) Validate() error {
	if i.Codec != CodecShellExactV1 {
		return fmt.Errorf("%w: unsupported codec %q", ErrInvalidIdentity, i.Codec)
	}
	if err := validateLiteral(i.Literal); err != nil {
		return err
	}
	want := ShellExactDigest(i.Literal)
	if !bytes.Equal(i.Digest[:], want[:]) {
		return fmt.Errorf("%w: digest does not match literal", ErrInvalidIdentity)
	}
	return nil
}

// MatchesShellExact reports whether candidate is the exact literal authorized
// by i. It verifies both the digest and the literal bytes.
func (i CommandIdentity) MatchesShellExact(candidate []byte) bool {
	if i.Validate() != nil || validateLiteral(candidate) != nil {
		return false
	}
	got := ShellExactDigest(candidate)
	return bytes.Equal(i.Digest[:], got[:]) && bytes.Equal(i.Literal, candidate)
}

func validateLiteral(literal []byte) error {
	if len(literal) == 0 {
		return fmt.Errorf("%w: literal is empty", ErrInvalidIdentity)
	}
	if len(literal) > MaxLiteralBytes {
		return fmt.Errorf("%w: literal is %d bytes; maximum is %d", ErrTooLarge, len(literal), MaxLiteralBytes)
	}
	if bytes.IndexByte(literal, 0) >= 0 {
		return fmt.Errorf("%w: literal contains NUL", ErrInvalidIdentity)
	}
	return nil
}
