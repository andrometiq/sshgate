package gate

import (
	"errors"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// Sentinel errors returned by Verify and VerifySigned. Callers should match them
// with errors.Is rather than string-comparing the message.
var (
	// ErrBadFormat means the input did not parse as a well-formed
	// SSHGATE_SIG envelope (missing prefix, bad base64, bad JSON, or
	// missing required field).
	ErrBadFormat = errors.New("bad signed-command format")

	// ErrBadSig means the envelope parsed but the Ed25519 signature did
	// not verify against the supplied public key.
	ErrBadSig = errors.New("signature verification failed")

	// ErrExpired means the signed command's exp timestamp is at or
	// before the verification clock (now >= exp).
	ErrExpired = errors.New("signature expired")

	// ErrNotYetValid means the signed command's ts is more than
	// sigwire.MaxClockSkew ahead of the gate's clock.
	ErrNotYetValid = errors.New("signature not yet valid: its timestamp is ahead of this host's clock")

	// ErrValidityTooLong means the signed command's validity window
	// (exp-ts) exceeds sigwire.MaxSigValidity. This caps the blast
	// radius of an approved signature and is enforced even if the
	// signature itself is valid.
	ErrValidityTooLong = errors.New("signature validity window too long")

	// ErrEmptyCmd means the signed payload's cmd field was empty after
	// decoding. gate refuses to execute a zero-length command.
	ErrEmptyCmd = errors.New("signed payload has empty cmd")

	// ErrHostMismatch means the signed payload's host-key binding (the
	// payload's host fingerprint) did not match any of THIS gate's own SSH
	// host-key fingerprints — or the payload carried no binding at all. It
	// makes a signature approved for one server un-replayable on another, and
	// is enforced fail-closed: an empty binding, or an empty set of gate host
	// keys, is a mismatch.
	ErrHostMismatch = errors.New("signed payload host-key binding does not match this gate")

	// ErrNetUnsupported means VerifySigned verified a payload that carries a
	// signed network grant (Net). VerifySigned's callers do not honour the
	// grant, so the command is refused rather than run without it.
	ErrNetUnsupported = errors.New(sigwire.GateNetUnsupported)
)
