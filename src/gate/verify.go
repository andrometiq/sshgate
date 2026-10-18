package gate

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// Verified is what a fully verified SSHGATE_SIG line authorises: the inner
// command and the capabilities its signed payload grants. Reveal and Net are
// read from the authenticated bytes only, never from agent input.
type Verified struct {
	Cmd    string
	Reveal bool
	Net    bool
}

// Verify parses line as a SSHGATE_SIG envelope, verifies its Ed25519
// signature against pubkey, and enforces the spec's time bounds and
// per-server host-key binding:
//
//   - ts must not be more than sigwire.MaxClockSkew ahead of now
//     (⇒ ErrNotYetValid)
//   - exp must be strictly greater than now (now >= exp ⇒ ErrExpired)
//   - exp - ts must not exceed sigwire.MaxSigValidity
//   - the inner cmd must be non-empty
//   - the payload's Host fingerprint must match one of selfHostFPs (the
//     gate's OWN host-key fingerprints, derived from /etc/ssh/ssh_host_*.pub
//     at process start) ⇒ otherwise ErrHostMismatch
//
// The host binding makes a signature approved for one server cryptographically
// un-replayable on another: the signer copies the target's pinned host
// fingerprint into the payload, and each gate independently verifies that the
// binding names ITSELF. It is fail-closed — an empty payload.Host, or an empty
// selfHostFPs set, is a mismatch (a signed write must always carry a binding
// that the executing gate recognises).
//
// selfHostFPs are the fingerprints in canonical hostkey.Fingerprint form
// ("SHA256:..."). The host check runs LAST, after signature and time
// verification, so an unauthenticated caller cannot probe the gate's host set.
//
// On success, the inner cmd and the verified Reveal and Net flags are
// returned. Each flag is true only when the AUTHENTICATED payload set it: it
// is read from the signed bytes, never from any agent input, so the
// (untrusted) agent cannot self-elevate. On any failure the zero Verified is
// returned, so no command or capability leaks through for a payload that did
// not fully verify.
//
// On failure, the returned error wraps one of the package's sentinels
// (ErrBadFormat, ErrBadSig, ErrNotYetValid, ErrExpired, ErrValidityTooLong,
// ErrEmptyCmd, ErrHostMismatch) so callers can match with errors.Is.
//
// Verify (or VerifySigned) is the only correct way to unwrap a SSHGATE_SIG
// line — callers MUST NOT execute the inner cmd from sigwire.DecodeSigned
// alone, because DecodeSigned does not verify the signature.
func Verify(line string, pubkey ed25519.PublicKey, now time.Time, selfHostFPs []string) (Verified, error) {
	sig, payload, err := sigwire.DecodeSigned(line)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrBadFormat, err)
	}
	// DecodeSigned already enforces non-empty cmd at the wire layer;
	// this second check is defensive in case the contract ever loosens.
	if payload.Cmd == "" {
		return Verified{}, ErrEmptyCmd
	}

	// Re-marshal the payload to obtain the exact bytes that were signed.
	// Both signer and verifier go through encoding/json, so the byte
	// sequence is stable.
	signedBytes, err := json.Marshal(payload)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: marshal payload for verify: %v", ErrBadFormat, err)
	}
	if !ed25519.Verify(pubkey, signedBytes, sig) {
		return Verified{}, ErrBadSig
	}

	// Time bounds. The gate is the AUTHORITATIVE validity cap, independent
	// of the signer — so a buggy, leaked, or hostile signer can never mint
	// an over-long or never-expiring token. Reject malformed timestamps
	// BEFORE any arithmetic: this both rejects nonsense (ts/exp <= 0, or a
	// non-positive window) and guarantees 0 < TS < Exp so the Exp-TS
	// subtraction below cannot overflow.
	nowUnix := now.Unix()
	if payload.TS <= 0 || payload.Exp <= 0 || payload.Exp <= payload.TS {
		return Verified{}, ErrBadFormat
	}
	if nowUnix < payload.TS-int64(sigwire.MaxClockSkew/time.Second) {
		return Verified{}, ErrNotYetValid
	}
	if nowUnix >= payload.Exp {
		return Verified{}, ErrExpired
	}
	// Compare the window in int64 SECONDS. Multiplying an attacker-controlled
	// seconds value into an int64-ns time.Duration (Duration(exp-ts)*Second)
	// overflows NEGATIVE for windows > ~9.2e9s, so a `> MaxSigValidity` check
	// silently ACCEPTS a ~290-billion-year token. The guards above keep both
	// operands positive with Exp > TS, so this subtraction stays in range.
	if payload.Exp-payload.TS > int64(sigwire.MaxSigValidity/time.Second) {
		return Verified{}, ErrValidityTooLong
	}

	// Per-server host-key binding (LAST, after authenticity + time). The
	// payload's Host must name one of THIS gate's own host keys. Enforced
	// fail-closed: an empty binding or an empty self set is a mismatch, so a
	// signature minted for another server — or with no binding — can never run
	// here. Empty Host is checked explicitly so it cannot match an (also empty)
	// stray entry.
	//
	// Residual (inherent to host-key binding, NOT a defect): two machines that
	// genuinely SHARE their /etc/ssh host keys — a cloned VM / golden image —
	// are ONE identity to this check, so a signature bound to one verifies on
	// the other. This is the standard property of host-key binding; the
	// mitigation is to regenerate host keys on clones. See
	// docs/proposed/feature3-grants-reveal-audit-binding.md §3.
	if payload.Host == "" || !containsFP(selfHostFPs, payload.Host) {
		return Verified{}, ErrHostMismatch
	}
	// All checks passed: surface the AUTHENTICATED flags alongside the inner
	// cmd. They are only ever returned here, after authenticity + time + host
	// binding all hold, so a failed verify can never leak a capability.
	return Verified{Cmd: payload.Cmd, Reveal: payload.Reveal, Net: payload.Net}, nil
}

// VerifySigned is Verify for callers that do not handle signed network
// grants: it refuses a verified payload with Net set (ErrNetUnsupported), so
// such a caller can never run the command while dropping the grant. Every
// other result is Verify's.
func VerifySigned(line string, pubkey ed25519.PublicKey, now time.Time, selfHostFPs []string) (innerCmd string, reveal bool, err error) {
	verified, err := Verify(line, pubkey, now, selfHostFPs)
	if err != nil {
		return "", false, err
	}
	if verified.Net {
		return "", false, ErrNetUnsupported
	}
	return verified.Cmd, verified.Reveal, nil
}

// containsFP reports whether want is present in fps. A linear scan is correct
// here: a host has only a handful of host keys (ed25519/rsa/ecdsa), and the
// comparison is a constant short fingerprint string.
func containsFP(fps []string, want string) bool {
	for _, fp := range fps {
		if fp == want {
			return true
		}
	}
	return false
}
