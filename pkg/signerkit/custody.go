package signerkit

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// Typed sentinels for the custody + construction surface (C12). They are the
// package's public error vocabulary: callers match them with errors.Is rather
// than string-comparing messages, and no store-subpackage sentinel is ever
// leaked through them. Their messages are intentionally prefix-free so they
// read correctly both on their own (New) and wrapped in the daemon's
// "sign: %v" response (signAll/signTransferLegs).
var (
	// ErrNoSigner is returned when a signature is requested but no signing
	// identity is configured (neither Signer nor Key, and no rotation). On the
	// struct-literal path this replaces today's ed25519.Sign panic on a
	// zero-length key; New returns it when Config.Signer is nil.
	ErrNoSigner = errors.New("no signer configured")
	// ErrLocked is returned by every minting path while a Lock is held. The
	// daemon maps it to an "error" sign response (and an "error"/"approved-error"
	// audit row) rather than retrying.
	ErrLocked = errors.New("signer locked")
	// ErrNoAudit is returned by New when Config.Audit is nil. Audit is required
	// non-nil so a compromised host app cannot silently run without a trail
	// (the anti-suppression property is hollow if audit is optional).
	ErrNoAudit = errors.New("audit sink is required (Config.Audit must be non-nil)")
)

// Operator identifies the human (or machine principal) behind a custody control
// or a hosted-plane vote. ID is the stable identifier; DisplayName is what the
// audit trail shows; Verified records whether the auth layer authenticated
// them; AuthnMethod records HOW ("webauthn" / "totp") so the append-only ledger
// can carry it per vote (C12). It never carries a credential or secret.
type Operator struct {
	ID          string
	DisplayName string
	Verified    bool
	AuthnMethod string
}

// resolveSigner returns the active signing identity, honoring Lock and
// rotation under custodyMu. Precedence (C7): a live RotateTo target wins, else
// the exported Signer, else the exported Key; all nil ⇒ ErrNoSigner. A held
// Lock short-circuits to ErrLocked before any identity is consulted, so a
// locked signer refuses even when a valid key is present.
func (d *Daemon) resolveSigner() (crypto.Signer, error) {
	d.custodyMu.RLock()
	locked := d.locked
	reason := d.lockReason
	rot := d.rotSigner
	d.custodyMu.RUnlock()

	if locked {
		if reason == "" {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("%w: %s", ErrLocked, reason)
	}
	if rot != nil {
		return rot, nil
	}
	if d.Signer != nil {
		return d.Signer, nil
	}
	if len(d.Key) > 0 {
		return d.Key, nil
	}
	return nil, ErrNoSigner
}

// signBytes mints one Ed25519 signature over msg through the resolved custody
// identity. It is the SINGLE choke point both local sign sites route through
// (signAll, signTransferLegs) — so Lock (C1), rotation (C2), the concurrency
// guard (C3), and the crypto.Signer seam (C7) apply to every minted signature
// at once, in one place, rather than being scattered per caller. The remote
// pass-through path in respond (the carried-verdict branch, len(Signatures)>0)
// mints nothing with the local key and is deliberately exempt (C1) — a hosted
// backend's signatures are governed by that service's own Lock.
//
// opts is pinned to crypto.Hash(0): pure (unhashed) Ed25519. For a file key
// that is byte-identical to ed25519.Sign(key, msg) — Ed25519 is deterministic
// (RFC 8032) and ignores the rand argument in this mode — which is exactly what
// keeps the phase-0 envelope goldens stable across the seam. A KMS/HSM-backed
// crypto.Signer must likewise implement standard Ed25519 for its envelopes to
// verify on the gate.
func (d *Daemon) signBytes(msg []byte) ([]byte, error) {
	s, err := d.resolveSigner()
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signer produced a %d-byte signature; want %d (Ed25519)", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// Lock is the in-memory kill-switch: it refuses every subsequent signature
// (signAll, signTransferLegs, and the phase-5 vote engine — all via signBytes)
// with ErrLocked until Unlock. reason is surfaced in the sign error and the
// lifecycle audit row; op identifies the actor for the trail (C12).
//
// Lock is FORWARD-ONLY (C1): a signature already minted before the Lock is on
// the wire and stays valid until its Exp (<= sigwire.MaxSigValidity, 5 min) —
// Lock cannot recall it; the bounded validity window is the mitigation, not
// revocation. A mid-flight approval that resolves after the Lock lands fails at
// signBytes: the sign path returns an error response + an "error" audit row,
// the transfer path an "approved-error" row (the human tapped, the mint was
// refused). Lock state is process-memory only — a restart clears it, so a
// durable kill-switch means removing/rotating the key at construction, not
// relying on Lock surviving a restart.
func (d *Daemon) Lock(reason string, op Operator) error {
	d.custodyMu.Lock()
	d.locked = true
	d.lockReason = reason
	d.custodyMu.Unlock()
	d.auditLifecycle("lock", reason, op)
	return nil
}

// Unlock clears a Lock, re-enabling signing. It is idempotent — unlocking an
// already-unlocked signer is a no-op that still records the actor. op
// identifies the actor for the audit trail, symmetric with Lock (C12).
func (d *Daemon) Unlock(op Operator) error {
	d.custodyMu.Lock()
	d.locked = false
	d.lockReason = ""
	d.custodyMu.Unlock()
	d.auditLifecycle("unlock", "", op)
	return nil
}

// RotateTo atomically cuts the active signing identity over to next, effective
// immediately for every subsequent signature. next must be non-nil (use Lock to
// disable signing entirely).
//
// This is an ATOMIC CUT-OVER, not a dual-accept window (C2): the gate loads
// exactly ONE public key (gate.LoadPubKey) and VerifySigned takes one, so the
// signer cannot make gates accept two keys and the library will not fake it.
// Operational cost: each gate is re-provisioned with the new public key
// individually, so there is an unavoidable per-gate rejection window (the
// gate's exit 65/77 class) between the cut-over and re-provisioning during
// which envelopes minted by the new signer do not yet verify. Zero-downtime
// rotation would require future gate-side dual-key acceptance — an explicit
// roadmap deferral, not implemented here. An approval that resolves after the
// cut-over mints with next; gates not yet re-provisioned reject it. Rotation is
// process-memory only and is NOT persisted — the constructed Signer/Key is the
// durable source, so after cutting over the integrator updates their
// wiring/config. A held Lock is independent: RotateTo does not clear it, and a
// locked signer stays locked on the new identity until Unlock.
func (d *Daemon) RotateTo(next crypto.Signer) error {
	if next == nil {
		return errors.New("RotateTo: next signer is nil (use Lock to disable signing)")
	}
	d.custodyMu.Lock()
	d.rotSigner = next
	d.custodyMu.Unlock()
	d.auditLifecycle("rotate", "", Operator{})
	return nil
}

// auditLifecycle records a custody-control transition (lock/unlock/rotate) as a
// best-effort row on the local AuditLog, so the kill-switch and rotation leave
// a trail (the whole reason Lock/Unlock carry an Operator — C12). It is
// deliberately best-effort and nil-safe: a struct-literal Daemon need not have
// wired an Audit, and a custody control must never panic. Errors go to stderr,
// matching the daemon's fail-open grant/transfer audit posture. These rows use
// dedicated statuses ("lock"/"unlock"/"rotate"), disjoint from the sign-path
// verdict statuses, so no existing audit consumer or golden is affected.
func (d *Daemon) auditLifecycle(event, reason string, op Operator) {
	if d.Audit == nil {
		return
	}
	who := op.DisplayName
	if who == "" {
		who = op.ID
	}
	desc := "custody: " + event
	if reason != "" {
		desc += " (" + reason + ")"
	}
	ev := AuditEvent{
		TS:         d.now().UTC(),
		Status:     event,
		Commands:   []string{desc},
		ApprovedBy: who,
	}
	if err := d.Audit.Write(ev); err != nil {
		fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", err)
	}
}
