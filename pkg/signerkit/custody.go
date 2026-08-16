package signerkit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/karthikeyan5/sshgate/src/policy"
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
	// ErrSignerKeyChanged marks a policy approval whose frozen Ed25519 key ID
	// no longer matches current custody. Callers map it to the dedicated stable
	// signer_key_changed policy outcome and must never mint under the new key.
	ErrSignerKeyChanged = errors.New("signer key changed")
	// ErrInvalidSignerPublicKey marks a crypto.Signer whose Public method does
	// not return the exact 32-byte ed25519.PublicKey type required by policy.
	ErrInvalidSignerPublicKey = errors.New("signer public key is not exact Ed25519")
)

// BaseManifestMaterialization is the custody-atomic result of one policy mint.
// Every slice is a copy and remains valid after the custody lock is released.
type BaseManifestMaterialization struct {
	PublicKey   ed25519.PublicKey
	SignerKeyID string
	Envelope    []byte
}

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

// resolveSignerLocked returns the active signing identity while the caller holds
// custodyMu for reading. Precedence (C7): a live RotateTo target wins, else
// the exported Signer, else the exported Key; all nil ⇒ ErrNoSigner. A held
// Lock short-circuits to ErrLocked before any identity is consulted, so a
// locked signer refuses even when a valid key is present.
func (d *Daemon) resolveSignerLocked() (crypto.Signer, error) {
	locked := d.locked
	reason := d.lockReason
	rot := d.rotSigner

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
	// Keep the read lock across the external crypto.Signer call. Lock and
	// RotateTo take the write lock, so when either control returns every mint
	// that began under the prior custody state has completed. Releasing the lock
	// before Sign would let an HSM/KMS call finish successfully after Lock had
	// already reported success, violating the control's linearized semantics.
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()

	s, err := d.resolveSignerLocked()
	if err != nil {
		return nil, err
	}
	return signWithResolved(s, msg)
}

// SnapshotBaseManifestSigner freezes the current exact Ed25519 public key and
// its domain-separated policy key ID for a future human prompt. The later
// MaterializeBaseManifest call must receive this ID and rechecks it while
// holding custody across parse, signing, encoding, and verification.
func (d *Daemon) SnapshotBaseManifestSigner() (ed25519.PublicKey, string, error) {
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()

	signer, err := d.resolveSignerLocked()
	if err != nil {
		return nil, "", err
	}
	publicKey, err := exactEd25519PublicKey(signer)
	if err != nil {
		return nil, "", err
	}
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil {
		return nil, "", err
	}
	return publicKey, keyID, nil
}

// WithBaseManifestSignerIfCurrent holds policy custody across one short durable
// commit. The callback must not perform external I/O and must preserve the
// custody -> policy-store lock order.
func (d *Daemon) WithBaseManifestSignerIfCurrent(expectedKeyID string, expectedPublicKey ed25519.PublicKey, commit func() error) error {
	if commit == nil {
		return errors.New("base manifest custody commit callback is nil")
	}
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()

	signer, err := d.resolveSignerLocked()
	if err != nil {
		return err
	}
	publicKey, err := exactEd25519PublicKey(signer)
	if err != nil {
		return err
	}
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil {
		return err
	}
	if keyID != expectedKeyID || !bytes.Equal(publicKey, expectedPublicKey) {
		return fmt.Errorf("%w: current %s; expected %s", ErrSignerKeyChanged, keyID, expectedKeyID)
	}
	return commit()
}

// MaterializeBaseManifest validates and signs exactPayload while holding
// custodyMu.RLock for the complete operation. Lock and RotateTo therefore
// linearize outside the mint, and a post-prompt rotation fails with
// ErrSignerKeyChanged rather than silently signing with the new identity.
func (d *Daemon) MaterializeBaseManifest(expectedSignerKeyID, expectedHost string, exactPayload []byte) (BaseManifestMaterialization, error) {
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()

	signer, err := d.resolveSignerLocked()
	if err != nil {
		return BaseManifestMaterialization{}, err
	}
	publicKey, err := exactEd25519PublicKey(signer)
	if err != nil {
		return BaseManifestMaterialization{}, err
	}
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil {
		return BaseManifestMaterialization{}, err
	}
	if keyID != expectedSignerKeyID {
		return BaseManifestMaterialization{}, fmt.Errorf("%w: current %s; expected %s", ErrSignerKeyChanged, keyID, expectedSignerKeyID)
	}

	manifest, err := policy.ParseBaseManifest(exactPayload)
	if err != nil {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: parse: %w", err)
	}
	if manifest.Host != expectedHost {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: payload host %q does not match expected host %q", manifest.Host, expectedHost)
	}
	signingBytes, err := policy.BaseManifestSigningBytes(exactPayload)
	if err != nil {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: signing bytes: %w", err)
	}
	signature, err := signWithResolved(signer, signingBytes)
	if err != nil {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: sign: %w", err)
	}
	envelope, err := policy.EncodeBaseManifestEnvelope(exactPayload, signature)
	if err != nil {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: encode: %w", err)
	}
	// A crypto.Signer can return a correctly-sized signature made by a
	// different key. Verify against the exact snapshotted Public() result so a
	// hostile or broken HSM cannot escape an invalid envelope.
	if _, err := policy.VerifyBaseManifest(envelope, publicKey); err != nil {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: verify signer result: %w", err)
	}
	returnedPayload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		return BaseManifestMaterialization{}, fmt.Errorf("materialize base manifest: decode signer result: %w", err)
	}
	if !bytes.Equal(returnedPayload, exactPayload) {
		return BaseManifestMaterialization{}, errors.New("materialize base manifest: encoded payload substitution")
	}
	return BaseManifestMaterialization{
		PublicKey:   append(ed25519.PublicKey(nil), publicKey...),
		SignerKeyID: keyID,
		Envelope:    append([]byte(nil), envelope...),
	}, nil
}

func exactEd25519PublicKey(signer crypto.Signer) (ed25519.PublicKey, error) {
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidSignerPublicKey
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

// signWithResolved invokes one already-resolved Ed25519 crypto.Signer. Custody
// callers hold custodyMu across this call; splitting resolution from minting
// lets a hosted multi-command batch resolve once and stay on one key for the
// entire batch while preserving the single-command choke point above.
func signWithResolved(s crypto.Signer, msg []byte) ([]byte, error) {
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
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
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
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
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
	return d.rotateTo(next, "", Operator{})
}

// RotateToWithAudit is the additive metadata-rich rotation surface. RotateTo
// retains the frozen one-argument API; callers that have an authenticated
// operator and reason use this method so the generic lifecycle sink records
// them without breaking existing integrators.
func (d *Daemon) RotateToWithAudit(next crypto.Signer, reason string, op Operator) error {
	return d.rotateTo(next, reason, op)
}

func (d *Daemon) rotateTo(next crypto.Signer, reason string, op Operator) error {
	if next == nil {
		return errors.New("RotateTo: next signer is nil (use Lock to disable signing)")
	}
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	d.custodyMu.Lock()
	d.rotSigner = next
	d.custodyMu.Unlock()
	d.auditLifecycle("rotate", reason, op)
	return nil
}

// auditLifecycle records a custody-control transition through the generic sink
// wired by New(Config). A legacy struct-literal Daemon has no lifecycleSink, so
// it falls back to its concrete AuditLog. The branches are deliberately
// exclusive: New wires both fields when Config.Audit is an *AuditLog, but each
// transition still produces exactly one row.
//
// Local custody lifecycle audit remains deliberately best-effort and fail-open,
// matching the frozen local-daemon contract: the state transition is already
// applied, sink failures are surfaced on stderr, and no failure can re-enable a
// locked signer or block an operator's recovery action. lifecycleMu surrounds
// transition + emission so concurrent controls cannot reorder their rows.
// Hosted votes retain their separate fail-closed Verdict contract.
func (d *Daemon) auditLifecycle(event, reason string, op Operator) {
	e := AuditCall{
		Time:      d.now().UTC(),
		Lifecycle: event,
		Reason:    reason,
		Operator:  &op,
	}
	if d.lifecycleSink != nil {
		if err := d.lifecycleSink.Call(context.Background(), e); err != nil {
			fmt.Fprintf(os.Stderr, "signer: audit custody %s failed: %v\n", event, err)
		}
		return
	}
	if d.Audit != nil {
		if err := d.Audit.Call(context.Background(), e); err != nil {
			fmt.Fprintf(os.Stderr, "signer: audit custody %s failed: %v\n", event, err)
		}
	}
}
