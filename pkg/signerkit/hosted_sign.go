package signerkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// hosted_sign.go is the shared-core signing surface the hosted (Tier-3)
// approval engine drives at quorum. It is the whole point of the phase-5
// one-codebase reconciliation: the hosted plane no longer owns a separate
// ed25519 key + Sign routine (the branch's deleted signerserver.Signer).
// Instead sign-at-approval routes through the SAME custody choke point
// (signBytes, custody.go) as the local socket path — so Lock, RotateTo, and
// the crypto.Signer seam govern hosted signing FOR FREE, and every hosted
// envelope is byte-identical to a local one and verifies under the same
// gate.VerifySigned. One signing core, one maintenance surface.

// HostedSignCommand is one approved command the hosted approval engine asks
// the core to sign. HostKeyFP binds the minted SigPayload.Host to the
// executing gate (D4); the current gate fail-closes a Host-less write
// (gate.ErrHostMismatch), so a real deployment MUST supply it. TTLSeconds is
// the requested validity window (Exp-TS), capped at sigwire.MaxSigValidity.
type HostedSignCommand struct {
	Cmd        string
	HostKeyFP  string
	TTLSeconds int64
}

// HostedSignResult is one minted envelope. The JSON tags match the hosted
// poll-response signature shape ({cmd, sig}) so the machine wire stays
// byte-identical — the frozen HostedServerBackend decodes it unchanged.
type HostedSignResult struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// SignApproved mints one gate-valid SSHGATE_SIG envelope per command at
// hosted-approval time. Each signature is minted at approvedAt (sign-at-
// approval — the 5-minute validity window is measured from the human's
// approval, NEVER submit time) with an independent core-minted nonce, and
// routed through signBytes so Lock/RotateTo/crypto.Signer apply.
//
// Reveal is NEVER set on the hosted path: the hosted (Tier-3) signer stays
// reveal-fail-closed (the v2 wire + UI carry no reveal banner), so a hosted
// approval can never mint an un-redacted reveal. Host-threading (D4) must not
// accidentally carry Reveal along — it does not here (C14).
//
// TTL bounds mirror the gate's cap: a non-positive or over-cap TTL is rejected
// up front rather than minting an envelope the gate would refuse. On any error
// SignApproved returns nil and the error — never a partially-filled slice, so a
// caller cannot ship a subset.
func (s *Service) SignApproved(cmds []HostedSignCommand, approvedAt time.Time) ([]HostedSignResult, error) {
	return s.daemon.signApproved(cmds, approvedAt)
}

func (d *Daemon) signApproved(cmds []HostedSignCommand, approvedAt time.Time) ([]HostedSignResult, error) {
	if len(cmds) == 0 {
		return nil, errors.New("signerkit: no commands to sign")
	}
	ts := approvedAt.Unix()
	maxSecs := int64(sigwire.MaxSigValidity / time.Second)
	payloads := make([]sigwire.SigPayload, len(cmds))
	signedPayloads := make([][]byte, len(cmds))
	for i, c := range cmds {
		if c.Cmd == "" {
			return nil, fmt.Errorf("signerkit: commands[%d].cmd is empty", i)
		}
		if c.TTLSeconds <= 0 {
			return nil, fmt.Errorf("signerkit: commands[%d].ttl_seconds must be > 0, got %d", i, c.TTLSeconds)
		}
		if c.TTLSeconds > maxSecs {
			return nil, fmt.Errorf("signerkit: commands[%d].ttl_seconds %d exceeds max %d", i, c.TTLSeconds, maxSecs)
		}
		nonce, err := newNonce()
		if err != nil {
			return nil, fmt.Errorf("signerkit: nonce for commands[%d]: %w", i, err)
		}
		payloads[i] = sigwire.SigPayload{
			Cmd:   c.Cmd,
			TS:    ts,
			Exp:   ts + c.TTLSeconds,
			Nonce: nonce,
			// Bind to the target's pinned host key (D4). Reveal deliberately
			// left zero — hosted stays fail-closed.
			Host: c.HostKeyFP,
		}
		// Sign the exact bytes the gate reconstructs on verify (both sides go
		// through the same json.Marshal of SigPayload, so the bytes are stable).
		signedBytes, err := jsonMarshal(payloads[i])
		if err != nil {
			return nil, fmt.Errorf("signerkit: marshal payload for commands[%d]: %w", i, err)
		}
		signedPayloads[i] = signedBytes
	}

	// Resolve custody once and hold it across the whole batch. Lock/RotateTo
	// linearize at the batch boundary, so a two-command approval can never be
	// split across old and new signing identities.
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()
	signer, err := d.resolveSignerLocked()
	if err != nil {
		return nil, err
	}

	out := make([]HostedSignResult, len(cmds))
	for i, c := range cmds {
		sig, err := signWithResolved(signer, signedPayloads[i])
		if err != nil {
			return nil, err
		}
		wire, err := sigwire.EncodeSigned(sig, payloads[i])
		if err != nil {
			return nil, fmt.Errorf("signerkit: encode envelope for commands[%d]: %w", i, err)
		}
		out[i] = HostedSignResult{Cmd: c.Cmd, Sig: wire}
	}
	return out, nil
}

// Call records an incoming hosted sign request on the required AuditSink (C5)
// by delegating to the sink the Service was constructed with. It is the
// hosted-plane analogue of the local daemon's own audit row: every Submit /
// POST /v1/sign should Call before the request enters the approval queue.
func (s *Service) Call(ctx context.Context, e AuditCall) error {
	return s.audit.Call(ctx, e)
}

// Verdict records a single operator's resolution on the required AuditSink
// (C5). The hosted approval engine emits it BEFORE flipping request state and
// fails CLOSED on a sink error — the opposite of the local daemon's fail-open,
// post-delivery audit, and per-spec: a compromised or misconfigured host app
// cannot silently suppress the record of who approved what.
func (s *Service) Verdict(ctx context.Context, e AuditVerdict) error {
	return s.audit.Verdict(ctx, e)
}
