//go:build linux

package signerkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	policyAuditPhaseSubmission      = "submission"
	policyAuditPhaseHumanVerdict    = "human-verdict"
	policyAuditPhaseMaterialization = "materialization"
	policyAuditPhaseTerminalNoMint  = "terminal-no-mint"
	policyAuditPrincipalLocal       = "local-owner"
)

type localPolicyDecisionHooks struct {
	journal   *localPolicyJournal
	requestID string
	challenge string
}

type policyNoOpAuditError struct{ err error }

func (e *policyNoOpAuditError) Error() string { return e.err.Error() }
func (e *policyNoOpAuditError) Unwrap() error { return e.err }

func (h *localPolicyDecisionHooks) Activate(_ context.Context) error {
	_, err := h.journal.activateLocal(h.requestID, h.challenge)
	return err
}

func (h *localPolicyDecisionHooks) CommitVerdict(_ context.Context, result BaseManifestApprovalResult) error {
	_, err := h.journal.commitLocalVerdict(h.requestID, h.challenge, result)
	return err
}

func (h *localPolicyDecisionHooks) AcknowledgeVerdict(_ context.Context, result BaseManifestApprovalResult) error {
	return h.journal.acknowledgeLocalVerdict(h.requestID, result)
}

func (d *Daemon) handleBaseManifestPolicy(ctx context.Context, conn io.Writer, frame []byte) error {
	decoded, err := policywire.DecodeRequestLine(frame)
	if err != nil {
		// A non-canonical frame does not provide trustworthy response identity or
		// tuple fields. Close this one-request connection; never answer it on the
		// ordinary sign wire or fabricate a request ID.
		return fmt.Errorf("policy request rejected before dispatch: %w", err)
	}
	if d.policyJournal == nil {
		return d.respondPolicyEphemeral(ctx, conn, decoded, policywire.ErrorPolicyNotSupported)
	}
	if err := d.retryPolicyRecovery(ctx); err != nil {
		return fmt.Errorf("policy recovery unavailable: %w", err)
	}

	lookup, found, err := d.policyJournal.lookup(decoded)
	if err != nil {
		return d.respondPolicyJournalError(ctx, conn, decoded, err)
	}
	if found && lookup.Terminal != nil {
		return writePolicyResponse(conn, *lookup.Terminal)
	}

	backend, ok := d.Backend.(BaseManifestApprovalBackend)
	if !ok {
		if found {
			// The durable ID remains authoritative. A temporary capability or
			// configuration loss must not manufacture an uncached terminal that a
			// restored backend could later contradict.
			return errors.New("policy backend unavailable for existing nonterminal request")
		}
		return d.respondPolicyEphemeral(ctx, conn, decoded, policywire.ErrorPolicyNotSupported)
	}
	mode := policyModeLocalTelegram
	if _, hosted := d.Backend.(HostedBaseManifestApprovalBackend); hosted {
		mode = policyModeHosted
	}
	if found && lookup.Record.Mode != mode {
		// Never reinterpret an in-flight local card as hosted polling or vice
		// versa. This is transport-unavailable, not a terminal that could allow a
		// second human decision under a replacement backend.
		return errors.New("policy request backend mode changed while request is nonterminal")
	}

	if !found {
		publicKey, keyErr := d.snapshotPolicyAuthority(mode)
		if keyErr != nil {
			return fmt.Errorf("snapshot policy authority: %w", keyErr)
		}
		begin, beginErr := d.policyJournal.begin(decoded, mode, publicKey, d.now())
		if beginErr != nil {
			return d.respondPolicyJournalError(ctx, conn, decoded, beginErr)
		}
		lookup = begin
	}

	wait, leader := d.acquirePolicyFlight(decoded.Wire.RequestID)
	if !leader {
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		retry, ok, lookupErr := d.policyJournal.lookup(decoded)
		if lookupErr != nil {
			return d.respondPolicyJournalError(ctx, conn, decoded, lookupErr)
		}
		if ok && retry.Terminal != nil {
			return writePolicyResponse(conn, *retry.Terminal)
		}
		return errors.New("policy request remains unexposed after joined flight")
	}
	defer d.releasePolicyFlight(decoded.Wire.RequestID, wait)

	response, err := d.processPolicyRecord(ctx, decoded.Wire.RequestID, backend)
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("policy request processing produced no terminal response")
	}
	return writePolicyResponse(conn, *response)
}

func (d *Daemon) snapshotPolicyAuthority(mode policyRequestMode) (ed25519.PublicKey, error) {
	if mode == policyModeHosted {
		hosted, ok := d.Backend.(HostedBaseManifestApprovalBackend)
		if !ok {
			return nil, errors.New("hosted policy backend marker missing")
		}
		raw, err := hosted.BaseManifestAuthorityPublicKey()
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("hosted policy authority key is %d bytes; want %d", len(raw), ed25519.PublicKeySize)
		}
		return append(ed25519.PublicKey(nil), raw...), nil
	}
	publicKey, _, err := d.SnapshotBaseManifestSigner()
	return publicKey, err
}

func (d *Daemon) acquirePolicyFlight(requestID string) (<-chan struct{}, bool) {
	d.policyFlightsMu.Lock()
	defer d.policyFlightsMu.Unlock()
	if d.policyFlights == nil {
		d.policyFlights = make(map[string]chan struct{})
	}
	if existing, ok := d.policyFlights[requestID]; ok {
		return existing, false
	}
	done := make(chan struct{})
	d.policyFlights[requestID] = done
	return done, true
}

func (d *Daemon) releasePolicyFlight(requestID string, wait <-chan struct{}) {
	d.policyFlightsMu.Lock()
	defer d.policyFlightsMu.Unlock()
	current, ok := d.policyFlights[requestID]
	if !ok || (<-chan struct{})(current) != wait {
		return
	}
	delete(d.policyFlights, requestID)
	close(current)
}

func (d *Daemon) processPolicyRecord(ctx context.Context, requestID string, backend BaseManifestApprovalBackend) (*policywire.Response, error) {
	for {
		record, err := d.policyJournal.record(requestID)
		if err != nil {
			return nil, err
		}
		if policyStateIsTerminal(record.State) {
			return clonePolicyResponse(record.Response), nil
		}
		switch record.State {
		case policyStateReceivedUnaudited:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseSubmission); err != nil {
				return nil, fmt.Errorf("policy submission audit: %w", err)
			}
			if record.FailureCode != "" {
				if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
					return nil, fmt.Errorf("policy rejection audit: %w", err)
				}
				if _, err := d.policyJournal.finalizeNoMint(requestID); err != nil {
					return nil, err
				}
				continue
			}
			if record.NoOp {
				// Stage the trusted existing envelope first so the no-op terminal
				// audit binds the exact result hash. Exposure still goes through the
				// same custody/head-linearized commit as a freshly materialized result.
				if _, err := d.policyJournal.stageNoOp(requestID); err != nil {
					return nil, err
				}
				continue
			}
			if record.Mode == policyModeLocalTelegram {
				publicKey, keyID, keyErr := d.SnapshotBaseManifestSigner()
				frozen, _ := policyRequestPublicKey(&record)
				if keyErr != nil || keyID != record.ExpectedSignerKeyID || !bytes.Equal(publicKey, frozen) {
					if _, err := d.policyJournal.rejectReceived(requestID, policywire.ErrorSignerKeyChanged); err != nil {
						return nil, err
					}
					continue
				}
				challenge, err := newCallbackChallenge()
				if err != nil {
					return nil, err
				}
				if _, err := d.policyJournal.markNotifying(requestID, challenge); err != nil {
					return nil, err
				}
			} else {
				if _, err := d.policyJournal.markNotifying(requestID, ""); err != nil {
					return nil, err
				}
			}
			continue

		case policyStateNotifying, policyStatePending:
			if backend == nil {
				return nil, errors.New("policy backend unavailable for nonterminal request")
			}
			if record.Mode == policyModeLocalTelegram && record.State == policyStatePending {
				// With no active flight this can only be a legacy/raw construction
				// that skipped startup reconciliation. Never re-prompt it.
				if _, err := d.policyJournal.interruptLocal(requestID); err != nil {
					return nil, err
				}
				continue
			}
			result, err := d.requestPolicyDecision(ctx, record, backend)
			if err != nil {
				if record.Mode == policyModeHosted {
					// POST/GET may already be durable remotely; preserve notifying or
					// pending so the exact ID can reconcile later.
					return nil, fmt.Errorf("hosted policy reconciliation unavailable: %w", err)
				}
				current, loadErr := d.policyJournal.record(requestID)
				if loadErr != nil {
					return nil, loadErr
				}
				if current.State == policyStateNotifying {
					if _, markErr := d.policyJournal.markNotificationError(requestID); markErr != nil {
						return nil, markErr
					}
				} else if current.State == policyStatePending {
					if _, markErr := d.policyJournal.interruptLocal(requestID); markErr != nil {
						return nil, markErr
					}
				}
				continue
			}
			if record.Mode == policyModeLocalTelegram {
				if err := d.policyJournal.acknowledgeLocalVerdict(requestID, result); err != nil {
					return nil, fmt.Errorf("backend published uncommitted policy verdict: %w", err)
				}
			} else if err := d.stageHostedResult(requestID, result); err != nil {
				return nil, err
			}
			continue

		case policyStateApprovalReceived:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseHumanVerdict); err != nil {
				return nil, fmt.Errorf("policy approval audit: %w", err)
			}
			if _, err := d.policyJournal.setApprovedMaterializing(requestID); err != nil {
				return nil, err
			}
			continue

		case policyStateDenialReceived, policyStateTimeoutReceived, policyStateInterruptionReceived:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseHumanVerdict); err != nil {
				return nil, fmt.Errorf("policy verdict audit: %w", err)
			}
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
				return nil, fmt.Errorf("policy no-mint terminal audit: %w", err)
			}
			if _, err := d.policyJournal.finalizeNoMint(requestID); err != nil {
				return nil, err
			}
			continue

		case policyStateNotificationErrorReceived:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
				return nil, fmt.Errorf("policy notification failure audit: %w", err)
			}
			if _, err := d.policyJournal.finalizeNoMint(requestID); err != nil {
				return nil, err
			}
			continue

		case policyStateApprovedMaterializing:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseMaterialization); err != nil {
				return nil, fmt.Errorf("policy pre-mint audit: %w", err)
			}
			payload, err := policyRequestPayload(&record)
			if err != nil {
				return nil, err
			}
			materialized, err := d.MaterializeBaseManifest(record.ExpectedSignerKeyID, record.HostKeyFP, payload)
			if err != nil {
				code := policywire.ErrorPolicyMaterializationFailed
				if errors.Is(err, ErrSignerKeyChanged) {
					code = policywire.ErrorSignerKeyChanged
				}
				if _, markErr := d.policyJournal.setMaterializationError(requestID, code); markErr != nil {
					return nil, markErr
				}
				continue
			}
			frozen, err := policyRequestPublicKey(&record)
			if err != nil || materialized.SignerKeyID != record.ExpectedSignerKeyID || !bytes.Equal(materialized.PublicKey, frozen) {
				if _, markErr := d.policyJournal.setMaterializationError(requestID, policywire.ErrorSignerKeyChanged); markErr != nil {
					return nil, markErr
				}
				continue
			}
			if _, err := d.policyJournal.persistApprovedUnexposed(requestID, materialized.Envelope); err != nil {
				return nil, err
			}
			continue

		case policyStateApprovedUnexposed:
			if record.NoOp {
				if _, commitErr := d.commitLocalNoOpUnderCustody(ctx, requestID, record); commitErr != nil {
					var auditErr *policyNoOpAuditError
					if errors.As(commitErr, &auditErr) {
						return nil, fmt.Errorf("policy no-op audit: %w", auditErr)
					}
					var protocolErr *policyJournalError
					code := policywire.ErrorPolicyMaterializationFailed
					if errors.As(commitErr, &protocolErr) && protocolErr.Code == policywire.ErrorStalePolicyHead {
						code = policywire.ErrorStalePolicyHead
					} else if errors.Is(commitErr, ErrSignerKeyChanged) {
						code = policywire.ErrorSignerKeyChanged
					}
					if _, markErr := d.policyJournal.setMaterializationError(requestID, code); markErr != nil {
						return nil, markErr
					}
					continue
				}
				continue
			}
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseMaterialization); err != nil {
				return nil, fmt.Errorf("policy result audit: %w", err)
			}
			if record.Mode == policyModeLocalTelegram {
				if _, commitErr := d.commitLocalPolicyApprovedUnderCustody(requestID, record); commitErr != nil {
					var protocolErr *policyJournalError
					code := policywire.ErrorPolicyMaterializationFailed
					if errors.As(commitErr, &protocolErr) && protocolErr.Code == policywire.ErrorStalePolicyHead {
						code = policywire.ErrorStalePolicyHead
					} else if errors.Is(commitErr, ErrSignerKeyChanged) {
						code = policywire.ErrorSignerKeyChanged
					}
					if _, markErr := d.policyJournal.setMaterializationError(requestID, code); markErr != nil {
						return nil, markErr
					}
					continue
				}
				continue
			}
			if _, err := d.policyJournal.commitApproved(requestID); err != nil {
				var protocolErr *policyJournalError
				if record.Mode == policyModeLocalTelegram && errors.As(err, &protocolErr) && protocolErr.Code == policywire.ErrorStalePolicyHead {
					if _, markErr := d.policyJournal.setMaterializationError(requestID, policywire.ErrorStalePolicyHead); markErr != nil {
						return nil, markErr
					}
					continue
				}
				return nil, err
			}
			continue

		case policyStateMaterializationErrorReceived:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
				return nil, fmt.Errorf("policy materialization failure audit: %w", err)
			}
			if _, err := d.policyJournal.finalizeNoMint(requestID); err != nil {
				return nil, err
			}
			continue

		case policyStateHostedTerminalUnexposed:
			if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
				return nil, fmt.Errorf("hosted policy terminal import audit: %w", err)
			}
			if _, err := d.policyJournal.finalizeNoMint(requestID); err != nil {
				return nil, err
			}
			continue
		default:
			return nil, fmt.Errorf("policy request %s has unsupported state %s", requestID, record.State)
		}
	}
}

func (d *Daemon) commitLocalPolicyApprovedUnderCustody(requestID string, record policyRequestRecord) (policyRequestRecord, error) {
	// Lock order is custody -> journal. No journal transaction acquires custody,
	// so RotateTo/Lock cannot race between this exact recheck and durable
	// head/result exposure and no reverse-order deadlock is introduced.
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()
	if err := d.verifyPolicyCustodyLocked(record); err != nil {
		return policyRequestRecord{}, err
	}
	if d.policyBeforeCommit != nil {
		d.policyBeforeCommit()
	}
	return d.policyJournal.commitApproved(requestID)
}

func (d *Daemon) commitLocalNoOpUnderCustody(ctx context.Context, requestID string, record policyRequestRecord) (policyRequestRecord, error) {
	if !record.NoOp || record.Mode != policyModeLocalTelegram {
		return policyRequestRecord{}, errPolicyConflict
	}
	d.custodyMu.RLock()
	defer d.custodyMu.RUnlock()
	if err := d.verifyPolicyCustodyLocked(record); err != nil {
		return policyRequestRecord{}, err
	}
	// No-op has no mint phase. Hold the same custody snapshot across its
	// result-bound terminal audit and durable head/response commit so rotation
	// cannot make an old-key envelope appear current between those boundaries.
	if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
		return policyRequestRecord{}, &policyNoOpAuditError{err: err}
	}
	if d.policyBeforeCommit != nil {
		d.policyBeforeCommit()
	}
	return d.policyJournal.commitApproved(requestID)
}

// verifyPolicyCustodyLocked requires custodyMu to be held for reading.
func (d *Daemon) verifyPolicyCustodyLocked(record policyRequestRecord) error {
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
	frozen, err := policyRequestPublicKey(&record)
	if err != nil {
		return err
	}
	if keyID != record.ExpectedSignerKeyID || !bytes.Equal(publicKey, frozen) {
		return ErrSignerKeyChanged
	}
	return nil
}

func (d *Daemon) requestPolicyDecision(ctx context.Context, record policyRequestRecord, backend BaseManifestApprovalBackend) (BaseManifestApprovalResult, error) {
	payload, err := policyRequestPayload(&record)
	if err != nil {
		return BaseManifestApprovalResult{}, err
	}
	publicKey, err := policyRequestPublicKey(&record)
	if err != nil {
		return BaseManifestApprovalResult{}, err
	}
	request := BaseManifestApprovalRequest{
		RequestID:           record.RequestID,
		HostKeyFP:           record.HostKeyFP,
		ExpectedSignerKeyID: record.ExpectedSignerKeyID,
		Payload:             append([]byte(nil), payload...),
		FrozenPublicKey:     append([]byte(nil), publicKey...),
		ExpectedHeadDigest:  record.ExpectedHeadDigest,
		Bootstrap:           record.Bootstrap,
		CallbackChallenge:   record.CallbackChallenge,
		Submitted:           time.Unix(0, record.SubmittedUnixNano),
	}
	if record.Mode == policyModeLocalTelegram {
		request.DecisionHooks = &localPolicyDecisionHooks{
			journal: d.policyJournal, requestID: record.RequestID, challenge: record.CallbackChallenge,
		}
	}
	resultCh, err := backend.RequestBaseManifest(ctx, request)
	if err != nil {
		return BaseManifestApprovalResult{}, err
	}
	if resultCh == nil {
		return BaseManifestApprovalResult{}, errors.New("policy backend returned nil result channel")
	}
	if record.Mode == policyModeHosted && record.State == policyStateNotifying {
		if _, err := d.policyJournal.activateHosted(record.RequestID); err != nil {
			return BaseManifestApprovalResult{}, err
		}
	}
	select {
	case result, ok := <-resultCh:
		if !ok {
			if record.Mode == policyModeHosted {
				return BaseManifestApprovalResult{}, errors.New("hosted policy result channel closed before terminal reconciliation")
			}
			timeout := BaseManifestApprovalResult{Status: policywire.StatusTimeout, Kind: BaseManifestResultLocalDecision}
			current, loadErr := d.policyJournal.record(record.RequestID)
			if loadErr != nil {
				return BaseManifestApprovalResult{}, loadErr
			}
			if current.State == policyStatePending {
				if _, err := d.policyJournal.commitLocalVerdict(record.RequestID, current.CallbackChallenge, timeout); err != nil {
					return BaseManifestApprovalResult{}, err
				}
			}
			return timeout, nil
		}
		return result, nil
	case <-ctx.Done():
		if record.Mode == policyModeHosted {
			return BaseManifestApprovalResult{}, ctx.Err()
		}
		timeout := BaseManifestApprovalResult{Status: policywire.StatusTimeout, Kind: BaseManifestResultLocalDecision}
		current, loadErr := d.policyJournal.record(record.RequestID)
		if loadErr != nil {
			return BaseManifestApprovalResult{}, loadErr
		}
		if current.State == policyStatePending {
			if _, err := d.policyJournal.commitLocalVerdict(record.RequestID, current.CallbackChallenge, timeout); err != nil {
				return BaseManifestApprovalResult{}, err
			}
		}
		return timeout, nil
	}
}

func (d *Daemon) stageHostedResult(requestID string, result BaseManifestApprovalResult) error {
	if result.Kind != BaseManifestResultRemoteEnvelope || result.ApprovedBy != "" || result.OperatorAuthMethod != "" {
		return errors.New("hosted policy backend returned wrong custody/result shape")
	}
	record, err := d.policyJournal.record(requestID)
	if err != nil {
		return err
	}
	response := policywire.Response{
		RequestID: record.RequestID, Purpose: policywire.Purpose, Status: result.Status,
		PayloadSHA256: record.PayloadSHA256, BaseDigest: record.BaseDigest, SignerKeyID: record.ExpectedSignerKeyID,
		ErrorCode: result.ErrorCode, Retryable: result.Retryable,
	}
	switch result.Status {
	case policywire.StatusApproved:
		if result.ErrorCode != "" || result.Retryable || len(result.ManifestEnvelope) == 0 {
			return errors.New("hosted approval carried invalid error/envelope fields")
		}
		response.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(result.ManifestEnvelope)
		if _, err := policywire.MarshalResponse(response); err != nil {
			return err
		}
		_, err = d.policyJournal.persistApprovedUnexposed(requestID, result.ManifestEnvelope)
		return err
	case policywire.StatusDenied, policywire.StatusTimeout, policywire.StatusInterrupted, policywire.StatusError:
		if len(result.ManifestEnvelope) != 0 {
			return errors.New("hosted non-approval carried envelope")
		}
		if _, err := policywire.MarshalResponse(response); err != nil {
			return err
		}
		_, err = d.policyJournal.stageHostedTerminal(requestID, response)
		return err
	default:
		return errors.New("hosted backend returned nonterminal/unknown status")
	}
}

func writePolicyResponse(w io.Writer, response policywire.Response) error {
	line, err := policywire.MarshalResponseLine(response)
	if err != nil {
		return err
	}
	n, err := w.Write(line)
	if err == nil && n != len(line) {
		return io.ErrShortWrite
	}
	return err
}

func (d *Daemon) respondPolicyJournalError(ctx context.Context, conn io.Writer, decoded policywire.DecodedRequest, err error) error {
	var protocolErr *policyJournalError
	if !errors.As(err, &protocolErr) || protocolErr.Code == "" {
		return err
	}
	return d.respondPolicyEphemeral(ctx, conn, decoded, protocolErr.Code)
}

func (d *Daemon) respondPolicyEphemeral(ctx context.Context, conn io.Writer, decoded policywire.DecodedRequest, code policywire.ErrorCode) error {
	record := ephemeralPolicyRecord(decoded, d.now())
	if d.policyJournal != nil {
		if trusted, err := d.policyJournal.trustedHeadDigest(decoded.Wire.HostKeyFP); err == nil {
			record.TrustedHeadDigest = trusted
		}
	}
	record.FailureCode = code
	if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseSubmission); err != nil {
		return fmt.Errorf("policy rejected submission audit: %w", err)
	}
	if err := d.emitPolicyAudit(ctx, record, policyAuditPhaseTerminalNoMint); err != nil {
		return fmt.Errorf("policy terminal rejection audit: %w", err)
	}
	response, err := buildPolicyResponse(&record, policywire.StatusError, code, nil)
	if err != nil {
		return err
	}
	return writePolicyResponse(conn, response)
}

func ephemeralPolicyRecord(decoded policywire.DecodedRequest, submitted time.Time) policyRequestRecord {
	payloadSHA, baseDigest, _ := policywire.PayloadDigests(decoded.Payload)
	record := policyRequestRecord{
		RequestID: decoded.Wire.RequestID, Purpose: policywire.Purpose, HostKeyFP: decoded.Wire.HostKeyFP,
		ExpectedSignerKeyID: decoded.Wire.ExpectedSignerKeyID, PayloadSHA256: payloadSHA, BaseDigest: baseDigest,
		ExpectedHeadDigest: decoded.Wire.ExpectedHeadDigest, Bootstrap: decoded.Wire.Bootstrap,
		Epoch: decoded.Manifest.Epoch, Revision: decoded.Manifest.Revision,
		MissAction: string(decoded.Manifest.MissAction), Growth: string(decoded.Manifest.Growth),
		EntryCount: len(decoded.Manifest.Entries), RevocationCount: len(decoded.Manifest.RevokedPermitIDs),
		SubmittedUnixNano: submitted.UnixNano(), Mode: policyModeLocalTelegram,
		State: policyStateReceivedUnaudited, StateVersion: 1,
	}
	record.TupleDigest = policyTupleDigestFields(record.RequestID, record.Purpose, record.HostKeyFP,
		record.ExpectedSignerKeyID, record.PayloadSHA256, record.ExpectedHeadDigest, record.Bootstrap)
	return record
}

func (d *Daemon) policyAuditSink() AuditSink {
	if d.policySink != nil {
		return d.policySink
	}
	if d.Audit != nil {
		return d.Audit
	}
	return nil
}

func (d *Daemon) emitPolicyAudit(ctx context.Context, record policyRequestRecord, phase string) error {
	sink := d.policyAuditSink()
	if sink == nil {
		return ErrNoAudit
	}
	metadata := policyAuditMetadata(record, phase)
	if phase == policyAuditPhaseHumanVerdict && record.ApprovedBy != "" {
		approved := record.State == policyStateApprovalReceived || record.State == policyStateApprovedMaterializing ||
			record.State == policyStateApprovedUnexposed || record.State == policyStateApproved
		return sink.Verdict(ctx, AuditVerdict{
			Time: d.now().UTC(), RequestID: record.RequestID,
			Operator: Operator{ID: record.ApprovedBy, DisplayName: record.ApprovedBy, Verified: true, AuthnMethod: record.OperatorAuthMethod},
			Approved: approved, Policy: &metadata,
		})
	}
	return sink.Call(ctx, AuditCall{Time: d.now().UTC(), RequestID: record.RequestID, HostKeyFP: record.HostKeyFP, Policy: &metadata})
}

func policyAuditMetadata(record policyRequestRecord, phase string) PolicyAuditMetadata {
	metadata := PolicyAuditMetadata{
		Purpose: policywire.Purpose, Principal: policyAuditPrincipalLocal, TupleDigest: record.TupleDigest,
		Phase: phase, StateVersion: record.StateVersion, RequestID: record.RequestID,
		HostKeyFP: record.HostKeyFP, PayloadSHA256: record.PayloadSHA256,
		CandidateDigest: record.BaseDigest, HeadDigest: record.TrustedHeadDigest,
		Epoch: record.Epoch, Revision: record.Revision, MissAction: record.MissAction, Growth: record.Growth,
		EntryCount: record.EntryCount, RevocationCount: record.RevocationCount,
		SignerKeyID: record.ExpectedSignerKeyID, ResultSHA256: record.ResultSHA256,
		Outcome: policyAuditOutcome(record, phase), ErrorCode: string(record.FailureCode), NoOp: record.NoOp,
		VerifiedOperator: record.ApprovedBy, OperatorAuthMethod: record.OperatorAuthMethod,
	}
	metadata.EventID = policyAuditEventID(metadata)
	return metadata
}

func policyAuditOutcome(record policyRequestRecord, phase string) string {
	switch phase {
	case policyAuditPhaseSubmission:
		return "received"
	case policyAuditPhaseMaterialization:
		if record.ResultEnvelopeB64 != "" {
			return "minted-unexposed"
		}
		return "attempt"
	case policyAuditPhaseHumanVerdict:
		switch record.State {
		case policyStateApprovalReceived:
			return "approved"
		case policyStateDenialReceived:
			return "denied"
		case policyStateTimeoutReceived:
			return "timeout"
		case policyStateInterruptionReceived:
			return "interrupted"
		}
	case policyAuditPhaseTerminalNoMint:
		if record.FailureCode != "" {
			return "error"
		}
		if record.NoOp {
			return "approved-no-op"
		}
		if record.Response != nil {
			return string(record.Response.Status)
		}
		switch record.State {
		case policyStateDenialReceived:
			return "denied"
		case policyStateTimeoutReceived:
			return "timeout"
		case policyStateInterruptionReceived:
			return "interrupted"
		default:
			return "error"
		}
	}
	return ""
}

func policyAuditEventID(metadata PolicyAuditMetadata) string {
	h := sha256.New()
	_, _ = h.Write([]byte("sshgate-policy-audit-event-v1\x00"))
	for _, field := range []string{metadata.Purpose, metadata.Principal, metadata.RequestID, metadata.TupleDigest, metadata.Phase} {
		writePolicyLengthField(h, []byte(field))
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], metadata.StateVersion)
	_, _ = h.Write(version[:])
	return hex.EncodeToString(h.Sum(nil))
}

func (d *Daemon) retryPolicyRecovery(ctx context.Context) error {
	d.policyRecoveryMu.Lock()
	defer d.policyRecoveryMu.Unlock()
	if d.policyJournal == nil {
		return nil
	}
	ids, err := d.policyJournal.recoverableRequestIDs()
	if err != nil {
		d.policyRecoveryErr = err
		return err
	}
	for _, requestID := range ids {
		wait, leader := d.acquirePolicyFlight(requestID)
		if !leader {
			// An already-serving caller owns this durable ID. It will either
			// finish the state transition or leave it recoverable for the next
			// pass; recovery must never race its audit/materialization path.
			continue
		}
		_, processErr := d.processPolicyRecord(ctx, requestID, nil)
		d.releasePolicyFlight(requestID, wait)
		if processErr != nil {
			d.policyRecoveryErr = processErr
			return processErr
		}
	}
	d.policyRecoveryErr = nil
	return nil
}

func (d *Daemon) initializePolicyRecovery(ctx context.Context) error {
	if d.policyJournal == nil {
		return nil
	}
	if _, err := d.policyJournal.reconcileLocalStartup(); err != nil {
		d.policyRecoveryErr = err
		return err
	}
	return d.retryPolicyRecovery(ctx)
}

func (d *Daemon) policyRecoveryStatus() error {
	d.policyRecoveryMu.Lock()
	defer d.policyRecoveryMu.Unlock()
	return d.policyRecoveryErr
}

var _ BaseManifestDecisionHooks = (*localPolicyDecisionHooks)(nil)

// Keep the exact public-key verification dependency explicit in this file;
// hosted envelopes are checked by persistApprovedUnexposed under the frozen
// key and local materialization is checked inside custody.go.
var _ = policy.VerifyBaseManifest
