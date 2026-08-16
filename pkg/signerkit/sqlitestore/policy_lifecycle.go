package sqlitestore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func (store *policyDB) Fenced(lease policystore.Lease) policystore.RecoveryStore {
	copy := lease
	return &policyDB{database: store.database, fence: &copy}
}

func (store *policyDB) MarkSubmissionAudited(ctx context.Context, key policystore.Key, version uint64) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateReceivedUnaudited || request.StateVersion != version {
			return policystore.ErrStaleVersion
		}
		request.SubmissionAudited = true
		return nil
	})
}

func (store *policyDB) MarkRejectionSubmissionAudited(ctx context.Context, key policystore.Key, version uint64) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateRejectionUnaudited || request.StateVersion != version {
			return policystore.ErrStaleVersion
		}
		request.SubmissionAudited = true
		return nil
	})
}

func (store *policyDB) ActivateSubmission(ctx context.Context, key policystore.Key, receivedVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateReceivedUnaudited || request.StateVersion != receivedVersion || !request.SubmissionAudited {
			return policystore.ErrStaleVersion
		}
		if request.NoOp {
			head, err := loadPolicyHead(ctx, transaction, request.AuthorityID, request.HostKeyFP)
			if err != nil {
				return err
			}
			payload, _, err := policy.DecodeBaseManifestEnvelope(head.ManifestEnvelope)
			if err != nil || !bytes.Equal(payload, request.Payload) {
				return fmt.Errorf("%w: no-op head changed", policystore.ErrStaleVersion)
			}
			request.State = policystore.StateNoOpUnexposed
			request.StateVersion++
			request.ResultEnvelope = slices.Clone(head.ManifestEnvelope)
			request.ResultSHA256 = digestBytes(head.ManifestEnvelope)
		} else {
			request.State = policystore.StatePending
		}
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) StageRejectionError(ctx context.Context, key policystore.Key, rejectionVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateRejectionUnaudited || request.StateVersion != rejectionVersion || !request.SubmissionAudited {
			return policystore.ErrStaleVersion
		}
		request.State = policystore.StateRejectionErrorReceived
		request.StateVersion++
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) PrepareVote(ctx context.Context, input policystore.VoteInput) (policystore.VoteResult, error) {
	if err := policystore.ValidateIdentity(input.Operator); err != nil {
		return policystore.VoteResult{}, err
	}
	if input.Decision != policystore.DecisionApprove && input.Decision != policystore.DecisionDeny {
		return policystore.VoteResult{}, errors.New("policy vote decision is invalid")
	}
	if input.AuthnMethod != policystore.AuthnSession && input.AuthnMethod != policystore.AuthnTOTP {
		return policystore.VoteResult{}, errors.New("policy vote authentication method is invalid")
	}
	return withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (policystore.VoteResult, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return policystore.VoteResult{}, err
		}
		request, err := loadPolicyRequestByReviewID(ctx, transaction, input.ReviewID)
		if err != nil {
			return policystore.VoteResult{}, err
		}
		if err := store.validateFence(request, input.Now); err != nil {
			return policystore.VoteResult{}, err
		}
		existing, err := loadPolicyVote(ctx, transaction, request.Key(), input.Operator)
		if err == nil {
			if request.State != policystore.StatePending {
				return policystore.VoteResult{}, policystore.ErrConflict
			}
			if existing.Decision == input.Decision {
				tally, tallyErr := policyTally(ctx, transaction, request)
				return policystore.VoteResult{Vote: existing, NeedsAudit: !existing.Audited, Tally: tally}, tallyErr
			}
			if !existing.Audited {
				return policystore.VoteResult{}, policystore.ErrUnavailable
			}
			return policystore.VoteResult{}, policystore.ErrVoteConflict
		}
		if !errors.Is(err, policystore.ErrNotFound) {
			return policystore.VoteResult{}, err
		}
		if request.State != policystore.StatePending || !request.SubmissionAudited {
			return policystore.VoteResult{}, policystore.ErrConflict
		}
		if err := validateFrozenVoter(ctx, transaction, meta, request, input.Operator, input.AuthnMethod); err != nil {
			return policystore.VoteResult{}, err
		}
		vote := &policystore.Vote{Principal: request.Principal, RequestID: request.RequestID, Operator: input.Operator,
			Decision: input.Decision, AuthnMethod: input.AuthnMethod, Timestamp: input.Now.UTC().Unix(),
			AuditStateVersion: request.StateVersion + 1, TupleDigest: request.TupleDigest, Purpose: request.Purpose,
			PayloadSHA256: request.PayloadSHA256, CandidateDigest: request.BaseDigest,
			HeadDigest: request.ExpectedHeadDigest, SignerKeyID: request.FrozenSignerKeyID.Value}
		if err := setPolicyVoteLogicalBytes(vote); err != nil {
			return policystore.VoteResult{}, err
		}
		if request.ReservedBytes < vote.LogicalBytes {
			return policystore.VoteResult{}, fmt.Errorf("%w: vote exceeded reservation", policystore.ErrCorrupt)
		}
		request.StateVersion++
		request.ReservedBytes -= vote.LogicalBytes
		request.UpdatedAt = input.Now.UTC().Unix()
		if err := updatePolicyRequest(ctx, transaction, request); err != nil {
			return policystore.VoteResult{}, err
		}
		if err := insertPolicyVote(ctx, transaction, vote); err != nil {
			return policystore.VoteResult{}, err
		}
		if err := finishPolicyMutation(ctx, transaction, meta); err != nil {
			return policystore.VoteResult{}, err
		}
		tally, err := policyTally(ctx, transaction, request)
		return policystore.VoteResult{Vote: vote, NeedsAudit: true, Tally: tally}, err
	})
}

func (store *policyDB) PublishVoteAudit(ctx context.Context, key policystore.Key, operator string, auditVersion uint64) (policystore.TallyResult, error) {
	if err := policystore.ValidateIdentity(operator); err != nil {
		return policystore.TallyResult{}, err
	}
	return withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (policystore.TallyResult, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return policystore.TallyResult{}, err
		}
		request, err := loadPolicyRequest(ctx, transaction, key)
		if err != nil {
			return policystore.TallyResult{}, err
		}
		if err := store.validateFence(request, time.Now()); err != nil {
			return policystore.TallyResult{}, err
		}
		vote, err := loadPolicyVote(ctx, transaction, key, operator)
		if err != nil {
			return policystore.TallyResult{}, err
		}
		if vote.AuditStateVersion != auditVersion {
			return policystore.TallyResult{}, policystore.ErrStaleVersion
		}
		if !vote.Audited {
			if _, err := transaction.ExecContext(ctx, `UPDATE policy_votes SET audited=1 WHERE principal=? AND request_id=? AND operator=? AND audited=0 AND audit_state_version=?`, key.Principal, key.RequestID, operator, policyInteger(auditVersion)); err != nil {
				return policystore.TallyResult{}, fmt.Errorf("publish policy vote audit: %w", err)
			}
		}
		if err := finishPolicyMutation(ctx, transaction, meta); err != nil {
			return policystore.TallyResult{}, err
		}
		return policyTally(ctx, transaction, request)
	})
}

func (store *policyDB) ClaimDenial(ctx context.Context, key policystore.Key, expectedVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StatePending || request.StateVersion != expectedVersion {
			return policystore.ErrStaleVersion
		}
		if err := requireNoUnauditedVotes(ctx, transaction, key); err != nil {
			return err
		}
		tally, err := policyTally(ctx, transaction, request)
		if err != nil {
			return err
		}
		if !tally.DenialReached {
			return policystore.ErrConflict
		}
		request.State = policystore.StateDenialReceived
		request.StateVersion++
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) ClaimApproval(ctx context.Context, key policystore.Key, expectedVersion uint64, workerID string, now time.Time, ttl time.Duration) (policystore.WorkLease, error) {
	if err := policystore.ValidateIdentity(workerID); err != nil {
		return policystore.WorkLease{}, err
	}
	if ttl <= 0 || ttl > time.Duration(policystore.RecoveryLeaseMaxTTLSeconds)*time.Second {
		return policystore.WorkLease{}, errors.New("policy work lease TTL is outside bounds")
	}
	request, err := store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StatePending || request.StateVersion != expectedVersion {
			return policystore.ErrStaleVersion
		}
		if err := requireNoUnauditedVotes(ctx, transaction, key); err != nil {
			return err
		}
		tally, err := policyTally(ctx, transaction, request)
		if err != nil {
			return err
		}
		if !tally.ApprovalReached || tally.DenialReached {
			return policystore.ErrConflict
		}
		head, headErr := loadPolicyHead(ctx, transaction, request.AuthorityID, request.HostKeyFP)
		if request.Bootstrap {
			if headErr == nil {
				return policystore.ErrStaleVersion
			}
			if !errors.Is(headErr, policystore.ErrNotFound) {
				return headErr
			}
		} else {
			if headErr != nil || !headMatchesTrusted(request, head) {
				return policystore.ErrStaleVersion
			}
			copyClaimedHead(request, head)
		}
		if request.RecoveryLeaseGeneration >= uint64(^uint64(0)>>1) {
			return fmt.Errorf("%w: recovery lease generation exhausted", policystore.ErrCorrupt)
		}
		request.State = policystore.StateApprovedMaterializing
		request.StateVersion++
		request.RecoveryLeaseOwner = workerID
		request.RecoveryLeaseUntil = now.Add(ttl).UTC().Unix()
		request.RecoveryLeaseGeneration++
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
	if err != nil {
		return policystore.WorkLease{}, err
	}
	return policystore.WorkLease{Lease: policystore.Lease{Key: key, Owner: workerID, Generation: request.RecoveryLeaseGeneration,
		Until: time.Unix(request.RecoveryLeaseUntil, 0).UTC()}, StateVersion: request.StateVersion}, nil
}

func (store *policyDB) MarkPreMintAudited(ctx context.Context, lease policystore.WorkLease) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, lease.Key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateApprovedMaterializing || request.StateVersion != lease.StateVersion || !leaseMatches(request, lease.Lease) {
			return policystore.ErrLeaseLost
		}
		request.PreMintAudited = true
		return nil
	})
}

func (store *policyDB) PersistMaterialized(ctx context.Context, lease policystore.WorkLease, envelope []byte, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, lease.Key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateApprovedMaterializing || request.StateVersion != lease.StateVersion || !leaseMatches(request, lease.Lease) || !request.PreMintAudited {
			return policystore.ErrLeaseLost
		}
		manifest, err := policy.VerifyBaseManifest(envelope, ed25519.PublicKey(request.FrozenSignerPublicKey))
		if err != nil {
			return fmt.Errorf("policy materialized envelope: %w", err)
		}
		payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
		if err != nil || !bytes.Equal(payload, request.Payload) || manifest.Host != request.HostKeyFP {
			return errors.New("policy materialized envelope does not match admitted payload")
		}
		request.ResultEnvelope = slices.Clone(envelope)
		request.ResultSHA256 = digestBytes(envelope)
		request.State = policystore.StateApprovedUnexposed
		request.StateVersion++
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) MarkResultAudited(ctx context.Context, key policystore.Key, unexposedVersion uint64) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateApprovedUnexposed || request.StateVersion != unexposedVersion {
			return policystore.ErrStaleVersion
		}
		request.ResultAudited = true
		return nil
	})
}

func (store *policyDB) MarkNoOpTerminalAudited(ctx context.Context, key policystore.Key, unexposedVersion uint64) (*policystore.Request, error) {
	return store.markTerminalAudited(ctx, key, policystore.StateNoOpUnexposed, unexposedVersion)
}

func (store *policyDB) MarkErrorTerminalAudited(ctx context.Context, key policystore.Key, errorVersion uint64) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateErrorReceived || request.StateVersion != errorVersion || request.ErrorFamily == policystore.ErrorFamilySemantic {
			return policystore.ErrStaleVersion
		}
		request.TerminalAudited = true
		return nil
	})
}

func (store *policyDB) MarkDenialTerminalAudited(ctx context.Context, key policystore.Key, denialVersion uint64) (*policystore.Request, error) {
	return store.markTerminalAudited(ctx, key, policystore.StateDenialReceived, denialVersion)
}

func (store *policyDB) MarkRejectionTerminalAudited(ctx context.Context, key policystore.Key, rejectionVersion uint64) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		matrix2A := request.State == policystore.StateRejectionErrorReceived && isMatrix2A(*request)
		matrix2B := request.State == policystore.StateErrorReceived && request.ErrorFamily == policystore.ErrorFamilySemantic && request.FailureCode == policywire.ErrorQuorumUnattainable
		if request.StateVersion != rejectionVersion || (!matrix2A && !matrix2B) {
			return policystore.ErrStaleVersion
		}
		request.TerminalAudited = true
		return nil
	})
}

func (store *policyDB) markTerminalAudited(ctx context.Context, key policystore.Key, state policystore.State, version uint64) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != state || request.StateVersion != version {
			return policystore.ErrStaleVersion
		}
		request.TerminalAudited = true
		return nil
	})
}

func (store *policyDB) PublishApproved(ctx context.Context, key policystore.Key, unexposedVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.publishApproved(ctx, key, unexposedVersion, now, false)
}

func (store *policyDB) PublishNoOp(ctx context.Context, key policystore.Key, unexposedVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.publishApproved(ctx, key, unexposedVersion, now, true)
}

func (store *policyDB) publishApproved(ctx context.Context, key policystore.Key, version uint64, now time.Time, noOp bool) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		wantState := policystore.StateApprovedUnexposed
		if noOp {
			wantState = policystore.StateNoOpUnexposed
		}
		if request.State != wantState || request.StateVersion != version || request.NoOp != noOp ||
			(noOp && !request.TerminalAudited) || (!noOp && !request.ResultAudited) {
			return policystore.ErrStaleVersion
		}
		if noOp {
			head, err := loadPolicyHead(ctx, transaction, request.AuthorityID, request.HostKeyFP)
			if err != nil || !headMatchesTrusted(request, head) || !bytes.Equal(request.ResultEnvelope, head.ManifestEnvelope) {
				return policystore.ErrStaleVersion
			}
		} else {
			head, trusted, err := materializedPolicyHead(request, now)
			if err != nil {
				return err
			}
			if err := upsertPolicyHead(ctx, transaction, head, request.Bootstrap, trusted); err != nil {
				return err
			}
		}
		body, err := terminalPolicyResponse(request, policywire.StatusApproved)
		if err != nil {
			return err
		}
		publishPolicyTerminal(request, policystore.StateApproved, body, 200, now)
		return nil
	})
}

func (store *policyDB) PublishDenied(ctx context.Context, key policystore.Key, denialVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.publishSimpleTerminal(ctx, key, policystore.StateDenialReceived, denialVersion, policystore.StateDenied, policywire.StatusDenied, 200, now)
}

func (store *policyDB) PublishError(ctx context.Context, key policystore.Key, errorVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateErrorReceived || request.StateVersion != errorVersion ||
			!request.TerminalAudited || request.ErrorFamily == policystore.ErrorFamilySemantic {
			return policystore.ErrStaleVersion
		}
		body, err := terminalPolicyResponse(request, policywire.StatusError)
		if err != nil {
			return err
		}
		httpStatus, err := policyErrorHTTP(request.FailureCode)
		if err != nil {
			return err
		}
		publishPolicyTerminal(request, policystore.StateError, body, httpStatus, now)
		return nil
	})
}

func (store *policyDB) PublishRejection(ctx context.Context, key policystore.Key, rejectionVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		matrix2A := request.State == policystore.StateRejectionErrorReceived && isMatrix2A(*request)
		matrix2B := request.State == policystore.StateErrorReceived && request.ErrorFamily == policystore.ErrorFamilySemantic && request.FailureCode == policywire.ErrorQuorumUnattainable
		if request.StateVersion != rejectionVersion || !request.TerminalAudited || (!matrix2A && !matrix2B) {
			return policystore.ErrStaleVersion
		}
		body, err := terminalPolicyResponse(request, policywire.StatusError)
		if err != nil {
			return err
		}
		httpStatus, err := policyErrorHTTP(request.FailureCode)
		if err != nil {
			return err
		}
		publishPolicyTerminal(request, policystore.StateError, body, httpStatus, now)
		return nil
	})
}

func (store *policyDB) publishSimpleTerminal(ctx context.Context, key policystore.Key, from policystore.State, version uint64,
	to policystore.State, status policywire.Status, httpStatus int, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if request.State != from || request.StateVersion != version || !request.TerminalAudited {
			return policystore.ErrStaleVersion
		}
		body, err := terminalPolicyResponse(request, status)
		if err != nil {
			return err
		}
		if status == policywire.StatusError {
			httpStatus, err = policyErrorHTTP(request.FailureCode)
			if err != nil {
				return err
			}
		}
		publishPolicyTerminal(request, to, body, httpStatus, now)
		return nil
	})
}

func (store *policyDB) StageIntakeKeyError(ctx context.Context, key policystore.Key, receivedVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.stagePolicyError(ctx, key, policystore.StateReceivedUnaudited, receivedVersion, policystore.ErrorFamilyProcessing, policywire.ErrorSignerKeyChanged, now, nil)
}

func (store *policyDB) StageMaterializationError(ctx context.Context, lease policystore.WorkLease, code policywire.ErrorCode, now time.Time) (*policystore.Request, error) {
	if code != policywire.ErrorSignerKeyChanged && code != policywire.ErrorStalePolicyHead && code != policywire.ErrorPolicyMaterializationFailed {
		return nil, errors.New("policy materialization error code is not allowed")
	}
	return store.mutatePolicyRequest(ctx, lease.Key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StateApprovedMaterializing || request.StateVersion != lease.StateVersion ||
			!leaseMatches(request, lease.Lease) || !request.SubmissionAudited || !request.PreMintAudited {
			return policystore.ErrLeaseLost
		}
		request.State = policystore.StateErrorReceived
		request.StateVersion++
		request.ErrorFamily = policystore.ErrorFamilyProcessing
		request.FailureCode = code
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) StageNoOpError(ctx context.Context, key policystore.Key, version uint64, code policywire.ErrorCode, now time.Time) (*policystore.Request, error) {
	return store.stagePublicationError(ctx, key, policystore.StateNoOpUnexposed, version, code, now)
}

func (store *policyDB) StagePublicationError(ctx context.Context, key policystore.Key, version uint64, code policywire.ErrorCode, now time.Time) (*policystore.Request, error) {
	return store.stagePublicationError(ctx, key, policystore.StateApprovedUnexposed, version, code, now)
}

func (store *policyDB) stagePublicationError(ctx context.Context, key policystore.Key, state policystore.State, version uint64, code policywire.ErrorCode, now time.Time) (*policystore.Request, error) {
	if code != policywire.ErrorSignerKeyChanged && code != policywire.ErrorStalePolicyHead {
		return nil, errors.New("policy publication error code is not allowed")
	}
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != state || request.StateVersion != version || !request.SubmissionAudited ||
			(state == policystore.StateApprovedUnexposed && !request.ResultAudited) ||
			(state == policystore.StateNoOpUnexposed && !request.TerminalAudited) {
			return policystore.ErrStaleVersion
		}
		request.State = policystore.StateErrorReceived
		request.StateVersion++
		request.ErrorFamily = policystore.ErrorFamilyPublication
		request.FailureCode = code
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) stagePolicyError(ctx context.Context, key policystore.Key, from policystore.State, version uint64,
	family policystore.ErrorFamily, code policywire.ErrorCode, now time.Time, lease *policystore.Lease) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != from || request.StateVersion != version || !request.SubmissionAudited {
			return policystore.ErrStaleVersion
		}
		if lease != nil && !leaseMatches(request, *lease) {
			return policystore.ErrLeaseLost
		}
		request.State = policystore.StateErrorReceived
		request.StateVersion++
		request.ErrorFamily = family
		request.FailureCode = code
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) StageQuorumUnattainable(ctx context.Context, key policystore.Key, expectedVersion uint64, now time.Time) (*policystore.Request, error) {
	return store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State != policystore.StatePending || request.StateVersion != expectedVersion || !request.SubmissionAudited {
			return policystore.ErrStaleVersion
		}
		if err := requireNoUnauditedVotes(ctx, transaction, key); err != nil {
			return err
		}
		attainable, err := policyCurrentlyAttainable(ctx, transaction, request)
		if err != nil {
			return err
		}
		if attainable {
			return policystore.ErrConflict
		}
		request.State = policystore.StateErrorReceived
		request.StateVersion++
		request.ErrorFamily = policystore.ErrorFamilySemantic
		request.FailureCode = policywire.ErrorQuorumUnattainable
		request.UpdatedAt = now.UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
}

func (store *policyDB) ReconcilePendingAttainability(ctx context.Context, authorityID string, now time.Time) (policystore.AttainabilityResult, error) {
	return withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (policystore.AttainabilityResult, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return policystore.AttainabilityResult{}, err
		}
		if authorityID != meta.AuthorityID {
			return policystore.AttainabilityResult{}, policystore.ErrAuthorityMismatch
		}
		rows, err := transaction.QueryContext(ctx, `SELECT principal,request_id FROM policy_requests WHERE authority_id=? AND storage_kind='full' AND state='pending' ORDER BY updated_at,principal,request_id LIMIT 257`, authorityID)
		if err != nil {
			return policystore.AttainabilityResult{}, err
		}
		var keys []policystore.Key
		for rows.Next() {
			var key policystore.Key
			if err := rows.Scan(&key.Principal, &key.RequestID); err != nil {
				rows.Close()
				return policystore.AttainabilityResult{}, err
			}
			keys = append(keys, key)
		}
		if err := rows.Close(); err != nil {
			return policystore.AttainabilityResult{}, err
		}
		if len(keys) > policystore.MaxActiveGlobal {
			return policystore.AttainabilityResult{}, fmt.Errorf("%w: pending rows exceed global bound", policystore.ErrCorrupt)
		}
		result := policystore.AttainabilityResult{}
		for _, key := range keys {
			if store.fence != nil && store.fence.Key != key {
				continue
			}
			request, err := loadPolicyRequest(ctx, transaction, key)
			if err != nil {
				return policystore.AttainabilityResult{}, err
			}
			if err := store.validateFence(request, now); err != nil {
				return policystore.AttainabilityResult{}, err
			}
			result.Examined = append(result.Examined, key)
			if err := requireNoUnauditedVotes(ctx, transaction, key); errors.Is(err, policystore.ErrUnauditedVote) {
				continue
			} else if err != nil {
				return policystore.AttainabilityResult{}, err
			}
			attainable, err := policyCurrentlyAttainable(ctx, transaction, request)
			if err != nil {
				return policystore.AttainabilityResult{}, err
			}
			if !attainable {
				request.State = policystore.StateErrorReceived
				request.StateVersion++
				request.ErrorFamily = policystore.ErrorFamilySemantic
				request.FailureCode = policywire.ErrorQuorumUnattainable
				request.UpdatedAt = now.UTC().Unix()
				if err := setExactPolicyReservation(ctx, transaction, request); err != nil {
					return policystore.AttainabilityResult{}, err
				}
				if err := updatePolicyRequest(ctx, transaction, request); err != nil {
					return policystore.AttainabilityResult{}, err
				}
				result.Unattainable = append(result.Unattainable, key)
			}
		}
		if err := finishPolicyMutation(ctx, transaction, meta); err != nil {
			return policystore.AttainabilityResult{}, err
		}
		return result, nil
	})
}

func (store *policyDB) mutatePolicyRequest(ctx context.Context, key policystore.Key,
	mutation func(context.Context, *sql.Tx, *policystore.Request) error) (*policystore.Request, error) {
	if err := validatePolicyKey(key); err != nil {
		return nil, err
	}
	return withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (*policystore.Request, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return nil, err
		}
		request, err := loadPolicyRequest(ctx, transaction, key)
		if err != nil {
			return nil, err
		}
		if err := store.validateFence(request, time.Now()); err != nil {
			return nil, err
		}
		if err := mutation(ctx, transaction, request); err != nil {
			return nil, err
		}
		if err := updatePolicyRequest(ctx, transaction, request); err != nil {
			return nil, err
		}
		if err := finishPolicyMutation(ctx, transaction, meta); err != nil {
			return nil, err
		}
		return request, nil
	})
}

func (store *policyDB) validateFence(request *policystore.Request, now time.Time) error {
	if store.fence == nil {
		return nil
	}
	if store.fence.Key != request.Key() || !leaseMatches(request, *store.fence) || request.RecoveryLeaseUntil <= now.UTC().Unix() {
		return policystore.ErrLeaseLost
	}
	return nil
}

func leaseMatches(request *policystore.Request, lease policystore.Lease) bool {
	return request.Key() == lease.Key && request.RecoveryLeaseOwner == lease.Owner && request.RecoveryLeaseGeneration == lease.Generation
}

func setExactPolicyReservation(ctx context.Context, queryer policyQueryer, request *policystore.Request) error {
	remaining, err := expectedRequestRemaining(ctx, queryer, request)
	if err != nil {
		return err
	}
	if remaining > request.ReservedBytes {
		return fmt.Errorf("%w: transition increased reservation from %d to %d", policystore.ErrCorrupt, request.ReservedBytes, remaining)
	}
	request.ReservedBytes = remaining
	return nil
}

func setPolicyVoteLogicalBytes(vote *policystore.Vote) error {
	vote.LogicalBytes = 0
	fields, err := policystore.VoteFields(*vote)
	if err != nil {
		return err
	}
	charge, err := policystore.VoteLogicalCharge(fields)
	if err != nil {
		return err
	}
	vote.LogicalBytes = charge
	return nil
}

func loadPolicyRequestByReviewID(ctx context.Context, queryer policyQueryer, reviewID string) (*policystore.Request, error) {
	row := queryer.QueryRowContext(ctx, "SELECT "+policyColumnNames(policystore.RequestColumns[:])+" FROM policy_requests WHERE review_id=?", reviewID)
	fields, err := scanPolicyFields(row, policystore.RequestColumns[:])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, policystore.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	request, err := policystore.RequestFromFields(fields)
	return &request, err
}

func validateFrozenVoter(ctx context.Context, queryer policyQueryer, meta policyMeta, request *policystore.Request, operator string, method policystore.AuthnMethod) error {
	var voters []string
	if err := json.Unmarshal(request.EligibleVotersJSON, &voters); err != nil || !slices.Contains(voters, operator) {
		return policystore.ErrUnavailable
	}
	if (request.VoteStepUpRequired && method != policystore.AuthnTOTP) || (!request.VoteStepUpRequired && method != policystore.AuthnSession) {
		return policystore.ErrUnavailable
	}
	var valid int
	query := `SELECT count(*) FROM users u WHERE u.id=? AND u.role=? AND EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id)`
	if !request.VoteStepUpRequired {
		query = `SELECT count(*) FROM users u WHERE u.id=? AND u.role=? AND (EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id) OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id))`
	}
	if err := queryer.QueryRowContext(ctx, query, operator, meta.PolicyVoterRole).Scan(&valid); err != nil {
		return err
	}
	if valid != 1 {
		return policystore.ErrUnavailable
	}
	return nil
}

func policyTally(ctx context.Context, queryer policyQueryer, request *policystore.Request) (policystore.TallyResult, error) {
	var approvals, denials, unaudited int
	if err := queryer.QueryRowContext(ctx, `SELECT coalesce(sum(CASE WHEN audited=1 AND decision='approve' THEN 1 ELSE 0 END),0),coalesce(sum(CASE WHEN audited=1 AND decision='deny' THEN 1 ELSE 0 END),0),coalesce(sum(CASE WHEN audited=0 THEN 1 ELSE 0 END),0) FROM policy_votes WHERE principal=? AND request_id=?`, request.Principal, request.RequestID).Scan(&approvals, &denials, &unaudited); err != nil {
		return policystore.TallyResult{}, err
	}
	eligible := int(request.EligibleVoterCount.Value)
	tally := policystore.TallyResult{Approvals: approvals, Denials: denials, Unaudited: unaudited,
		Required: int(request.RequiredApprovals), Eligible: eligible}
	tally.ApprovalReached = approvals >= tally.Required
	tally.DenialReached = (request.DenyVeto && denials > 0) || approvals+(eligible-approvals-denials-unaudited) < tally.Required
	return tally, nil
}

func requireNoUnauditedVotes(ctx context.Context, queryer policyQueryer, key policystore.Key) error {
	var count int
	if err := queryer.QueryRowContext(ctx, `SELECT count(*) FROM policy_votes WHERE principal=? AND request_id=? AND audited=0`, key.Principal, key.RequestID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return policystore.ErrUnauditedVote
	}
	return nil
}

func copyClaimedHead(request *policystore.Request, head *policystore.Head) {
	request.ClaimedHeadEnvelope = slices.Clone(head.ManifestEnvelope)
	request.ClaimedHeadDigest = policystore.NullableString{Value: head.BaseDigest, Valid: true}
	request.ClaimedHeadKeyID = policystore.NullableString{Value: head.SignerKeyID, Valid: true}
	request.ClaimedHeadPublicKey = slices.Clone(head.SignerPublicKey)
	request.ClaimedHeadEpochBE = slices.Clone(head.EpochBE)
	request.ClaimedHeadRevisionBE = slices.Clone(head.RevisionBE)
	request.ClaimedHeadRowVersion = policystore.NullableInt64{Value: int64(head.RowVersion), Valid: true}
}

func headMatchesTrusted(request *policystore.Request, head *policystore.Head) bool {
	if head == nil || !request.TrustedHeadDigest.Valid || !request.TrustedHeadKeyID.Valid || !request.TrustedHeadRowVersion.Valid {
		return false
	}
	return bytes.Equal(head.ManifestEnvelope, request.TrustedHeadEnvelope) && head.BaseDigest == request.TrustedHeadDigest.Value &&
		head.SignerKeyID == request.TrustedHeadKeyID.Value && bytes.Equal(head.SignerPublicKey, request.TrustedHeadPublicKey) &&
		bytes.Equal(head.EpochBE, request.TrustedHeadEpochBE) && bytes.Equal(head.RevisionBE, request.TrustedHeadRevisionBE) &&
		head.RowVersion == uint64(request.TrustedHeadRowVersion.Value)
}

func materializedPolicyHead(request *policystore.Request, now time.Time) (*policystore.Head, *policystore.Head, error) {
	trusted, err := trustedHeadFromRequest(request)
	if err != nil {
		return nil, nil, err
	}
	if !request.Bootstrap {
		if !request.ClaimedHeadDigest.Valid || !headMatchesTrusted(request, &policystore.Head{
			ManifestEnvelope: request.ClaimedHeadEnvelope, BaseDigest: request.ClaimedHeadDigest.Value,
			SignerKeyID: request.ClaimedHeadKeyID.Value, SignerPublicKey: request.ClaimedHeadPublicKey,
			EpochBE: request.ClaimedHeadEpochBE, RevisionBE: request.ClaimedHeadRevisionBE,
			RowVersion: uint64(request.ClaimedHeadRowVersion.Value)}) {
			return nil, nil, fmt.Errorf("%w: claimed predecessor differs", policystore.ErrCorrupt)
		}
	}
	head := &policystore.Head{AuthoritySingleton: 1, AuthorityID: request.AuthorityID, HostKeyFP: request.HostKeyFP,
		ManifestEnvelope: slices.Clone(request.ResultEnvelope), PayloadSHA256: request.PayloadSHA256, BaseDigest: request.BaseDigest,
		EpochBE: slices.Clone(request.EpochBE), RevisionBE: slices.Clone(request.RevisionBE), SignerKeyID: request.FrozenSignerKeyID.Value,
		SignerPublicKey: slices.Clone(request.FrozenSignerPublicKey), RowVersion: candidateRowVersion(trusted), UpdatedAt: now.UTC().Unix()}
	return head, trusted, nil
}

func terminalPolicyResponse(request *policystore.Request, status policywire.Status) ([]byte, error) {
	response := policywire.Response{RequestID: request.RequestID, AuthorityID: request.AuthorityID, Purpose: request.Purpose,
		Status: status, PayloadSHA256: request.PayloadSHA256, BaseDigest: request.BaseDigest, SignerKeyID: request.FrozenSignerKeyID.Value}
	if status == policywire.StatusApproved {
		response.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(request.ResultEnvelope)
	}
	if status == policywire.StatusError {
		response.ErrorCode = request.FailureCode
		response.Retryable = request.FailureCode == policywire.ErrorPolicyMaterializationFailed
	}
	return policywire.MarshalResponse(response)
}

func publishPolicyTerminal(request *policystore.Request, state policystore.State, body []byte, status int, now time.Time) {
	request.State = state
	request.TerminalResponse = slices.Clone(body)
	request.TerminalHTTPStatus = policystore.NullableInt64{Value: int64(status), Valid: true}
	request.ResolvedAt = policystore.NullableInt64{Value: now.UTC().Unix(), Valid: true}
	request.UpdatedAt = now.UTC().Unix()
	request.ReservedBytes = rejectionFloor(request)
	request.RecoveryLeaseOwner = ""
	request.RecoveryLeaseUntil = 0
}

func policyErrorHTTP(code policywire.ErrorCode) (int, error) {
	switch code {
	case policywire.ErrorInvalidPolicyRequest:
		return 400, nil
	case policywire.ErrorPolicyRequestInProgress, policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead,
		policywire.ErrorPolicyKeyTransitionRequired, policywire.ErrorQuorumUnattainable:
		return 409, nil
	case policywire.ErrorPolicyMaterializationFailed:
		return 500, nil
	default:
		return 0, errors.New("policy durable error has no HTTP mapping")
	}
}

func policyCurrentlyAttainable(ctx context.Context, queryer policyQueryer, request *policystore.Request) (bool, error) {
	var voters []string
	if err := json.Unmarshal(request.EligibleVotersJSON, &voters); err != nil {
		return false, fmt.Errorf("%w: frozen voter JSON", policystore.ErrCorrupt)
	}
	tally, err := policyTally(ctx, queryer, request)
	if err != nil {
		return false, err
	}
	possible := tally.Approvals
	for _, voter := range voters {
		var voted int
		if err := queryer.QueryRowContext(ctx, `SELECT count(*) FROM policy_votes WHERE principal=? AND request_id=? AND operator=?`, request.Principal, request.RequestID, voter).Scan(&voted); err != nil {
			return false, err
		}
		if voted != 0 {
			continue
		}
		var eligible int
		query := `SELECT count(*) FROM users u WHERE u.id=? AND u.role='operator' AND EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id)`
		if !request.VoteStepUpRequired {
			query = `SELECT count(*) FROM users u WHERE u.id=? AND u.role='operator' AND (EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id) OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id))`
		}
		if err := queryer.QueryRowContext(ctx, query, voter).Scan(&eligible); err != nil {
			return false, err
		}
		possible += eligible
	}
	return possible >= int(request.RequiredApprovals), nil
}
