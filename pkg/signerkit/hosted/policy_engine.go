package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	policyAuditPhaseSubmission      = "submission"
	policyAuditPhaseHumanVerdict    = "human-verdict"
	policyAuditPhaseMaterialization = "materialization"
	policyAuditPhaseTerminalNoMint  = "terminal-no-mint"
	policyRecoveryLeaseTTL          = 120 * time.Second
)

var ErrPolicyUnavailable = errors.New("hosted policy is not ready")

// PolicyCustody is the complete signer surface reachable by the policy engine.
// Every state-changing callback runs custody -> policy-store, never the reverse.
type PolicyCustody interface {
	SnapshotBaseManifestSigner() (ed25519.PublicKey, string, error)
	WithBaseManifestSignerIfCurrent(string, ed25519.PublicKey, func() error) error
	MaterializeBaseManifestContext(context.Context, string, string, []byte) (signerkit.BaseManifestMaterialization, error)
}

// PolicyFaultPoint names a crash boundary. Hooks run only after the named
// boundary has succeeded, so every injected failure represents an uncertain
// caller outcome over already-durable work.
type PolicyFaultPoint string

const (
	PolicyFaultAfterSubmissionAudit        PolicyFaultPoint = "after-submission-audit"
	PolicyFaultAfterSubmissionAcknowledged PolicyFaultPoint = "after-submission-acknowledged"
	PolicyFaultAfterSubmissionActivated    PolicyFaultPoint = "after-submission-activated"
	PolicyFaultAfterRejectionStaged        PolicyFaultPoint = "after-rejection-staged"
	PolicyFaultAfterVotePrepared           PolicyFaultPoint = "after-vote-prepared"
	PolicyFaultAfterVoteAudit              PolicyFaultPoint = "after-vote-audit"
	PolicyFaultAfterVoteAcknowledged       PolicyFaultPoint = "after-vote-acknowledged"
	PolicyFaultAfterDenialClaimed          PolicyFaultPoint = "after-denial-claimed"
	PolicyFaultAfterApprovalClaimed        PolicyFaultPoint = "after-approval-claimed"
	PolicyFaultAfterPreMintAudit           PolicyFaultPoint = "after-pre-mint-audit"
	PolicyFaultAfterPreMintAcknowledged    PolicyFaultPoint = "after-pre-mint-acknowledged"
	PolicyFaultAfterMint                   PolicyFaultPoint = "after-mint"
	PolicyFaultAfterMaterializedPersisted  PolicyFaultPoint = "after-materialized-persisted"
	PolicyFaultAfterResultAudit            PolicyFaultPoint = "after-result-audit"
	PolicyFaultAfterResultAcknowledged     PolicyFaultPoint = "after-result-acknowledged"
	PolicyFaultAfterNoMintAudit            PolicyFaultPoint = "after-no-mint-audit"
	PolicyFaultAfterNoMintAcknowledged     PolicyFaultPoint = "after-no-mint-acknowledged"
	PolicyFaultAfterErrorStaged            PolicyFaultPoint = "after-error-staged"
	PolicyFaultAfterFinalCAS               PolicyFaultPoint = "after-final-cas"
)

// AllPolicyFaultPoints is the exhaustive Phase-C boundary matrix.
var AllPolicyFaultPoints = [...]PolicyFaultPoint{
	PolicyFaultAfterSubmissionAudit,
	PolicyFaultAfterSubmissionAcknowledged,
	PolicyFaultAfterSubmissionActivated,
	PolicyFaultAfterRejectionStaged,
	PolicyFaultAfterVotePrepared,
	PolicyFaultAfterVoteAudit,
	PolicyFaultAfterVoteAcknowledged,
	PolicyFaultAfterDenialClaimed,
	PolicyFaultAfterApprovalClaimed,
	PolicyFaultAfterPreMintAudit,
	PolicyFaultAfterPreMintAcknowledged,
	PolicyFaultAfterMint,
	PolicyFaultAfterMaterializedPersisted,
	PolicyFaultAfterResultAudit,
	PolicyFaultAfterResultAcknowledged,
	PolicyFaultAfterNoMintAudit,
	PolicyFaultAfterNoMintAcknowledged,
	PolicyFaultAfterErrorStaged,
	PolicyFaultAfterFinalCAS,
}

// PolicyReadiness is independent from ordinary /v1 availability. A durable
// audit failure is sticky for the policy plane.
type PolicyReadiness struct {
	mu    sync.RWMutex
	ready bool
	err   error
	audit signerkit.DurableAuditSink
}

func newPolicyReadiness(audit signerkit.DurableAuditSink) *PolicyReadiness {
	return &PolicyReadiness{audit: audit}
}

func (readiness *PolicyReadiness) SetReady(ctx context.Context) error {
	if readiness == nil || readiness.audit == nil {
		return ErrPolicyUnavailable
	}
	if err := readiness.audit.PolicyAuditReady(ctx); err != nil {
		readiness.Fail(err)
		return err
	}
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	if readiness.err != nil {
		return readiness.err
	}
	readiness.ready = true
	return nil
}

func (readiness *PolicyReadiness) Fail(err error) {
	if readiness == nil {
		return
	}
	if err == nil {
		err = ErrPolicyUnavailable
	}
	readiness.mu.Lock()
	readiness.ready = false
	if readiness.err == nil {
		readiness.err = err
	}
	readiness.mu.Unlock()
}

func (readiness *PolicyReadiness) MarkUnready() {
	if readiness == nil {
		return
	}
	readiness.mu.Lock()
	readiness.ready = false
	readiness.mu.Unlock()
}

func (readiness *PolicyReadiness) Check(ctx context.Context) error {
	if readiness == nil {
		return ErrPolicyUnavailable
	}
	readiness.mu.RLock()
	ready, sticky := readiness.ready, readiness.err
	readiness.mu.RUnlock()
	if !ready {
		if sticky != nil {
			return sticky
		}
		return ErrPolicyUnavailable
	}
	if err := readiness.audit.PolicyAuditReady(ctx); err != nil {
		readiness.Fail(err)
		return err
	}
	return nil
}

func (readiness *PolicyReadiness) Ready() bool {
	if readiness == nil {
		return false
	}
	readiness.mu.RLock()
	defer readiness.mu.RUnlock()
	return readiness.ready && readiness.err == nil
}

type PolicyEngineConfig struct {
	AuthorityID string
	WorkerID    string
	Store       policystore.Store
	Core        PolicyCustody
	Audit       signerkit.DurableAuditSink
	Now         func() time.Time
	Fault       func(PolicyFaultPoint) error
	Sleep       func(context.Context, time.Duration) error
	Jitter      func(time.Duration) time.Duration
}

// PolicyEngine owns durable event acknowledgement and every transition after
// Begin/PrepareVote. Store CASes remain the correctness boundary.
type PolicyEngine struct {
	authorityID string
	workerID    string
	store       policystore.Store
	core        PolicyCustody
	audit       signerkit.DurableAuditSink
	readiness   *PolicyReadiness
	now         func() time.Time
	fault       func(PolicyFaultPoint) error
	sleep       func(context.Context, time.Duration) error
	jitter      func(time.Duration) time.Duration
}

func NewPolicyEngine(config PolicyEngineConfig) (*PolicyEngine, error) {
	if !policyauthority.ValidAuthorityID(config.AuthorityID) {
		return nil, errors.New("hosted policy engine: invalid authority ID")
	}
	if config.Store == nil {
		return nil, errors.New("hosted policy engine: store is required")
	}
	if config.Core == nil {
		return nil, errors.New("hosted policy engine: custody core is required")
	}
	if config.Audit == nil {
		return nil, errors.New("hosted policy engine: durable audit is required")
	}
	if err := policystore.ValidateIdentity(config.WorkerID); err != nil {
		return nil, fmt.Errorf("hosted policy engine: worker ID: %w", err)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	sleep := config.Sleep
	if sleep == nil {
		sleep = sleepPolicyContext
	}
	jitter := config.Jitter
	if jitter == nil {
		jitter = func(delay time.Duration) time.Duration {
			// A process-local clock sample supplies bounded non-security jitter.
			spread := delay / 4
			if spread == 0 {
				return delay
			}
			return delay - spread + time.Duration(time.Now().UnixNano()%int64(2*spread+1))
		}
	}
	return &PolicyEngine{
		authorityID: config.AuthorityID,
		workerID:    config.WorkerID,
		store:       config.Store,
		core:        config.Core,
		audit:       config.Audit,
		readiness:   newPolicyReadiness(config.Audit),
		now:         now,
		fault:       config.Fault,
		sleep:       sleep,
		jitter:      jitter,
	}, nil
}

func (engine *PolicyEngine) Readiness() *PolicyReadiness { return engine.readiness }

func (engine *PolicyEngine) faultAfter(point PolicyFaultPoint) error {
	if engine.fault == nil {
		return nil
	}
	return engine.fault(point)
}

// Submit persists a new policy request and drives only its deterministic
// post-Begin lifecycle. HTTP response-class freezing remains handler-owned.
func (engine *PolicyEngine) Submit(ctx context.Context, input policystore.BeginInput) (policystore.BeginResult, error) {
	result, err := engine.store.Begin(ctx, input)
	if err != nil || result.Request == nil {
		return result, err
	}
	if err := engine.advance(ctx, result.Request, engine.store, false); err != nil {
		return result, err
	}
	return result, nil
}

// Vote durably audits the frozen vote before it may influence a claim.
func (engine *PolicyEngine) Vote(ctx context.Context, input policystore.VoteInput) (policystore.VoteResult, error) {
	result, err := engine.store.PrepareVote(ctx, input)
	if err != nil {
		return result, err
	}
	if err := engine.faultAfter(PolicyFaultAfterVotePrepared); err != nil {
		return result, err
	}
	request, err := engine.store.GetByReviewID(ctx, input.ReviewID)
	if err != nil {
		return result, err
	}
	if result.NeedsAudit {
		if result.Vote == nil {
			return result, fmt.Errorf("%w: prepared vote is absent", policystore.ErrCorrupt)
		}
		if err := engine.emitVote(ctx, request, result.Vote); err != nil {
			return result, err
		}
		if err := engine.faultAfter(PolicyFaultAfterVoteAudit); err != nil {
			return result, err
		}
		result.Tally, err = engine.store.PublishVoteAudit(ctx, result.Vote.Key(), result.Vote.Operator, result.Vote.AuditStateVersion)
		if err != nil {
			return result, err
		}
		if err := engine.faultAfter(PolicyFaultAfterVoteAcknowledged); err != nil {
			return result, err
		}
	}
	request, err = engine.store.GetByReviewID(ctx, input.ReviewID)
	if err != nil {
		return result, err
	}
	if err := engine.claimTally(ctx, request, result.Tally, engine.store, false); err != nil {
		return result, err
	}
	return result, nil
}

func (engine *PolicyEngine) claimTally(ctx context.Context, request *policystore.Request, tally policystore.TallyResult, operations policystore.RecoveryStore, recovery bool) error {
	if tally.Unaudited != 0 || (!tally.ApprovalReached && !tally.DenialReached) {
		return nil
	}
	if tally.DenialReached {
		claimed, err := operations.ClaimDenial(ctx, request.Key(), request.StateVersion, engine.now().UTC())
		if err != nil {
			return err
		}
		if err := engine.faultAfter(PolicyFaultAfterDenialClaimed); err != nil {
			return err
		}
		return engine.advance(ctx, claimed, operations, recovery)
	}
	if !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: approved request has incomplete custody pair", policystore.ErrCorrupt)
	}
	var lease policystore.WorkLease
	err := engine.core.WithBaseManifestSignerIfCurrent(request.FrozenSignerKeyID.Value, ed25519.PublicKey(request.FrozenSignerPublicKey), func() error {
		var claimErr error
		lease, claimErr = operations.ClaimApproval(ctx, request.Key(), request.StateVersion, engine.workerID, engine.now().UTC(), policyRecoveryLeaseTTL)
		return claimErr
	})
	if err != nil {
		return err
	}
	if err := engine.faultAfter(PolicyFaultAfterApprovalClaimed); err != nil {
		return err
	}
	claimed := *request
	claimed.State = policystore.StateApprovedMaterializing
	claimed.StateVersion = lease.StateVersion
	claimed.RecoveryLeaseOwner = lease.Owner
	claimed.RecoveryLeaseGeneration = lease.Generation
	claimed.RecoveryLeaseUntil = lease.Until.Unix()
	if !claimed.Bootstrap {
		fresh, fetchErr := engine.store.GetByReviewID(ctx, request.ReviewID)
		if fetchErr != nil {
			return fetchErr
		}
		claimed = *fresh
	}
	if recovery {
		operations = engine.store.Fenced(lease.Lease)
	}
	return engine.advance(ctx, &claimed, operations, recovery)
}

func (engine *PolicyEngine) advance(ctx context.Context, request *policystore.Request, operations policystore.RecoveryStore, recoveryAttempt bool) error {
	for steps := 0; request != nil && steps < 24; steps++ {
		now := engine.now().UTC()
		switch request.State {
		case policystore.StateReceivedUnaudited:
			if !request.SubmissionAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseSubmission, "received"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterSubmissionAudit); err != nil {
					return err
				}
				updated, err := operations.MarkSubmissionAudited(ctx, request.Key(), request.StateVersion)
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterSubmissionAcknowledged); err != nil {
					return err
				}
			}
			if !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: accepted request has incomplete custody pair", policystore.ErrCorrupt)
			}
			var updated *policystore.Request
			err := engine.core.WithBaseManifestSignerIfCurrent(request.FrozenSignerKeyID.Value, ed25519.PublicKey(request.FrozenSignerPublicKey), func() error {
				var activateErr error
				updated, activateErr = operations.ActivateSubmission(ctx, request.Key(), request.StateVersion, now)
				return activateErr
			})
			if errors.Is(err, signerkit.ErrSignerKeyChanged) {
				updated, err = operations.StageIntakeKeyError(ctx, request.Key(), request.StateVersion, now)
				if err == nil {
					err = engine.faultAfter(PolicyFaultAfterErrorStaged)
				}
			}
			if err != nil {
				return err
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterSubmissionActivated); err != nil {
				return err
			}

		case policystore.StateRejectionUnaudited:
			if !request.SubmissionAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseSubmission, "received"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterSubmissionAudit); err != nil {
					return err
				}
				updated, err := operations.MarkRejectionSubmissionAudited(ctx, request.Key(), request.StateVersion)
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterSubmissionAcknowledged); err != nil {
					return err
				}
			}
			updated, err := operations.StageRejectionError(ctx, request.Key(), request.StateVersion, now)
			if err != nil {
				return err
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterRejectionStaged); err != nil {
				return err
			}

		case policystore.StateRejectionErrorReceived:
			if !request.TerminalAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseTerminalNoMint, "error"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterNoMintAudit); err != nil {
					return err
				}
				updated, err := operations.MarkRejectionTerminalAudited(ctx, request.Key(), request.StateVersion)
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterNoMintAcknowledged); err != nil {
					return err
				}
			}
			updated, err := operations.PublishRejection(ctx, request.Key(), request.StateVersion, now)
			if err != nil {
				return err
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterFinalCAS); err != nil {
				return err
			}

		case policystore.StatePending:
			return nil

		case policystore.StateApprovedMaterializing:
			lease := requestWorkLease(request)
			if !request.PreMintAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseMaterialization, "attempt"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterPreMintAudit); err != nil {
					return err
				}
				updated, err := operations.MarkPreMintAudited(ctx, lease)
				if err != nil {
					return err
				}
				request = updated
				lease = requestWorkLease(request)
				if err := engine.faultAfter(PolicyFaultAfterPreMintAcknowledged); err != nil {
					return err
				}
			}
			materialized, err := engine.core.MaterializeBaseManifestContext(ctx, request.FrozenSignerKeyID.Value, request.HostKeyFP, request.Payload)
			if err != nil {
				if recoveryAttempt && !errors.Is(err, signerkit.ErrSignerKeyChanged) {
					return &policyMintAttemptError{cause: err}
				}
				code := policywire.ErrorPolicyMaterializationFailed
				if errors.Is(err, signerkit.ErrSignerKeyChanged) {
					code = policywire.ErrorSignerKeyChanged
				}
				updated, stageErr := operations.StageMaterializationError(ctx, lease, code, now)
				if stageErr != nil {
					return errors.Join(err, stageErr)
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				continue
			}
			if err := engine.faultAfter(PolicyFaultAfterMint); err != nil {
				return err
			}
			if materialized.SignerKeyID != request.FrozenSignerKeyID.Value || !bytes.Equal(materialized.PublicKey, request.FrozenSignerPublicKey) {
				updated, stageErr := operations.StageMaterializationError(ctx, lease, policywire.ErrorSignerKeyChanged, now)
				if stageErr != nil {
					return stageErr
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				continue
			}
			if err := verifyMaterializedPolicyResult(request, materialized.Envelope); err != nil {
				updated, stageErr := operations.StageMaterializationError(ctx, lease, policywire.ErrorPolicyMaterializationFailed, now)
				if stageErr != nil {
					return errors.Join(err, stageErr)
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				if recoveryAttempt {
					if request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
						return fmt.Errorf("%w: materialization exhaustion retained recovery lease", policystore.ErrCorrupt)
					}
					return nil
				}
				continue
			}
			updated, err := operations.PersistMaterialized(ctx, lease, materialized.Envelope, now)
			if err != nil {
				return err
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterMaterializedPersisted); err != nil {
				return err
			}

		case policystore.StateApprovedUnexposed:
			if err := verifyPersistedPolicyResult(request); err != nil {
				updated, stageErr := operations.StagePublicationError(ctx, request.Key(), request.StateVersion, policywire.ErrorSignerKeyChanged, now)
				if stageErr != nil {
					return errors.Join(err, stageErr)
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				continue
			}
			currentPublic, currentID, err := engine.core.SnapshotBaseManifestSigner()
			if err != nil {
				return err
			}
			keyChanged := currentID != request.FrozenSignerKeyID.Value || !bytes.Equal(currentPublic, request.FrozenSignerPublicKey)
			if !request.ResultAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseMaterialization, "minted-unexposed"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterResultAudit); err != nil {
					return err
				}
				updated, err := operations.MarkResultAudited(ctx, request.Key(), request.StateVersion)
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterResultAcknowledged); err != nil {
					return err
				}
			}
			if keyChanged {
				updated, stageErr := operations.StagePublicationError(ctx, request.Key(), request.StateVersion, policywire.ErrorSignerKeyChanged, now)
				if stageErr != nil {
					return stageErr
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				continue
			}
			var updated *policystore.Request
			err = engine.core.WithBaseManifestSignerIfCurrent(currentID, currentPublic, func() error {
				var publishErr error
				updated, publishErr = operations.PublishApproved(ctx, request.Key(), request.StateVersion, now)
				return publishErr
			})
			if err != nil {
				code := policywire.ErrorStalePolicyHead
				if errors.Is(err, signerkit.ErrSignerKeyChanged) {
					code = policywire.ErrorSignerKeyChanged
				} else if !errors.Is(err, policystore.ErrStaleVersion) {
					return err
				}
				updated, err = operations.StagePublicationError(ctx, request.Key(), request.StateVersion, code, now)
				if errors.Is(err, policystore.ErrStaleVersion) {
					return nil
				}
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				continue
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterFinalCAS); err != nil {
				return err
			}

		case policystore.StateNoOpUnexposed:
			if !request.TerminalAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseTerminalNoMint, "approved-no-op"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterNoMintAudit); err != nil {
					return err
				}
				updated, err := operations.MarkNoOpTerminalAudited(ctx, request.Key(), request.StateVersion)
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterNoMintAcknowledged); err != nil {
					return err
				}
			}
			var updated *policystore.Request
			err := engine.core.WithBaseManifestSignerIfCurrent(request.FrozenSignerKeyID.Value, ed25519.PublicKey(request.FrozenSignerPublicKey), func() error {
				var publishErr error
				updated, publishErr = operations.PublishNoOp(ctx, request.Key(), request.StateVersion, now)
				return publishErr
			})
			if err != nil {
				code := policywire.ErrorStalePolicyHead
				if errors.Is(err, signerkit.ErrSignerKeyChanged) {
					code = policywire.ErrorSignerKeyChanged
				} else if !errors.Is(err, policystore.ErrStaleVersion) {
					return err
				}
				updated, err = operations.StageNoOpError(ctx, request.Key(), request.StateVersion, code, now)
				if errors.Is(err, policystore.ErrStaleVersion) {
					return nil
				}
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterErrorStaged); err != nil {
					return err
				}
				continue
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterFinalCAS); err != nil {
				return err
			}

		case policystore.StateDenialReceived:
			if !request.TerminalAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseTerminalNoMint, "denied"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterNoMintAudit); err != nil {
					return err
				}
				updated, err := operations.MarkDenialTerminalAudited(ctx, request.Key(), request.StateVersion)
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterNoMintAcknowledged); err != nil {
					return err
				}
			}
			updated, err := operations.PublishDenied(ctx, request.Key(), request.StateVersion, now)
			if err != nil {
				return err
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterFinalCAS); err != nil {
				return err
			}

		case policystore.StateErrorReceived:
			if !request.TerminalAudited {
				if err := engine.emitCall(ctx, request, policyAuditPhaseTerminalNoMint, "error"); err != nil {
					return err
				}
				if err := engine.faultAfter(PolicyFaultAfterNoMintAudit); err != nil {
					return err
				}
				var updated *policystore.Request
				var err error
				if request.ErrorFamily == policystore.ErrorFamilySemantic {
					updated, err = operations.MarkRejectionTerminalAudited(ctx, request.Key(), request.StateVersion)
				} else {
					updated, err = operations.MarkErrorTerminalAudited(ctx, request.Key(), request.StateVersion)
				}
				if err != nil {
					return err
				}
				request = updated
				if err := engine.faultAfter(PolicyFaultAfterNoMintAcknowledged); err != nil {
					return err
				}
			}
			var updated *policystore.Request
			var err error
			if request.ErrorFamily == policystore.ErrorFamilySemantic {
				updated, err = operations.PublishRejection(ctx, request.Key(), request.StateVersion, now)
			} else {
				updated, err = operations.PublishError(ctx, request.Key(), request.StateVersion, now)
			}
			if err != nil {
				return err
			}
			request = updated
			if err := engine.faultAfter(PolicyFaultAfterFinalCAS); err != nil {
				return err
			}

		case policystore.StateApproved, policystore.StateDenied, policystore.StateError:
			return nil

		default:
			return fmt.Errorf("%w: unknown policy state %q", policystore.ErrCorrupt, request.State)
		}
	}
	return fmt.Errorf("%w: policy lifecycle exceeded bounded transitions", policystore.ErrCorrupt)
}

func requestWorkLease(request *policystore.Request) policystore.WorkLease {
	return policystore.WorkLease{
		Lease: policystore.Lease{
			Key: request.Key(), Owner: request.RecoveryLeaseOwner,
			Generation: request.RecoveryLeaseGeneration,
			Until:      time.Unix(request.RecoveryLeaseUntil, 0).UTC(),
		},
		StateVersion: request.StateVersion,
	}
}

func verifyPersistedPolicyResult(request *policystore.Request) error {
	if request == nil || !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize || len(request.ResultEnvelope) == 0 {
		return fmt.Errorf("%w: incomplete persisted policy result", policystore.ErrCorrupt)
	}
	keyID, err := policy.SignerKeyID(ed25519.PublicKey(request.FrozenSignerPublicKey))
	if err != nil || keyID != request.FrozenSignerKeyID.Value || keyID != request.ExpectedSignerKeyID {
		return fmt.Errorf("%w: persisted policy key identity", policystore.ErrCorrupt)
	}
	manifest, err := policy.VerifyBaseManifest(request.ResultEnvelope, ed25519.PublicKey(request.FrozenSignerPublicKey))
	if err != nil || manifest.Host != request.HostKeyFP {
		return fmt.Errorf("%w: persisted policy envelope", policystore.ErrCorrupt)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(request.ResultEnvelope)
	if err != nil || !bytes.Equal(payload, request.Payload) {
		return fmt.Errorf("%w: persisted policy payload", policystore.ErrCorrupt)
	}
	return nil
}

func verifyMaterializedPolicyResult(request *policystore.Request, envelope []byte) error {
	if request == nil || !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize || len(envelope) == 0 {
		return fmt.Errorf("%w: incomplete materialized policy result", policystore.ErrCorrupt)
	}
	manifest, err := policy.VerifyBaseManifest(envelope, ed25519.PublicKey(request.FrozenSignerPublicKey))
	if err != nil || manifest.Host != request.HostKeyFP {
		return fmt.Errorf("%w: materialized policy envelope", policystore.ErrCorrupt)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
	if err != nil || !bytes.Equal(payload, request.Payload) {
		return fmt.Errorf("%w: materialized policy payload", policystore.ErrCorrupt)
	}
	return nil
}

func (engine *PolicyEngine) emitCall(ctx context.Context, request *policystore.Request, phase, outcome string) error {
	metadata, err := policyAuditMetadataForRequest(request, phase, outcome, request.StateVersion, "", "")
	if err != nil {
		return err
	}
	err = engine.audit.Call(ctx, signerkit.AuditCall{
		Time: engine.now().UTC(), RequestID: request.RequestID,
		HostKeyFP: request.HostKeyFP, Policy: &metadata,
	})
	if err != nil {
		engine.readiness.Fail(err)
	}
	return err
}

func (engine *PolicyEngine) emitVote(ctx context.Context, request *policystore.Request, vote *policystore.Vote) error {
	if vote == nil {
		return fmt.Errorf("%w: nil policy vote", policystore.ErrCorrupt)
	}
	outcome := "approved"
	if vote.Decision == policystore.DecisionDeny {
		outcome = "denied"
	}
	metadata, err := policyAuditMetadataForRequest(request, policyAuditPhaseHumanVerdict, outcome,
		vote.AuditStateVersion, vote.Operator, string(vote.AuthnMethod))
	if err != nil {
		return err
	}
	err = engine.audit.Verdict(ctx, signerkit.AuditVerdict{
		Time: engine.now().UTC(), RequestID: request.RequestID,
		Operator: signerkit.Operator{ID: vote.Operator, DisplayName: vote.Operator, Verified: true, AuthnMethod: string(vote.AuthnMethod)},
		Approved: vote.Decision == policystore.DecisionApprove, Policy: &metadata,
	})
	if err != nil {
		engine.readiness.Fail(err)
	}
	return err
}

func policyAuditMetadataForRequest(request *policystore.Request, phase, outcome string, stateVersion uint64, operator, method string) (signerkit.PolicyAuditMetadata, error) {
	if request == nil {
		return signerkit.PolicyAuditMetadata{}, fmt.Errorf("%w: nil policy request", policystore.ErrCorrupt)
	}
	epoch, err := exactPolicyUint64(request.EpochBE)
	if err != nil {
		return signerkit.PolicyAuditMetadata{}, fmt.Errorf("%w: epoch: %v", policystore.ErrCorrupt, err)
	}
	revision, err := exactPolicyUint64(request.RevisionBE)
	if err != nil {
		return signerkit.PolicyAuditMetadata{}, fmt.Errorf("%w: revision: %v", policystore.ErrCorrupt, err)
	}
	entryCount, err := auditCount(request.EntryCount)
	if err != nil {
		return signerkit.PolicyAuditMetadata{}, err
	}
	revocationCount, err := auditCount(request.RevocationCount)
	if err != nil {
		return signerkit.PolicyAuditMetadata{}, err
	}
	evidence, err := policyAuditEvidenceForRequest(request)
	if err != nil {
		return signerkit.PolicyAuditMetadata{}, err
	}
	headDigest := ""
	if request.TrustedHeadDigest.Valid {
		headDigest = request.TrustedHeadDigest.Value
	}
	metadata := signerkit.PolicyAuditMetadata{
		AuthorityID: request.AuthorityID, Purpose: request.Purpose, Principal: request.Principal,
		TupleDigest: request.TupleDigest, Phase: phase, StateVersion: stateVersion,
		RequestID: request.RequestID, HostKeyFP: request.HostKeyFP,
		PayloadSHA256: request.PayloadSHA256, CandidateDigest: request.BaseDigest,
		HeadDigest: headDigest, Epoch: epoch, Revision: revision,
		MissAction: request.MissAction, Growth: request.Growth, EntryCount: entryCount,
		RevocationCount: revocationCount, SignerKeyID: request.ExpectedSignerKeyID,
		ResultSHA256: request.ResultSHA256, Outcome: outcome, ErrorCode: string(request.FailureCode),
		NoOp: request.NoOp, VerifiedOperator: operator, OperatorAuthMethod: method,
		Evidence: evidence,
	}
	metadata.EventID = policyauthority.AuditEventID(policyauthority.AuditEvent{
		AuthorityID: metadata.AuthorityID, Purpose: metadata.Purpose, Principal: metadata.Principal,
		RequestID: metadata.RequestID, TupleDigest: metadata.TupleDigest,
		Phase: metadata.Phase, StateVersion: metadata.StateVersion,
	})
	return metadata, nil
}

func policyAuditEvidenceForRequest(request *policystore.Request) (*signerkit.PolicyAuditEvidence, error) {
	evidence := &signerkit.PolicyAuditEvidence{ExpectedSignerKeyID: request.ExpectedSignerKeyID}
	if request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != 0 {
		if !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: incomplete frozen signer evidence", policystore.ErrCorrupt)
		}
		evidence.FrozenSignerKeyID = request.FrozenSignerKeyID.Value
		evidence.FrozenSignerPublicKeyB64 = base64.StdEncoding.EncodeToString(request.FrozenSignerPublicKey)
	}
	if len(request.TrustedHeadEpochBE) != 0 || len(request.TrustedHeadRevisionBE) != 0 {
		epoch, err := exactPolicyUint64(request.TrustedHeadEpochBE)
		if err != nil {
			return nil, fmt.Errorf("%w: trusted epoch evidence", policystore.ErrCorrupt)
		}
		revision, err := exactPolicyUint64(request.TrustedHeadRevisionBE)
		if err != nil {
			return nil, fmt.Errorf("%w: trusted revision evidence", policystore.ErrCorrupt)
		}
		evidence.TrustedEpoch = strconv.FormatUint(epoch, 10)
		evidence.TrustedRevision = strconv.FormatUint(revision, 10)
	}
	if len(request.ClaimedHeadEpochBE) != 0 || len(request.ClaimedHeadRevisionBE) != 0 {
		epoch, err := exactPolicyUint64(request.ClaimedHeadEpochBE)
		if err != nil {
			return nil, fmt.Errorf("%w: claimed epoch evidence", policystore.ErrCorrupt)
		}
		revision, err := exactPolicyUint64(request.ClaimedHeadRevisionBE)
		if err != nil {
			return nil, fmt.Errorf("%w: claimed revision evidence", policystore.ErrCorrupt)
		}
		evidence.ClaimedEpoch = strconv.FormatUint(epoch, 10)
		evidence.ClaimedRevision = strconv.FormatUint(revision, 10)
	}
	return evidence, nil
}

func exactPolicyUint64(value []byte) (uint64, error) {
	if len(value) != 8 {
		return 0, errors.New("field is not exactly eight bytes")
	}
	return binary.BigEndian.Uint64(value), nil
}

func auditCount(value int64) (int, error) {
	if value < 0 || uint64(value) > uint64(math.MaxInt) {
		return 0, fmt.Errorf("%w: audit count outside int range", policystore.ErrCorrupt)
	}
	return int(value), nil
}
