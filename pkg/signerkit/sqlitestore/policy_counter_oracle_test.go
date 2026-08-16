package sqlitestore

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

type policyCounterOracle struct {
	t        *testing.T
	database *DB
	store    policystore.Store
	step     int
}

func (oracle *policyCounterOracle) check(label string) {
	oracle.t.Helper()
	oracle.step++
	_, err := withPolicyImmediate(context.Background(), oracle.database.db, func(transaction *sql.Tx) (struct{}, error) {
		meta, err := readPolicyMeta(context.Background(), transaction)
		if err != nil {
			return struct{}{}, err
		}
		fresh, err := recomputePolicyLedger(context.Background(), transaction, meta)
		if err != nil {
			return struct{}{}, err
		}
		stored := policyCounters{Used: meta.LogicalUsedBytes, Reserved: meta.LogicalReservedBytes,
			Full: meta.FullRequestCount, Heads: meta.HeadCount, Active: meta.ActiveCount}
		if stored != fresh {
			return struct{}{}, fmt.Errorf("stored=%+v recomputed=%+v", stored, fresh)
		}
		return struct{}{}, nil
	})
	if err != nil {
		oracle.t.Fatalf("counter oracle step %d (%s): %v", oracle.step, label, err)
	}
}

func oracleActivatePolicy(t *testing.T, oracle *policyCounterOracle, input policystore.BeginInput) *policystore.Request {
	t.Helper()
	ctx := context.Background()
	begin, err := oracle.store.Begin(ctx, input)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	oracle.check("accepted admission")
	request, err := oracle.store.MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion)
	if err != nil {
		t.Fatalf("MarkSubmissionAudited: %v", err)
	}
	oracle.check("submission audit")
	request, err = oracle.store.ActivateSubmission(ctx, request.Key(), request.StateVersion, input.Now.Add(time.Second))
	if err != nil {
		t.Fatalf("ActivateSubmission: %v", err)
	}
	oracle.check("submission activation")
	return request
}

func oracleClaimPolicy(t *testing.T, oracle *policyCounterOracle, input policystore.BeginInput) (*policystore.Request, policystore.WorkLease) {
	t.Helper()
	ctx := context.Background()
	request := oracleActivatePolicy(t, oracle, input)
	vote, err := oracle.store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: input.Now.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("PrepareVote: %v", err)
	}
	oracle.check("vote insert")
	if _, err := oracle.store.PublishVoteAudit(ctx, request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
		t.Fatalf("PublishVoteAudit: %v", err)
	}
	oracle.check("vote audit")
	lease, err := oracle.store.ClaimApproval(ctx, request.Key(), vote.Vote.AuditStateVersion, "worker", input.Now.Add(3*time.Second), 2*time.Minute)
	if err != nil {
		t.Fatalf("ClaimApproval: %v", err)
	}
	oracle.check("approval claim")
	request, err = oracle.store.MarkPreMintAudited(ctx, lease)
	if err != nil {
		t.Fatalf("MarkPreMintAudited: %v", err)
	}
	oracle.check("pre-mint audit")
	return request, lease
}

func oraclePersistPolicy(t *testing.T, oracle *policyCounterOracle, private ed25519.PrivateKey, input policystore.BeginInput,
	request *policystore.Request, lease policystore.WorkLease) *policystore.Request {
	t.Helper()
	decoded, err := policywire.DecodeRequest(input.CanonicalRequest)
	if err != nil {
		t.Fatalf("PersistMaterialized: %v", err)
	}
	envelope, err := policy.SignBaseManifest(private, decoded.Manifest)
	if err != nil {
		t.Fatalf("MarkResultAudited: %v", err)
	}
	request, err = oracle.store.PersistMaterialized(context.Background(), lease, envelope, input.Now.Add(4*time.Second))
	if err != nil {
		t.Fatalf("PublishApproved: %v", err)
	}
	oracle.check("materialized persistence")
	return request
}

func oraclePublishPolicy(t *testing.T, oracle *policyCounterOracle, private ed25519.PrivateKey,
	input policystore.BeginInput) *policystore.Request {
	t.Helper()
	request, lease := oracleClaimPolicy(t, oracle, input)
	request = oraclePersistPolicy(t, oracle, private, input, request, lease)
	var err error
	request, err = oracle.store.MarkResultAudited(context.Background(), request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	oracle.check("result audit")
	request, err = oracle.store.PublishApproved(context.Background(), request.Key(), request.StateVersion, input.Now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oracle.check("approved publication")
	return request
}

func TestPolicyIncrementalCountersMatchRecomputeMutationMatrix(t *testing.T) {
	t.Run("authority binding", func(t *testing.T) {
		database := openPolicyTestDB(t)
		public, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := policy.SignerKeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		config := testPolicyConfig("machine", 1, false)
		digest, err := policystore.ConfigDigest(config)
		if err != nil {
			t.Fatal(err)
		}
		store := database.PolicyStore()
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{
			AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID, AccountingVersion: policystore.AccountingVersion,
			ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
			MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config,
		}); err != nil {
			t.Fatal(err)
		}
		oracle.check("authority binding")
	})

	t.Run("accepted successor no-op and compaction", func(t *testing.T) {
		database, store, public, private, keyID, _ := newPolicyStoreHarness(t, 1, false)
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		addPolicyVoter(t, database, "voter-a")
		now := time.Unix(20_000, 0).UTC()
		firstInput := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 20_000, 1, now)
		first := oraclePublishPolicy(t, oracle, private, firstInput)

		decoded, err := policywire.DecodeRequest(firstInput.CanonicalRequest)
		if err != nil {
			t.Fatal(err)
		}
		successorManifest := decoded.Manifest
		successorManifest.Revision++
		identity, err := policy.NewShellExactIdentity([]byte("echo counter oracle successor"))
		if err != nil {
			t.Fatal(err)
		}
		successorManifest.Entries = []policy.BaseEntry{{ID: "pa_oob_0123456789abcdef0123456789abcdef",
			Identity: identity, Source: policy.EntrySourceOutOfBand}}
		successorInput := policySuccessorInput(t, public, keyID, first, 20_001, successorManifest, now.Add(10*time.Second))
		successor := oraclePublishPolicy(t, oracle, private, successorInput)

		noOpInput := policySuccessorInput(t, public, keyID, successor, 20_002, successorManifest, now.Add(20*time.Second))
		begin, err := store.Begin(context.Background(), noOpInput)
		if err != nil || begin.Request == nil || !begin.Request.NoOp {
			t.Fatalf("no-op admission = %+v, %v", begin, err)
		}
		oracle.check("no-op admission")
		noOp, err := store.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op submission audit")
		noOp, err = store.ActivateSubmission(context.Background(), noOp.Key(), noOp.StateVersion, noOpInput.Now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op activation")
		noOp, err = store.MarkNoOpTerminalAudited(context.Background(), noOp.Key(), noOp.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op terminal audit")
		if _, err := store.PublishNoOp(context.Background(), noOp.Key(), noOp.StateVersion, noOpInput.Now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op publication")

		record, err := store.SnapshotTerminalArchive(context.Background(), first.Key(), first.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		reference, _, err := record.ObjectRef()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CommitTerminalArchive(context.Background(), first.Key(), first.StateVersion, reference); err != nil {
			t.Fatal(err)
		}
		oracle.check("compaction request conversion and vote deletion")
	})

	t.Run("leased admission rejection and compaction", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		now := time.Now().UTC().Truncate(time.Second)
		input := policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "d", 2, now)
		begin, err := store.Begin(context.Background(), input)
		if err != nil || begin.Request.State != policystore.StateRejectionUnaudited {
			t.Fatalf("rejection admission = %+v, %v", begin, err)
		}
		oracle.check("rejection admission")
		components, err := policystore.Matrix2AReservation(input.CanonicalRequest, input.Payload)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := store.AcquireRecoveryLease(context.Background(), begin.Request.Key(), "rejection-worker", now, 2*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("rejection lease acquire")
		fenced := store.Fenced(lease)
		request, err := fenced.MarkRejectionSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("rejection submission audit")
		if request.ReservedBytes != begin.Request.ReservedBytes-components.Growth.LeaseOwner {
			t.Fatalf("rejection owner allowance reserve = %d; want %d",
				request.ReservedBytes, begin.Request.ReservedBytes-components.Growth.LeaseOwner)
		}
		request, err = fenced.StageRejectionError(context.Background(), request.Key(), request.StateVersion, input.Now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("rejection staging")
		request, err = fenced.MarkRejectionTerminalAudited(context.Background(), request.Key(), request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("rejection terminal audit")
		request, err = fenced.PublishRejection(context.Background(), request.Key(), request.StateVersion, input.Now.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("rejection publication")
		floor := uint64(len(input.CanonicalRequest) + len(input.Payload))
		if request.ReservedBytes != floor || request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
			t.Fatalf("published rejection reserve/lease = %d %q/%d; want %d and cleared",
				request.ReservedBytes, request.RecoveryLeaseOwner, request.RecoveryLeaseUntil, floor)
		}
		record, err := store.SnapshotTerminalArchive(context.Background(), request.Key(), request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		reference, _, err := record.ObjectRef()
		if err != nil {
			t.Fatal(err)
		}
		compacted, err := store.CommitTerminalArchive(context.Background(), request.Key(), request.StateVersion, reference)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("rejection compaction")
		if compacted.Request.StorageKind != policystore.StorageTombstone || compacted.Request.ReservedBytes != floor {
			t.Fatalf("compacted rejection = %+v; want tombstone reserve %d", compacted.Request, floor)
		}
	})

	t.Run("denial claim and publication", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 22_000, 1, time.Unix(22_000, 0).UTC())
		request := oracleActivatePolicy(t, oracle, input)
		vote, err := store.PrepareVote(context.Background(), policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
			Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: input.Now.Add(2 * time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("denial vote")
		if _, err := store.PublishVoteAudit(context.Background(), request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
			t.Fatal(err)
		}
		oracle.check("denial vote audit")
		request, err = store.ClaimDenial(context.Background(), request.Key(), vote.Vote.AuditStateVersion, input.Now.Add(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("denial claim")
		request, err = store.MarkDenialTerminalAudited(context.Background(), request.Key(), request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("denial terminal audit")
		if _, err := store.PublishDenied(context.Background(), request.Key(), request.StateVersion, input.Now.Add(4*time.Second)); err != nil {
			t.Fatal(err)
		}
		oracle.check("denial publication")
	})

	t.Run("recovery lease acquire release and clear", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 23_000, 1, time.Unix(23_000, 0).UTC())
		begin, err := store.Begin(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("lease admission")
		lease, err := store.AcquireRecoveryLease(context.Background(), begin.Request.Key(), "worker-a", input.Now, 2*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("lease acquire")
		if err := store.ReleaseRecoveryLease(context.Background(), lease); err != nil {
			t.Fatal(err)
		}
		oracle.check("lease release")
		if _, err := store.AcquireRecoveryLease(context.Background(), begin.Request.Key(), "worker-b", input.Now.Add(time.Second), 2*time.Minute); err != nil {
			t.Fatal(err)
		}
		oracle.check("lease reacquire")
		if err := database.ClearPolicyRecoveryLease(context.Background(), begin.Request.ReviewID); err != nil {
			t.Fatal(err)
		}
		oracle.check("maintenance lease clear")
	})

	t.Run("fenced recovery lifecycle", func(t *testing.T) {
		t.Run("activation clears lease", func(t *testing.T) {
			database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
			addPolicyVoter(t, database, "voter-a")
			oracle := &policyCounterOracle{t: t, database: database, store: store}
			now := time.Now().UTC().Truncate(time.Second)
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 23_100, 1, now)
			begin, err := store.Begin(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced activation admission")
			lease, err := store.AcquireRecoveryLease(context.Background(), begin.Request.Key(), "activation-worker", now, 2*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced activation lease acquire")
			fenced := store.Fenced(lease)
			request, err := fenced.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced activation submission audit")
			request, err = fenced.ActivateSubmission(context.Background(), request.Key(), request.StateVersion, now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced activation lease clear")
			if request.State != policystore.StatePending || request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
				t.Fatalf("fenced activation retained lease: %+v", request)
			}
		})

		t.Run("vote audit without outcome clears lease", func(t *testing.T) {
			database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 2, false)
			addPolicyVoter(t, database, "voter-a")
			addPolicyVoter(t, database, "voter-b")
			oracle := &policyCounterOracle{t: t, database: database, store: store}
			now := time.Now().UTC().Truncate(time.Second)
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 23_200, 1, now)
			request := oracleActivatePolicy(t, oracle, input)
			vote, err := store.PrepareVote(context.Background(), policystore.VoteInput{ReviewID: request.ReviewID,
				Operator: "voter-a", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession,
				Now: now.Add(2 * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced no-outcome vote")
			lease, err := store.AcquireRecoveryLease(context.Background(), request.Key(), "vote-audit-worker", now.Add(3*time.Second), 2*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced no-outcome lease acquire")
			tally, err := store.Fenced(lease).PublishVoteAudit(context.Background(), request.Key(), "voter-a", vote.Vote.AuditStateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced no-outcome vote audit lease clear")
			request, err = store.GetByReviewID(context.Background(), request.ReviewID)
			if err != nil || tally.ApprovalReached || tally.DenialReached || request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
				t.Fatalf("fenced no-outcome vote audit = %+v, request %+v, %v", tally, request, err)
			}
		})

		t.Run("approval claim", func(t *testing.T) {
			database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
			addPolicyVoter(t, database, "voter-a")
			oracle := &policyCounterOracle{t: t, database: database, store: store}
			now := time.Now().UTC().Truncate(time.Second)
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 23_300, 1, now)
			request := oracleActivatePolicy(t, oracle, input)
			vote, err := store.PrepareVote(context.Background(), policystore.VoteInput{ReviewID: request.ReviewID,
				Operator: "voter-a", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession,
				Now: now.Add(2 * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced approval vote")
			if _, err := store.PublishVoteAudit(context.Background(), request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced approval vote audit")
			lease, err := store.AcquireRecoveryLease(context.Background(), request.Key(), "approval-worker", now.Add(3*time.Second), 2*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced approval lease acquire")
			workLease, err := store.Fenced(lease).ClaimApproval(context.Background(), request.Key(), vote.Vote.AuditStateVersion,
				lease.Owner, now.Add(4*time.Second), 2*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("fenced approval claim")
			request, err = store.GetByReviewID(context.Background(), request.ReviewID)
			if err != nil || request.State != policystore.StateApprovedMaterializing || workLease.Generation != lease.Generation ||
				request.RecoveryLeaseOwner != lease.Owner {
				t.Fatalf("fenced approval claim = %+v, request %+v, %v", workLease, request, err)
			}
		})
	})

	t.Run("processing materialization and publication errors", func(t *testing.T) {
		t.Run("intake", func(t *testing.T) {
			database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
			addPolicyVoter(t, database, "voter-a")
			oracle := &policyCounterOracle{t: t, database: database, store: store}
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 24_000, 1, time.Unix(24_000, 0).UTC())
			begin, err := store.Begin(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("intake admission")
			request, err := store.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("intake submission audit")
			request, err = store.StageIntakeKeyError(context.Background(), request.Key(), request.StateVersion, input.Now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("intake error staging")
			request, err = store.MarkErrorTerminalAudited(context.Background(), request.Key(), request.StateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("intake error audit")
			if _, err := store.PublishError(context.Background(), request.Key(), request.StateVersion, input.Now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			oracle.check("intake error publication")
		})

		t.Run("materialization", func(t *testing.T) {
			database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
			addPolicyVoter(t, database, "voter-a")
			oracle := &policyCounterOracle{t: t, database: database, store: store}
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 24_100, 1, time.Unix(24_100, 0).UTC())
			request, lease := oracleClaimPolicy(t, oracle, input)
			request, err := store.StageMaterializationError(context.Background(), lease, policywire.ErrorPolicyMaterializationFailed, input.Now.Add(4*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("materialization error staging")
			request, err = store.MarkErrorTerminalAudited(context.Background(), request.Key(), request.StateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("materialization error audit")
			if _, err := store.PublishError(context.Background(), request.Key(), request.StateVersion, input.Now.Add(5*time.Second)); err != nil {
				t.Fatal(err)
			}
			oracle.check("materialization error publication")
		})

		t.Run("publication", func(t *testing.T) {
			database, store, public, private, keyID, _ := newPolicyStoreHarness(t, 1, false)
			addPolicyVoter(t, database, "voter-a")
			oracle := &policyCounterOracle{t: t, database: database, store: store}
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 24_200, 1, time.Unix(24_200, 0).UTC())
			request, lease := oracleClaimPolicy(t, oracle, input)
			request = oraclePersistPolicy(t, oracle, private, input, request, lease)
			request, err := store.MarkResultAudited(context.Background(), request.Key(), request.StateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("publication result audit")
			request, err = store.StagePublicationError(context.Background(), request.Key(), request.StateVersion, policywire.ErrorStalePolicyHead, input.Now.Add(5*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("publication error staging")
			request, err = store.MarkErrorTerminalAudited(context.Background(), request.Key(), request.StateVersion)
			if err != nil {
				t.Fatal(err)
			}
			oracle.check("publication error audit")
			if _, err := store.PublishError(context.Background(), request.Key(), request.StateVersion, input.Now.Add(6*time.Second)); err != nil {
				t.Fatal(err)
			}
			oracle.check("publication error publication")
		})
	})

	t.Run("no-op publication error", func(t *testing.T) {
		database, store, public, private, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		now := time.Unix(25_000, 0).UTC()
		firstInput := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 25_000, 1, now)
		first := oraclePublishPolicy(t, oracle, private, firstInput)
		decoded, err := policywire.DecodeRequest(firstInput.CanonicalRequest)
		if err != nil {
			t.Fatal(err)
		}
		input := policySuccessorInput(t, public, keyID, first, 25_001, decoded.Manifest, now.Add(10*time.Second))
		begin, err := store.Begin(context.Background(), input)
		if err != nil || !begin.Request.NoOp {
			t.Fatalf("no-op admission = %+v, %v", begin, err)
		}
		oracle.check("no-op error admission")
		request, err := store.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op error submission audit")
		request, err = store.ActivateSubmission(context.Background(), request.Key(), request.StateVersion, input.Now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op error activation")
		request, err = store.MarkNoOpTerminalAudited(context.Background(), request.Key(), request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op error terminal audit")
		request, err = store.StageNoOpError(context.Background(), request.Key(), request.StateVersion, policywire.ErrorStalePolicyHead, input.Now.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op error staging")
		request, err = store.MarkErrorTerminalAudited(context.Background(), request.Key(), request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op staged error audit")
		if _, err := store.PublishError(context.Background(), request.Key(), request.StateVersion, input.Now.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
		oracle.check("no-op staged error publication")
	})

	t.Run("quorum-unattainable staging", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 2, false)
		addPolicyVoter(t, database, "voter-a")
		addPolicyVoter(t, database, "voter-b")
		oracle := &policyCounterOracle{t: t, database: database, store: store}
		input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 26_000, 1, time.Unix(26_000, 0).UTC())
		request := oracleActivatePolicy(t, oracle, input)
		if _, err := database.db.Exec(`DELETE FROM totp_secrets WHERE user_id='voter-b'`); err != nil {
			t.Fatal(err)
		}
		reconciled, err := store.ReconcilePendingAttainability(context.Background(), authorityID("a"), input.Now.Add(2*time.Second))
		if err != nil || len(reconciled.UnattainableCandidates) != 1 {
			t.Fatalf("unattainable candidates = %+v, %v", reconciled, err)
		}
		candidate := reconciled.UnattainableCandidates[0]
		request, err = store.StageQuorumUnattainable(context.Background(), candidate.Key, candidate.StateVersion, input.Now.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("quorum-unattainable staging")
		request, err = store.MarkRejectionTerminalAudited(context.Background(), request.Key(), request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		oracle.check("quorum-unattainable audit")
		if _, err := store.PublishRejection(context.Background(), request.Key(), request.StateVersion, input.Now.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
		oracle.check("quorum-unattainable publication")
	})
}
