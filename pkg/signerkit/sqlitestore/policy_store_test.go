package sqlitestore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func TestPolicyStoreBootstrapLifecycleAndCompaction(t *testing.T) {
	database := openPolicyTestDB(t)
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(nil)
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
	if err := store.BindAuthority(ctx, policystore.AuthorityBinding{AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID,
		AccountingVersion: policystore.AccountingVersion, ConfigDigest: digest, SignerKeyID: keyID,
		SignerPublicKey: public, MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config}); err != nil {
		t.Fatalf("BindAuthority: %v", err)
	}
	if _, err := database.db.Exec(`INSERT INTO users(id,username,role,created_at) VALUES('voter','voter','operator',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`INSERT INTO totp_secrets(user_id,secret,created_at) VALUES('voter','secret',1)`); err != nil {
		t.Fatal(err)
	}

	host := "SHA256:" + strings.Repeat("A", 43)
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: host, Epoch: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wireRequest, err := policywire.NewRequest(requestID("1"), host, keyID, payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policywire.MarshalRequest(wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA, _, err := policywire.PayloadDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	tuple := policyauthority.RequestTuple{RequestID: wireRequest.RequestID, Purpose: policywire.Purpose, HostKeyFP: host,
		ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA, Bootstrap: true}
	now := time.Unix(1000, 0).UTC()
	begin, err := store.Begin(ctx, policystore.BeginInput{Key: policystore.Key{Principal: "machine", RequestID: wireRequest.RequestID},
		Tuple: tuple, CanonicalRequest: canonical, Payload: payload, AuthorityID: authorityID("a"), ReviewID: reviewID("1"),
		RequesterPrincipal: "machine", SignerKeyID: keyID, SignerPublicKey: public, ReviewJSON: []byte(`{"summary":"bootstrap"}`),
		ReviewRenderedBytes: 23, ReviewItemCount: 1, ReviewRendererVersion: config.ReviewRendererVersion,
		ReviewRulesDigest: config.ReviewRulesDigest, Now: now})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if begin.Lookup.Kind != policystore.LookupExact || begin.Request.State != policystore.StateReceivedUnaudited {
		t.Fatalf("Begin result = %+v", begin)
	}
	if fetched, fetchErr := store.Fetch(ctx, begin.Request.Key()); fetchErr != nil || fetched.PendingResponse != nil {
		t.Fatalf("unavailable live Fetch carried pending bytes: %+v, %v", fetched, fetchErr)
	}
	request := begin.Request
	request, err = store.MarkSubmissionAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	if got := request.ReservedBytes; got != begin.Request.ReservedBytes {
		t.Fatalf("submission audit moved reservation: %d != %d", got, begin.Request.ReservedBytes)
	}
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	vote, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if vote.Vote.HeadDigest != "" {
		t.Fatalf("bootstrap vote head digest = %q; want empty", vote.Vote.HeadDigest)
	}
	if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter", vote.Vote.AuditStateVersion); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{time.Minute, 2*time.Minute + time.Second} {
		if _, err := store.ClaimApproval(ctx, request.Key(), vote.Vote.AuditStateVersion, "worker", now.Add(3*time.Second), ttl); err == nil {
			t.Fatalf("ClaimApproval accepted TTL %s", ttl)
		}
	}
	lease, err := store.ClaimApproval(ctx, request.Key(), vote.Vote.AuditStateVersion, "worker", now.Add(3*time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !lease.Until.Equal(now.Add(123 * time.Second)) {
		t.Fatalf("approval lease until = %s; want %s", lease.Until, now.Add(123*time.Second))
	}
	publicationGeneration := lease.Generation
	if _, err := store.MarkPreMintAudited(ctx, lease); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(private, manifest)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PersistMaterialized(ctx, lease, envelope, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.MarkResultAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PublishApproved(ctx, request.Key(), request.StateVersion, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if request.ReservedBytes != 0 || request.State != policystore.StateApproved ||
		request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 ||
		request.RecoveryLeaseGeneration != publicationGeneration {
		t.Fatalf("published request state/reserve/lease = %s/%d %q/%d/%d", request.State, request.ReservedBytes,
			request.RecoveryLeaseOwner, request.RecoveryLeaseUntil, request.RecoveryLeaseGeneration)
	}
	if fetched, fetchErr := store.Fetch(ctx, request.Key()); fetchErr != nil || fetched.PendingResponse != nil {
		t.Fatalf("terminal Fetch carried pending bytes: %+v, %v", fetched, fetchErr)
	}
	// A successor request carrying byte-identical payload takes the no-op path:
	// it has no approval claim/predecessor claim, does not enter the vote queue,
	// and publication must not rewrite the authoritative head.
	noOpWire, err := policywire.NewRequest(requestID("2"), host, keyID, payload, request.BaseDigest, false)
	if err != nil {
		t.Fatal(err)
	}
	noOpCanonical, _ := policywire.MarshalRequest(noOpWire)
	noOpTuple := policyauthority.RequestTuple{RequestID: noOpWire.RequestID, Purpose: policywire.Purpose, HostKeyFP: host,
		ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA, ExpectedHeadDigest: request.BaseDigest}
	noOpBegin, err := store.Begin(ctx, policystore.BeginInput{Key: policystore.Key{Principal: "machine", RequestID: noOpWire.RequestID},
		Tuple: noOpTuple, CanonicalRequest: noOpCanonical, Payload: payload, AuthorityID: authorityID("a"), ReviewID: reviewID("2"),
		RequesterPrincipal: "machine", SignerKeyID: keyID, SignerPublicKey: public, ReviewJSON: []byte(`{"summary":"no-op"}`),
		ReviewRenderedBytes: 19, ReviewItemCount: 0, ReviewRendererVersion: config.ReviewRendererVersion,
		ReviewRulesDigest: config.ReviewRulesDigest, Now: now.Add(6 * time.Second)})
	if err != nil {
		t.Fatalf("Begin no-op: %v", err)
	}
	noOp, err := store.MarkSubmissionAudited(ctx, noOpBegin.Request.Key(), noOpBegin.Request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	noOp, err = store.ActivateSubmission(ctx, noOp.Key(), noOp.StateVersion, now.Add(7*time.Second))
	if err != nil || noOp.State != policystore.StateNoOpUnexposed || noOp.ClaimedHeadEnvelope != nil {
		t.Fatalf("activate no-op = %+v, %v", noOp, err)
	}
	noOpReserve := noOp.ReservedBytes
	noOp, err = store.MarkNoOpTerminalAudited(ctx, noOp.Key(), noOp.StateVersion)
	if err != nil || noOp.ReservedBytes != noOpReserve {
		t.Fatalf("no-op terminal audit moved reserve: %+v, %v", noOp, err)
	}
	noOp, err = store.PublishNoOp(ctx, noOp.Key(), noOp.StateVersion, now.Add(8*time.Second))
	if err != nil || noOp.State != policystore.StateApproved || noOp.ReservedBytes != 0 || noOp.ClaimedHeadEnvelope != nil {
		t.Fatalf("publish no-op = %+v, %v", noOp, err)
	}
	var headCount, headVersion int
	if err := database.db.QueryRow(`SELECT count(*),max(row_version) FROM policy_heads`).Scan(&headCount, &headVersion); err != nil {
		t.Fatal(err)
	}
	if headCount != 1 || headVersion != 1 {
		t.Fatalf("no-op rewrote head: count/version=%d/%d", headCount, headVersion)
	}
	record, err := store.SnapshotTerminalArchive(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	reference, encoded, err := record.ObjectRef()
	if err != nil {
		t.Fatal(err)
	}
	compacted, err := store.CommitTerminalArchive(ctx, request.Key(), request.StateVersion, reference)
	if err != nil {
		t.Fatal(err)
	}
	if compacted.Request.StorageKind != policystore.StorageTombstone || compacted.Request.RecoveryLeaseOwner != "" ||
		compacted.Request.RecoveryLeaseUntil != 0 || compacted.Request.RecoveryLeaseGeneration != publicationGeneration {
		t.Fatalf("tombstone storage/lease = %s %q/%d/%d", compacted.Request.StorageKind,
			compacted.Request.RecoveryLeaseOwner, compacted.Request.RecoveryLeaseUntil, compacted.Request.RecoveryLeaseGeneration)
	}
	if fetched, fetchErr := store.Fetch(ctx, request.Key()); fetchErr != nil || fetched.PendingResponse != nil {
		t.Fatalf("tombstone Fetch carried pending bytes: %+v, %v", fetched, fetchErr)
	}
	terminal, err := ResolveTerminalArchive(compacted.Request, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(terminal) != string(record.Request.TerminalResponse) {
		t.Fatal("resolved terminal differs")
	}
	corruptTombstone := *compacted.Request
	corruptTombstone.LogicalBytes++
	if _, err := ResolveTerminalArchive(&corruptTombstone, encoded); !errors.Is(err, policystore.ErrCorrupt) {
		t.Fatalf("archive resolution accepted corrupt tombstone logical bytes: %v", err)
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		t.Fatalf("post-compaction verification: %v", err)
	}
}

func TestPolicyStoreExactIDPrecedesAdmissionValidation(t *testing.T) {
	database := openPolicyTestDB(t)
	ctx := context.Background()
	public, _, _ := ed25519.GenerateKey(nil)
	keyID, _ := policy.SignerKeyID(public)
	config := testPolicyConfig("machine", 1, false)
	digest, _ := policystore.ConfigDigest(config)
	store := database.PolicyStore()
	if err := store.BindAuthority(ctx, policystore.AuthorityBinding{AuthorityID: authorityID("b"), ArchiveID: config.ArchiveID,
		AccountingVersion: policystore.AccountingVersion, ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
		MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config}); err != nil {
		t.Fatal(err)
	}
	host := "SHA256:" + strings.Repeat("A", 43)
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: host, Epoch: 2, MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	payload, _ := policy.MarshalBaseManifest(manifest)
	wireRequest, _ := policywire.NewRequest(requestID("2"), host, keyID, payload, "", true)
	canonical, _ := policywire.MarshalRequest(wireRequest)
	payloadSHA, _, _ := policywire.PayloadDigests(payload)
	tuple := policyauthority.RequestTuple{RequestID: wireRequest.RequestID, Purpose: policywire.Purpose, HostKeyFP: host,
		ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA, Bootstrap: true}
	input := policystore.BeginInput{Key: policystore.Key{Principal: "machine", RequestID: wireRequest.RequestID}, Tuple: tuple,
		CanonicalRequest: canonical, Payload: payload, AuthorityID: authorityID("b"), ReviewID: reviewID("2"),
		RequesterPrincipal: "machine", SignerKeyID: keyID, SignerPublicKey: public, Now: time.Unix(2000, 0)}
	first, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Request.State != policystore.StateRejectionUnaudited {
		t.Fatalf("state = %s; want rejection", first.Request.State)
	}
	input.ReviewID = "bad"
	retry, err := store.Begin(ctx, input)
	if err == nil || retry.Lookup.Kind != "" {
		// Strict boundary validation precedes the transaction, while every
		// authority/admission predicate is deliberately after exact lookup.
		t.Fatalf("malformed boundary retry = %+v, %v", retry, err)
	}
	input.ReviewID = reviewID("3")
	retry, err = store.Begin(ctx, input)
	if err != nil || retry.Lookup.Kind != policystore.LookupExact {
		t.Fatalf("exact retry = %+v, %v", retry, err)
	}
}

func TestPolicyFetchResultPendingResponseVisibility(t *testing.T) {
	t.Parallel()
	source := []byte(`{"status":"pending"}`)
	request := &policystore.Request{StorageKind: policystore.StorageFull, State: policystore.StatePending,
		SubmissionAudited: true, PendingResponse: source}
	result := policyFetchResult(request)
	if result.Class != policystore.RowLive || result.Visibility != policystore.VisibilityPending || !bytes.Equal(result.PendingResponse, source) {
		t.Fatalf("pending FetchResult = %+v", result)
	}
	result.PendingResponse[0] = 'X'
	if source[0] == 'X' {
		t.Fatal("pending FetchResult aliases the stored response")
	}

	for _, test := range []struct {
		name    string
		request policystore.Request
	}{
		{name: "live unavailable", request: policystore.Request{StorageKind: policystore.StorageFull,
			State: policystore.StateReceivedUnaudited, PendingResponse: source}},
		{name: "rejection live", request: policystore.Request{StorageKind: policystore.StorageFull,
			State: policystore.StateRejectionErrorReceived, SubmissionAudited: true, PendingResponse: source}},
		{name: "terminal", request: policystore.Request{StorageKind: policystore.StorageFull,
			State: policystore.StateApproved, SubmissionAudited: true, PendingResponse: source}},
		{name: "tombstone", request: policystore.Request{StorageKind: policystore.StorageTombstone,
			State: policystore.StateApproved, SubmissionAudited: true, PendingResponse: source}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := policyFetchResult(&test.request); got.PendingResponse != nil {
				t.Fatalf("FetchResult carried pending bytes: %+v", got)
			}
		})
	}
}

func TestPolicyAuthorityMismatchAndCounterDriftFailClosed(t *testing.T) {
	database, store, public, _, keyID, config := newPolicyStoreHarness(t, 1, false)
	ctx := context.Background()
	other := config
	other.ArchiveID = archiveID("b")
	otherDigest, _ := policystore.ConfigDigest(other)
	err := store.BindAuthority(ctx, policystore.AuthorityBinding{AuthorityID: authorityID("b"), ArchiveID: other.ArchiveID,
		AccountingVersion: policystore.AccountingVersion, ConfigDigest: otherDigest, SignerKeyID: keyID,
		SignerPublicKey: public, MaxRejectionReservedBytesPerPrincipal: other.MaxRejectionReservedBytesPerPrincipal, Config: other})
	if !errors.Is(err, policystore.ErrAuthorityMismatch) {
		t.Fatalf("authority rebind error = %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_authority_meta SET logical_used_bytes=1 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAuthorityBinding(ctx); !errors.Is(err, policystore.ErrCounterDrift) {
		t.Fatalf("counter drift verification error = %v", err)
	}
}

func TestPolicyStartupRosterRejectsInvalidIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity string
	}{
		{name: "empty", identity: ""},
		{name: "over bound", identity: strings.Repeat("x", policystore.MaxIdentityBytes+1)},
		{name: "nul", identity: "operator\x00suffix"},
		{name: "invalid utf8", identity: string([]byte{0xff})},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, store, public, _, keyID, config := newPolicyStoreHarness(t, 1, false)
			username := fmt.Sprintf("invalid-roster-%d", index)
			if _, err := database.db.Exec(`INSERT INTO users(id,username,role,created_at) VALUES(?,?, 'operator',1)`, test.identity, username); err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(`INSERT INTO totp_secrets(user_id,secret,created_at) VALUES(?,'secret',1)`, test.identity); err != nil {
				t.Fatal(err)
			}
			digest, err := policystore.ConfigDigest(config)
			if err != nil {
				t.Fatal(err)
			}
			err = store.BindAuthority(context.Background(), policystore.AuthorityBinding{
				AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID, AccountingVersion: policystore.AccountingVersion,
				ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
				MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config,
			})
			if !errors.Is(err, policystore.ErrCorrupt) {
				t.Fatalf("startup roster identity error = %v; want corruption refusal", err)
			}
		})
	}
}

func TestPolicyAdmissionAndVoteRejectIdentityGrammar(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
	addPolicyVoter(t, database, "voter-a")
	request := activatePolicyBootstrap(t, store, public, keyID, 6500, time.Unix(13_500, 0).UTC())
	tests := []struct {
		name     string
		identity string
	}{
		{name: "empty", identity: ""},
		{name: "over bound", identity: strings.Repeat("x", policystore.MaxIdentityBytes+1)},
		{name: "nul", identity: "identity\x00suffix"},
		{name: "invalid utf8", identity: string([]byte{0xff})},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), test.identity,
				6600+index, 1, time.Unix(13_600+int64(index), 0).UTC())
			if _, err := store.Begin(context.Background(), input); err == nil {
				t.Fatal("admission accepted invalid principal")
			}
			if _, err := store.PrepareVote(context.Background(), policystore.VoteInput{ReviewID: request.ReviewID,
				Operator: test.identity, Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession,
				Now: time.Unix(13_700+int64(index), 0).UTC()}); err == nil {
				t.Fatal("vote accepted invalid operator")
			}
		})
	}
}

func TestPolicyTunedRejectionCapRoundTripsThroughBinding(t *testing.T) {
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
	config.MaxRejectionReservedBytesPerPrincipal = 4096
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	store := database.PolicyStore()
	if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{
		AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID, AccountingVersion: policystore.AccountingVersion,
		ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
		MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config,
	}); err != nil {
		t.Fatal(err)
	}
	binding, err := store.VerifyAuthorityBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if binding.MaxRejectionReservedBytesPerPrincipal != 4096 || binding.Config.MaxRejectionReservedBytesPerPrincipal != 4096 {
		t.Fatalf("tuned cap did not round trip: %+v", binding)
	}
}

func TestPolicyMatrix2AReservationFloorAndAuditAcknowledgements(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
	ctx := context.Background()
	input := policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "3", 2, time.Unix(3000, 0))
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request := begin.Request
	if request.State != policystore.StateRejectionUnaudited || request.FailureCode != policywire.ErrorInvalidPolicyRequest {
		t.Fatalf("rejection admission = %s/%s", request.State, request.FailureCode)
	}
	components, err := policystore.Matrix2AReservation(input.CanonicalRequest, input.Payload)
	if err != nil {
		t.Fatal(err)
	}
	wantInitial, err := components.Total()
	if err != nil {
		t.Fatal(err)
	}
	initial := request.ReservedBytes
	if initial != wantInitial || initial <= components.Floor() {
		t.Fatalf("Matrix-2a admission reserve = %d; want %d above floor %d", initial, wantInitial, components.Floor())
	}
	lease, err := store.AcquireRecoveryLease(ctx, request.Key(), "rejection-worker", time.Now().UTC(), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err = loadPolicyRequest(ctx, database.db, request.Key())
	if err != nil {
		t.Fatal(err)
	}
	if request.ReservedBytes != initial-components.Growth.LeaseOwner {
		t.Fatalf("first rejection lease reserve = %d; want %d", request.ReservedBytes, initial-components.Growth.LeaseOwner)
	}
	fenced := store.Fenced(lease)
	request, err = fenced.MarkRejectionSubmissionAudited(ctx, request.Key(), request.StateVersion)
	wantAfterLease := initial - components.Growth.LeaseOwner
	if err != nil || request.ReservedBytes != wantAfterLease {
		t.Fatalf("submission acknowledgement reserve = %d/%v; want %d", request.ReservedBytes, err, wantAfterLease)
	}
	beforeStage := request.ReservedBytes
	request, err = fenced.StageRejectionError(ctx, request.Key(), request.StateVersion, input.Now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if request.ReservedBytes != beforeStage-components.Growth.Spelling {
		t.Fatalf("rejection staging reserve = %d; want %d", request.ReservedBytes, beforeStage-components.Growth.Spelling)
	}
	staged := request.ReservedBytes
	request, err = fenced.MarkRejectionTerminalAudited(ctx, request.Key(), request.StateVersion)
	if err != nil || request.ReservedBytes != staged {
		t.Fatalf("terminal acknowledgement moved reserve: %d/%v", request.ReservedBytes, err)
	}
	request, err = fenced.PublishRejection(ctx, request.Key(), request.StateVersion, input.Now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	floor := uint64(len(input.CanonicalRequest) + len(input.Payload))
	if request.ReservedBytes != floor || request.TerminalHTTPStatus.Value != 400 || request.RecoveryLeaseOwner != "" ||
		request.RecoveryLeaseUntil != 0 || request.RecoveryLeaseGeneration != lease.Generation {
		t.Fatalf("published Matrix-2a reserve/status = %d/%d; want %d/400", request.ReservedBytes, request.TerminalHTTPStatus.Value, floor)
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		t.Fatalf("Matrix-2a publication scan equality: %v", err)
	}
	fetched, err := store.Fetch(ctx, request.Key())
	if err != nil || fetched.Class != policystore.RowTerminal || fetched.Visibility != "" || fetched.TerminalHTTPStatus != 400 {
		t.Fatalf("Fetch terminal = %+v, %v", fetched, err)
	}
	record, err := store.SnapshotTerminalArchive(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	reference, encoded, err := record.ObjectRef()
	if err != nil {
		t.Fatal(err)
	}
	compacted, err := store.CommitTerminalArchive(ctx, request.Key(), request.StateVersion, reference)
	if err != nil {
		t.Fatal(err)
	}
	if compacted.Request.ReservedBytes != floor || compacted.Request.RecoveryLeaseOwner != "" ||
		compacted.Request.RecoveryLeaseUntil != 0 || compacted.Request.RecoveryLeaseGeneration != lease.Generation {
		t.Fatalf("Matrix-2a tombstone reserve/lease = %d %q/%d/%d; want floor %d and cleared generation %d",
			compacted.Request.ReservedBytes, compacted.Request.RecoveryLeaseOwner, compacted.Request.RecoveryLeaseUntil,
			compacted.Request.RecoveryLeaseGeneration, floor, lease.Generation)
	}
	if _, err := ResolveTerminalArchive(compacted.Request, encoded); err != nil {
		t.Fatalf("resolve Matrix-2a tombstone: %v", err)
	}
}

func TestPolicyVoteUnauditedBarrierAndConflictFencing(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
	addPolicyVoter(t, database, "voter-a")
	ctx := context.Background()
	input := policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "4", 1, time.Unix(4000, 0))
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := store.MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion)
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, input.Now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: input.Now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: input.Now.Add(3 * time.Second)})
	if !errors.Is(err, policystore.ErrUnavailable) {
		t.Fatalf("opposite unaudited vote error = %v", err)
	}
	if _, err := store.ClaimApproval(ctx, request.Key(), prepared.Vote.AuditStateVersion, "worker", input.Now.Add(3*time.Second), 2*time.Minute); !errors.Is(err, policystore.ErrUnauditedVote) {
		t.Fatalf("claim across unaudited vote error = %v", err)
	}
	if _, err := database.db.Exec(`DELETE FROM totp_secrets WHERE user_id='voter-a'`); err != nil {
		t.Fatal(err)
	}
	reconciled, err := store.ReconcilePendingAttainability(ctx, authorityID("a"), input.Now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciled.UnattainableCandidates) != 1 {
		t.Fatalf("read-only reconciliation did not enumerate blocked candidate: %+v", reconciled)
	}
	candidate := reconciled.UnattainableCandidates[0]
	if _, err := store.StageQuorumUnattainable(ctx, candidate.Key, candidate.StateVersion, input.Now.Add(3*time.Second)); !errors.Is(err, policystore.ErrUnauditedVote) {
		t.Fatalf("per-key staging crossed unaudited-vote barrier: %v", err)
	}
	fetched, err := store.Fetch(ctx, request.Key())
	if err != nil || fetched.State != policystore.StatePending || !bytes.Equal(fetched.PendingResponse, request.PendingResponse) {
		t.Fatalf("unaudited-vote barrier changed request: %+v, %v", fetched, err)
	}
	fetched.PendingResponse[0] ^= 0xff
	refetched, err := store.Fetch(ctx, request.Key())
	if err != nil || !bytes.Equal(refetched.PendingResponse, request.PendingResponse) {
		t.Fatalf("Fetch pending response was not defensively copied: %+v, %v", refetched, err)
	}
	if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-a", prepared.Vote.AuditStateVersion); err != nil {
		t.Fatal(err)
	}
	_, err = store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: input.Now.Add(4 * time.Second)})
	if !errors.Is(err, policystore.ErrVoteConflict) {
		t.Fatalf("opposite audited vote error = %v", err)
	}
}

func TestPolicySafetyScanUsesOneRootHookAndFailsOnCounterDrift(t *testing.T) {
	database, store, _, _, _, _ := newPolicyStoreHarness(t, 1, false)
	ctx := context.Background()
	scanner, ok := store.(policystore.SafetyScanner)
	if !ok {
		t.Fatal("policy store does not implement SafetyScanner")
	}
	rootChecks := 0
	if err := scanner.SafetyScan(ctx, func(request *policystore.Request) error {
		if request != nil {
			t.Fatalf("empty ledger unexpectedly inspected tombstone %+v", request.Key())
		}
		rootChecks++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rootChecks != 1 {
		t.Fatalf("root hook count = %d; want one in the complete snapshot", rootChecks)
	}
	injected := errors.New("archive invariant failed")
	if err := scanner.SafetyScan(ctx, func(*policystore.Request) error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("archive scan failure = %v; want injected error", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_authority_meta SET logical_used_bytes=1 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	err := scanner.SafetyScan(ctx, func(*policystore.Request) error { return nil })
	var drift *policystore.CounterDriftError
	if !errors.As(err, &drift) || drift.Counter != "logical_used_bytes" || drift.Stored != 1 || drift.Recomputed != 0 {
		t.Fatalf("safety scan drift = %v (%+v)", err, drift)
	}
}

func TestPolicyRecoveryCompletionClearsLeaseAndOutcomeReadyPendingIsListed(t *testing.T) {
	t.Run("activation to pending", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		now := time.Now().UTC().Truncate(time.Second)
		begin, err := store.Begin(context.Background(), policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "a", 1, now))
		if err != nil {
			t.Fatal(err)
		}
		owner := strings.Repeat("w", policystore.MaxIdentityBytes)
		lease, err := store.AcquireRecoveryLease(context.Background(), begin.Request.Key(), owner, now, 2*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		fenced := store.Fenced(lease)
		request, err := fenced.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		request, err = fenced.ActivateSubmission(context.Background(), request.Key(), request.StateVersion, now)
		if err != nil {
			t.Fatal(err)
		}
		if request.State != policystore.StatePending || request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
			t.Fatalf("activation completion retained lease: %+v", request)
		}
	})

	t.Run("vote acknowledgement without outcome", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 2, false)
		addPolicyVoter(t, database, "voter-a")
		addPolicyVoter(t, database, "voter-b")
		now := time.Now().UTC().Truncate(time.Second)
		begin, err := store.Begin(context.Background(), policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "b", 1, now))
		if err != nil {
			t.Fatal(err)
		}
		request, _ := store.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
		request, _ = store.ActivateSubmission(context.Background(), request.Key(), request.StateVersion, now)
		vote, err := store.PrepareVote(context.Background(), policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		lease, err := store.AcquireRecoveryLease(context.Background(), request.Key(), strings.Repeat("w", policystore.MaxIdentityBytes), now, 2*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Fenced(lease).PublishVoteAudit(context.Background(), request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
			t.Fatal(err)
		}
		request, err = store.GetByReviewID(context.Background(), request.ReviewID)
		if err != nil || request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
			t.Fatalf("completed vote item retained lease: %+v, %v", request, err)
		}
	})

	t.Run("audited threshold pending is recovery work", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		now := time.Now().UTC().Truncate(time.Second)
		begin, err := store.Begin(context.Background(), policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "c", 1, now))
		if err != nil {
			t.Fatal(err)
		}
		request, _ := store.MarkSubmissionAudited(context.Background(), begin.Request.Key(), begin.Request.StateVersion)
		request, _ = store.ActivateSubmission(context.Background(), request.Key(), request.StateVersion, now)
		vote, err := store.PrepareVote(context.Background(), policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishVoteAudit(context.Background(), request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
			t.Fatal(err)
		}
		page, err := store.ListRecovery(context.Background(), authorityID("a"), now, nil, 64)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Requests) != 1 || page.Requests[0].State != policystore.StatePending || page.Requests[0].Key() != request.Key() {
			t.Fatalf("outcome-ready pending recovery page = %+v", page.Requests)
		}
	})
}

func TestPolicyMatrix2BQuorumUnattainableUsesRejectionPublication(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 2, false)
	addPolicyVoter(t, database, "voter-a")
	addPolicyVoter(t, database, "voter-b")
	ctx := context.Background()
	input := policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "5", 1, time.Unix(5000, 0))
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := store.MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion)
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, input.Now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`DELETE FROM totp_secrets WHERE user_id='voter-b'`); err != nil {
		t.Fatal(err)
	}
	reconciled, err := store.ReconcilePendingAttainability(ctx, authorityID("a"), input.Now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciled.Unattainable) != 1 || reconciled.Unattainable[0] != request.Key() {
		t.Fatalf("reconciliation result = %+v", reconciled)
	}
	beforeStage, err := store.GetByReviewID(ctx, request.ReviewID)
	if err != nil || beforeStage.State != policystore.StatePending {
		t.Fatalf("read-only reconciliation mutated request: %+v, %v", beforeStage, err)
	}
	candidate := reconciled.UnattainableCandidates[0]
	if _, err := store.StageQuorumUnattainable(ctx, candidate.Key, candidate.StateVersion, input.Now.Add(2*time.Second)); err != nil {
		t.Fatalf("per-key quorum staging: %v", err)
	}
	request, err = store.GetByReviewID(ctx, request.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if request.ErrorFamily != policystore.ErrorFamilySemantic || request.FailureCode != policywire.ErrorQuorumUnattainable || request.PendingResponse == nil {
		t.Fatalf("Matrix-2b staged row = %+v", request)
	}
	request, err = store.MarkRejectionTerminalAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PublishRejection(ctx, request.Key(), request.StateVersion, input.Now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if request.State != policystore.StateError || request.ReservedBytes != 0 || request.TerminalHTTPStatus.Value != 409 {
		t.Fatalf("Matrix-2b terminal = %s reserve=%d HTTP=%d", request.State, request.ReservedBytes, request.TerminalHTTPStatus.Value)
	}
}

func TestPolicyFrozenStepUpRejectsImpossibleElectorateWithoutRow(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, true)
	if _, err := database.db.Exec(`INSERT INTO users(id,username,role,created_at) VALUES('webauthn-only','webauthn-only','operator',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`INSERT INTO webauthn_credentials(user_id,credential_id,credential,created_at) VALUES('webauthn-only',x'01',x'02',1)`); err != nil {
		t.Fatal(err)
	}
	input := policyBootstrapInput(t, public, keyID, authorityID("a"), "machine", "6", 1, time.Unix(6000, 0))
	if _, err := store.Begin(context.Background(), input); !errors.Is(err, policystore.ErrCapacity) {
		t.Fatalf("impossible step-up electorate error = %v", err)
	}
	lookup, err := store.Lookup(context.Background(), input.Key, input.Tuple)
	if err != nil || lookup.Kind != policystore.LookupAbsent {
		t.Fatalf("impossible electorate persisted a row: %+v, %v", lookup, err)
	}
}

func TestPolicyFrozenAuthRejectsMethodAndFactorDowngrade(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, true)
	addPolicyVoter(t, database, "voter-a")
	request := activatePolicyBootstrap(t, store, public, keyID, 6800, time.Unix(13_800, 0).UTC())
	ctx := context.Background()
	if _, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: time.Unix(13_802, 0).UTC()}); !errors.Is(err, policystore.ErrUnavailable) {
		t.Fatalf("frozen step-up accepted downgraded method: %v", err)
	}
	if _, err := database.db.Exec(`DELETE FROM totp_secrets WHERE user_id='voter-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnTOTP, Now: time.Unix(13_803, 0).UTC()}); !errors.Is(err, policystore.ErrUnavailable) {
		t.Fatalf("frozen step-up accepted removed factor: %v", err)
	}
	reconciled, err := store.ReconcilePendingAttainability(ctx, authorityID("a"), time.Unix(13_804, 0).UTC())
	if err != nil || len(reconciled.Unattainable) != 1 || reconciled.Unattainable[0] != request.Key() {
		t.Fatalf("downgraded frozen electorate reconciliation = %+v, %v", reconciled, err)
	}
}

func TestPolicyMatrix2AAdmissionBudgets(t *testing.T) {
	t.Run("first row retained bytes", func(t *testing.T) {
		database := openPolicyTestDB(t)
		public, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := policy.SignerKeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		input := largeRejectedPolicyInput(t, public, keyID, 1, time.Unix(6500, 0).UTC())
		floor := uint64(len(input.CanonicalRequest) + len(input.Payload))
		config := testPolicyConfig("machine", 1, false)
		config.MaxRejectionReservedBytesPerPrincipal = floor - 1
		digest, err := policystore.ConfigDigest(config)
		if err != nil {
			t.Fatal(err)
		}
		store := database.PolicyStore()
		if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{
			AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID, AccountingVersion: policystore.AccountingVersion,
			ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
			MaxRejectionReservedBytesPerPrincipal: floor - 1, Config: config,
		}); err != nil {
			t.Fatal(err)
		}
		_, err = store.Begin(context.Background(), input)
		var capacity *policystore.CapacityError
		if !errors.As(err, &capacity) || capacity.Kind != policystore.CapacityRetainedBytes {
			t.Fatalf("first-row retained-byte exhaustion error = %v", err)
		}
	})

	t.Run("rolling window", func(t *testing.T) {
		_, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		now := time.Unix(7000, 0).UTC()
		for index := 1; index <= policystore.RejectionWindowLimit; index++ {
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", index, 2, now)
			terminalizePolicyRejection(t, store, input)
		}
		input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", policystore.RejectionWindowLimit+1, 2, now)
		_, err := store.Begin(context.Background(), input)
		var capacity *policystore.CapacityError
		if !errors.As(err, &capacity) || capacity.Kind != policystore.CapacityWindow || capacity.RetryAfter <= 0 {
			t.Fatalf("window exhaustion error = %v", err)
		}
	})

	t.Run("retained rows", func(t *testing.T) {
		_, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		now := time.Unix(8000, 0).UTC()
		for index := 1; index <= policystore.RejectionRetainedRowLimit; index++ {
			input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", index, 2,
				now.Add(time.Duration(index)*time.Duration(policystore.RejectionWindowSeconds+1)*time.Second))
			terminalizePolicyRejection(t, store, input)
		}
		input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", policystore.RejectionRetainedRowLimit+1, 2,
			now.Add(time.Duration(policystore.RejectionRetainedRowLimit+1)*time.Duration(policystore.RejectionWindowSeconds+1)*time.Second))
		_, err := store.Begin(context.Background(), input)
		var capacity *policystore.CapacityError
		if !errors.As(err, &capacity) || capacity.Kind != policystore.CapacityRetainedRows {
			t.Fatalf("retained-row exhaustion error = %v", err)
		}
	})

	t.Run("retained bytes", func(t *testing.T) {
		database := openPolicyTestDB(t)
		public, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := policy.SignerKeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		first := largeRejectedPolicyInput(t, public, keyID, 1, time.Unix(9000, 0).UTC())
		floor := uint64(len(first.CanonicalRequest) + len(first.Payload))
		config := testPolicyConfig("machine", 1, false)
		config.MaxRejectionReservedBytesPerPrincipal = floor
		digest, err := policystore.ConfigDigest(config)
		if err != nil {
			t.Fatal(err)
		}
		store := database.PolicyStore()
		if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{
			AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID, AccountingVersion: policystore.AccountingVersion,
			ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
			MaxRejectionReservedBytesPerPrincipal: floor, Config: config,
		}); err != nil {
			t.Fatal(err)
		}
		begin, err := store.Begin(context.Background(), first)
		if err != nil {
			t.Fatalf("full Matrix-2a floor admission: %v", err)
		}
		if begin.Request.ReservedBytes <= floor {
			t.Fatalf("full Matrix-2a reserve = %d; want transient reserve above floor %d", begin.Request.ReservedBytes, floor)
		}
		var globalReserved uint64
		if err := database.db.QueryRow(`SELECT logical_reserved_bytes FROM policy_authority_meta WHERE singleton=1`).Scan(&globalReserved); err != nil {
			t.Fatal(err)
		}
		if globalReserved != begin.Request.ReservedBytes {
			t.Fatalf("global reserve = %d; want full transient reserve %d", globalReserved, begin.Request.ReservedBytes)
		}
		if _, err := store.VerifyAuthorityBinding(context.Background()); err != nil {
			t.Fatalf("full Matrix-2a floor safety scan: %v", err)
		}
		second := largeRejectedPolicyInput(t, public, keyID, 2, time.Unix(9001, 0).UTC())
		_, err = store.Begin(context.Background(), second)
		var capacity *policystore.CapacityError
		if !errors.As(err, &capacity) || capacity.Kind != policystore.CapacityRetainedBytes {
			t.Fatalf("retained-byte exhaustion error = %v", err)
		}
	})
}

func TestPolicyMatrix2BTerminalizesWithEveryRejectionBudgetSaturated(t *testing.T) {
	database := openPolicyTestDB(t)
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	baseTime := time.Unix(10_000, 0).UTC()
	large := largeRejectedPolicyInput(t, public, keyID, 1000, baseTime.Add(2*time.Second))
	small := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 1001, 2, baseTime)
	largeFloor := uint64(len(large.CanonicalRequest) + len(large.Payload))
	smallFloor := uint64(len(small.CanonicalRequest) + len(small.Payload))
	rejectionCap := largeFloor + uint64(policystore.RejectionRetainedRowLimit-1)*smallFloor
	config := testPolicyConfig("machine", 2, false)
	config.MaxRejectionReservedBytesPerPrincipal = rejectionCap
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	store := database.PolicyStore()
	if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{
		AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID, AccountingVersion: policystore.AccountingVersion,
		ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
		MaxRejectionReservedBytesPerPrincipal: rejectionCap, Config: config,
	}); err != nil {
		t.Fatal(err)
	}
	addPolicyVoter(t, database, "voter-a")
	addPolicyVoter(t, database, "voter-b")
	ctx := context.Background()
	accepted := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 1, 1, baseTime)
	begin, err := store.Begin(ctx, accepted)
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, baseTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	largeTerminal := terminalizePolicyRejection(t, store, large)
	largeRecord, err := store.SnapshotTerminalArchive(ctx, largeTerminal.Key(), largeTerminal.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	largeReference, _, err := largeRecord.ObjectRef()
	if err != nil {
		t.Fatal(err)
	}
	largeCompaction, err := store.CommitTerminalArchive(ctx, largeTerminal.Key(), largeTerminal.StateVersion, largeReference)
	if err != nil {
		t.Fatal(err)
	}
	largeTerminal = largeCompaction.Request
	recentTime := baseTime.Add(100 * time.Duration(policystore.RejectionWindowSeconds+1) * time.Second)
	for index := 0; index < policystore.RejectionRetainedRowLimit-1; index++ {
		admittedAt := baseTime.Add(time.Duration(index+2) * time.Duration(policystore.RejectionWindowSeconds+1) * time.Second)
		if index >= policystore.RejectionRetainedRowLimit-1-policystore.RejectionWindowLimit {
			admittedAt = recentTime
		}
		input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 1001+index, 2, admittedAt)
		terminalizePolicyRejection(t, store, input)
	}
	var retainedRows, recentRows int
	var retainedBytes uint64
	cutoff := recentTime.Unix() - policystore.RejectionWindowSeconds
	if err := database.db.QueryRow(`SELECT count(*),coalesce(sum(CASE WHEN created_at>? THEN 1 ELSE 0 END),0),coalesce(sum(reserved_bytes),0)
		FROM policy_requests WHERE principal='machine' AND error_family='semantic-rejection' AND
		failure_code IN ('invalid_policy_request','policy_request_in_progress','signer_key_changed','stale_policy_head','policy_key_transition_required')`, cutoff).
		Scan(&retainedRows, &recentRows, &retainedBytes); err != nil {
		t.Fatal(err)
	}
	if retainedRows != policystore.RejectionRetainedRowLimit || recentRows != policystore.RejectionWindowLimit ||
		retainedBytes != rejectionCap || retainedBytes+largeFloor <= rejectionCap {
		t.Fatalf("budgets are not saturated: rows=%d recent=%d bytes=%d next-large=%d large-floor=%d",
			retainedRows, recentRows, retainedBytes, largeFloor, largeTerminal.ReservedBytes)
	}
	if _, err := database.db.Exec(`DELETE FROM totp_secrets WHERE user_id='voter-b'`); err != nil {
		t.Fatal(err)
	}
	before := *request
	request, err = store.StageQuorumUnattainable(ctx, request.Key(), request.StateVersion, recentTime.Add(time.Second))
	if err != nil {
		t.Fatalf("Matrix-2b staging consulted rejection budgets: %v", err)
	}
	if !bytes.Equal(request.CanonicalRequest, before.CanonicalRequest) || !bytes.Equal(request.Payload, before.Payload) ||
		!bytes.Equal(request.PendingResponse, before.PendingResponse) || request.ResultEnvelope != nil ||
		request.ReservedBytes > before.ReservedBytes || request.LogicalBytes+request.ReservedBytes > before.LogicalBytes+before.ReservedBytes {
		t.Fatalf("Matrix-2b changed blobs or commitment: before=%d/%d after=%d/%d",
			before.LogicalBytes, before.ReservedBytes, request.LogicalBytes, request.ReservedBytes)
	}
	request, err = store.MarkRejectionTerminalAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PublishRejection(ctx, request.Key(), request.StateVersion, recentTime.Add(2*time.Second))
	if err != nil || request.State != policystore.StateError || request.ReservedBytes != 0 {
		t.Fatalf("Matrix-2b terminalization = %+v, %v", request, err)
	}
}

func TestPolicyCrossPrincipalCollisionAndExpectedKeyPrecedence(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
	addPolicyVoter(t, database, "voter-a")
	ctx := context.Background()
	now := time.Unix(11_000, 0).UTC()
	firstInput := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "principal-a", 2000, 1, now)
	first, err := store.Begin(ctx, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest, err := store.MarkSubmissionAudited(ctx, first.Request.Key(), first.Request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateSubmission(ctx, firstRequest.Key(), firstRequest.StateVersion, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	// The primary key is principal-scoped, but the authority/host active slot is
	// not: the identical request ID from another principal receives its own
	// durable Matrix-2a rejection without leaking the first row.
	crossPrincipal := firstInput
	crossPrincipal.Key.Principal = "principal-b"
	crossPrincipal.RequesterPrincipal = "principal-b"
	crossPrincipal.ReviewID = reviewID("b")
	crossPrincipal.Now = now.Add(2 * time.Second)
	collision, err := store.Begin(ctx, crossPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if collision.Request.Principal != "principal-b" || collision.Request.State != policystore.StateRejectionUnaudited ||
		collision.Request.FailureCode != policywire.ErrorPolicyRequestInProgress {
		t.Fatalf("cross-principal collision = %+v", collision.Request)
	}
	if fetched, err := store.Fetch(ctx, firstInput.Key); err != nil || fetched.State != policystore.StatePending {
		t.Fatalf("first principal fetch = %+v, %v", fetched, err)
	}
	if _, err := store.Fetch(ctx, policystore.Key{Principal: "principal-c", RequestID: firstInput.Key.RequestID}); !errors.Is(err, policystore.ErrNotFound) {
		t.Fatalf("cross-principal Fetch leaked a row: %v", err)
	}

	// An expected-key mismatch precedes the active-host check, freezes the
	// current bound signer pair, and a same-ID retry with that changed tuple is a
	// conflict against the original exact row.
	mismatched := firstInput
	mismatched.Key.Principal = "principal-c"
	mismatched.RequesterPrincipal = "principal-c"
	mismatched.Key.RequestID = requestID("c")
	mismatched.ReviewID = reviewID("c")
	mismatched.Now = now.Add(3 * time.Second)
	mismatched.Tuple.RequestID = mismatched.Key.RequestID
	mismatched.Tuple.ExpectedSignerKeyID = hex64("f")
	wireRequest, err := policywire.NewRequest(mismatched.Key.RequestID, mismatched.Tuple.HostKeyFP,
		mismatched.Tuple.ExpectedSignerKeyID, mismatched.Payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	mismatched.CanonicalRequest, err = policywire.MarshalRequest(wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	keyRejection, err := store.Begin(ctx, mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if keyRejection.Request.FailureCode != policywire.ErrorSignerKeyChanged ||
		keyRejection.Request.ExpectedSignerKeyID != hex64("f") ||
		!keyRejection.Request.FrozenSignerKeyID.Valid || keyRejection.Request.FrozenSignerKeyID.Value != keyID ||
		!bytes.Equal(keyRejection.Request.FrozenSignerPublicKey, public) {
		t.Fatalf("expected/frozen key rejection = %+v", keyRejection.Request)
	}

	changedRetry := firstInput
	changedRetry.Tuple.ExpectedSignerKeyID = hex64("f")
	retryWire, err := policywire.NewRequest(changedRetry.Key.RequestID, changedRetry.Tuple.HostKeyFP,
		changedRetry.Tuple.ExpectedSignerKeyID, changedRetry.Payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	changedRetry.CanonicalRequest, err = policywire.MarshalRequest(retryWire)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.Begin(ctx, changedRetry)
	if err != nil || retry.Lookup.Kind != policystore.LookupConflict || retry.Request != nil {
		t.Fatalf("same-ID expected-key perturbation = %+v, %v", retry, err)
	}
}

func TestPolicySuccessorPredecessorAndFinalPublicationRace(t *testing.T) {
	database, store, public, private, keyID, _ := newPolicyStoreHarness(t, 1, false)
	addPolicyVoter(t, database, "voter-a")
	ctx := context.Background()
	now := time.Unix(12_000, 0).UTC()
	published := publishPolicyBootstrap(t, store, public, private, keyID, 3000, now)
	if _, err := database.db.Exec(`UPDATE policy_heads SET manifest_envelope=manifest_envelope||x'00',
		payload_sha256=?,base_digest=?,row_version=row_version+1,logical_bytes=logical_bytes+1,updated_at=updated_at+1
		WHERE authority_id=? AND host_key_fp=?`, hex64("b"), hex64("c"), authorityID("a"), published.HostKeyFP); err == nil {
		t.Fatal("head trigger accepted a successor without an epoch/revision increase")
	}
	if _, err := database.db.Exec(`UPDATE policy_heads SET manifest_envelope=manifest_envelope||x'00',
		payload_sha256=?,base_digest=?,revision_be=x'0000000000000002',row_version=row_version+2,
		logical_bytes=logical_bytes+1,updated_at=updated_at+1 WHERE authority_id=? AND host_key_fp=?`,
		hex64("b"), hex64("c"), authorityID("a"), published.HostKeyFP); err == nil {
		t.Fatal("head trigger accepted a skipped CAS row version")
	}

	identity, err := policy.NewShellExactIdentity([]byte("echo successor"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: published.HostKeyFP, Epoch: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 2,
		Entries: []policy.BaseEntry{{ID: "pa_oob_0123456789abcdef0123456789abcdef", Identity: identity, Source: policy.EntrySourceOutOfBand}}}
	input := policySuccessorInput(t, public, keyID, published, 3001, manifest, now.Add(10*time.Second))
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request := begin.Request
	if request.Bootstrap || request.TrustedHeadEnvelope == nil || !request.TrustedHeadDigest.Valid ||
		!request.TrustedHeadKeyID.Valid || request.TrustedHeadPublicKey == nil || request.TrustedHeadEpochBE == nil ||
		request.TrustedHeadRevisionBE == nil || !request.TrustedHeadRowVersion.Valid ||
		request.ClaimedHeadEnvelope != nil || request.ClaimedHeadDigest.Valid || request.ClaimedHeadKeyID.Valid ||
		request.ClaimedHeadPublicKey != nil || request.ClaimedHeadEpochBE != nil || request.ClaimedHeadRevisionBE != nil ||
		request.ClaimedHeadRowVersion.Valid {
		t.Fatalf("successor admission predecessor sets = %+v", request)
	}
	request, err = store.MarkSubmissionAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, input.Now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	vote, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: input.Now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if vote.Vote.HeadDigest != published.BaseDigest {
		t.Fatalf("successor vote head digest = %q; want %q", vote.Vote.HeadDigest, published.BaseDigest)
	}
	if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
		t.Fatal(err)
	}
	claimBefore, err := loadPolicyRequest(ctx, database.db, request.Key())
	if err != nil {
		t.Fatal(err)
	}
	components, err := reservationComponentsForRequest(claimBefore)
	if err != nil {
		t.Fatal(err)
	}
	wantClaimedCharge := uint64(len(claimBefore.TrustedHeadEnvelope) + len(claimBefore.TrustedHeadDigest.Value) +
		len(claimBefore.TrustedHeadKeyID.Value) + len(claimBefore.TrustedHeadPublicKey) +
		len(claimBefore.TrustedHeadEpochBE) + len(claimBefore.TrustedHeadRevisionBE) + 8)
	if components.Growth.ClaimedGroup != wantClaimedCharge {
		t.Fatalf("claimed-group reservation = %d; want exact census %d", components.Growth.ClaimedGroup, wantClaimedCharge)
	}
	lease, err := store.ClaimApproval(ctx, request.Key(), vote.Vote.AuditStateVersion, "worker", input.Now.Add(3*time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.GetByReviewID(ctx, request.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if request.ClaimedHeadEnvelope == nil || !request.ClaimedHeadDigest.Valid || !request.ClaimedHeadKeyID.Valid ||
		request.ClaimedHeadPublicKey == nil || request.ClaimedHeadEpochBE == nil || request.ClaimedHeadRevisionBE == nil ||
		!request.ClaimedHeadRowVersion.Valid || !bytes.Equal(request.ClaimedHeadEnvelope, request.TrustedHeadEnvelope) ||
		request.ClaimedHeadDigest != request.TrustedHeadDigest || request.ClaimedHeadKeyID != request.TrustedHeadKeyID ||
		request.ClaimedHeadRowVersion != request.TrustedHeadRowVersion {
		t.Fatalf("successor claimed predecessor set = %+v", request)
	}
	wantClaimedRemaining, err := policystore.DeriveRemaining(policystore.RemainingInput{Components: components,
		State: policystore.StateApprovedMaterializing, ClaimedGroupConsumed: true, LeaseOwnerConsumed: true})
	if err != nil {
		t.Fatal(err)
	}
	if request.ReservedBytes != wantClaimedRemaining ||
		request.LogicalBytes+request.ReservedBytes > claimBefore.LogicalBytes+claimBefore.ReservedBytes {
		t.Fatalf("successor claim reserve/commitment: before=%d/%d after=%d/%d want reserve=%d",
			claimBefore.LogicalBytes, claimBefore.ReservedBytes, request.LogicalBytes, request.ReservedBytes, wantClaimedRemaining)
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		t.Fatalf("successor claim scan equality: %v", err)
	}
	if _, err := store.MarkPreMintAudited(ctx, lease); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(private, manifest)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PersistMaterialized(ctx, lease, envelope, input.Now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.MarkResultAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}

	type raceResult struct {
		request *policystore.Request
		err     error
	}
	start := make(chan struct{})
	results := make(chan raceResult, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		result, publishErr := store.PublishApproved(ctx, request.Key(), request.StateVersion, input.Now.Add(5*time.Second))
		results <- raceResult{request: result, err: publishErr}
	}()
	go func() {
		defer wait.Done()
		<-start
		result, stageErr := store.StagePublicationError(ctx, request.Key(), request.StateVersion,
			policywire.ErrorStalePolicyHead, input.Now.Add(5*time.Second))
		results <- raceResult{request: result, err: stageErr}
	}()
	close(start)
	wait.Wait()
	close(results)
	var winner *policystore.Request
	successes, stale := 0, 0
	for result := range results {
		if result.err == nil {
			successes++
			winner = result.request
		} else if errors.Is(result.err, policystore.ErrStaleVersion) {
			stale++
		} else {
			t.Fatalf("publication race error = %v", result.err)
		}
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("publication race outcomes: success=%d stale=%d", successes, stale)
	}
	var headVersion int
	if err := database.db.QueryRow(`SELECT row_version FROM policy_heads WHERE authority_id=? AND host_key_fp=?`, authorityID("a"), published.HostKeyFP).Scan(&headVersion); err != nil {
		t.Fatal(err)
	}
	switch winner.State {
	case policystore.StateApproved:
		if headVersion != 2 || winner.ReservedBytes != 0 {
			t.Fatalf("published race winner head/reserve = %d/%d", headVersion, winner.ReservedBytes)
		}
	case policystore.StateErrorReceived:
		if headVersion != 1 || !bytes.Equal(winner.ResultEnvelope, envelope) || winner.ErrorFamily != policystore.ErrorFamilyPublication {
			t.Fatalf("staged race winner = %+v; head=%d", winner, headVersion)
		}
		audited, err := store.MarkErrorTerminalAudited(ctx, winner.Key(), winner.StateVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishError(ctx, audited.Key(), audited.StateVersion, input.Now.Add(6*time.Second)); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unexpected publication race winner state %s", winner.State)
	}
}

func TestPolicyRecoveryLeaseTakeoverAndOwnerClearFence(t *testing.T) {
	database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
	addPolicyVoter(t, database, "voter-a")
	ctx := context.Background()
	now := time.Now().UTC()
	input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", 4000, 1, now)
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), "worker-a", now, 0); err == nil {
		t.Fatal("zero recovery lease TTL accepted")
	}
	if _, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), "worker-a", now, time.Minute); err == nil {
		t.Fatal("short recovery lease TTL accepted")
	}
	if _, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), "worker-a", now, 2*time.Minute+time.Second); err == nil {
		t.Fatal("overlong recovery lease TTL accepted")
	}
	if err := database.ClearPolicyRecoveryLease(ctx, begin.Request.ReviewID); !errors.Is(err, policystore.ErrLeaseLost) {
		t.Fatalf("generation-zero empty owner clear = %v", err)
	}
	firstOwner := strings.Repeat("w", policystore.MaxIdentityBytes)
	first, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), firstOwner, now, 2*time.Minute)
	if err != nil || !first.Until.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("first recovery lease = %+v, %v", first, err)
	}
	firstRequest, err := loadPolicyRequest(ctx, database.db, begin.Request.Key())
	if err != nil {
		t.Fatal(err)
	}
	if firstRequest.ReservedBytes+policystore.MaxIdentityBytes != begin.Request.ReservedBytes ||
		firstRequest.LogicalBytes+firstRequest.ReservedBytes != begin.Request.LogicalBytes+begin.Request.ReservedBytes {
		t.Fatalf("first owner did not consume its whole allowance: before=%d/%d after=%d/%d",
			begin.Request.LogicalBytes, begin.Request.ReservedBytes, firstRequest.LogicalBytes, firstRequest.ReservedBytes)
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		t.Fatalf("first lease scan equality: %v", err)
	}
	if _, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), "worker-b", now.Add(time.Second), 2*time.Minute); !errors.Is(err, policystore.ErrUnavailable) {
		t.Fatalf("live recovery lease takeover = %v", err)
	}
	second, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), "worker-b", now.Add(2*time.Minute+time.Second), 2*time.Minute)
	if err != nil || second.Generation != first.Generation+1 {
		t.Fatalf("expired recovery lease takeover = %+v, %v", second, err)
	}
	if _, err := store.Fenced(first).MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion); !errors.Is(err, policystore.ErrLeaseLost) {
		t.Fatalf("old recovery generation mutation = %v", err)
	}
	if err := database.ClearPolicyRecoveryLease(ctx, begin.Request.ReviewID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Fenced(second).MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion); !errors.Is(err, policystore.ErrLeaseLost) {
		t.Fatalf("owner-cleared recovery generation mutation = %v", err)
	}
	request, err := loadPolicyRequest(ctx, database.db, begin.Request.Key())
	if err != nil {
		t.Fatal(err)
	}
	if request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 || request.RecoveryLeaseGeneration != second.Generation+1 {
		t.Fatalf("owner clear result = %+v", request)
	}
	if request.ReservedBytes != firstRequest.ReservedBytes {
		t.Fatalf("takeover/clear restored owner allowance: %d != %d", request.ReservedBytes, firstRequest.ReservedBytes)
	}
	if err := database.ClearPolicyRecoveryLease(ctx, begin.Request.ReviewID); err != nil {
		t.Fatalf("post-lease empty owner clear = %v", err)
	}
	request, err = loadPolicyRequest(ctx, database.db, begin.Request.Key())
	if err != nil {
		t.Fatal(err)
	}
	if request.ReservedBytes != firstRequest.ReservedBytes || request.RecoveryLeaseGeneration != second.Generation+2 {
		t.Fatalf("post-lease empty clear reserve/generation = %d/%d", request.ReservedBytes, request.RecoveryLeaseGeneration)
	}
	third, err := store.AcquireRecoveryLease(ctx, begin.Request.Key(), "worker-c", now.Add(4*time.Minute), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseRecoveryLease(ctx, third); err != nil {
		t.Fatal(err)
	}
	request, err = loadPolicyRequest(ctx, database.db, begin.Request.Key())
	if err != nil {
		t.Fatal(err)
	}
	if request.ReservedBytes != firstRequest.ReservedBytes || request.RecoveryLeaseOwner != "" ||
		request.RecoveryLeaseUntil != 0 || request.RecoveryLeaseGeneration != third.Generation {
		t.Fatalf("reacquire/release result = %+v", request)
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		t.Fatalf("reacquire scan equality: %v", err)
	}
}

func TestPolicyGlobalActiveSlot(t *testing.T) {
	meta := policyMeta{MaxHeads: policystore.MaxHeads, MaxRequests: policystore.MaxFullRequests,
		MaxActiveGlobal: policystore.MaxActiveGlobal, MaxActivePerPrincipal: policystore.MaxActivePerPrincipal}
	if err := checkPolicyAdmissionCounts(meta, 0, policystore.MaxActiveGlobal-1, 0, false, false); err != nil {
		t.Fatalf("last global active slot refused: %v", err)
	}
	err := checkPolicyAdmissionCounts(meta, 0, policystore.MaxActiveGlobal, 0, false, false)
	var capacity *policystore.CapacityError
	if !errors.As(err, &capacity) || capacity.Kind != policystore.CapacityGlobalHeadroom {
		t.Fatalf("global active slot overflow = %v", err)
	}
	if err := checkPolicyAdmissionCounts(meta, 0, policystore.MaxActiveGlobal, 0, true, true); err != nil {
		t.Fatalf("Matrix-2a incorrectly consumed an active slot: %v", err)
	}
}

func TestPolicyVoteRaces(t *testing.T) {
	t.Run("duplicate and opposite", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		request := activatePolicyBootstrap(t, store, public, keyID, 7000, time.Unix(14_000, 0).UTC())
		ctx := context.Background()
		start := make(chan struct{})
		type voteOutcome struct {
			result policystore.VoteResult
			err    error
		}
		outcomes := make(chan voteOutcome, 12)
		var wait sync.WaitGroup
		for index := 0; index < cap(outcomes); index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				result, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
					Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: time.Unix(14_002, 0).UTC()})
				outcomes <- voteOutcome{result: result, err: err}
			}()
		}
		close(start)
		wait.Wait()
		close(outcomes)
		for outcome := range outcomes {
			if outcome.err != nil || outcome.result.Vote == nil || outcome.result.Vote.AuditStateVersion != 2 || !outcome.result.NeedsAudit {
				t.Fatalf("duplicate vote result = %+v, %v", outcome.result, outcome.err)
			}
		}
		var voteCount int
		if err := database.db.QueryRow(`SELECT count(*) FROM policy_votes WHERE principal=? AND request_id=?`,
			request.Principal, request.RequestID).Scan(&voteCount); err != nil {
			t.Fatal(err)
		}
		if voteCount != 1 {
			t.Fatalf("duplicate vote race wrote %d rows", voteCount)
		}
		if _, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
			Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: time.Unix(14_003, 0).UTC()}); !errors.Is(err, policystore.ErrUnavailable) {
			t.Fatalf("opposite probe against unaudited winner = %v", err)
		}
		if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-a", 2); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
			Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: time.Unix(14_004, 0).UTC()}); !errors.Is(err, policystore.ErrVoteConflict) {
			t.Fatalf("opposite probe against audited winner = %v", err)
		}
	})

	t.Run("opposite concurrent", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		request := activatePolicyBootstrap(t, store, public, keyID, 7100, time.Unix(15_000, 0).UTC())
		ctx := context.Background()
		start := make(chan struct{})
		outcomes := make(chan error, 2)
		var wait sync.WaitGroup
		for _, decision := range []policystore.Decision{policystore.DecisionApprove, policystore.DecisionDeny} {
			decision := decision
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				_, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
					Decision: decision, AuthnMethod: policystore.AuthnSession, Now: time.Unix(15_002, 0).UTC()})
				outcomes <- err
			}()
		}
		close(start)
		wait.Wait()
		close(outcomes)
		successes, unavailable := 0, 0
		for err := range outcomes {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, policystore.ErrUnavailable):
				unavailable++
			default:
				t.Fatalf("opposite concurrent vote error = %v", err)
			}
		}
		if successes != 1 || unavailable != 1 {
			t.Fatalf("opposite concurrent outcomes: success=%d unavailable=%d", successes, unavailable)
		}
	})

	t.Run("deny veto wins", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		addPolicyVoter(t, database, "voter-b")
		request := activatePolicyBootstrap(t, store, public, keyID, 7200, time.Unix(16_000, 0).UTC())
		ctx := context.Background()
		approve, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
			Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: time.Unix(16_002, 0).UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-a", approve.Vote.AuditStateVersion); err != nil {
			t.Fatal(err)
		}
		deny, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-b",
			Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: time.Unix(16_003, 0).UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-b", deny.Vote.AuditStateVersion); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ClaimApproval(ctx, request.Key(), deny.Vote.AuditStateVersion, "worker", time.Unix(16_004, 0).UTC(), 2*time.Minute); !errors.Is(err, policystore.ErrConflict) {
			t.Fatalf("approval overtook deny veto: %v", err)
		}
		claimed, err := store.ClaimDenial(ctx, request.Key(), deny.Vote.AuditStateVersion, time.Unix(16_004, 0).UTC())
		if err != nil || claimed.State != policystore.StateDenialReceived {
			t.Fatalf("deny-veto claim = %+v, %v", claimed, err)
		}
	})

	t.Run("one approval claim", func(t *testing.T) {
		database, store, public, _, keyID, _ := newPolicyStoreHarness(t, 1, false)
		addPolicyVoter(t, database, "voter-a")
		request := activatePolicyBootstrap(t, store, public, keyID, 7300, time.Unix(17_000, 0).UTC())
		ctx := context.Background()
		vote, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
			Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: time.Unix(17_002, 0).UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		outcomes := make(chan error, 8)
		var wait sync.WaitGroup
		for index := 0; index < cap(outcomes); index++ {
			index := index
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				_, err := store.ClaimApproval(ctx, request.Key(), vote.Vote.AuditStateVersion,
					fmt.Sprintf("worker-%d", index), time.Unix(17_003, 0).UTC(), 2*time.Minute)
				outcomes <- err
			}()
		}
		close(start)
		wait.Wait()
		close(outcomes)
		successes, stale := 0, 0
		for err := range outcomes {
			if err == nil {
				successes++
			} else if errors.Is(err, policystore.ErrStaleVersion) {
				stale++
			} else {
				t.Fatalf("approval claim race error = %v", err)
			}
		}
		if successes != 1 || stale != cap(outcomes)-1 {
			t.Fatalf("approval claim race outcomes: success=%d stale=%d", successes, stale)
		}
	})
}

func newPolicyStoreHarness(t *testing.T, approvals uint64, stepUp bool) (*DB, policystore.Store, ed25519.PublicKey, ed25519.PrivateKey, string, policystore.ConfigDigestInput) {
	t.Helper()
	database := openPolicyTestDB(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	config := testPolicyConfig("machine", approvals, stepUp)
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	store := database.PolicyStore()
	if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{AuthorityID: authorityID("a"), ArchiveID: config.ArchiveID,
		AccountingVersion: policystore.AccountingVersion, ConfigDigest: digest, SignerKeyID: keyID, SignerPublicKey: public,
		MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config}); err != nil {
		t.Fatal(err)
	}
	return database, store, public, private, keyID, config
}

func addPolicyVoter(t *testing.T, database *DB, voter string) {
	t.Helper()
	if _, err := database.db.Exec(`INSERT INTO users(id,username,role,created_at) VALUES(?,?, 'operator',1)`, voter, voter); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`INSERT INTO totp_secrets(user_id,secret,created_at) VALUES(?,'secret',1)`, voter); err != nil {
		t.Fatal(err)
	}
}

func policyBootstrapInput(t *testing.T, public ed25519.PublicKey, keyID, authority, principal, suffix string, epoch uint64, now time.Time) policystore.BeginInput {
	t.Helper()
	host := "SHA256:" + strings.Repeat("A", 43)
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: host, Epoch: epoch,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wireRequest, err := policywire.NewRequest(requestID(suffix), host, keyID, payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policywire.MarshalRequest(wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA, _, _ := policywire.PayloadDigests(payload)
	review := []byte(`{"summary":"bootstrap"}`)
	return policystore.BeginInput{Key: policystore.Key{Principal: principal, RequestID: wireRequest.RequestID},
		Tuple: policyauthority.RequestTuple{RequestID: wireRequest.RequestID, Purpose: policywire.Purpose, HostKeyFP: host,
			ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA, Bootstrap: true}, CanonicalRequest: canonical, Payload: payload,
		AuthorityID: authority, ReviewID: reviewID(suffix), RequesterPrincipal: principal, SignerKeyID: keyID,
		SignerPublicKey: public, ReviewJSON: review, ReviewRenderedBytes: int64(len(review)), ReviewItemCount: 1,
		ReviewRendererVersion: "sshgate-policy-review-v2", ReviewRulesDigest: hex64("e"), Now: now}
}

func policyBootstrapInputNumber(t *testing.T, public ed25519.PublicKey, keyID, authority, principal string, number int, epoch uint64, now time.Time) policystore.BeginInput {
	t.Helper()
	host := "SHA256:" + strings.Repeat("A", 43)
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: host, Epoch: epoch,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	return policyBeginInputForManifest(t, public, keyID, authority, principal, number, manifest, now)
}

func policyBeginInputForManifest(t *testing.T, public ed25519.PublicKey, keyID, authority, principal string, number int, manifest policy.BaseManifest, now time.Time) policystore.BeginInput {
	t.Helper()
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request := fmt.Sprintf("pm_%032x", number)
	wireRequest, err := policywire.NewRequest(request, manifest.Host, keyID, payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policywire.MarshalRequest(wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA, _, err := policywire.PayloadDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	review := []byte(`{"summary":"bootstrap"}`)
	return policystore.BeginInput{Key: policystore.Key{Principal: principal, RequestID: request},
		Tuple: policyauthority.RequestTuple{RequestID: request, Purpose: policywire.Purpose, HostKeyFP: manifest.Host,
			ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA, Bootstrap: true}, CanonicalRequest: canonical, Payload: payload,
		AuthorityID: authority, ReviewID: fmt.Sprintf("pr_%032x", number), RequesterPrincipal: principal, SignerKeyID: keyID,
		SignerPublicKey: public, ReviewJSON: review, ReviewRenderedBytes: int64(len(review)), ReviewItemCount: 1,
		ReviewRendererVersion: "sshgate-policy-review-v2", ReviewRulesDigest: hex64("e"), Now: now}
}

func largeRejectedPolicyInput(t *testing.T, public ed25519.PublicKey, keyID string, number int, now time.Time) policystore.BeginInput {
	t.Helper()
	host := "SHA256:" + strings.Repeat("A", 43)
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: host, Epoch: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	for index := 1; index <= 64; index++ {
		identity, err := policy.NewShellExactIdentity(bytes.Repeat([]byte{'x'}, 16<<10))
		if err != nil {
			t.Fatal(err)
		}
		manifest.Entries = append(manifest.Entries, policy.BaseEntry{ID: fmt.Sprintf("pa_oob_%032x", index), Identity: identity, Source: policy.EntrySourceOutOfBand})
	}
	return policyBeginInputForManifest(t, public, keyID, authorityID("a"), "machine", number, manifest, now)
}

func terminalizePolicyRejection(t *testing.T, store policystore.Store, input policystore.BeginInput) *policystore.Request {
	t.Helper()
	ctx := context.Background()
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatalf("begin rejection %s: %v", input.Key.RequestID, err)
	}
	request := begin.Request
	if request.State != policystore.StateRejectionUnaudited {
		t.Fatalf("%s state = %s; want rejection", input.Key.RequestID, request.State)
	}
	request, err = store.MarkRejectionSubmissionAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.StageRejectionError(ctx, request.Key(), request.StateVersion, input.Now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.MarkRejectionTerminalAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PublishRejection(ctx, request.Key(), request.StateVersion, input.Now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func publishPolicyBootstrap(t *testing.T, store policystore.Store, public ed25519.PublicKey, private ed25519.PrivateKey,
	keyID string, number int, now time.Time) *policystore.Request {
	t.Helper()
	ctx := context.Background()
	input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", number, 1, now)
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	vote, err := store.PrepareVote(ctx, policystore.VoteInput{ReviewID: request.ReviewID, Operator: "voter-a",
		Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishVoteAudit(ctx, request.Key(), "voter-a", vote.Vote.AuditStateVersion); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimApproval(ctx, request.Key(), vote.Vote.AuditStateVersion, "worker", now.Add(3*time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkPreMintAudited(ctx, lease); err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeRequest(input.CanonicalRequest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(private, decoded.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PersistMaterialized(ctx, lease, envelope, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.MarkResultAudited(ctx, request.Key(), request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.PublishApproved(ctx, request.Key(), request.StateVersion, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func activatePolicyBootstrap(t *testing.T, store policystore.Store, public ed25519.PublicKey, keyID string,
	number int, now time.Time) *policystore.Request {
	t.Helper()
	ctx := context.Background()
	input := policyBootstrapInputNumber(t, public, keyID, authorityID("a"), "machine", number, 1, now)
	begin, err := store.Begin(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.MarkSubmissionAudited(ctx, begin.Request.Key(), begin.Request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	request, err = store.ActivateSubmission(ctx, request.Key(), request.StateVersion, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func policySuccessorInput(t *testing.T, public ed25519.PublicKey, keyID string, predecessor *policystore.Request,
	number int, manifest policy.BaseManifest, now time.Time) policystore.BeginInput {
	t.Helper()
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request := fmt.Sprintf("pm_%032x", number)
	wireRequest, err := policywire.NewRequest(request, manifest.Host, keyID, payload, predecessor.BaseDigest, false)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policywire.MarshalRequest(wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA, _, err := policywire.PayloadDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	review := []byte(`{"summary":"successor"}`)
	return policystore.BeginInput{Key: policystore.Key{Principal: "machine", RequestID: request},
		Tuple: policyauthority.RequestTuple{RequestID: request, Purpose: policywire.Purpose, HostKeyFP: manifest.Host,
			ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA, ExpectedHeadDigest: predecessor.BaseDigest},
		CanonicalRequest: canonical, Payload: payload, AuthorityID: authorityID("a"), ReviewID: fmt.Sprintf("pr_%032x", number),
		RequesterPrincipal: "machine", SignerKeyID: keyID, SignerPublicKey: public, ReviewJSON: review,
		ReviewRenderedBytes: int64(len(review)), ReviewItemCount: 1, ReviewRendererVersion: "sshgate-policy-review-v2",
		ReviewRulesDigest: hex64("e"), Now: now}
}

func testPolicyConfig(requester string, approvals uint64, stepUp bool) policystore.ConfigDigestInput {
	config := policystore.DefaultConfigDigestInput()
	config.RequesterOperatorID = requester
	config.RequiredApprovals = approvals
	config.DenyVeto = true
	config.PolicyVoterRole = "operator"
	config.VoterEligibilityVersion = "v1"
	config.VoteStepUpRequired = stepUp
	config.VoteAuthMethodsJSON = []byte(`["session"]`)
	if stepUp {
		config.VoteAuthMethodsJSON = []byte(`["totp"]`)
	}
	config.ArchiveID = archiveID("a")
	config.ReviewRendererVersion = "sshgate-policy-review-v2"
	config.ReviewRulesDigest = hex64("e")
	return config
}
