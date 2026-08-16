package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ordinary "github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/redact"
)

const (
	testPolicyAuthority = "pauth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPolicyArchiveID = "parch_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPolicyHost      = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

type testPolicyAudit struct {
	mu       sync.Mutex
	readyErr error
	calls    []signerkit.AuditCall
	verdicts []signerkit.AuditVerdict
}

func (audit *testPolicyAudit) PolicyAuditReady(context.Context) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	return audit.readyErr
}
func (audit *testPolicyAudit) Call(_ context.Context, event signerkit.AuditCall) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.readyErr != nil {
		return audit.readyErr
	}
	audit.calls = append(audit.calls, event)
	return nil
}
func (audit *testPolicyAudit) Verdict(_ context.Context, event signerkit.AuditVerdict) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.readyErr != nil {
		return audit.readyErr
	}
	audit.verdicts = append(audit.verdicts, event)
	return nil
}
func (audit *testPolicyAudit) fail(err error) {
	audit.mu.Lock()
	audit.readyErr = err
	audit.mu.Unlock()
}

type testPolicyCore struct {
	mu         sync.RWMutex
	private    ed25519.PrivateKey
	public     ed25519.PublicKey
	keyID      string
	failMint   bool
	mintCalls  atomic.Int64
	deadlineMu sync.Mutex
	deadlines  []time.Duration
}

func newTestPolicyCore(t testing.TB) *testPolicyCore {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return &testPolicyCore{private: private, public: public, keyID: keyID}
}

func (core *testPolicyCore) SnapshotBaseManifestSigner() (ed25519.PublicKey, string, error) {
	core.mu.RLock()
	defer core.mu.RUnlock()
	return append(ed25519.PublicKey(nil), core.public...), core.keyID, nil
}
func (core *testPolicyCore) WithBaseManifestSignerIfCurrent(keyID string, publicKey ed25519.PublicKey, commit func() error) error {
	core.mu.RLock()
	defer core.mu.RUnlock()
	if keyID != core.keyID || !bytes.Equal(publicKey, core.public) {
		return signerkit.ErrSignerKeyChanged
	}
	return commit()
}
func (core *testPolicyCore) MaterializeBaseManifestContext(ctx context.Context, keyID, host string, payload []byte) (signerkit.BaseManifestMaterialization, error) {
	core.mintCalls.Add(1)
	if deadline, ok := ctx.Deadline(); ok {
		core.deadlineMu.Lock()
		core.deadlines = append(core.deadlines, time.Until(deadline))
		core.deadlineMu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return signerkit.BaseManifestMaterialization{}, err
	}
	core.mu.RLock()
	defer core.mu.RUnlock()
	if core.failMint {
		return signerkit.BaseManifestMaterialization{}, errors.New("injected HSM failure")
	}
	if keyID != core.keyID {
		return signerkit.BaseManifestMaterialization{}, signerkit.ErrSignerKeyChanged
	}
	manifest, err := policy.ParseBaseManifest(payload)
	if err != nil || manifest.Host != host {
		return signerkit.BaseManifestMaterialization{}, errors.New("invalid materialization payload")
	}
	envelope, err := policy.SignBaseManifest(core.private, manifest)
	return signerkit.BaseManifestMaterialization{PublicKey: append(ed25519.PublicKey(nil), core.public...), SignerKeyID: core.keyID, Envelope: envelope}, err
}

func (core *testPolicyCore) rotate(t testing.TB) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	core.mu.Lock()
	core.public, core.private, core.keyID = public, private, keyID
	core.mu.Unlock()
}

type embeddedPolicyStore struct{ policystore.Store }

type admissionCaptureStore struct {
	policystore.Store
	head    policystore.VerifiedHeadView
	headErr error
	inputs  []policystore.BeginInput
}

func (store *admissionCaptureStore) VerifiedHead(context.Context, string) (policystore.VerifiedHeadView, error) {
	return store.head, store.headErr
}

func (store *admissionCaptureStore) Begin(_ context.Context, input policystore.BeginInput) (policystore.BeginResult, error) {
	input.CanonicalRequest = slices.Clone(input.CanonicalRequest)
	input.Payload = slices.Clone(input.Payload)
	input.SignerPublicKey = slices.Clone(input.SignerPublicKey)
	input.ReviewJSON = slices.Clone(input.ReviewJSON)
	store.inputs = append(store.inputs, input)
	return policystore.BeginResult{Lookup: policystore.LookupResult{Kind: policystore.LookupExact}}, nil
}

func TestPolicyAdmissionRendersCompleteReviewWithFreshSalt(t *testing.T) {
	core := newTestPolicyCore(t)
	store := &admissionCaptureStore{headErr: policystore.ErrNotFound}
	randomBytes := append(bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 48)...)
	var salts [][32]byte
	engine, err := NewPolicyEngine(PolicyEngineConfig{
		AuthorityID: testPolicyAuthority, WorkerID: "worker", Store: store, Core: core, Audit: &testPolicyAudit{},
		Now: func() time.Time { return time.Unix(20_000, 0).UTC() }, Random: bytes.NewReader(randomBytes),
		ReviewRules: []redact.Rule{{ID: "test"}},
		RedactString: func(_ string, salt [32]byte, _ []redact.Rule) (string, bool) {
			salts = append(salts, salt)
			return fmt.Sprintf("salt-%02x", salt[0]), true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 2; index++ {
		admission := testPolicyAdmission(t, core.keyID, fmt.Sprintf("pm_%032x", index), "", true, 1)
		if _, err := engine.Admit(context.Background(), admission); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.inputs) != 2 || len(salts) != 2 || salts[0] == salts[1] {
		t.Fatalf("renders=%d salts=%x/%x", len(store.inputs), salts[0], salts[1])
	}
	for index, input := range store.inputs {
		if len(input.ReviewJSON) == 0 || input.ReviewRenderedBytes != int64(len(input.ReviewJSON)) || input.ReviewItemCount != 2 ||
			input.ReviewRendererVersion != policyreview.RendererVersion || input.ReviewRulesDigest != policyreview.RulesDigest() {
			t.Fatalf("review group %d = %+v", index, input)
		}
		if marker := fmt.Sprintf(`"text":"salt-%02x"`, index+1); !bytes.Contains(input.ReviewJSON, []byte(marker)) {
			t.Fatalf("review %d missing salt marker %q: %s", index, marker, input.ReviewJSON)
		}
	}
}

func TestPolicyAdmissionUnsafeHeadMappingPassesNoReview(t *testing.T) {
	core := newTestPolicyCore(t)
	store := &admissionCaptureStore{head: policystore.VerifiedHeadView{Head: policystore.Head{BaseDigest: strings.Repeat("1", 64)}}}
	engine := newTestEngine(t, store, core, &testPolicyAudit{}, time.Unix(20_100, 0).UTC(), nil)
	admission := testPolicyAdmission(t, core.keyID, "pm_99999999999999999999999999999999", strings.Repeat("2", 64), false, 2)
	if _, err := engine.Admit(context.Background(), admission); err != nil {
		t.Fatal(err)
	}
	if len(store.inputs) != 1 {
		t.Fatalf("Begin calls = %d", len(store.inputs))
	}
	input := store.inputs[0]
	if input.ReviewJSON != nil || input.ReviewRenderedBytes != 0 || input.ReviewItemCount != 0 || input.ReviewRendererVersion != "" || input.ReviewRulesDigest != "" {
		t.Fatalf("unsafe mapping fabricated review data: %+v", input)
	}
}

func testPolicyAdmission(t testing.TB, keyID, requestID, expectedHead string, bootstrap bool, revision uint64) PolicyAdmissionInput {
	t.Helper()
	identity, err := policy.NewShellExactIdentity([]byte("echo <review>"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: testPolicyHost, Epoch: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: revision,
		Entries: []policy.BaseEntry{{ID: "pa_oob_11111111111111111111111111111111", Identity: identity, Source: policy.EntrySourceOutOfBand}}}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := policywire.NewRequest(requestID, testPolicyHost, keyID, payload, expectedHead, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policywire.MarshalRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeRequest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return PolicyAdmissionInput{Principal: "machine", CanonicalRequest: canonical, Decoded: decoded}
}

type workerPolicyStore struct {
	policystore.Store
	rosterCalls    atomic.Int64
	recoveryCalls  atomic.Int64
	releases       atomic.Int64
	rosterSignal   chan struct{}
	recoverySignal chan struct{}
}

func (store *workerPolicyStore) ReconcilePendingAttainability(context.Context, string, time.Time) (policystore.AttainabilityResult, error) {
	store.rosterCalls.Add(1)
	select {
	case store.rosterSignal <- struct{}{}:
	default:
	}
	return policystore.AttainabilityResult{}, nil
}
func (store *workerPolicyStore) ListUnauditedVotes(context.Context, string, *policystore.RecoveryCursor, int) (policystore.VoteRecoveryPage, error) {
	return policystore.VoteRecoveryPage{}, nil
}
func (store *workerPolicyStore) ListRecovery(context.Context, string, time.Time, *policystore.RecoveryCursor, int) (policystore.RecoveryPage, error) {
	store.recoveryCalls.Add(1)
	select {
	case store.recoverySignal <- struct{}{}:
	default:
	}
	return policystore.RecoveryPage{}, nil
}
func (store *workerPolicyStore) ReleaseRecoveryLease(context.Context, policystore.Lease) error {
	store.releases.Add(1)
	return nil
}

type rosterPolicyStore struct {
	policystore.Store
	candidates []policystore.AttainabilityCandidate
	staged     []policystore.AttainabilityCandidate
}

type startupPolicyStore struct {
	policystore.Store
	bindErr   error
	scanErr   error
	rosterErr error
}

func (store *startupPolicyStore) BindAuthority(context.Context, policystore.AuthorityBinding) error {
	return store.bindErr
}
func (store *startupPolicyStore) SafetyScan(_ context.Context, inspect func(*policystore.Request) error) error {
	if store.scanErr != nil {
		return store.scanErr
	}
	return inspect(nil)
}
func (store *startupPolicyStore) ReconcilePendingAttainability(context.Context, string, time.Time) (policystore.AttainabilityResult, error) {
	return policystore.AttainabilityResult{}, store.rosterErr
}
func (store *startupPolicyStore) ListUnauditedVotes(context.Context, string, *policystore.RecoveryCursor, int) (policystore.VoteRecoveryPage, error) {
	return policystore.VoteRecoveryPage{}, nil
}
func (store *startupPolicyStore) ListRecovery(context.Context, string, time.Time, *policystore.RecoveryCursor, int) (policystore.RecoveryPage, error) {
	return policystore.RecoveryPage{}, nil
}

type startupPolicyDatabase struct {
	store   policystore.Store
	closed  atomic.Bool
	onClose func()
}

func (database *startupPolicyDatabase) PolicyStore() policystore.Store { return database.store }
func (database *startupPolicyDatabase) Close() error {
	database.closed.Store(true)
	if database.onClose != nil {
		database.onClose()
	}
	return nil
}

func (store *rosterPolicyStore) ReconcilePendingAttainability(context.Context, string, time.Time) (policystore.AttainabilityResult, error) {
	return policystore.AttainabilityResult{UnattainableCandidates: append([]policystore.AttainabilityCandidate(nil), store.candidates...)}, nil
}
func (store *rosterPolicyStore) StageQuorumUnattainable(_ context.Context, key policystore.Key, version uint64, _ time.Time) (*policystore.Request, error) {
	candidate := policystore.AttainabilityCandidate{Key: key, StateVersion: version}
	store.staged = append(store.staged, candidate)
	switch len(store.staged) {
	case 1:
		return nil, policystore.ErrStaleVersion
	case 2:
		return nil, policystore.ErrUnauditedVote
	case 3:
		return nil, policystore.ErrConflict
	default:
		return &policystore.Request{}, nil
	}
}

func TestPolicyAuditMetadataCarriesDistinctFrozenEvidence(t *testing.T) {
	core := newTestPolicyCore(t)
	request := &policystore.Request{
		Principal: "machine", RequestID: "pm_11111111111111111111111111111111", AuthorityID: testPolicyAuthority,
		Purpose: policywire.Purpose, TupleDigest: strings.Repeat("1", 64), HostKeyFP: testPolicyHost,
		PayloadSHA256: strings.Repeat("2", 64), BaseDigest: strings.Repeat("3", 64),
		ExpectedSignerKeyID: strings.Repeat("0", 64), FrozenSignerKeyID: policystore.NullableString{Value: core.keyID, Valid: true},
		FrozenSignerPublicKey: core.public, EpochBE: uint64Bytes(7), RevisionBE: uint64Bytes(9),
		TrustedHeadEpochBE: uint64Bytes(1), TrustedHeadRevisionBE: uint64Bytes(2),
		ClaimedHeadEpochBE: uint64Bytes(3), ClaimedHeadRevisionBE: uint64Bytes(4),
		MissAction: "ask", Growth: "sign-to-add", StateVersion: 6,
	}
	metadata, err := policyAuditMetadataForRequest(request, policyAuditPhaseMaterialization, "attempt", request.StateVersion, "voter", "totp")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SignerKeyID != request.ExpectedSignerKeyID || metadata.Evidence == nil ||
		metadata.Evidence.ExpectedSignerKeyID != request.ExpectedSignerKeyID || metadata.Evidence.FrozenSignerKeyID != core.keyID ||
		metadata.Evidence.TrustedEpoch != "1" || metadata.Evidence.ClaimedRevision != "4" {
		t.Fatalf("metadata evidence collapsed identities: %+v", metadata)
	}
	wantID := policyauthority.AuditEventID(policyauthority.AuditEvent{AuthorityID: request.AuthorityID, Purpose: request.Purpose,
		Principal: request.Principal, RequestID: request.RequestID, TupleDigest: request.TupleDigest,
		Phase: policyAuditPhaseMaterialization, StateVersion: request.StateVersion})
	if metadata.EventID != wantID {
		t.Fatalf("event ID = %s; want %s", metadata.EventID, wantID)
	}
}

func TestPolicyFaultPointsAreCompleteAndUnique(t *testing.T) {
	if len(AllPolicyFaultPoints) != 19 {
		t.Fatalf("fault point count = %d; want 19", len(AllPolicyFaultPoints))
	}
	seen := make(map[PolicyFaultPoint]bool)
	for _, point := range AllPolicyFaultPoints {
		if point == "" || seen[point] {
			t.Fatalf("invalid duplicate fault point %q", point)
		}
		seen[point] = true
	}
}

func TestPolicyRosterSweepStagesEveryCandidateIndependently(t *testing.T) {
	core := newTestPolicyCore(t)
	audit := &testPolicyAudit{}
	store := &rosterPolicyStore{candidates: []policystore.AttainabilityCandidate{
		{Key: policystore.Key{Principal: "one", RequestID: "pm_11111111111111111111111111111111"}, StateVersion: 1},
		{Key: policystore.Key{Principal: "two", RequestID: "pm_22222222222222222222222222222222"}, StateVersion: 2},
		{Key: policystore.Key{Principal: "three", RequestID: "pm_33333333333333333333333333333333"}, StateVersion: 3},
		{Key: policystore.Key{Principal: "four", RequestID: "pm_44444444444444444444444444444444"}, StateVersion: 4},
	}}
	engine := newTestEngine(t, store, core, audit, time.Now().UTC(), nil)
	if err := engine.RosterSweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.staged) != len(store.candidates) {
		t.Fatalf("staged candidates = %d; want %d", len(store.staged), len(store.candidates))
	}
	for index := range store.candidates {
		if store.staged[index] != store.candidates[index] {
			t.Fatalf("stage[%d] = %+v; want %+v", index, store.staged[index], store.candidates[index])
		}
	}
	if len(audit.calls) != 0 || len(audit.verdicts) != 0 {
		t.Fatal("DB-only roster sweep performed external audit")
	}
}

func TestPolicyEngineFaultMatrixRecoversEveryBoundary(t *testing.T) {
	for _, point := range AllPolicyFaultPoints {
		point := point
		t.Run(string(point), func(t *testing.T) {
			database, store, core, audit, input := newHostedPolicyHarness(t, 1)
			defer database.Close()
			crash := fmt.Errorf("crash at %s", point)
			clock := input.Now
			engine := newTestEngine(t, store, core, audit, clock, func(got PolicyFaultPoint) error {
				if got == point {
					return crash
				}
				return nil
			})

			var runErr error
			switch faultScenario(point) {
			case "rejection":
				input.Tuple.ExpectedSignerKeyID = strings.Repeat("0", 64)
				input.SignerKeyID = core.keyID
				wireRequest, err := policywire.NewRequest(input.Key.RequestID, testPolicyHost, input.Tuple.ExpectedSignerKeyID, input.Payload, "", true)
				if err != nil {
					t.Fatal(err)
				}
				input.CanonicalRequest, err = policywire.MarshalRequest(wireRequest)
				if err != nil {
					t.Fatal(err)
				}
				_, runErr = engine.Submit(context.Background(), input)
			case "denial":
				_, runErr = engine.Submit(context.Background(), input)
				if runErr == nil {
					_, runErr = engine.Vote(context.Background(), policystore.VoteInput{ReviewID: input.ReviewID, Operator: "voter", Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: clock})
				}
			case "mint-error":
				_, runErr = engine.Submit(context.Background(), input)
				core.failMint = true
				if runErr == nil {
					_, runErr = engine.Vote(context.Background(), policystore.VoteInput{ReviewID: input.ReviewID, Operator: "voter", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: clock})
				}
			default:
				_, runErr = engine.Submit(context.Background(), input)
				if runErr == nil {
					_, runErr = engine.Vote(context.Background(), policystore.VoteInput{ReviewID: input.ReviewID, Operator: "voter", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: clock})
				}
			}
			if !errors.Is(runErr, crash) {
				t.Fatalf("injected boundary error = %v; want %v", runErr, crash)
			}

			recovery := newTestEngine(t, store, core, audit, clock.Add(5*time.Minute), nil)
			if err := recovery.RecoverOnce(context.Background()); err != nil {
				t.Fatalf("recovery after %s: %v", point, err)
			}
			if point == PolicyFaultAfterMaterializedPersisted && core.mintCalls.Load() != 1 {
				t.Fatalf("approved_unexposed recovery reminted after persist: count=%d", core.mintCalls.Load())
			}
			fetched, err := store.Fetch(context.Background(), input.Key)
			if err != nil {
				t.Fatal(err)
			}
			if fetched.State == policystore.StateReceivedUnaudited || fetched.State == policystore.StateRejectionUnaudited ||
				fetched.State == policystore.StateApprovedMaterializing || fetched.State == policystore.StateApprovedUnexposed ||
				fetched.State == policystore.StateDenialReceived || fetched.State == policystore.StateErrorReceived {
				t.Fatalf("recovery left hidden boundary state %q", fetched.State)
			}
		})
	}
}

func TestPolicyRecoveryUsesOneLeaseEightAttemptsAndBoundedBackoff(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	defer database.Close()
	clock := input.Now
	crash := errors.New("crash after claim")
	claimEngine := newTestEngine(t, store, core, audit, clock, func(point PolicyFaultPoint) error {
		if point == PolicyFaultAfterApprovalClaimed {
			return crash
		}
		return nil
	})
	if _, err := claimEngine.Submit(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := claimEngine.Vote(context.Background(), policystore.VoteInput{ReviewID: input.ReviewID, Operator: "voter", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: clock}); !errors.Is(err, crash) {
		t.Fatalf("claim crash = %v", err)
	}
	claimed, err := store.GetByReviewID(context.Background(), input.ReviewID)
	if err != nil || claimed.State != policystore.StateApprovedMaterializing {
		t.Fatalf("claimed row = %+v, %v", claimed, err)
	}
	claimedGeneration := claimed.RecoveryLeaseGeneration
	core.failMint = true
	core.mintCalls.Store(0)
	core.deadlineMu.Lock()
	core.deadlines = nil
	core.deadlineMu.Unlock()
	var delays []time.Duration
	recoveryNow := clock.Add(5 * time.Minute)
	recovery, err := NewPolicyEngine(PolicyEngineConfig{
		AuthorityID: testPolicyAuthority, WorkerID: strings.Repeat("w", policystore.MaxIdentityBytes),
		Store: store, Core: core, Audit: audit, Now: func() time.Time { return recoveryNow },
		Sleep: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
		Jitter: func(delay time.Duration) time.Duration { return delay },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.RecoverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	staged, err := store.GetByReviewID(context.Background(), input.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if staged.State != policystore.StateErrorReceived || staged.RecoveryLeaseGeneration != claimedGeneration+1 || staged.RecoveryLeaseOwner != "" || staged.RecoveryLeaseUntil != 0 {
		t.Fatalf("exhaustion staging/lease = %+v", staged)
	}
	if err := recovery.RecoverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if core.mintCalls.Load() != policyRecoveryMaxAttempts {
		t.Fatalf("mint attempts = %d; want %d", core.mintCalls.Load(), policyRecoveryMaxAttempts)
	}
	wantDelays := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	if len(delays) != len(wantDelays) {
		t.Fatalf("backoff count = %d; want %d (%v)", len(delays), len(wantDelays), delays)
	}
	for index := range wantDelays {
		if delays[index] != wantDelays[index] || delays[index] > policyRecoveryBackoffMax {
			t.Fatalf("backoff[%d] = %s; want %s", index, delays[index], wantDelays[index])
		}
	}
	core.deadlineMu.Lock()
	deadlines := append([]time.Duration(nil), core.deadlines...)
	core.deadlineMu.Unlock()
	if len(deadlines) != policyRecoveryMaxAttempts {
		t.Fatalf("deadline count = %d; want %d", len(deadlines), policyRecoveryMaxAttempts)
	}
	for index, budget := range deadlines {
		if budget <= 0 || budget > policyRecoveryAttemptMax+100*time.Millisecond {
			t.Fatalf("attempt deadline[%d] = %s", index, budget)
		}
	}
	terminal, err := store.GetByReviewID(context.Background(), input.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.State != policystore.StateError || terminal.FailureCode != policywire.ErrorPolicyMaterializationFailed ||
		terminal.RecoveryLeaseGeneration != claimedGeneration+2 || terminal.RecoveryLeaseOwner != "" || terminal.RecoveryLeaseUntil != 0 {
		t.Fatalf("exhaustion terminal/lease = %+v", terminal)
	}
}

func TestPolicyRecoveryLeasesAndPublishesMatrix2AWithExpectedIdentity(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	defer database.Close()
	expected := strings.Repeat("0", 64)
	input.Tuple.ExpectedSignerKeyID = expected
	wireRequest, err := policywire.NewRequest(input.Key.RequestID, testPolicyHost, expected, input.Payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	input.CanonicalRequest, err = policywire.MarshalRequest(wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	crash := errors.New("crash after Matrix-2a submission audit")
	engine := newTestEngine(t, store, core, audit, input.Now, func(point PolicyFaultPoint) error {
		if point == PolicyFaultAfterSubmissionAudit {
			return crash
		}
		return nil
	})
	if _, err := engine.Submit(context.Background(), input); !errors.Is(err, crash) {
		t.Fatalf("Matrix-2a crash = %v", err)
	}
	recovery := newTestEngine(t, store, core, audit, input.Now.Add(5*time.Minute), nil)
	if err := recovery.RecoverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	request, err := store.GetByReviewID(context.Background(), input.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if request.State != policystore.StateError || request.RecoveryLeaseGeneration == 0 || request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
		t.Fatalf("Matrix-2a recovery/lease = %+v", request)
	}
	decoded, err := policywire.DecodeResponse(request.TerminalResponse)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Wire.SignerKeyID != expected || decoded.Wire.SignerKeyID == core.keyID {
		t.Fatalf("Matrix-2a machine signer ID = %q; expected immutable %q, frozen %q", decoded.Wire.SignerKeyID, expected, core.keyID)
	}
}

func TestPolicyRecoveryStagesRotatedPersistedResultWithoutRemint(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	defer database.Close()
	crash := errors.New("crash after persist")
	engine := newTestEngine(t, store, core, audit, input.Now, func(point PolicyFaultPoint) error {
		if point == PolicyFaultAfterMaterializedPersisted {
			return crash
		}
		return nil
	})
	if _, err := engine.Submit(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Vote(context.Background(), policystore.VoteInput{ReviewID: input.ReviewID, Operator: "voter", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Now: input.Now}); !errors.Is(err, crash) {
		t.Fatalf("persist crash = %v", err)
	}
	if core.mintCalls.Load() != 1 {
		t.Fatalf("initial mint count = %d", core.mintCalls.Load())
	}
	core.rotate(t)
	recovery := newTestEngine(t, store, core, audit, input.Now.Add(5*time.Minute), nil)
	if err := recovery.RecoverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if core.mintCalls.Load() != 1 {
		t.Fatalf("approved_unexposed recovery reminted: count=%d", core.mintCalls.Load())
	}
	request, err := store.GetByReviewID(context.Background(), input.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	if request.State != policystore.StateError || request.ErrorFamily != policystore.ErrorFamilyPublication ||
		request.FailureCode != policywire.ErrorSignerKeyChanged || request.ResultEnvelope == nil ||
		request.RecoveryLeaseOwner != "" || request.RecoveryLeaseUntil != 0 {
		t.Fatalf("rotated result recovery = %+v", request)
	}
}

func faultScenario(point PolicyFaultPoint) string {
	switch point {
	case PolicyFaultAfterRejectionStaged:
		return "rejection"
	case PolicyFaultAfterDenialClaimed, PolicyFaultAfterNoMintAudit, PolicyFaultAfterNoMintAcknowledged:
		return "denial"
	case PolicyFaultAfterErrorStaged:
		return "mint-error"
	default:
		return "approval"
	}
}

func TestPolicyRoutesMountedBehindUniformReadinessAndStickyAudit(t *testing.T) {
	core := newTestPolicyCore(t)
	audit := &testPolicyAudit{}
	engine := newTestEngine(t, &embeddedPolicyStore{}, core, audit, time.Now().UTC(), nil)
	lease, archive := testPolicyArchive(t)
	defer lease.Close()
	defer archive.Close()

	server := NewServer("secret", nil, log.New(io.Discard, "", 0))
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	var handled atomic.Int64
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		handled.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	})
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: handler, Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	paths := []struct{ method, path string }{
		{http.MethodPost, "/v2/policy/base-manifests"},
		{http.MethodGet, "/v2/policy/base-manifests/pm_11111111111111111111111111111111"},
		{http.MethodGet, "/ui/policy/pending"},
		{http.MethodGet, "/ui/policy/requests/pr_11111111111111111111111111111111"},
		{http.MethodPost, "/ui/policy/requests/pr_11111111111111111111111111111111/approve"},
		{http.MethodPost, "/ui/policy/requests/pr_11111111111111111111111111111111/deny"},
		{http.MethodGet, "/ui/policy/requests/pr_11111111111111111111111111111111/audit"},
	}
	for _, route := range paths {
		request := httptest.NewRequest(route.method, route.path, nil)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"policy authority unavailable\"}\n" ||
			response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("pre-ready %s %s = %d %q headers=%v", route.method, route.path, response.Code, response.Body.String(), response.Header())
		}
	}
	invalidResponse := httptest.NewRecorder()
	server.ServeHTTP(invalidResponse, httptest.NewRequest(http.MethodGet, "/v2/policy/not-a-route", nil))
	if invalidResponse.Code != http.StatusNotFound {
		t.Fatalf("invalid pre-ready policy target = %d; want unmounted 404", invalidResponse.Code)
	}
	ordinaryResponse := httptest.NewRecorder()
	server.ServeHTTP(ordinaryResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if ordinaryResponse.Code != http.StatusOK {
		t.Fatalf("ordinary health while policy unready = %d", ordinaryResponse.Code)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	readyRequest := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", nil)
	readyRequest.Header.Set("Authorization", "Bearer secret")
	readyResponse := httptest.NewRecorder()
	server.ServeHTTP(readyResponse, readyRequest)
	if readyResponse.Code != http.StatusNoContent || handled.Load() != 1 {
		t.Fatalf("ready route = %d handled=%d", readyResponse.Code, handled.Load())
	}
	sticky := errors.New("audit inode changed")
	audit.fail(sticky)
	failedResponse := httptest.NewRecorder()
	server.ServeHTTP(failedResponse, readyRequest)
	if failedResponse.Code != http.StatusServiceUnavailable || engine.Readiness().Ready() || handled.Load() != 1 {
		t.Fatalf("sticky audit did not close policy: code=%d ready=%v handled=%d", failedResponse.Code, engine.Readiness().Ready(), handled.Load())
	}
	ordinaryResponse = httptest.NewRecorder()
	server.ServeHTTP(ordinaryResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if ordinaryResponse.Code != http.StatusOK {
		t.Fatalf("sticky policy audit affected ordinary v1 liveness: %d", ordinaryResponse.Code)
	}
}

func TestPolicyServerOwnsTwoWorkersAndJoinsWithoutLeaseClear(t *testing.T) {
	core := newTestPolicyCore(t)
	audit := &testPolicyAudit{}
	store := &workerPolicyStore{rosterSignal: make(chan struct{}, 4), recoverySignal: make(chan struct{}, 1)}
	engine, err := NewPolicyEngine(PolicyEngineConfig{
		AuthorityID: testPolicyAuthority, WorkerID: strings.Repeat("w", policystore.MaxIdentityBytes),
		Store: store, Core: core, Audit: audit,
		Sleep: sleepPolicyContext, Jitter: func(delay time.Duration) time.Duration { return delay },
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, archive := testPolicyArchive(t)
	defer lease.Close()
	defer archive.Close()
	server := NewServer("secret", nil, log.New(io.Discard, "", 0))
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	server.policyRosterWait = 5 * time.Millisecond
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: http.NotFoundHandler(), Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.StartPolicyWorkers(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.recoverySignal:
	case <-time.After(time.Second):
		t.Fatal("RECOVERY worker did not run")
	}
	if policyRosterSweepInterval != 30*time.Second {
		t.Fatalf("production roster interval = %s; want 30s", policyRosterSweepInterval)
	}
	for sweep := 0; sweep < 3; sweep++ {
		select {
		case <-store.rosterSignal:
		case <-time.After(time.Second):
			t.Fatalf("ROSTER worker completed only %d independent sweeps", sweep)
		}
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if engine.Readiness().Ready() {
		t.Fatal("Server.Close left policy ready")
	}
	if store.releases.Load() != 0 {
		t.Fatalf("shutdown cleared %d row leases", store.releases.Load())
	}
	rosterAfterClose := store.rosterCalls.Load()
	recoveryAfterClose := store.recoveryCalls.Load()
	time.Sleep(15 * time.Millisecond)
	if store.rosterCalls.Load() != rosterAfterClose || store.recoveryCalls.Load() != recoveryAfterClose {
		t.Fatal("policy worker continued after Server.Close joined it")
	}
}

func TestPolicyStartupOrdersLeaseDatabaseArchiveAuditMountScanAndWorkers(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(root, "policy.db")
	archiveRoot := filepath.Join(root, "archive")
	if err := os.Mkdir(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	auditParent := filepath.Join(root, "audit")
	if err := os.Mkdir(auditParent, 0o700); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(auditParent, "policy.jsonl")
	core := newTestPolicyCore(t)
	config := testPolicyStoreConfig(1)
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	binding := policystore.AuthorityBinding{
		AuthorityID: testPolicyAuthority, ArchiveID: testPolicyArchiveID,
		AccountingVersion: policystore.AccountingVersion, ConfigDigest: digest,
		MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config,
	}
	var phases []string
	startup := PolicyStartupConfig{
		DatabasePath: databasePath, ArchiveRoot: archiveRoot, Binding: binding,
		WorkerID: strings.Repeat("w", policystore.MaxIdentityBytes), Core: core,
		OpenDatabase: func() (PolicyDatabase, error) {
			if _, err := os.Stat(databasePath + ".policy-maintenance.lock"); err != nil {
				return nil, fmt.Errorf("lease missing before DB open: %w", err)
			}
			phases = append(phases, "database")
			database, err := sqlitestore.Open(databasePath)
			if err != nil {
				return nil, err
			}
			for _, user := range []string{"machine", "voter"} {
				if err := database.CreateUser(context.Background(), &ordinary.User{ID: user, Username: user, Role: ordinary.Role("operator")}); err != nil {
					return nil, err
				}
				if err := database.SetTOTP(context.Background(), user, "secret"); err != nil {
					return nil, err
				}
			}
			return database, nil
		},
		OpenAudit: func() (signerkit.DurableAuditSink, error) {
			if _, err := os.Stat(databasePath); err != nil {
				return nil, fmt.Errorf("audit opened before DB: %w", err)
			}
			if info, err := os.Stat(archiveRoot); err != nil || !info.IsDir() {
				return nil, errors.New("audit opened before archive root validation")
			}
			phases = append(phases, "audit")
			return signerkit.NewDurableFileAuditSink(auditPath)
		},
		BuildServer: func(database PolicyDatabase) (*Server, error) {
			for _, shard := range []string{"00", "ff"} {
				if info, err := os.Stat(filepath.Join(archiveRoot, shard)); err != nil || !info.IsDir() {
					return nil, fmt.Errorf("server built before shard %s", shard)
				}
			}
			phases = append(phases, "server")
			ordinaryDatabase, ok := database.(*sqlitestore.DB)
			if !ok {
				return nil, errors.New("unexpected database type")
			}
			server := NewServer("secret", ordinaryDatabase, log.New(io.Discard, "", 0))
			server.MachineClientID = "machine"
			server.Human = &HumanAPI{}
			return server, nil
		},
		BuildHandler: func(_ *PolicyEngine, _ *policyarchive.Archive) (http.Handler, error) {
			phases = append(phases, "handler")
			return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }), nil
		},
		StopIntake: func() error {
			phases = append(phases, "stop-http")
			return nil
		},
	}
	runtime, err := StartPolicy(context.Background(), startup)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(phases, ",") != "database,audit,server,handler" {
		t.Fatalf("startup phases = %v", phases)
	}
	request := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	runtime.Server.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !runtime.Engine.Readiness().Ready() {
		t.Fatalf("policy not ready after complete startup: code=%d ready=%v", response.Code, runtime.Engine.Readiness().Ready())
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if phases[len(phases)-1] != "stop-http" {
		t.Fatalf("shutdown did not stop HTTP intake: %v", phases)
	}
	exclusive, err := policyarchive.AcquireMaintenanceLease(databasePath, policyarchive.LeaseExclusive)
	if err != nil {
		t.Fatalf("maintenance lease was not released last: %v", err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRuntimeShutdownOrder(t *testing.T) {
	store := &startupPolicyStore{}
	config, databasePath, _ := minimalPolicyStartup(t, store)
	databaseValue, err := config.OpenDatabase()
	if err != nil {
		t.Fatal(err)
	}
	database, ok := databaseValue.(*startupPolicyDatabase)
	if !ok {
		t.Fatal("minimal startup did not expose its test database")
	}
	var runtime *PolicyRuntime
	var order []string
	database.onClose = func() {
		order = append(order, "database")
		if runtime == nil || runtime.Lease == nil {
			t.Fatal("database closed without maintenance lease")
		}
		if err := runtime.Lease.Revalidate(); err != nil {
			t.Fatalf("database closed after maintenance lease release: %v", err)
		}
	}
	config.StopIntake = func() error {
		order = append(order, "http")
		if runtime == nil || runtime.Engine.Readiness().Ready() {
			t.Fatal("HTTP intake stopped before policy became unready")
		}
		if database.closed.Load() {
			t.Fatal("HTTP intake stopped after database close")
		}
		return nil
	}
	runtime, err = StartPolicy(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "http,database" {
		t.Fatalf("shutdown order = %v", order)
	}
	exclusive, err := policyarchive.AcquireMaintenanceLease(databasePath, policyarchive.LeaseExclusive)
	if err != nil {
		t.Fatalf("maintenance lease was not released last: %v", err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyStartupRefusesEveryFailedPrerequisiteBeforeReadiness(t *testing.T) {
	t.Run("incomplete configuration", func(t *testing.T) {
		if runtime, err := StartPolicy(context.Background(), PolicyStartupConfig{}); err == nil || runtime != nil {
			t.Fatalf("incomplete startup = %+v, %v", runtime, err)
		}
	})

	t.Run("database failure stops later work and releases lease", func(t *testing.T) {
		config, databasePath, _ := minimalPolicyStartup(t, &startupPolicyStore{})
		openedAudit := false
		config.OpenDatabase = func() (PolicyDatabase, error) { return nil, errors.New("database failed") }
		config.OpenAudit = func() (signerkit.DurableAuditSink, error) {
			openedAudit = true
			return &testPolicyAudit{}, nil
		}
		if _, err := StartPolicy(context.Background(), config); err == nil || !strings.Contains(err.Error(), "open database") {
			t.Fatalf("database startup failure = %v", err)
		}
		if openedAudit {
			t.Fatal("audit opened after database failure")
		}
		exclusive, err := policyarchive.AcquireMaintenanceLease(databasePath, policyarchive.LeaseExclusive)
		if err != nil {
			t.Fatal(err)
		}
		exclusive.Close()
	})

	t.Run("archive root failure precedes audit", func(t *testing.T) {
		store := &startupPolicyStore{}
		config, _, archiveRoot := minimalPolicyStartup(t, store)
		if err := os.Chmod(archiveRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		openedAudit := false
		config.OpenAudit = func() (signerkit.DurableAuditSink, error) {
			openedAudit = true
			return &testPolicyAudit{}, nil
		}
		if _, err := StartPolicy(context.Background(), config); err == nil || !strings.Contains(err.Error(), "archive root") {
			t.Fatalf("archive startup failure = %v", err)
		}
		if openedAudit {
			t.Fatal("audit opened after archive root failure")
		}
	})

	t.Run("audit readiness precedes bind", func(t *testing.T) {
		bindSentinel := errors.New("bind should not run")
		store := &startupPolicyStore{bindErr: bindSentinel}
		config, _, _ := minimalPolicyStartup(t, store)
		auditFailure := errors.New("audit recovery intent not clear")
		config.OpenAudit = func() (signerkit.DurableAuditSink, error) { return &testPolicyAudit{readyErr: auditFailure}, nil }
		if _, err := StartPolicy(context.Background(), config); !errors.Is(err, auditFailure) || errors.Is(err, bindSentinel) {
			t.Fatalf("audit readiness startup failure = %v", err)
		}
	})

	t.Run("binding failure precedes shards and mount", func(t *testing.T) {
		bindFailure := errors.New("key reused by another authority")
		store := &startupPolicyStore{bindErr: bindFailure}
		config, _, archiveRoot := minimalPolicyStartup(t, store)
		built := false
		config.BuildServer = func(PolicyDatabase) (*Server, error) {
			built = true
			return nil, errors.New("unexpected build")
		}
		if _, err := StartPolicy(context.Background(), config); !errors.Is(err, bindFailure) {
			t.Fatalf("binding startup failure = %v", err)
		}
		if built {
			t.Fatal("server built after binding failure")
		}
		if _, err := os.Stat(filepath.Join(archiveRoot, "00")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("shard created after binding failure: %v", err)
		}
	})

	t.Run("shard invariant precedes mount", func(t *testing.T) {
		store := &startupPolicyStore{}
		config, _, archiveRoot := minimalPolicyStartup(t, store)
		if err := os.WriteFile(filepath.Join(archiveRoot, "00"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		built := false
		config.BuildServer = func(PolicyDatabase) (*Server, error) {
			built = true
			return nil, errors.New("unexpected build")
		}
		if _, err := StartPolicy(context.Background(), config); err == nil || !strings.Contains(err.Error(), "archive shards") {
			t.Fatalf("shard startup failure = %v", err)
		}
		if built {
			t.Fatal("server built after shard failure")
		}
	})

	t.Run("safety scan and roster sweep gate readiness", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			scanErr   error
			rosterErr error
		}{
			{name: "scan", scanErr: errors.New("counter drift")},
			{name: "roster", rosterErr: errors.New("roster unavailable")},
		} {
			t.Run(test.name, func(t *testing.T) {
				store := &startupPolicyStore{scanErr: test.scanErr, rosterErr: test.rosterErr}
				config, _, _ := minimalPolicyStartup(t, store)
				runtime, err := StartPolicy(context.Background(), config)
				if err == nil || runtime != nil {
					t.Fatalf("gating prerequisite accepted: runtime=%+v err=%v", runtime, err)
				}
				if test.scanErr != nil && !errors.Is(err, test.scanErr) {
					t.Fatalf("scan failure = %v", err)
				}
				if test.rosterErr != nil && !errors.Is(err, test.rosterErr) {
					t.Fatalf("roster failure = %v", err)
				}
			})
		}
	})
}

func minimalPolicyStartup(t testing.TB, store policystore.Store) (PolicyStartupConfig, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(root, "policy.db")
	archiveRoot := filepath.Join(root, "archive")
	if err := os.Mkdir(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	core := newTestPolicyCore(t)
	digestConfig := testPolicyStoreConfig(1)
	digest, err := policystore.ConfigDigest(digestConfig)
	if err != nil {
		t.Fatal(err)
	}
	database := &startupPolicyDatabase{store: store}
	config := PolicyStartupConfig{
		DatabasePath: databasePath, ArchiveRoot: archiveRoot,
		Binding: policystore.AuthorityBinding{AuthorityID: testPolicyAuthority, ArchiveID: testPolicyArchiveID,
			AccountingVersion: policystore.AccountingVersion, ConfigDigest: digest,
			MaxRejectionReservedBytesPerPrincipal: digestConfig.MaxRejectionReservedBytesPerPrincipal, Config: digestConfig},
		WorkerID: strings.Repeat("w", policystore.MaxIdentityBytes), Core: core,
		OpenDatabase: func() (PolicyDatabase, error) { return database, nil },
		OpenAudit:    func() (signerkit.DurableAuditSink, error) { return &testPolicyAudit{}, nil },
		BuildServer: func(PolicyDatabase) (*Server, error) {
			server := NewServer("secret", nil, log.New(io.Discard, "", 0))
			server.MachineClientID = "machine"
			server.Human = &HumanAPI{}
			return server, nil
		},
		BuildHandler: func(*PolicyEngine, *policyarchive.Archive) (http.Handler, error) { return http.NotFoundHandler(), nil },
		StopIntake:   func() error { return nil },
	}
	return config, databasePath, archiveRoot
}

func newHostedPolicyHarness(t testing.TB, approvals uint64) (*sqlitestore.DB, policystore.Store, *testPolicyCore, *testPolicyAudit, policystore.BeginInput) {
	t.Helper()
	database, err := sqlitestore.Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"machine", "voter"} {
		if err := database.CreateUser(context.Background(), &ordinary.User{ID: user, Username: user, Role: ordinary.Role("operator"), CreatedAt: time.Unix(1, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := database.SetTOTP(context.Background(), user, "secret"); err != nil {
			t.Fatal(err)
		}
	}
	core := newTestPolicyCore(t)
	config := testPolicyStoreConfig(approvals)
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	store := database.PolicyStore()
	if err := store.BindAuthority(context.Background(), policystore.AuthorityBinding{
		AuthorityID: testPolicyAuthority, ArchiveID: testPolicyArchiveID, AccountingVersion: policystore.AccountingVersion,
		ConfigDigest: digest, SignerKeyID: core.keyID, SignerPublicKey: core.public,
		MaxRejectionReservedBytesPerPrincipal: config.MaxRejectionReservedBytesPerPrincipal, Config: config,
	}); err != nil {
		t.Fatal(err)
	}
	audit := &testPolicyAudit{}
	return database, store, core, audit, testPolicyBeginInput(t, core, 1, time.Now().UTC().Truncate(time.Second))
}

func newTestEngine(t testing.TB, store policystore.Store, core PolicyCustody, audit signerkit.DurableAuditSink, now time.Time, fault func(PolicyFaultPoint) error) *PolicyEngine {
	t.Helper()
	engine, err := NewPolicyEngine(PolicyEngineConfig{
		AuthorityID: testPolicyAuthority, WorkerID: strings.Repeat("w", policystore.MaxIdentityBytes),
		Store: store, Core: core, Audit: audit, Now: func() time.Time { return now }, Fault: fault,
		Sleep: func(context.Context, time.Duration) error { return nil }, Jitter: func(delay time.Duration) time.Duration { return delay },
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func testPolicyStoreConfig(approvals uint64) policystore.ConfigDigestInput {
	config := policystore.DefaultConfigDigestInput()
	config.RequesterOperatorID = "machine"
	config.RequiredApprovals = approvals
	config.DenyVeto = true
	config.PolicyVoterRole = "operator"
	config.VoterEligibilityVersion = "v1"
	config.VoteAuthMethodsJSON = []byte(`["session"]`)
	config.ArchiveID = testPolicyArchiveID
	config.ReviewRendererVersion = policyreview.RendererVersion
	config.ReviewRulesDigest = policyreview.RulesDigest()
	return config
}

func testPolicyBeginInput(t testing.TB, core *testPolicyCore, number int, now time.Time) policystore.BeginInput {
	t.Helper()
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: testPolicyHost, Epoch: 1, MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requestID := fmt.Sprintf("pm_%032x", number)
	reviewID := fmt.Sprintf("pr_%032x", number)
	wireRequest, err := policywire.NewRequest(requestID, testPolicyHost, core.keyID, payload, "", true)
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
	return policystore.BeginInput{
		Key: policystore.Key{Principal: "machine", RequestID: requestID},
		Tuple: policyauthority.RequestTuple{RequestID: requestID, Purpose: policywire.Purpose, HostKeyFP: testPolicyHost,
			ExpectedSignerKeyID: core.keyID, PayloadSHA256: payloadSHA, Bootstrap: true},
		CanonicalRequest: canonical, Payload: payload, AuthorityID: testPolicyAuthority, ReviewID: reviewID,
		RequesterPrincipal: "machine", SignerKeyID: core.keyID, SignerPublicKey: core.public,
		ReviewJSON: review, ReviewRenderedBytes: int64(len(review)), ReviewItemCount: 1,
		ReviewRendererVersion: policyreview.RendererVersion, ReviewRulesDigest: policyreview.RulesDigest(), Now: now,
	}
}

func testPolicyArchive(t testing.TB) (*policyarchive.MaintenanceLease, *policyarchive.Archive) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "archive")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(filepath.Dir(root), "policy.db")
	lease, err := policyarchive.AcquireMaintenanceLease(databasePath, policyarchive.LeaseShared)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := policyarchive.OpenServing(root, lease)
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	return lease, archive
}

func uint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}
