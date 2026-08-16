package hosted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ordinary "github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/pquerna/otp/totp"
)

type policyHumanTestStore struct {
	policystore.Store
	rows       map[string]*policystore.Request
	pending    []*policystore.Request
	votes      map[policystore.Key][]*policystore.Vote
	getErr     error
	listErr    error
	prepareErr error
	prepared   []policystore.VoteInput
}

func (store *policyHumanTestStore) GetByReviewID(_ context.Context, reviewID string) (*policystore.Request, error) {
	if store.getErr != nil {
		return nil, store.getErr
	}
	row := store.rows[reviewID]
	if row == nil || !row.SubmissionAudited {
		return nil, policystore.ErrNotFound
	}
	copy := *row
	copy.FrozenSignerPublicKey = slices.Clone(row.FrozenSignerPublicKey)
	copy.ReviewJSON = slices.Clone(row.ReviewJSON)
	return &copy, nil
}

func (store *policyHumanTestStore) ListPending(context.Context, string, *policystore.PendingCursor, int) (policystore.PendingPage, error) {
	if store.listErr != nil {
		return policystore.PendingPage{}, store.listErr
	}
	return policystore.PendingPage{Requests: slices.Clone(store.pending)}, nil
}

func (store *policyHumanTestStore) ListVotes(_ context.Context, key policystore.Key, _ *policystore.VoteCursor, _ int) (policystore.VotePage, error) {
	if store.listErr != nil {
		return policystore.VotePage{}, store.listErr
	}
	return policystore.VotePage{Votes: slices.Clone(store.votes[key])}, nil
}

func (store *policyHumanTestStore) PrepareVote(_ context.Context, input policystore.VoteInput) (policystore.VoteResult, error) {
	store.prepared = append(store.prepared, input)
	if store.prepareErr != nil {
		return policystore.VoteResult{}, store.prepareErr
	}
	return policystore.VoteResult{Vote: &policystore.Vote{Principal: "machine", RequestID: "pm_1", Operator: input.Operator,
		Decision: input.Decision, AuthnMethod: input.AuthnMethod, Timestamp: input.Now.Unix(), Audited: true},
		NeedsAudit: false, Tally: policystore.TallyResult{Approvals: 1, Denials: 1, Unaudited: 99}}, nil
}

func newPolicyHumanHandlerFixture(t testing.TB) (*policyHumanHandler, *policyHumanTestStore, *policystore.Request, *testPolicyCore) {
	t.Helper()
	core := newTestPolicyCore(t)
	review := []byte(`{"contract":"sshgate-policy-review-v2","purpose":"base_manifest_sign_v1","principal":"machine","request_id":"pm_11111111111111111111111111111111","review_id":"pr_11111111111111111111111111111111","authority_id":"pauth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","host":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","bootstrap":true,"epoch":"1","revision":"1","miss_action":"ask","growth":"sign-to-add","entry_count":"0","revocation_count":"0","logical_change_count":"1","axes_changed":true,"items":[{"kind":"axes"}],"warnings":[],"marker":"\u003cscript\u003e"}`)
	digest := sha256.Sum256(review)
	row := &policystore.Request{Principal: "machine", RequestID: "pm_11111111111111111111111111111111",
		ReviewID: "pr_11111111111111111111111111111111", AuthorityID: testPolicyAuthority,
		StorageKind: policystore.StorageFull, Purpose: policywire.Purpose, BaseDigest: strings.Repeat("b", 64),
		HostKeyFP: testPolicyHost, ExpectedSignerKeyID: core.keyID, Bootstrap: true,
		FrozenSignerKeyID: policystore.NullableString{Value: core.keyID, Valid: true}, FrozenSignerPublicKey: slices.Clone(core.public),
		ReviewJSON: review, ReviewSHA256: policystore.NullableString{Value: hex.EncodeToString(digest[:]), Valid: true},
		ReviewRenderedBytes:   policystore.NullableInt64{Value: int64(len(review)), Valid: true},
		ReviewItemCount:       policystore.NullableInt64{Value: 1, Valid: true},
		ReviewRendererVersion: policystore.NullableString{Value: policyreview.RendererVersion, Valid: true},
		ReviewRulesDigest:     policystore.NullableString{Value: policyreview.RulesDigest(), Valid: true},
		RequiredApprovals:     2, DenyVeto: true, State: policystore.StatePending, StateVersion: 2,
		SubmissionAudited: true, CreatedAt: 7}
	store := &policyHumanTestStore{rows: map[string]*policystore.Request{row.ReviewID: row},
		pending: []*policystore.Request{row}, votes: map[policystore.Key][]*policystore.Vote{row.Key(): {
			{Principal: row.Principal, RequestID: row.RequestID, Operator: "zeta", Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnTOTP, Timestamp: 10, Audited: true},
			{Principal: row.Principal, RequestID: row.RequestID, Operator: "hidden", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Timestamp: 1, Audited: false},
			{Principal: row.Principal, RequestID: row.RequestID, Operator: "alpha", Decision: policystore.DecisionApprove, AuthnMethod: policystore.AuthnSession, Timestamp: 5, Audited: true},
		}}}
	engine := newTestEngine(t, store, core, &testPolicyAudit{}, time.Unix(20_000, 0).UTC(), nil)
	lease, archive := testPolicyArchive(t)
	t.Cleanup(func() { _ = archive.Close() })
	t.Cleanup(func() { _ = lease.Close() })
	human := &HumanAPI{Auth: &AuthManager{cfg: AuthConfig{RPOrigins: []string{"https://signer.example.com"}}}}
	handler, err := newPolicyHumanHandler(engine, archive, human)
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, row, core
}

func policyHumanRequest(t testing.TB, handler *policyHumanHandler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Origin", "https://signer.example.com")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeAuthenticated(response, request, "voter")
	return response
}

func TestPolicyHumanR75WireShapesR76ProjectionAndR78Digests(t *testing.T) {
	handler, store, row, core := newPolicyHumanHandlerFixture(t)

	second := *row
	second.ReviewID = "pr_00000000000000000000000000000000"
	second.RequestID = "pm_00000000000000000000000000000000"
	second.CreatedAt = row.CreatedAt
	second.ReviewJSON = nil
	second.ReviewSHA256 = policystore.NullableString{}
	second.ReviewRenderedBytes = policystore.NullableInt64{}
	second.ReviewItemCount = policystore.NullableInt64{}
	second.ReviewRendererVersion = policystore.NullableString{}
	second.ReviewRulesDigest = policystore.NullableString{}
	store.rows[second.ReviewID] = &second
	store.pending = []*policystore.Request{row, &second}
	store.votes[second.Key()] = nil

	pending := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/pending", "")
	wantPending := fmt.Sprintf(`{"pending":[{"review_id":"%s","principal":"machine","request_id":"%s","purpose":"base_manifest_sign_v1","host":"%s","state":"pending","created_at":7,"approvals":0,"denials":0,"required_approvals":2,"deny_veto":true,"bootstrap":true},{"review_id":"%s","principal":"machine","request_id":"%s","purpose":"base_manifest_sign_v1","host":"%s","state":"pending","created_at":7,"approvals":1,"denials":1,"required_approvals":2,"deny_veto":true,"bootstrap":true}]}`,
		second.ReviewID, second.RequestID, testPolicyHost, row.ReviewID, row.RequestID, testPolicyHost) + "\n"
	if pending.Code != http.StatusOK || pending.Body.String() != wantPending {
		t.Fatalf("pending = %d %s\nwant %s", pending.Code, pending.Body.String(), wantPending)
	}

	detail := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/requests/"+row.ReviewID, "")
	keyB64 := base64.StdEncoding.EncodeToString(core.public)
	wantDetail := fmt.Sprintf(`{"review_id":"%s","state":"pending","created_at":7,"keys":{"expected_signer_key_id":"%s","frozen_signer_key_id":"%s","frozen_signer_public_key_b64":"%s","mismatch":false},"digests":{"candidate_base_digest":"%s"},"tally":{"approvals":1,"denials":1,"required_approvals":2,"deny_veto":true},"votes":[{"operator":"alpha","decision":"approve","authn_method":"session","ts":5},{"operator":"zeta","decision":"deny","authn_method":"totp","ts":10}],"review":%s}`,
		row.ReviewID, core.keyID, core.keyID, keyB64, row.BaseDigest, row.ReviewJSON) + "\n"
	if detail.Code != http.StatusOK || detail.Body.String() != wantDetail || strings.Contains(detail.Body.String(), "hidden") {
		t.Fatalf("detail = %d %s\nwant %s", detail.Code, detail.Body.String(), wantDetail)
	}
	if !bytes.Contains(detail.Body.Bytes(), append([]byte(`"review":`), row.ReviewJSON...)) {
		t.Fatal("detail did not embed the admission-frozen review bytes verbatim")
	}

	audit := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/requests/"+row.ReviewID+"/audit", "")
	wantAudit := fmt.Sprintf(`{"review_id":"%s","state":"pending","keys":{"expected_signer_key_id":"%s","frozen_signer_key_id":"%s","frozen_signer_public_key_b64":"%s","mismatch":false},"digests":{"candidate_base_digest":"%s"},"votes":[{"operator":"alpha","decision":"approve","authn_method":"session","ts":5},{"operator":"zeta","decision":"deny","authn_method":"totp","ts":10}]}`,
		row.ReviewID, core.keyID, core.keyID, keyB64, row.BaseDigest) + "\n"
	if audit.Code != http.StatusOK || audit.Body.String() != wantAudit || strings.Contains(audit.Body.String(), "tally") {
		t.Fatalf("audit = %d %s\nwant %s", audit.Code, audit.Body.String(), wantAudit)
	}

	vote := policyHumanRequest(t, handler, http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve", "")
	const wantVote = `{"decision":"approve","state":"pending","tally":{"approvals":1,"denials":1,"required_approvals":2,"deny_veto":true}}` + "\n"
	if vote.Code != http.StatusOK || vote.Body.String() != wantVote || strings.Contains(vote.Body.String(), "unaudited") {
		t.Fatalf("vote = %d %s", vote.Code, vote.Body.String())
	}
	if len(store.prepared) != 1 || store.prepared[0].AuthnMethod != policystore.AuthnSession {
		t.Fatalf("prepared votes = %+v", store.prepared)
	}
	deny := policyHumanRequest(t, handler, http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/deny", `{}`)
	const wantDeny = `{"decision":"deny","state":"pending","tally":{"approvals":1,"denials":1,"required_approvals":2,"deny_veto":true}}` + "\n"
	if deny.Code != http.StatusOK || deny.Body.String() != wantDeny {
		t.Fatalf("deny = %d %s", deny.Code, deny.Body.String())
	}
}

func TestPolicyHumanRejectionKeysDigestsAndEmptyVotes(t *testing.T) {
	handler, store, row, core := newPolicyHumanHandlerFixture(t)
	rejection := *row
	rejection.State = policystore.StateError
	rejection.ErrorFamily = policystore.ErrorFamilySemantic
	rejection.FailureCode = policywire.ErrorInvalidPolicyRequest
	rejection.TerminalHTTPStatus = policystore.NullableInt64{Value: 400, Valid: true}
	rejection.TrustedHeadDigest = policystore.NullableString{Value: strings.Repeat("c", 64), Valid: true}
	rejection.ExpectedSignerKeyID = strings.Repeat("d", 64)
	store.rows[row.ReviewID] = &rejection

	detail := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/requests/"+row.ReviewID, "")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `"mismatch":true`) ||
		!strings.Contains(detail.Body.String(), `"trusted_head_digest":"`+strings.Repeat("c", 64)+`"`) ||
		!strings.Contains(detail.Body.String(), `"tally":{"approvals":0,"denials":0`) || !strings.Contains(detail.Body.String(), `"votes":[]`) {
		t.Fatalf("rejection detail = %d %s (key=%s)", detail.Code, detail.Body.String(), core.keyID)
	}
	audit := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/requests/"+row.ReviewID+"/audit", "")
	if audit.Code != http.StatusOK || !strings.Contains(audit.Body.String(), `"terminal_http_status":400,"votes":[]`) || strings.Contains(audit.Body.String(), "tally") {
		t.Fatalf("rejection audit = %d %s", audit.Code, audit.Body.String())
	}
}

func TestPolicyHumanRawGrammarAndClosedFailures(t *testing.T) {
	handler, store, row, _ := newPolicyHumanHandlerFixture(t)
	invalid := []string{
		"/ui/policy/pending?x=1",
		"/ui/policy/pending?",
		"/ui/policy/requests/" + row.ReviewID + "/",
		"/ui/policy/requests/pr_1111111111111111111111111111111A",
		"/ui/policy/requests/pr_111111111111111111111111111111%31",
		"/ui/policy/requests//" + row.ReviewID,
	}
	for _, target := range invalid {
		response := policyHumanRequest(t, handler, http.MethodGet, target, "")
		if response.Code != http.StatusBadRequest || response.Body.String() != "{\"error\":\"invalid policy request\"}\n" {
			t.Errorf("invalid %q = %d %q", target, response.Code, response.Body.String())
		}
	}
	wrong := policyHumanRequest(t, handler, http.MethodDelete, "/ui/policy/requests/"+row.ReviewID, "")
	if wrong.Code != http.StatusMethodNotAllowed || wrong.Body.String() != "{\"error\":\"method not allowed\"}\n" {
		t.Fatalf("wrong method = %d %q", wrong.Code, wrong.Body.String())
	}
	malformed := policyHumanRequest(t, handler, http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve", `{"extra":true}`)
	if malformed.Code != http.StatusBadRequest || malformed.Body.String() != "{\"error\":\"invalid policy request\"}\n" {
		t.Fatalf("malformed body = %d %q", malformed.Code, malformed.Body.String())
	}
	nullBody := policyHumanRequest(t, handler, http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve", `null`)
	if nullBody.Code != http.StatusBadRequest || nullBody.Body.String() != "{\"error\":\"invalid policy request\"}\n" {
		t.Fatalf("null body = %d %q", nullBody.Code, nullBody.Body.String())
	}

	tests := []struct {
		name string
		err  error
		code int
		body string
	}{
		{name: "absent", err: policystore.ErrNotFound, code: 404, body: "not found"},
		{name: "ineligible", err: policystore.ErrNotEligible, code: 403, body: "not eligible"},
		{name: "audited conflict", err: policystore.ErrVoteConflict, code: 409, body: "vote_conflict"},
		{name: "terminal conflict", err: policystore.ErrConflict, code: 409, body: "vote_conflict"},
		{name: "unaudited winner", err: policystore.ErrUnavailable, code: 503, body: "policy authority unavailable"},
		{name: "infrastructure", err: errors.New("db failed"), code: 503, body: "policy authority unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store.getErr = nil
			store.prepareErr = test.err
			if errors.Is(test.err, policystore.ErrNotFound) {
				store.getErr = test.err
				store.prepareErr = nil
			}
			response := policyHumanRequest(t, handler, http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/deny", "")
			want := fmt.Sprintf("{\"error\":%q}\n", test.body)
			if response.Code != test.code || response.Body.String() != want {
				t.Fatalf("response = %d %q; want %d %q", response.Code, response.Body.String(), test.code, want)
			}
		})
	}

	store.getErr, store.prepareErr = nil, nil
	store.prepared = nil
	row.VoteStepUpRequired = true
	stepUp := policyHumanRequest(t, handler, http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve", "")
	if stepUp.Code != http.StatusUnauthorized || stepUp.Body.String() != "{\"error\":\"step-up required\"}\n" || len(store.prepared) != 0 {
		t.Fatalf("missing step-up = %d %q prepared=%d", stepUp.Code, stepUp.Body.String(), len(store.prepared))
	}
}

func TestPolicyHumanSubmissionEvidenceAndCollectionBounds(t *testing.T) {
	handler, store, row, core := newPolicyHumanHandlerFixture(t)
	target := "/ui/policy/requests/" + row.ReviewID

	row.SubmissionAudited = false
	response := policyHumanRequest(t, handler, http.MethodGet, target, "")
	if response.Code != http.StatusNotFound || response.Body.String() != "{\"error\":\"not found\"}\n" {
		t.Fatalf("pre-acknowledgement detail = %d %q", response.Code, response.Body.String())
	}
	row.SubmissionAudited = true

	row.FrozenSignerKeyID = policystore.NullableString{}
	row.FrozenSignerPublicKey = nil
	response = policyHumanRequest(t, handler, http.MethodGet, target, "")
	wantKeys := `"keys":{"expected_signer_key_id":"` + core.keyID + `","mismatch":false}`
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), wantKeys) || strings.Contains(response.Body.String(), "frozen_signer") {
		t.Fatalf("absent custody snapshot = %d %s", response.Code, response.Body.String())
	}
	row.FrozenSignerKeyID = policystore.NullableString{Value: core.keyID, Valid: true}
	response = policyHumanRequest(t, handler, http.MethodGet, target, "")
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"policy authority unavailable\"}\n" {
		t.Fatalf("partial custody snapshot = %d %q", response.Code, response.Body.String())
	}
	row.FrozenSignerPublicKey = slices.Clone(core.public)
	row.ReviewRulesDigest = policystore.NullableString{}
	response = policyHumanRequest(t, handler, http.MethodGet, target, "")
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"policy authority unavailable\"}\n" {
		t.Fatalf("partial review group = %d %q", response.Code, response.Body.String())
	}
	row.ReviewRulesDigest = policystore.NullableString{Value: policyreview.RulesDigest(), Valid: true}

	originalPending := store.pending
	many := make([]*policystore.Request, policystore.MaxActiveGlobal)
	for index := range many {
		copy := *row
		copy.ReviewID = fmt.Sprintf("pr_%032x", index)
		copy.RequestID = fmt.Sprintf("pm_%032x", index)
		copy.CreatedAt = int64(index)
		many[index] = &copy
	}
	store.pending = many
	response = policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/pending", "")
	if response.Code != http.StatusOK || strings.Count(response.Body.String(), `"review_id"`) != policystore.MaxActiveGlobal {
		t.Fatalf("pending at bound = %d review_ids=%d", response.Code, strings.Count(response.Body.String(), `"review_id"`))
	}
	store.pending = append(many, row)
	response = policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/pending", "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("pending over bound = %d %s", response.Code, response.Body.String())
	}
	store.pending = originalPending

	originalVotes := store.votes[row.Key()]
	votes := make([]*policystore.Vote, policystore.MaxVotesPerRequest)
	for index := range votes {
		votes[index] = &policystore.Vote{Principal: row.Principal, RequestID: row.RequestID,
			Operator: fmt.Sprintf("voter-%03d", index), Decision: policystore.DecisionApprove,
			AuthnMethod: policystore.AuthnSession, Timestamp: int64(index), Audited: true}
	}
	store.votes[row.Key()] = votes
	response = policyHumanRequest(t, handler, http.MethodGet, target, "")
	if response.Code != http.StatusOK || strings.Count(response.Body.String(), `"operator"`) != policystore.MaxVotesPerRequest {
		t.Fatalf("votes at bound = %d operators=%d", response.Code, strings.Count(response.Body.String(), `"operator"`))
	}
	store.votes[row.Key()] = append(votes, originalVotes[0])
	response = policyHumanRequest(t, handler, http.MethodGet, target, "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("votes over bound = %d %s", response.Code, response.Body.String())
	}
}

func TestPolicyHumanServesVerifiedTombstoneArchive(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	t.Cleanup(func() { _ = database.Close() })
	engine := newTestEngine(t, store, core, audit, input.Now, nil)
	decoded, err := policywire.DecodeRequest(input.CanonicalRequest)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := engine.Admit(context.Background(), PolicyAdmissionInput{Principal: "machine", CanonicalRequest: input.CanonicalRequest, Decoded: decoded})
	if err != nil || begin.Request == nil {
		t.Fatalf("admit = %+v, %v", begin, err)
	}
	if _, err := engine.Vote(context.Background(), policystore.VoteInput{ReviewID: begin.Request.ReviewID, Operator: "voter",
		Decision: policystore.DecisionDeny, AuthnMethod: policystore.AuthnSession, Now: input.Now}); err != nil {
		t.Fatal(err)
	}
	terminal, err := store.GetByReviewID(context.Background(), begin.Request.ReviewID)
	if err != nil || !terminal.State.Terminal() {
		t.Fatalf("terminal = %+v, %v", terminal, err)
	}
	record, err := store.SnapshotTerminalArchive(context.Background(), terminal.Key(), terminal.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	reference, encoded, err := record.ObjectRef()
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "archive")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lockTarget := filepath.Join(filepath.Dir(root), "policy.db")
	exclusive, err := policyarchive.AcquireMaintenanceLease(lockTarget, policyarchive.LeaseExclusive)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := policyarchive.OpenServing(root, exclusive)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.PublishBinding(exclusive, testPolicyArchiveID, testPolicyAuthority); err != nil {
		t.Fatal(err)
	}
	if err := archive.PrepareServingShards(exclusive); err != nil {
		t.Fatal(err)
	}
	object, err := archive.PublishObject(exclusive, encoded)
	if err != nil || object.SHA256 != reference.ObjectSHA256 || object.Bytes != reference.RecordBytes {
		t.Fatalf("publish archive object = %+v, %v", object, err)
	}
	if _, err := store.CommitTerminalArchive(context.Background(), terminal.Key(), terminal.StateVersion, reference); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}

	shared, err := policyarchive.AcquireMaintenanceLease(lockTarget, policyarchive.LeaseShared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shared.Close() })
	archive, err = policyarchive.OpenServing(root, shared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = archive.Close() })
	if err := archive.VerifyBinding(testPolicyArchiveID, testPolicyAuthority); err != nil {
		t.Fatal(err)
	}
	if err := archive.VerifyShards(); err != nil {
		t.Fatal(err)
	}
	handler, err := newPolicyHumanHandler(engine, archive, &HumanAPI{Auth: &AuthManager{cfg: AuthConfig{RPOrigins: []string{"https://signer.example.com"}}}})
	if err != nil {
		t.Fatal(err)
	}
	detail := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/requests/"+terminal.ReviewID, "")
	if detail.Code != http.StatusOK || !bytes.Contains(detail.Body.Bytes(), append([]byte(`"review":`), record.Request.ReviewJSON...)) ||
		!strings.Contains(detail.Body.String(), `"operator":"voter","decision":"deny"`) {
		t.Fatalf("tombstone detail = %d %s", detail.Code, detail.Body.String())
	}
	auditResponse := policyHumanRequest(t, handler, http.MethodGet, "/ui/policy/requests/"+terminal.ReviewID+"/audit", "")
	if auditResponse.Code != http.StatusOK || !strings.Contains(auditResponse.Body.String(), `"terminal_http_status":200`) ||
		!strings.Contains(auditResponse.Body.String(), `"operator":"voter","decision":"deny"`) || strings.Contains(auditResponse.Body.String(), `"tally"`) {
		t.Fatalf("tombstone audit = %d %s", auditResponse.Code, auditResponse.Body.String())
	}
}

func TestPolicyHumanSessionPlaneAndCSRF(t *testing.T) {
	handler, store, row, _ := newPolicyHumanHandlerFixture(t)
	database, err := sqlitestore.Open(filepath.Join(t.TempDir(), "human.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.CreateUser(context.Background(), &ordinary.User{ID: "voter", Username: "voter", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	if err := database.SetTOTP(context.Background(), "voter", secret); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthManager(database, AuthConfig{RPID: "signer.example.com", RPDisplayName: "SSHGate",
		RPOrigins: []string{"https://signer.example.com"}, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	authNow := time.Now().UTC().Truncate(time.Second)
	auth.now = func() time.Time { return authNow }
	session, err := auth.IssueSession(context.Background(), "voter")
	if err != nil {
		t.Fatal(err)
	}
	human := &HumanAPI{Auth: auth, Store: database}
	handler.human = human
	server := NewServer("secret", database, log.New(io.Discard, "", 0))
	server.MachineClientID = "machine"
	server.Human = human
	lease, archive := testPolicyArchive(t)
	t.Cleanup(func() { _ = archive.Close() })
	t.Cleanup(func() { _ = lease.Close() })
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: handler.engine, Handler: http.NotFoundHandler(), Archive: archive,
		Lease: lease, DurableAudit: handler.engine.audit}); err != nil {
		t.Fatal(err)
	}
	if err := handler.engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}

	bearerOnly := httptest.NewRequest(http.MethodGet, "/ui/policy/pending", nil)
	bearerOnly.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, bearerOnly)
	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("bearer authenticated human route: %d %q", response.Code, response.Body.String())
	}

	sessionOnly := httptest.NewRequest(http.MethodGet, "/v2/policy/base-manifests/pm_11111111111111111111111111111111", nil)
	sessionOnly.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	response = httptest.NewRecorder()
	server.ServeHTTP(response, sessionOnly)
	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("session authenticated machine route: %d %q", response.Code, response.Body.String())
	}

	csrf := httptest.NewRequest(http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve", nil)
	csrf.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	csrf.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, csrf)
	if response.Code != http.StatusForbidden || response.Body.String() != "{\"error\":\"forbidden origin\"}\n" || len(store.prepared) != 0 {
		t.Fatalf("CSRF response = %d %q prepared=%d", response.Code, response.Body.String(), len(store.prepared))
	}

	row.VoteStepUpRequired = true // frozen row wins over HumanAPI.Cfg's false zero value.
	invalidStepUp := httptest.NewRequest(http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve",
		strings.NewReader(`{"step_up_totp":"000000"}`))
	invalidStepUp.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	invalidStepUp.Header.Set("Origin", "https://signer.example.com")
	invalidStepUp.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, invalidStepUp)
	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"step-up required\"}\n" || len(store.prepared) != 0 {
		t.Fatalf("invalid frozen inline TOTP = %d %q prepared=%+v", response.Code, response.Body.String(), store.prepared)
	}
	code, err := totp.GenerateCode(secret, auth.now())
	if err != nil {
		t.Fatal(err)
	}
	stepUp := httptest.NewRequest(http.MethodPost, "/ui/policy/requests/"+row.ReviewID+"/approve",
		strings.NewReader(fmt.Sprintf(`{"step_up_totp":%q}`, code)))
	stepUp.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	stepUp.Header.Set("Origin", "https://signer.example.com")
	stepUp.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, stepUp)
	if response.Code != http.StatusOK || len(store.prepared) != 1 || store.prepared[0].AuthnMethod != policystore.AuthnTOTP {
		t.Fatalf("frozen inline TOTP = %d %q prepared=%+v", response.Code, response.Body.String(), store.prepared)
	}
}

func TestPolicyEngineRejectsRendererRulesMismatch(t *testing.T) {
	core := newTestPolicyCore(t)
	base := PolicyEngineConfig{AuthorityID: testPolicyAuthority, WorkerID: "worker", Store: &embeddedPolicyStore{}, Core: core, Audit: &testPolicyAudit{}}
	for _, mutate := range []func(*PolicyEngineConfig){
		func(config *PolicyEngineConfig) {
			config.ReviewRendererVersion = policyreview.RendererVersion + "-wrong"
		},
		func(config *PolicyEngineConfig) { config.ReviewRulesDigest = strings.Repeat("0", 64) },
	} {
		config := base
		mutate(&config)
		if _, err := NewPolicyEngine(config); err == nil {
			t.Fatal("policy engine accepted a renderer/rules binding mismatch")
		}
	}
}
