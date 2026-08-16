package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

// policyHumanHandler owns only the five policy human-plane contracts. Session
// authentication and readiness stay in AttachPolicy; the existing HumanAPI
// remains the single owner of Origin, content-type, rate-limit, and TOTP checks.
type policyHumanHandler struct {
	engine  *PolicyEngine
	store   policystore.Store
	archive *policyarchive.Archive
	human   *HumanAPI
}

func newPolicyHumanHandler(engine *PolicyEngine, archive *policyarchive.Archive, human *HumanAPI) (*policyHumanHandler, error) {
	if engine == nil || engine.store == nil || archive == nil || human == nil {
		return nil, errors.New("engine, store, archive, and human API are required")
	}
	return &policyHumanHandler{engine: engine, store: engine.store, archive: archive, human: human}, nil
}

type policyHumanRoute uint8

const (
	policyHumanInvalid policyHumanRoute = iota
	policyHumanPending
	policyHumanDetail
	policyHumanApprove
	policyHumanDeny
	policyHumanAudit
)

func (handler *policyHumanHandler) ServeAuthenticated(writer http.ResponseWriter, request *http.Request, operator string) {
	route, reviewID := classifyPolicyHumanTarget(request.URL.EscapedPath(), request.URL.RawQuery, request.URL.ForceQuery)
	if route == policyHumanInvalid {
		writeJSONError(writer, http.StatusBadRequest, "invalid policy request")
		return
	}
	wantMethod := http.MethodGet
	if route == policyHumanApprove || route == policyHumanDeny {
		wantMethod = http.MethodPost
	}
	if request.Method != wantMethod {
		writeJSONError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if reviewID != "" {
		request.SetPathValue("review_id", reviewID)
	}
	switch route {
	case policyHumanPending:
		handler.pending(writer, request)
	case policyHumanDetail:
		handler.detail(writer, request)
	case policyHumanApprove:
		if handler.human.allowMutation(writer, request) {
			handler.vote(writer, request, operator, policystore.DecisionApprove)
		}
	case policyHumanDeny:
		if handler.human.allowMutation(writer, request) {
			handler.vote(writer, request, operator, policystore.DecisionDeny)
		}
	case policyHumanAudit:
		handler.audit(writer, request)
	}
}

func classifyPolicyHumanTarget(target, rawQuery string, forceQuery bool) (policyHumanRoute, string) {
	if rawQuery != "" || forceQuery {
		return policyHumanInvalid, ""
	}
	if target == "/ui/policy/pending" {
		return policyHumanPending, ""
	}
	const prefix = "/ui/policy/requests/"
	if len(target) < len(prefix)+35 || target[:len(prefix)] != prefix {
		return policyHumanInvalid, ""
	}
	reviewID := target[len(prefix) : len(prefix)+35]
	if !validPolicyReviewID(reviewID) {
		return policyHumanInvalid, ""
	}
	switch target[len(prefix)+35:] {
	case "":
		return policyHumanDetail, reviewID
	case "/approve":
		return policyHumanApprove, reviewID
	case "/deny":
		return policyHumanDeny, reviewID
	case "/audit":
		return policyHumanAudit, reviewID
	default:
		return policyHumanInvalid, ""
	}
}

func validPolicyReviewID(reviewID string) bool {
	if len(reviewID) != 35 || reviewID[:3] != "pr_" {
		return false
	}
	for index := 3; index < len(reviewID); index++ {
		if (reviewID[index] < '0' || reviewID[index] > '9') && (reviewID[index] < 'a' || reviewID[index] > 'f') {
			return false
		}
	}
	return true
}

type policyPendingResponse struct {
	Pending []policyPendingItem `json:"pending"`
}

type policyPendingItem struct {
	ReviewID          string            `json:"review_id"`
	Principal         string            `json:"principal"`
	RequestID         string            `json:"request_id"`
	Purpose           string            `json:"purpose"`
	Host              string            `json:"host"`
	State             policystore.State `json:"state"`
	CreatedAt         int64             `json:"created_at"`
	Approvals         int               `json:"approvals"`
	Denials           int               `json:"denials"`
	RequiredApprovals int64             `json:"required_approvals"`
	DenyVeto          bool              `json:"deny_veto"`
	Bootstrap         bool              `json:"bootstrap"`
}

type policyKeys struct {
	ExpectedSignerKeyID      string `json:"expected_signer_key_id"`
	FrozenSignerKeyID        string `json:"frozen_signer_key_id,omitempty"`
	FrozenSignerPublicKeyB64 string `json:"frozen_signer_public_key_b64,omitempty"`
	Mismatch                 bool   `json:"mismatch"`
}

type policyDigests struct {
	CandidateBaseDigest string `json:"candidate_base_digest"`
	TrustedHeadDigest   string `json:"trusted_head_digest,omitempty"`
}

type policyTally struct {
	Approvals         int   `json:"approvals"`
	Denials           int   `json:"denials"`
	RequiredApprovals int64 `json:"required_approvals"`
	DenyVeto          bool  `json:"deny_veto"`
}

type policyVote struct {
	Operator    string                  `json:"operator"`
	Decision    policystore.Decision    `json:"decision"`
	AuthnMethod policystore.AuthnMethod `json:"authn_method"`
	TS          int64                   `json:"ts"`
}

type policyDetailResponse struct {
	ReviewID  string            `json:"review_id"`
	State     policystore.State `json:"state"`
	CreatedAt int64             `json:"created_at"`
	Keys      policyKeys        `json:"keys"`
	Digests   policyDigests     `json:"digests"`
	Tally     policyTally       `json:"tally"`
	Votes     []policyVote      `json:"votes"`
	Review    json.RawMessage   `json:"review,omitempty"`
}

type policyVoteResponse struct {
	Decision policystore.Decision `json:"decision"`
	State    policystore.State    `json:"state"`
	Tally    policyTally          `json:"tally"`
}

type policyAuditResponse struct {
	ReviewID           string            `json:"review_id"`
	State              policystore.State `json:"state"`
	Keys               policyKeys        `json:"keys"`
	Digests            policyDigests     `json:"digests"`
	TerminalHTTPStatus *int64            `json:"terminal_http_status,omitempty"`
	Votes              []policyVote      `json:"votes"`
}

func (handler *policyHumanHandler) pending(writer http.ResponseWriter, request *http.Request) {
	page, err := handler.store.ListPending(request.Context(), handler.engine.authorityID, nil, policystore.MaxActiveGlobal)
	if err != nil || page.Next != nil || len(page.Requests) > policystore.MaxActiveGlobal {
		writePolicyHumanUnavailable(writer)
		return
	}
	for _, row := range page.Requests {
		if row == nil || row.State != policystore.StatePending || !row.SubmissionAudited || !validPolicyReviewID(row.ReviewID) {
			writePolicyHumanUnavailable(writer)
			return
		}
	}
	sort.Slice(page.Requests, func(left, right int) bool {
		if page.Requests[left].CreatedAt != page.Requests[right].CreatedAt {
			return page.Requests[left].CreatedAt < page.Requests[right].CreatedAt
		}
		return page.Requests[left].ReviewID < page.Requests[right].ReviewID
	})
	items := make([]policyPendingItem, 0, len(page.Requests))
	for _, row := range page.Requests {
		votes, err := handler.visibleVotes(request.Context(), row.Key(), nil)
		if err != nil {
			writePolicyHumanUnavailable(writer)
			return
		}
		tally := publicPolicyTally(row, projectPolicyVotes(votes))
		items = append(items, policyPendingItem{ReviewID: row.ReviewID, Principal: row.Principal,
			RequestID: row.RequestID, Purpose: row.Purpose, Host: row.HostKeyFP, State: row.State,
			CreatedAt: row.CreatedAt, Approvals: tally.Approvals, Denials: tally.Denials,
			RequiredApprovals: row.RequiredApprovals, DenyVeto: row.DenyVeto, Bootstrap: row.Bootstrap})
	}
	writeJSON(writer, http.StatusOK, policyPendingResponse{Pending: items})
}

func (handler *policyHumanHandler) detail(writer http.ResponseWriter, request *http.Request) {
	row, votes, err := handler.humanRow(request.Context(), request.PathValue("review_id"))
	if err != nil {
		writePolicyHumanLookupError(writer, err)
		return
	}
	review, err := policyReviewJSON(row)
	if err != nil {
		writePolicyHumanUnavailable(writer)
		return
	}
	keys, digests, err := policyHumanEvidence(row)
	if err != nil {
		writePolicyHumanUnavailable(writer)
		return
	}
	visible := projectPolicyVotes(votes)
	if policyMatrix2A(row) {
		visible = []policyVote{}
	}
	response := policyDetailResponse{ReviewID: row.ReviewID, State: row.State, CreatedAt: row.CreatedAt,
		Keys: keys, Digests: digests, Tally: publicPolicyTally(row, visible),
		Votes: visible, Review: review}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *policyHumanHandler) audit(writer http.ResponseWriter, request *http.Request) {
	row, votes, err := handler.humanRow(request.Context(), request.PathValue("review_id"))
	if err != nil {
		writePolicyHumanLookupError(writer, err)
		return
	}
	keys, digests, err := policyHumanEvidence(row)
	if err != nil {
		writePolicyHumanUnavailable(writer)
		return
	}
	visible := projectPolicyVotes(votes)
	if policyMatrix2A(row) {
		visible = []policyVote{}
	}
	var status *int64
	if row.TerminalHTTPStatus.Valid {
		value := row.TerminalHTTPStatus.Value
		status = &value
	}
	writeJSON(writer, http.StatusOK, policyAuditResponse{ReviewID: row.ReviewID, State: row.State,
		Keys: keys, Digests: digests, TerminalHTTPStatus: status, Votes: visible})
}

func (handler *policyHumanHandler) vote(writer http.ResponseWriter, request *http.Request, operator string, decision policystore.Decision) {
	bodyReader := http.MaxBytesReader(writer, request.Body, int64(maxHumanBody))
	body, err := readLimited(bodyReader, int64(maxHumanBody))
	if err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid policy request")
		return
	}
	var voteBody voteRequest
	if len(body) != 0 {
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			writeJSONError(writer, http.StatusBadRequest, "invalid policy request")
			return
		}
		if err := decodeStrictJSON(trimmed, &voteBody); err != nil {
			writeJSONError(writer, http.StatusBadRequest, "invalid policy request")
			return
		}
	}
	row, err := handler.store.GetByReviewID(request.Context(), request.PathValue("review_id"))
	if err != nil {
		writePolicyHumanLookupError(writer, err)
		return
	}
	method := policystore.AuthnSession
	if row.VoteStepUpRequired {
		if !handler.human.allowAuth(writer, request, operator, "vote") {
			return
		}
		if voteBody.StepUpTOTP == "" {
			writeJSONError(writer, http.StatusUnauthorized, "step-up required")
			return
		}
		if _, err := handler.human.Auth.StepUp(request.Context(), operator, StepUpTOTP, voteBody.StepUpTOTP); err != nil {
			switch {
			case errors.Is(err, ErrTOTPNotEnrolled):
				writeJSONError(writer, http.StatusForbidden, "not eligible")
			case errors.Is(err, ErrAuthFailed):
				writeJSONError(writer, http.StatusUnauthorized, "step-up required")
			default:
				writePolicyHumanUnavailable(writer)
			}
			return
		}
		method = policystore.AuthnTOTP
	}
	_, err = handler.engine.Vote(request.Context(), policystore.VoteInput{ReviewID: row.ReviewID,
		Operator: operator, Decision: decision, AuthnMethod: method, Now: handler.engine.now().UTC()})
	if err != nil {
		switch {
		case errors.Is(err, policystore.ErrNotFound):
			writeJSONError(writer, http.StatusNotFound, "not found")
		case errors.Is(err, policystore.ErrNotEligible):
			writeJSONError(writer, http.StatusForbidden, "not eligible")
		case errors.Is(err, policystore.ErrVoteConflict), errors.Is(err, policystore.ErrConflict):
			writeJSONError(writer, http.StatusConflict, "vote_conflict")
		default:
			writePolicyHumanUnavailable(writer)
		}
		return
	}
	row, votes, err := handler.humanRow(request.Context(), row.ReviewID)
	if err != nil {
		writePolicyHumanUnavailable(writer)
		return
	}
	writeJSON(writer, http.StatusOK, policyVoteResponse{Decision: decision, State: row.State,
		Tally: publicPolicyTally(row, projectPolicyVotes(votes))})
}

func (handler *policyHumanHandler) humanRow(ctx context.Context, reviewID string) (*policystore.Request, []*policystore.Vote, error) {
	row, err := handler.store.GetByReviewID(ctx, reviewID)
	if err != nil {
		return nil, nil, err
	}
	if row.StorageKind == policystore.StorageFull {
		votes, err := handler.visibleVotes(ctx, row.Key(), nil)
		return row, votes, err
	}
	if row.StorageKind != policystore.StorageTombstone {
		return nil, nil, policystore.ErrCorrupt
	}
	reference := row.ArchiveRef()
	if reference == nil {
		return nil, nil, policystore.ErrCorrupt
	}
	encoded, err := handler.archive.ReadObject(policyarchive.ObjectRef{SHA256: reference.ObjectSHA256, Bytes: reference.RecordBytes})
	if err != nil {
		return nil, nil, err
	}
	if _, err := sqlitestore.ResolveTerminalArchive(row, encoded); err != nil {
		return nil, nil, err
	}
	record, err := policystore.DecodeArchiveRecord(encoded)
	if err != nil {
		return nil, nil, err
	}
	votes := make([]*policystore.Vote, 0, len(record.Votes))
	for index := range record.Votes {
		vote := record.Votes[index]
		votes = append(votes, &vote)
	}
	visible, err := handler.visibleVotes(ctx, record.Request.Key(), votes)
	return &record.Request, visible, err
}

func (handler *policyHumanHandler) visibleVotes(ctx context.Context, key policystore.Key, supplied []*policystore.Vote) ([]*policystore.Vote, error) {
	votes := supplied
	if votes == nil {
		page, err := handler.store.ListVotes(ctx, key, nil, policystore.MaxVotesPerRequest)
		if err != nil {
			return nil, err
		}
		if page.Next != nil || len(page.Votes) > policystore.MaxVotesPerRequest {
			return nil, policystore.ErrCorrupt
		}
		votes = page.Votes
	}
	if len(votes) > policystore.MaxVotesPerRequest {
		return nil, policystore.ErrCorrupt
	}
	visible := make([]*policystore.Vote, 0, len(votes))
	for _, vote := range votes {
		if vote == nil {
			return nil, policystore.ErrCorrupt
		}
		if vote.Audited {
			visible = append(visible, vote)
		}
	}
	sort.Slice(visible, func(left, right int) bool {
		if visible[left].Timestamp != visible[right].Timestamp {
			return visible[left].Timestamp < visible[right].Timestamp
		}
		return visible[left].Operator < visible[right].Operator
	})
	return visible, nil
}

func projectPolicyVotes(votes []*policystore.Vote) []policyVote {
	projected := make([]policyVote, 0, len(votes))
	for _, vote := range votes {
		if vote != nil && vote.Audited {
			projected = append(projected, policyVote{Operator: vote.Operator, Decision: vote.Decision,
				AuthnMethod: vote.AuthnMethod, TS: vote.Timestamp})
		}
	}
	return projected
}

func publicPolicyTally(row *policystore.Request, votes []policyVote) policyTally {
	tally := policyTally{RequiredApprovals: row.RequiredApprovals, DenyVeto: row.DenyVeto}
	for _, vote := range votes {
		switch vote.Decision {
		case policystore.DecisionApprove:
			tally.Approvals++
		case policystore.DecisionDeny:
			tally.Denials++
		}
	}
	return tally
}

func policyHumanEvidence(row *policystore.Request) (policyKeys, policyDigests, error) {
	if row == nil || !validPolicyHex(row.ExpectedSignerKeyID) || !validPolicyHex(row.BaseDigest) {
		return policyKeys{}, policyDigests{}, policystore.ErrCorrupt
	}
	keys := policyKeys{ExpectedSignerKeyID: row.ExpectedSignerKeyID}
	frozenPresent := row.FrozenSignerKeyID.Valid || row.FrozenSignerPublicKey != nil
	if frozenPresent {
		if !row.FrozenSignerKeyID.Valid || !validPolicyHex(row.FrozenSignerKeyID.Value) || len(row.FrozenSignerPublicKey) != ed25519.PublicKeySize {
			return policyKeys{}, policyDigests{}, policystore.ErrCorrupt
		}
		derived, err := policy.SignerKeyID(ed25519.PublicKey(row.FrozenSignerPublicKey))
		if err != nil || derived != row.FrozenSignerKeyID.Value {
			return policyKeys{}, policyDigests{}, policystore.ErrCorrupt
		}
		keys.FrozenSignerKeyID = row.FrozenSignerKeyID.Value
		keys.FrozenSignerPublicKeyB64 = base64.StdEncoding.EncodeToString(row.FrozenSignerPublicKey)
		keys.Mismatch = row.FrozenSignerKeyID.Value != row.ExpectedSignerKeyID
	}
	digests := policyDigests{CandidateBaseDigest: row.BaseDigest}
	if row.TrustedHeadDigest.Valid {
		if !validPolicyHex(row.TrustedHeadDigest.Value) {
			return policyKeys{}, policyDigests{}, policystore.ErrCorrupt
		}
		digests.TrustedHeadDigest = row.TrustedHeadDigest.Value
	}
	return keys, digests, nil
}

func validPolicyHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := range value {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func policyReviewJSON(row *policystore.Request) (json.RawMessage, error) {
	present := row.ReviewJSON != nil || row.ReviewSHA256.Valid || row.ReviewRenderedBytes.Valid ||
		row.ReviewItemCount.Valid || row.ReviewRendererVersion.Valid || row.ReviewRulesDigest.Valid
	if !present {
		return nil, nil
	}
	if row.ReviewJSON == nil || !json.Valid(row.ReviewJSON) || !row.ReviewSHA256.Valid ||
		!row.ReviewRenderedBytes.Valid || row.ReviewRenderedBytes.Value != int64(len(row.ReviewJSON)) ||
		row.ReviewRenderedBytes.Value > policyreview.MaxDocumentBytes || !row.ReviewItemCount.Valid ||
		row.ReviewItemCount.Value < 0 || row.ReviewItemCount.Value > policyreview.MaxDocumentItems ||
		!row.ReviewRendererVersion.Valid || row.ReviewRendererVersion.Value != policyreview.RendererVersion ||
		!row.ReviewRulesDigest.Valid || row.ReviewRulesDigest.Value != policyreview.RulesDigest() {
		return nil, policystore.ErrCorrupt
	}
	digest := sha256.Sum256(row.ReviewJSON)
	if hex.EncodeToString(digest[:]) != row.ReviewSHA256.Value {
		return nil, policystore.ErrCorrupt
	}
	var document struct {
		Contract string            `json:"contract"`
		Items    []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(row.ReviewJSON, &document); err != nil || document.Contract != policyreview.RendererVersion || int64(len(document.Items)) != row.ReviewItemCount.Value {
		return nil, policystore.ErrCorrupt
	}
	return json.RawMessage(row.ReviewJSON), nil
}

func policyMatrix2A(row *policystore.Request) bool {
	return row.ErrorFamily == policystore.ErrorFamilySemantic && row.FailureCode != policywire.ErrorQuorumUnattainable
}

func writePolicyHumanLookupError(writer http.ResponseWriter, err error) {
	if errors.Is(err, policystore.ErrNotFound) {
		writeJSONError(writer, http.StatusNotFound, "not found")
		return
	}
	writePolicyHumanUnavailable(writer)
}

func writePolicyHumanUnavailable(writer http.ResponseWriter) {
	writeJSONError(writer, http.StatusServiceUnavailable, "policy authority unavailable")
}
