package approvalwire

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// HostedRoot is the hosted machine plane's approvals root. The six routes:
//
//	POST /v2/approvals                    submit  (HostedSubmitBody)
//	GET  /v2/approvals/{id}               get     (HostedGetQuery)
//	GET  /v2/approvals?limit=&cursor=     list    (HostedListQuery)
//	POST /v2/approvals/wait               wait    (HostedWaitBody)
//	POST /v2/approvals/{id}/claim         claim   (HostedClaimBody)
//	POST /v2/approvals/{id}/report        report  (HostedReportBody)
//
// Every answer is a Response with the HTTP status HTTPStatus gives it.
const HostedRoot = "/v2/approvals"

// The hosted request bodies and queries. Each may carry requester_sub, the
// optional sub-principal (^local-uid:[0-9]{1,10}$, E19) the local proxy sets
// from SO_PEERCRED; absent is the empty namespace. The kind is the route and
// the request ID is in the path, so neither is in the body.

// HostedSubmitBody is POST /v2/approvals.
type HostedSubmitBody struct {
	ApprovalProto int                        `json:"approval_proto"`
	RequesterSub  string                     `json:"requester_sub,omitempty"`
	Draft         approvalplan.ApprovalDraft `json:"draft"`
}

// HostedWaitBody is POST /v2/approvals/wait.
type HostedWaitBody struct {
	ApprovalProto int      `json:"approval_proto"`
	RequesterSub  string   `json:"requester_sub,omitempty"`
	RequestIDs    []string `json:"request_ids"`
	WaitSeconds   int      `json:"wait_seconds"`
}

// HostedClaimBody is POST /v2/approvals/{id}/claim.
type HostedClaimBody struct {
	ApprovalProto int    `json:"approval_proto"`
	RequesterSub  string `json:"requester_sub,omitempty"`
	ClaimToken    string `json:"claim_token"`
	PlanHash      string `json:"plan_hash"`
}

// HostedReportBody is POST /v2/approvals/{id}/report.
type HostedReportBody struct {
	ApprovalProto int    `json:"approval_proto"`
	RequesterSub  string `json:"requester_sub,omitempty"`
	ClaimToken    string `json:"claim_token"`
	PlanHash      string `json:"plan_hash"`
	Report        Report `json:"report"`
}

// HostedGetQuery is the query of GET /v2/approvals/{id}.
type HostedGetQuery struct {
	RequesterSub string
}

// HostedListQuery is the query of GET /v2/approvals.
type HostedListQuery struct {
	RequesterSub string
	Limit        int
	Cursor       string
}

func (b HostedSubmitBody) check() error {
	if err := checkHostedHeader(b.ApprovalProto, b.RequesterSub); err != nil {
		return err
	}
	return validateDraft(b.Draft)
}

func (b HostedWaitBody) check() error {
	if err := checkHostedHeader(b.ApprovalProto, b.RequesterSub); err != nil {
		return err
	}
	return validateWait(b.RequestIDs, b.WaitSeconds)
}

func (b HostedClaimBody) check() error {
	if err := checkHostedHeader(b.ApprovalProto, b.RequesterSub); err != nil {
		return err
	}
	return validateClaim(b.ClaimToken, b.PlanHash)
}

func (b HostedReportBody) check() error {
	if err := checkHostedHeader(b.ApprovalProto, b.RequesterSub); err != nil {
		return err
	}
	if err := validateClaim(b.ClaimToken, b.PlanHash); err != nil {
		return err
	}
	return validateReport(b.Report)
}

func checkHostedHeader(proto int, sub string) error {
	if proto != Proto {
		return invalid("approval_proto", "must be %d", Proto)
	}
	if sub != "" && !approvalplan.ValidRequesterSub(sub) {
		return invalid("requester_sub", "must match ^local-uid:[0-9]{1,10}$")
	}
	return nil
}

// HostedRoute returns the method and path of kind's hosted route. requestID
// is required by get, claim and report and must be empty otherwise.
func HostedRoute(kind, requestID string) (method, path string, err error) {
	needsID := kind == KindGet || kind == KindClaim || kind == KindReport
	if needsID {
		if err := validateRequestID("request_id", requestID); err != nil {
			return "", "", err
		}
	} else if requestID != "" {
		return "", "", fmt.Errorf("approvalwire: %s takes no request id in its path", kind)
	}
	switch kind {
	case KindSubmit:
		return http.MethodPost, HostedRoot, nil
	case KindGet:
		return http.MethodGet, HostedRoot + "/" + requestID, nil
	case KindList:
		return http.MethodGet, HostedRoot, nil
	case KindWait:
		return http.MethodPost, HostedRoot + "/wait", nil
	case KindClaim:
		return http.MethodPost, HostedRoot + "/" + requestID + "/claim", nil
	case KindReport:
		return http.MethodPost, HostedRoot + "/" + requestID + "/report", nil
	}
	return "", "", fmt.Errorf("approvalwire: unknown kind %q", kind)
}

// hostedBodyKind maps a body type to the kind of its route.
func hostedBodyKind(body any) (string, bool) {
	switch body.(type) {
	case HostedSubmitBody:
		return KindSubmit, true
	case HostedWaitBody:
		return KindWait, true
	case HostedClaimBody:
		return KindClaim, true
	case HostedReportBody:
		return KindReport, true
	}
	return "", false
}

// MarshalHostedBody validates a hosted POST body and returns its canonical
// JSON, without a newline.
func MarshalHostedBody(body any) ([]byte, error) {
	if _, ok := hostedBodyKind(body); !ok {
		return nil, fmt.Errorf("approvalwire: %T is not a hosted body type", body)
	}
	if err := body.(checker).check(); err != nil {
		return nil, err
	}
	line, err := marshalLine(body)
	if err != nil {
		return nil, err
	}
	return line[:len(line)-1], nil
}

// DecodeHostedBody strictly decodes the POST body of kind's route into its
// typed value. Refusals are *approvalplan.CodeError, as for DecodeLocalRequest.
func DecodeHostedBody(kind string, body []byte) (any, error) {
	if len(body) > MaxFrameBytes {
		return nil, &approvalplan.CodeError{Code: approvalplan.CodeRequestTooLarge, Field: "body", Msg: fmt.Sprintf("is %d bytes; maximum is %d", len(body), MaxFrameBytes)}
	}
	switch kind {
	case KindSubmit:
		return decodeRequest[HostedSubmitBody](body)
	case KindWait:
		return decodeRequest[HostedWaitBody](body)
	case KindClaim:
		return decodeRequest[HostedClaimBody](body)
	case KindReport:
		return decodeRequest[HostedReportBody](body)
	}
	return nil, fmt.Errorf("approvalwire: %q has no hosted body", kind)
}

// Encode returns the canonical query: url.Values.Encode order, requester_sub
// omitted when empty.
func (q HostedGetQuery) Encode() (string, error) {
	if err := checkHostedHeader(Proto, q.RequesterSub); err != nil {
		return "", err
	}
	return queryOf(q.RequesterSub, 0, "").Encode(), nil
}

// Encode returns the canonical query: url.Values.Encode order, cursor and
// requester_sub omitted when empty.
func (q HostedListQuery) Encode() (string, error) {
	if err := checkHostedHeader(Proto, q.RequesterSub); err != nil {
		return "", err
	}
	if err := validateList(q.Limit, q.Cursor); err != nil {
		return "", err
	}
	return queryOf(q.RequesterSub, q.Limit, q.Cursor).Encode(), nil
}

func queryOf(sub string, limit int, cursor string) url.Values {
	v := url.Values{}
	if sub != "" {
		v.Set("requester_sub", sub)
	}
	if limit != 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		v.Set("cursor", cursor)
	}
	return v
}

// DecodeHostedGetQuery strictly decodes GET /v2/approvals/{id}'s raw query:
// only requester_sub, at most once, in canonical encoding.
func DecodeHostedGetQuery(rawQuery string) (HostedGetQuery, error) {
	v, err := strictQuery(rawQuery, "requester_sub")
	if err != nil {
		return HostedGetQuery{}, err
	}
	q := HostedGetQuery{RequesterSub: v.Get("requester_sub")}
	if err := canonicalQuery(rawQuery, q.Encode); err != nil {
		return HostedGetQuery{}, err
	}
	return q, nil
}

// DecodeHostedListQuery strictly decodes GET /v2/approvals's raw query:
// limit (required), cursor and requester_sub, each at most once, in canonical
// encoding.
func DecodeHostedListQuery(rawQuery string) (HostedListQuery, error) {
	v, err := strictQuery(rawQuery, "requester_sub", "limit", "cursor")
	if err != nil {
		return HostedListQuery{}, err
	}
	limit, err := strconv.Atoi(v.Get("limit"))
	if err != nil {
		return HostedListQuery{}, invalid("limit", "must be 1..%d", MaxListLimit)
	}
	q := HostedListQuery{RequesterSub: v.Get("requester_sub"), Limit: limit, Cursor: v.Get("cursor")}
	if err := canonicalQuery(rawQuery, q.Encode); err != nil {
		return HostedListQuery{}, err
	}
	return q, nil
}

func strictQuery(rawQuery string, allowed ...string) (url.Values, error) {
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, invalid("query", "%v", err)
	}
	for key, values := range v {
		if !slices.Contains(allowed, key) {
			return nil, invalid("query", "unknown parameter %q", key)
		}
		if len(values) != 1 {
			return nil, invalid(key, "must appear once")
		}
	}
	return v, nil
}

// canonicalQuery validates the decoded query through encode and requires the
// raw query to be its canonical encoding.
func canonicalQuery(rawQuery string, encode func() (string, error)) error {
	canonical, err := encode()
	if err != nil {
		return err
	}
	if canonical != rawQuery {
		return invalid("query", "not in canonical form")
	}
	return nil
}

// HTTPStatus is the one HTTP status each refusal code answers with on the
// hosted plane; an ok answer is 200. signer_incompatible is a local frame
// only and has none (0).
func HTTPStatus(code approvalplan.Code) int {
	switch code {
	case approvalplan.CodeNotFound:
		return http.StatusNotFound
	case approvalplan.CodeConflict, approvalplan.CodeSubmitWindowClosed:
		return http.StatusConflict
	case approvalplan.CodeInvalidRequest, approvalplan.CodeReservedVerb:
		return http.StatusBadRequest
	case approvalplan.CodeRequestTooLarge:
		return http.StatusRequestEntityTooLarge
	case approvalplan.CodeRequestUnrenderable, approvalplan.CodeInvalidReport:
		return http.StatusUnprocessableEntity
	case approvalplan.CodeSubmitWindowAhead:
		return http.StatusTooEarly
	case approvalplan.CodeQueueFull:
		return http.StatusTooManyRequests
	case approvalplan.CodeInvalidClaim:
		return http.StatusForbidden
	case approvalplan.CodeStorageUncertain, approvalplan.CodeBusy, approvalplan.CodeLifecycleUnavailable:
		return http.StatusServiceUnavailable
	case approvalplan.CodeRecordCorrupt:
		return http.StatusInternalServerError
	}
	return 0
}

// MarshalHostedResponse validates resp as the hosted answer to kind and
// returns its HTTP status and canonical JSON body (no newline). The server
// sends it as application/json; busy also sends Retry-After: 1 (E21).
func MarshalHostedResponse(kind string, resp Response) (int, []byte, error) {
	if err := validateResponse(kind, resp, true); err != nil {
		return 0, nil, fmt.Errorf("approvalwire: hosted %s response: %w", kind, err)
	}
	line, err := marshalLine(resp)
	if err != nil {
		return 0, nil, err
	}
	return hostedStatusOf(resp), line[:len(line)-1], nil
}

func hostedStatusOf(resp Response) int {
	if resp.OK {
		return http.StatusOK
	}
	return HTTPStatus(resp.Error.Code)
}

// ClassifyHostedResponse turns one hosted HTTP answer to kind into the same
// (Response, error) DecodeLocalResponse gives. An approvals envelope is an
// application/json body that strictly decodes and validates as kind's answer;
// its status must be HTTPStatus of its code (200 when ok). Then:
//   - a non-envelope 404 (an older server: the policy plane's
//     {"error":"not found"} or the mux's text 404) → ErrSignerIncompatible
//     (E69); a not_found envelope stays a *WireError not_found;
//   - any other non-envelope answer, a 503 from a reverse proxy included →
//     ErrTransport;
//   - an envelope with the wrong status → a malformed-response error.
func ClassifyHostedResponse(kind string, status int, contentType string, body []byte) (Response, error) {
	resp, ok := hostedEnvelope(kind, contentType, body)
	if !ok {
		if status == http.StatusNotFound {
			return Response{}, fmt.Errorf("%w: hosted %s answered a 404 that is not an approvals envelope", ErrSignerIncompatible, kind)
		}
		return Response{}, fmt.Errorf("%w: %s answered HTTP %d", ErrTransport, kind, status)
	}
	if want := hostedStatusOf(resp); status != want {
		return Response{}, fmt.Errorf("approvalwire: hosted %s answered HTTP %d with an envelope that needs %d", kind, status, want)
	}
	if !resp.OK {
		return resp, resp.Error
	}
	return resp, nil
}

func hostedEnvelope(kind, contentType string, body []byte) (Response, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(body) > MaxFrameBytes {
		return Response{}, false
	}
	var resp Response
	if decodeStrict(body, &resp) != nil || validateResponse(kind, resp, true) != nil {
		return Response{}, false
	}
	return resp, true
}
