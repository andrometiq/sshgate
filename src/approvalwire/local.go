package approvalwire

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// The local request frames. None carries requester_sub or proto_version: the
// principal is the peer's SO_PEERCRED uid, and the daemon's global proto check
// passes a frame without proto_version (E13).

// SubmitRequest is approval_submit_v2.
type SubmitRequest struct {
	ApprovalProto int                        `json:"approval_proto"`
	Kind          string                     `json:"kind"`
	Draft         approvalplan.ApprovalDraft `json:"draft"`
}

// GetRequest is approval_get_v2.
type GetRequest struct {
	ApprovalProto int    `json:"approval_proto"`
	Kind          string `json:"kind"`
	RequestID     string `json:"request_id"`
}

// ListRequest is approval_list_v2. An empty cursor is the first page.
type ListRequest struct {
	ApprovalProto int    `json:"approval_proto"`
	Kind          string `json:"kind"`
	Limit         int    `json:"limit"`
	Cursor        string `json:"cursor,omitempty"`
}

// WaitRequest is approval_wait_v2: wait up to WaitSeconds (≤55) for any of
// RequestIDs to change, then answer their summaries.
type WaitRequest struct {
	ApprovalProto int      `json:"approval_proto"`
	Kind          string   `json:"kind"`
	RequestIDs    []string `json:"request_ids"`
	WaitSeconds   int      `json:"wait_seconds"`
}

// ClaimRequest is approval_claim_v2. ClaimToken is the raw 256-bit token as
// lowercase hex; the signer compares its hash with the frozen one (E25).
type ClaimRequest struct {
	ApprovalProto int    `json:"approval_proto"`
	Kind          string `json:"kind"`
	RequestID     string `json:"request_id"`
	ClaimToken    string `json:"claim_token"`
	PlanHash      string `json:"plan_hash"`
}

// ReportRequest is approval_report_v2.
type ReportRequest struct {
	ApprovalProto int    `json:"approval_proto"`
	Kind          string `json:"kind"`
	RequestID     string `json:"request_id"`
	ClaimToken    string `json:"claim_token"`
	PlanHash      string `json:"plan_hash"`
	Report        Report `json:"report"`
}

func (r SubmitRequest) check() error {
	if err := checkHeader(r.ApprovalProto, r.Kind, KindSubmit); err != nil {
		return err
	}
	return validateDraft(r.Draft)
}

func (r GetRequest) check() error {
	if err := checkHeader(r.ApprovalProto, r.Kind, KindGet); err != nil {
		return err
	}
	return validateRequestID("request_id", r.RequestID)
}

func (r ListRequest) check() error {
	if err := checkHeader(r.ApprovalProto, r.Kind, KindList); err != nil {
		return err
	}
	return validateList(r.Limit, r.Cursor)
}

func (r WaitRequest) check() error {
	if err := checkHeader(r.ApprovalProto, r.Kind, KindWait); err != nil {
		return err
	}
	return validateWait(r.RequestIDs, r.WaitSeconds)
}

func (r ClaimRequest) check() error {
	if err := checkHeader(r.ApprovalProto, r.Kind, KindClaim); err != nil {
		return err
	}
	if err := validateRequestID("request_id", r.RequestID); err != nil {
		return err
	}
	return validateClaim(r.ClaimToken, r.PlanHash)
}

func (r ReportRequest) check() error {
	if err := checkHeader(r.ApprovalProto, r.Kind, KindReport); err != nil {
		return err
	}
	if err := validateRequestID("request_id", r.RequestID); err != nil {
		return err
	}
	if err := validateClaim(r.ClaimToken, r.PlanHash); err != nil {
		return err
	}
	return validateReport(r.Report)
}

type checker interface{ check() error }

// MarshalLocalRequest validates one of the six request types and returns its
// frame: canonical JSON and one newline.
func MarshalLocalRequest(req any) ([]byte, error) {
	c, ok := req.(checker)
	if !ok || !isLocalRequest(req) {
		return nil, fmt.Errorf("approvalwire: %T is not a local request type", req)
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return marshalLine(req)
}

func isLocalRequest(req any) bool {
	switch req.(type) {
	case SubmitRequest, GetRequest, ListRequest, WaitRequest, ClaimRequest, ReportRequest:
		return true
	}
	return false
}

// DecodeLocalRequest strictly decodes one request frame (one trailing newline
// allowed) into its typed value: SubmitRequest, GetRequest, ListRequest,
// WaitRequest, ClaimRequest or ReportRequest. Every refusal is an
// *approvalplan.CodeError the daemon can answer with: request_too_large over
// MaxFrameBytes or approvalplan.MaxDraftBytes, otherwise invalid_request (an
// unknown field such as requester_sub included) or the draft validator's code.
func DecodeLocalRequest(line []byte) (any, error) {
	if len(line) > MaxFrameBytes {
		return nil, &approvalplan.CodeError{Code: approvalplan.CodeRequestTooLarge, Field: "frame", Msg: fmt.Sprintf("is %d bytes; maximum is %d", len(line), MaxFrameBytes)}
	}
	body := withoutOneNewline(line)
	var peek struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return nil, invalid("frame", "%v", err)
	}
	switch peek.Kind {
	case KindSubmit:
		return decodeRequest[SubmitRequest](body)
	case KindGet:
		return decodeRequest[GetRequest](body)
	case KindList:
		return decodeRequest[ListRequest](body)
	case KindWait:
		return decodeRequest[WaitRequest](body)
	case KindClaim:
		return decodeRequest[ClaimRequest](body)
	case KindReport:
		return decodeRequest[ReportRequest](body)
	}
	return nil, invalid("kind", "unknown kind %q", peek.Kind)
}

func decodeRequest[T checker](body []byte) (any, error) {
	var req T
	if err := decodeStrict(body, &req); err != nil {
		return nil, invalid("frame", "%v", err)
	}
	if err := req.check(); err != nil {
		return nil, err
	}
	return req, nil
}

// MarshalLocalResponse validates resp as the answer to kind and returns its
// frame.
func MarshalLocalResponse(kind string, resp Response) ([]byte, error) {
	if err := validateResponse(kind, resp, false); err != nil {
		return nil, fmt.Errorf("approvalwire: %s response: %w", kind, err)
	}
	return marshalLine(resp)
}

// DecodeLocalResponse strictly decodes the daemon's answer to a kind request.
// An ok answer returns (resp, nil); a refusal returns (resp, *WireError), so
// errors.Is classifies busy, storage_uncertain and signer_incompatible. A
// pre-v2 daemon's legacy "unsupported kind" error frame returns
// ErrSignerIncompatible. Anything else is a malformed-response error.
func DecodeLocalResponse(kind string, line []byte) (Response, error) {
	if len(line) > MaxFrameBytes {
		return Response{}, fmt.Errorf("approvalwire: %s response is %d bytes; maximum is %d", kind, len(line), MaxFrameBytes)
	}
	body := withoutOneNewline(line)
	var resp Response
	if err := decodeStrict(body, &resp); err != nil {
		if isLegacyUnsupportedKind(kind, body) {
			return Response{}, fmt.Errorf("%w: the local signer answered %q with the legacy unsupported-kind error", ErrSignerIncompatible, kind)
		}
		return Response{}, fmt.Errorf("approvalwire: malformed %s response: %w", kind, err)
	}
	if err := validateResponse(kind, resp, false); err != nil {
		return Response{}, fmt.Errorf("approvalwire: invalid %s response: %w", kind, err)
	}
	if !resp.OK {
		return resp, resp.Error
	}
	return resp, nil
}

// isLegacyUnsupportedKind matches the error frame a pre-v2 daemon answers an
// unknown kind with: respondError(conn, peek.Kind, `unsupported kind "<kind>"`)
// (pkg/signerkit/daemon.go, the dispatch default case), whose signResponse
// carries request_id, status, error and proto_version (1, or absent on builds
// older than the proto check).
func isLegacyUnsupportedKind(kind string, body []byte) bool {
	var legacy struct {
		RequestID    string `json:"request_id"`
		Status       string `json:"status"`
		Error        string `json:"error"`
		ProtoVersion int    `json:"proto_version,omitempty"`
	}
	if decodeStrict(body, &legacy) != nil {
		return false
	}
	return legacy.Status == "error" &&
		legacy.Error == fmt.Sprintf("unsupported kind %q", kind) &&
		(legacy.RequestID == kind || legacy.RequestID == "") &&
		(legacy.ProtoVersion == 0 || legacy.ProtoVersion == 1)
}

func checkHeader(proto int, kind, want string) error {
	if proto != Proto {
		return invalid("approval_proto", "must be %d", Proto)
	}
	if kind != want {
		return invalid("kind", "is %q; want %q", kind, want)
	}
	return nil
}

func validateRequestID(field, id string) error {
	if !approvalplan.ValidRequestID(id) {
		return invalid(field, "must match ^a2_[A-Za-z0-9_-]{22}$")
	}
	return nil
}

// validateDraft bounds the draft's own encoding (it is canonical inside a
// canonical frame, so this is the byte length it arrived with) and runs the
// draft validator, prefixing its field with "draft".
func validateDraft(d approvalplan.ApprovalDraft) error {
	b, err := json.Marshal(d)
	if err != nil {
		return invalid("draft", "%v", err)
	}
	if len(b) > approvalplan.MaxDraftBytes {
		return &approvalplan.CodeError{Code: approvalplan.CodeRequestTooLarge, Field: "draft", Msg: fmt.Sprintf("is %d bytes; maximum is %d", len(b), approvalplan.MaxDraftBytes)}
	}
	if err := d.Validate(); err != nil {
		var ce *approvalplan.CodeError
		if !errors.As(err, &ce) {
			return invalid("draft", "%v", err)
		}
		field := "draft"
		if ce.Field != "" {
			field += "." + ce.Field
		}
		return &approvalplan.CodeError{Code: ce.Code, Field: field, Msg: ce.Msg}
	}
	return nil
}

func validateList(limit int, cursor string) error {
	if limit < 1 || limit > MaxListLimit {
		return invalid("limit", "must be 1..%d", MaxListLimit)
	}
	if cursor != "" && !validCursor(cursor) {
		return invalid("cursor", "must be 1..%d base64url bytes", MaxCursorBytes)
	}
	return nil
}

func validateWait(ids []string, waitSeconds int) error {
	if len(ids) < 1 || len(ids) > approvalplan.AwaitMaxIDs {
		return invalid("request_ids", "must hold 1..%d ids", approvalplan.AwaitMaxIDs)
	}
	seen := make(map[string]bool, len(ids))
	for i, id := range ids {
		if err := validateRequestID(fmt.Sprintf("request_ids[%d]", i), id); err != nil {
			return err
		}
		if seen[id] {
			return invalid(fmt.Sprintf("request_ids[%d]", i), "repeats %s", id)
		}
		seen[id] = true
	}
	if maxWait := int(approvalplan.AwaitMaxWait.Seconds()); waitSeconds < 0 || waitSeconds > maxWait {
		return invalid("wait_seconds", "must be 0..%d", maxWait)
	}
	return nil
}

func validateClaim(token, planHash string) error {
	if !approvalplan.ValidSHA256Hex(token) {
		return invalid("claim_token", "must be 64 lowercase hex")
	}
	if !approvalplan.ValidSHA256Hex(planHash) {
		return invalid("plan_hash", "must be 64 lowercase hex")
	}
	return nil
}

func marshalLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("approvalwire: encode: %w", err)
	}
	if len(b)+1 > MaxFrameBytes {
		return nil, fmt.Errorf("approvalwire: frame is %d bytes; maximum is %d", len(b)+1, MaxFrameBytes)
	}
	return append(b, '\n'), nil
}
