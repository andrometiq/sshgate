package approvalwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Proto is the v2 approval family's own version, carried by every frame and
// body as approval_proto.
const Proto = 1

// The six local socket kinds (E13). There is no vote or cancel kind: operator
// actions stay on the human surfaces (K13).
const (
	KindSubmit = "approval_submit_v2"
	KindGet    = "approval_get_v2"
	KindList   = "approval_list_v2"
	KindWait   = "approval_wait_v2"
	KindClaim  = "approval_claim_v2"
	KindReport = "approval_report_v2"
)

// Kinds lists the six kinds in wire order.
var Kinds = []string{KindSubmit, KindGet, KindList, KindWait, KindClaim, KindReport}

// MaxFrameBytes bounds one local frame or hosted body in either direction,
// newline included. It covers a draft at approvalplan.MaxDraftBytes, a Claim
// answer carrying a worst-case signature set, and a full List or Wait page of
// summaries, and it stays under policywire.MaxSocketFrameBytes, the bound the
// daemon reads its first line with (asserted by the tests).
const MaxFrameBytes = 1 << 20

// Bounds of the list and wait requests.
const (
	MaxListLimit   = 100
	MaxCursorBytes = 128
	MaxMessageLen  = 512
)

// Fixed messages. not_found is byte-identical for a foreign and a missing id
// (SA-6.6) and for every 404 the hosted approvals plane answers (E3);
// signer_incompatible is E69's exact frame; busy is E21's fixed envelope.
const (
	MessageNotFound           = "approval request not found"
	MessageBusy               = "signer busy: the command was not applied; resend the same request"
	MessageSignerIncompatible = "hosted signer-server does not serve /v2/approvals; upgrade it (migration 7) before this MCP"
)

// Typed answers a caller classifies by errors.Is. A *WireError carrying the
// matching code satisfies the first three.
var (
	// ErrSignerIncompatible: the signer does not serve the v2 family (a pre-v2
	// local daemon's "unsupported kind", the proxy's signer_incompatible
	// frame, or a hosted non-envelope 404). Definitive (E69).
	ErrSignerIncompatible = errors.New("approvalwire: signer does not serve the v2 approval protocol")
	// ErrStorageUncertain: the signer's commit outcome is unknown. Resend the
	// same request bytes.
	ErrStorageUncertain = errors.New("approvalwire: signer storage outcome uncertain")
	// ErrBusy: hosted contention; the command was not applied, so resending
	// the same bytes is always safe (E21).
	ErrBusy = errors.New("approvalwire: signer busy; the command was not applied")
	// ErrResponseLost: the request was fully written but no response came
	// back. The command may have been applied; reconcile with Get.
	ErrResponseLost = errors.New("approvalwire: request written but no response arrived")
	// ErrTransport: a hosted answer other than 404 that is not an approvals
	// envelope (a reverse proxy's 502/503, say). Transient, as today.
	ErrTransport = errors.New("approvalwire: hosted answer is not an approvals envelope")
)

// WireError is a refusal on the wire: a code from approvalplan's closed set
// and a bounded one-line message.
type WireError struct {
	Code    approvalplan.Code `json:"code"`
	Message string            `json:"message"`
}

func (e *WireError) Error() string {
	return fmt.Sprintf("approvalwire: %s: %s", e.Code, e.Message)
}

// Is maps the codes that have a typed answer onto it.
func (e *WireError) Is(target error) bool {
	switch e.Code {
	case approvalplan.CodeSignerIncompatible:
		return target == ErrSignerIncompatible
	case approvalplan.CodeStorageUncertain:
		return target == ErrStorageUncertain
	case approvalplan.CodeBusy:
		return target == ErrBusy
	}
	return false
}

// Response is the one envelope every kind answers with, locally and hosted:
// {approval_proto:1, ok:true, …} or {approval_proto:1, ok:false, error:{…}}.
// Which payload an ok answer carries depends on its kind: Submit and Get a
// summary, List summaries and an optional next cursor, Wait summaries, Claim
// a claim answer, Report nothing.
type Response struct {
	ApprovalProto int                    `json:"approval_proto"`
	OK            bool                   `json:"ok"`
	Error         *WireError             `json:"error,omitempty"`
	Summary       *approvalplan.Summary  `json:"summary,omitempty"`
	Summaries     []approvalplan.Summary `json:"summaries,omitempty"`
	Claim         *ClaimAnswer           `json:"claim,omitempty"`
	NextCursor    string                 `json:"next_cursor,omitempty"`
}

// ErrorResponse builds the refusal envelope for code. A code with a fixed
// message ignores message.
func ErrorResponse(code approvalplan.Code, message string) Response {
	if fixed, ok := FixedMessage(code); ok {
		message = fixed
	}
	return Response{ApprovalProto: Proto, Error: &WireError{Code: code, Message: message}}
}

// FixedMessage returns the message a code must carry, if it has one.
func FixedMessage(code approvalplan.Code) (string, bool) {
	switch code {
	case approvalplan.CodeNotFound:
		return MessageNotFound, true
	case approvalplan.CodeBusy:
		return MessageBusy, true
	case approvalplan.CodeSignerIncompatible:
		return MessageSignerIncompatible, true
	}
	return "", false
}

// ClaimAnswer is a Claim's answer (SA-4 Claim). Reason is set only for
// materialization_error (a mint error other than window_closed, which answers
// expired), Class only for execution_reported, and DecidedAt and Signatures
// only for signatures: one envelope per signed leg in plan order, valid from
// DecidedAt for each leg's TTL.
type ClaimAnswer struct {
	Status     approvalplan.ClaimStatus `json:"status"`
	Reason     string                   `json:"reason,omitempty"`
	Class      approvalplan.JobClass    `json:"class,omitempty"`
	DecidedAt  *time.Time               `json:"decided_at,omitempty"`
	Signatures []string                 `json:"signatures,omitempty"`
}

// ReportSequence is the only report sequence: one final report, no progress
// reports (E25).
const ReportSequence = 1

// Report is the one final execution report (E38): every step 1..step_count,
// the job class, executed_ordinals, partial and result_digest. It never
// carries output bodies. The wire checks its shape; the signer checks that
// the steps are well formed and that class, executed_ordinals and partial
// equal approvalplan's functions of them (invalid_report, SA-4 Report).
type Report struct {
	ReportSequence   int                       `json:"report_sequence"`
	Steps            []approvalplan.StepReport `json:"steps"`
	Class            approvalplan.JobClass     `json:"class"`
	ExecutedOrdinals []int                     `json:"executed_ordinals,omitempty"`
	Partial          bool                      `json:"partial,omitempty"`
	ResultDigest     string                    `json:"result_digest"`
}

// decodeStrict decodes exactly one JSON value into dst, refusing unknown
// fields and trailing data, and requires the bytes to equal dst's json.Marshal
// encoding, which refuses duplicate keys, whitespace, alternate escapes and
// non-canonical numbers and times.
func decodeStrict(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	again, err := json.Marshal(dst)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return errors.New("not in canonical form")
	}
	return nil
}

// withoutOneNewline strips the frame's single trailing newline.
func withoutOneNewline(frame []byte) []byte {
	if n := len(frame); n > 0 && frame[n-1] == '\n' {
		return frame[:n-1]
	}
	return frame
}

func invalid(field, format string, args ...any) *approvalplan.CodeError {
	return &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Field: field, Msg: fmt.Sprintf(format, args...)}
}

// validateResponse checks resp as the answer to kind. hosted forbids the
// local-only signer_incompatible code.
func validateResponse(kind string, resp Response, hosted bool) error {
	if !slices.Contains(Kinds, kind) {
		return fmt.Errorf("unknown kind %q", kind)
	}
	if resp.ApprovalProto != Proto {
		return fmt.Errorf("approval_proto %d; want %d", resp.ApprovalProto, Proto)
	}
	if !resp.OK {
		if resp.Error == nil || resp.Summary != nil || len(resp.Summaries) > 0 || resp.Claim != nil || resp.NextCursor != "" {
			return errors.New("a refusal carries exactly one error and no payload")
		}
		if hosted && resp.Error.Code == approvalplan.CodeSignerIncompatible {
			return errors.New("signer_incompatible is a local frame only")
		}
		return validateWireError(*resp.Error)
	}
	if resp.Error != nil {
		return errors.New("an ok answer carries no error")
	}
	switch kind {
	case KindSubmit, KindGet:
		if resp.Summary == nil || len(resp.Summaries) > 0 || resp.Claim != nil || resp.NextCursor != "" {
			return fmt.Errorf("%s answers exactly one summary", kind)
		}
		return validateSummary("summary", *resp.Summary)
	case KindList, KindWait:
		if resp.Summary != nil || resp.Claim != nil {
			return fmt.Errorf("%s answers summaries only", kind)
		}
		return validateSummaries(kind, resp)
	case KindClaim:
		if resp.Claim == nil || resp.Summary != nil || len(resp.Summaries) > 0 || resp.NextCursor != "" {
			return errors.New("claim answers exactly one claim answer")
		}
		return validateClaimAnswer(*resp.Claim)
	case KindReport:
		if resp.Summary != nil || len(resp.Summaries) > 0 || resp.Claim != nil || resp.NextCursor != "" {
			return errors.New("report answers no payload")
		}
	}
	return nil
}

func validateWireError(e WireError) error {
	if !e.Code.Valid() {
		return fmt.Errorf("unknown error code %q", e.Code)
	}
	if fixed, ok := FixedMessage(e.Code); ok {
		if e.Message != fixed {
			return fmt.Errorf("%s must carry its fixed message", e.Code)
		}
		return nil
	}
	if !validMessage(e.Message) {
		return fmt.Errorf("error message must be 1..%d bytes of printable UTF-8 on one line", MaxMessageLen)
	}
	return nil
}

func validateSummaries(kind string, resp Response) error {
	limit := MaxListLimit
	if kind == KindWait {
		if resp.NextCursor != "" {
			return errors.New("wait answers no cursor")
		}
		limit = approvalplan.AwaitMaxIDs
	} else if resp.NextCursor != "" && !validCursor(resp.NextCursor) {
		return fmt.Errorf("next_cursor must be 1..%d base64url bytes", MaxCursorBytes)
	}
	if len(resp.Summaries) > limit {
		return fmt.Errorf("%d summaries; maximum is %d", len(resp.Summaries), limit)
	}
	for i, s := range resp.Summaries {
		if err := validateSummary(fmt.Sprintf("summaries[%d]", i), s); err != nil {
			return err
		}
	}
	return nil
}

// validateSummary checks every identity, enum and stamp of a summary. The
// views' coherence is the signer's (SA-6); the wire checks the vocabulary.
func validateSummary(field string, s approvalplan.Summary) error {
	switch {
	case !approvalplan.ValidRequestID(s.RequestID):
		return fmt.Errorf("%s.request_id is invalid", field)
	case !approvalplan.ValidRecordHandle(s.RecordHandle):
		return fmt.Errorf("%s.record_handle is invalid", field)
	case !s.Kind.Valid() || s.Kind == approvalplan.KindRegisterTransferKey:
		return fmt.Errorf("%s.kind %q is not a v2 submission kind", field, s.Kind)
	case !approvalplan.ValidSHA256Hex(s.PlanHash):
		return fmt.Errorf("%s.plan_hash must be 64 lowercase hex", field)
	case s.Coordinator != "" && !s.Coordinator.Valid():
		return fmt.Errorf("%s.coordinator %q is unknown", field, s.Coordinator)
	case !s.ApprovalStatus.Valid():
		return fmt.Errorf("%s.approval_status %q is unknown", field, s.ApprovalStatus)
	case !s.AssistState.Valid() || s.AssistRevision < 0 || s.AssistRevision > 1:
		return fmt.Errorf("%s.assist_state/assist_revision is invalid", field)
	case !s.ExecutionStatus.Valid():
		return fmt.Errorf("%s.execution_status %q is unknown", field, s.ExecutionStatus)
	case s.ExecutionClass != "" && !s.ExecutionClass.Valid():
		return fmt.Errorf("%s.execution_class %q is unknown", field, s.ExecutionClass)
	case !s.NotificationStatus.Valid():
		return fmt.Errorf("%s.notification_status %q is unknown", field, s.NotificationStatus)
	case !validRecordClass(s.Class):
		return fmt.Errorf("%s.class %q is unknown", field, s.Class)
	case !validOrdinals(s.ExecutedOrdinals):
		return fmt.Errorf("%s.executed_ordinals must ascend within 1..%d", field, approvalplan.MaxSteps)
	case !validText(s.TerminalReason, MaxMessageLen, true) || !validText(s.NotExecutableReason, MaxMessageLen, true):
		return fmt.Errorf("%s reasons must be printable one-line UTF-8 of at most %d bytes", field, MaxMessageLen)
	case s.GrantID != "" && (s.Kind != approvalplan.KindStandingGrant || s.GrantID != s.RequestID):
		return fmt.Errorf("%s.grant_id must be a grant record's request_id (E9)", field)
	case s.GrantExpiresAt != nil && s.GrantID == "":
		return fmt.Errorf("%s.grant_expires_at needs grant_id", field)
	}
	for _, stamp := range []*time.Time{&s.CreatedAt, &s.RequestExpiresAt, s.SyncClaimDeadline, s.DecidedAt, s.GrantExpiresAt} {
		if stamp != nil && !validStamp(*stamp) {
			return fmt.Errorf("%s stamps must be non-zero UTC times", field)
		}
	}
	return nil
}

func validateClaimAnswer(c ClaimAnswer) error {
	if !c.Status.Valid() {
		return fmt.Errorf("claim status %q is unknown", c.Status)
	}
	hasReason, hasClass, hasSignatures := c.Reason != "", c.Class != "", c.DecidedAt != nil || len(c.Signatures) > 0
	if hasReason != (c.Status == approvalplan.ClaimMaterializationError) {
		return errors.New("claim reason is carried by materialization_error only, and always")
	}
	if hasClass != (c.Status == approvalplan.ClaimExecutionReported) {
		return errors.New("claim class is carried by execution_reported only, and always")
	}
	if hasSignatures != (c.Status == approvalplan.ClaimSignatures) {
		return errors.New("decided_at and signatures are carried by signatures only, and always")
	}
	switch c.Status {
	case approvalplan.ClaimMaterializationError:
		if !validMintReason(c.Reason) {
			return fmt.Errorf("materialization_error reason %q is not a mint error", c.Reason)
		}
	case approvalplan.ClaimExecutionReported:
		if !c.Class.Valid() {
			return fmt.Errorf("execution_reported class %q is unknown", c.Class)
		}
	case approvalplan.ClaimSignatures:
		return validateSignatures(*c.DecidedAt, c.Signatures)
	}
	return nil
}

func validateSignatures(decidedAt time.Time, sigs []string) error {
	if !validStamp(decidedAt) {
		return errors.New("claim decided_at must be a non-zero UTC time")
	}
	if len(sigs) < 1 || len(sigs) > approvalplan.MaxSteps {
		return fmt.Errorf("claim carries %d signatures; want 1..%d", len(sigs), approvalplan.MaxSteps)
	}
	for i, s := range sigs {
		if !validSignatureEnvelope(s) {
			return fmt.Errorf("claim signatures[%d] is not an SSHGATE_SIG envelope", i)
		}
	}
	return nil
}

// validateReport checks the report's shape and vocabulary. Coherence of the
// class, executed_ordinals and partial with the steps is the signer's.
func validateReport(r Report) error {
	if r.ReportSequence != ReportSequence {
		return invalid("report.report_sequence", "must be %d", ReportSequence)
	}
	if len(r.Steps) < 1 || len(r.Steps) > approvalplan.MaxSteps {
		return invalid("report.steps", "must hold 1..%d steps", approvalplan.MaxSteps)
	}
	for i, s := range r.Steps {
		if s.Ordinal < 1 || s.Ordinal > approvalplan.MaxSteps || !s.Status.Valid() ||
			(s.StdoutBytes != nil && *s.StdoutBytes < 0) || (s.StderrBytes != nil && *s.StderrBytes < 0) {
			return invalid(fmt.Sprintf("report.steps[%d]", i), "needs an ordinal in 1..%d, a known status and non-negative byte counts", approvalplan.MaxSteps)
		}
	}
	if !r.Class.Valid() {
		return invalid("report.class", "unknown class %q", r.Class)
	}
	if !validOrdinals(r.ExecutedOrdinals) {
		return invalid("report.executed_ordinals", "must ascend within 1..%d", approvalplan.MaxSteps)
	}
	if !approvalplan.ValidSHA256Hex(r.ResultDigest) {
		return invalid("report.result_digest", "must be 64 lowercase hex")
	}
	return nil
}

func validRecordClass(c approvalplan.RecordClass) bool {
	return c == approvalplan.ClassLive || c == approvalplan.ClassAwaitingReport || c == approvalplan.ClassSettled
}

func validMintReason(reason string) bool {
	switch reason {
	case approvalplan.MintReasonGrantNotLive, approvalplan.MintReasonClockSkew, approvalplan.MintReasonStaleTransferKey,
		approvalplan.MintReasonReservedVerb, approvalplan.MintReasonSigningFailed:
		return true
	}
	return false
}

func validOrdinals(ordinals []int) bool {
	previous := 0
	for _, o := range ordinals {
		if o <= previous || o > approvalplan.MaxSteps {
			return false
		}
		previous = o
	}
	return true
}

func validStamp(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC
}

// validSignatureEnvelope checks "SSHGATE_SIG:" + base64url(64-byte sig) +
// ":" + base64url(payload), unpadded (src/sigwire/payload.go EncodeSigned).
func validSignatureEnvelope(s string) bool {
	const prefix, sigLen = "SSHGATE_SIG:", 86
	if len(s) < len(prefix)+sigLen+2 || s[:len(prefix)] != prefix || s[len(prefix)+sigLen] != ':' {
		return false
	}
	return isBase64URL(s[len(prefix):len(prefix)+sigLen]) && isBase64URL(s[len(prefix)+sigLen+1:])
}

func isBase64URL(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func validCursor(s string) bool {
	return len(s) >= 1 && len(s) <= MaxCursorBytes && isBase64URL(s)
}

func validMessage(s string) bool { return validText(s, MaxMessageLen, false) }

// validText reports whether s is at most max bytes of valid UTF-8 with no C0
// control, DEL or C1 control (so it stays one printable line).
func validText(s string, max int, emptyOK bool) bool {
	if len(s) > max || (s == "" && !emptyOK) || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}
