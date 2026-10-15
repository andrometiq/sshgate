package approvalplan

import "fmt"

// Code is the closed set of v2 answer and error codes shared by the pure state
// core's answers and the local and hosted wires.
type Code string

const (
	CodeNotFound             Code = "not_found"
	CodeConflict             Code = "conflict"
	CodeInvalidRequest       Code = "invalid_request"
	CodeReservedVerb         Code = "reserved_verb"
	CodeRequestTooLarge      Code = "request_too_large"
	CodeRequestUnrenderable  Code = "request_unrenderable"
	CodeSubmitWindowClosed   Code = "submit_window_closed"
	CodeSubmitWindowAhead    Code = "submit_window_ahead"
	CodeQueueFull            Code = "queue_full"
	CodeInvalidClaim         Code = "invalid_claim"
	CodeInvalidReport        Code = "invalid_report"
	CodeStorageUncertain     Code = "storage_uncertain"
	CodeBusy                 Code = "busy"
	CodeRecordCorrupt        Code = "record_corrupt"
	CodeLifecycleUnavailable Code = "lifecycle_unavailable"
	CodeSignerIncompatible   Code = "signer_incompatible"
)

// AllCodes lists every Code in wire order. The goldens pin it.
var AllCodes = []Code{
	CodeNotFound, CodeConflict, CodeInvalidRequest, CodeReservedVerb,
	CodeRequestTooLarge, CodeRequestUnrenderable, CodeSubmitWindowClosed,
	CodeSubmitWindowAhead, CodeQueueFull, CodeInvalidClaim, CodeInvalidReport,
	CodeStorageUncertain, CodeBusy, CodeRecordCorrupt, CodeLifecycleUnavailable,
	CodeSignerIncompatible,
}

// Valid reports whether c is a member of the closed set.
func (c Code) Valid() bool {
	for _, known := range AllCodes {
		if c == known {
			return true
		}
	}
	return false
}

// Retryable reports whether c is transient in SA-5's one split: the same
// request bytes may be resent with bounded backoff. Every other code is
// definitive.
func (c Code) Retryable() bool {
	switch c {
	case CodeStorageUncertain, CodeBusy, CodeLifecycleUnavailable, CodeQueueFull, CodeSubmitWindowAhead:
		return true
	}
	return false
}

// CodeError is a refusal carrying its wire code and, for a validation
// refusal, the field that failed.
type CodeError struct {
	Code  Code
	Field string
	Msg   string
}

func (e *CodeError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("approvalplan: %s: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("approvalplan: %s: %s: %s", e.Code, e.Field, e.Msg)
}

func codeErr(code Code, field, format string, args ...any) *CodeError {
	return &CodeError{Code: code, Field: field, Msg: fmt.Sprintf(format, args...)}
}

func invalid(field, format string, args ...any) *CodeError {
	return codeErr(CodeInvalidRequest, field, format, args...)
}

// within prefixes a nested validation error's field with its parent path.
func within(prefix string, err error) error {
	ce, ok := err.(*CodeError)
	if !ok {
		return err
	}
	field := prefix
	if ce.Field != "" {
		field = prefix + "." + ce.Field
	}
	return &CodeError{Code: ce.Code, Field: field, Msg: ce.Msg}
}

// ClaimStatus is the closed set of Claim answers (SA-4 Claim).
type ClaimStatus string

const (
	ClaimSignatures           ClaimStatus = "signatures"
	ClaimNotReady             ClaimStatus = "not_ready"
	ClaimDenied               ClaimStatus = "denied"
	ClaimCanceled             ClaimStatus = "canceled"
	ClaimExpired              ClaimStatus = "expired"
	ClaimError                ClaimStatus = "error"
	ClaimExecutionReported    ClaimStatus = "execution_reported"
	ClaimMaterializationError ClaimStatus = "materialization_error"
)

// Valid reports whether s is a member of the closed set.
func (s ClaimStatus) Valid() bool {
	switch s {
	case ClaimSignatures, ClaimNotReady, ClaimDenied, ClaimCanceled, ClaimExpired,
		ClaimError, ClaimExecutionReported, ClaimMaterializationError:
		return true
	}
	return false
}
