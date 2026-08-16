package hosted

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

// PolicyMachineHandler serves only the two exact machine policy resources.
// AttachPolicy owns raw-target dispatch, authentication, throttling, and the
// readiness guard around this handler.
type PolicyMachineHandler struct {
	engine  *PolicyEngine
	store   policystore.Store
	archive *policyarchive.Archive
}

func NewPolicyMachineHandler(engine *PolicyEngine, archive *policyarchive.Archive) (*PolicyMachineHandler, error) {
	if engine == nil || engine.store == nil || archive == nil {
		return nil, errors.New("hosted policy handler: engine, store, and archive are required")
	}
	return &PolicyMachineHandler{engine: engine, store: engine.store, archive: archive}, nil
}

func (handler *PolicyMachineHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	switch request.Method {
	case http.MethodPost:
		handler.post(writer, request)
	case http.MethodGet:
		handler.get(writer, request)
	default:
		writeJSONError(writer, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (handler *PolicyMachineHandler) post(writer http.ResponseWriter, request *http.Request) {
	principal, ok := machinePrincipalFromContext(request.Context())
	if !ok {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, int64(policywire.MaxRequestFrameBytes))
	body, err := readLimited(request.Body, int64(policywire.MaxRequestFrameBytes))
	if err != nil {
		writePolicyGeneric(writer, http.StatusBadRequest, "invalid policy request")
		return
	}
	decoded, err := policywire.DecodeRequest(body)
	if err != nil {
		writePolicyGeneric(writer, http.StatusBadRequest, "invalid policy request")
		return
	}
	tuple, err := policyTuple(decoded)
	if err != nil {
		writePolicyGeneric(writer, http.StatusBadRequest, "invalid policy request")
		return
	}
	key := policystore.Key{Principal: principal, RequestID: decoded.Wire.RequestID}
	lookup, err := handler.store.Lookup(request.Context(), key, tuple)
	if err != nil {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	switch lookup.Kind {
	case policystore.LookupConflict:
		handler.writeConflict(writer, request.Context(), principal, decoded)
		return
	case policystore.LookupExact:
		handler.writeExactPost(writer, request.Context(), decoded, tuple, lookup, nil, true)
		return
	case policystore.LookupAbsent:
		result, submitErr := handler.engine.Admit(request.Context(), PolicyAdmissionInput{
			Principal: principal, CanonicalRequest: body, Decoded: decoded,
		})
		if result.Lookup.Kind == policystore.LookupConflict {
			handler.writeConflict(writer, request.Context(), principal, decoded)
			return
		}
		if result.Request == nil {
			handler.writeAdmissionError(writer, submitErr)
			return
		}
		handler.writeExactPost(writer, request.Context(), decoded, tuple, result.Lookup, submitErr, false)
	default:
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
	}
}

func policyTuple(decoded policywire.DecodedRequest) (policystore.RequestTuple, error) {
	payloadSHA, _, err := policywire.PayloadDigests(decoded.Payload)
	if err != nil {
		return policystore.RequestTuple{}, err
	}
	return policyauthority.RequestTuple{
		RequestID: decoded.Wire.RequestID, Purpose: policywire.Purpose, HostKeyFP: decoded.Wire.HostKeyFP,
		ExpectedSignerKeyID: decoded.Wire.ExpectedSignerKeyID, PayloadSHA256: payloadSHA,
		ExpectedHeadDigest: decoded.Wire.ExpectedHeadDigest, Bootstrap: decoded.Wire.Bootstrap,
	}, nil
}

func (handler *PolicyMachineHandler) writeConflict(writer http.ResponseWriter, ctx context.Context, principal string, decoded policywire.DecodedRequest) {
	body, err := handler.engine.IdempotencyConflict(ctx, principal, decoded)
	if err != nil || !handler.engine.Readiness().Ready() {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	handler.writeCanonical(writer, http.StatusConflict, body, decoded.Wire.RequestID, false)
}

func (handler *PolicyMachineHandler) writeExactPost(writer http.ResponseWriter, ctx context.Context, decoded policywire.DecodedRequest, tuple policystore.RequestTuple, lookup policystore.LookupResult, progressErr error, resume bool) {
	switch lookup.Class {
	case policystore.RowTerminal, policystore.RowTombstone:
		handler.writeLookupTerminal(writer, lookup, decoded.Wire.RequestID)
		return
	case policystore.RowLive:
		if lookup.Visibility == policystore.VisibilityPending {
			handler.writePending(writer, lookup.Request, true)
			return
		}
	default:
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	if lookup.Request == nil {
		handler.writeAdmissionError(writer, progressErr)
		return
	}
	if resume && progressErr == nil {
		progressErr = handler.engine.Resume(ctx, lookup.Request)
	}
	if !handler.engine.Readiness().Ready() {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	refreshed, err := handler.store.Lookup(ctx, lookup.Request.Key(), tuple)
	if err != nil || refreshed.Kind != policystore.LookupExact || refreshed.Request == nil {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	acceptedAdmission := lookup.Request.ErrorFamily == policystore.ErrorFamilyNone && lookup.Request.FailureCode == ""
	if acceptedAdmission && refreshed.Request.SubmissionAudited {
		handler.writePending(writer, refreshed.Request, true)
		return
	}
	if !acceptedAdmission && (refreshed.Class == policystore.RowTerminal || refreshed.Class == policystore.RowTombstone) {
		handler.writeLookupTerminal(writer, refreshed, decoded.Wire.RequestID)
		return
	}
	_ = progressErr
	writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
}

func (handler *PolicyMachineHandler) writeAdmissionError(writer http.ResponseWriter, err error) {
	var capacity *policystore.CapacityError
	if errors.As(err, &capacity) {
		if capacity.Kind == policystore.CapacityWindow {
			seconds := int64(math.Ceil(capacity.RetryAfter.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			if seconds > policystore.RejectionWindowSeconds {
				seconds = policystore.RejectionWindowSeconds
			}
			writer.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
		}
		writePolicyGeneric(writer, http.StatusTooManyRequests, "too many requests")
		return
	}
	writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
}

func (handler *PolicyMachineHandler) get(writer http.ResponseWriter, request *http.Request) {
	principal, ok := machinePrincipalFromContext(request.Context())
	if !ok {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	target := request.URL.EscapedPath()
	const prefix = "/v2/policy/base-manifests/"
	requestID := target[len(prefix):]
	result, err := handler.store.Fetch(request.Context(), policystore.Key{Principal: principal, RequestID: requestID})
	if errors.Is(err, policystore.ErrNotFound) {
		writePolicyGeneric(writer, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	switch result.Class {
	case policystore.RowLive:
		if result.Visibility != policystore.VisibilityPending || result.PendingResponse == nil {
			writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
			return
		}
		handler.writeCanonical(writer, http.StatusAccepted, result.PendingResponse, requestID, false)
	case policystore.RowTerminal:
		handler.writeCanonical(writer, result.TerminalHTTPStatus, result.TerminalResponse, requestID, false)
	case policystore.RowTombstone:
		body, err := handler.resolveTombstone(result.Tombstone, result.Archive)
		if err != nil {
			writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
			return
		}
		handler.writeCanonical(writer, result.TerminalHTTPStatus, body, requestID, false)
	default:
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
	}
}

func (handler *PolicyMachineHandler) writePending(writer http.ResponseWriter, request *policystore.Request, location bool) {
	if request == nil || request.PendingResponse == nil {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	if location {
		writer.Header().Set("Location", "/v2/policy/base-manifests/"+request.RequestID)
	}
	handler.writeCanonical(writer, http.StatusAccepted, request.PendingResponse, request.RequestID, location)
}

func (handler *PolicyMachineHandler) writeLookupTerminal(writer http.ResponseWriter, lookup policystore.LookupResult, requestID string) {
	if lookup.Request == nil || !lookup.Request.TerminalHTTPStatus.Valid {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	if lookup.Class == policystore.RowTerminal {
		handler.writeCanonical(writer, int(lookup.Request.TerminalHTTPStatus.Value), lookup.Request.TerminalResponse, requestID, false)
		return
	}
	body, err := handler.resolveTombstone(lookup.Request, lookup.Archive)
	if err != nil {
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	handler.writeCanonical(writer, int(lookup.Request.TerminalHTTPStatus.Value), body, requestID, false)
}

func (handler *PolicyMachineHandler) resolveTombstone(tombstone *policystore.Request, reference *policystore.ArchiveRef) ([]byte, error) {
	if tombstone == nil || reference == nil {
		return nil, errors.New("incomplete policy tombstone")
	}
	encoded, err := handler.archive.ReadObject(policyarchive.ObjectRef{SHA256: reference.ObjectSHA256, Bytes: reference.RecordBytes})
	if err != nil {
		return nil, err
	}
	return sqlitestore.ResolveTerminalArchive(tombstone, encoded)
}

func (handler *PolicyMachineHandler) writeCanonical(writer http.ResponseWriter, status int, body []byte, requestID string, keepLocation bool) {
	decoded, err := policywire.DecodeResponse(body)
	if err != nil || decoded.Wire.RequestID != requestID || decoded.Wire.AuthorityID != handler.engine.authorityID {
		writer.Header().Del("Location")
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	want, err := policyMachineHTTPStatus(decoded.Wire)
	if err != nil || want != status {
		writer.Header().Del("Location")
		writePolicyGeneric(writer, http.StatusServiceUnavailable, "policy authority unavailable")
		return
	}
	if !keepLocation {
		writer.Header().Del("Location")
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func policyMachineHTTPStatus(response policywire.Response) (int, error) {
	switch response.Status {
	case policywire.StatusPending:
		return http.StatusAccepted, nil
	case policywire.StatusApproved, policywire.StatusDenied, policywire.StatusTimeout, policywire.StatusInterrupted:
		return http.StatusOK, nil
	case policywire.StatusError:
		return policystore.HTTPStatusForError(response.ErrorCode)
	default:
		return 0, errors.New("unknown policy response status")
	}
}

func writePolicyGeneric(writer http.ResponseWriter, status int, message string) {
	writer.Header().Del("Location")
	if status != http.StatusTooManyRequests {
		writer.Header().Del("Retry-After")
	}
	writeJSONError(writer, status, message)
}

var _ http.Handler = (*PolicyMachineHandler)(nil)
