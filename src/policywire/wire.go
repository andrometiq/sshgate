// Package policywire defines the dedicated base-manifest approval wire. It is
// intentionally disjoint from sigwire and the ordinary signer request types:
// policy authority must never be interpreted as a command-signing request.
package policywire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/karthikeyan5/sshgate/src/policy"
)

const (
	// Kind and Purpose are deliberately the same frozen spelling on their
	// respective request and response fields.
	Kind    = "base_manifest_sign_v1"
	Purpose = "base_manifest_sign_v1"

	// ProtoVersion is local to the policy purpose. It does not change the
	// frozen global sigwire protocol version.
	ProtoVersion = 1

	jsonFrameOverhead = 4 << 10

	// MaxRequestFrameBytes and MaxResponseFrameBytes are derived from the
	// policy codec maxima plus a fixed typed-JSON allowance. MaxSocketFrameBytes
	// is the larger of the two and is also used by the ordinary socket path so
	// bounding allocation cannot silently shrink its legacy envelope.
	MaxRequestFrameBytes  = base64EncodedMaxPolicyPayload + jsonFrameOverhead
	MaxResponseFrameBytes = base64EncodedMaxPolicyEnvelope + jsonFrameOverhead
	MaxSocketFrameBytes   = MaxResponseFrameBytes

	base64EncodedMaxPolicyPayload  = (policy.MaxPolicyPayloadBytes + 2) / 3 * 4
	base64EncodedMaxPolicyEnvelope = (policy.MaxPolicyEnvelopeBytes + 2) / 3 * 4
)

// Status is the policy-purpose status vocabulary. It is not shared with the
// ordinary ResultStatus enum.
type Status string

const (
	StatusPending     Status = "pending"
	StatusApproved    Status = "approved"
	StatusDenied      Status = "denied"
	StatusTimeout     Status = "timeout"
	StatusInterrupted Status = "interrupted"
	StatusError       Status = "error"
)

// ErrorCode is the closed policy-purpose error vocabulary.
type ErrorCode string

const (
	ErrorInvalidPolicyRequest        ErrorCode = "invalid_policy_request"
	ErrorPolicyNotSupported          ErrorCode = "policy_not_supported"
	ErrorIdempotencyConflict         ErrorCode = "idempotency_conflict"
	ErrorPolicyRequestInProgress     ErrorCode = "policy_request_in_progress"
	ErrorSignerKeyChanged            ErrorCode = "signer_key_changed"
	ErrorStalePolicyHead             ErrorCode = "stale_policy_head"
	ErrorPolicyKeyTransitionRequired ErrorCode = "policy_key_transition_required"
	ErrorPolicyJournalFull           ErrorCode = "policy_journal_full"
	ErrorPolicyNotificationFailed    ErrorCode = "policy_notification_failed"
	ErrorPolicyMaterializationFailed ErrorCode = "policy_materialization_failed"
)

// Request is the exact typed request shape. PayloadB64 is standard padded
// base64 of the canonical BaseManifest payload.
type Request struct {
	Kind                string `json:"kind"`
	RequestID           string `json:"request_id"`
	PolicyProto         int    `json:"policy_proto"`
	HostKeyFP           string `json:"host_key_fp"`
	ExpectedSignerKeyID string `json:"expected_signer_key_id"`
	PayloadB64          string `json:"payload_b64"`
	ExpectedHeadDigest  string `json:"expected_head_digest,omitempty"`
	Bootstrap           bool   `json:"bootstrap,omitempty"`
}

// DecodedRequest retains the exact payload bytes alongside the validated wire
// and parsed canonical manifest. Callers must use Payload for signing rather
// than marshal Manifest again.
type DecodedRequest struct {
	Wire     Request
	Payload  []byte
	Manifest policy.BaseManifest
}

// Response is the exact typed response shape. Retryable is intentionally not
// omitted: false is part of the dedicated response contract. Only approved
// responses carry ManifestEnvelopeB64.
type Response struct {
	RequestID           string    `json:"request_id"`
	Purpose             string    `json:"purpose"`
	Status              Status    `json:"status"`
	PayloadSHA256       string    `json:"payload_sha256"`
	BaseDigest          string    `json:"base_digest"`
	SignerKeyID         string    `json:"signer_key_id"`
	ErrorCode           ErrorCode `json:"error_code,omitempty"`
	Retryable           bool      `json:"retryable"`
	ManifestEnvelopeB64 string    `json:"manifest_envelope_b64,omitempty"`
}

// DecodedResponse retains exact approved envelope bytes when present.
type DecodedResponse struct {
	Wire             Response
	ManifestEnvelope []byte
}

// NewRequest constructs the typed wire from exact canonical payload bytes.
func NewRequest(requestID, hostKeyFP, signerKeyID string, payload []byte, expectedHeadDigest string, bootstrap bool) (Request, error) {
	if len(payload) == 0 || len(payload) > policy.MaxPolicyPayloadBytes {
		return Request{}, fmt.Errorf("policy wire request: payload length %d is outside 1..%d", len(payload), policy.MaxPolicyPayloadBytes)
	}
	req := Request{
		Kind:                Kind,
		RequestID:           requestID,
		PolicyProto:         ProtoVersion,
		HostKeyFP:           hostKeyFP,
		ExpectedSignerKeyID: signerKeyID,
		PayloadB64:          base64.StdEncoding.EncodeToString(payload),
		ExpectedHeadDigest:  expectedHeadDigest,
		Bootstrap:           bootstrap,
	}
	if _, _, err := validateRequest(req); err != nil {
		return Request{}, err
	}
	return req, nil
}

// MarshalRequest returns canonical typed JSON without socket framing.
func MarshalRequest(req Request) ([]byte, error) {
	if _, _, err := validateRequest(req); err != nil {
		return nil, err
	}
	return json.Marshal(req)
}

// MarshalRequestLine returns canonical typed JSON followed by one newline.
func MarshalRequestLine(req Request) ([]byte, error) {
	body, err := MarshalRequest(req)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// DecodeRequest strictly accepts only the canonical json.Marshal(Request)
// representation and validates/decode the exact policy payload once.
func DecodeRequest(body []byte) (DecodedRequest, error) {
	var req Request
	if err := decodeCanonical(body, &req); err != nil {
		return DecodedRequest{}, fmt.Errorf("policy wire request: %w", err)
	}
	payload, manifest, err := validateRequest(req)
	if err != nil {
		return DecodedRequest{}, err
	}
	return DecodedRequest{Wire: req, Payload: payload, Manifest: manifest}, nil
}

// DecodeRequestLine accepts canonical request JSON with either one trailing
// newline or a clean EOF boundary. CRLF and every other suffix are rejected.
func DecodeRequestLine(frame []byte) (DecodedRequest, error) {
	return DecodeRequest(withoutOneNewline(frame))
}

// MarshalResponse returns canonical typed JSON without socket framing.
func MarshalResponse(resp Response) ([]byte, error) {
	if _, err := validateResponse(resp); err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

// MarshalResponseLine returns canonical typed JSON followed by one newline.
func MarshalResponseLine(resp Response) ([]byte, error) {
	body, err := MarshalResponse(resp)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// DecodeResponse strictly accepts only canonical json.Marshal(Response).
func DecodeResponse(body []byte) (DecodedResponse, error) {
	var resp Response
	if err := decodeCanonical(body, &resp); err != nil {
		return DecodedResponse{}, fmt.Errorf("policy wire response: %w", err)
	}
	envelope, err := validateResponse(resp)
	if err != nil {
		return DecodedResponse{}, err
	}
	return DecodedResponse{Wire: resp, ManifestEnvelope: envelope}, nil
}

// DecodeResponseLine is the framed counterpart of DecodeResponse.
func DecodeResponseLine(frame []byte) (DecodedResponse, error) {
	return DecodeResponse(withoutOneNewline(frame))
}

// PayloadDigests computes the raw payload SHA-256 and the domain-separated
// BaseManifest digest in their frozen lowercase-hex wire forms.
func PayloadDigests(payload []byte) (payloadSHA256, baseDigest string, err error) {
	base, err := policy.BaseManifestPayloadDigest(payload)
	if err != nil {
		return "", "", err
	}
	raw := sha256.Sum256(payload)
	return hex.EncodeToString(raw[:]), hex.EncodeToString(base[:]), nil
}

func validateRequest(req Request) ([]byte, policy.BaseManifest, error) {
	if req.Kind != Kind {
		return nil, policy.BaseManifest{}, fmt.Errorf("policy wire request: kind %q; want %q", req.Kind, Kind)
	}
	if !validRequestID(req.RequestID) {
		return nil, policy.BaseManifest{}, errors.New("policy wire request: request_id must be pm_ plus 32 lowercase hexadecimal characters")
	}
	if req.PolicyProto != ProtoVersion {
		return nil, policy.BaseManifest{}, fmt.Errorf("policy wire request: policy_proto %d; want %d", req.PolicyProto, ProtoVersion)
	}
	if !validDigest(req.ExpectedSignerKeyID) {
		return nil, policy.BaseManifest{}, errors.New("policy wire request: expected_signer_key_id must be 64 lowercase hexadecimal characters")
	}
	if req.Bootstrap {
		if req.ExpectedHeadDigest != "" {
			return nil, policy.BaseManifest{}, errors.New("policy wire request: bootstrap must omit expected_head_digest")
		}
	} else if !validDigest(req.ExpectedHeadDigest) {
		return nil, policy.BaseManifest{}, errors.New("policy wire request: non-bootstrap requires a 64-character lowercase expected_head_digest")
	}
	payload, err := decodeCanonicalBase64(req.PayloadB64, policy.MaxPolicyPayloadBytes, "payload_b64")
	if err != nil {
		return nil, policy.BaseManifest{}, fmt.Errorf("policy wire request: %w", err)
	}
	manifest, err := policy.ParseBaseManifest(payload)
	if err != nil {
		return nil, policy.BaseManifest{}, fmt.Errorf("policy wire request: payload: %w", err)
	}
	if manifest.Host != req.HostKeyFP {
		return nil, policy.BaseManifest{}, fmt.Errorf("policy wire request: payload host %q does not match host_key_fp %q", manifest.Host, req.HostKeyFP)
	}
	return payload, manifest, nil
}

func validateResponse(resp Response) ([]byte, error) {
	if !validRequestID(resp.RequestID) {
		return nil, errors.New("policy wire response: invalid request_id")
	}
	if resp.Purpose != Purpose {
		return nil, fmt.Errorf("policy wire response: purpose %q; want %q", resp.Purpose, Purpose)
	}
	if !validDigest(resp.PayloadSHA256) || !validDigest(resp.BaseDigest) || !validDigest(resp.SignerKeyID) {
		return nil, errors.New("policy wire response: payload/base/key digests must be 64 lowercase hexadecimal characters")
	}
	if !validStatus(resp.Status) {
		return nil, fmt.Errorf("policy wire response: unknown status %q", resp.Status)
	}
	if resp.Status == StatusError {
		if !validErrorCode(resp.ErrorCode) {
			return nil, fmt.Errorf("policy wire response: unknown error_code %q", resp.ErrorCode)
		}
		canRetry := resp.ErrorCode == ErrorPolicyNotificationFailed || resp.ErrorCode == ErrorPolicyMaterializationFailed
		if resp.Retryable != canRetry {
			return nil, fmt.Errorf("policy wire response: retryable=%t is invalid for error_code %q", resp.Retryable, resp.ErrorCode)
		}
	} else if resp.ErrorCode != "" || resp.Retryable {
		return nil, errors.New("policy wire response: non-error status cannot carry error_code or retryable=true")
	}

	if resp.Status == StatusApproved {
		if resp.ManifestEnvelopeB64 == "" {
			return nil, errors.New("policy wire response: approved status requires manifest_envelope_b64")
		}
		envelope, err := decodeCanonicalBase64(resp.ManifestEnvelopeB64, policy.MaxPolicyEnvelopeBytes, "manifest_envelope_b64")
		if err != nil {
			return nil, err
		}
		payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
		if err != nil {
			return nil, fmt.Errorf("policy wire response: manifest envelope: %w", err)
		}
		payloadSHA, baseDigest, err := PayloadDigests(payload)
		if err != nil {
			return nil, fmt.Errorf("policy wire response: manifest payload: %w", err)
		}
		if payloadSHA != resp.PayloadSHA256 || baseDigest != resp.BaseDigest {
			return nil, errors.New("policy wire response: manifest envelope digests do not match response")
		}
		return envelope, nil
	}
	if resp.ManifestEnvelopeB64 != "" {
		return nil, errors.New("policy wire response: only approved status may carry manifest_envelope_b64")
	}
	return nil, nil
}

func decodeCanonicalBase64(encoded string, maxDecoded int, field string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	maxEncoded := base64.StdEncoding.EncodedLen(maxDecoded)
	if len(encoded) > maxEncoded || base64.StdEncoding.DecodedLen(len(encoded)) > maxDecoded {
		return nil, fmt.Errorf("%s exceeds %d decoded bytes", field, maxDecoded)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("%s is not canonical standard base64", field)
	}
	if len(decoded) == 0 || len(decoded) > maxDecoded {
		return nil, fmt.Errorf("%s decoded length %d is outside 1..%d", field, len(decoded), maxDecoded)
	}
	return decoded, nil
}

func decodeCanonical(body []byte, dst any) error {
	if len(body) == 0 {
		return errors.New("empty JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	canonical, err := json.Marshal(dst)
	if err != nil {
		return fmt.Errorf("re-marshal JSON: %w", err)
	}
	if !bytes.Equal(body, canonical) {
		return errors.New("JSON is not the canonical typed encoding")
	}
	return nil
}

func withoutOneNewline(frame []byte) []byte {
	if len(frame) > 0 && frame[len(frame)-1] == '\n' {
		return frame[:len(frame)-1]
	}
	return frame
}

func validRequestID(s string) bool {
	return len(s) == 35 && s[:3] == "pm_" && validLowerHex(s[3:])
}

func validDigest(s string) bool { return len(s) == 64 && validLowerHex(s) }

func validLowerHex(s string) bool {
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func validStatus(s Status) bool {
	switch s {
	case StatusPending, StatusApproved, StatusDenied, StatusTimeout, StatusInterrupted, StatusError:
		return true
	default:
		return false
	}
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorInvalidPolicyRequest, ErrorPolicyNotSupported, ErrorIdempotencyConflict,
		ErrorPolicyRequestInProgress, ErrorSignerKeyChanged, ErrorStalePolicyHead,
		ErrorPolicyKeyTransitionRequired, ErrorPolicyJournalFull,
		ErrorPolicyNotificationFailed, ErrorPolicyMaterializationFailed:
		return true
	default:
		return false
	}
}
