package policywire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
)

const (
	testHost        = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testAuthorityID = "pauth_0123456789abcdef0123456789abcdef"
	testPayload     = `{"schema":1,"host":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","epoch":1,"miss_action":"classifier","growth":"none","revision":1,"revoked_permit_ids":[],"entries":[]}`
)

func testRequest(t testing.TB) Request {
	t.Helper()
	req, err := NewRequest(
		"pm_0123456789abcdef0123456789abcdef",
		testHost,
		strings.Repeat("a", 64),
		[]byte(testPayload),
		"",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRequestLineGolden(t *testing.T) {
	got, err := MarshalRequestLine(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"kind\":\"base_manifest_sign_v1\",\"request_id\":\"pm_0123456789abcdef0123456789abcdef\",\"policy_proto\":1,\"host_key_fp\":\"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"expected_signer_key_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"payload_b64\":\"eyJzY2hlbWEiOjEsImhvc3QiOiJTSEEyNTY6QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsImVwb2NoIjoxLCJtaXNzX2FjdGlvbiI6ImNsYXNzaWZpZXIiLCJncm93dGgiOiJub25lIiwicmV2aXNpb24iOjEsInJldm9rZWRfcGVybWl0X2lkcyI6W10sImVudHJpZXMiOltdfQ==\",\"bootstrap\":true}\n"
	if string(got) != want {
		t.Fatalf("request wire drifted:\n got  %q\n want %q", got, want)
	}
	decoded, err := DecodeRequestLine(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Payload, []byte(testPayload)) || decoded.Manifest.Host != testHost {
		t.Fatalf("decoded request drifted: %#v", decoded)
	}
}

func TestResponseLineGolden(t *testing.T) {
	resp := Response{
		RequestID:     "pm_0123456789abcdef0123456789abcdef",
		AuthorityID:   testAuthorityID,
		Purpose:       Purpose,
		Status:        StatusDenied,
		PayloadSHA256: strings.Repeat("b", 64),
		BaseDigest:    strings.Repeat("c", 64),
		SignerKeyID:   strings.Repeat("a", 64),
	}
	got, err := MarshalResponseLine(resp)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"request_id\":\"pm_0123456789abcdef0123456789abcdef\",\"authority_id\":\"pauth_0123456789abcdef0123456789abcdef\",\"purpose\":\"base_manifest_sign_v1\",\"status\":\"denied\",\"payload_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"base_digest\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"signer_key_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"retryable\":false}\n"
	if string(got) != want {
		t.Fatalf("response wire drifted:\n got  %q\n want %q", got, want)
	}
	if _, err := DecodeResponseLine(got); err != nil {
		t.Fatal(err)
	}
}

func TestRequestStrictCanonicalJSON(t *testing.T) {
	line, err := MarshalRequest(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"leading whitespace":  append([]byte(" "), line...),
		"trailing whitespace": append(append([]byte(nil), line...), ' '),
		"duplicate":           []byte(strings.Replace(string(line), `"kind":"`+Kind+`"`, `"kind":"`+Kind+`","kind":"`+Kind+`"`, 1)),
		"unknown":             []byte(strings.Replace(string(line), `{"kind"`, `{"extra":1,"kind"`, 1)),
		"reordered": []byte(strings.Replace(
			string(line),
			`{"kind":"`+Kind+`","request_id":"pm_0123456789abcdef0123456789abcdef"`,
			`{"request_id":"pm_0123456789abcdef0123456789abcdef","kind":"`+Kind+`"`,
			1,
		)),
		"double newline": append(append([]byte(nil), line...), '\n', '\n'),
		"CRLF":           append(append([]byte(nil), line...), '\r', '\n'),
	}
	for name, malformed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequestLine(malformed); err == nil {
				t.Fatalf("accepted %s: %q", name, malformed)
			}
		})
	}
	if _, err := DecodeRequest(line); err != nil {
		t.Fatalf("canonical newline-less request rejected: %v", err)
	}
}

func TestRequestRejectsFieldAndPayloadSubstitution(t *testing.T) {
	base := testRequest(t)
	tests := map[string]func(*Request){
		"kind":                func(r *Request) { r.Kind = "sign" },
		"request id":          func(r *Request) { r.RequestID = "pm_UPPER" },
		"policy proto":        func(r *Request) { r.PolicyProto++ },
		"key id":              func(r *Request) { r.ExpectedSignerKeyID = strings.Repeat("A", 64) },
		"head omitted":        func(r *Request) { r.Bootstrap = false },
		"head on bootstrap":   func(r *Request) { r.ExpectedHeadDigest = strings.Repeat("b", 64) },
		"noncanonical base64": func(r *Request) { r.PayloadB64 = strings.TrimRight(r.PayloadB64, "=") },
		"wrong host":          func(r *Request) { r.HostKeyFP = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
		"noncanonical payload": func(r *Request) {
			r.PayloadB64 = base64.StdEncoding.EncodeToString(append([]byte(" "), []byte(testPayload)...))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			body, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(body); err == nil {
				t.Fatalf("accepted mutation %s", name)
			}
		})
	}
}

func TestResponseStatusEnvelopeAndRetryContracts(t *testing.T) {
	base := Response{
		RequestID:     "pm_0123456789abcdef0123456789abcdef",
		AuthorityID:   testAuthorityID,
		Purpose:       Purpose,
		Status:        StatusDenied,
		PayloadSHA256: strings.Repeat("b", 64),
		BaseDigest:    strings.Repeat("c", 64),
		SignerKeyID:   strings.Repeat("a", 64),
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{Schema: 1, Host: testHost, Epoch: 1, Revision: 1, MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone}
	envelope, err := policy.SignBaseManifest(priv, manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA, baseDigest, err := PayloadDigests(payload)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*Response){
		"unknown status":       func(r *Response) { r.Status = "done" },
		"envelope on denied":   func(r *Response) { r.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope) },
		"approved no envelope": func(r *Response) { r.Status = StatusApproved },
		"error no code":        func(r *Response) { r.Status = StatusError },
		"unknown code":         func(r *Response) { r.Status = StatusError; r.ErrorCode = "backend_detail" },
		"retry wrong code":     func(r *Response) { r.Status = StatusError; r.ErrorCode = ErrorSignerKeyChanged; r.Retryable = true },
		"retry flag missing":   func(r *Response) { r.Status = StatusError; r.ErrorCode = ErrorPolicyNotificationFailed },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			body, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeResponse(body); err == nil {
				t.Fatalf("accepted mutation %s", name)
			}
		})
	}

	approved := base
	approved.Status = StatusApproved
	approved.PayloadSHA256 = payloadSHA
	approved.BaseDigest = baseDigest
	approved.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
	body, err := MarshalResponse(approved)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ManifestEnvelope, envelope) {
		t.Fatal("approved envelope bytes changed")
	}
	tamperedDigest := approved
	tamperedDigest.PayloadSHA256 = strings.Repeat("d", 64)
	tamperedBody, err := json.Marshal(tamperedDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(tamperedBody); err == nil {
		t.Fatal("approved envelope/response digest substitution accepted")
	}

	retry := base
	retry.Status = StatusError
	retry.ErrorCode = ErrorPolicyMaterializationFailed
	retry.Retryable = true
	if _, err := MarshalResponse(retry); err != nil {
		t.Fatalf("valid retryable error rejected: %v", err)
	}
}

func TestResponseAuthorityPresenceBiconditional(t *testing.T) {
	base := Response{
		RequestID: "pm_0123456789abcdef0123456789abcdef", AuthorityID: testAuthorityID,
		Purpose: Purpose, Status: StatusDenied,
		PayloadSHA256: strings.Repeat("b", 64), BaseDigest: strings.Repeat("c", 64), SignerKeyID: strings.Repeat("a", 64),
	}
	tests := map[string]func(*Response){
		"required authority absent": func(r *Response) { r.AuthorityID = "" },
		"unsupported carries authority": func(r *Response) {
			r.Status = StatusError
			r.ErrorCode = ErrorPolicyNotSupported
		},
		"wrong authority prefix": func(r *Response) { r.AuthorityID = "xauth_0123456789abcdef0123456789abcdef" },
		"uppercase authority":    func(r *Response) { r.AuthorityID = "pauth_0123456789ABCDEF0123456789abcdef" },
		"padded authority":       func(r *Response) { r.AuthorityID += "0" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := base
			mutate(&response)
			if _, err := MarshalResponse(response); err == nil {
				t.Fatal("invalid authority presence accepted on encode")
			}
			body, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeResponse(body); err == nil {
				t.Fatal("invalid authority presence accepted on decode")
			}
		})
	}

	unsupported := base
	unsupported.AuthorityID = ""
	unsupported.Status = StatusError
	unsupported.ErrorCode = ErrorPolicyNotSupported
	body, err := MarshalResponse(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"request_id\":\"pm_0123456789abcdef0123456789abcdef\",\"purpose\":\"base_manifest_sign_v1\",\"status\":\"error\",\"payload_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"base_digest\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"signer_key_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"error_code\":\"policy_not_supported\",\"retryable\":false}"
	if string(body) != want {
		t.Fatalf("policy_not_supported response bytes changed:\n got  %q\n want %q", body, want)
	}
	if _, err := DecodeResponse(body); err != nil {
		t.Fatalf("canonical policy_not_supported response rejected: %v", err)
	}
}

func TestQuorumUnattainableResponseGolden(t *testing.T) {
	response := Response{
		RequestID: "pm_0123456789abcdef0123456789abcdef", AuthorityID: testAuthorityID,
		Purpose: Purpose, Status: StatusError,
		PayloadSHA256: strings.Repeat("b", 64), BaseDigest: strings.Repeat("c", 64), SignerKeyID: strings.Repeat("a", 64),
		ErrorCode: ErrorQuorumUnattainable,
	}
	line, err := MarshalResponseLine(response)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"request_id\":\"pm_0123456789abcdef0123456789abcdef\",\"authority_id\":\"pauth_0123456789abcdef0123456789abcdef\",\"purpose\":\"base_manifest_sign_v1\",\"status\":\"error\",\"payload_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"base_digest\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"signer_key_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"error_code\":\"quorum_unattainable\",\"retryable\":false}\n"
	if string(line) != want {
		t.Fatalf("quorum_unattainable response wire drifted:\n got  %q\n want %q", line, want)
	}
	if _, err := DecodeResponseLine(line); err != nil {
		t.Fatalf("quorum_unattainable response rejected: %v", err)
	}
}

func TestFrameBoundsAreDerivedFromPolicyMaxima(t *testing.T) {
	if got, want := MaxRequestFrameBytes, base64.StdEncoding.EncodedLen(policy.MaxPolicyPayloadBytes)+(4<<10); got != want {
		t.Fatalf("request frame bound = %d; want %d", got, want)
	}
	if got, want := MaxResponseFrameBytes, base64.StdEncoding.EncodedLen(policy.MaxPolicyEnvelopeBytes)+(4<<10); got != want {
		t.Fatalf("response frame bound = %d; want %d", got, want)
	}
	if MaxSocketFrameBytes < MaxRequestFrameBytes || MaxSocketFrameBytes < MaxResponseFrameBytes {
		t.Fatal("ordinary socket bound is not the larger policy frame bound")
	}
}

func TestDecodeCanonicalBase64BoundExactAndPlusOne(t *testing.T) {
	exact := bytes.Repeat([]byte{'x'}, policy.MaxPolicyPayloadBytes)
	decoded, err := decodeCanonicalBase64(base64.StdEncoding.EncodeToString(exact), policy.MaxPolicyPayloadBytes, "payload_b64")
	if err != nil {
		t.Fatalf("exact %d-byte payload rejected: %v", policy.MaxPolicyPayloadBytes, err)
	}
	if !bytes.Equal(decoded, exact) {
		t.Fatal("exact-limit payload changed during decode")
	}
	plusOne := bytes.Repeat([]byte{'x'}, policy.MaxPolicyPayloadBytes+1)
	if _, err := decodeCanonicalBase64(base64.StdEncoding.EncodeToString(plusOne), policy.MaxPolicyPayloadBytes, "payload_b64"); err == nil {
		t.Fatal("payload bound +1 accepted")
	}
}

func TestPayloadDigestsRejectNonCanonicalPayload(t *testing.T) {
	sha, base, err := PayloadDigests([]byte(testPayload))
	if err != nil || len(sha) != 64 || len(base) != 64 {
		t.Fatalf("PayloadDigests = %q, %q, %v", sha, base, err)
	}
	if _, _, err := PayloadDigests(append([]byte(" "), []byte(testPayload)...)); err == nil {
		t.Fatal("noncanonical payload accepted")
	}
}

func TestDecodeResponseRejectsOversizeBeforeBase64Decode(t *testing.T) {
	resp := Response{
		RequestID: "pm_0123456789abcdef0123456789abcdef", AuthorityID: testAuthorityID, Purpose: Purpose, Status: StatusApproved,
		PayloadSHA256: strings.Repeat("b", 64), BaseDigest: strings.Repeat("c", 64), SignerKeyID: strings.Repeat("a", 64),
		ManifestEnvelopeB64: strings.Repeat("A", base64.StdEncoding.EncodedLen(policy.MaxPolicyEnvelopeBytes)+4),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(body); err == nil || errors.Is(err, policy.ErrInvalidEnvelope) {
		t.Fatalf("oversize response error = %v", err)
	}
}
