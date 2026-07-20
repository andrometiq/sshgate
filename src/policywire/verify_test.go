package policywire

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
)

type responseVerificationFixture struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	request Request
	payload []byte
}

func newResponseVerificationFixture(t testing.TB) responseVerificationFixture {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: testHost, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest("pm_0123456789abcdef0123456789abcdef", testHost, keyID, payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	return responseVerificationFixture{private: private, public: public, request: request, payload: payload}
}

func (f responseVerificationFixture) response(t testing.TB, status Status) DecodedResponse {
	t.Helper()
	payloadSHA, baseDigest, err := PayloadDigests(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{
		RequestID: f.request.RequestID, Purpose: Purpose, Status: status,
		PayloadSHA256: payloadSHA, BaseDigest: baseDigest, SignerKeyID: f.request.ExpectedSignerKeyID,
	}
	if status == StatusApproved {
		manifest, err := policy.ParseBaseManifest(f.payload)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := policy.SignBaseManifest(f.private, manifest)
		if err != nil {
			t.Fatal(err)
		}
		response.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
	}
	if status == StatusError {
		response.ErrorCode = ErrorPolicyNotificationFailed
		response.Retryable = true
	}
	body, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestVerifyResponseForRequestAcceptsEveryCorrelatedStatus(t *testing.T) {
	fixture := newResponseVerificationFixture(t)
	statuses := []Status{StatusPending, StatusApproved, StatusDenied, StatusTimeout, StatusInterrupted, StatusError}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			if err := VerifyResponseForRequest(fixture.request, fixture.response(t, status), fixture.public); err != nil {
				t.Fatalf("VerifyResponseForRequest(%s): %v", status, err)
			}
		})
	}
}

func TestVerifyResponseForRequestRejectsTupleSubstitution(t *testing.T) {
	fixture := newResponseVerificationFixture(t)
	base := fixture.response(t, StatusDenied)
	tests := map[string]func(*DecodedResponse){
		"request id": func(r *DecodedResponse) { r.Wire.RequestID = "pm_ffffffffffffffffffffffffffffffff" },
		"purpose":    func(r *DecodedResponse) { r.Wire.Purpose = "sign" },
		"payload sha": func(r *DecodedResponse) {
			r.Wire.PayloadSHA256 = strings.Repeat("a", 64)
		},
		"base digest": func(r *DecodedResponse) { r.Wire.BaseDigest = strings.Repeat("b", 64) },
		"signer key":  func(r *DecodedResponse) { r.Wire.SignerKeyID = strings.Repeat("c", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := base
			mutate(&response)
			if err := VerifyResponseForRequest(fixture.request, response, fixture.public); err == nil {
				t.Fatal("substituted response accepted")
			}
		})
	}
}

func TestVerifyResponseForRequestRejectsWrongKeyAndSignature(t *testing.T) {
	fixture := newResponseVerificationFixture(t)
	approved := fixture.response(t, StatusApproved)

	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = byte(255 - i)
	}
	otherPublic := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	if err := VerifyResponseForRequest(fixture.request, approved, otherPublic); err == nil {
		t.Fatal("wrong frozen public key accepted")
	}
	if err := VerifyResponseForRequest(fixture.request, approved, fixture.public[:31]); err == nil {
		t.Fatal("short frozen public key accepted")
	}

	tamperedEnvelope, err := policy.EncodeBaseManifestEnvelope(fixture.payload, make([]byte, ed25519.SignatureSize))
	if err != nil {
		t.Fatal(err)
	}
	tampered := approved
	tampered.Wire.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(tamperedEnvelope)
	tampered.ManifestEnvelope = tamperedEnvelope
	if err := VerifyResponseForRequest(fixture.request, tampered, fixture.public); err == nil {
		t.Fatal("bad envelope signature accepted")
	}

	decodedMismatch := approved
	decodedMismatch.ManifestEnvelope = append([]byte(nil), approved.ManifestEnvelope...)
	decodedMismatch.ManifestEnvelope[0] ^= 1
	if err := VerifyResponseForRequest(fixture.request, decodedMismatch, fixture.public); err == nil {
		t.Fatal("decoded envelope/wire mismatch accepted")
	}
}

func TestVerifyResponseForRequestRejectsDifferentValidManifest(t *testing.T) {
	fixture := newResponseVerificationFixture(t)
	different := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: fixture.request.HostKeyFP, Epoch: 1, Revision: 2,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	}
	envelope, err := policy.SignBaseManifest(fixture.private, different)
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
	response := Response{
		RequestID: fixture.request.RequestID, Purpose: Purpose, Status: StatusApproved,
		PayloadSHA256: payloadSHA, BaseDigest: baseDigest, SignerKeyID: fixture.request.ExpectedSignerKeyID,
		ManifestEnvelopeB64: base64.StdEncoding.EncodeToString(envelope),
	}
	body, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResponseForRequest(fixture.request, decoded, fixture.public); err == nil {
		t.Fatal("different valid manifest accepted for request")
	}
}

func TestVerifyResponseForRequestRejectsDifferentHostManifest(t *testing.T) {
	fixture := newResponseVerificationFixture(t)
	hostBytes := make([]byte, 32)
	for i := range hostBytes {
		hostBytes[i] = byte(64 + i)
	}
	differentHost := "SHA256:" + base64.RawStdEncoding.EncodeToString(hostBytes)
	different := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: differentHost, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	}
	envelope, err := policy.SignBaseManifest(fixture.private, different)
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
	response := Response{
		RequestID: fixture.request.RequestID, Purpose: Purpose, Status: StatusApproved,
		PayloadSHA256: payloadSHA, BaseDigest: baseDigest, SignerKeyID: fixture.request.ExpectedSignerKeyID,
		ManifestEnvelopeB64: base64.StdEncoding.EncodeToString(envelope),
	}
	body, err := MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResponseForRequest(fixture.request, decoded, fixture.public); err == nil {
		t.Fatal("different-host manifest accepted for request")
	}
}
