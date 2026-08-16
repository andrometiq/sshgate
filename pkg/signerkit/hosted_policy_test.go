package signerkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	hostedPolicyTestAuthority = "pauth_0123456789abcdef0123456789abcdef"
	hostedPolicyTestHost      = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hostedPolicyTestRequestID = "pm_0123456789abcdef0123456789abcdef"
)

type hostedPolicyRoundTripFunc func(*http.Request) (*http.Response, error)

func (function hostedPolicyRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type hostedPolicyFixture struct {
	public  ed25519.PublicKey
	request BaseManifestApprovalRequest
	wire    policywire.Request
}

func newHostedPolicyFixture(t testing.TB) hostedPolicyFixture {
	t.Helper()
	seed := bytes.Repeat([]byte{0x41}, ed25519.SeedSize)
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: hostedPolicyTestHost, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wireRequest, err := policywire.NewRequest(hostedPolicyTestRequestID, hostedPolicyTestHost, keyID, payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	return hostedPolicyFixture{
		public: public,
		request: BaseManifestApprovalRequest{
			RequestID: hostedPolicyTestRequestID, FrozenAuthorityID: hostedPolicyTestAuthority,
			HostKeyFP: hostedPolicyTestHost, ExpectedSignerKeyID: keyID, Payload: payload,
			FrozenPublicKey: append([]byte(nil), public...), Bootstrap: true,
		},
		wire: wireRequest,
	}
}

func (fixture hostedPolicyFixture) response(t testing.TB, status policywire.Status, code policywire.ErrorCode) policywire.Response {
	t.Helper()
	payloadSHA, baseDigest, err := policywire.PayloadDigests(fixture.request.Payload)
	if err != nil {
		t.Fatal(err)
	}
	response := policywire.Response{
		RequestID: fixture.request.RequestID, AuthorityID: fixture.request.FrozenAuthorityID,
		Purpose: policywire.Purpose, Status: status, PayloadSHA256: payloadSHA,
		BaseDigest: baseDigest, SignerKeyID: fixture.request.ExpectedSignerKeyID,
		ErrorCode: code,
	}
	response.Retryable = code == policywire.ErrorPolicyNotificationFailed || code == policywire.ErrorPolicyMaterializationFailed
	return response
}

func hostedPolicyHTTPResponseFor(t testing.TB, request *http.Request, status int, body []byte, location string) *http.Response {
	t.Helper()
	header := make(http.Header)
	if location != "" {
		header.Set("Location", location)
	}
	return &http.Response{
		StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Request: request,
	}
}

func marshalHostedPolicyResponse(t testing.TB, response policywire.Response) []byte {
	t.Helper()
	body, err := policywire.MarshalResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHostedPolicyAnchorIsInseparableAndDefensivelyCopied(t *testing.T) {
	fixture := newHostedPolicyFixture(t)
	if _, err := (&HostedServerBackend{}).BaseManifestAuthorityPublicKey(); err == nil {
		t.Fatal("unconfigured anchor accepted")
	}
	for _, test := range []struct {
		key       ed25519.PublicKey
		authority string
	}{
		{fixture.public[:31], hostedPolicyTestAuthority},
		{fixture.public, ""},
		{fixture.public, "pauth_" + strings.Repeat("A", 32)},
	} {
		if err := (&HostedServerBackend{}).ConfigurePolicyAuthority(test.key, test.authority); err == nil {
			t.Fatalf("invalid anchor accepted: key=%d authority=%q", len(test.key), test.authority)
		}
	}

	configured := append(ed25519.PublicKey(nil), fixture.public...)
	backend := &HostedServerBackend{}
	if err := backend.ConfigurePolicyAuthority(configured, hostedPolicyTestAuthority); err != nil {
		t.Fatal(err)
	}
	first, err := backend.BaseManifestAuthorityPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	configured[0] ^= 0xff
	first[1] ^= 0xff
	second, err := backend.BaseManifestAuthorityPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, fixture.public) {
		t.Fatalf("snapshotted key changed through caller alias: %x", second)
	}
	if authority, err := backend.BaseManifestAuthorityID(); err != nil || authority != hostedPolicyTestAuthority {
		t.Fatalf("authority = %q, %v", authority, err)
	}
	if err := backend.ConfigurePolicyAuthority(fixture.public, hostedPolicyTestAuthority); err == nil {
		t.Fatal("configured anchor was overwritten")
	}
}

func TestHostedPolicyClientPollsOnlyCorrelatedPendingAndAcceptsMismatchTerminal(t *testing.T) {
	fixture := newHostedPolicyFixture(t)
	pending := marshalHostedPolicyResponse(t, fixture.response(t, policywire.StatusPending, ""))
	mismatch := marshalHostedPolicyResponse(t, fixture.response(t, policywire.StatusError, policywire.ErrorSignerKeyChanged))
	var mu sync.Mutex
	paths := make([]string, 0, 2)
	responses := []struct {
		status   int
		body     []byte
		location string
	}{
		{http.StatusAccepted, pending, "/v2/policy/base-manifests/" + fixture.request.RequestID},
		{http.StatusConflict, mismatch, ""},
	}
	transport := hostedPolicyRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, request.Method+" "+request.URL.EscapedPath())
		if len(responses) == 0 {
			t.Fatal("unexpected extra request")
		}
		next := responses[0]
		responses = responses[1:]
		return hostedPolicyHTTPResponseFor(t, request, next.status, next.body, next.location), nil
	})
	backend := &HostedServerBackend{
		BaseURL: "https://policy.example", APIKey: "secret", ClientID: "machine",
		// Recovery verifies the persisted historical pair in the request. The
		// daemon separately compares that pair with this current anchor.
		HTTPClient: &http.Client{Transport: transport}, Timeout: time.Second,
	}
	if err := backend.ConfigurePolicyAuthority(bytes.Repeat([]byte{0x22}, ed25519.PublicKeySize), "pauth_ffffffffffffffffffffffffffffffff"); err != nil {
		t.Fatal(err)
	}
	resultChannel, err := backend.RequestBaseManifest(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	result := <-resultChannel
	if result.BackendError != nil || result.Status != policywire.StatusError || result.ErrorCode != policywire.ErrorSignerKeyChanged || result.AuthorityID != hostedPolicyTestAuthority || result.Kind != BaseManifestResultRemoteEnvelope {
		t.Fatalf("mismatch terminal = %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"POST /v2/policy/base-manifests",
		"GET /v2/policy/base-manifests/" + fixture.request.RequestID,
	}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("requests = %v; want %v", paths, want)
	}
}

func TestHostedPolicyClientVerificationMatrix(t *testing.T) {
	fixture := newHostedPolicyFixture(t)
	base := fixture.response(t, policywire.StatusDenied, "")
	tests := []struct {
		name       string
		mutate     func(*policywire.Response)
		httpStatus int
		body       []byte
		location   string
	}{
		{name: "wrong request", mutate: func(response *policywire.Response) { response.RequestID = "pm_ffffffffffffffffffffffffffffffff" }, httpStatus: http.StatusOK},
		{name: "wrong authority", mutate: func(response *policywire.Response) { response.AuthorityID = "pauth_ffffffffffffffffffffffffffffffff" }, httpStatus: http.StatusOK},
		{name: "wrong purpose", mutate: func(response *policywire.Response) { response.Purpose = "ordinary_sign" }, httpStatus: http.StatusOK},
		{name: "wrong payload", mutate: func(response *policywire.Response) { response.PayloadSHA256 = strings.Repeat("f", 64) }, httpStatus: http.StatusOK},
		{name: "wrong key", mutate: func(response *policywire.Response) { response.SignerKeyID = strings.Repeat("f", 64) }, httpStatus: http.StatusOK},
		{name: "wrong status mapping", httpStatus: http.StatusAccepted},
		{name: "terminal location", httpStatus: http.StatusOK, location: "/v2/policy/base-manifests/" + fixture.request.RequestID},
		{name: "generic error", httpStatus: http.StatusServiceUnavailable, body: []byte("{\"error\":\"policy authority unavailable\"}\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := base
			if test.mutate != nil {
				test.mutate(&response)
			}
			body := test.body
			if body == nil {
				// json.Marshal deliberately bypasses the strict encoder for the
				// wrong-purpose case so the client, not the fixture, rejects it.
				var err error
				body, err = json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
			}
			client := &http.Client{Transport: hostedPolicyRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return hostedPolicyHTTPResponseFor(t, request, test.httpStatus, body, test.location), nil
			})}
			backend := &HostedServerBackend{
				BaseURL: "https://policy.example", APIKey: "secret", ClientID: "machine",
				HTTPClient: client,
			}
			if err := backend.ConfigurePolicyAuthority(fixture.public, hostedPolicyTestAuthority); err != nil {
				t.Fatal(err)
			}
			if _, err := backend.RequestBaseManifest(context.Background(), fixture.request); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

func TestHostedPolicyClientRejectsMissingAuthorityAndRedirectWithoutMutatingClient(t *testing.T) {
	fixture := newHostedPolicyFixture(t)
	notSupported := fixture.response(t, policywire.StatusError, policywire.ErrorPolicyNotSupported)
	notSupported.AuthorityID = ""
	body := marshalHostedPolicyResponse(t, notSupported)
	originalRedirectCalls := 0
	client := &http.Client{
		Transport: hostedPolicyRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return hostedPolicyHTTPResponseFor(t, request, http.StatusFound, body, "https://evil.example/steal"), nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			originalRedirectCalls++
			return nil
		},
	}
	backend := &HostedServerBackend{
		BaseURL: "https://policy.example", APIKey: "secret", ClientID: "machine",
		HTTPClient: client,
	}
	if err := backend.ConfigurePolicyAuthority(fixture.public, hostedPolicyTestAuthority); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.RequestBaseManifest(context.Background(), fixture.request); err == nil {
		t.Fatal("authority-less policy_not_supported accepted")
	}
	if originalRedirectCalls != 0 || client.CheckRedirect == nil {
		t.Fatalf("caller client redirect policy was mutated or invoked: calls=%d", originalRedirectCalls)
	}
}
