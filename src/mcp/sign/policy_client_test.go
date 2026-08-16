package sign

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const policyClientTestHost = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type policyClientFixture struct {
	private     ed25519.PrivateKey
	public      ed25519.PublicKey
	authorityID string
	request     policywire.Request
	payload     []byte
}

type fullWriteErrorConn struct{ *readResultConn }

func (c *fullWriteErrorConn) Write(p []byte) (int, error) { return len(p), errWriteBoom }

func newPolicyClientFixture(t testing.TB) policyClientFixture {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 31)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: policyClientTestHost, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request, err := policywire.NewRequest(
		"pm_0123456789abcdef0123456789abcdef",
		policyClientTestHost,
		keyID,
		payload,
		"",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return policyClientFixture{
		private: private, public: public,
		authorityID: "pauth_0123456789abcdef0123456789abcdef",
		request:     request, payload: payload,
	}
}

func (f policyClientFixture) response(t testing.TB, status policywire.Status) policywire.Response {
	t.Helper()
	payloadSHA, baseDigest, err := policywire.PayloadDigests(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	response := policywire.Response{
		RequestID: f.request.RequestID, AuthorityID: f.authorityID, Purpose: policywire.Purpose, Status: status,
		PayloadSHA256: payloadSHA, BaseDigest: baseDigest, SignerKeyID: f.request.ExpectedSignerKeyID,
	}
	if status == policywire.StatusApproved {
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
	if status == policywire.StatusError {
		response.ErrorCode = policywire.ErrorPolicyNotificationFailed
		response.Retryable = true
	}
	return response
}

func policyResponseLine(t testing.TB, response policywire.Response) []byte {
	t.Helper()
	line, err := policywire.MarshalResponseLine(response)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func withPolicyResponse(t *testing.T, response []byte) <-chan []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	original := dialWithCtx
	t.Cleanup(func() { dialWithCtx = original })
	dialWithCtx = func(context.Context, string) (net.Conn, error) { return clientConn, nil }
	requestLine := make(chan []byte, 1)
	go func() {
		defer serverConn.Close()
		line, _ := bufio.NewReader(serverConn).ReadBytes('\n')
		requestLine <- line
		if len(response) != 0 {
			_, _ = serverConn.Write(response)
		}
	}()
	return requestLine
}

func TestRequestBaseManifestApprovedWritesExactRequestAndVerifiesEnvelope(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	requestLine := withPolicyResponse(t, policyResponseLine(t, fixture.response(t, policywire.StatusApproved)))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}

	result, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if err != nil {
		t.Fatal(err)
	}
	wantRequest, err := policywire.MarshalRequestLine(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-requestLine; !bytes.Equal(got, wantRequest) {
		t.Fatalf("request line changed:\n got %q\nwant %q", got, wantRequest)
	}
	if result.RequestID != fixture.request.RequestID || result.SignerKeyID != fixture.request.ExpectedSignerKeyID {
		t.Fatalf("result correlation = %#v", result)
	}
	verified, err := policy.VerifyBaseManifest(result.ManifestEnvelope, fixture.public)
	if err != nil || verified.Host != fixture.request.HostKeyFP {
		t.Fatalf("returned envelope verification = %#v, %v", verified, err)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(result.ManifestEnvelope)
	if err != nil || !bytes.Equal(payload, fixture.payload) {
		t.Fatalf("returned payload mismatch: %v", err)
	}
}

func TestRequestBaseManifestAcceptsCanonicalResponseAtCleanEOF(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	body, err := policywire.MarshalResponse(fixture.response(t, policywire.StatusApproved))
	if err != nil {
		t.Fatal(err)
	}
	withPolicyResponse(t, body) // no trailing newline; server closes after the body
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	result, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ManifestEnvelope) == 0 {
		t.Fatal("clean-EOF approved response lost its verified envelope")
	}
}

func TestRequestBaseManifestReturnsTypedTerminalOutcomes(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	statuses := []policywire.Status{
		policywire.StatusDenied,
		policywire.StatusTimeout,
		policywire.StatusInterrupted,
		policywire.StatusError,
	}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			withPolicyResponse(t, policyResponseLine(t, fixture.response(t, status)))
			client := &Client{SocketPath: "/unused", Timeout: time.Second}
			_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
			var terminal *PolicyError
			if !errors.As(err, &terminal) {
				t.Fatalf("error = %v; want *PolicyError", err)
			}
			if terminal.RequestID != fixture.request.RequestID || terminal.Status != status {
				t.Fatalf("terminal = %#v", terminal)
			}
			if status == policywire.StatusError {
				if terminal.ErrorCode != policywire.ErrorPolicyNotificationFailed || !terminal.Retryable {
					t.Fatalf("error terminal = %#v", terminal)
				}
			} else if terminal.ErrorCode != "" || terminal.Retryable {
				t.Fatalf("non-error terminal carried error fields: %#v", terminal)
			}
		})
	}
}

func TestRequestBaseManifestRejectsPendingFromLocalSocket(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	withPolicyResponse(t, policyResponseLine(t, fixture.response(t, policywire.StatusPending)))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if !errors.Is(err, ErrPolicyPending) {
		t.Fatalf("error = %v; want ErrPolicyPending", err)
	}
	var terminal *PolicyError
	if errors.As(err, &terminal) {
		t.Fatalf("pending was exposed as a terminal PolicyError: %#v", terminal)
	}
}

func TestRequestBaseManifestRejectsResponseTupleMismatches(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	tests := map[string]func(*policywire.Response){
		"request id": func(r *policywire.Response) { r.RequestID = "pm_ffffffffffffffffffffffffffffffff" },
		"authority id": func(r *policywire.Response) {
			r.AuthorityID = "pauth_ffffffffffffffffffffffffffffffff"
		},
		"payload sha": func(r *policywire.Response) {
			r.PayloadSHA256 = strings.Repeat("a", 64)
		},
		"base digest": func(r *policywire.Response) { r.BaseDigest = strings.Repeat("b", 64) },
		"signer key":  func(r *policywire.Response) { r.SignerKeyID = strings.Repeat("c", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := fixture.response(t, policywire.StatusDenied)
			mutate(&response)
			withPolicyResponse(t, policyResponseLine(t, response))
			client := &Client{SocketPath: "/unused", Timeout: time.Second}
			if _, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID); err == nil || !strings.Contains(err.Error(), "verify response") {
				t.Fatalf("mismatch error = %v", err)
			}
		})
	}
}

func TestRequestBaseManifestRejectsAbsentAuthorityAgainstPinnedPair(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	response := fixture.response(t, policywire.StatusError)
	response.AuthorityID = ""
	response.ErrorCode = policywire.ErrorPolicyNotSupported
	response.Retryable = false
	withPolicyResponse(t, policyResponseLine(t, response))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if err == nil || !strings.Contains(err.Error(), "verify response") || !strings.Contains(err.Error(), "authority_id") {
		t.Fatalf("absent-authority error = %v; want pair-verification failure", err)
	}
	var terminal *PolicyError
	if errors.As(err, &terminal) {
		t.Fatalf("absent hosted authority was exposed as a verified terminal: %#v", terminal)
	}
}

func TestRequestBaseManifestRejectsWrongKeySignatureAndValidSubstitute(t *testing.T) {
	fixture := newPolicyClientFixture(t)

	t.Run("wrong frozen key", func(t *testing.T) {
		otherSeed := make([]byte, ed25519.SeedSize)
		for i := range otherSeed {
			otherSeed[i] = byte(255 - i)
		}
		otherPublic := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
		client := &Client{SocketPath: "/must-not-dial", Timeout: time.Second}
		if _, err := client.RequestBaseManifest(context.Background(), fixture.request, otherPublic, fixture.authorityID); err == nil || !strings.Contains(err.Error(), "does not match frozen key") {
			t.Fatalf("wrong-key error = %v", err)
		}
	})

	t.Run("wrong signature", func(t *testing.T) {
		response := fixture.response(t, policywire.StatusApproved)
		envelope, err := policy.EncodeBaseManifestEnvelope(fixture.payload, make([]byte, ed25519.SignatureSize))
		if err != nil {
			t.Fatal(err)
		}
		response.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
		withPolicyResponse(t, policyResponseLine(t, response))
		client := &Client{SocketPath: "/unused", Timeout: time.Second}
		if _, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID); err == nil {
			t.Fatal("wrong signature accepted")
		}
	})

	t.Run("different valid manifest", func(t *testing.T) {
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
		payloadSHA, baseDigest, err := policywire.PayloadDigests(payload)
		if err != nil {
			t.Fatal(err)
		}
		response := fixture.response(t, policywire.StatusApproved)
		response.PayloadSHA256 = payloadSHA
		response.BaseDigest = baseDigest
		response.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
		withPolicyResponse(t, policyResponseLine(t, response))
		client := &Client{SocketPath: "/unused", Timeout: time.Second}
		if _, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID); err == nil {
			t.Fatal("different valid manifest accepted")
		}
	})
}

func TestRequestBaseManifestUsesPolicyResponseFrameBound(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	withPolicyResponse(t, bytes.Repeat([]byte{'x'}, policywire.MaxResponseFrameBytes+1))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if !errors.Is(err, lineframe.ErrTooLarge) {
		t.Fatalf("oversize error = %v; want lineframe.ErrTooLarge", err)
	}
	if errors.Is(err, ErrPolicyVerdictUnknown) {
		t.Fatalf("oversize response misclassified as unknown verdict: %v", err)
	}
}

func TestRequestBaseManifestTransportUncertainty(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	tests := map[string]error{
		"clean EOF":       io.EOF,
		"network timeout": netTimeoutErr{},
	}
	for name, readErr := range tests {
		t.Run(name, func(t *testing.T) {
			withFakeDial(t, newReadResultConn(readErr))
			client := &Client{SocketPath: "/unused", Timeout: time.Second}
			_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
			if !errors.Is(err, ErrPolicyVerdictUnknown) {
				t.Fatalf("error = %v; want ErrPolicyVerdictUnknown", err)
			}
			if errors.Is(err, ErrVerdictUnknown) {
				t.Fatalf("policy uncertainty collapsed into ordinary sentinel: %v", err)
			}
		})
	}
}

func TestRequestBaseManifestFullWriteWithErrorIsVerdictUnknown(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	withFakeDial(t, &fullWriteErrorConn{readResultConn: newReadResultConn(io.EOF)})
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if !errors.Is(err, ErrPolicyVerdictUnknown) || !errors.Is(err, errWriteBoom) {
		t.Fatalf("full-write error = %v; want both ErrPolicyVerdictUnknown and underlying write error", err)
	}
}

func TestRequestBaseManifestZeroByteWriteErrorIsNotVerdictUnknown(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	withFakeDial(t, newWriteFailConn())
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if err == nil || !errors.Is(err, errWriteBoom) || errors.Is(err, ErrPolicyVerdictUnknown) {
		t.Fatalf("zero-byte write error = %v", err)
	}
}

func TestRequestBaseManifestPartialEOFIsMalformedNotUnknown(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	withPolicyResponse(t, []byte(`{"request_id":"pm_0123456789abcdef`))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(context.Background(), fixture.request, fixture.public, fixture.authorityID)
	if err == nil || !strings.Contains(err.Error(), "malformed response") {
		t.Fatalf("partial response error = %v", err)
	}
	if errors.Is(err, ErrPolicyVerdictUnknown) {
		t.Fatalf("partial response misclassified as unknown verdict: %v", err)
	}
}

func TestRequestBaseManifestContextCancellationIsNotUnknown(t *testing.T) {
	fixture := newPolicyClientFixture(t)
	withFakeDial(t, newReadResultConn(io.EOF))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.RequestBaseManifest(ctx, fixture.request, fixture.public, fixture.authorityID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v; want context.Canceled", err)
	}
	if errors.Is(err, ErrPolicyVerdictUnknown) {
		t.Fatalf("cancelled request misclassified as unknown verdict: %v", err)
	}
}
