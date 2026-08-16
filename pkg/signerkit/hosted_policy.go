package signerkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	hostedPolicyNon2xxBodyLimit = 16 << 10
	hostedPolicyMaxPollAttempts = 64
	hostedPolicyInitialBackoff  = 100 * time.Millisecond
	hostedPolicyMaxBackoff      = 2 * time.Second
)

type hostedPolicyAnchor struct {
	publicKey   ed25519.PublicKey
	authorityID string
}

type hostedPolicyHTTPResponse struct {
	decoded policywire.DecodedResponse
	pending bool
}

// ConfigurePolicyAuthority installs one complete hosted policy trust anchor.
// It copies the key before returning and cannot leave a half-configured pair.
// Configuration must finish before the backend is shared between goroutines.
func (h *HostedServerBackend) ConfigurePolicyAuthority(publicKey ed25519.PublicKey, authorityID string) error {
	if h == nil {
		return errors.New("hosted: nil backend")
	}
	if h.policyConfigured {
		return errors.New("hosted: policy authority is already configured")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("hosted: policy public key is %d bytes; want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if !policyauthority.ValidAuthorityID(authorityID) {
		return errors.New("hosted: policy authority_id is not canonical")
	}
	copy(h.policyPublicKey[:], publicKey)
	h.policyAuthorityID = authorityID
	h.policyConfigured = true
	return nil
}

// HostedBaseManifestAuthority marks the hosted backend's remote-custody policy
// capability. The concrete pair is available only through the checked accessors
// below.
func (*HostedServerBackend) HostedBaseManifestAuthority() {}

// BaseManifestAuthorityPublicKey returns a defensive copy of the configured
// policy key. The key and authority ID are validated and snapshotted together.
func (h *HostedServerBackend) BaseManifestAuthorityPublicKey() ([]byte, error) {
	anchor, err := h.configuredPolicyAnchor()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), anchor.publicKey...), nil
}

// BaseManifestAuthorityID returns the authority half of the configured policy
// trust anchor. The key and authority ID are validated and snapshotted together.
func (h *HostedServerBackend) BaseManifestAuthorityID() (string, error) {
	anchor, err := h.configuredPolicyAnchor()
	if err != nil {
		return "", err
	}
	return anchor.authorityID, nil
}

func (h *HostedServerBackend) configuredPolicyAnchor() (*hostedPolicyAnchor, error) {
	if h == nil || !h.policyConfigured {
		return nil, errors.New("hosted: PolicyPublicKey and PolicyAuthorityID are required for policy requests")
	}
	return &hostedPolicyAnchor{
		publicKey:   append(ed25519.PublicKey(nil), h.policyPublicKey[:]...),
		authorityID: h.policyAuthorityID,
	}, nil
}

// RequestBaseManifest submits or reconciles one exact hosted policy request.
// Only a verified authority terminal is exposed as a result; local timeout,
// cancellation, malformed replies, and poll exhaustion are transport errors.
func (h *HostedServerBackend) RequestBaseManifest(ctx context.Context, req BaseManifestApprovalRequest) (<-chan BaseManifestApprovalResult, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	if _, err := h.configuredPolicyAnchor(); err != nil {
		return nil, err
	}
	wireRequest, frozenKey, err := hostedPolicyWireRequest(req)
	if err != nil {
		return nil, err
	}
	body, err := policywire.MarshalRequest(wireRequest)
	if err != nil {
		return nil, fmt.Errorf("hosted policy: marshal request: %w", err)
	}

	totalTimeout := h.Timeout
	if totalTimeout == 0 {
		totalTimeout = 60 * time.Second
	}
	if totalTimeout < 0 {
		return nil, errors.New("hosted policy: Timeout cannot be negative")
	}
	requestCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	postURL := strings.TrimRight(h.BaseURL, "/") + "/v2/policy/base-manifests"
	response, err := h.doHostedPolicyRequest(requestCtx, http.MethodPost, postURL, body, wireRequest, frozenKey, req.FrozenAuthorityID)
	if err != nil {
		cancel()
		return nil, err
	}
	if !response.pending {
		cancel()
		return completedHostedPolicyResult(response.decoded), nil
	}

	pollURL := strings.TrimRight(h.BaseURL, "/") + "/v2/policy/base-manifests/" + url.PathEscape(wireRequest.RequestID)
	result := make(chan BaseManifestApprovalResult, 1)
	go h.pollHostedPolicy(requestCtx, cancel, pollURL, wireRequest, frozenKey, req.FrozenAuthorityID, result)
	return result, nil
}

func hostedPolicyWireRequest(req BaseManifestApprovalRequest) (policywire.Request, ed25519.PublicKey, error) {
	if req.DecisionHooks != nil || len(req.TrustedHeadEnvelope) != 0 {
		return policywire.Request{}, nil, errors.New("hosted policy: request carried local decision state")
	}
	if len(req.FrozenPublicKey) != ed25519.PublicKeySize {
		return policywire.Request{}, nil, fmt.Errorf("hosted policy: frozen public key is %d bytes; want %d", len(req.FrozenPublicKey), ed25519.PublicKeySize)
	}
	if !policyauthority.ValidAuthorityID(req.FrozenAuthorityID) {
		return policywire.Request{}, nil, errors.New("hosted policy: frozen authority_id is not canonical")
	}
	frozenKey := append(ed25519.PublicKey(nil), req.FrozenPublicKey...)
	keyID, err := policy.SignerKeyID(frozenKey)
	if err != nil {
		return policywire.Request{}, nil, fmt.Errorf("hosted policy: frozen public key: %w", err)
	}
	if keyID != req.ExpectedSignerKeyID {
		return policywire.Request{}, nil, errors.New("hosted policy: expected signer key ID does not match frozen public key")
	}
	wireRequest, err := policywire.NewRequest(
		req.RequestID,
		req.HostKeyFP,
		req.ExpectedSignerKeyID,
		append([]byte(nil), req.Payload...),
		req.ExpectedHeadDigest,
		req.Bootstrap,
	)
	if err != nil {
		return policywire.Request{}, nil, fmt.Errorf("hosted policy: request: %w", err)
	}
	return wireRequest, frozenKey, nil
}

func (h *HostedServerBackend) pollHostedPolicy(ctx context.Context, cancel context.CancelFunc, pollURL string, request policywire.Request, frozenKey ed25519.PublicKey, frozenAuthorityID string, out chan<- BaseManifestApprovalResult) {
	defer cancel()
	defer close(out)
	backoff := hostedPolicyInitialBackoff
	for attempt := 0; attempt < hostedPolicyMaxPollAttempts; attempt++ {
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			out <- BaseManifestApprovalResult{BackendError: fmt.Errorf("hosted policy: polling ended: %w", ctx.Err())}
			return
		case <-timer.C:
		}

		response, err := h.doHostedPolicyRequest(ctx, http.MethodGet, pollURL, nil, request, frozenKey, frozenAuthorityID)
		if err != nil {
			out <- BaseManifestApprovalResult{BackendError: err}
			return
		}
		if !response.pending {
			out <- hostedPolicyResult(response.decoded)
			return
		}
		if backoff < hostedPolicyMaxBackoff {
			backoff *= 2
			if backoff > hostedPolicyMaxBackoff {
				backoff = hostedPolicyMaxBackoff
			}
		}
	}
	out <- BaseManifestApprovalResult{BackendError: errors.New("hosted policy: polling attempt limit exhausted")}
}

func (h *HostedServerBackend) doHostedPolicyRequest(ctx context.Context, method, endpoint string, body []byte, request policywire.Request, frozenKey ed25519.PublicKey, frozenAuthorityID string) (hostedPolicyHTTPResponse, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: build %s request: %w", method, err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+h.APIKey)
	httpRequest.Header.Set("Accept", "application/json")
	if body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}

	response, err := h.policyClient().Do(httpRequest)
	if err != nil {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: %s: %w", method, err)
	}
	defer response.Body.Close()
	limit := hostedPolicyNon2xxBodyLimit
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		limit = policywire.MaxResponseFrameBytes
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: read %s response: %w", method, err)
	}
	if len(responseBody) > limit {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: %s response exceeds %d bytes", method, limit)
	}
	decoded, err := policywire.DecodeResponse(responseBody)
	if err != nil {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: decode %s response with HTTP %d: %w", method, response.StatusCode, err)
	}
	if err := policywire.VerifyResponseForRequest(request, decoded, frozenKey, frozenAuthorityID); err != nil {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: verify %s response: %w", method, err)
	}
	expectedStatus, err := hostedPolicyHTTPStatus(decoded.Wire)
	if err != nil {
		return hostedPolicyHTTPResponse{}, err
	}
	if response.StatusCode != expectedStatus {
		return hostedPolicyHTTPResponse{}, fmt.Errorf("hosted policy: %s response status %d does not match canonical terminal status %d", method, response.StatusCode, expectedStatus)
	}

	locations := response.Header.Values("Location")
	pending := decoded.Wire.Status == policywire.StatusPending
	if method == http.MethodPost && pending {
		want := "/v2/policy/base-manifests/" + url.PathEscape(request.RequestID)
		if len(locations) != 1 || locations[0] != want {
			return hostedPolicyHTTPResponse{}, errors.New("hosted policy: pending POST response has invalid Location")
		}
	} else if len(locations) != 0 {
		return hostedPolicyHTTPResponse{}, errors.New("hosted policy: response carried an unexpected Location")
	}
	return hostedPolicyHTTPResponse{decoded: decoded, pending: pending}, nil
}

func hostedPolicyHTTPStatus(response policywire.Response) (int, error) {
	switch response.Status {
	case policywire.StatusPending:
		return http.StatusAccepted, nil
	case policywire.StatusApproved, policywire.StatusDenied, policywire.StatusTimeout, policywire.StatusInterrupted:
		return http.StatusOK, nil
	case policywire.StatusError:
		switch response.ErrorCode {
		case policywire.ErrorInvalidPolicyRequest:
			return http.StatusBadRequest, nil
		case policywire.ErrorIdempotencyConflict,
			policywire.ErrorPolicyRequestInProgress,
			policywire.ErrorSignerKeyChanged,
			policywire.ErrorStalePolicyHead,
			policywire.ErrorPolicyKeyTransitionRequired,
			policywire.ErrorQuorumUnattainable:
			return http.StatusConflict, nil
		case policywire.ErrorPolicyJournalFull:
			return http.StatusTooManyRequests, nil
		case policywire.ErrorPolicyNotificationFailed, policywire.ErrorPolicyMaterializationFailed:
			return http.StatusInternalServerError, nil
		case policywire.ErrorPolicyNotSupported:
			return http.StatusNotImplemented, nil
		}
	}
	return 0, errors.New("hosted policy: response has no canonical HTTP status")
}

func completedHostedPolicyResult(response policywire.DecodedResponse) <-chan BaseManifestApprovalResult {
	out := make(chan BaseManifestApprovalResult, 1)
	out <- hostedPolicyResult(response)
	close(out)
	return out
}

func hostedPolicyResult(response policywire.DecodedResponse) BaseManifestApprovalResult {
	return BaseManifestApprovalResult{
		AuthorityID:      response.Wire.AuthorityID,
		Status:           response.Wire.Status,
		ErrorCode:        response.Wire.ErrorCode,
		Retryable:        response.Wire.Retryable,
		Kind:             BaseManifestResultRemoteEnvelope,
		ManifestEnvelope: append([]byte(nil), response.ManifestEnvelope...),
	}
}

func (h *HostedServerBackend) policyClient() *http.Client {
	client := *h.client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

var _ BaseManifestApprovalBackend = (*HostedServerBackend)(nil)
var _ HostedBaseManifestApprovalBackend = (*HostedServerBackend)(nil)
