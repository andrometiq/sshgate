package sign

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// ErrPolicyVerdictUnknown means the exact policy request was fully written,
// but no complete response arrived. The signer may already have committed a
// terminal human decision. Callers must fail closed and may recover only by
// resubmitting the same request tuple with the same request ID; they must not
// generate a replacement ID automatically.
var ErrPolicyVerdictUnknown = errors.New("policy: verdict undelivered; recover with the exact same request ID")

// ErrPolicyPending marks a protocol violation on the local signer socket.
// Hosted polling may return pending, but the local daemon exposes only audited
// terminal policy outcomes.
var ErrPolicyPending = errors.New("policy: local signer returned nonterminal pending")

// PolicyResult is a verified approved base-manifest result. Every digest and
// the envelope has been correlated to the submitted request and the frozen
// authority key. ManifestEnvelope is a defensive copy.
type PolicyResult struct {
	RequestID        string
	PayloadSHA256    string
	BaseDigest       string
	SignerKeyID      string
	ManifestEnvelope []byte
}

// PolicyError is a verified, audited terminal non-approval returned by the
// policy wire. Status is denied, timeout, interrupted, or error. ErrorCode and
// Retryable are populated only for status=error and retain the wire's closed
// vocabulary; no backend detail is accepted or exposed.
type PolicyError struct {
	RequestID string
	Status    policywire.Status
	ErrorCode policywire.ErrorCode
	Retryable bool
}

func (e *PolicyError) Error() string {
	if e == nil {
		return "policy: <nil terminal error>"
	}
	if e.Status == policywire.StatusError {
		return fmt.Sprintf("policy: request %s failed with %s (retryable=%t)", e.RequestID, e.ErrorCode, e.Retryable)
	}
	return fmt.Sprintf("policy: request %s ended with %s", e.RequestID, e.Status)
}

// RequestBaseManifest submits one already-constructed policy request to the
// local signer socket and verifies the response against the frozen public-key
// and authority-ID pair. It never generates or replaces a request ID and never
// retries. Callers that receive ErrPolicyVerdictUnknown may recover only with
// the exact same request tuple and ID.
//
// Approval returns PolicyResult. Every terminal non-approval returns a typed
// *PolicyError. A pending response is rejected because pending is hosted-only
// and must never be emitted by the local signer socket.
func (c *Client) RequestBaseManifest(ctx context.Context, request policywire.Request, frozenPublicKey ed25519.PublicKey, frozenAuthorityID string) (PolicyResult, error) {
	wire, err := policywire.MarshalRequestLine(request)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("policy: request: %w", err)
	}
	keyID, err := policy.SignerKeyID(frozenPublicKey)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("policy: frozen authority key: %w", err)
	}
	if request.ExpectedSignerKeyID != keyID {
		return PolicyResult{}, fmt.Errorf("policy: request signer key %q does not match frozen key %q", request.ExpectedSignerKeyID, keyID)
	}
	if c.SocketPath == "" {
		return PolicyResult{}, fmt.Errorf("policy: SocketPath is empty")
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = sigwire.ClientSignTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialWithCtx(dialCtx, c.SocketPath)
	if err != nil {
		return PolicyResult{}, classifyDialError(err)
	}
	defer conn.Close()

	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	written, err := writePolicyRequest(conn, wire)
	if err != nil {
		if written == len(wire) {
			return PolicyResult{}, fmt.Errorf("%w: request write acknowledgement failed: %w", ErrPolicyVerdictUnknown, err)
		}
		return PolicyResult{}, fmt.Errorf("policy: write: %w", err)
	}

	line, err := lineframe.Read(conn, policywire.MaxResponseFrameBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PolicyResult{}, fmt.Errorf("policy: %w", ctxErr)
		}
		if isVerdictLost(err, len(line)) {
			return PolicyResult{}, fmt.Errorf("%w: %v", ErrPolicyVerdictUnknown, err)
		}
		return PolicyResult{}, fmt.Errorf("policy: read response: %w", err)
	}

	decoded, err := policywire.DecodeResponseLine(line)
	if err != nil {
		return PolicyResult{}, fmt.Errorf("policy: malformed response: %w", err)
	}
	if err := policywire.VerifyResponseForRequest(request, decoded, frozenPublicKey, frozenAuthorityID); err != nil {
		return PolicyResult{}, fmt.Errorf("policy: verify response: %w", err)
	}

	response := decoded.Wire
	switch response.Status {
	case policywire.StatusApproved:
		return PolicyResult{
			RequestID:        response.RequestID,
			PayloadSHA256:    response.PayloadSHA256,
			BaseDigest:       response.BaseDigest,
			SignerKeyID:      response.SignerKeyID,
			ManifestEnvelope: append([]byte(nil), decoded.ManifestEnvelope...),
		}, nil
	case policywire.StatusPending:
		return PolicyResult{}, ErrPolicyPending
	case policywire.StatusDenied, policywire.StatusTimeout, policywire.StatusInterrupted, policywire.StatusError:
		return PolicyResult{}, &PolicyError{
			RequestID: response.RequestID,
			Status:    response.Status,
			ErrorCode: response.ErrorCode,
			Retryable: response.Retryable,
		}
	default:
		// DecodeResponseLine has a closed status vocabulary. Keep this branch
		// defensive in case that contract changes without this client.
		return PolicyResult{}, fmt.Errorf("policy: unhandled response status %q", response.Status)
	}
}

func writePolicyRequest(w io.Writer, request []byte) (int, error) {
	written := 0
	for len(request) > 0 {
		n, err := w.Write(request)
		if n < 0 || n > len(request) {
			return written, fmt.Errorf("invalid write count %d for %d remaining bytes", n, len(request))
		}
		if n > 0 {
			request = request[n:]
			written += n
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
