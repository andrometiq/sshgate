package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HostedServerBackend speaks the v2 wire protocol against a hosted
// signer-server (see docs/design.md §"Signed-write wire format" and
// docs/approval-architecture.md). It is the swap-point that lets a
// signer laptop daemon delegate approval to a centralized HTTPS
// service instead of running a local Telegram bot.
//
// Wire dance:
//
//	POST /v1/sign           → 202 {request_id, poll_url}
//	GET  /v1/poll/{request_id} (long-poll)
//	                        → 200 {status, signatures?, approved_by_user?, approved_at?}
//
// The handler loops on /v1/poll until status leaves "pending", the
// per-request Timeout fires, or ctx is cancelled. On approval we
// hand the signed payloads back via the same Result channel as the
// TelegramBackend, so the daemon's downstream code path is
// unchanged.
//
// Concurrency: HTTPClient is shared across calls (stdlib http.Client
// is safe for concurrent use). Request spawns one goroutine per call
// to drive the long-poll; the goroutine exits as soon as it sends
// one Result on the channel.
type HostedServerBackend struct {
	// BaseURL is the signer-server origin (no trailing slash).
	// Example: https://signer-server.example.com. Required.
	BaseURL string

	// APIKey is the bearer token sent on every request as
	// "Authorization: Bearer <APIKey>". Required.
	APIKey string

	// ClientID identifies this laptop in the server's audit log
	// (e.g. "karthi-laptop"). Required.
	ClientID string

	// HTTPClient is the transport used for both sign + poll. When
	// nil, http.DefaultClient is used; production wiring should
	// inject a client with explicit Timeout < PollWait * 2 so a
	// dead connection surfaces before the long-poll deadline.
	HTTPClient *http.Client

	// PollWait is the server-side long-poll window per /v1/poll
	// request (v2.1 will support ?wait= query param). Defaults to
	// 30s. The client may issue multiple polls inside one Request
	// call if Timeout > PollWait.
	PollWait time.Duration

	// Timeout is the total per-Request budget (across submit +
	// possibly-multiple polls). Defaults to 60s. ctx cancellation
	// always wins over Timeout.
	Timeout time.Duration
}

// signRequestBody is the POST /v1/sign body. Matches the
// signer-server handlers.signRequest shape exactly — keep them
// in lockstep with the wire protocol spec.
type signRequestBody struct {
	ClientID string             `json:"client_id"`
	Commands []signRequestCmdV2 `json:"commands"`
}

type signRequestCmdV2 struct {
	Server     string `json:"server"`
	Cmd        string `json:"cmd"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// signAcceptedBody is the 202 response. We only consume RequestID;
// PollURL is informational (we construct the URL ourselves to keep
// the client immune to a misbehaving server that returns a relative
// URL containing a different scheme/host).
type signAcceptedBody struct {
	RequestID string `json:"request_id"`
	PollURL   string `json:"poll_url"`
}

// pollBody is the GET /v1/poll/{id} response. Mirrors the server
// handler's pollResponse shape.
type pollBody struct {
	RequestID  string      `json:"request_id"`
	Status     string      `json:"status"`
	Signatures []signedSig `json:"signatures,omitempty"`
	ApprovedBy string      `json:"approved_by_user,omitempty"`
	ApprovedAt *time.Time  `json:"approved_at,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type signedSig struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// Request implements Backend. It POSTs the sign request, kicks off a
// goroutine that long-polls /v1/poll until resolution, and returns
// the result channel synchronously.
//
// The returned channel is closed after exactly one Result is sent.
// On submission error (network, 4xx/5xx from POST /v1/sign) Request
// returns the error and no channel — same contract as
// TelegramBackend.
func (h *HostedServerBackend) Request(ctx context.Context, req ApprovalRequest) (<-chan Result, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}

	// Fail-CLOSED on secret-reveal. The v2 wire structs (signRequestCmdV2
	// here, signRequestCmd on the server) carry only server/cmd/ttl_seconds —
	// they do NOT carry the reveal flag or its mandatory reason. If we let a
	// reveal request through, the server would sign it as an ordinary
	// (reveal=false) approval and a future v2 web UI could render it as a
	// plain write — no scary banner, no reason shown — which a human could
	// approve unknowingly. That is fail-SAFE only by accident today (the gate
	// redactor still strips the output). We make it fail-CLOSED instead:
	// reject reveal here, BEFORE any HTTP call, so no future v2 build can
	// silently ship an un-bannered reveal. The hosted path may enable reveal
	// only once the wire structs + web UI carry the reason and the scary
	// approval banner end-to-end (that is the v2 feature work, out of scope).
	for _, c := range req.Commands {
		if c.Reveal {
			return nil, errors.New("hosted: secret-reveal is not supported on the hosted (Tier-3) signer backend yet; use the local Telegram signer")
		}
	}

	pollWait := h.PollWait
	if pollWait == 0 {
		pollWait = 30 * time.Second
	}
	totalTimeout := h.Timeout
	if totalTimeout == 0 {
		totalTimeout = 60 * time.Second
	}

	body := signRequestBody{
		ClientID: h.ClientID,
		Commands: make([]signRequestCmdV2, len(req.Commands)),
	}
	for i, c := range req.Commands {
		body.Commands[i] = signRequestCmdV2{
			Server:     c.Server,
			Cmd:        c.Cmd,
			TTLSeconds: c.TTLSec,
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("hosted: marshal sign body: %w", err)
	}

	// Submit synchronously: the daemon needs to know up-front
	// whether the server accepted the request. A POST failure is
	// surfaced as Backend.Request's error (and the daemon answers
	// the MCP with {status: "error"} rather than waiting on a
	// channel that will never resolve).
	submitURL := strings.TrimRight(h.BaseURL, "/") + "/v1/sign"
	submitCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(submitCtx, http.MethodPost, submitURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("hosted: build sign request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+h.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	client := h.client()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hosted: submit sign: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("hosted: submit sign returned %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
	var accepted signAcceptedBody
	if err := json.NewDecoder(resp.Body).Decode(&accepted); err != nil {
		return nil, fmt.Errorf("hosted: decode sign response: %w", err)
	}
	if accepted.RequestID == "" {
		return nil, errors.New("hosted: server returned empty request_id")
	}

	// Construct the poll URL ourselves rather than trusting the
	// server-provided PollURL — defence against a misbehaving (or
	// compromised) server pointing us at a different origin.
	pollURL := strings.TrimRight(h.BaseURL, "/") + "/v1/poll/" + url.PathEscape(accepted.RequestID)

	ch := make(chan Result, 1)
	go h.pollLoop(ctx, pollURL, totalTimeout, pollWait, ch)
	return ch, nil
}

// pollLoop drives the GET /v1/poll long-poll until resolution or
// timeout. It owns the result channel: exactly one Result is sent,
// then the channel is closed.
//
// The total budget is bounded by `totalTimeout`. Each individual
// HTTP request is bounded by pollWait + a small slop so a slow
// upstream surfaces as a transient error rather than hanging us.
func (h *HostedServerBackend) pollLoop(parentCtx context.Context, pollURL string, totalTimeout, pollWait time.Duration, out chan<- Result) {
	defer close(out)
	deadline := time.Now().Add(totalTimeout)
	client := h.client()

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			out <- Result{Status: StatusTimeout}
			return
		}
		// Bound this iteration's HTTP request to either pollWait
		// + slop or the remaining budget, whichever is smaller.
		iterTimeout := pollWait + 5*time.Second
		if iterTimeout > remaining {
			iterTimeout = remaining
		}
		iterCtx, cancel := context.WithTimeout(parentCtx, iterTimeout)
		req, err := http.NewRequestWithContext(iterCtx, http.MethodGet, pollURL, nil)
		if err != nil {
			cancel()
			out <- Result{Status: StatusTimeout}
			return
		}
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			// ctx cancelled? terminal.
			if errors.Is(parentCtx.Err(), context.Canceled) || errors.Is(parentCtx.Err(), context.DeadlineExceeded) {
				out <- Result{Status: StatusTimeout}
				return
			}
			// Otherwise treat as a poll iteration failure: brief
			// backoff and retry until deadline. We don't retry
			// forever — the outer `if remaining <= 0` guards.
			select {
			case <-parentCtx.Done():
				out <- Result{Status: StatusTimeout}
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		// Read+close before evaluating to free the connection
		// promptly. We don't stream; bodies are small JSON.
		bodyBytes, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			// Same backoff as a connect error.
			select {
			case <-parentCtx.Done():
				out <- Result{Status: StatusTimeout}
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// 404 = unknown request_id (we sent the wrong ID or
			// the server lost the row). 401 = bad token. Either
			// way the request is unrecoverable for this loop.
			out <- Result{Status: StatusTimeout}
			return
		}

		var body pollBody
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			out <- Result{Status: StatusTimeout}
			return
		}

		switch body.Status {
		case "approved":
			// Convert wire-shape signedSig → backend.SignedCmd so the
			// daemon's signing path can pass these through verbatim
			// instead of re-signing with its (now-vestigial-in-this-
			// mode) local key.
			var sigs []SignedCmd
			if len(body.Signatures) > 0 {
				sigs = make([]SignedCmd, len(body.Signatures))
				for i, s := range body.Signatures {
					sigs[i] = SignedCmd{Cmd: s.Cmd, Sig: s.Sig}
				}
			}
			out <- Result{Status: StatusApproved, ApprovedBy: body.ApprovedBy, Signatures: sigs}
			return
		case "denied":
			out <- Result{Status: StatusDenied, ApprovedBy: body.ApprovedBy}
			return
		case "error":
			// Server-reported terminal error — treat as timeout
			// from the daemon's perspective (it will report
			// "error" via the audit path; the Backend interface
			// has no distinct "remote error" status in v1).
			out <- Result{Status: StatusTimeout}
			return
		case "timeout":
			// Server's poll window elapsed but the request
			// itself is still alive on the server. Loop again
			// until our totalTimeout.
			continue
		case "pending":
			// Same as "timeout" from our perspective — re-poll.
			continue
		default:
			// Unknown status — defensive timeout.
			out <- Result{Status: StatusTimeout}
			return
		}
	}
}

// RequestGrant fails CLOSED on the hosted (Tier-3) backend. The v2 wire
// protocol + web UI do not yet carry the distinct "STANDING GRANT" banner
// (alias + scope + duration + the "auto-signs WITHOUT further taps"
// warning), so a grant routed here could be rendered as an ordinary
// approval and minted unknowingly. We reject it BEFORE any HTTP call —
// exactly like reveal (see Request) — so no future v2 build silently
// ships an un-bannered grant. Re-enable only once the hosted approval UI
// carries the grant semantics end-to-end (out of scope here).
func (h *HostedServerBackend) RequestGrant(_ context.Context, _ GrantApprovalRequest) (<-chan Result, error) {
	return nil, errors.New("hosted: standing grants are not supported on the hosted (Tier-3) signer backend yet; use the local Telegram signer")
}

// RequestTransfer fails CLOSED on the hosted (Tier-3) backend. Box→box transfer
// is Tier-2 (local Telegram signer) only in P2: the hosted server holds no
// ed25519 key, no per-server transfer registry, and no transfer approval UI, so
// it can neither source the pinned pubkeys nor render the SECRET-TRANSFER
// banner. We reject BEFORE any HTTP call, exactly like RequestGrant, so no
// future build silently ships an un-anchored transfer. (See the P2 spec §2b for
// the four hosted-server pieces this would need.)
func (h *HostedServerBackend) RequestTransfer(_ context.Context, _ TransferApprovalRequest) (<-chan Result, error) {
	return nil, errors.New("hosted: box→box transfer is not supported on the hosted (Tier-3) signer backend yet; use the local Telegram signer")
}

// RequestRegisterKey fails CLOSED on the hosted (Tier-3) backend for the same
// reason: there is no server-side transfer registry to populate and no register
// approval UI. Reject before any HTTP call.
func (h *HostedServerBackend) RequestRegisterKey(_ context.Context, _ RegisterApprovalRequest) (<-chan Result, error) {
	return nil, errors.New("hosted: box→box xfer-key registration is not supported on the hosted (Tier-3) signer backend yet; use the local Telegram signer")
}

// validate returns the first config error, if any.
func (h *HostedServerBackend) validate() error {
	if h.BaseURL == "" {
		return errors.New("hosted: BaseURL is required")
	}
	if h.APIKey == "" {
		return errors.New("hosted: APIKey is required")
	}
	if h.ClientID == "" {
		return errors.New("hosted: ClientID is required")
	}
	return nil
}

func (h *HostedServerBackend) client() *http.Client {
	if h.HTTPClient != nil {
		return h.HTTPClient
	}
	return http.DefaultClient
}

// readSnippet returns up to 256 bytes from r as a string, for
// inclusion in error messages. We cap the size so a hostile or
// misconfigured server can't blow up the daemon's error log.
func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 256))
	return strings.TrimSpace(string(b))
}

// Compile-time interface check.
var _ Backend = (*HostedServerBackend)(nil)
