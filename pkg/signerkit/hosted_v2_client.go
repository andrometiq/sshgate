package signerkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalwire"
)

// HostedApprovalResponse preserves the envelope and HTTP retry metadata. A
// refusal returns both this value and its typed error; callers decide retries.
type HostedApprovalResponse struct {
	Response   approvalwire.Response
	RetryAfter string
}

// RequestApproval sends one machine-plane request. request is one of the six
// approvalwire local request values. The forwarder supplies requesterSub from
// peer credentials; a direct bearer client may use the empty namespace.
// Timeout bounds each call (60 seconds by default), including response reads.
// Unlike Request's legacy polling loop, this method never retries.
func (h *HostedServerBackend) RequestApproval(ctx context.Context, requesterSub string, request any) (HostedApprovalResponse, error) {
	if _, err := approvalwire.MarshalLocalRequest(request); err != nil {
		return HostedApprovalResponse{}, err
	}
	kind, id, query := "", "", ""
	var body any
	var err error
	switch r := request.(type) {
	case approvalwire.SubmitRequest:
		kind = r.Kind
		body = approvalwire.HostedSubmitBody{ApprovalProto: r.ApprovalProto, RequesterSub: requesterSub, Draft: r.Draft}
	case approvalwire.GetRequest:
		kind, id = r.Kind, r.RequestID
		query, err = (approvalwire.HostedGetQuery{RequesterSub: requesterSub}).Encode()
	case approvalwire.ListRequest:
		kind = r.Kind
		query, err = (approvalwire.HostedListQuery{RequesterSub: requesterSub, Limit: r.Limit, Cursor: r.Cursor}).Encode()
	case approvalwire.WaitRequest:
		kind = r.Kind
		body = approvalwire.HostedWaitBody{ApprovalProto: r.ApprovalProto, RequesterSub: requesterSub, RequestIDs: r.RequestIDs, WaitSeconds: r.WaitSeconds}
	case approvalwire.ClaimRequest:
		kind, id = r.Kind, r.RequestID
		body = approvalwire.HostedClaimBody{ApprovalProto: r.ApprovalProto, RequesterSub: requesterSub, ClaimToken: r.ClaimToken, PlanHash: r.PlanHash}
	case approvalwire.ReportRequest:
		kind, id = r.Kind, r.RequestID
		body = approvalwire.HostedReportBody{ApprovalProto: r.ApprovalProto, RequesterSub: requesterSub, ClaimToken: r.ClaimToken, PlanHash: r.PlanHash, Report: r.Report}
	}
	if err != nil {
		return HostedApprovalResponse{}, err
	}
	var payload []byte
	if body != nil {
		payload, err = approvalwire.MarshalHostedBody(body)
		if err != nil {
			return HostedApprovalResponse{}, err
		}
	}
	method, path, err := approvalwire.HostedRoute(kind, id)
	if err != nil {
		return HostedApprovalResponse{}, err
	}
	if err := h.validate(); err != nil {
		return HostedApprovalResponse{}, err
	}
	timeout := h.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if timeout < 0 {
		return HostedApprovalResponse{}, errors.New("hosted approvals: timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	endpoint := strings.TrimRight(h.BaseURL, "/") + path
	if query != "" {
		endpoint += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return HostedApprovalResponse{}, errors.New("hosted approvals: cannot build request")
	}
	req.Header.Set("Authorization", "Bearer "+h.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Do not follow redirects or replay a consumed body on a transport retry.
	req.GetBody = nil
	client := *h.client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		// net/http errors can include URLs; never echo request identities or bodies.
		if ctx.Err() != nil {
			return HostedApprovalResponse{}, ctx.Err()
		}
		return HostedApprovalResponse{}, approvalwire.ErrResponseLost
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, approvalwire.MaxFrameBytes+1))
	if err != nil {
		return HostedApprovalResponse{}, approvalwire.ErrResponseLost
	}
	if len(data) > approvalwire.MaxFrameBytes {
		return HostedApprovalResponse{}, fmt.Errorf("hosted approvals: response exceeds %d bytes", approvalwire.MaxFrameBytes)
	}
	decoded, err := approvalwire.ClassifyHostedResponse(kind, resp.StatusCode, resp.Header.Get("Content-Type"), data)
	return HostedApprovalResponse{Response: decoded, RetryAfter: resp.Header.Get("Retry-After")}, err
}
