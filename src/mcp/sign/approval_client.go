package sign

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
)

// Approval call deadlines (E13, A5): every call is bounded by CallTimeout,
// except Wait, which is bounded by its wait plus ApprovalWaitGrace. They are
// safe because Submit returns at commit, before any Telegram send (E63).
const (
	DefaultApprovalCallTimeout = 30 * time.Second
	ApprovalWaitGrace          = 10 * time.Second
)

// ApprovalClient speaks the six v2 approval kinds to the local signer socket.
// It talks only to the local socket: a hosted signer is reached through the
// local daemon's proxy, never over HTTP from the MCP.
//
// Errors are typed for the caller's one definitive/transient split (SA-5):
// a refusal is an *approvalwire.WireError (errors.Is matches
// approvalwire.ErrBusy, ErrStorageUncertain and ErrSignerIncompatible for
// those codes); a pre-v2 daemon is approvalwire.ErrSignerIncompatible; a
// request written in full with no response is approvalwire.ErrResponseLost;
// a dial failure is ErrUnreachable or ErrSignerPermission. It never retries.
type ApprovalClient struct {
	SocketPath  string
	CallTimeout time.Duration
}

// Submit sends a draft and returns the frozen record's summary.
func (c *ApprovalClient) Submit(ctx context.Context, draft approvalplan.ApprovalDraft) (approvalplan.Summary, error) {
	req := approvalwire.SubmitRequest{ApprovalProto: approvalwire.Proto, Kind: approvalwire.KindSubmit, Draft: draft}
	resp, err := c.call(ctx, approvalwire.KindSubmit, req, c.callTimeout())
	if err != nil {
		return approvalplan.Summary{}, err
	}
	return summaryFor(approvalwire.KindSubmit, draft.RequestID, resp)
}

// Get returns one record's summary.
func (c *ApprovalClient) Get(ctx context.Context, requestID string) (approvalplan.Summary, error) {
	req := approvalwire.GetRequest{ApprovalProto: approvalwire.Proto, Kind: approvalwire.KindGet, RequestID: requestID}
	resp, err := c.call(ctx, approvalwire.KindGet, req, c.callTimeout())
	if err != nil {
		return approvalplan.Summary{}, err
	}
	return summaryFor(approvalwire.KindGet, requestID, resp)
}

// List returns one page of the caller's records and the next cursor ("" at
// the end).
func (c *ApprovalClient) List(ctx context.Context, limit int, cursor string) ([]approvalplan.Summary, string, error) {
	req := approvalwire.ListRequest{ApprovalProto: approvalwire.Proto, Kind: approvalwire.KindList, Limit: limit, Cursor: cursor}
	resp, err := c.call(ctx, approvalwire.KindList, req, c.callTimeout())
	if err != nil {
		return nil, "", err
	}
	if len(resp.Summaries) > limit {
		return nil, "", fmt.Errorf("approval: %s answered %d summaries for limit %d", approvalwire.KindList, len(resp.Summaries), limit)
	}
	return resp.Summaries, resp.NextCursor, nil
}

// Wait waits up to wait (whole seconds, at most 55 s) for any of ids to
// change and returns their summaries. Its deadline is wait plus
// ApprovalWaitGrace.
func (c *ApprovalClient) Wait(ctx context.Context, ids []string, wait time.Duration) ([]approvalplan.Summary, error) {
	if wait < 0 || wait%time.Second != 0 {
		return nil, fmt.Errorf("approval: wait %v must be a non-negative whole number of seconds", wait)
	}
	req := approvalwire.WaitRequest{
		ApprovalProto: approvalwire.Proto, Kind: approvalwire.KindWait,
		RequestIDs: ids, WaitSeconds: int(wait / time.Second),
	}
	resp, err := c.call(ctx, approvalwire.KindWait, req, wait+ApprovalWaitGrace)
	if err != nil {
		return nil, err
	}
	if len(resp.Summaries) > len(ids) {
		return nil, fmt.Errorf("approval: %s answered %d summaries for %d ids", approvalwire.KindWait, len(resp.Summaries), len(ids))
	}
	for _, s := range resp.Summaries {
		if !slices.Contains(ids, s.RequestID) {
			return nil, fmt.Errorf("approval: %s answered request %s, which was not asked for", approvalwire.KindWait, s.RequestID)
		}
	}
	return resp.Summaries, nil
}

// Claim presents the raw claim token and the plan hash; it is the only call
// that returns signatures (E25).
func (c *ApprovalClient) Claim(ctx context.Context, requestID, planHash string, claimToken [32]byte) (approvalwire.ClaimAnswer, error) {
	req := approvalwire.ClaimRequest{
		ApprovalProto: approvalwire.Proto, Kind: approvalwire.KindClaim,
		RequestID: requestID, ClaimToken: hex.EncodeToString(claimToken[:]), PlanHash: planHash,
	}
	resp, err := c.call(ctx, approvalwire.KindClaim, req, c.callTimeout())
	if err != nil {
		return approvalwire.ClaimAnswer{}, err
	}
	return *resp.Claim, nil
}

// Report sends the one final execution report. A nil error is the signer's
// acknowledgement (an exact duplicate is acknowledged too).
func (c *ApprovalClient) Report(ctx context.Context, requestID, planHash string, claimToken [32]byte, rep approvalwire.Report) error {
	req := approvalwire.ReportRequest{
		ApprovalProto: approvalwire.Proto, Kind: approvalwire.KindReport,
		RequestID: requestID, ClaimToken: hex.EncodeToString(claimToken[:]), PlanHash: planHash, Report: rep,
	}
	_, err := c.call(ctx, approvalwire.KindReport, req, c.callTimeout())
	return err
}

func (c *ApprovalClient) callTimeout() time.Duration {
	if c.CallTimeout > 0 {
		return c.CallTimeout
	}
	return DefaultApprovalCallTimeout
}

// call writes one frame and reads one answer on a fresh connection.
func (c *ApprovalClient) call(ctx context.Context, kind string, req any, timeout time.Duration) (approvalwire.Response, error) {
	frame, err := approvalwire.MarshalLocalRequest(req)
	if err != nil {
		return approvalwire.Response{}, fmt.Errorf("approval: %s request: %w", kind, err)
	}
	if c.SocketPath == "" {
		return approvalwire.Response{}, errors.New("approval: SocketPath is empty")
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialWithCtx(callCtx, c.SocketPath)
	if err != nil {
		return approvalwire.Response{}, classifyDialError(err)
	}
	defer conn.Close()
	if deadline, ok := callCtx.Deadline(); ok {
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

	written, err := writePolicyRequest(conn, frame)
	if err != nil {
		if written == len(frame) {
			return approvalwire.Response{}, fmt.Errorf("%w: %s write acknowledgement failed: %w", approvalwire.ErrResponseLost, kind, err)
		}
		return approvalwire.Response{}, fmt.Errorf("approval: %s write: %w", kind, err)
	}
	line, err := lineframe.Read(conn, approvalwire.MaxFrameBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return approvalwire.Response{}, fmt.Errorf("%w: %s canceled after the request was written: %w", approvalwire.ErrResponseLost, kind, ctxErr)
		}
		if isVerdictLost(err, len(line)) {
			return approvalwire.Response{}, fmt.Errorf("%w: %s: %v", approvalwire.ErrResponseLost, kind, err)
		}
		return approvalwire.Response{}, fmt.Errorf("approval: %s read response: %w", kind, err)
	}
	resp, err := approvalwire.DecodeLocalResponse(kind, line)
	if err != nil {
		return approvalwire.Response{}, fmt.Errorf("approval: %w", err)
	}
	return resp, nil
}

// summaryFor checks that an ok Submit or Get answer is about the request asked.
func summaryFor(kind, requestID string, resp approvalwire.Response) (approvalplan.Summary, error) {
	if resp.Summary.RequestID != requestID {
		return approvalplan.Summary{}, fmt.Errorf("approval: %s for %s answered request %s", kind, requestID, resp.Summary.RequestID)
	}
	return *resp.Summary, nil
}
