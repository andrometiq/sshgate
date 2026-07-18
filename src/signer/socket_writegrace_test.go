package signer_test

import (
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// These tests guard F1: a verdict that resolves at the approval-wait
// deadline must still be DELIVERED to the client as a proper JSON status
// line, not lost to a torn-down connection (which the MCP would see as a
// bare EOF / i-o-timeout with no sentinel).
//
// The fix splits serveOne's single absolute deadline into a WAIT budget
// (= HandlerTimeout - sigwire.ResponseWriteGrace) driving both the
// connection's initial deadline AND connCtx, and the daemon RESETS the
// connection write deadline to now + ResponseWriteGrace immediately before
// each response write. So when the wait deadline fires and the daemon
// resolves "timeout" via ctx.Done(), the verdict line still has a fresh,
// full grace to reach the client.
//
// Distinguishing old from new: the backend here NEVER resolves a real
// verdict within the connection's lifetime, so the daemon's ctx.Done()
// branch produces "timeout" in BOTH designs. The difference is delivery:
//   - NEW: connCtx fires at the wait budget (HandlerTimeout - grace); the
//     daemon resets the write deadline to now + grace (a full 5s) and the
//     "timeout" line lands.
//   - OLD (single shared deadline = HandlerTimeout): connCtx and the write
//     deadline expire at the SAME instant, so the post-decision write has
//     zero budget — it fails and the connection is torn down (client EOF).
// HandlerTimeout is set just over ResponseWriteGrace so the wait budget is
// a small positive slice and the test resolves quickly.

func TestServer_TimeoutAtDeadline_DeliversTimeoutLine(t *testing.T) {
	t.Parallel()
	const handlerTimeout = sigwire.ResponseWriteGrace + 250*time.Millisecond
	// Wait budget is ~250ms. The backend delay far exceeds the whole
	// connection lifetime, so no real verdict ever resolves — the daemon's
	// ctx.Done() branch yields "timeout". The only question is whether that
	// timeout line is DELIVERED, which is exactly the write-grace guarantee.
	bk := delayedBackend{
		delay:  10 * time.Second,
		result: signerkit.Result{Status: signerkit.StatusApproved, ApprovedBy: "karthi"},
	}
	sockPath, stop := newServerWithDaemon(t, bk, handlerTimeout)
	defer stop()

	const req = `{"kind":"sign","request_id":"r_to","commands":[{"server":"prod","cmd":"reboot","ttl_seconds":60}]}` + "\n"
	// Client read budget exceeds the wait budget + the reset grace so the
	// client is never the one to time out — any failure is the server's.
	resp, err := dialSignAndRead(t, sockPath, req, 2*sigwire.ResponseWriteGrace)
	if err != nil {
		t.Fatalf("timeout verdict was not delivered (verdict-undelivered regression): %v", err)
	}
	if resp.RequestID != "r_to" {
		t.Errorf("RequestID = %q; want r_to", resp.RequestID)
	}
	if resp.Status != "timeout" {
		t.Fatalf("Status = %q; want timeout (a wait-deadline verdict must be delivered, not lost to EOF)", resp.Status)
	}
}

// TestServer_DenyNearDeadline_DeliversDeniedLine proves a real DENY verdict
// that resolves a hair before the wait deadline still reaches the client as
// status="denied" (rather than racing the connection to teardown). The
// backend resolves shortly before the wait budget elapses; the daemon's
// per-write deadline reset (now + grace) guarantees the line lands.
func TestServer_DenyNearDeadline_DeliversDeniedLine(t *testing.T) {
	t.Parallel()
	const handlerTimeout = sigwire.ResponseWriteGrace + 400*time.Millisecond
	// Wait budget ~400ms; resolve denied at ~250ms — inside the wait window,
	// so the daemon takes the real-verdict path, signs nothing, and must
	// deliver "denied".
	bk := delayedBackend{
		delay:  250 * time.Millisecond,
		result: signerkit.Result{Status: signerkit.StatusDenied, ApprovedBy: "karthi"},
	}
	sockPath, stop := newServerWithDaemon(t, bk, handlerTimeout)
	defer stop()

	const req = `{"kind":"sign","request_id":"r_deny","commands":[{"server":"prod","cmd":"rm -rf /srv","ttl_seconds":60}]}` + "\n"
	resp, err := dialSignAndRead(t, sockPath, req, 2*sigwire.ResponseWriteGrace)
	if err != nil {
		t.Fatalf("deny verdict was not delivered (verdict-undelivered regression): %v", err)
	}
	if resp.Status != "denied" {
		t.Fatalf("Status = %q; want denied (a human DENY must reach the client, never be lost)", resp.Status)
	}
}
