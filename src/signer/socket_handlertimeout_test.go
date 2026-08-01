package signer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// delayedBackend resolves every request with a fixed Result after a fixed
// wall-clock delay, simulating a human-in-the-loop approval that takes
// real time to arrive (the Telegram backend's tap). It is the minimal
// fixture this regression needs: MockBackend resolves synchronously, so
// it cannot exercise the "approval arrives mid-connection, after some
// wall-clock has elapsed" path that the HandlerTimeout bug lived on.
//
// Request honours ctx cancellation: if the daemon's connCtx fires before
// the delay elapses, we stop the timer and never send — the daemon's own
// <-ctx.Done() branch then resolves the request as timeout, exactly as a
// real backend's contract requires (signerkit.Backend doc: "SHOULD honour
// ctx cancellation by yielding StatusTimeout").
type delayedBackend struct {
	delay  time.Duration
	result signerkit.Result
}

func (b delayedBackend) Request(ctx context.Context, _ signerkit.ApprovalRequest) (<-chan signerkit.Result, error) {
	return b.delayedResult(ctx), nil
}

// RequestGrant mirrors Request so delayedBackend satisfies the widened
// Backend interface; the handler-timeout tests only exercise the sign
// path, but the daemon needs a complete backend.
func (b delayedBackend) RequestGrant(ctx context.Context, _ signerkit.GrantApprovalRequest) (<-chan signerkit.Result, error) {
	return b.delayedResult(ctx), nil
}

// RequestTransfer / RequestRegisterKey mirror Request so delayedBackend
// satisfies the widened Backend interface; the handler-timeout tests only
// exercise the sign path, but the daemon needs a complete backend.
func (b delayedBackend) RequestTransfer(ctx context.Context, _ signerkit.TransferApprovalRequest) (<-chan signerkit.Result, error) {
	return b.delayedResult(ctx), nil
}

func (b delayedBackend) RequestRegisterKey(ctx context.Context, _ signerkit.RegisterApprovalRequest) (<-chan signerkit.Result, error) {
	return b.delayedResult(ctx), nil
}

func (b delayedBackend) delayedResult(ctx context.Context) <-chan signerkit.Result {
	ch := make(chan signerkit.Result, 1)
	go func() {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			ch <- b.result
		case <-ctx.Done():
			// Mirror a real backend: on cancellation, yield nothing here
			// and let the daemon's ctx.Done() branch produce timeout. (We
			// could send StatusTimeout, but the daemon's select already
			// covers ctx.Done(), and sending would race with that branch.)
		}
	}()
	return ch
}

// newServerWithDaemon stands up a real signerkit.Server over a unix socket in
// t.TempDir(), backed by a real signerkit.Daemon (its own keypair + audit
// log) wired to bk, with the given HandlerTimeout. It returns the socket
// path and a stop func that cancels Listen and waits for it to exit.
//
// This mirrors the construction in socket_test.go (startTestServer) and
// daemon_test.go (newDaemon): a real Server + real Daemon, no mocked
// transport, so the per-connection deadline in serveOne is genuinely
// exercised end-to-end.
func newServerWithDaemon(t *testing.T, bk signerkit.Backend, handlerTimeout time.Duration) (sockPath string, stop func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := signerkit.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	daemon := &signerkit.Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
		NowFunc: func() time.Time { return time.Unix(1000, 0) },
	}

	dir := t.TempDir()
	sockPath = filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerkit.Server{Path: sockPath, Handler: daemon, HandlerTimeout: handlerTimeout}
	done := make(chan error, 1)
	go func() { done <- srv.Listen(ctx) }()

	waitForSocket(t, sockPath, cancel)

	return sockPath, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Listen did not exit within 2s of cancel")
		}
		audit.Close()
	}
}

// signResp is the subset of the wire response these tests assert on.
type signResp struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	Signatures []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"signatures"`
}

// dialSignAndRead connects to sockPath, writes one sign request line, and
// reads exactly one JSON response line. A read error / EOF-before-newline
// is returned to the caller so a test can assert "the response actually
// arrived" — which is the precise failure mode of the HandlerTimeout bug
// (the connection deadline expired before the post-approval write).
func dialSignAndRead(t *testing.T, sockPath, requestLine string, readBudget time.Duration) (signResp, error) {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(requestLine)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Generous client-side read deadline: it must be longer than both the
	// server's HandlerTimeout and the backend delay so the CLIENT never
	// times out first — any read failure we observe is then attributable
	// to the SERVER (e.g. a connection-deadline-driven close), which is
	// exactly the regression we are guarding.
	conn.SetReadDeadline(time.Now().Add(readBudget))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return signResp{}, err
	}
	var resp signResp
	if jerr := json.Unmarshal(bytes.TrimRight(line, "\n"), &resp); jerr != nil {
		t.Fatalf("unmarshal response: %v\nraw=%q", jerr, line)
	}
	return resp, nil
}

// TestServer_DelayedApprovalWithinWindow_IsDelivered is the core
// regression guard. It reproduces the production wiring's failure mode in
// miniature: a human approval that arrives after real wall-clock has
// elapsed (100ms) but still WITHIN the connection's HandlerTimeout
// (300ms) must be signed AND delivered back over the same connection.
//
// The bug: serveOne applies ONE absolute deadline covering request-read +
// approval-wait + response-write, and passes the same timeout as connCtx
// into the daemon. When the approval window exceeded HandlerTimeout, the
// approval was both (a) cut short by connCtx and (b) — even when it did
// land — undeliverable because the connection deadline had already
// expired by the time the daemon tried to write the signature
// ("approved-undelivered": the master key signed but the MCP never got
// the signature). This test fails (read error / EOF / status != approved)
// if HandlerTimeout is ever set shorter than the backend's wait again.
func TestServer_DelayedApprovalWithinWindow_IsDelivered(t *testing.T) {
	t.Parallel()
	const (
		handlerTimeout = 300 * time.Millisecond
		approvalDelay  = 100 * time.Millisecond // strictly < handlerTimeout
	)
	bk := delayedBackend{
		delay:  approvalDelay,
		result: signerkit.Result{Status: signerkit.StatusApproved, ApprovedBy: "operator"},
	}
	sockPath, stop := newServerWithDaemon(t, bk, handlerTimeout)
	defer stop()

	const req = `{"kind":"sign","request_id":"r_delay_ok","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60}]}` + "\n"
	// Read budget well beyond both the delay and the handler timeout so the
	// client is never the one to time out.
	resp, err := dialSignAndRead(t, sockPath, req, 2*time.Second)
	if err != nil {
		t.Fatalf("response did not arrive (this is the approved-undelivered regression): %v", err)
	}
	if resp.RequestID != "r_delay_ok" {
		t.Errorf("RequestID = %q; want r_delay_ok", resp.RequestID)
	}
	if resp.Status != "approved" {
		t.Fatalf("Status = %q; want approved (a delayed-but-in-window approval must be honoured)", resp.Status)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("got %d signatures; want 1", len(resp.Signatures))
	}
	if resp.Signatures[0].Sig == "" {
		t.Errorf("signature is empty; the master key signed but no signature was delivered")
	}
}

// TestServer_ApprovalAfterWindow_IsNotApproved documents the boundary
// from the short-timeout side: when the backend's wait EXCEEDS
// HandlerTimeout, the approval is NOT honoured — the client never receives
// an "approved" status with a signature.
//
// Note on what is and isn't deterministic here, and why this test asserts
// the negative rather than a delivered "timeout" line: serveOne uses a
// SINGLE absolute deadline (HandlerTimeout) for BOTH the daemon's connCtx
// (approval-wait budget) AND the connection's write deadline. So at the
// instant connCtx fires and the daemon resolves "timeout", the connection
// write deadline has ALSO just expired, leaving zero budget to write the
// timeout response — the write fails with i/o timeout and the client
// observes EOF. (That coupling is precisely the structural reason a
// too-short HandlerTimeout is dangerous: it eats the very write budget the
// post-decision response needs.) Asserting a delivered "timeout" JSON line
// would therefore be racy/flaky. What IS deterministic and meaningful is
// the security-relevant invariant: a decision arriving after the window is
// never delivered as an approved signature. Either outcome below satisfies
// that: (a) the connection is torn down (read error / EOF), or (b) a
// non-approved status line arrives — but NEVER an approved one.
func TestServer_ApprovalAfterWindow_IsNotApproved(t *testing.T) {
	t.Parallel()
	const (
		handlerTimeout = 100 * time.Millisecond
		approvalDelay  = 1 * time.Second // strictly > handlerTimeout
	)
	bk := delayedBackend{
		delay:  approvalDelay,
		result: signerkit.Result{Status: signerkit.StatusApproved, ApprovedBy: "operator"},
	}
	sockPath, stop := newServerWithDaemon(t, bk, handlerTimeout)
	defer stop()

	const req = `{"kind":"sign","request_id":"r_delay_late","commands":[{"server":"prod","cmd":"reboot","ttl_seconds":60}]}` + "\n"
	// Client read budget shorter than the backend delay so a genuine hang
	// surfaces as a client read timeout rather than blocking the suite, yet
	// well beyond the handler timeout so the server-driven close/response
	// is what we observe.
	resp, err := dialSignAndRead(t, sockPath, req, 800*time.Millisecond)
	if err != nil {
		// Server tore the connection down at the deadline before any
		// approved signature could be written — acceptable and expected
		// for the single-deadline design. The approval was NOT delivered.
		return
	}
	// If a response line did arrive, it must NOT be an approved signature:
	// an approval that landed after the window must never be honoured.
	if resp.Status == "approved" {
		t.Errorf("Status = %q with %d signature(s); want a non-approved outcome "+
			"(a decision arriving after HandlerTimeout must never be delivered as approved)",
			resp.Status, len(resp.Signatures))
	}
}
