package sign_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// ---- request-side (highest priority) ---------------------------------
//
// The daemon builds its trust decision from the request body the client
// puts on the wire (src/signer/daemon.go signRequestCmd: server / cmd /
// ttl_seconds). If the MCP client silently dropped or renamed any of
// those fields, the daemon would audit/approve the wrong thing while the
// happy-path response test still passed. These tests decode the exact
// commands[] the fake server received and assert a faithful, ordered,
// field-correct, 1:1 mapping from the CmdReq input.

func decodeCommands(t *testing.T, req map[string]any) []map[string]any {
	t.Helper()
	raw, ok := req["commands"].([]any)
	if !ok {
		t.Fatalf("req.commands missing or wrong type: %#v", req["commands"])
	}
	out := make([]map[string]any, len(raw))
	for i, c := range raw {
		m, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("commands[%d] wrong type: %#v", i, c)
		}
		out[i] = m
	}
	return out
}

func TestSign_RequestBody_CapturesAllFields(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		// Echo each requested cmd back, approved, so Sign succeeds and we
		// can independently inspect the captured request.
		return `{"request_id":"rid-7","status":"approved","signatures":[` +
			`{"cmd":"df -h","sig":"SSHGATE_SIG:a:b"},` +
			`{"cmd":"systemctl restart nginx","sig":"SSHGATE_SIG:c:d"}]}`
	})
	defer stop()

	in := []sign.CmdReq{
		{Server: "prod-web", Cmd: "df -h", TTLSec: 30},
		{Server: "prod-lb", Cmd: "systemctl restart nginx", TTLSec: 120},
	}
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	if _, err := c.Sign(context.Background(), "rid-7", in); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var req map[string]any
	select {
	case req = <-gotReq:
	case <-time.After(2 * time.Second):
		t.Fatal("server received no request")
	}

	if req["kind"] != "sign" {
		t.Errorf("kind = %v; want sign", req["kind"])
	}
	if req["request_id"] != "rid-7" {
		t.Errorf("request_id = %v; want rid-7", req["request_id"])
	}

	cmds := decodeCommands(t, req)
	if len(cmds) != len(in) {
		t.Fatalf("got %d commands on the wire; want %d (1:1 with input)", len(cmds), len(in))
	}
	for i, want := range in {
		got := cmds[i]
		if got["server"] != want.Server {
			t.Errorf("commands[%d].server = %v; want %q (silent server drop?)", i, got["server"], want.Server)
		}
		if got["cmd"] != want.Cmd {
			t.Errorf("commands[%d].cmd = %v; want %q (silent cmd drop?)", i, got["cmd"], want.Cmd)
		}
		// JSON numbers decode to float64 through map[string]any.
		ttl, ok := got["ttl_seconds"].(float64)
		if !ok {
			t.Errorf("commands[%d].ttl_seconds missing/!number: %#v (wire field renamed?)", i, got["ttl_seconds"])
		} else if int64(ttl) != want.TTLSec {
			t.Errorf("commands[%d].ttl_seconds = %v; want %d", i, int64(ttl), want.TTLSec)
		}
		// Guard against the wrong JSON key being emitted for TTL.
		if _, bad := got["ttl"]; bad {
			t.Errorf("commands[%d] used key \"ttl\"; daemon expects \"ttl_seconds\"", i)
		}
		if _, bad := got["TTLSec"]; bad {
			t.Errorf("commands[%d] leaked Go field name \"TTLSec\"; want \"ttl_seconds\"", i)
		}
	}
}

// ---- approved with N>=2 signatures -> N ordered Signed, 1:1 ----------

func TestSign_ApprovedMultiSignature_OrderedOneToOne(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"rN","status":"approved","signatures":[` +
			`{"cmd":"cmd-0","sig":"SIG0"},` +
			`{"cmd":"cmd-1","sig":"SIG1"},` +
			`{"cmd":"cmd-2","sig":"SIG2"}]}`
	})
	defer stop()

	in := []sign.CmdReq{
		{Server: "s", Cmd: "cmd-0", TTLSec: 60},
		{Server: "s", Cmd: "cmd-1", TTLSec: 60},
		{Server: "s", Cmd: "cmd-2", TTLSec: 60},
	}
	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	res, err := c.Sign(context.Background(), "rN", in)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(res.Signed) != 3 {
		t.Fatalf("got %d signed; want 3", len(res.Signed))
	}
	for i := 0; i < 3; i++ {
		wantCmd := fmt.Sprintf("cmd-%d", i)
		wantSig := fmt.Sprintf("SIG%d", i)
		if res.Signed[i].Cmd != wantCmd || res.Signed[i].Sig != wantSig {
			t.Errorf("out[%d] = %+v; want {Cmd:%q Sig:%q} (order/1:1 broken)", i, res.Signed[i], wantCmd, wantSig)
		}
	}
}

// ---- unknown status -> non-sentinel error (default branch) -----------

func TestSign_UnknownStatus_DefaultBranchNonSentinel(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"pending-elsewhere"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil for unknown status")
	}
	// Must hit the default branch — never be confused with a real outcome.
	if errors.Is(err, sign.ErrDenied) || errors.Is(err, sign.ErrTimeout) ||
		errors.Is(err, sign.ErrUnreachable) || errors.Is(err, sign.ErrSignerPermission) {
		t.Errorf("unknown status mis-mapped to a sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown status") {
		t.Errorf("err = %q; want it to mention the unknown status", err.Error())
	}
}

// ---- error status with EMPTY detail -> fixed message -----------------

func TestSign_ErrorStatus_EmptyDetail_NoDetailMessage(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		// status=error but the "error" detail field is absent/empty.
		return `{"request_id":"r1","status":"error"}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil for error status")
	}
	if !strings.Contains(err.Error(), "daemon reported error (no detail)") {
		t.Errorf("err = %q; want the empty-detail message", err.Error())
	}
}

// ---- read-side EOF / partial invalid JSON -> malformed, not ctx --------
//
// The fake writes a fragment with NO trailing newline and then closes the
// connection. The bounded reader preserves those non-empty bytes as a final
// EOF frame; typed JSON decoding must reject it as malformed, NOT classify it
// as a zero-byte lost verdict or mis-attribute it to ctx cancellation.

func TestSign_ReadSideEOF_PartialLine_MalformedResponse(t *testing.T) {
	t.Parallel()
	// Custom raw server: write a newline-less fragment, then close.
	path, stop := startRawSigner(t, func(c rawConn) {
		_, _ = c.Write([]byte(`{"request_id":"r1","status":"appr`)) // no '\n'
		_ = c.Close()
	})
	defer stop()

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want a read error on EOF/partial line")
	}
	if !strings.Contains(err.Error(), "malformed response") {
		t.Errorf("err = %q; want malformed-response error", err.Error())
	}
	// Must NOT be attributed to context cancellation/deadline — the ctx
	// is healthy; only the peer hung up.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("read EOF mis-attributed to ctx: %v", err)
	}
	if errors.Is(err, sign.ErrVerdictUnknown) {
		t.Errorf("nonempty malformed EOF misclassified as unknown verdict: %v", err)
	}
}

// ---- input guards (table-driven, no dial) ----------------------------

func TestSign_InputGuards_NoDial(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		socketPath string
		requestID  string
		cmds       []sign.CmdReq
		wantSubstr string
	}{
		{
			name:       "empty SocketPath",
			socketPath: "",
			requestID:  "r1",
			cmds:       []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}},
			wantSubstr: "SocketPath is empty",
		},
		{
			name:       "empty requestID",
			socketPath: "/some/sock", // never dialed; guard fires first
			requestID:  "",
			cmds:       []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}},
			wantSubstr: "requestID is empty",
		},
		{
			name:       "empty cmds",
			socketPath: "/some/sock", // never dialed; guard fires first
			requestID:  "r1",
			cmds:       nil,
			wantSubstr: "no commands",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &sign.Client{SocketPath: tc.socketPath, Timeout: 2 * time.Second}
			_, err := c.Sign(context.Background(), tc.requestID, tc.cmds)
			if err == nil {
				t.Fatalf("err is nil; want %q", tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("err = %q; want it to contain %q", err.Error(), tc.wantSubstr)
			}
			// Guards must be transport-agnostic: no sentinel leakage.
			if errors.Is(err, sign.ErrUnreachable) || errors.Is(err, sign.ErrSignerPermission) {
				t.Errorf("input guard leaked a transport sentinel: %v", err)
			}
		})
	}
}

// ---- Timeout<=0 default (proves the 75s fallback, no long wait) -------
//
// A Client with Timeout:0 must still succeed against a prompt server —
// the internal default (75s) is applied, not a zero-duration deadline
// that would instantly cancel the dial/read. We assert success quickly,
// which can only happen if a sane fallback budget was used.

func TestSign_ZeroTimeout_AppliesDefaultBudget(t *testing.T) {
	t.Parallel()
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"approved","signatures":[{"cmd":"x","sig":"S"}]}`
	})
	defer stop()

	c := &sign.Client{SocketPath: path} // Timeout zero-valued
	done := make(chan error, 1)
	go func() {
		_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Sign with zero Timeout: %v (a zero budget would have cancelled instantly)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Sign with zero Timeout hung; default budget not applied as expected")
	}
}

// ---- ctx cancelled BEFORE dial -> must NOT become ErrSignerPermission
//
// SAFETY INVARIANT (asserted): a caller-cancelled dial must never be
// reported as ErrSignerPermission, because that sentinel drives the
// misleading "log out and back in to pick up the sshgatesigner group"
// guidance — there is no permission problem, the caller just cancelled.
//
// KNOWN PRODUCTION FINDING (documented, not silently asserted-away):
// classifyDialError checks its *net.OpError catch-all (-> ErrUnreachable)
// BEFORE any ctx-cancellation check, and wraps the underlying error with
// %v (not %w). So a pre-cancelled dial is currently mapped to
// ErrUnreachable AND the context.Canceled cause is erased from the chain.
// That contradicts the spirit of "ctx-cancel must not be mis-mapped to
// ErrUnreachable". This test documents the live behaviour rather than
// weakening to make the code look correct; see the t.Log below. The fix
// would be to test errors.Is(err, context.Canceled/DeadlineExceeded) at
// the top of classifyDialError and wrap with %w. (No production change
// made here, per the test-only mandate.)
func TestSign_CtxCancelledBeforeDial_NotSignerPermission(t *testing.T) {
	t.Parallel()
	// A live server exists, so an ErrSignerPermission here would be a
	// pure misclassification — the socket is fine, the caller cancelled.
	path, _, stop := startFakeSigner(t, func(req map[string]any) string {
		return `{"request_id":"r1","status":"approved","signatures":[]}`
	})
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE Sign dials

	c := &sign.Client{SocketPath: path, Timeout: 2 * time.Second}
	_, err := c.Sign(ctx, "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want non-nil when ctx cancelled before dial")
	}
	// Non-negotiable safety invariant.
	if errors.Is(err, sign.ErrSignerPermission) {
		t.Errorf("ctx-cancel-before-dial mis-mapped to ErrSignerPermission (would emit a bogus group/login warning): %v", err)
	}
	// Document the live mapping so a future fix flips this log into an
	// assertion. We do NOT assert ErrUnreachable absence (it currently
	// IS ErrUnreachable) to avoid a false-green; we record it instead.
	if errors.Is(err, sign.ErrUnreachable) {
		t.Logf("FINDING: ctx-cancel-before-dial currently maps to ErrUnreachable and drops the context.Canceled cause (err=%v). classifyDialError should check ctx-cancellation before the *net.OpError catch-all and wrap with %%w.", err)
	}
}

// ---- ECONNREFUSED (socket file exists, nothing listening) -> Unreachable

func TestSign_ConnRefused_StaleSocket_MapsToUnreachable(t *testing.T) {
	t.Parallel()
	path := bindNoListen(t) // socket inode present, no listener

	c := &sign.Client{SocketPath: path, Timeout: 500 * time.Millisecond}
	_, err := c.Sign(context.Background(), "r1", []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want ECONNREFUSED -> ErrUnreachable")
	}
	if !errors.Is(err, sign.ErrUnreachable) {
		t.Errorf("err = %v; want ErrUnreachable for connection-refused", err)
	}
	// A present-but-refusing socket is a dead daemon, not a perm problem.
	if errors.Is(err, sign.ErrSignerPermission) {
		t.Errorf("ECONNREFUSED mis-classified as ErrSignerPermission: %v", err)
	}
}

// ---- (optional) N parallel Sign on one Client under -race ------------

func TestSign_ParallelOnOneClient_RaceSafe(t *testing.T) {
	t.Parallel()
	path, gotReq, stop := startFakeSigner(t, func(req map[string]any) string {
		rid, _ := req["request_id"].(string)
		return fmt.Sprintf(`{"request_id":%q,"status":"approved","signatures":[{"cmd":"x","sig":"S"}]}`, rid)
	})
	defer stop()

	// startFakeSigner's per-conn handler does `gotReqCh <- req` BEFORE it
	// writes the response; gotReqCh is only buffered to 8, so with more
	// in-flight connections than that the handlers block on the send and
	// never reply (client then reads i/o-timeout). Drain it continuously
	// so every connection can make progress. Stop draining when the
	// server is torn down.
	drainDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-gotReq:
			case <-drainDone:
				return
			}
		}
	}()
	defer close(drainDone)

	c := &sign.Client{SocketPath: path, Timeout: 3 * time.Second}
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rid := fmt.Sprintf("r-%d", i)
			res, err := c.Sign(context.Background(), rid, []sign.CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
			if err != nil {
				errs[i] = err
				return
			}
			if len(res.Signed) != 1 || res.Signed[0].Sig != "S" {
				errs[i] = fmt.Errorf("goroutine %d: bad result %+v", i, res.Signed)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("parallel Sign %d: %v", i, err)
		}
	}
}

// ---- helpers ---------------------------------------------------------

// bindNoListen creates a unix socket inode at a temp path and closes the
// fd WITHOUT calling listen(2), leaving a stale socket file. Dialing it
// yields ECONNREFUSED (socket present, nobody listening). t.TempDir
// cleanup removes the file.
func bindNoListen(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "stale.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("bind: %v", err)
	}
	// Deliberately do NOT listen(2). Close the fd; the inode persists.
	if err := syscall.Close(fd); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected stale socket file to exist: %v", err)
	}
	return path
}
