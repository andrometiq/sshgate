package backend_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// fakeServer implements the v2 wire protocol just enough to test the
// HostedServerBackend client. Tests control its state via the
// approveAfter and denyAfter fields; the handler returns canned
// JSON bodies matching the server-side handlers' shapes.
type fakeServer struct {
	mu sync.Mutex
	// reqID is the ID returned by /v1/sign. Reset per test.
	reqID string
	// pollAction governs how /v1/poll responds. One of:
	//   "pending"   → loops forever returning "timeout" (server's
	//                 poll window elapsed; client should retry)
	//   "approved"  → next poll returns approved + signatures
	//   "denied"    → next poll returns denied
	//   "error"     → next poll returns error
	pollAction string
	// pollDelay is applied before each /v1/poll response so tests
	// can exercise the long-poll path without flakes.
	pollDelay time.Duration
	// signatureCmd populates the "cmd" field of the approved
	// signature so tests can assert end-to-end payload flow.
	signatureCmd string
	// pollEmptySignatures emits an approved response with no signatures.
	// The client must fail closed rather than trigger local signing.
	pollEmptySignatures bool

	// --- knobs for the poll matrix / failure-injection tests ---

	// signEmptyReqID makes /v1/sign return 202 with an empty
	// request_id, exercising the client's "empty request_id" guard.
	signEmptyReqID bool
	// pollHTTPStatus, when non-zero, overrides the /v1/poll HTTP
	// status (e.g. 404). A non-200 status is terminal for the client.
	pollHTTPStatus int
	// pollMalformed makes /v1/poll return a 200 body that is not valid
	// JSON, exercising the unmarshal-error → StatusTimeout path.
	pollMalformed bool
	// pollRawStatus, when non-empty, is written verbatim as the
	// "status" field (200 OK) — lets a test send an unknown status
	// string the action switch above can't express.
	pollRawStatus string
	// pollConnErrFirst makes the FIRST /v1/poll hijack and abruptly
	// close the connection (simulating a transient connect error). The
	// client should back off and retry; subsequent polls follow
	// pollAction (set to "approved" to assert retry-then-resolve).
	pollConnErrFirst bool
	pollHits         int
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/sign" && r.Method == http.MethodPost:
		f.mu.Lock()
		rid := f.reqID
		if f.signEmptyReqID {
			rid = ""
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"request_id": rid,
			"poll_url":   "/v1/poll/" + rid,
		})
	case strings.HasPrefix(r.URL.Path, "/v1/poll/") && r.Method == http.MethodGet:
		f.mu.Lock()
		f.pollHits++
		hit := f.pollHits
		action := f.pollAction
		delay := f.pollDelay
		sigCmd := f.signatureCmd
		emptySignatures := f.pollEmptySignatures
		httpStatus := f.pollHTTPStatus
		malformed := f.pollMalformed
		rawStatus := f.pollRawStatus
		connErrFirst := f.pollConnErrFirst
		f.mu.Unlock()

		// Transient transport error on the first poll: hijack and write a
		// truncated HTTP response (Content-Length promises more bytes than
		// we send), then close. The client receives response headers but
		// io.ReadAll on the body fails with unexpected EOF — surfacing as
		// a poll-iteration error the backend retries (it will NOT be
		// transparently retried by the transport, since a response WAS
		// received). This drives the backend's 500ms-backoff-then-retry
		// path deterministically.
		if connErrFirst && hit == 1 {
			if hj, ok := w.(http.Hijacker); ok {
				conn, buf, err := hj.Hijack()
				if err == nil {
					// Promise 100 bytes, send 5, then close → unexpected EOF.
					_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
					_ = buf.Flush()
					_ = conn.Close()
					return
				}
			}
			// Hijack unsupported — fall through to a 500 as a weaker
			// stand-in (still a retryable failure for the client).
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}

		// HTTP-status override (e.g. 404 unknown request_id) — terminal.
		if httpStatus != 0 {
			w.WriteHeader(httpStatus)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "scripted"})
			return
		}
		// Malformed 200 body → client unmarshal error → StatusTimeout.
		if malformed {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{not-json"))
			return
		}
		// Unknown status string → client's defensive default → Timeout.
		if rawStatus != "" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"request_id": strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":     rawStatus,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		switch action {
		case "approved":
			now := time.Now().UTC()
			signatures := []map[string]string{{"cmd": sigCmd, "sig": "SSHGATE_SIG:fake"}}
			if emptySignatures {
				signatures = nil
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id":       strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":           "approved",
				"signatures":       signatures,
				"approved_by_user": "karthi",
				"approved_at":      now,
			})
		case "denied":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id":       strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":           "denied",
				"approved_by_user": "karthi",
			})
		case "error":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":     "error",
				"error":      "boom",
			})
		default: // "pending" or unset
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":     "timeout",
			})
		}
	default:
		http.NotFound(w, r)
	}
}

// fakeWithAuth wraps fakeServer.handle with a bearer-token check so
// tests can assert that the client always sends Authorization.
func (f *fakeServer) handleWithAuth(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.handle(w, r)
	})
}

func newFakeServerBackend(t *testing.T, fs *fakeServer) (*signerkit.HostedServerBackend, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(fs.handleWithAuth("test-key"))
	t.Cleanup(ts.Close)
	return &signerkit.HostedServerBackend{
		BaseURL:    ts.URL,
		APIKey:     "test-key",
		ClientID:   "test-laptop",
		HTTPClient: ts.Client(),
		PollWait:   100 * time.Millisecond,
		Timeout:    3 * time.Second,
	}, ts
}

func TestHostedServerBackend_Approved(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_abc", pollAction: "approved", signatureCmd: "echo hi"}
	hb, _ := newFakeServerBackend(t, fs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := hb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "ignored-by-server-but-required-by-daemon",
		Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: "echo hi", TTLSec: 60}},
		Submitted: time.Now(),
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res, ok := <-ch:
		if !ok {
			t.Fatal("channel closed without a result")
		}
		if res.Status != signerkit.StatusApproved {
			t.Errorf("status = %v; want StatusApproved", res.Status)
		}
		if res.ApprovedBy != "karthi" {
			t.Errorf("ApprovedBy = %q; want karthi", res.ApprovedBy)
		}
		// Remote-signing contract: Signatures must be populated, one
		// per request command, with the wire string from the server.
		if len(res.Signatures) != 1 {
			t.Fatalf("Signatures len = %d; want 1 (one per request command)", len(res.Signatures))
		}
		if res.Signatures[0].Cmd != "echo hi" {
			t.Errorf("Signatures[0].Cmd = %q; want echo hi", res.Signatures[0].Cmd)
		}
		if res.Signatures[0].Sig != "SSHGATE_SIG:fake" {
			t.Errorf("Signatures[0].Sig = %q; want SSHGATE_SIG:fake (passthrough of server's wire string)", res.Signatures[0].Sig)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Request did not resolve within 3s")
	}
}

func TestHostedServerBackend_MalformedApprovalFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		fs      *fakeServer
		wantCmd string
	}{
		{name: "empty signatures", fs: &fakeServer{reqID: "r_empty", pollAction: "approved", pollEmptySignatures: true}, wantCmd: "echo hi"},
		{name: "wrong command", fs: &fakeServer{reqID: "r_wrong", pollAction: "approved", signatureCmd: "different command"}, wantCmd: "echo hi"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hb, _ := newFakeServerBackend(t, tc.fs)
			ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
				RequestID: "local-request",
				Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: tc.wantCmd, TTLSec: 60}},
			})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case res := <-ch:
				if res.Status != signerkit.StatusTimeout || len(res.Signatures) != 0 {
					t.Fatalf("malformed approval = %+v; want fail-closed timeout without signatures", res)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("malformed approval did not resolve")
			}
		})
	}
}

func TestHostedServerBackend_Denied(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_deny", pollAction: "denied"}
	hb, _ := newFakeServerBackend(t, fs)

	ctx := context.Background()
	ch, err := hb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r1",
		Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "rm -rf /", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res := <-ch:
		if res.Status != signerkit.StatusDenied {
			t.Errorf("status = %v; want StatusDenied", res.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Request did not resolve within 3s")
	}
}

func TestHostedServerBackend_TimeoutBudget(t *testing.T) {
	t.Parallel()
	// pollAction "" → server always returns "timeout"; client
	// should keep re-polling until its Timeout fires.
	fs := &fakeServer{reqID: "r_to"}
	hb, _ := newFakeServerBackend(t, fs)
	hb.PollWait = 50 * time.Millisecond
	hb.Timeout = 250 * time.Millisecond

	start := time.Now()
	ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "r1",
		Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res := <-ch:
		if res.Status != signerkit.StatusTimeout {
			t.Errorf("status = %v; want StatusTimeout", res.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Request did not time out")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("elapsed = %v; want >= ~250ms (Timeout budget)", elapsed)
	}
}

func TestHostedServerBackend_CtxCancel(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_cancel"}
	hb, _ := newFakeServerBackend(t, fs)
	hb.PollWait = 100 * time.Millisecond
	hb.Timeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := hb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r1",
		Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	// Cancel after a brief moment; the long-poll should yield
	// StatusTimeout quickly.
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	select {
	case res := <-ch:
		if res.Status != signerkit.StatusTimeout {
			t.Errorf("status = %v; want StatusTimeout on ctx cancel", res.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx cancel did not propagate")
	}
}

func TestHostedServerBackend_RejectsBadAuth(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_unauth"}
	hb, _ := newFakeServerBackend(t, fs)
	hb.APIKey = "wrong-token"

	_, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "r1",
		Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err == nil {
		t.Fatal("Request should fail with 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v; want a 401 mention", err)
	}
}

func TestHostedServerBackend_ValidatesConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hb   signerkit.HostedServerBackend
	}{
		{"no BaseURL", signerkit.HostedServerBackend{APIKey: "k", ClientID: "c"}},
		{"no APIKey", signerkit.HostedServerBackend{BaseURL: "http://x", ClientID: "c"}},
		{"no ClientID", signerkit.HostedServerBackend{BaseURL: "http://x", APIKey: "k"}},
		{"remote HTTP", signerkit.HostedServerBackend{BaseURL: "http://signer.example.com", APIKey: "k", ClientID: "c"}},
		{"URL credentials", signerkit.HostedServerBackend{BaseURL: "https://user@signer.example.com", APIKey: "k", ClientID: "c"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.hb.Request(context.Background(), signerkit.ApprovalRequest{
				RequestID: "r",
				Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
			})
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestHostedServerBackend_RejectsReveal(t *testing.T) {
	t.Parallel()
	// Fail-CLOSED defence: a reveal must NOT be silently downgraded to an
	// ordinary approval on the hosted path (the v2 wire structs don't carry
	// the reveal flag or its reason yet). If ANY command is a reveal, Request
	// must error WITHOUT touching the server — so no future v2 web UI can
	// render an un-bannered reveal a human approves unknowingly.
	// hit is written by the httptest handler goroutine and read by the test
	// goroutine, so it must be synchronized (atomic) to stay race-free under
	// `go test -race`. The Request path itself is sequential — only this
	// test-harness observation flag crosses goroutines.
	var hit atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"request_id":"r","poll_url":"/v1/poll/r"}`))
	}))
	defer ts.Close()

	hb := &signerkit.HostedServerBackend{
		BaseURL:    ts.URL,
		APIKey:     "k",
		ClientID:   "karthi-laptop",
		HTTPClient: ts.Client(),
		PollWait:   50 * time.Millisecond,
		Timeout:    2 * time.Second,
	}

	// A reveal command (possibly mixed with an ordinary one) must be rejected.
	ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "r_reveal",
		Commands: []signerkit.CommandReq{
			{Server: "prod", Cmd: "systemctl restart nginx", TTLSec: 60},
			{Server: "prod", Cmd: "cat /etc/secret.env", TTLSec: 60, Reveal: true, Reason: "need the DB password"},
		},
	})
	if err == nil {
		t.Fatal("Request with a reveal command should error; got nil")
	}
	if ch != nil {
		t.Error("Request returned a non-nil channel alongside the reveal error; want nil")
	}
	if !strings.Contains(err.Error(), "reveal") {
		t.Errorf("err = %v; want a mention of reveal", err)
	}
	if hit.Load() {
		t.Error("server was contacted on a reveal request; must fail-closed BEFORE the HTTP call")
	}

	// Sanity: the SAME backend still works for an ordinary (non-reveal) write.
	ch2, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "r_plain",
		Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: "systemctl restart nginx", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("non-reveal Request should succeed; got %v", err)
	}
	if !hit.Load() {
		t.Error("server was NOT contacted on a non-reveal request; the guard over-rejected")
	}
	if ch2 != nil {
		<-ch2 // drain so the poll goroutine exits cleanly
	}
}

func TestHostedServerBackend_SendsExpectedBody(t *testing.T) {
	t.Parallel()
	var captured []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sign" {
			captured, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"request_id":"r_x","poll_url":"/v1/poll/r_x"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"request_id":"r_x","status":"approved","signatures":[]}`))
	}))
	defer ts.Close()

	hb := &signerkit.HostedServerBackend{
		BaseURL:    ts.URL,
		APIKey:     "k",
		ClientID:   "karthi-laptop",
		HTTPClient: ts.Client(),
		PollWait:   50 * time.Millisecond,
		Timeout:    2 * time.Second,
	}
	ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "ignored",
		Commands: []signerkit.CommandReq{
			{Server: "prod", Cmd: "echo hi", TTLSec: 60},
			{Server: "stage", Cmd: "uptime", TTLSec: 30},
		},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	<-ch

	var body struct {
		ClientID string `json:"client_id"`
		Commands []struct {
			Server     string `json:"server"`
			Cmd        string `json:"cmd"`
			TTLSeconds int64  `json:"ttl_seconds"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("decode captured body: %v (raw=%q)", err, string(captured))
	}
	if body.ClientID != "karthi-laptop" {
		t.Errorf("client_id = %q; want karthi-laptop", body.ClientID)
	}
	if len(body.Commands) != 2 {
		t.Fatalf("commands len = %d; want 2", len(body.Commands))
	}
	if body.Commands[0].Cmd != "echo hi" || body.Commands[0].Server != "prod" || body.Commands[0].TTLSeconds != 60 {
		t.Errorf("commands[0] = %+v; want {prod, echo hi, 60}", body.Commands[0])
	}
}
