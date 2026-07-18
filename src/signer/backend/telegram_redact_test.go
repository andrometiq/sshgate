package backend_test

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// fakeToken is a synthetic bot token in the real @BotFather shape
// (<bot_id>:<secret>). It is NOT a live credential — it exists only so a
// transport error can embed it in the request URL path the same way a
// real token would, and so the assertions can prove redaction works.
const fakeToken = "123456789:AAFAKE_SECRET_TOKEN_abcdefghijklmnop"

// newRedactBackend builds a TelegramBackend whose getMe succeeds against a
// live fake server (so construction passes) but whose subsequent
// getUpdates / send calls will hit a transport error after the caller
// closes the server. The backend logs into the returned buffer so the
// test can inspect every log line for the token. Returns the backend, the
// log buffer, and a stop func that closes the fake server to force a real
// *url.Error on the next API call.
func newRedactBackend(t *testing.T, store backend.ChatStore) (*backend.TelegramBackend, *syncBuffer, func()) {
	t.Helper()
	if store == nil {
		store = &backend.MemChatStore{}
	}
	fake := newFakeTelegram(t)
	buf := &syncBuffer{}
	tb, err := backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken:       fakeToken,
		AllowedUserID:  allowedUserID,
		ChatStore:      store,
		APIEndpoint:    fake.URLPattern(),
		Logger:         log.New(buf, "", 0),
		RequestTimeout: time.Second,
		PollTimeoutSec: 0,
	})
	if err != nil {
		t.Fatalf("NewTelegramBackend: %v", err)
	}
	// Closing the server makes every later API call fail at the transport
	// layer, yielding a real *url.Error whose Error() embeds
	// <base>/bot<TOKEN>/<method>.
	stop := func() { fake.server.Close() }
	return tb, buf, stop
}

// assertNoTokenLeak fails if the captured text contains the raw token but
// passes the redaction marker requirement separately.
func assertNoTokenLeak(t *testing.T, where, captured string) {
	t.Helper()
	if strings.Contains(captured, fakeToken) {
		t.Fatalf("%s leaked the raw bot token:\n%s", where, captured)
	}
	// Also guard against the bare secret half leaking without the bot_id.
	if strings.Contains(captured, "AAFAKE_SECRET_TOKEN_abcdefghijklmnop") {
		t.Fatalf("%s leaked the bot token secret:\n%s", where, captured)
	}
}

// TestTelegram_GetUpdatesTransportErrorRedacted exercises the polling
// backoff path (telegram.go classifyAndLog -> "getUpdates transport
// error") against a dead API endpoint so a real *url.Error is produced,
// and asserts the captured log NEVER contains the token and DOES contain
// the redaction marker.
func TestTelegram_GetUpdatesTransportErrorRedacted(t *testing.T) {
	tb, buf, stop := newRedactBackend(t, nil)
	stop() // kill the server: getUpdates will now fail at transport level.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Wait until at least one transport-error log line lands.
	waitFor(t, 3*time.Second, func() bool {
		return strings.Contains(buf.String(), "transport error")
	})
	cancel()

	captured := buf.String()
	assertNoTokenLeak(t, "getUpdates transport-error log", captured)
	if !strings.Contains(captured, "bot<REDACTED>") {
		t.Fatalf("getUpdates transport-error log missing redaction marker:\n%s", captured)
	}
}

// TestTelegram_SendTransportErrorRedacted exercises the Request send path
// (telegram.go: "telegram send: %w") against a dead endpoint. The error is
// both RETURNED (bubbles to the daemon -> journal + wire) and must not
// carry the token. We assert the returned error string is clean and
// redacted.
func TestTelegram_SendTransportErrorRedacted(t *testing.T) {
	store := &backend.MemChatStore{}
	if err := store.Save(allowedChatID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tb, _, stop := newRedactBackend(t, store)
	stop() // kill the server: sendMessage will now fail at transport level.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	_, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_send_fail",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo hi", TTLSec: 60}},
	})
	if err == nil {
		t.Fatal("Request returned nil err against a dead endpoint; want a send error")
	}
	msg := err.Error()
	assertNoTokenLeak(t, "Request send error", msg)
	if !strings.Contains(msg, "bot<REDACTED>") {
		t.Fatalf("Request send error missing redaction marker: %q", msg)
	}
}

// TestTelegram_GrantSendTransportErrorRedacted is the RequestGrant twin of
// the send-path test (telegram.go: "telegram send: %w" at the grant site).
func TestTelegram_GrantSendTransportErrorRedacted(t *testing.T) {
	store := &backend.MemChatStore{}
	if err := store.Save(allowedChatID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tb, _, stop := newRedactBackend(t, store)
	stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	_, err := tb.RequestGrant(ctx, signerkit.GrantApprovalRequest{
		RequestID: "g_send_fail",
		Alias:     "x",
		Scope:     "all",
		Duration:  time.Hour,
	})
	if err == nil {
		t.Fatal("RequestGrant returned nil err against a dead endpoint; want a send error")
	}
	msg := err.Error()
	assertNoTokenLeak(t, "RequestGrant send error", msg)
	if !strings.Contains(msg, "bot<REDACTED>") {
		t.Fatalf("RequestGrant send error missing redaction marker: %q", msg)
	}
}

// TestTelegram_GetMeTransportErrorRedacted covers the NewTelegramBackend
// getMe path (telegram.go: "telegram getMe: %w"), which bubbles to the
// fatal startup log in main.go. A transport-level getMe failure must not
// embed the token.
func TestTelegram_GetMeTransportErrorRedacted(t *testing.T) {
	fake := newFakeTelegram(t)
	endpoint := fake.URLPattern()
	fake.server.Close() // dead before construction -> getMe transport error.

	_, err := backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken:      fakeToken,
		AllowedUserID: allowedUserID,
		ChatStore:     &backend.MemChatStore{},
		APIEndpoint:   endpoint,
	})
	if err == nil {
		t.Fatal("NewTelegramBackend returned nil err against a dead endpoint; want a getMe error")
	}
	msg := err.Error()
	assertNoTokenLeak(t, "getMe construction error", msg)
	if !strings.Contains(msg, "bot<REDACTED>") {
		t.Fatalf("getMe construction error missing redaction marker: %q", msg)
	}
}

// syncBuffer is a goroutine-safe bytes.Buffer wrapper. The polling loop
// writes from its own goroutine while the test reads, so the buffer must
// be mutex-guarded (the std bytes.Buffer is not safe for concurrent use).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
