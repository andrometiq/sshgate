//go:build integration

// Phase-2 end-to-end test for SSHGate (task 2.5).
//
// Lock criterion for Phase 2. Wires the REAL stack end-to-end with the
// only fake being the Telegram API itself (an in-process httptest
// server we drive from the test):
//
//   Runner (real MCP) → sign.Client → signer.Daemon (real)
//                                       → TelegramBackend (real)
//                                       → httptest fake Telegram
//                                       → callback injected from test
//                                       → daemon signs
//   Runner → ssh.Client → Docker openssh-server → real gate binary
//                                                 → /tmp/<file> on remote
//
// Six scenarios:
//   1. Approve single write — message rendered, callback resolves,
//      command runs on remote, audit logged.
//   2. Deny single write — wrapped ErrDenied, no SSH, audit logged.
//   3. Bulk approval — RunBatch with 3 commands triggers ONE
//      sendMessage; one Approve callback resolves; all three run.
//   4. Wrong-user callback — from.id mismatch is ignored; later real
//      callback succeeds.
//   5. Timeout — no callback within 500ms → wrapped ErrTimeout.
//   6. Goroutine leak — goleak.VerifyNone at the end.
//
// If Docker isn't available the test skips cleanly (same pattern as
// Phase 1).
package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/signer"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// --- fake Telegram ------------------------------------------------------

// phase2AllowedUserID is the only Telegram user_id whose callbacks the
// backend will honour. Picked arbitrarily; the value is local to this
// test.
const phase2AllowedUserID = int64(99999)

// phase2ChatID is the DM chat that the test pre-populates into the
// ChatStore (simulating a prior /start).
const phase2ChatID = int64(12345)

// fakeTG is an in-process httptest server that speaks just enough of
// the Telegram Bot API to satisfy TelegramBackend. Inbound updates
// (callback_query / message) are pushed by the test via pushCallback /
// pushMessage; outbound calls (sendMessage / edit / answerCallback) are
// captured into slice snapshots.
type fakeTG struct {
	t      *testing.T
	server *httptest.Server

	mu              sync.Mutex
	pendingUpdates  []fakeTGUpdate
	nextUpdateID    int
	nextMessageID   int
	sentMessages    []fakeTGSent
	editedMessages  []fakeTGEdit
	callbackAnswers []fakeTGAnswer

	getUpdatesCalls atomic.Int64
}

type fakeTGUpdate struct {
	UpdateID      int             `json:"update_id"`
	Message       json.RawMessage `json:"message,omitempty"`
	CallbackQuery json.RawMessage `json:"callback_query,omitempty"`
}

type fakeTGSent struct {
	ChatID      int64
	MessageID   int
	Text        string
	ReplyMarkup string
}

type fakeTGEdit struct {
	ChatID    int64
	MessageID int
	Text      string
}

type fakeTGAnswer struct {
	CallbackID string
	Text       string
}

func newFakeTG(t *testing.T) *fakeTG {
	t.Helper()
	f := &fakeTG{t: t, nextMessageID: 5000}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.route)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// URLPattern returns the value to pass as TelegramOptions.APIEndpoint:
// "<base>/bot%s/%s" so the bot library substitutes token + method.
func (f *fakeTG) URLPattern() string {
	return f.server.URL + "/bot%s/%s"
}

func (f *fakeTG) route(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "bot") {
		http.NotFound(w, r)
		return
	}
	method := parts[1]
	_ = r.ParseForm()

	switch method {
	case "getMe":
		f.replyGetMe(w)
	case "getUpdates":
		f.replyGetUpdates(w, r)
	case "sendMessage":
		f.replySendMessage(w, r)
	case "editMessageText", "editMessageReplyMarkup":
		f.replyEditMessage(w, r)
	case "answerCallbackQuery":
		f.replyAnswerCallback(w, r)
	default:
		writeTGResult(w, json.RawMessage(`{}`))
	}
}

func (f *fakeTG) replyGetMe(w http.ResponseWriter) {
	body := json.RawMessage(`{"id":7777,"is_bot":true,"first_name":"sshgate-signer-bot","username":"signer_bot"}`)
	writeTGResult(w, body)
}

func (f *fakeTG) replyGetUpdates(w http.ResponseWriter, r *http.Request) {
	f.getUpdatesCalls.Add(1)
	timeoutSec, _ := strconv.Atoi(r.FormValue("timeout"))
	offset, _ := strconv.Atoi(r.FormValue("offset"))

	// Cap long-poll to 1s so the test isn't held hostage by the
	// backend's poll loop on shutdown. Backend uses Timeout=0 in tests
	// anyway, so this is just defensive.
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	if timeoutSec > 1 {
		deadline = time.Now().Add(time.Second)
	}
	for {
		f.mu.Lock()
		var out []fakeTGUpdate
		var keep []fakeTGUpdate
		for _, u := range f.pendingUpdates {
			if u.UpdateID >= offset {
				out = append(out, u)
			} else {
				keep = append(keep, u)
			}
		}
		if len(out) > 0 {
			f.pendingUpdates = keep
			f.mu.Unlock()
			b, _ := json.Marshal(out)
			writeTGResult(w, b)
			return
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			writeTGResult(w, json.RawMessage(`[]`))
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fakeTG) replySendMessage(w http.ResponseWriter, r *http.Request) {
	chatID, _ := strconv.ParseInt(r.FormValue("chat_id"), 10, 64)
	text := r.FormValue("text")
	rm := r.FormValue("reply_markup")
	f.mu.Lock()
	mid := f.nextMessageID
	f.nextMessageID++
	f.sentMessages = append(f.sentMessages, fakeTGSent{
		ChatID: chatID, MessageID: mid, Text: text, ReplyMarkup: rm,
	})
	f.mu.Unlock()
	body := fmt.Sprintf(`{"message_id":%d,"chat":{"id":%d,"type":"private"},"date":%d,"text":%q}`,
		mid, chatID, time.Now().Unix(), text)
	writeTGResult(w, json.RawMessage(body))
}

func (f *fakeTG) replyEditMessage(w http.ResponseWriter, r *http.Request) {
	chatID, _ := strconv.ParseInt(r.FormValue("chat_id"), 10, 64)
	mid, _ := strconv.Atoi(r.FormValue("message_id"))
	text := r.FormValue("text")
	f.mu.Lock()
	f.editedMessages = append(f.editedMessages, fakeTGEdit{
		ChatID: chatID, MessageID: mid, Text: text,
	})
	f.mu.Unlock()
	body := fmt.Sprintf(`{"message_id":%d,"chat":{"id":%d,"type":"private"},"date":%d,"text":%q}`,
		mid, chatID, time.Now().Unix(), text)
	writeTGResult(w, json.RawMessage(body))
}

func (f *fakeTG) replyAnswerCallback(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("callback_query_id")
	text := r.FormValue("text")
	f.mu.Lock()
	f.callbackAnswers = append(f.callbackAnswers, fakeTGAnswer{
		CallbackID: id, Text: text,
	})
	f.mu.Unlock()
	writeTGResult(w, json.RawMessage(`true`))
}

func writeTGResult(w http.ResponseWriter, result json.RawMessage) {
	body, _ := json.Marshal(struct {
		Ok     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}{Ok: true, Result: result})
	_, _ = w.Write(body)
}

// pushCallback injects a callback_query update simulating a button tap.
// data is the callback payload, e.g. "approve:r_abc123".
func (f *fakeTG) pushCallback(fromID int64, username, data string, messageID int, chatID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextUpdateID++
	uid := f.nextUpdateID
	cbID := fmt.Sprintf("cb%d", uid)
	cb := fmt.Sprintf(`{"id":%q,"from":{"id":%d,"is_bot":false,"first_name":"u","username":%q},"chat_instance":"ci","data":%q,"message":{"message_id":%d,"chat":{"id":%d,"type":"private"},"date":%d,"text":"prev"}}`,
		cbID, fromID, username, data, messageID, chatID, time.Now().Unix())
	f.pendingUpdates = append(f.pendingUpdates, fakeTGUpdate{
		UpdateID: uid, CallbackQuery: json.RawMessage(cb),
	})
}

// Snapshot helpers — lock + copy so callers don't race the server.

func (f *fakeTG) sentSnapshot() []fakeTGSent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeTGSent, len(f.sentMessages))
	copy(out, f.sentMessages)
	return out
}

func (f *fakeTG) editsSnapshot() []fakeTGEdit {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeTGEdit, len(f.editedMessages))
	copy(out, f.editedMessages)
	return out
}

func (f *fakeTG) answersSnapshot() []fakeTGAnswer {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeTGAnswer, len(f.callbackAnswers))
	copy(out, f.callbackAnswers)
	return out
}

// --- signer + telegram wiring helpers --------------------------------

// startSignerTelegram boots a real signer.Server in a goroutine,
// wired to a real TelegramBackend pointed at the supplied fakeTG. The
// ChatStore is pre-populated with phase2ChatID (simulating a prior
// /start). Returns the socket path, audit log path, the backend (for
// callers that need to read PanicsTotal etc.), and a cleanup func.
func startSignerTelegram(t *testing.T, masterKeyPath string, fake *fakeTG, reqTimeout time.Duration) (socketPath, auditPath string, tb *backend.TelegramBackend, cleanup func()) {
	t.Helper()

	priv, err := signer.LoadKey(masterKeyPath)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	auditPath = filepath.Join(t.TempDir(), "approvals.log")
	audit, err := signer.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}

	store := &backend.MemChatStore{}
	if err := store.Save(phase2ChatID); err != nil {
		t.Fatalf("ChatStore seed: %v", err)
	}
	tb, err = backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken:       "phase2-test-token",
		AllowedUserID:  phase2AllowedUserID,
		ChatStore:      store,
		APIEndpoint:    fake.URLPattern(),
		Logger:         log.New(io.Discard, "", 0),
		RequestTimeout: reqTimeout,
		PollTimeoutSec: 0, // immediate getUpdates returns
	})
	if err != nil {
		t.Fatalf("NewTelegramBackend: %v", err)
	}

	daemon := &signer.Daemon{
		Key:     priv,
		Backend: tb,
		Audit:   audit,
	}
	socketPath = filepath.Join(t.TempDir(), "signer.sock")
	srv := &signer.Server{
		Path:           socketPath,
		Handler:        daemon,
		HandlerTimeout: 30 * time.Second,
	}

	// Two contexts:
	//   - backendCtx drives the TelegramBackend's polling loop.
	//   - serverCtx drives the Unix-socket accept loop.
	// Both share the same cancel so cleanup tears down everything.
	backendCtx, backendCancel := context.WithCancel(context.Background())
	if err := tb.Run(backendCtx); err != nil {
		backendCancel()
		_ = audit.Close()
		t.Fatalf("TelegramBackend.Run: %v", err)
	}

	serverCtx, serverCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serveErr error
	go func() {
		defer close(done)
		serveErr = srv.Listen(serverCtx)
	}()

	// Wait briefly for the socket file so callers can dial without races.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			serverCancel()
			<-done
			backendCancel()
			// Give the backend's polling goroutine a moment to exit
			// after ctx-cancel. It exits when its current getUpdates
			// returns (≤ 1s in the fake) or when stopCh closes — the
			// latter is immediate.
			waitWithDeadline(t, 3*time.Second, func() bool {
				return tb.PanicsTotal() >= 0 // sentinel: just give the loop time
			})
			_ = audit.Close()
			if serveErr != nil {
				t.Logf("signer Listen returned: %v", serveErr)
			}
		})
	}
	return socketPath, auditPath, tb, cleanup
}

// buildRunner constructs a real tools.Runner around the live signer
// socket and SSH key, with a registry containing `alias → host:port@user`.
// Returns the Runner; the caller invokes Run / RunBatch directly.
func buildRunner(t *testing.T, socketPath, sshKeyPath string, alias, host string, port int, user string) *tools.Runner {
	t.Helper()

	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	signClient := &signpkg.Client{
		SocketPath: socketPath,
		Timeout:    30 * time.Second,
	}
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	sshClient := &sshpkg.Client{
		KeyPath:        sshKeyPath,
		KnownHostsPath: khPath,
		Timeout:        15 * time.Second,
	}

	// The gate fails CLOSED on an empty/mismatched host binding (verify.go —
	// ErrHostMismatch), so a signed write MUST carry the target's real
	// host-key fingerprint. Production sources this from the TOFU pin recorded
	// at provision time; here we pin it the same way (a SSHGATE_VERSION read
	// populates known_hosts) and store it in Entry.Fingerprint, which
	// Runner.Run / RunBatch copy into the signed payload's Host.
	pinCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fp := pinContainerHostFP(pinCtx, t, sshClient, khPath)

	if err := servers.Add(alias, registry.Entry{
		Host:        host,
		Port:        port,
		User:        user,
		AddedAt:     time.Now(),
		Fingerprint: fp,
	}); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}

	return &tools.Runner{
		Servers:     servers,
		Sign:        signClient,
		SSH:         sshClient,
		WriteTTLSec: 60,
	}
}

// waitWithDeadline polls cond every 10ms until it returns true or
// timeout elapses. It does NOT fail the test on timeout — it's used in
// cleanup paths where best-effort waiting is appropriate.
func waitWithDeadline(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requireEventually polls cond until it returns true or timeout
// elapses, failing the test with msg if the deadline is hit. This is
// the test-side equivalent of testify's require.Eventually.
func requireEventually(t *testing.T, timeout time.Duration, cond func() bool, msg string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("requireEventually: "+msg, args...)
}

// extractRequestID parses the "Request ID: <id>" line from a fake
// Telegram message body. The backend renders it via formatApprovalMessage.
// Returns the id or "" if not found.
func extractRequestID(text string) string {
	const tag = "Request ID: "
	i := strings.Index(text, tag)
	if i < 0 {
		return ""
	}
	rest := text[i+len(tag):]
	// Trim at the next newline.
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// readAuditLines parses the audit log into a slice of records.
func readAuditLines(t *testing.T, path string) []signer.AuditEvent {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit %s: %v", path, err)
	}
	var out []signer.AuditEvent
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var ev signer.AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("parse audit line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// findAuditByRequestID returns the first audit event with matching
// RequestID, or nil.
func findAuditByRequestID(events []signer.AuditEvent, reqID string) *signer.AuditEvent {
	for i := range events {
		if events[i].RequestID == reqID {
			return &events[i]
		}
	}
	return nil
}

// --- the test -----------------------------------------------------------

func TestPhase2EndToEnd(t *testing.T) {
	// Phase-1-style setup: SSH key + gate key generated BEFORE
	// container boot (the linuxserver image bakes the pubkey into
	// authorized_keys at startup).
	sshKeyPriv, _ := generateSSHKey(t)
	_, gatePub := generateGateKeyPair(t)
	masterKey := strings.TrimSuffix(gatePub, ".pub") + ".key"

	containerCleanup := bootContainer(t)
	t.Cleanup(containerCleanup)

	deployGateBinary(t, gatePub)

	// One fake Telegram + one signer stack for scenarios 1–4 with a
	// generous 15s request timeout. Scenario 5 (Timeout) spins up its
	// own short-timeout stack so the others aren't held hostage by a
	// fast-expiring backend.
	fakeMain := newFakeTG(t)
	socketMain, auditMain, _, cleanupMain := startSignerTelegram(t, masterKey, fakeMain, 15*time.Second)
	t.Cleanup(cleanupMain)
	runnerMain := buildRunner(t, socketMain, sshKeyPriv, "test", "127.0.0.1", sshContainerPort, remoteUser)

	t.Run("ApproveSingleWrite", func(t *testing.T) {
		// Snapshot baselines so we can spot what THIS scenario added.
		baseSent := len(fakeMain.sentSnapshot())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Launch the runner in a goroutine; it will block in Sign until
		// we inject the approve callback below.
		type runResult struct {
			out tools.RunOutput
			err error
		}
		done := make(chan runResult, 1)
		go func() {
			out, err := runnerMain.Run(ctx, tools.RunInput{
				Alias:   "test",
				Command: "rm -f /tmp/test-write-1",
			})
			done <- runResult{out: out, err: err}
		}()

		// Wait for the approval message to fly out, then extract the
		// request_id from its body.
		requireEventually(t, 5*time.Second, func() bool {
			return len(fakeMain.sentSnapshot()) > baseSent
		}, "no sendMessage observed within 5s")
		sent := fakeMain.sentSnapshot()[baseSent]
		if sent.ChatID != phase2ChatID {
			t.Errorf("sendMessage ChatID=%d; want %d", sent.ChatID, phase2ChatID)
		}
		if !strings.Contains(sent.Text, "rm -f /tmp/test-write-1") {
			t.Errorf("sendMessage text missing command: %q", sent.Text)
		}
		if !strings.Contains(sent.ReplyMarkup, "approve:") || !strings.Contains(sent.ReplyMarkup, "deny:") {
			t.Errorf("sendMessage reply_markup missing Approve/Deny: %q", sent.ReplyMarkup)
		}
		reqID := extractRequestID(sent.Text)
		if reqID == "" {
			t.Fatalf("could not parse Request ID from message text: %q", sent.Text)
		}

		// Inject the approve callback from the allowed user.
		fakeMain.pushCallback(phase2AllowedUserID, "karthi", "approve:"+reqID, sent.MessageID, phase2ChatID)

		// Runner should return success.
		var res runResult
		select {
		case res = <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("Runner.Run did not return within 15s after approve")
		}
		if res.err != nil {
			t.Fatalf("Runner.Run err=%v stdout=%q stderr=%q exit=%d",
				res.err, res.out.Stdout, res.out.Stderr, res.out.ExitCode)
		}
		if res.out.ExitCode != 0 {
			t.Errorf("ExitCode=%d; want 0 (stderr=%q)", res.out.ExitCode, res.out.Stderr)
		}
		if res.out.Kind != "write" {
			t.Errorf("Kind=%q; want write", res.out.Kind)
		}
		if !res.out.Approved {
			t.Errorf("Approved=false; want true")
		}

		// At least one editMessage was issued (the Approved-by footer).
		// Subtests share fakeMain so we look for an edit referencing
		// THIS message_id.
		requireEventually(t, 3*time.Second, func() bool {
			for _, e := range fakeMain.editsSnapshot() {
				if e.MessageID == sent.MessageID && strings.Contains(e.Text, "Approved") {
					return true
				}
			}
			return false
		}, "no editMessage with 'Approved' footer for message_id=%d", sent.MessageID)

		// Audit log: one entry for this request_id with status=approved.
		ev := findAuditByRequestID(readAuditLines(t, auditMain), reqID)
		if ev == nil {
			t.Fatalf("audit log has no entry for request_id=%s", reqID)
		}
		if ev.Status != "approved" {
			t.Errorf("audit status=%q; want approved", ev.Status)
		}
		if len(ev.Commands) != 1 || ev.Commands[0] != "rm -f /tmp/test-write-1" {
			t.Errorf("audit commands=%v; want [rm -f /tmp/test-write-1]", ev.Commands)
		}
	})

	t.Run("DenySingleWrite", func(t *testing.T) {
		baseSent := len(fakeMain.sentSnapshot())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		type runResult struct {
			out tools.RunOutput
			err error
		}
		done := make(chan runResult, 1)
		go func() {
			out, err := runnerMain.Run(ctx, tools.RunInput{
				Alias:   "test",
				Command: "rm -f /tmp/test-write-2",
			})
			done <- runResult{out: out, err: err}
		}()

		requireEventually(t, 5*time.Second, func() bool {
			return len(fakeMain.sentSnapshot()) > baseSent
		}, "no sendMessage observed within 5s")
		sent := fakeMain.sentSnapshot()[baseSent]
		reqID := extractRequestID(sent.Text)
		if reqID == "" {
			t.Fatalf("missing Request ID in: %q", sent.Text)
		}

		// Inject DENY callback.
		fakeMain.pushCallback(phase2AllowedUserID, "karthi", "deny:"+reqID, sent.MessageID, phase2ChatID)

		var res runResult
		select {
		case res = <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("Runner.Run did not return within 15s after deny")
		}
		if res.err == nil {
			t.Fatalf("Runner.Run returned nil err on deny; want wrapped ErrDenied. out=%+v", res.out)
		}
		if !errors.Is(res.err, signpkg.ErrDenied) {
			t.Errorf("err does not wrap ErrDenied: %v", res.err)
		}
		// No SSH happens on deny.
		if len(res.out.Stdout) != 0 {
			t.Errorf("stdout=%q on deny; should be empty (cmd should never reach remote)", res.out.Stdout)
		}

		// Audit: one denied entry for this request_id.
		ev := findAuditByRequestID(readAuditLines(t, auditMain), reqID)
		if ev == nil {
			t.Fatalf("audit log has no entry for request_id=%s", reqID)
		}
		if ev.Status != "denied" {
			t.Errorf("audit status=%q; want denied", ev.Status)
		}

		// editMessageText with denied footer.
		requireEventually(t, 3*time.Second, func() bool {
			for _, e := range fakeMain.editsSnapshot() {
				if e.MessageID == sent.MessageID && strings.Contains(e.Text, "Denied") {
					return true
				}
			}
			return false
		}, "no editMessage with 'Denied' footer for message_id=%d", sent.MessageID)
	})

	t.Run("BulkApproval", func(t *testing.T) {
		baseSent := len(fakeMain.sentSnapshot())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		type batchResult struct {
			out tools.RunBatchOutput
			err error
		}
		done := make(chan batchResult, 1)
		go func() {
			out, err := runnerMain.RunBatch(ctx, tools.RunBatchInput{
				Alias: "test",
				Commands: []string{
					"touch /tmp/bulk-a",
					"touch /tmp/bulk-b",
					"touch /tmp/bulk-c",
				},
			})
			done <- batchResult{out: out, err: err}
		}()

		// Exactly ONE sendMessage with all three commands listed.
		requireEventually(t, 5*time.Second, func() bool {
			return len(fakeMain.sentSnapshot()) > baseSent
		}, "no sendMessage observed within 5s")
		// Give the backend a beat to ensure no extra sendMessage trails
		// in (the contract is ONE approval prompt for the whole batch).
		time.Sleep(100 * time.Millisecond)
		afterSent := fakeMain.sentSnapshot()
		newSends := afterSent[baseSent:]
		if len(newSends) != 1 {
			t.Fatalf("got %d sendMessages for batch; want exactly 1: %+v", len(newSends), newSends)
		}
		sent := newSends[0]
		for _, c := range []string{"touch /tmp/bulk-a", "touch /tmp/bulk-b", "touch /tmp/bulk-c"} {
			if !strings.Contains(sent.Text, c) {
				t.Errorf("batch message missing command %q: %q", c, sent.Text)
			}
		}
		if !strings.Contains(sent.Text, "3 commands queued") {
			t.Errorf("batch message missing '3 commands queued': %q", sent.Text)
		}
		reqID := extractRequestID(sent.Text)
		if reqID == "" {
			t.Fatalf("missing Request ID in batch message: %q", sent.Text)
		}

		// ONE approve callback resolves the whole batch.
		fakeMain.pushCallback(phase2AllowedUserID, "karthi", "approve:"+reqID, sent.MessageID, phase2ChatID)

		var res batchResult
		select {
		case res = <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("RunBatch did not return within 20s after approve")
		}
		if res.err != nil {
			t.Fatalf("RunBatch err=%v out=%+v", res.err, res.out)
		}
		if !res.out.Approved {
			t.Errorf("Approved=false; want true")
		}
		if res.out.Denied {
			t.Errorf("Denied=true; want false")
		}
		if len(res.out.Results) != 3 {
			t.Fatalf("len(Results)=%d; want 3", len(res.out.Results))
		}
		for i, r := range res.out.Results {
			if r.ExitCode != 0 {
				t.Errorf("Results[%d] exit=%d stderr=%q; want 0", i, r.ExitCode, r.Stderr)
			}
			if r.Skipped {
				t.Errorf("Results[%d] Skipped=true; want false", i)
			}
		}

		// All three files exist on the remote.
		stdout, _, exit, err := directUnsignedSSH(t, sshKeyPriv,
			"127.0.0.1", sshContainerPort, remoteUser, "ls /tmp/bulk-a /tmp/bulk-b /tmp/bulk-c")
		if err != nil {
			t.Fatalf("ls bulk files: %v", err)
		}
		if exit != 0 {
			t.Errorf("ls bulk files exit=%d stdout=%q; want 0 (all three should exist)", exit, stdout)
		}
		if !strings.Contains(string(stdout), "/tmp/bulk-a") ||
			!strings.Contains(string(stdout), "/tmp/bulk-b") ||
			!strings.Contains(string(stdout), "/tmp/bulk-c") {
			t.Errorf("ls bulk output missing one or more files: %q", stdout)
		}

		// Audit: one entry with all 3 commands.
		ev := findAuditByRequestID(readAuditLines(t, auditMain), reqID)
		if ev == nil {
			t.Fatalf("audit log has no entry for batch request_id=%s", reqID)
		}
		if ev.Status != "approved" {
			t.Errorf("audit status=%q; want approved", ev.Status)
		}
		if len(ev.Commands) != 3 {
			t.Errorf("audit commands=%v; want 3-cmd batch", ev.Commands)
		}
	})

	t.Run("WrongUserCallbackIgnored", func(t *testing.T) {
		baseSent := len(fakeMain.sentSnapshot())
		baseAnswers := len(fakeMain.answersSnapshot())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		type runResult struct {
			out tools.RunOutput
			err error
		}
		done := make(chan runResult, 1)
		go func() {
			out, err := runnerMain.Run(ctx, tools.RunInput{
				Alias:   "test",
				Command: "rm -f /tmp/test-write-4",
			})
			done <- runResult{out: out, err: err}
		}()

		requireEventually(t, 5*time.Second, func() bool {
			return len(fakeMain.sentSnapshot()) > baseSent
		}, "no sendMessage observed within 5s")
		sent := fakeMain.sentSnapshot()[baseSent]
		reqID := extractRequestID(sent.Text)
		if reqID == "" {
			t.Fatalf("missing Request ID")
		}

		// Wrong user attempts to approve.
		const wrongUserID = int64(99998)
		fakeMain.pushCallback(wrongUserID, "stranger", "approve:"+reqID, sent.MessageID, phase2ChatID)

		// The backend should answer with "not authorized" and the
		// pending request must remain unresolved. Wait briefly to
		// confirm the run-call did NOT return.
		requireEventually(t, 3*time.Second, func() bool {
			for _, a := range fakeMain.answersSnapshot()[baseAnswers:] {
				if strings.Contains(strings.ToLower(a.Text), "not authorized") {
					return true
				}
			}
			return false
		}, "no 'not authorized' callback answer observed")
		select {
		case res := <-done:
			t.Fatalf("Runner.Run returned %+v / err=%v after wrong-user callback; should still be pending",
				res.out, res.err)
		case <-time.After(300 * time.Millisecond):
			// good — still pending.
		}

		// Now inject the REAL approve callback.
		fakeMain.pushCallback(phase2AllowedUserID, "karthi", "approve:"+reqID, sent.MessageID, phase2ChatID)

		var res runResult
		select {
		case res = <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("Runner.Run did not return within 15s after authorised approve")
		}
		if res.err != nil {
			t.Fatalf("Runner.Run err=%v after authorised approve", res.err)
		}
		if res.out.ExitCode != 0 {
			t.Errorf("ExitCode=%d after authorised approve; want 0 (stderr=%q)",
				res.out.ExitCode, res.out.Stderr)
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		// Fresh signer + telegram pair with a 500ms request timeout.
		// Reusing the main stack would force every other scenario to
		// race the same short timeout — cleaner to spin a dedicated one.
		fakeTO := newFakeTG(t)
		socketTO, _, _, cleanupTO := startSignerTelegram(t, masterKey, fakeTO, 500*time.Millisecond)
		t.Cleanup(cleanupTO)
		runnerTO := buildRunner(t, socketTO, sshKeyPriv, "test-to", "127.0.0.1", sshContainerPort, remoteUser)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		type runResult struct {
			out tools.RunOutput
			err error
		}
		done := make(chan runResult, 1)
		start := time.Now()
		go func() {
			out, err := runnerTO.Run(ctx, tools.RunInput{
				Alias:   "test-to",
				Command: "rm -f /tmp/test-timeout",
			})
			done <- runResult{out: out, err: err}
		}()

		var res runResult
		select {
		case res = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Runner.Run did not return within 5s on a 500ms-timeout backend")
		}
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Errorf("timeout took %s; want under ~1s", elapsed)
		}
		if res.err == nil {
			t.Fatalf("Runner.Run returned nil err on timeout; want wrapped ErrTimeout. out=%+v", res.out)
		}
		if !errors.Is(res.err, signpkg.ErrTimeout) {
			t.Errorf("err does not wrap ErrTimeout: %v", res.err)
		}
	})

	t.Run("NoGoroutineLeaks", func(t *testing.T) {
		// Force the heavy lifetimes registered via t.Cleanup to run
		// BEFORE goleak inspects, by triggering them explicitly. The
		// parent test's t.Cleanup will re-invoke them via sync.Once
		// (idempotent).
		cleanupMain()
		containerCleanup()

		goleak.VerifyNone(t,
			// Same exclusions as Phase 1 — see comment there.
			goleak.IgnoreTopFunction("os/exec.(*Cmd).watchCtx"),
			goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
			// The bot library's HTTP client may park idle connections
			// briefly after the server closes. The httptest server's
			// Close() reaps them, but on heavily loaded test runners
			// the reap can lag a few ms past goleak's check.
			goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
			goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		)
	})
}
