package backend_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// fakeTelegram mimics the Telegram Bot API endpoints used by
// TelegramBackend: getMe, getUpdates, sendMessage, editMessageText,
// editMessageReplyMarkup, answerCallbackQuery. Tests push updates
// into pendingUpdates; getUpdates drains them one batch at a time.
type fakeTelegram struct {
	t *testing.T

	server *httptest.Server

	mu               sync.Mutex
	pendingUpdates   []fakeUpdate
	nextUpdateID     int
	sentMessages     []sentMessage
	editedMessages   []editedMessage
	callbackAnswers  []callbackAnswer
	getUpdatesCalled atomic.Int64
	nextMessageID    int
	getMeAlwaysFail  bool

	// sendMessageFailCode, when non-zero, makes respondSendMessage
	// return a Telegram API error envelope ({"ok":false,...}) carrying
	// this error_code instead of a success body. Used to exercise the
	// "telegram send" failure path in Request. The library inspects the
	// JSON `ok` field (not the HTTP status), so we encode the failure in
	// the body.
	sendMessageFailCode int

	// getUpdatesFailCodes is a FIFO queue of API error_codes that
	// respondGetUpdates returns (as {"ok":false,...}) before falling back
	// to normal long-poll behaviour. Each call to getUpdates consumes one
	// entry. Lets a test script a 4xx → 5xx → success recovery sequence.
	getUpdatesFailCodes []int
}

type fakeUpdate struct {
	UpdateID      int             `json:"update_id"`
	Message       json.RawMessage `json:"message,omitempty"`
	CallbackQuery json.RawMessage `json:"callback_query,omitempty"`
}

type sentMessage struct {
	ChatID      int64
	Text        string
	ReplyMarkup string
}

type editedMessage struct {
	ChatID    int64
	MessageID int
	Text      string
}

type callbackAnswer struct {
	CallbackID string
	Text       string
}

func newFakeTelegram(t *testing.T) *fakeTelegram {
	t.Helper()
	f := &fakeTelegram{t: t, nextMessageID: 1000}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.route)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// URLPattern returns the value to pass as TelegramOptions.APIEndpoint:
// "<base>/bot%s/%s" so the library substitutes token + method.
func (f *fakeTelegram) URLPattern() string {
	return f.server.URL + "/bot%s/%s"
}

func (f *fakeTelegram) route(w http.ResponseWriter, r *http.Request) {
	// path looks like /bot<token>/<method>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "bot") {
		http.NotFound(w, r)
		return
	}
	method := parts[1]
	_ = r.ParseForm()

	switch method {
	case "getMe":
		f.respondGetMe(w)
	case "getUpdates":
		f.respondGetUpdates(w, r)
	case "sendMessage":
		f.respondSendMessage(w, r)
	case "editMessageText", "editMessageReplyMarkup":
		f.respondEditMessage(w, r, method)
	case "answerCallbackQuery":
		f.respondAnswerCallback(w, r)
	default:
		// Unknown method — return a benign empty success so the bot
		// library doesn't crash on undefined methods we don't care
		// about.
		writeAPIResult(w, json.RawMessage(`{}`))
	}
}

func (f *fakeTelegram) respondGetMe(w http.ResponseWriter) {
	f.mu.Lock()
	fail := f.getMeAlwaysFail
	f.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
		return
	}
	body := json.RawMessage(`{"id":7777,"is_bot":true,"first_name":"signer-bot","username":"signer_bot"}`)
	writeAPIResult(w, body)
}

func (f *fakeTelegram) respondGetUpdates(w http.ResponseWriter, r *http.Request) {
	f.getUpdatesCalled.Add(1)

	// Scripted failure sequence: pop one error_code per call and return
	// an API error envelope. The library turns {"ok":false,...} into a
	// *tgbotapi.Error carrying Code; classifyAndLog buckets it 4xx/5xx.
	f.mu.Lock()
	if len(f.getUpdatesFailCodes) > 0 {
		code := f.getUpdatesFailCodes[0]
		f.getUpdatesFailCodes = f.getUpdatesFailCodes[1:]
		f.mu.Unlock()
		writeAPIError(w, code, "scripted getUpdates failure")
		return
	}
	f.mu.Unlock()

	timeoutSec, _ := strconv.Atoi(r.FormValue("timeout"))
	offset, _ := strconv.Atoi(r.FormValue("offset"))

	// Block-with-timeout semantics: if no pending updates, wait up to
	// timeoutSec seconds (capped at 1s to keep tests snappy) for any
	// to arrive. We cap regardless of the caller-supplied value
	// because the test path uses long-poll = 0 anyway.
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	if timeoutSec > 1 {
		deadline = time.Now().Add(time.Second)
	}
	for {
		f.mu.Lock()
		var out []fakeUpdate
		var keep []fakeUpdate
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
			writeAPIResult(w, b)
			return
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			writeAPIResult(w, json.RawMessage(`[]`))
			return
		}
		// Cheap poll. Tests inject updates from another goroutine.
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fakeTelegram) respondSendMessage(w http.ResponseWriter, r *http.Request) {
	chatID, _ := strconv.ParseInt(r.FormValue("chat_id"), 10, 64)
	text := r.FormValue("text")
	rm := r.FormValue("reply_markup")
	f.mu.Lock()
	failCode := f.sendMessageFailCode
	f.mu.Unlock()
	if failCode != 0 {
		// Record nothing as "sent" — the upstream rejected the send.
		writeAPIError(w, failCode, "scripted sendMessage failure")
		return
	}
	f.mu.Lock()
	mid := f.nextMessageID
	f.nextMessageID++
	f.sentMessages = append(f.sentMessages, sentMessage{ChatID: chatID, Text: text, ReplyMarkup: rm})
	f.mu.Unlock()
	body := fmt.Sprintf(`{"message_id":%d,"chat":{"id":%d,"type":"private"},"date":%d,"text":%q}`, mid, chatID, time.Now().Unix(), text)
	writeAPIResult(w, json.RawMessage(body))
}

func (f *fakeTelegram) respondEditMessage(w http.ResponseWriter, r *http.Request, method string) {
	chatID, _ := strconv.ParseInt(r.FormValue("chat_id"), 10, 64)
	mid, _ := strconv.Atoi(r.FormValue("message_id"))
	text := r.FormValue("text")
	f.mu.Lock()
	f.editedMessages = append(f.editedMessages, editedMessage{ChatID: chatID, MessageID: mid, Text: text})
	f.mu.Unlock()
	body := fmt.Sprintf(`{"message_id":%d,"chat":{"id":%d,"type":"private"},"date":%d,"text":%q}`, mid, chatID, time.Now().Unix(), text)
	writeAPIResult(w, json.RawMessage(body))
	_ = method
}

func (f *fakeTelegram) respondAnswerCallback(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("callback_query_id")
	text := r.FormValue("text")
	f.mu.Lock()
	f.callbackAnswers = append(f.callbackAnswers, callbackAnswer{CallbackID: id, Text: text})
	f.mu.Unlock()
	writeAPIResult(w, json.RawMessage(`true`))
}

func writeAPIResult(w http.ResponseWriter, result json.RawMessage) {
	body, _ := json.Marshal(struct {
		Ok     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}{Ok: true, Result: result})
	_, _ = w.Write(body)
}

// writeAPIError writes a Telegram API failure envelope. The bot library
// decodes the JSON and (because ok=false) returns a *tgbotapi.Error
// carrying error_code regardless of the HTTP status, so callers see a
// classified upstream error. We set the HTTP status too for realism.
func writeAPIError(w http.ResponseWriter, code int, desc string) {
	if code >= 100 && code <= 599 {
		w.WriteHeader(code)
	}
	body, _ := json.Marshal(struct {
		Ok          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}{Ok: false, ErrorCode: code, Description: desc})
	_, _ = w.Write(body)
}

// pushMessage injects a /start (or other text) message update.
func (f *fakeTelegram) pushMessage(fromID, chatID int64, text string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextUpdateID++
	uid := f.nextUpdateID
	entitySuffix := ""
	if strings.HasPrefix(text, "/") {
		// Mark "/start" so IsCommand() returns true. Telegram requires
		// a "bot_command" entity covering the leading slash+verb.
		end := strings.IndexByte(text, ' ')
		if end < 0 {
			end = len(text)
		}
		entitySuffix = fmt.Sprintf(`,"entities":[{"type":"bot_command","offset":0,"length":%d}]`, end)
	}
	msg := fmt.Sprintf(`{"message_id":%d,"from":{"id":%d,"is_bot":false,"first_name":"u","username":"karthi"},"chat":{"id":%d,"type":"private","first_name":"u"},"date":%d,"text":%q%s}`,
		uid, fromID, chatID, time.Now().Unix(), text, entitySuffix)
	f.pendingUpdates = append(f.pendingUpdates, fakeUpdate{UpdateID: uid, Message: json.RawMessage(msg)})
	return uid
}

// pushCallback injects a callback_query update for an inline button tap.
func (f *fakeTelegram) pushCallback(fromID int64, username, data string, messageID int, chatID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextUpdateID++
	uid := f.nextUpdateID
	cbID := fmt.Sprintf("cb%d", uid)
	cb := fmt.Sprintf(`{"id":%q,"from":{"id":%d,"is_bot":false,"first_name":"u","username":%q},"chat_instance":"ci","data":%q,"message":{"message_id":%d,"chat":{"id":%d,"type":"private"},"date":%d,"text":"prev"}}`,
		cbID, fromID, username, data, messageID, chatID, time.Now().Unix())
	f.pendingUpdates = append(f.pendingUpdates, fakeUpdate{UpdateID: uid, CallbackQuery: json.RawMessage(cb)})
}

// pushRawMessage injects a message update with a caller-supplied raw
// JSON `message` object. Used for poison-update tests that need a
// /start command with nil Chat / nil From (which the structured
// pushMessage helper can't express because it always fills both).
func (f *fakeTelegram) pushRawMessage(messageJSON string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextUpdateID++
	uid := f.nextUpdateID
	f.pendingUpdates = append(f.pendingUpdates, fakeUpdate{UpdateID: uid, Message: json.RawMessage(messageJSON)})
	return uid
}

// snapshot helpers — lock + copy so callers don't race the server goroutine.

func (f *fakeTelegram) sentSnapshot() []sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]sentMessage, len(f.sentMessages))
	copy(out, f.sentMessages)
	return out
}

func (f *fakeTelegram) editsSnapshot() []editedMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]editedMessage, len(f.editedMessages))
	copy(out, f.editedMessages)
	return out
}

func (f *fakeTelegram) callbackAnswersSnapshot() []callbackAnswer {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]callbackAnswer, len(f.callbackAnswers))
	copy(out, f.callbackAnswers)
	return out
}

// --- helpers for the actual tests ---------------------------------------

// Test constants — synthetic values chosen so the codebase is publish-safe.
// AllowedUserID in production is operator-configured via signer config.
const allowedUserID = int64(77777777)
const allowedChatID = int64(99999999)

func newTestBackend(t *testing.T, fake *fakeTelegram, store backend.ChatStore, reqTimeout time.Duration) *backend.TelegramBackend {
	t.Helper()
	if store == nil {
		store = &backend.MemChatStore{}
	}
	tb, err := backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken:       "tok",
		AllowedUserID:  allowedUserID,
		ChatStore:      store,
		APIEndpoint:    fake.URLPattern(),
		Logger:         log.New(io.Discard, "", 0),
		RequestTimeout: reqTimeout,
		PollTimeoutSec: 0,
	})
	if err != nil {
		t.Fatalf("NewTelegramBackend: %v", err)
	}
	return tb
}

// stubExplainer is an in-memory Explainer for telegram_test scenarios.
// Returning err != nil makes the backend take the "no explanations"
// fallback path; returning lines exercises the rendering path.
type stubExplainer struct {
	lines []string
	err   error
	delay time.Duration
}

func (s *stubExplainer) Explain(ctx context.Context, cmds []string) ([]string, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	// Pad / truncate to len(cmds) the same way OpenAICompatibleExplainer
	// does — the backend renders one line per command.
	out := make([]string, len(cmds))
	for i := range cmds {
		if i < len(s.lines) {
			out[i] = s.lines[i]
		}
	}
	return out, nil
}

// waitFor polls fn until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitFor: condition not met within %s", timeout)
}

// --- tests --------------------------------------------------------------

func TestNewTelegramBackend_RequiresFields(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	cases := []struct {
		name string
		opts backend.TelegramOptions
	}{
		{"missing token", backend.TelegramOptions{AllowedUserID: 1, ChatStore: &backend.MemChatStore{}, APIEndpoint: fake.URLPattern()}},
		{"missing user", backend.TelegramOptions{BotToken: "t", ChatStore: &backend.MemChatStore{}, APIEndpoint: fake.URLPattern()}},
		{"missing chatstore", backend.TelegramOptions{BotToken: "t", AllowedUserID: 1, APIEndpoint: fake.URLPattern()}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := backend.NewTelegramBackend(c.opts); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

func TestNewTelegramBackend_GetMeFailureSurfaces(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	fake.mu.Lock()
	fake.getMeAlwaysFail = true
	fake.mu.Unlock()
	_, err := backend.NewTelegramBackend(backend.TelegramOptions{
		BotToken: "t", AllowedUserID: 1, ChatStore: &backend.MemChatStore{}, APIEndpoint: fake.URLPattern(),
	})
	if err == nil {
		t.Fatal("expected getMe failure to surface")
	}
}

func TestTelegram_ApprovePath(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedChatID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	ch, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_approve",
		Commands: []signerkit.CommandReq{
			{Server: "prod-db", Cmd: "systemctl restart nginx", TTLSec: 60},
		},
		Submitted: time.Now(),
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	// One message should have been sent.
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	sent := fake.sentSnapshot()[0]
	if sent.ChatID != allowedChatID {
		t.Errorf("ChatID = %d; want %d", sent.ChatID, allowedChatID)
	}
	if !strings.Contains(sent.Text, "systemctl restart nginx") {
		t.Errorf("message missing command: %q", sent.Text)
	}
	if !strings.Contains(sent.ReplyMarkup, "approve:r_approve") {
		t.Errorf("reply markup missing approve button: %q", sent.ReplyMarkup)
	}

	// Inject an Approve callback from the allowed user.
	fake.pushCallback(allowedUserID, "karthi", "approve:r_approve", 1000, allowedChatID)

	var got signerkit.Result
	select {
	case got = <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no Result delivered within 2s")
	}
	if got.Status != signerkit.StatusApproved {
		t.Errorf("Status = %v; want Approved", got.Status)
	}
	if got.ApprovedBy != "@karthi" {
		t.Errorf("ApprovedBy = %q; want @karthi", got.ApprovedBy)
	}
	// Telegram is a local-signing backend: it must leave Signatures nil
	// so the daemon falls back to d.Key for the cryptographic step.
	if got.Signatures != nil {
		t.Errorf("Signatures = %v; want nil (Telegram is approval-only, daemon signs locally)", got.Signatures)
	}

	// Callback should have been answered.
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) == 1 })

	// Message should have been edited with an approval footer.
	waitFor(t, time.Second, func() bool { return len(fake.editsSnapshot()) >= 1 })
	edits := fake.editsSnapshot()
	if !strings.Contains(edits[0].Text, "Approved") {
		t.Errorf("edit text missing 'Approved': %q", edits[0].Text)
	}
}

func TestTelegram_DenyPath(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	ch, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_deny",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "rm -rf /tmp", TTLSec: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	fake.pushCallback(allowedUserID, "karthi", "deny:r_deny", 1000, allowedChatID)

	select {
	case got := <-ch:
		if got.Status != signerkit.StatusDenied {
			t.Errorf("Status = %v; want Denied", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Result")
	}
}

func TestTelegram_WrongUserCallbackIgnored(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	ch, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_wrong",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo hi", TTLSec: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })

	// Callback from a different user with an Approve payload — must NOT
	// resolve the pending request.
	fake.pushCallback(int64(123), "stranger", "approve:r_wrong", 1000, allowedChatID)

	// We expect Timeout (after the configured 200ms RequestTimeout),
	// not Approved.
	select {
	case got := <-ch:
		if got.Status != signerkit.StatusTimeout {
			t.Errorf("Status = %v; want Timeout (unauthorized callback should be ignored)", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Result within 2s")
	}

	// The unauthorized callback should still be answered (to clear the
	// stranger's client spinner), with "not authorized" text.
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 1 })
	answers := fake.callbackAnswersSnapshot()
	foundUnauth := false
	for _, a := range answers {
		if strings.Contains(strings.ToLower(a.Text), "not authorized") {
			foundUnauth = true
			break
		}
	}
	if !foundUnauth {
		t.Errorf("callback answers did not include 'not authorized': %v", answers)
	}
}

func TestTelegram_UnknownRequestIDCallback(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	// No Request has been made — push a callback referencing a phantom
	// request_id. The backend must answer it (clear the spinner) and
	// not panic.
	fake.pushCallback(allowedUserID, "karthi", "approve:ghost", 1000, allowedChatID)

	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 1 })
	answers := fake.callbackAnswersSnapshot()
	if !strings.Contains(strings.ToLower(answers[0].Text), "expired") {
		t.Errorf("callback answer = %q; want 'expired...'", answers[0].Text)
	}
	if tb.PanicsTotal() != 0 {
		t.Errorf("PanicsTotal = %d; want 0", tb.PanicsTotal())
	}
}

func TestTelegram_StartFromAllowedUserCapturesChatID(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	fake.pushMessage(allowedUserID, allowedChatID, "/start")

	waitFor(t, time.Second, func() bool {
		_, ok, _ := store.Load()
		return ok
	})
	id, ok, _ := store.Load()
	if !ok || id != allowedChatID {
		t.Errorf("Load() = (%d, %v); want (%d, true)", id, ok, allowedChatID)
	}

	// And a confirmation reply went out.
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) >= 1 })
	sent := fake.sentSnapshot()
	if !strings.Contains(strings.ToLower(sent[0].Text), "linked") {
		t.Errorf("confirmation text = %q; want 'Linked...'", sent[0].Text)
	}
}

func TestTelegram_StartFromWrongUserDoesNotCapture(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	fake.pushMessage(int64(123), int64(456), "/start")

	// Wait for the refusal message to fly out before asserting "store
	// is empty" — otherwise we race the polling goroutine.
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) >= 1 })
	if _, ok, _ := store.Load(); ok {
		t.Error("store captured a chat_id from an unauthorized user")
	}
}

func TestTelegram_TimeoutDeliversTimeoutResult(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	ch, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_timeout",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo hi", TTLSec: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-ch:
		if got.Status != signerkit.StatusTimeout {
			t.Errorf("Status = %v; want Timeout", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Result within 2s")
	}

	// The expiry edit should have happened (best-effort; allow up to 1s).
	waitFor(t, time.Second, func() bool {
		for _, e := range fake.editsSnapshot() {
			if strings.Contains(e.Text, "Expired") {
				return true
			}
		}
		return false
	})
}

func TestTelegram_CtxCancelDeliversTimeoutEarly(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 10*time.Second) // long timeout

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	if err := tb.Run(runCtx); err != nil {
		t.Fatal(err)
	}

	reqCtx, reqCancel := context.WithCancel(context.Background())
	ch, err := tb.Request(reqCtx, signerkit.ApprovalRequest{
		RequestID: "r_ctx",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo", TTLSec: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	reqCancel()

	select {
	case got := <-ch:
		if got.Status != signerkit.StatusTimeout {
			t.Errorf("Status = %v; want Timeout (ctx cancel)", got.Status)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("ctx-cancel took %s; should be near-immediate", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Result within 2s after ctx cancel")
	}
}

func TestTelegram_RequestRequiresChatID(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{} // empty
	tb := newTestBackend(t, fake, store, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_x",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo", TTLSec: 60}},
	})
	if err == nil {
		t.Fatal("Request returned nil err with empty chatstore; want error")
	}
}

func TestTelegram_ExplainerHappyPath(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)
	tb.Explainer = &stubExplainer{
		lines: []string{
			"restart the nginx web server",
			"install certbot via apt",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_expl",
		Commands: []signerkit.CommandReq{
			{Server: "prod", Cmd: "systemctl restart nginx", TTLSec: 60},
			{Server: "prod", Cmd: "apt install -y certbot", TTLSec: 60},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text

	// Commands present.
	for _, want := range []string{"systemctl restart nginx", "apt install -y certbot"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing command %q\n---\n%s", want, body)
		}
	}
	// Explanations rendered with the arrow prefix beneath each command.
	for _, want := range []string{
		"restart the nginx web server",
		"install certbot via apt",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing explanation %q\n---\n%s", want, body)
		}
	}
	if strings.Contains(body, "no explanations") {
		t.Errorf("body unexpectedly contains 'no explanations' footer:\n%s", body)
	}
}

func TestTelegram_ExplainerEmptyEntryRendersFallbackText(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)
	tb.Explainer = &stubExplainer{
		lines: []string{"first explained", ""}, // second is empty
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_partial",
		Commands: []signerkit.CommandReq{
			{Server: "x", Cmd: "echo first", TTLSec: 60},
			{Server: "x", Cmd: "echo second", TTLSec: 60},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text
	if !strings.Contains(body, "first explained") {
		t.Errorf("body missing 'first explained':\n%s", body)
	}
	if !strings.Contains(body, "(no explanation)") {
		t.Errorf("body missing '(no explanation)' fallback for empty entry:\n%s", body)
	}
}

func TestTelegram_ExplainerErrorFallsBackToFooter(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)
	tb.Explainer = &stubExplainer{err: errors.New("upstream-down")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_err",
		Commands: []signerkit.CommandReq{
			{Server: "x", Cmd: "echo hi", TTLSec: 60},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text

	if !strings.Contains(body, "echo hi") {
		t.Errorf("body missing command after explainer error:\n%s", body)
	}
	if !strings.Contains(body, "no explanations") {
		t.Errorf("body missing 'no explanations' footer after explainer error:\n%s", body)
	}
}

func TestTelegram_ExplainerTimeoutFallsBackToFooter(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)
	tb.Explainer = &stubExplainer{delay: 500 * time.Millisecond}
	tb.ExplainerTimeout = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_to",
		Commands: []signerkit.CommandReq{
			{Server: "x", Cmd: "echo timeout-case", TTLSec: 60},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Request blocked %s on explainer; expected ≤ ExplainerTimeout + slack", elapsed)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text
	if !strings.Contains(body, "echo timeout-case") {
		t.Errorf("body missing command after explainer timeout:\n%s", body)
	}
	if !strings.Contains(body, "no explanations") {
		t.Errorf("body missing 'no explanations' footer after explainer timeout:\n%s", body)
	}
}

func TestTelegram_RunTwiceRejected(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newTestBackend(t, fake, &backend.MemChatStore{}, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tb.Run(ctx); err == nil {
		t.Fatal("second Run returned nil; want error")
	}
}
