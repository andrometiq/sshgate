//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// The restart matrix drives a tagged signer subprocess (file store, Telegram
// notifier) against an in-test Bot API. Crashes are SIGKILL or faultpoint
// exits; stops are SIGTERM.

type botCall struct {
	method string
	form   url.Values
	id     int // message_id the fake assigned to a sendMessage
}

type botReply int

const (
	replyOK    botReply = iota
	replyReset          // connection reset; the call did not apply
	replyHang           // applied; the response is never sent
	reply429            // retry_after=30
)

// fakeBot is a Bot API that keeps every update, so a restart at offset 0
// redelivers all of them, as when the previous process never confirmed them.
type fakeBot struct {
	server    *httptest.Server
	mu        sync.Mutex
	calls     []botCall
	updates   []string
	nextID    int
	live      bool
	explainer int
	intercept func(context.Context, botCall) botReply
}

func newFakeBot(t *testing.T) *fakeBot {
	b := &fakeBot{nextID: 1000}
	b.server = httptest.NewServer(b)
	t.Cleanup(b.server.Close)
	return b
}

func (b *fakeBot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/explain") {
		b.mu.Lock()
		b.explainer++
		b.mu.Unlock()
		// The server notices the client's close only after the body is read.
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done() // the provider never answers; assist times out
		return
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	method := path.Base(r.URL.Path)
	switch method {
	case "getMe":
		fmt.Fprint(w, `{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Test","username":"test_bot"}}`)
		return
	case "getUpdates":
		b.getUpdates(w, r)
		return
	}
	b.mu.Lock()
	call := botCall{method: method, form: r.Form}
	if method == "sendMessage" {
		b.nextID++
		call.id = b.nextID
	} else {
		call.id, _ = strconv.Atoi(r.Form.Get("message_id"))
	}
	b.calls = append(b.calls, call)
	intercept := b.intercept
	b.mu.Unlock()
	reply := replyOK
	if intercept != nil {
		reply = intercept(r.Context(), call)
	}
	switch reply {
	case replyReset:
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			conn.Close()
		}
	case replyHang:
		<-r.Context().Done()
	case reply429:
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}`)
	default:
		if method == "answerCallbackQuery" {
			fmt.Fprint(w, `{"ok":true,"result":true}`)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"date":1,"chat":{"id":42,"type":"private"}}}`, call.id)
	}
}

func (b *fakeBot) getUpdates(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.Form.Get("offset"))
	wait := time.Duration(0)
	if timeout := r.Form.Get("timeout"); timeout != "" && timeout != "0" {
		b.mu.Lock()
		b.live = true
		b.mu.Unlock()
		wait = 300 * time.Millisecond // short polls keep shutdown prompt
	}
	deadline := time.Now().Add(wait)
	for {
		b.mu.Lock()
		var batch []string
		for i := max(offset-1, 0); i < len(b.updates) && len(batch) < 100; i++ {
			batch = append(batch, b.updates[i])
		}
		b.mu.Unlock()
		if len(batch) != 0 || !time.Now().Before(deadline) || r.Context().Err() != nil {
			fmt.Fprintf(w, `{"ok":true,"result":[%s]}`, strings.Join(batch, ","))
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (b *fakeBot) setIntercept(fn func(context.Context, botCall) botReply) {
	b.mu.Lock()
	b.intercept = fn
	b.mu.Unlock()
}

func (b *fakeBot) push(body string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updates = append(b.updates, fmt.Sprintf(`{"update_id":%d,%s}`, len(b.updates)+1, body))
}

func (b *fakeBot) command(text string) {
	length := len(strings.Fields(text)[0])
	b.push(fmt.Sprintf(`"message":{"message_id":%d,"date":1,"from":{"id":42,"first_name":"Operator"},"chat":{"id":42,"type":"private"},"text":%q,"entities":[{"type":"bot_command","offset":0,"length":%d}]}`, time.Now().UnixNano()%1000000, text, length))
}

// tap queues a callback and returns its query ID.
func (b *fakeBot) tap(data string, messageID int) string {
	b.mu.Lock()
	id := fmt.Sprintf("tap-%d", len(b.updates)+1)
	b.mu.Unlock()
	b.push(fmt.Sprintf(`"callback_query":{"id":%q,"from":{"id":42,"first_name":"Operator"},"message":{"message_id":%d,"date":1,"chat":{"id":42,"type":"private"}},"data":%q}`, id, messageID, data))
	return id
}

func (b *fakeBot) snapshot() []botCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]botCall(nil), b.calls...)
}

func (b *fakeBot) explainerCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.explainer
}

// answers returns every answerCallbackQuery text for a query ID.
func (b *fakeBot) answers(queryID string) []string {
	var texts []string
	for _, call := range b.snapshot() {
		if call.method == "answerCallbackQuery" && call.form.Get("callback_query_id") == queryID {
			texts = append(texts, call.form.Get("text"))
		}
	}
	return texts
}

func (b *fakeBot) isLive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.live
}

// callbacks returns the v: callback data a card or card edit carries.
func callbacks(call botCall) []string {
	var keyboard struct {
		Rows [][]struct {
			Data string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if json.Unmarshal([]byte(call.form.Get("reply_markup")), &keyboard) != nil {
		return nil
	}
	var data []string
	for _, row := range keyboard.Rows {
		for _, button := range row {
			if strings.HasPrefix(button.Data, "v:") {
				data = append(data, button.Data)
			}
		}
	}
	return data
}

func button(t *testing.T, call botCall, prefix string) string {
	t.Helper()
	for _, data := range callbacks(call) {
		if strings.HasPrefix(data, prefix) {
			return data
		}
	}
	t.Fatalf("no %s button on %s %v", prefix, call.method, call.form)
	return ""
}

func isCard(call botCall) bool { return call.method == "sendMessage" && len(callbacks(call)) != 0 }
func isPart(call botCall) bool {
	return call.method == "sendMessage" && !isCard(call) && strings.HasPrefix(call.form.Get("text"), "🔐 SSHGate approval review")
}
func isCardEdit(call botCall) bool {
	return call.method == "editMessageText" && len(callbacks(call)) != 0
}
func isIncomplete(call botCall) bool {
	return call.method == "editMessageText" && strings.Contains(call.form.Get("text"), "INCOMPLETE")
}

// forRecord keeps the review parts, cards and edits of one request; edits are
// matched by message ID against the request's sends.
func forRecord(calls []botCall, requestID string) []botCall {
	ids := map[int]bool{}
	var out []botCall
	for _, call := range calls {
		switch {
		case call.method == "sendMessage" && strings.Contains(call.form.Get("text"), "Request: "+requestID+" "):
			ids[call.id] = true
			out = append(out, call)
		case call.method == "editMessageText" && ids[call.id]:
			out = append(out, call)
		}
	}
	return out
}

func count(calls []botCall, match func(botCall) bool) int {
	n := 0
	for _, call := range calls {
		if match(call) {
			n++
		}
	}
	return n
}

func eventually(t *testing.T, limit time.Duration, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type matrix struct {
	t                           *testing.T
	bot                         *fakeBot
	configPath, socket, journal string
	proc                        *signerProcess
	principal                   string
}

type matrixOptions struct{ explainer bool }

func newMatrix(t *testing.T, options matrixOptions) *matrix {
	t.Helper()
	_, cfg := initSignerTree(t)
	// Unix socket paths are short; t.TempDir may not be.
	dir, err := os.MkdirTemp("/tmp", "b2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := &matrix{t: t, bot: newFakeBot(t), configPath: filepath.Join(dir, "config.toml"), socket: filepath.Join(dir, "sock"), journal: cfg.Approvals.JournalRoot, principal: fmt.Sprintf("local-uid:%d", os.Geteuid())}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("123:test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	chat := filepath.Join(dir, "chat.json")
	if err := (&backend.FileChatStore{Path: chat}).Save(42); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("[paths]\nkey = %q\npubkey = %q\naudit_log = %q\nsocket = %q\npolicy_journal = %q\n\n[approvals]\njournal_root = %q\n\n[backend]\ntype = \"telegram\"\n\n[backend.telegram]\ntoken_path = %q\nallowed_user_id = 42\nchatstore_path = %q\n",
		cfg.Paths.Key, cfg.Paths.PubKey, cfg.Paths.AuditLog, m.socket, cfg.Paths.PolicyJournal, cfg.Approvals.JournalRoot, token, chat)
	if options.explainer {
		key := filepath.Join(dir, "explainer-key")
		if err := os.WriteFile(key, []byte("test-key"), 0o600); err != nil {
			t.Fatal(err)
		}
		body += fmt.Sprintf("\n[backend.telegram.explainer]\nenabled = true\nendpoint = %q\nmodel = \"test-model\"\napi_key_path = %q\ntimeout_sec = 2\n", m.bot.server.URL+"/explain", key)
	}
	if err := os.WriteFile(m.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

// start launches a signer that dies with the test process.
func (m *matrix) start(env ...string) {
	m.t.Helper()
	m.bot.mu.Lock()
	m.bot.live = false
	m.bot.mu.Unlock()
	cmd := exec.Command(buildSigner(m.t), "--config", m.configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	m.proc = startSignerCommand(m.t, cmd, append([]string{"SSHGATE_TELEGRAM_API_URL=" + m.bot.server.URL}, env...)...)
}

// ready waits for the socket and for the poller's first live fetch, after
// the redelivery drain.
func (m *matrix) ready() {
	m.t.Helper()
	waitForSocket(m.t, m.proc, m.socket)
	eventually(m.t, 20*time.Second, "the poller", func() bool {
		if !m.proc.isRunning() {
			m.t.Fatalf("signer exited; stderr:\n%s", m.proc.stderr.String())
		}
		return m.bot.isLive()
	})
}

func (m *matrix) restart(env ...string) {
	m.t.Helper()
	m.start(env...)
	m.ready()
}

func (m *matrix) kill() {
	m.t.Helper()
	if err := m.proc.cmd.Process.Kill(); err != nil {
		m.t.Fatal(err)
	}
	m.proc.exitCode(m.t)
}

// crashed waits for a faultpoint exit.
func (m *matrix) crashed() {
	m.t.Helper()
	if code := m.proc.exitCode(m.t); code != 86 {
		m.t.Fatalf("exit %d, want the faultpoint exit 86; stderr:\n%s", code, m.proc.stderr.String())
	}
}

func (m *matrix) submit(n int) string {
	m.t.Helper()
	return m.submitCommands(n, "systemctl restart nginx")
}

// submitCommands submits the canonical write fixture with one step per command.
func (m *matrix) submitCommands(n int, commands ...string) string {
	m.t.Helper()
	request := m.fixture("request-submit-write.json", n)
	template := request.Draft.CommandJob.Steps[0]
	request.Draft.CommandJob.Steps = nil
	for i, command := range commands {
		step := template
		sum := sha256.Sum256([]byte(command))
		step.Ordinal, step.ExactCommand, step.CommandSHA256 = i+1, command, hex.EncodeToString(sum[:])
		request.Draft.CommandJob.Steps = append(request.Draft.CommandJob.Steps, step)
	}
	return m.send(request)
}

func (m *matrix) submitGrant(n int) string {
	m.t.Helper()
	return m.send(m.fixture("request-submit-grant.json", n))
}

func (m *matrix) fixture(name string, n int) aw.SubmitRequest {
	m.t.Helper()
	data, err := os.ReadFile("../../../approvalwire/testdata/local/" + name)
	if err != nil {
		m.t.Fatal(err)
	}
	decoded, err := aw.DecodeLocalRequest(bytes.TrimSpace(data))
	if err != nil {
		m.t.Fatal(err)
	}
	request := decoded.(aw.SubmitRequest)
	request.Draft.RequestID = st.ID(n)
	request.Draft.SubmitNotAfter = time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	return request
}

func (m *matrix) encode(request aw.SubmitRequest) []byte {
	m.t.Helper()
	data, err := aw.MarshalLocalRequest(request)
	if err != nil {
		m.t.Fatal(err)
	}
	return bytes.TrimSpace(data)
}

func (m *matrix) send(request aw.SubmitRequest) string {
	m.t.Helper()
	if response := approvalCall(m.t, m.socket, m.encode(request)); !strings.Contains(response, `"ok":true`) {
		m.t.Fatalf("submit %s: %s", request.Draft.RequestID, response)
	}
	return request.Draft.RequestID
}

func (m *matrix) get(id string) ap.Summary {
	m.t.Helper()
	response := approvalCall(m.t, m.socket, []byte(`{"approval_proto":1,"kind":"approval_get_v2","request_id":"`+id+`"}`))
	var decoded struct {
		OK      bool       `json:"ok"`
		Summary ap.Summary `json:"summary"`
	}
	if err := json.Unmarshal([]byte(response), &decoded); err != nil || !decoded.OK {
		m.t.Fatalf("get %s: %v %s", id, err, response)
	}
	return decoded.Summary
}

func (m *matrix) key(id string) string { return ap.RecordKey(m.principal, id) }

func (m *matrix) handle(id string) string { return ap.RecordHandle(m.key(id)) }

// raw returns the record file's committed bytes.
func (m *matrix) raw(id string) []byte {
	m.t.Helper()
	data, err := os.ReadFile(filepath.Join(m.journal, m.key(id)))
	if err != nil {
		m.t.Fatal(err)
	}
	return data
}

func (m *matrix) record(id string) ap.R1 {
	m.t.Helper()
	var rec ap.R1
	if err := json.Unmarshal(m.raw(id), &rec); err != nil {
		m.t.Fatal(err)
	}
	return rec
}

func (m *matrix) waitRecord(id, what string, ready func(ap.R1) bool) ap.R1 {
	m.t.Helper()
	var rec ap.R1
	eventually(m.t, 20*time.Second, what, func() bool {
		data, err := os.ReadFile(filepath.Join(m.journal, m.key(id)))
		if err != nil || json.Unmarshal(data, &rec) != nil {
			return false
		}
		return ready(rec)
	})
	return rec
}

// settled waits until the record file stops changing.
func (m *matrix) settled(id string) []byte {
	m.t.Helper()
	previous := m.raw(id)
	for stable := 0; stable < 10; {
		time.Sleep(50 * time.Millisecond)
		if current := m.raw(id); bytes.Equal(current, previous) {
			stable++
		} else {
			previous, stable = current, 0
		}
	}
	return previous
}

// delivered waits until the record's latest card entry is delivered and
// returns that card's send and, when it was edited, the edit.
func (m *matrix) delivered(id string) (botCall, botCall) {
	m.t.Helper()
	m.waitRecord(id, "a delivered card", func(r ap.R1) bool {
		if r.Payload == nil || len(r.Payload.CardEntries) == 0 {
			return false
		}
		last := r.Payload.CardEntries[len(r.Payload.CardEntries)-1]
		return !last.Retired && last.MsgID != nil && (last.Outcome == ap.OutcomeSent || last.Confirmed)
	})
	m.settled(id)
	var card, edit botCall
	for _, call := range forRecord(m.bot.snapshot(), id) {
		switch {
		case isCard(call):
			card, edit = call, botCall{}
		case isCardEdit(call) && call.id == card.id:
			edit = call
		}
	}
	if card.id == 0 {
		m.t.Fatal("no card sent")
	}
	return card, edit
}

// quiet asserts that no record notification is sent for a while.
func (m *matrix) quiet(id string, d time.Duration) {
	m.t.Helper()
	before := len(forRecord(m.bot.snapshot(), id))
	time.Sleep(d)
	if after := forRecord(m.bot.snapshot(), id); len(after) != before {
		m.t.Fatalf("unexpected sends: %+v", after[before:])
	}
}

func (m *matrix) answered(queryID string) string {
	m.t.Helper()
	var texts []string
	eventually(m.t, 10*time.Second, "callback answer "+queryID, func() bool {
		texts = m.bot.answers(queryID)
		return len(texts) != 0
	})
	return texts[0]
}

func (m *matrix) reply(text string) {
	m.t.Helper()
	eventually(m.t, 10*time.Second, "reply "+text, func() bool {
		for _, call := range m.bot.snapshot() {
			if call.method == "sendMessage" && call.form.Get("text") == text {
				return true
			}
		}
		return false
	})
}

// hold intercepts the first call that matches: it is reported on the
// returned channel and then answered with reply once release is closed (or
// at once when release is nil).
func (m *matrix) hold(match func(botCall) bool, reply botReply, release <-chan struct{}) <-chan botCall {
	held := make(chan botCall, 1)
	var once sync.Once
	m.bot.setIntercept(func(ctx context.Context, call botCall) botReply {
		first := false
		if match(call) {
			once.Do(func() { first = true })
		}
		if !first {
			return replyOK
		}
		held <- call
		if release != nil {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return reply
	})
	return held
}

func receive(t *testing.T, held <-chan botCall) botCall {
	t.Helper()
	select {
	case call := <-held:
		return call
	case <-time.After(20 * time.Second):
		t.Fatal("the chosen call never arrived")
		return botCall{}
	}
}
