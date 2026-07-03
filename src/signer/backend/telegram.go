package backend

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TelegramBackend implements Backend over a dedicated Telegram bot DM.
//
// The contract (spec §"signer-bot"): signer posts a message
// listing the queued commands plus Approve/Deny inline-keyboard buttons
// to the single allowed user's DM. Authentication is Telegram-side: we
// trust `from.id == AllowedUserID` on every callback because Telegram
// validates that field at the protocol level — Claude has no Telegram
// session and cannot impersonate the allowed user.
//
// Concurrency model:
//   - Run starts ONE goroutine that polls getUpdates and dispatches
//     callbacks to the pending map.
//   - Request is called by the daemon's per-connection goroutine and
//     registers a pending channel in the map; the polling goroutine (or
//     a per-request timer goroutine) resolves it.
//   - Each pending request is resolved exactly once — the first of
//     {approve, deny, timeout, ctx-cancel} wins.
type TelegramBackend struct {
	// Static config — set at construction, never mutated.
	allowedUserID int64
	chatStore     ChatStore
	logger        *log.Logger
	reqTimeout    time.Duration
	pollTimeout   int // seconds, passed to getUpdates

	// Explainer is optional. When non-nil, Request calls it for the
	// pending command list and renders one-line plain-English
	// explanations underneath each command in the approval message.
	// Approval is never blocked on Explainer availability — any error
	// (including ctx.DeadlineExceeded from ExplainerTimeout) results
	// in the commands being rendered alone with a small footer noting
	// the reason. Set at construction; the field is exported so callers
	// (cmd/signer/main) can wire it up post-NewTelegramBackend
	// without an options-struct churn.
	Explainer Explainer

	// ExplainerTimeout bounds the wall-clock window of the Explainer
	// call. Defaults to 5s if zero. Independent of reqTimeout.
	ExplainerTimeout time.Duration

	// RedactSalt + RedactRules scrub a secret embedded in the COMMAND STRING
	// before it is rendered into the approval/grant-approval MESSAGE text
	// posted to Telegram (F5, the 4th sink). ONLY the matched secret is
	// replaced by a per-session marker — the command SHAPE stays visible, so
	// the human still sees WHAT runs (and that a secret is present), just not
	// the literal secret, and the secret never reaches Telegram's servers.
	//
	// This is DISPLAY-ONLY: the command that flows through signing/execution
	// is the RAW request command, never the redacted display copy. The salt is
	// a per-process random 32 bytes and the ruleset is rules.Combined(), both
	// generated ONCE at startup and shared with the signer Daemon (cmd/main
	// wires the SAME salt + already-compiled slice — never compile per-message).
	// A zero salt + nil rules is a valid no-op: RedactString fast-paths nil
	// rules and renders the command verbatim, so a backend built without them
	// (any test/stub) still works.
	RedactSalt  [32]byte
	RedactRules []redact.Rule

	// Telegram client. Constructed in NewTelegramBackend (which calls
	// GetMe to fail fast on a bad token); shared by Run + Request.
	bot *tgbotapi.BotAPI

	// Run lifecycle. running is set on Run and cleared when the loop
	// returns; concurrent Run calls return an error.
	runMu       sync.Mutex
	running     bool
	runDone     chan struct{}
	panicsTotal atomic.Int64

	// Pending requests keyed by RequestID.
	pending sync.Map // map[string]*pendingState
}

// pendingState is the per-request bookkeeping. once guards the
// resolution channel so the first arbiter (approve / deny / timeout /
// ctx-cancel) wins.
//
// All fields are written exactly once, before pendingState is stored
// in TelegramBackend.pending. Subsequent reads happen after a
// successful sync.Map.Load (acts as the publish-fence) and inside
// ps.once.Do — both establish happens-before with the publish, so
// there's no need for a separate mutex protecting the fields.
type pendingState struct {
	ch        chan Result
	once      sync.Once
	chatID    int64  // DM chat where the request message was posted
	messageID int    // for editing the message on resolution
	stopTimer func() // tears down the timer + ctx-watcher goroutine
}

// TelegramOptions configures a TelegramBackend.
type TelegramOptions struct {
	// BotToken is the @BotFather-issued token. Required.
	BotToken string
	// AllowedUserID is the only Telegram user_id whose callbacks the
	// backend will honour. Required (a zero value is rejected).
	AllowedUserID int64
	// ChatStore persists the DM chat_id captured from /start. Required.
	ChatStore ChatStore
	// APIEndpoint overrides the default Telegram API base URL pattern
	// ("https://api.telegram.org/bot%s/%s"). Tests point this at an
	// httptest server. Leave empty for production.
	APIEndpoint string
	// Logger receives structured-ish event lines. Defaults to a logger
	// writing to os.Stderr with prefix "signer-bot: ".
	Logger *log.Logger
	// RequestTimeout is the per-request wait window — how long we wait
	// for the human Telegram tap before resolving as timed-out. Defaults
	// to sigwire.ApprovalWindow. Tests inject a short duration.
	RequestTimeout time.Duration
	// PollTimeoutSec is the getUpdates long-poll timeout in seconds.
	// Defaults to 30. Tests inject 0 so getUpdates returns
	// immediately; production uses 30 to keep the upstream request
	// rate low (daemon.md §11).
	PollTimeoutSec int
}

// APIEndpointForBase converts a user-facing Bot-API BASE url (e.g.
// "https://tg-proxy.example.com") into the tgbotapi endpoint PATTERN
// ("<base>/bot%s/%s") that TelegramOptions.APIEndpoint expects. An empty
// (or whitespace-only) base returns "" — the signal NewTelegramBackend
// reads as "use the default api.telegram.org", byte-for-byte today's
// behavior. This is the production hook for routing the approval bot
// through a maintainer-owned reverse proxy when api.telegram.org is
// IP-blocked (an existing reverse-proxy override pattern). The base is validated so a typo
// can never send the bot token — interpolated into the request path — to
// a non-TLS or malformed host. The proxy must preserve Telegram's path
// shape (<base>/bot<token>/<method> -> api.telegram.org/bot<token>/<method>).
func APIEndpointForBase(base string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", nil
	}
	if err := validateAPIBaseURL(base); err != nil {
		return "", err
	}
	return strings.TrimSuffix(base, "/") + "/bot%s/%s", nil
}

// validateAPIBaseURL rejects a base URL that could leak the bot token to a
// bad host: it must parse, carry a host, and be https:// — with the single
// exception of http:// for an explicit localhost host (a local reverse
// proxy). The error names only the base, never the token.
func validateAPIBaseURL(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid api_base_url %q: %w", base, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid api_base_url %q: missing host", base)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("refusing api_base_url %q: http:// is only allowed for a "+
			"localhost reverse proxy (the bot token must not transit a non-TLS remote host)", base)
	default:
		return fmt.Errorf("refusing api_base_url %q: scheme must be https:// (got %q)", base, u.Scheme)
	}
}

// botTokenRe matches the bot token as it appears embedded in a Telegram
// Bot-API request URL path: "bot<bot_id>:<secret>" (e.g.
// "bot123456789:AAF…"). The go-telegram-bot-api library puts the token in
// the URL PATH (<base>/bot<TOKEN>/<method>), and Go stdlib's
// *url.Error.Error() embeds the full URL — so any transport error that is
// logged or returned would otherwise leak the token verbatim.
var botTokenRe = regexp.MustCompile(`bot\d+:[A-Za-z0-9_-]+`)

// redactToken renders err.Error() with any embedded bot token replaced by
// "bot<REDACTED>". This is the single choke point every Telegram error
// that can reach a log line, a returned-error string, or the wire MUST
// pass through, so the @BotFather token can never escape to the systemd
// journal or the MCP/agent. Returns "<nil>" for a nil error so call sites
// stay one-liners.
func redactToken(err error) string {
	if err == nil {
		return "<nil>"
	}
	return botTokenRe.ReplaceAllString(err.Error(), "bot<REDACTED>")
}

// NewTelegramBackend builds a TelegramBackend, verifies the token via
// getMe (so a misconfigured production daemon fails on startup, not on
// the first approval request — daemon.md §11), and returns the
// instance. Call Run to start polling, then Request to enqueue work.
func NewTelegramBackend(opts TelegramOptions) (*TelegramBackend, error) {
	if opts.BotToken == "" {
		return nil, errors.New("telegram: BotToken is required")
	}
	if opts.AllowedUserID == 0 {
		return nil, errors.New("telegram: AllowedUserID is required")
	}
	if opts.ChatStore == nil {
		return nil, errors.New("telegram: ChatStore is required")
	}

	endpoint := opts.APIEndpoint
	if endpoint == "" {
		endpoint = tgbotapi.APIEndpoint
	}
	bot, err := tgbotapi.NewBotAPIWithAPIEndpoint(opts.BotToken, endpoint)
	if err != nil {
		// %s + redactToken (not %w): the underlying *url.Error embeds the
		// token in its URL path, and this error bubbles to main.go's fatal
		// startup log. No caller unwraps this error (verified: no
		// errors.Is/As on the getMe path in signer or mcp/sign), so
		// dropping the wrap chain costs nothing.
		return nil, fmt.Errorf("telegram getMe: %s", redactToken(err))
	}

	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "signer-bot: ", log.LstdFlags|log.Lmicroseconds)
	}
	reqTimeout := opts.RequestTimeout
	if reqTimeout == 0 {
		reqTimeout = sigwire.ApprovalWindow
	}
	poll := opts.PollTimeoutSec
	if poll == 0 && opts.PollTimeoutSec == 0 {
		// Production default — 30s long-poll matches the upstream's
		// own example and keeps QPS low. Tests that want immediate
		// returns pass a negative sentinel via the helper below; the
		// zero value here is intentionally the production default.
		poll = 30
	}

	t := &TelegramBackend{
		allowedUserID: opts.AllowedUserID,
		chatStore:     opts.ChatStore,
		logger:        logger,
		reqTimeout:    reqTimeout,
		pollTimeout:   poll,
		bot:           bot,
	}
	return t, nil
}

// Run starts the long-poll loop in a goroutine and returns once the
// loop is established. The loop terminates when ctx is cancelled (or
// when StopReceivingUpdates is invoked internally). Calling Run twice
// concurrently returns an error.
//
// The returned error is non-nil only for the "already running" case;
// transient Telegram errors during polling are logged and retried
// with exponential backoff (daemon.md §7, §11).
func (t *TelegramBackend) Run(ctx context.Context) error {
	t.runMu.Lock()
	if t.running {
		t.runMu.Unlock()
		return errors.New("telegram: Run already in progress")
	}
	t.running = true
	t.runDone = make(chan struct{})
	t.runMu.Unlock()

	go t.pollLoop(ctx)
	return nil
}

// pollLoop is the goroutine started by Run. It owns the lifetime of
// the polling loop and signals completion via runDone.
func (t *TelegramBackend) pollLoop(ctx context.Context) {
	defer close(t.runDone)
	defer func() {
		t.runMu.Lock()
		t.running = false
		t.runMu.Unlock()
	}()

	// Cancel-watcher: cancelling ctx must terminate the long-poll
	// even if Telegram is mid-response. StopReceivingUpdates closes
	// the shutdown channel inside the BotAPI; our GetUpdates loop is
	// hand-rolled (not GetUpdatesChan) so we also poll ctx ourselves.
	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			close(stopCh)
		case <-t.runDone:
			// pollLoop returned for another reason; nothing to do.
		}
	}()

	offset := 0
	backoff := 100 * time.Millisecond
	const backoffCap = 30 * time.Second

	for {
		select {
		case <-stopCh:
			t.logger.Printf("polling: ctx cancelled, exiting loop")
			return
		default:
		}

		updates, err := t.fetchUpdates(offset)
		if err != nil {
			// Distinguish ctx-cancel from a real upstream error.
			select {
			case <-stopCh:
				return
			default:
			}
			t.classifyAndLog(err)
			// Backoff with cap. We can't use a Ticker cleanly here
			// because the duration grows; sleep with a select so
			// shutdown wins.
			select {
			case <-stopCh:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > backoffCap {
				backoff = backoffCap
			}
			continue
		}
		// Success — reset backoff.
		backoff = 100 * time.Millisecond

		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			t.dispatch(u)
		}
	}
}

// fetchUpdates wraps bot.GetUpdates with a recover. A panic in the
// upstream library or our own dispatch must not kill the polling
// goroutine (daemon.md §7); we log + count it and continue.
func (t *TelegramBackend) fetchUpdates(offset int) (updates []tgbotapi.Update, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			t.panicsTotal.Add(1)
			t.logger.Printf("PANIC in fetchUpdates: %v\n%s", r, debug.Stack())
			retErr = fmt.Errorf("recovered panic: %v", r)
		}
	}()
	cfg := tgbotapi.NewUpdate(offset)
	cfg.Timeout = t.pollTimeout
	return t.bot.GetUpdates(cfg)
}

// dispatch routes a single Update. Wrapped in a recover so a poison
// update can't take down the polling loop.
func (t *TelegramBackend) dispatch(u tgbotapi.Update) {
	defer func() {
		if r := recover(); r != nil {
			t.panicsTotal.Add(1)
			t.logger.Printf("PANIC in dispatch: %v\n%s", r, debug.Stack())
		}
	}()

	switch {
	case u.CallbackQuery != nil:
		t.handleCallback(u.CallbackQuery)
	case u.Message != nil && u.Message.IsCommand() && u.Message.Command() == "start":
		t.handleStart(u.Message)
	}
}

// handleStart processes a /start message. Only the allowed user can
// link a chat; messages from anyone else get a polite refusal and we
// do NOT save their chat_id. This is the "single allowed peer" rule
// the spec emphasises.
func (t *TelegramBackend) handleStart(m *tgbotapi.Message) {
	if m.From == nil || m.From.ID != t.allowedUserID {
		// Mask the allowed user_id so a curious third party scanning
		// the bot's responses doesn't learn it verbatim — the bot
		// itself is the secret-bearing surface, not the chat partner.
		masked := maskUserID(t.allowedUserID)
		reply := tgbotapi.NewMessage(m.Chat.ID, fmt.Sprintf("this bot only serves %s — message ignored", masked))
		if _, err := t.bot.Send(reply); err != nil {
			t.logger.Printf("send refusal: %s", redactToken(err))
		}
		fromID := int64(0)
		if m.From != nil {
			fromID = m.From.ID
		}
		t.logger.Printf("/start from unauthorized user_id=%d ignored", fromID)
		return
	}

	if err := t.chatStore.Save(m.Chat.ID); err != nil {
		t.logger.Printf("chatstore save: %v", err)
		// Reply anyway so the operator sees something; the missing
		// peer.json will surface on the next approval request.
	}
	reply := tgbotapi.NewMessage(m.Chat.ID, "Linked — SSHGate approvals will now reach you here.")
	if _, err := t.bot.Send(reply); err != nil {
		t.logger.Printf("send link confirmation: %s", redactToken(err))
	}
	t.logger.Printf("/start: linked chat_id=%d for user_id=%d", m.Chat.ID, m.From.ID)
}

// handleCallback processes an Approve/Deny tap.
func (t *TelegramBackend) handleCallback(cb *tgbotapi.CallbackQuery) {
	if cb.From == nil || cb.From.ID != t.allowedUserID {
		// Wrong user — answer the callback to clear the spinner on
		// their client but DO NOT touch any pending request.
		ans := tgbotapi.NewCallbackWithAlert(cb.ID, "not authorized")
		if _, err := t.bot.Request(ans); err != nil {
			t.logger.Printf("answer unauthorized callback: %s", redactToken(err))
		}
		fromID := int64(0)
		if cb.From != nil {
			fromID = cb.From.ID
		}
		t.logger.Printf("callback from unauthorized user_id=%d ignored", fromID)
		return
	}

	action, reqID, ok := parseCallbackData(cb.Data)
	if !ok {
		ans := tgbotapi.NewCallback(cb.ID, "invalid request")
		if _, err := t.bot.Request(ans); err != nil {
			t.logger.Printf("answer invalid-data callback: %s", redactToken(err))
		}
		return
	}

	raw, ok := t.pending.Load(reqID)
	if !ok {
		ans := tgbotapi.NewCallback(cb.ID, "expired or already resolved")
		if _, err := t.bot.Request(ans); err != nil {
			t.logger.Printf("answer unknown-reqid callback: %s", redactToken(err))
		}
		return
	}
	ps := raw.(*pendingState)

	var status ResultStatus
	var verbPast string
	switch action {
	case "approve":
		status = StatusApproved
		verbPast = "Approved"
	case "deny":
		status = StatusDenied
		verbPast = "Denied"
	default:
		// parseCallbackData guarantees this; defensive.
		return
	}

	approver := callbackApprover(cb)
	t.resolve(reqID, ps, Result{Status: status, ApprovedBy: approver})

	// Answer the callback so the user's client clears its spinner.
	ans := tgbotapi.NewCallback(cb.ID, strings.ToLower(verbPast))
	if _, err := t.bot.Request(ans); err != nil {
		t.logger.Printf("answer callback: %s", redactToken(err))
	}

	// Edit the original message to remove buttons and record outcome.
	footer := fmt.Sprintf("\n\n%s %s by %s at %s", outcomeMark(status), verbPast, approver, time.Now().UTC().Format(time.RFC3339))
	origText := ""
	if cb.Message != nil {
		origText = cb.Message.Text
	}
	edit := tgbotapi.NewEditMessageText(ps.chatID, ps.messageID, origText+footer)
	if _, err := t.bot.Send(edit); err != nil {
		t.logger.Printf("edit message: %s", redactToken(err))
	}
}

// Request implements Backend. Caller must have called Run first;
// otherwise messages cannot be delivered (the polling goroutine
// resolves callbacks).
func (t *TelegramBackend) Request(ctx context.Context, req ApprovalRequest) (<-chan Result, error) {
	chatID, ok, err := t.chatStore.Load()
	if err != nil {
		return nil, fmt.Errorf("chatstore load: %w", err)
	}
	if !ok {
		return nil, errors.New("telegram: no DM chat captured yet — operator must /start the bot")
	}

	explanations, explainErr := t.runExplainer(ctx, req.Commands)
	text := formatApprovalMessage(req, t.reqTimeout, explanations, explainErr, t.RedactSalt, t.RedactRules)
	msg := tgbotapi.NewMessage(chatID, text)
	// The approve button label makes a SECRET-REVEAL unmistakable: a normal
	// write reads "✓ Approve all"; a reveal reads "✓ Approve SECRET-REVEAL" so
	// the operator cannot tap through on muscle memory. The callback data
	// ("approve:<reqID>") is identical either way — the gate-enforced
	// capability lives in the signed payload, not in the button.
	approveLabel := "✓ Approve all"
	switch {
	case requestHasReveal(req):
		approveLabel = "✓ Approve SECRET-REVEAL"
	case requestHasUpdate(req):
		approveLabel = "✓ Approve GATE UPDATE"
	}
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(approveLabel, "approve:"+req.RequestID),
			tgbotapi.NewInlineKeyboardButtonData("✗ Deny", "deny:"+req.RequestID),
		),
	)
	sent, err := t.bot.Send(msg)
	if err != nil {
		// %s + redactToken (not %w): a transport-level send failure is a
		// *url.Error embedding the token in its URL path, and this error
		// bubbles to the daemon's respondError -> journal + wire `error`
		// field. No caller unwraps it (verified: daemon.go stringifies via
		// %v, no errors.Is/As on this path), so the wrap chain is expendable.
		return nil, fmt.Errorf("telegram send: %s", redactToken(err))
	}

	ch := make(chan Result, 1)
	// done signals the timer + ctx-watcher to exit cleanly when the
	// request is resolved by approve/deny. Closing done is idempotent
	// because we guard the close with stopOnce.
	done := make(chan struct{})
	var stopOnce sync.Once
	stopTimer := func() {
		stopOnce.Do(func() { close(done) })
	}

	ps := &pendingState{
		ch:        ch,
		chatID:    chatID,
		messageID: sent.MessageID,
		stopTimer: stopTimer,
	}
	// Publish the entry BEFORE starting the timer/ctx-watcher goroutines
	// so any goroutine that observes a pending state via the map sees
	// fully initialised fields. (sync.Map.Store has the happens-before
	// edges we need.)
	t.pending.Store(req.RequestID, ps)

	// Timer + ctx watcher live in one goroutine: whichever event fires
	// first calls timeout(); the other branches are silent no-ops via
	// sync.Once on the resolution side.
	go func() {
		timer := time.NewTimer(t.reqTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			t.timeout(req.RequestID, ps)
		case <-ctx.Done():
			t.timeout(req.RequestID, ps)
		case <-done:
			// Approve/deny resolved first; exit cleanly.
		}
	}()
	return ch, nil
}

// RequestGrant implements Backend's standing-grant approval. It mirrors
// Request — same chatStore load, same t.pending registration keyed by
// RequestID, same approve:/deny: callback wiring, timer + ctx watcher,
// and resolve path (handleCallback/resolve are generic over RequestID, so
// a grant pending resolves through the identical code). The ONLY
// difference is the message body: formatGrantApprovalMessage renders a
// distinct, scary "STANDING GRANT" banner so the human cannot mistake it
// for a one-shot write — approving it auto-signs the scoped commands for
// the whole window without further taps.
func (t *TelegramBackend) RequestGrant(ctx context.Context, req GrantApprovalRequest) (<-chan Result, error) {
	chatID, ok, err := t.chatStore.Load()
	if err != nil {
		return nil, fmt.Errorf("chatstore load: %w", err)
	}
	if !ok {
		return nil, errors.New("telegram: no DM chat captured yet — operator must /start the bot")
	}

	text := formatGrantApprovalMessage(req, t.reqTimeout, t.RedactSalt, t.RedactRules)
	msg := tgbotapi.NewMessage(chatID, text)
	// A standing grant gets its own unmistakable approve label so the
	// operator cannot tap through on muscle memory. Callback data is the
	// same "approve:<reqID>" / "deny:<reqID>" — the grant semantics live
	// in the signer's in-memory table, not in the button.
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✓ Approve STANDING GRANT", "approve:"+req.RequestID),
			tgbotapi.NewInlineKeyboardButtonData("✗ Deny", "deny:"+req.RequestID),
		),
	)
	sent, err := t.bot.Send(msg)
	if err != nil {
		// %s + redactToken (not %w): a transport-level send failure is a
		// *url.Error embedding the token in its URL path, and this error
		// bubbles to the daemon's respondError -> journal + wire `error`
		// field. No caller unwraps it (verified: daemon.go stringifies via
		// %v, no errors.Is/As on this path), so the wrap chain is expendable.
		return nil, fmt.Errorf("telegram send: %s", redactToken(err))
	}

	ch := make(chan Result, 1)
	done := make(chan struct{})
	var stopOnce sync.Once
	stopTimer := func() {
		stopOnce.Do(func() { close(done) })
	}

	ps := &pendingState{
		ch:        ch,
		chatID:    chatID,
		messageID: sent.MessageID,
		stopTimer: stopTimer,
	}
	t.pending.Store(req.RequestID, ps)

	go func() {
		timer := time.NewTimer(t.reqTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			t.timeout(req.RequestID, ps)
		case <-ctx.Done():
			t.timeout(req.RequestID, ps)
		case <-done:
		}
	}()
	return ch, nil
}

// resolve sends r on ps.ch exactly once and tears down the watcher
// goroutine. Subsequent resolves are silent no-ops (handled by
// sync.Once).
func (t *TelegramBackend) resolve(reqID string, ps *pendingState, r Result) {
	ps.once.Do(func() {
		ps.ch <- r
		close(ps.ch)
		ps.stopTimer()
		t.pending.Delete(reqID)
	})
}

// timeout edits the message to reflect expiration and resolves with
// StatusTimeout. Idempotent via sync.Once — if approve/deny got there
// first, we don't edit the message (that path already did).
func (t *TelegramBackend) timeout(reqID string, ps *pendingState) {
	resolved := false
	ps.once.Do(func() {
		ps.ch <- Result{Status: StatusTimeout}
		close(ps.ch)
		ps.stopTimer()
		t.pending.Delete(reqID)
		resolved = true
	})
	if !resolved {
		return
	}
	// Edit the original to indicate expiry. Best-effort; if Telegram
	// rejects, the user just sees stale buttons that no longer work.
	edit := tgbotapi.NewEditMessageText(ps.chatID, ps.messageID, fmt.Sprintf("⏰ Expired (no response in %s)", t.reqTimeout))
	if _, err := t.bot.Send(edit); err != nil {
		t.logger.Printf("edit-on-timeout: %s", redactToken(err))
	}
}

// classifyAndLog distinguishes upstream 4xx vs 5xx for logs
// (daemon.md §11.4). The library's *Error carries Code; anything else
// (network, parse) we treat as transient.
func (t *TelegramBackend) classifyAndLog(err error) {
	var apiErr *tgbotapi.Error
	if errors.As(err, &apiErr) {
		class := "5xx"
		if apiErr.Code >= 400 && apiErr.Code < 500 {
			class = "4xx"
		}
		t.logger.Printf("getUpdates %s error code=%d msg=%q", class, apiErr.Code, apiErr.Message)
		return
	}
	t.logger.Printf("getUpdates transport error: %s", redactToken(err))
}

// PanicsTotal returns the number of recovered panics across the
// polling goroutine. Exposed for tests and future metrics wiring.
func (t *TelegramBackend) PanicsTotal() int64 {
	return t.panicsTotal.Load()
}

// parseCallbackData parses "approve:<reqID>" or "deny:<reqID>".
func parseCallbackData(data string) (action, reqID string, ok bool) {
	i := strings.IndexByte(data, ':')
	if i <= 0 {
		return "", "", false
	}
	action, reqID = data[:i], data[i+1:]
	if reqID == "" {
		return "", "", false
	}
	if action != "approve" && action != "deny" {
		return "", "", false
	}
	return action, reqID, true
}

// callbackApprover renders the approver identity for the audit log.
// Telegram usernames are optional, so fall back to "id:<from.id>" so
// the audit row is never blank.
func callbackApprover(cb *tgbotapi.CallbackQuery) string {
	if cb.From == nil {
		return ""
	}
	if cb.From.UserName != "" {
		return "@" + cb.From.UserName
	}
	return fmt.Sprintf("id:%d", cb.From.ID)
}

// outcomeMark returns the leading glyph used in the message-footer
// edit (visual quick-scan for the operator scrolling back through
// their bot history).
func outcomeMark(s ResultStatus) string {
	switch s {
	case StatusApproved:
		return "✓"
	case StatusDenied:
		return "✗"
	default:
		return "•"
	}
}

// runExplainer is a thin wrapper around t.Explainer.Explain that:
//   - returns (nil, nil) if no explainer is configured
//   - enforces ExplainerTimeout (default 5s)
//   - never panics — any panic in the Explainer is caught and logged so
//     a misbehaving model client cannot kill the request goroutine
//     (daemon.md §7).
//
// Returning a non-nil error tells the caller to fall back to the
// "commands only + footer" rendering. The error string is fed through
// sanitiseExplainerErr before rendering so we never leak credentials,
// upstream URLs, or stack-y wrappers to the operator's Telegram DM.
func (t *TelegramBackend) runExplainer(ctx context.Context, cmds []CommandReq) (lines []string, err error) {
	if t.Explainer == nil || len(cmds) == 0 {
		return nil, nil
	}
	defer func() {
		if r := recover(); r != nil {
			t.panicsTotal.Add(1)
			t.logger.Printf("PANIC in explainer: %v\n%s", r, debug.Stack())
			lines = nil
			err = fmt.Errorf("explainer panic")
		}
	}()

	timeout := t.ExplainerTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	flat := make([]string, len(cmds))
	for i, c := range cmds {
		flat[i] = c.Cmd
	}
	return t.Explainer.Explain(ectx, flat)
}

// sanitiseExplainerErr renders a short, credential-free reason string
// for the "no explanations" footer. We intentionally lose detail — the
// daemon log carries the full err for diagnostics; the Telegram DM
// only needs enough for the operator to know whether to bother retrying.
func sanitiseExplainerErr(err error) string {
	if err == nil {
		return "unknown"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	// Strip anything that looks like a URL or bearer token — defence
	// in depth in case a future Explainer leaks the endpoint or auth
	// header into its error string.
	msg := err.Error()
	for _, banned := range []string{"http://", "https://", "Bearer "} {
		if strings.Contains(msg, banned) {
			return "upstream error"
		}
	}
	if len(msg) > 80 {
		msg = msg[:80] + "…"
	}
	return msg
}

// redactForDisplay scrubs a secret embedded in a command STRING before it is
// rendered into the approval/grant message text (F5, 4th sink). It replaces
// ONLY the matched secret substring with a per-session marker, leaving the
// command structure visible. Fail-OPEN: on an internal redactor error it
// returns the RAW command (consistent with the three at-rest F5 sinks — a
// visible command is better than a dropped/garbled approval prompt). A nil
// ruleset fast-paths to the raw command via RedactString. This is purely the
// DISPLAY copy — the caller's request command is never mutated.
func redactForDisplay(cmd string, salt [32]byte, rules []redact.Rule) string {
	red, ok := redact.RedactString(cmd, salt, rules)
	if !ok {
		return cmd
	}
	return red
}

// formatApprovalMessage renders the message body per spec
// §"Approval message shape." We pick plain text (no Markdown/HTML
// parse-mode) because commands can contain '*', '_', '`', etc., that
// would otherwise need escaping — KISS over rich formatting.
//
// When explanations is non-nil and len matches Commands, each command
// is followed by an indented "→ <explanation>" line; empty entries
// render "→ (no explanation)". When explainErr is non-nil we fall
// back to commands-only and append a single "(no explanations: …)"
// footer line.
//
// Each command STRING is redacted secret-only (F5) before rendering: the
// matched secret is replaced by a per-session marker, the command shape stays
// visible. This is display-only — req.Commands is read, never mutated, so the
// raw command still flows through signing/execution.
// updateVerbPrefix marks a signed gate-binary update command
// (SSHGATE_UPDATE <sha256hex>). Kept in sync with the gate's dispatch prefix.
const updateVerbPrefix = "SSHGATE_UPDATE "

// requestHasUpdate reports whether any command in req is a signed gate-binary
// update. update_gate sends exactly one such command.
func requestHasUpdate(req ApprovalRequest) bool {
	for _, c := range req.Commands {
		if strings.HasPrefix(c.Cmd, updateVerbPrefix) {
			return true
		}
	}
	return false
}

// formatUpdateApprovalMessage renders the gate-binary update approval body. It
// is deliberately alarming: approving it REPLACES the security-critical gate
// binary on the target server, so the banner names that consequence, names the
// server, and renders the new binary's SHA-256 RAW — a hash is NOT a secret and
// the operator must see exactly the bytes the master key signed, so it is
// printed OUTSIDE redactForDisplay (Finding 7). Reason (when the MCP set one)
// carries the staged + running build revisions so a downgrade is spottable.
// Plain text (no parse-mode), like formatApprovalMessage.
func formatUpdateApprovalMessage(req ApprovalRequest, timeout time.Duration) string {
	var b strings.Builder
	// update_gate always sends exactly one command; guard anyway.
	if len(req.Commands) == 0 {
		return ""
	}
	c := req.Commands[0]
	server := c.Server

	b.WriteString("⚠️ GATE BINARY UPDATE — approving this REPLACES the SSHGate gate binary on ")
	if server != "" {
		b.WriteString(server)
	} else {
		b.WriteString("this server")
	}
	b.WriteString(". The new gate governs every future command on this server. Only approve an update you initiated.\n\n")

	b.WriteString("🔐 SSHGate GATE UPDATE")
	if server != "" {
		b.WriteString(" — ")
		b.WriteString(server)
	}
	b.WriteString("\n\n")

	// The committed hash. Validate its shape BEFORE rendering: a valid 64-lowercase-hex
	// digest renders RAW (never through redactForDisplay — R2/Finding-7 WYSIWYG),
	// but a crafted c.Cmd could smuggle newlines to inject fake banner lines
	// (phishing). The gate already rejects any non-64-hex update so it can never
	// install; the banner must likewise never render attacker-injected lines, so
	// anything malformed collapses to a single-line marker.
	hash := strings.TrimPrefix(c.Cmd, updateVerbPrefix)
	if isLower64Hex(hash) {
		fmt.Fprintf(&b, "New gate SHA-256: %s\n", hash)
	} else {
		b.WriteString("New gate SHA-256: <malformed hash — the gate will reject this update>\n")
	}
	if c.Reason != "" {
		fmt.Fprintf(&b, "Build: %s\n", c.Reason)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "Request ID: %s\n", req.RequestID)
	fmt.Fprintf(&b, "Expires in %s\n", timeout)
	return b.String()
}

// isLower64Hex reports whether s is EXACTLY 64 lowercase hex characters — the
// shape of a SHA-256 digest the MCP emits (hex.EncodeToString). The update
// banner renders a valid hash raw; anything else (wrong length, uppercase, or a
// smuggled newline meant to inject fake banner lines) is a malformed hash the
// gate will reject anyway, so the banner shows a marker instead of the raw bytes.
func isLower64Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func formatApprovalMessage(req ApprovalRequest, timeout time.Duration, explanations []string, explainErr error, salt [32]byte, rules []redact.Rule) string {
	// A gate-binary update gets its own alarming layout and, crucially, renders
	// the committed SHA-256 RAW (never through redactForDisplay) — see
	// formatUpdateApprovalMessage. Checked first: an update is never also a
	// reveal, so this cannot steal a reveal's banner.
	if requestHasUpdate(req) {
		return formatUpdateApprovalMessage(req, timeout)
	}

	var b strings.Builder
	server := ""
	if len(req.Commands) > 0 {
		server = req.Commands[0].Server
	}
	reveal := requestHasReveal(req)
	if reveal {
		// A SECRET-REVEAL gets a distinct, scary banner: the operator must
		// instantly recognise that approving this lets RAW secret values
		// escape redaction and reach the agent (and the AI provider, and this
		// chat). This is deliberately alarming — it is not a normal write.
		b.WriteString("⚠️ SECRET-REVEAL — output will NOT be redacted; raw secret values go to the agent, the AI provider, and this chat.\n\n")
	}
	if reveal {
		b.WriteString("🔓 SSHGate SECRET-REVEAL")
	} else {
		b.WriteString("🔐 SSHGate approval")
	}
	if server != "" {
		b.WriteString(" — ")
		b.WriteString(server)
	}
	b.WriteString("\n\n")
	if reveal {
		// Show the mandatory reason(s) right up top so the human knows WHY raw
		// secrets are being requested before reading the command.
		for _, c := range req.Commands {
			if c.Reveal && c.Reason != "" {
				fmt.Fprintf(&b, "Reason: %s\n", c.Reason)
			}
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%d command", len(req.Commands))
	if len(req.Commands) != 1 {
		b.WriteByte('s')
	}
	b.WriteString(" queued:\n")

	renderExplanations := explainErr == nil && len(explanations) == len(req.Commands)
	for i, c := range req.Commands {
		// Redact the secret in the DISPLAY copy only; c.Cmd (and thus the
		// signed/executed command) is untouched.
		fmt.Fprintf(&b, "%d. %s\n", i+1, redactForDisplay(c.Cmd, salt, rules))
		if renderExplanations {
			line := explanations[i]
			if line == "" {
				b.WriteString("   → (no explanation)\n")
			} else {
				fmt.Fprintf(&b, "   → %s\n", line)
			}
		}
	}
	b.WriteString("\n")
	if explainErr != nil {
		fmt.Fprintf(&b, "(no explanations: %s)\n", sanitiseExplainerErr(explainErr))
	}
	fmt.Fprintf(&b, "Request ID: %s\n", req.RequestID)
	fmt.Fprintf(&b, "Expires in %s\n", timeout)
	return b.String()
}

// formatGrantApprovalMessage renders the STANDING GRANT approval body.
// It is deliberately alarming and explicit: approving it lets the signer
// auto-sign the scoped commands for the WHOLE window with no further taps,
// which is a strictly bigger authorisation than a one-shot write — so the
// banner, scope, duration, and computed expiry are all spelled out. Plain
// text (no Markdown/HTML parse-mode) for the same reason as
// formatApprovalMessage: commands can contain '*', '_', '`'.
//
// Expiry is computed as time.Now()+Duration in UTC. It is display-only
// (the signer records the authoritative expiry off its own injected
// clock); a few-ms skew between this render and the stored expiry is
// irrelevant.
//
// Each scoped command STRING is redacted secret-only (F5) before rendering,
// exactly like formatApprovalMessage: the matched secret is replaced by a
// per-session marker, the command shape stays visible, and req.Commands is
// read but never mutated (the grant is stored from the RAW command list, not
// this display copy).
func formatGrantApprovalMessage(req GrantApprovalRequest, timeout time.Duration, salt [32]byte, rules []redact.Rule) string {
	var b strings.Builder
	b.WriteString("⚠️ STANDING GRANT — approving this auto-signs the commands below for the whole window WITHOUT further taps.\n\n")
	fmt.Fprintf(&b, "🟠 SSHGate STANDING GRANT — %s\n\n", req.Alias)
	switch req.Scope {
	case "all":
		fmt.Fprintf(&b, "Scope: ALL commands on %s\n", req.Alias)
	case "commands":
		b.WriteString("Scope: ONLY these exact commands:\n")
		for i, c := range req.Commands {
			// Redact the secret in the DISPLAY copy only; the grant is stored
			// from the RAW req.Commands, so the scoped command is untouched.
			fmt.Fprintf(&b, "%d. %s\n", i+1, redactForDisplay(c, salt, rules))
		}
	default:
		fmt.Fprintf(&b, "Scope: %s\n", req.Scope)
	}
	fmt.Fprintf(&b, "Duration: %s\n", req.Duration)
	expires := time.Now().Add(req.Duration).UTC().Format(time.RFC3339)
	fmt.Fprintf(&b, "Expires at: %s\n\n", expires)
	fmt.Fprintf(&b, "Request ID: %s\n", req.RequestID)
	fmt.Fprintf(&b, "Approval expires in %s\n", timeout)
	return b.String()
}

// requestHasReveal reports whether any command in the request is a
// SECRET-REVEAL. The MCP enforces single-command-only for reveals, so in
// practice a reveal request is exactly one command; this scans defensively so
// the scary UX is shown if reveal appears anywhere.
func requestHasReveal(req ApprovalRequest) bool {
	for _, c := range req.Commands {
		if c.Reveal {
			return true
		}
	}
	return false
}

// maskUserID renders an id like "1234567" as "12***67". The point is
// to make the bot's refusal message unambiguous to the operator (who knows
// his own user_id and recognises the partial) without leaking the
// full value to a curious third party who DMs the bot.
func maskUserID(id int64) string {
	s := fmt.Sprintf("%d", id)
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// Compile-time interface check.
var _ Backend = (*TelegramBackend)(nil)
