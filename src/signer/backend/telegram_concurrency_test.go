package backend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func orderingCallback(action string) *tgbotapi.CallbackQuery {
	return &tgbotapi.CallbackQuery{ID: action, From: &tgbotapi.User{ID: 1}, Data: action + ":ordering", Message: &tgbotapi.Message{MessageID: 2, Chat: &tgbotapi.Chat{ID: 3}}}
}

func awaitBarrier(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("barrier not reached")
	}
}

func TestTelegram_BufferedDecisionPrecedesContendingLiveCallback(t *testing.T) {
	for _, first := range []string{"approve", "deny"} {
		t.Run(first, func(t *testing.T) {
			tb := &TelegramBackend{allowedUserID: 1, logger: log.New(io.Discard, "", 0)}
			res, release, err := tb.reservePending("ordering")
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			res.ctx, res.expires, res.chatID = context.Background(), time.Now().Add(time.Minute), 3
			tb.handleCallback(orderingCallback(first))
			paused, resume, contending := make(chan struct{}), make(chan struct{}), make(chan struct{})
			resumeOnce := sync.OnceFunc(func() { close(resume) })
			defer resumeOnce()
			tb.beforeReplay = func() { close(paused); <-resume }
			tb.beforeCallbackLock = func() { close(contending) }
			ps := &pendingState{ch: make(chan signerkit.Result, 1), chatID: 3, messageID: 2, stopTimer: func() {}}
			published := make(chan error, 1)
			go func() { published <- tb.publishPending("ordering", res, ps) }()
			awaitBarrier(t, paused)
			opposite, want := "deny", signerkit.StatusApproved
			if first == "deny" {
				opposite, want = "approve", signerkit.StatusDenied
			}
			liveDone := make(chan struct{})
			go func() { tb.handleCallback(orderingCallback(opposite)); close(liveDone) }()
			awaitBarrier(t, contending)
			// Probe the critical section without a scheduling delay. If replay was moved
			// outside it, let the live tap finish before allowing replay to proceed.
			if tb.pendingMu.TryLock() {
				tb.pendingMu.Unlock()
				awaitBarrier(t, liveDone)
			}
			resumeOnce()
			if err := <-published; err != nil {
				t.Fatal(err)
			}
			awaitBarrier(t, liveDone)
			if got := <-ps.ch; got.Status != want {
				t.Fatalf("earlier %s lost: got %v, want %v", first, got.Status, want)
			}
			if _, open := <-ps.ch; open {
				t.Fatal("request resolved more than once")
			}
		})
	}
}

type notificationTransport struct {
	ctx       context.Context
	updates   chan string
	polling   chan struct{}
	answering chan struct{}
	release   chan struct{}
}

func (transport *notificationTransport) Do(req *http.Request) (*http.Response, error) {
	result := `true`
	switch {
	case strings.HasSuffix(req.URL.Path, "/getMe"):
		result = `{"id":1,"is_bot":true,"first_name":"test"}`
	case strings.HasSuffix(req.URL.Path, "/getUpdates"):
		select {
		case transport.polling <- struct{}{}:
		default:
		}
		select {
		case result = <-transport.updates:
		case <-transport.ctx.Done():
			result = `[]`
		}
	case strings.HasSuffix(req.URL.Path, "/answerCallbackQuery"):
		transport.answering <- struct{}{}
		<-transport.release
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":` + result + `}`)), Header: make(http.Header)}, nil
}

func TestTelegram_NotificationBurstBoundedWhileAcknowledgementsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &notificationTransport{ctx: ctx, updates: make(chan string, 1), polling: make(chan struct{}, 2), answering: make(chan struct{}, 4096), release: make(chan struct{})}
	var logs bytes.Buffer
	bot, err := tgbotapi.NewBotAPIWithClient("test", tgbotapi.APIEndpoint, transport)
	if err != nil {
		t.Fatal(err)
	}
	tb := &TelegramBackend{allowedUserID: 1, bot: bot, logger: log.New(&logs, "", 0)}
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(func() { cancel(); close(transport.release); awaitBarrier(t, tb.runDone) })
	defer stop()
	for i := 0; i < notificationWorkers; i++ {
		tb.handleCallback(orderingCallback("approve"))
	}
	for i := 0; i < notificationWorkers; i++ {
		awaitBarrier(t, transport.answering)
	}
	awaitBarrier(t, transport.polling)
	baseline := runtime.NumGoroutine()
	// Exercise the real poll/dispatch path with a stale backlog, then a live Deny.
	ps := &pendingState{ch: make(chan signerkit.Result, 1), chatID: 3, messageID: 2, ctx: ctx, expires: time.Now().Add(time.Minute), stopTimer: func() {}}
	tb.pending.Store("live", ps)
	const burst = 2000
	var updates strings.Builder
	updates.WriteByte('[')
	for i := 0; i < burst; i++ {
		if i > 0 {
			updates.WriteByte(',')
		}
		fmt.Fprintf(&updates, `{"update_id":%d,"callback_query":{"id":"stale","from":{"id":1},"data":"approve:unknown"}}`, i)
	}
	fmt.Fprintf(&updates, `,{"update_id":%d,"callback_query":{"id":"live","from":{"id":1},"data":"deny:live","message":{"message_id":2,"chat":{"id":3}}}}]`, burst)
	transport.updates <- updates.String()
	select {
	case result := <-ps.ch:
		if result.Status != signerkit.StatusDenied {
			t.Fatalf("result = %v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked acknowledgements stalled polling/decision")
	}
	// A subsequent poll proves every callback finished despite blocked I/O.
	awaitBarrier(t, transport.polling)
	tb.runMu.Lock()
	queue := tb.notifications
	tb.runMu.Unlock()
	if got := len(queue); got != notificationQueueSize {
		t.Fatalf("queued = %d", got)
	}
	if got := runtime.NumGoroutine() - baseline; got > 2 {
		t.Fatalf("burst added %d goroutines", got)
	}
	if got := tb.notificationsDropped.Load(); got != burst+1-notificationQueueSize {
		t.Fatalf("dropped = %d", got)
	}
	stop()
	if !strings.Contains(logs.String(), "telegram notification dropped: total=") {
		t.Fatal("missing counted drop log")
	}
}
