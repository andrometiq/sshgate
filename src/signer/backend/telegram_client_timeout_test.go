package backend

// In-package (white-box) test pinning the Telegram bot's HTTP-client
// timeout: the upstream library constructs &http.Client{} with NO
// timeout, so a black-holed connection could wedge the single poll
// goroutine inside an in-flight getUpdates Do() far beyond the
// 5-minute approval window (laptop sleep/resume, NAT/VPN flap). The
// backend must hand the library an explicit client whose timeout
// exceeds the long-poll hold. White-box because the bot field is
// unexported.

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewTelegramBackend_HTTPClientTimeout(t *testing.T) {
	t.Parallel()
	// Minimal fake Telegram API: every method (only getMe is hit at
	// construction) answers ok:true.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"t","username":"t_bot"}}`)
	}))
	// t.Cleanup, not defer: the parallel subtests outlive this
	// function body, and the server must outlive them.
	t.Cleanup(srv.Close)
	endpoint := srv.URL + "/bot%s/%s"

	cases := []struct {
		name    string
		pollSec int
		want    time.Duration
	}{
		// 30s production long-poll + 15s headroom.
		{"production default poll", 0, 45 * time.Second},
		// Explicit poll override still gets headroom above the hold.
		{"explicit 60s poll", 60, 75 * time.Second},
		// Test sentinel (immediate-return polls): floor stays bounded.
		{"negative sentinel poll", -1, 15 * time.Second},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			tb, err := NewTelegramBackend(TelegramOptions{
				BotToken:       "tok",
				AllowedUserID:  1,
				ChatStore:      &MemChatStore{},
				APIEndpoint:    endpoint,
				Logger:         log.New(io.Discard, "", 0),
				PollTimeoutSec: c.pollSec,
			})
			if err != nil {
				t.Fatalf("NewTelegramBackend: %v", err)
			}
			hc, ok := tb.bot.Client.(*http.Client)
			if !ok {
				t.Fatalf("bot client is %T, want *http.Client", tb.bot.Client)
			}
			if hc.Timeout != c.want {
				t.Fatalf("bot HTTP client timeout = %v, want %v (must stay above the long-poll hold, and must never be zero)", hc.Timeout, c.want)
			}
		})
	}
}
