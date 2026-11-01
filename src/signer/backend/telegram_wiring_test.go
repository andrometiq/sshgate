package backend

import (
	"bytes"
	"context"
	"errors"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
)

func TestStartStrangerCoalescesWithAndWithoutLifecycle(t *testing.T) {
	for _, attached := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			f := newCallbackFixture(t)
			if !attached {
				original := f.backend.approvalCallbacks
				defer func() { f.backend.approvalCallbacks = original }()
				f.backend.approvalCallbacks = nil
			}
			var logs bytes.Buffer
			f.backend.logger = log.New(&logs, "", 0)
			audit := &commandAudit{}
			f.backend.CommandAudit = audit
			for i := 0; i < 1000; i++ {
				u := commandUpdate(i, "/start private-argument")
				u.Message.From.ID = 99
				u.Message.Chat.ID = 99
				f.backend.dispatch(u)
			}
			if len(f.api.snapshot()) != 0 || len(audit.events) != 0 || logs.Len() != 0 {
				t.Fatal("stranger flood produced immediate output")
			}
			if id, _, _ := f.backend.chatStore.Load(); id != 42 {
				t.Fatal("stranger replaced link")
			}
			time.Sleep(time.Minute)
			f.clock.Advance(time.Minute)
			f.backend.flushCommandRefusals()
			if len(audit.events) != 1 || audit.events[0].Approval.Transition != "command_refused{count=1000,wrong_user=1000,not_private=0}" {
				t.Fatalf("audit: %+v", audit.events)
			}
			if strings.Contains(logs.String(), "private-argument") || len(f.api.snapshot()) != 0 {
				t.Fatal("refusal leaked input or sent a reply")
			}
			f.backend.dispatch(commandUpdate(1001, "/start"))
			if len(f.api.snapshot()) != 1 || !strings.Contains(f.api.snapshot()[0].form.Get("text"), "Linked") {
				t.Fatal("allowed linking changed")
			}
		})
	}
}

func TestCommandRefusalCountersSaturate(t *testing.T) {
	f := newCallbackFixture(t)
	audit := &commandAudit{}
	f.backend.CommandAudit = audit
	f.backend.commandRefusals = commandRefusalState{wrongUser: math.MaxUint64, notPrivate: 1, strangerDeadline: time.Minute}
	f.clock.Advance(time.Second)
	f.backend.countCommandRefusal("wrong_user")
	if f.backend.commandRefusals.wrongUser != math.MaxUint64 || f.backend.commandRefusals.strangerDeadline != time.Minute {
		t.Fatal("wrong-user count overflowed or deadline reset")
	}
	f.backend.commandRefusals.notPrivate = math.MaxUint64
	f.backend.countCommandRefusal("not_private")
	if f.backend.commandRefusals.notPrivate != math.MaxUint64 {
		t.Fatal("not-private count overflowed")
	}
	f.clock.Advance(time.Minute)
	f.backend.flushCommandRefusals()
	want := "command_refused{count=18446744073709551615,wrong_user=18446744073709551615,not_private=18446744073709551615}"
	if len(audit.events) != 1 || audit.events[0].Approval.Transition != want {
		t.Fatalf("audit: %+v", audit.events)
	}
	if f.backend.commandRefusals.wrongUser != 0 || f.backend.commandRefusals.notPrivate != 0 {
		t.Fatal("counts not drained")
	}
}

func TestLinkedLegacyNotifierRequiresCurrentLink(t *testing.T) {
	fixed, api, artifact := legacyNotifierFixture(t)
	n, err := NewLinkedTelegramLegacyNotifier(fixed.backend)
	if err != nil {
		t.Fatal(err)
	}
	if n.Destination().ChatID != 0 || n.Prepare(artifact) == nil {
		t.Fatal("unlinked notifier accepted delivery")
	}
	if err := fixed.backend.chatStore.Save(-42); err != nil {
		t.Fatal(err)
	}
	data := artifact.Data()
	data.Context.Destination = lc.LegacyDestination{ChatID: -42}
	artifact, err = lc.NewPreparedLegacyApproval(data)
	if err != nil {
		t.Fatal(err)
	}
	if n.Destination() != data.Context.Destination {
		t.Fatal("linked destination not loaded")
	}
	if err = n.Prepare(artifact); err != nil {
		t.Fatal(err)
	}
	if _, err = n.Deliver(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	for _, call := range api.snapshot() {
		if call.form.Get("chat_id") != "-42" {
			t.Fatalf("wrong destination: %+v", call)
		}
	}
	n.Release(artifact.Data().Instance)
	fixed.backend.chatStore.Save(42)
	if n.Destination().ChatID != 42 || n.Prepare(artifact) == nil {
		t.Fatal("stale destination accepted")
	}
}

// This constructor test installs an in-process Bot API transport before any
// parallel tests start; no listener or external connection is needed.
type wiringBotTransport struct{ api *legacyBotAPI }

func (t wiringBotTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t.api.Do(r) }

func TestTelegramConstructorWarnsForNonPrivateLink(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	for _, chat := range []int64{0, 42, -42, 99} {
		t.Run(strconv.FormatInt(chat, 10), func(t *testing.T) {
			api := &legacyBotAPI{}
			http.DefaultTransport = wiringBotTransport{api}
			store := &MemChatStore{}
			if chat != 0 {
				store.Save(chat)
			}
			var logs bytes.Buffer
			backend, err := NewTelegramBackend(TelegramOptions{BotToken: approvalTestToken, AllowedUserID: 42, ChatStore: store, APIEndpoint: "http://bot.invalid/bot%s/%s", Logger: log.New(&logs, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			api.reset()
			wantWarning := chat != 0 && chat != 42
			if strings.Contains(logs.String(), "WARN:") != wantWarning || (wantWarning && !strings.Contains(logs.String(), "v2 notifications refused")) {
				t.Fatalf("warning: %q", logs.String())
			}
			if wantWarning && !strings.Contains(logs.String(), "send /start again in the allowed user's private DM") {
				t.Fatalf("warning lacks recovery guidance: %q", logs.String())
			}
			err = backend.Burst(context.Background(), func(b lc.BurstSession) error {
				_, err := b.SendCard(context.Background(), notificationFixture(t, 1))
				return err
			})
			if chat == 42 {
				if err != nil || len(api.snapshot()) != 1 {
					t.Fatalf("linked DM delivery: %v, %+v", err, api.snapshot())
				}
			} else if err == nil || len(api.snapshot()) != 0 {
				t.Fatalf("notification escaped linked DM: %v, %+v", err, api.snapshot())
			}
		})
	}
}

type failedLinkedChatStore struct{}

func (failedLinkedChatStore) Load() (int64, bool, error) {
	return -42, true, errors.New("link unavailable")
}
func (failedLinkedChatStore) Save(int64) error { return errors.New("link unavailable") }

func TestLinkedLegacyNotifierFailsClosedOnUnreadableLink(t *testing.T) {
	if _, err := NewLinkedTelegramLegacyNotifier(nil); err == nil {
		t.Fatal("nil backend accepted")
	}
	fixed, _, artifact := legacyNotifierFixture(t)
	fixed.backend.chatStore = failedLinkedChatStore{}
	n, err := NewLinkedTelegramLegacyNotifier(fixed.backend)
	if err != nil {
		t.Fatal(err)
	}
	if n.Destination().ChatID != 0 || n.Prepare(artifact) == nil {
		t.Fatal("unreadable link accepted")
	}
}

func TestStartMalformedUpdatePreservesRecovery(t *testing.T) {
	for _, shape := range []string{"missing-both", "missing-chat-allowed", "missing-chat-stranger"} {
		t.Run(shape, func(t *testing.T) {
			f := newCallbackFixture(t)
			u := commandUpdate(1, "/start")
			u.Message.Chat = nil
			if shape == "missing-both" {
				u.Message.From = nil
			}
			if shape == "missing-chat-stranger" {
				u.Message.From.ID = 99
			}
			before := f.backend.PanicsTotal()
			f.backend.dispatch(u)
			if f.backend.PanicsTotal() != before+1 {
				t.Fatal("malformed start did not reach dispatch recovery")
			}
			if len(f.api.snapshot()) != 0 || f.backend.commandRefusals.wrongUser != 0 {
				t.Fatal("malformed start was sent or coalesced")
			}
			f.backend.dispatch(commandUpdate(2, "/start"))
			calls := f.api.snapshot()
			if len(calls) != 1 || !strings.Contains(calls[0].form.Get("text"), "Linked") {
				t.Fatal("linking did not survive malformed update")
			}
		})
	}
}
