package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

type commandAudit struct {
	events []signerkit.AuditEvent
	fail   bool
}

func (a *commandAudit) Write(e signerkit.AuditEvent) error {
	a.events = append(a.events, e)
	if a.fail {
		return errors.New("audit unavailable")
	}
	return nil
}
func commandUpdate(id int, text string) tgbotapi.Update {
	return tgbotapi.Update{UpdateID: id, Message: &tgbotapi.Message{From: &tgbotapi.User{ID: 42}, Chat: &tgbotapi.Chat{ID: 42, Type: "private"}, Text: text, Entities: []tgbotapi.MessageEntity{{Type: "bot_command", Offset: 0, Length: len(strings.Fields(text)[0])}}}}
}
func TestApprovalCommandGate(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*TelegramBackend, *tgbotapi.Message)
	}{
		{"unknown", "unknown_command", func(_ *TelegramBackend, _ *tgbotapi.Message) {}},
		{"wrong user", "wrong_user", func(_ *TelegramBackend, m *tgbotapi.Message) { m.From.ID = 99 }},
		{"missing user", "wrong_user", func(_ *TelegramBackend, m *tgbotapi.Message) { m.From = nil }},
		{"group", "not_private", func(_ *TelegramBackend, m *tgbotapi.Message) { m.Chat.Type = "group" }},
		{"wrong chat", "not_private", func(_ *TelegramBackend, m *tgbotapi.Message) { m.Chat.ID = 99 }},
		{"missing chat", "not_private", func(_ *TelegramBackend, m *tgbotapi.Message) { m.Chat = nil }},
		{"forward user", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardFrom = &tgbotapi.User{ID: 99} }},
		{"forward chat", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardFromChat = &tgbotapi.Chat{ID: 99} }},
		{"forward message", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardFromMessageID = 1 }},
		{"forward signature", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardSignature = "private" }},
		{"forward name", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardSenderName = "private" }},
		{"forward date", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardDate = 1 }},
		{"automatic forward", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.IsAutomaticForward = true }},
		{"drained", "redelivered", func(b *TelegramBackend, _ *tgbotapi.Message) { b.commandDrain = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newCallbackFixture(t)
			a := &commandAudit{}
			f.backend.CommandAudit = a
			if tt.reason != "unknown_command" {
				f.backend.approvalCommands = map[string]func(*tgbotapi.Message){"cancel": func(*tgbotapi.Message) {
					t.Fatal("refused command reached its handler")
				}}
			}
			u := commandUpdate(100, "/cancel secret-argument")
			tt.change(f.backend, u.Message)
			before := time.Now()
			f.backend.dispatch(u)
			if tt.reason == "wrong_user" || tt.reason == "not_private" {
				if len(a.events) != 0 || len(f.backend.notifications) != 0 || len(f.api.snapshot()) != 0 {
					t.Fatal("unauthenticated refusal produced output")
				}
				return
			}
			if len(a.events) != 1 {
				t.Fatalf("audit events: %v", a.events)
			}
			e := a.events[0]
			transition := "command_refused{" + tt.reason + "}"
			if e.Status != "approval-"+transition || e.Approval == nil || e.Approval.Transition != transition || e.Approval.Replay != (tt.reason == "redelivered") || e.TS.Before(before) || e.TS.After(time.Now()) {
				t.Fatalf("event: %+v", e)
			}
			encoded, _ := json.Marshal(e)
			if strings.Contains(string(encoded), "secret-argument") || e.RequestID != "" || len(e.Commands) != 0 || len(e.Servers) != 0 {
				t.Fatalf("audit leaked input: %s", encoded)
			}
			select {
			case notify := <-f.backend.notifications:
				notify()
			default:
				t.Fatal("no refusal reply")
			}
			calls := f.api.snapshot()
			if len(calls) != 1 || calls[0].form.Get("chat_id") != "42" || calls[0].form.Get("text") != "command refused: "+tt.reason {
				t.Fatalf("reply: %+v", calls)
			}
		})
	}
}
func TestApprovalCommandReplyAndLegacy(t *testing.T) {
	for _, linked := range []int64{42, -42, 0} {
		t.Run(strconv.FormatInt(linked, 10), func(t *testing.T) {
			f := newCallbackFixture(t)
			a := &commandAudit{fail: true}
			f.backend.CommandAudit = a
			f.backend.chatStore.Save(linked)
			f.backend.dispatch(commandUpdate(1, "/deny_all"))
			if len(a.events) != 1 {
				t.Fatal("missing failed audit attempt")
			}
			if (len(f.backend.notifications) == 1) != (linked == 42) {
				t.Fatal("reply escaped linked DM")
			}
		})
	}
	f := newCallbackFixture(t)
	a := &commandAudit{}
	f.backend.CommandAudit = a
	f.backend.commandDrain = true
	f.backend.dispatch(commandUpdate(1, "/start"))
	if len(a.events) != 0 || len(f.api.snapshot()) != 1 {
		t.Fatal("start changed")
	}
	f.backend.approvalCallbacks = nil
	f.api.reset()
	f.backend.dispatch(commandUpdate(2, "/pending"))
	if len(a.events) != 0 || len(f.api.snapshot()) != 0 || len(f.backend.notifications) != 0 {
		t.Fatal("legacy command handling changed")
	}
}
func TestApprovalCommandStartupDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		a := &commandAudit{}
		f.backend.CommandAudit = a
		f.backend.pollTimeout = 30
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.backend.runDone = make(chan struct{})
		defer close(f.backend.runDone)
		batch := 0
		f.api.hook = func(r *http.Request, _ int) (string, error) {
			if !strings.HasSuffix(r.URL.Path, "getUpdates") {
				t.Fatal("unexpected API call")
			}
			batch++
			wantTimeout := "0"
			if batch == 4 {
				wantTimeout = "30"
			}
			if r.Form.Get("timeout") != wantTimeout && !(wantTimeout == "0" && r.Form.Get("timeout") == "") {
				t.Errorf("batch %d timeout %q", batch, r.Form.Get("timeout"))
			}
			if r.Form.Get("limit") != "100" {
				t.Error("missing explicit fetch limit")
			}
			var updates []tgbotapi.Update
			switch batch {
			case 1, 2:
				for i := 0; i < 100; i++ {
					updates = append(updates, commandUpdate((batch-1)*100+i+1, "/pending"))
				}
			case 3:
				updates = []tgbotapi.Update{commandUpdate(201, "/pending"), {UpdateID: 202, CallbackQuery: &tgbotapi.CallbackQuery{ID: "drained-callback", From: &tgbotapi.User{ID: 42}, Data: "v:invalid"}}}
			case 4:
				u := commandUpdate(203, "/pending")
				u.Message.Date = 1
				updates = []tgbotapi.Update{u}
				cancel()
				synctest.Wait()
			default:
				t.Fatal("extra poll")
			}
			b, _ := json.Marshal(struct {
				OK     bool              `json:"ok"`
				Result []tgbotapi.Update `json:"result"`
			}{true, updates})
			return string(b), nil
		}
		f.backend.pollLoop(ctx)
		f.api.hook = nil
		f.api.reset()
		for len(f.backend.notifications) > 0 {
			(<-f.backend.notifications)()
		}
		answered := 0
		for _, call := range f.api.snapshot() {
			if call.method == "answerCallbackQuery" && call.form.Get("callback_query_id") == "drained-callback" {
				answered++
			}
		}
		if answered != 1 {
			t.Fatalf("drained callback answered %d times", answered)
		}
		if len(a.events) != 1 || a.events[0].Status != "approval-command_refused{redelivered}" {
			t.Fatalf("bounded drain events: %+v", a.events)
		}
	})
}

func TestApprovalCommandForwardOrigin(t *testing.T) {
	for _, origin := range []string{`{"type":"user","sender_user":{"id":99},"date":1}`, `{"type":"hidden_user","sender_user_name":"private","date":1}`, `{"type":"chat","sender_chat":{"id":99},"date":1}`, `{"type":"channel","chat":{"id":99},"message_id":3,"date":1}`} {
		t.Run(origin, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				a := &commandAudit{}
				f.backend.CommandAudit = a
				f.backend.approvalCommands = map[string]func(*tgbotapi.Message){"pending": func(*tgbotapi.Message) {
					t.Fatal("forwarded command reached its handler")
				}}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.backend.runDone = make(chan struct{})
				defer close(f.backend.runDone)
				batch := 0
				f.api.hook = func(_ *http.Request, _ int) (string, error) {
					batch++
					if batch == 1 {
						return `{"ok":true,"result":[]}`, nil
					}
					cancel()
					synctest.Wait()
					return `{"ok":true,"result":[{"update_id":1,"message":{"from":{"id":42},"chat":{"id":42,"type":"private"},"text":"/pending","entities":[{"type":"bot_command","offset":0,"length":8}],"forward_origin":` + origin + `}}]}`, nil
				}
				f.backend.pollLoop(ctx)
				if len(a.events) != 1 || a.events[0].Status != "approval-command_refused{forwarded}" {
					t.Fatalf("events: %+v", a.events)
				}
			})
		})
	}
}

func TestApprovalRegisteredCommandClockCorrection(t *testing.T) {
	for _, skew := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				a := &commandAudit{}
				f.backend.CommandAudit = a
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var executed []int
				f.backend.approvalCommands = map[string]func(*tgbotapi.Message){"test": func(m *tgbotapi.Message) {
					executed = append(executed, m.MessageID)
					if m.MessageID == 2 {
						cancel()
						synctest.Wait()
					}
				}}
				f.backend.runDone = make(chan struct{})
				defer close(f.backend.runDone)
				// Start skewed, then correct the signer's wall clock after startup drain.
				telegramNow := f.clock.Wall()
				f.clock.StepWall(skew)
				batch := 0
				f.api.hook = func(r *http.Request, _ int) (string, error) {
					if !strings.HasSuffix(r.URL.Path, "getUpdates") {
						t.Fatal("unexpected API call")
					}
					batch++
					if batch > 2 {
						t.Fatal("post-drain command did not execute")
					}
					if batch == 2 {
						f.clock.StepWall(-skew)
					}
					u := commandUpdate(batch, "/test")
					u.Message.MessageID = batch
					u.Message.Date = int(telegramNow.Add(time.Duration(batch-1) * time.Second).Unix())
					body, err := json.Marshal(struct {
						OK     bool              `json:"ok"`
						Result []tgbotapi.Update `json:"result"`
					}{true, []tgbotapi.Update{u}})
					return string(body), err
				}
				f.backend.pollLoop(ctx)
				if len(executed) != 1 || executed[0] != 2 {
					t.Fatalf("executed commands: %v; want only post-drain command 2", executed)
				}
				if len(a.events) != 1 || a.events[0].Status != "approval-command_refused{redelivered}" {
					t.Fatalf("audit events: %+v", a.events)
				}
			})
		})
	}
}

func TestApprovalCommandStrangerFlood(t *testing.T) {
	for _, auditFails := range []bool{false, true} {
		t.Run(strconv.FormatBool(auditFails), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				a := &commandAudit{fail: auditFails}
				f.backend.CommandAudit = a
				var logs bytes.Buffer
				f.backend.logger = log.New(&logs, "", 0)
				flood := func() {
					for i := 0; i < 1000; i++ {
						u := commandUpdate(i+1, "/cancel secret-argument")
						if i%2 == 0 {
							u.Message.From.ID = 99
						} else {
							u.Message.Chat.Type = "group"
						}
						f.backend.dispatch(u)
						if i == 500 && !auditFails {
							f.start(t)
							if f.card(t) == nil {
								t.Fatal("approval card not delivered during flood")
							}
						}
					}
				}
				flood()
				if len(a.events) != 0 || len(f.backend.notifications) != 0 {
					t.Fatal("stranger flood produced immediate output")
				}
				if auditFails && len(f.api.snapshot()) != 0 {
					t.Fatal("stranger flood sent a message")
				}
				for _, call := range f.api.snapshot() {
					if strings.Contains(call.form.Get("text"), "command refused") {
						t.Fatal("stranger reply sent")
					}
				}
				f.clock.StepWall(time.Hour)
				f.backend.flushCommandRefusals()
				if len(a.events) != 0 {
					t.Fatal("wall correction flushed early")
				}
				f.clock.Advance(time.Minute)
				f.backend.flushCommandRefusals()
				f.backend.flushCommandRefusals()
				want := "command_refused{count=1000,wrong_user=500,not_private=500}"
				if len(a.events) != 1 || a.events[0].Approval.Transition != want || a.events[0].Approval.Replay {
					t.Fatalf("summary: %+v", a.events)
				}
				if strings.Count(logs.String(), "\n") != 1 || !strings.Contains(logs.String(), want) {
					t.Fatalf("logs: %s", logs.String())
				}
				// A second interval must reset the count, without replying.
				u := commandUpdate(1001, "/cancel secret-argument")
				u.Message.From.ID = 99
				f.backend.dispatch(u)
				f.clock.StepWall(-2 * time.Hour)
				f.clock.Advance(time.Minute - time.Nanosecond)
				f.backend.flushCommandRefusals()
				if len(a.events) != 1 {
					t.Fatal("second interval flushed early")
				}
				f.clock.Advance(time.Nanosecond)
				f.backend.flushCommandRefusals()
				if len(a.events) != 2 || a.events[1].Approval.Transition != "command_refused{count=1,wrong_user=1,not_private=0}" || len(f.backend.notifications) != 0 {
					t.Fatalf("second interval: %+v", a.events)
				}
			})
		})
	}
}

func TestApprovalCommandAuthenticatedFlood(t *testing.T) {
	for _, reason := range []string{"forwarded", "redelivered", "unknown_command"} {
		t.Run(reason, func(t *testing.T) {
			f := newCallbackFixture(t)
			a := &commandAudit{}
			f.backend.CommandAudit = a
			u := commandUpdate(1, "/cancel")
			if reason == "forwarded" {
				u.Message.ForwardDate = 1
			}
			f.backend.commandDrain = reason == "redelivered"
			for i := 0; i < 1000; i++ {
				f.backend.dispatch(u)
			}
			if len(a.events) != 1 || len(f.backend.notifications) != 1 {
				t.Fatalf("unbounded refusal: audit=%d replies=%d", len(a.events), len(f.backend.notifications))
			}
			(<-f.backend.notifications)()
			calls := f.api.snapshot()
			if len(calls) != 1 || calls[0].form.Get("text") != "command refused: "+reason {
				t.Fatalf("reply: %+v", calls)
			}
			f.clock.StepWall(time.Hour)
			f.backend.dispatch(u)
			if len(a.events) != 1 {
				t.Fatal("wall correction reset limit")
			}
			f.clock.Advance(time.Minute)
			f.backend.dispatch(u)
			if len(a.events) != 2 || len(f.backend.notifications) != 1 {
				t.Fatal("limit did not renew")
			}
		})
	}
}

func TestApprovalCommandIdlePollFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		a := &commandAudit{}
		f.backend.CommandAudit = a
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.backend.runDone = make(chan struct{})
		defer close(f.backend.runDone)
		batch := 0
		f.api.hook = func(_ *http.Request, _ int) (string, error) {
			batch++
			switch batch {
			case 1:
				u := commandUpdate(1, "/pending")
				u.Message.From.ID = 99
				data, err := json.Marshal(struct {
					OK     bool              `json:"ok"`
					Result []tgbotapi.Update `json:"result"`
				}{true, []tgbotapi.Update{u}})
				return string(data), err
			case 2:
				f.clock.Advance(time.Minute)
			case 3:
				if len(a.events) != 1 {
					t.Fatal("idle poll did not flush refusal count")
				}
				cancel()
				synctest.Wait()
			default:
				t.Fatal("extra poll")
			}
			return `{"ok":true,"result":[]}`, nil
		}
		f.backend.pollLoop(ctx)
		if len(f.backend.notifications) != 0 {
			t.Fatal("idle flush queued a reply")
		}
	})
}
