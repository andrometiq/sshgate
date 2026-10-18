package faketg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/tests/journey/faketg"
)

type fixture struct {
	t          *testing.T
	api, admin *httptest.Server
}

func setup(t *testing.T) *fixture { return setupControls(t, faketg.Controls{}) }
func setupControls(t *testing.T, controls faketg.Controls) *fixture {
	s := faketg.New(99999)
	s.Controls = controls
	f := &fixture{t, httptest.NewServer(http.HandlerFunc(s.API)), httptest.NewServer(http.HandlerFunc(s.Admin))}
	t.Cleanup(f.api.Close)
	t.Cleanup(f.admin.Close)
	return f
}
func (f *fixture) request(admin bool, path string, values url.Values, body string, status int, out any) {
	f.t.Helper()
	var response *http.Response
	var err error
	if admin {
		response, err = http.Post(f.admin.URL+path, "application/json", strings.NewReader(body))
	} else {
		response, err = http.PostForm(f.api.URL+"/bot123:synthetic/"+path, values)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	if response.StatusCode != status {
		f.t.Fatalf("%s: status %d: %s", path, response.StatusCode, data)
	}
	if out != nil {
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if err = json.Unmarshal(data, &envelope); err != nil {
			f.t.Fatal(err)
		}
		if err = json.Unmarshal(envelope.Result, out); err != nil {
			f.t.Fatal(err)
		}
	}
}
func (f *fixture) policy(policy string) {
	f.request(true, "/policy", nil, fmt.Sprintf(`{"policy":%q}`, policy), 200, nil)
}
func (f *fixture) send(text, markup string) tg.Message {
	values := url.Values{"chat_id": {"12345"}, "text": {text}}
	if markup != "" {
		values.Set("reply_markup", markup)
	}
	var m tg.Message
	f.request(false, "sendMessage", values, "", 200, &m)
	return m
}

const keyboard = `{"inline_keyboard":[[{"text":"✓ Approve all","callback_data":"opaque/yes:!"},{"text":"✗ Deny","callback_data":"opaque/no:?"}]]}`

func (f *fixture) updates(offset int) []tg.Update {
	var updates []tg.Update
	f.request(false, "getUpdates", url.Values{"offset": {fmt.Sprint(offset)}}, "", 200, &updates)
	return updates
}
func (f *fixture) events() ([]faketg.Event, []string) {
	response, err := http.Get(f.admin.URL + "/events")
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	var data struct {
		Result struct {
			Events   []faketg.Event `json:"events"`
			Failures []string       `json:"failures"`
		} `json:"result"`
	}
	if err = json.NewDecoder(response.Body).Decode(&data); err != nil {
		f.t.Fatal(err)
	}
	return data.Result.Events, data.Result.Failures
}

func TestProtocolTranscriptAndOffsets(t *testing.T) {
	f := setup(t)
	var user tg.User
	f.request(false, "getMe", nil, "", 200, &user)
	if !user.IsBot {
		t.Fatal(user)
	}
	f.request(true, "/start", nil, `{"chat_id":12345}`, 200, nil)
	initial := f.updates(0)
	if len(initial) != 1 || initial[0].Message.Text != "/start" || !initial[0].Message.IsCommand() || initial[0].Message.From.ID != 99999 || initial[0].Message.Chat.ID != 12345 {
		t.Fatal(initial)
	}
	if !reflect.DeepEqual(initial, f.updates(0)) {
		t.Fatal("read consumed unacknowledged update")
	}
	if len(f.updates(initial[0].UpdateID+1)) != 0 || len(f.updates(0)) != 0 {
		t.Fatal("acknowledged update retained")
	}
	m := f.send("card", keyboard)
	f.request(true, "/release", nil, fmt.Sprintf(`{"message_id":%d}`, m.MessageID), 200, nil)
	queryID := f.updates(0)[0].CallbackQuery.ID
	f.request(false, "editMessageText", url.Values{"chat_id": {"12345"}, "message_id": {fmt.Sprint(m.MessageID)}, "text": {"terminal"}, "reply_markup": {keyboard}}, "", 200, nil)
	f.request(false, "editMessageReplyMarkup", url.Values{"chat_id": {"12345"}, "message_id": {fmt.Sprint(m.MessageID)}, "reply_markup": {`{"inline_keyboard":[]}`}}, "", 200, nil)
	f.request(false, "answerCallbackQuery", url.Values{"callback_query_id": {queryID}, "text": {"recorded"}}, "", 200, nil)
	events, failures := f.events()
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Method] = true
		if e.Method == "editMessageReplyMarkup" && e.Fields["reply_markup"] != `{"inline_keyboard":[]}` {
			t.Fatal(e)
		}
		if e.Method == "answerCallbackQuery" && e.Fields["callback_query_id"] != queryID {
			t.Fatal(e)
		}
	}
	for _, method := range []string{"getMe", "getUpdates", "sendMessage", "editMessageText", "editMessageReplyMarkup", "answerCallbackQuery"} {
		if !seen[method] {
			t.Fatal("missing", method)
		}
	}
}

func TestPoliciesBindingAndReplay(t *testing.T) {
	for _, policy := range []string{"approve_now", "approve_after_sync_wait", "deny", "never", "hold"} {
		t.Run(policy, func(t *testing.T) {
			f := setup(t)
			f.policy(policy)
			f.send("review part 1", "")
			m := f.send("decision card", keyboard)
			updates := f.updates(0)
			if policy == "hold" || policy == "approve_after_sync_wait" || policy == "never" {
				if len(updates) != 0 {
					t.Fatal("premature callback")
				}
				// Save callbacks survive signer expiry edits removing the buttons.
				f.request(false, "editMessageReplyMarkup", url.Values{"chat_id": {"12345"}, "message_id": {fmt.Sprint(m.MessageID)}, "reply_markup": {`{"inline_keyboard":[]}`}}, "", 200, nil)
				status := 200
				if policy == "never" {
					status = 409
				}
				f.request(true, "/release", nil, fmt.Sprintf(`{"message_id":%d}`, m.MessageID), status, nil)
				if policy == "never" {
					if len(f.updates(0)) != 0 {
						t.Fatal("never delivered")
					}
					f.request(true, "/replay", nil, fmt.Sprintf(`{"message_id":%d}`, m.MessageID), 200, nil)
				}
				updates = f.updates(0)
			}
			if len(updates) != 1 {
				t.Fatalf("updates: %+v", updates)
			}
			cb := updates[0].CallbackQuery
			want := "opaque/yes:!"
			if policy == "deny" {
				want = "opaque/no:?"
			}
			if cb == nil || cb.Data != want || cb.From.ID != 99999 || cb.Message.Chat.ID != m.Chat.ID || cb.Message.MessageID != m.MessageID || cb.Message.Text != m.Text {
				t.Fatalf("binding: %+v", cb)
			}
			f.updates(updates[0].UpdateID + 1)
			action := "approve"
			if policy == "deny" {
				action = "deny"
			}
			f.request(true, "/replay", nil, fmt.Sprintf(`{"message_id":%d,"action":%q}`, m.MessageID, action), 200, nil)
			duplicate := f.updates(0)
			if len(duplicate) != 1 || duplicate[0].UpdateID <= updates[0].UpdateID || !reflect.DeepEqual(cb, duplicate[0].CallbackQuery) {
				t.Fatal("replay changed callback identity")
			}
			f.request(true, "/release", nil, fmt.Sprintf(`{"message_id":%d}`, m.MessageID), 409, nil)
		})
	}
}

func TestUnknownMethodAndAdminIsolation(t *testing.T) {
	f := setup(t)
	f.request(false, "deleteEverything", nil, "", 400, nil)
	_, failures := f.events()
	if len(failures) != 1 || !strings.Contains(failures[0], "deleteEverything") {
		t.Fatal(failures)
	}
	response, err := http.Post(f.api.URL+"/policy", "application/json", strings.NewReader(`{"policy":"approve_now"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal(response.StatusCode)
	}
	f.request(true, "/policy", nil, `{"policy":"typo"}`, 400, nil)
	f.request(true, "/release", nil, `{"message_id":999}`, 400, nil)
}

func TestRealBackendApproveAndDeny(t *testing.T) {
	for _, policy := range []string{"approve_now", "deny"} {
		t.Run(policy, func(t *testing.T) {
			f := setup(t)
			f.policy(policy)
			endpoint, err := backend.APIEndpointForBase(f.api.URL)
			if err != nil {
				t.Fatal(err)
			}
			store := &backend.MemChatStore{}
			if err = store.Save(12345); err != nil {
				t.Fatal(err)
			}
			b, err := backend.NewTelegramBackend(backend.TelegramOptions{BotToken: "123:synthetic", AllowedUserID: 99999, ChatStore: store, APIEndpoint: endpoint, Logger: log.New(io.Discard, "", 0), RequestTimeout: 5 * time.Second, PollTimeoutSec: 1})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := b.Run(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := b.Request(ctx, signerkit.ApprovalRequest{RequestID: "journey-real", Commands: []signerkit.CommandReq{{Cmd: "touch /tmp/journey"}}})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-result:
				expected := signerkit.StatusApproved
				if policy == "deny" {
					expected = signerkit.StatusDenied
				}
				if r.Status != expected {
					t.Fatalf("got %+v want %s", r, expected)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("backend result deadline")
			}
			// Wait for callback answers and terminal edits, which follow resolution.
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(5 * time.Millisecond)
			defer tick.Stop()
			for {
				events, failures := f.events()
				if len(failures) > 0 {
					t.Fatal(failures)
				}
				answer, edit := false, false
				var queryID string
				for _, e := range events {
					if e.Method == "update" {
						var u tg.Update
						_ = json.Unmarshal(e.Result, &u)
						if u.CallbackQuery != nil {
							queryID = u.CallbackQuery.ID
						}
					}
				}
				for _, e := range events {
					if e.Method == "answerCallbackQuery" {
						answer = queryID != "" && e.Fields["callback_query_id"] == queryID
					}
					if e.Method == "editMessageText" {
						word := "Approved"
						if policy == "deny" {
							word = "Denied"
						}
						var m tg.Message
						_ = json.Unmarshal(e.Result, &m)
						edit = strings.Contains(m.Text, word) && m.ReplyMarkup == nil
					}
				}
				if answer && edit {
					break
				}
				select {
				case <-tick.C:
				case <-deadline.C:
					t.Fatal("missing backend terminal evidence")
				}
			}
			cancel()
		})
	}
}

func TestRealBackendStart(t *testing.T) {
	f := setup(t)
	store := &backend.MemChatStore{}
	endpoint, err := backend.APIEndpointForBase(f.api.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := backend.NewTelegramBackend(backend.TelegramOptions{BotToken: "123:synthetic", AllowedUserID: 99999, ChatStore: store, APIEndpoint: endpoint, PollTimeoutSec: 1, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = b.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f.request(true, "/start", nil, `{"chat_id":12345}`, 200, nil)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		chat, ok, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			if chat != 12345 {
				t.Fatal(chat)
			}
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("backend did not capture /start")
		}
	}
}

func TestUpdateLimitAndLongPoll(t *testing.T) {
	waiting := make(chan struct{}, 1)
	timeout := make(chan time.Time)
	defer close(timeout)
	f := setupControls(t, faketg.Controls{PollWaiting: func() {
		select {
		case waiting <- struct{}{}:
		default:
		}
	}, PollTimeout: timeout})
	for range 3 {
		f.request(true, "/start", nil, `{"chat_id":12345}`, 200, nil)
	}
	var first []tg.Update
	f.request(false, "getUpdates", url.Values{"limit": {"2"}}, "", 200, &first)
	if len(first) != 2 {
		t.Fatal(first)
	}
	remaining := f.updates(first[1].UpdateID + 1)
	if len(remaining) != 1 {
		t.Fatal(remaining)
	}
	offset := remaining[0].UpdateID + 1
	f.updates(offset)
	done := make(chan []tg.Update, 1)
	go func() {
		var updates []tg.Update
		f.request(false, "getUpdates", url.Values{"offset": {fmt.Sprint(offset)}, "timeout": {"1"}}, "", 200, &updates)
		done <- updates
	}()
	select {
	case <-waiting:
	case <-time.After(3 * time.Second):
		t.Fatal("poll never waited")
	}
	f.request(true, "/start", nil, `{"chat_id":12345}`, 200, nil)
	select {
	case updates := <-done:
		if len(updates) != 1 || updates[0].UpdateID != offset {
			t.Fatal(updates)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long poll did not receive update")
	}
	f.request(false, "getUpdates", url.Values{"timeout": {"broken"}, "limit": {"2"}}, "", 400, nil)
}
