package faketg_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/tests/journey/faketg"
)

func TestMessageLimits(t *testing.T) {
	for _, tc := range []struct {
		name, text, data string
		valid            bool
	}{
		{"empty text", "", "a", false}, {"max text", strings.Repeat("界", 4096), "a", true},
		{"long text", strings.Repeat("界", 4097), "a", false}, {"empty callback", "card", "", false},
		{"max callback", "card", strings.Repeat("é", 32), true}, {"long callback", "card", strings.Repeat("é", 32) + "a", false},
		{"minimum", "a", "a", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			f.policy("approve_now")
			markup := fmt.Sprintf(`{"inline_keyboard":[[{"text":"Approve","callback_data":%q},{"text":"Deny","callback_data":"no"}]]}`, tc.data)
			status := 400
			if tc.valid {
				status = 200
			}
			f.request(false, "sendMessage", url.Values{"chat_id": {"12345"}, "text": {tc.text}, "reply_markup": {markup}}, "", status, nil)
			updates := f.updates(0)
			if tc.valid {
				if len(updates) != 1 {
					t.Fatal(updates)
				}
			} else {
				if len(updates) != 0 {
					t.Fatal("rejected send issued callback")
				}
				f.request(true, "/release", nil, `{"message_id":1}`, 400, nil)
				f.request(false, "editMessageText", url.Values{"chat_id": {"12345"}, "message_id": {"1"}, "text": {"changed"}}, "", 400, nil)
			}
		})
	}
}

func TestAnswersAndTerminalMarkup(t *testing.T) {
	f := setup(t)
	m := f.send("card", keyboard)
	for _, id := range []string{"", "invented", fmt.Sprintf("card-%d-approve", m.MessageID)} {
		f.request(false, "answerCallbackQuery", url.Values{"callback_query_id": {id}}, "", 400, nil)
	}
	f.request(true, "/release", nil, fmt.Sprintf(`{"message_id":%d}`, m.MessageID), 200, nil)
	id := f.updates(0)[0].CallbackQuery.ID
	for _, values := range []url.Values{
		{"text": {strings.Repeat("x", 201)}}, {"show_alert": {"maybe"}}, {"cache_time": {"-1"}}, {"url": {"https://example.invalid"}},
	} {
		values.Set("callback_query_id", id)
		f.request(false, "answerCallbackQuery", values, "", 400, nil)
	}
	// Repeated answers to an issued ID are deliberately idempotent in this fixture.
	for range 2 {
		f.request(false, "answerCallbackQuery", url.Values{"callback_query_id": {id}, "text": {strings.Repeat("界", 200)}, "show_alert": {"false"}, "cache_time": {"0"}}, "", 200, nil)
	}
	values := url.Values{"chat_id": {"12345"}, "message_id": {fmt.Sprint(m.MessageID)}, "text": {"terminal"}}
	var terminal tg.Message
	f.request(false, "editMessageText", values, "", 200, &terminal)
	if terminal.ReplyMarkup != nil {
		t.Fatal("keyboard survived text edit")
	}
	f.request(false, "editMessageText", values, "", 400, nil)
	f.request(false, "editMessageReplyMarkup", values, "", 400, nil)
	events, _ := f.events()
	unchanged := 0
	for _, e := range events {
		if strings.HasPrefix(e.Method, "editMessage") && e.Error != "" {
			if e.Error != "MESSAGE_NOT_MODIFIED" {
				t.Fatal(e)
			}
			unchanged++
		}
	}
	if unchanged != 2 {
		t.Fatalf("unchanged edit errors: %d", unchanged)
	}

}

func TestPollTimeoutAndCancellation(t *testing.T) {
	for _, cancelPoll := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelPoll), func(t *testing.T) {
			waiting := make(chan struct{}, 1)
			timeout := make(chan time.Time)
			s := faketg.New(99999)
			s.Controls = faketg.Controls{PollWaiting: func() { waiting <- struct{}{} }, PollTimeout: timeout}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(http.MethodPost, "/botfake/getUpdates", strings.NewReader("timeout=60")).WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { s.API(response, req); close(done) }()
			select {
			case <-waiting:
			case <-time.After(3 * time.Second):
				t.Fatal("not waiting")
			}
			if cancelPoll {
				cancel()
			} else {
				timeout <- time.Now()
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("poll stuck")
			}
			if !cancelPoll && !strings.Contains(response.Body.String(), `"result":[]`) {
				t.Fatal(response.Body.String())
			}
		})
	}
}

func TestCallbackBeforeSendResponse(t *testing.T) {
	hook, captured, release := faketg.HoldMessageResponse()
	defer release()
	f := setupControls(t, faketg.Controls{BeforeMessageResponse: hook})
	done := make(chan struct{})
	go func() { f.send("card", keyboard); close(done) }()
	var m tg.Message
	select {
	case m = <-captured:
	case <-time.After(3 * time.Second):
		t.Fatal("no card")
	}
	if len(f.updates(0)) != 0 {
		t.Fatal("callback before explicit release")
	}
	f.request(true, "/release", nil, fmt.Sprintf(`{"message_id":%d}`, m.MessageID), 200, nil)
	updates := f.updates(0)
	if len(updates) != 1 || updates[0].CallbackQuery.Message.MessageID != m.MessageID {
		t.Fatal(updates)
	}
	select {
	case <-done:
		t.Fatal("send response escaped barrier")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("send blocked")
	}
}

func TestMalformedKeyboardLeavesNoState(t *testing.T) {
	for _, button := range []string{
		"null", "{}", "[]", "42", `{"text":42,"callback_data":"yes"}`,
		`{"text":"Approve"}`, `{"text":null,"callback_data":"yes"}`,
		`{"text":"","callback_data":"yes"}`, `{"text":"Approve","callback_data":null}`,
		`{"text":"Approve","callback_data":"yes","url":"https://example.invalid"}`,
		`{"text":"Approve","url":"https://example.invalid"}`,
		`{"text":"Approve","callback_data":"yes","pay":true}`,
		`{"text":"Approve","callback_data":"yes","switch_inline_query":""}`,
	} {
		t.Run(button, func(t *testing.T) {
			f := setup(t)
			f.policy("approve_now")
			markup := strings.TrimSuffix(keyboard, "]]}") + "," + button + "]]}"
			f.request(false, "sendMessage", url.Values{"chat_id": {"12345"}, "text": {"card"}, "reply_markup": {markup}}, "", 400, nil)
			if updates := f.updates(0); len(updates) != 0 {
				t.Fatalf("rejected keyboard issued updates: %v", updates)
			}
			f.request(true, "/replay", nil, `{"message_id":1}`, 400, nil)
			f.request(false, "editMessageText", url.Values{"chat_id": {"12345"}, "message_id": {"1"}, "text": {"changed"}}, "", 400, nil)
			f.request(false, "answerCallbackQuery", url.Values{"callback_query_id": {"card-1-approve"}}, "", 400, nil)
			events, failures := f.events()
			if len(failures) != 3 {
				t.Fatalf("failures: %v", failures)
			}
			for _, event := range events {
				if event.Method == "update" || (event.Method == "sendMessage" && event.Error == "") {
					t.Fatalf("rejected state recorded: %+v", event)
				}
			}
		})
	}
}

func TestBotAPIErrorsThroughTelegramClient(t *testing.T) {
	for _, tc := range []struct {
		name, method, description string
		params                    tg.Params
	}{
		{"unknown method", "unsupported", "unknown Bot API method: unsupported", nil},
		{"invalid route", "extra/path", "invalid Bot API route", nil},
		{"invalid form", "sendMessage", "invalid form", tg.Params{"text": strings.Repeat("x", 1<<20)}},
		{"invalid chat", "sendMessage", "invalid chat_id", nil},
		{"invalid markup", "sendMessage", "invalid reply_markup", tg.Params{"chat_id": "12345", "text": "card", "reply_markup": "null"}},
		{"offset", "getUpdates", "invalid polling parameters", tg.Params{"offset": "bad"}},
		{"negative offset", "getUpdates", "invalid polling parameters", tg.Params{"offset": "-1"}},
		{"timeout", "getUpdates", "invalid polling parameters", tg.Params{"timeout": "bad"}},
		{"negative timeout", "getUpdates", "invalid polling parameters", tg.Params{"timeout": "-1"}},
		{"limit", "getUpdates", "invalid polling parameters", tg.Params{"limit": "bad"}},
		{"zero limit", "getUpdates", "invalid polling parameters", tg.Params{"limit": "0"}},
		{"large limit", "getUpdates", "invalid polling parameters", tg.Params{"limit": "101"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			bot, err := tg.NewBotAPIWithClient("123:synthetic", f.api.URL+"/bot%s/%s", f.api.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = bot.MakeRequest(tc.method, tc.params)
			apiErr, ok := err.(*tg.Error)
			code := 400
			if tc.name == "invalid route" {
				code = 404
			}
			if !ok || apiErr.Code != code || apiErr.Message != tc.description {
				t.Fatalf("API error: %T %v", err, err)
			}
			events, failures := f.events()
			if len(failures) != 1 || failures[0] != tc.description {
				t.Fatalf("failures: %v", failures)
			}
			last := events[len(events)-1]
			if last.Error != tc.description {
				t.Fatalf("missing error event: %+v", last)
			}
		})
	}
}
