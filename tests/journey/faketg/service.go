// Package faketg implements the local Telegram fixture for the journey suite.
package faketg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type Event struct {
	Sequence int               `json:"sequence"`
	Time     time.Time         `json:"time"`
	Method   string            `json:"method"`
	Fields   map[string]string `json:"fields,omitempty"`
	Result   json.RawMessage   `json:"result,omitempty"`
	Error    string            `json:"error,omitempty"`
}

type card struct {
	callbacks map[string]tg.CallbackQuery
	policy    string
	delivered bool
}

// Controls are configured before serving requests. Nil hooks use normal transport behavior.
type Controls struct {
	BeforeMessageResponse func(context.Context, tg.Message)
	PollWaiting           func()
	PollTimeout           <-chan time.Time
}

type Service struct {
	Controls                Controls
	issued                  map[string]bool
	mu                      sync.Mutex
	userID                  int64
	policy                  string
	nextMessage, nextUpdate int
	messages                map[int]tg.Message
	cards                   map[int]*card
	updates                 []tg.Update
	events                  []Event
	failures                []string
	changed                 chan struct{}
}

func New(userID int64) *Service {
	if userID == 0 {
		panic("faketg: user ID must be nonzero")
	}
	return &Service{issued: make(map[string]bool), userID: userID, policy: "hold", messages: make(map[int]tg.Message), cards: make(map[int]*card), changed: make(chan struct{})}
}

func (s *Service) record(method string, fields map[string]string, result any, err string) {
	data, _ := json.Marshal(result)
	s.events = append(s.events, Event{len(s.events) + 1, time.Now().UTC(), method, fields, data, err})
}
func reply(w http.ResponseWriter, status int, result any, err string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := map[string]any{"ok": err == "", "result": result, "description": err}
	if err != "" {
		response["error_code"] = status
	}
	_ = json.NewEncoder(w).Encode(response)
}
func (s *Service) fail(w http.ResponseWriter, status int, method, message string) {
	s.failures = append(s.failures, message)
	s.record(method, nil, nil, message)
	reply(w, status, nil, message)
}

// API serves only Bot API routes; mount Admin on a separate private listener.
func (s *Service) API(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "bot") {
		s.mu.Lock()
		s.fail(w, 404, "invalid_route", "invalid Bot API route")
		s.mu.Unlock()
		return
	}
	method := parts[1]
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		s.mu.Lock()
		s.fail(w, 400, method, "invalid form")
		s.mu.Unlock()
		return
	}
	if method == "getUpdates" {
		s.poll(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fields := map[string]string{}
	for k, v := range r.Form {
		if len(v) > 0 {
			fields[k] = v[0]
		}
	}
	var result any
	switch method {
	case "getMe":
		result = tg.User{ID: 7777, IsBot: true, FirstName: "Journey", UserName: "journey_bot"}
	case "sendMessage", "editMessageText", "editMessageReplyMarkup":
		chat, err := strconv.ParseInt(r.FormValue("chat_id"), 10, 64)
		if err != nil || chat == 0 {
			s.fail(w, 400, method, "invalid chat_id")
			return
		}
		var m tg.Message
		if method == "sendMessage" {
			s.nextMessage++
			m = tg.Message{MessageID: s.nextMessage, Chat: &tg.Chat{ID: chat, Type: "private"}, Date: int(time.Now().Unix())}
		} else {
			id, _ := strconv.Atoi(r.FormValue("message_id"))
			var ok bool
			m, ok = s.messages[id]
			if !ok || m.Chat.ID != chat {
				s.fail(w, 400, method, "unknown message")
				return
			}
		}
		original := m
		if method != "editMessageReplyMarkup" {
			m.Text = r.FormValue("text")
			if !utf8.ValidString(m.Text) || utf8.RuneCountInString(m.Text) < 1 || utf8.RuneCountInString(m.Text) > 4096 {
				s.fail(w, 400, method, "invalid text length")
				return
			}
		}
		if raw, ok := fields["reply_markup"]; ok {
			markup, err := parseKeyboard(raw)
			if err != nil {
				s.fail(w, 400, method, err.Error())
				return
			}
			m.ReplyMarkup = nil
			if len(markup.InlineKeyboard) > 0 {
				m.ReplyMarkup = &markup
			}
		} else {
			m.ReplyMarkup = nil
		}
		if method != "sendMessage" && original.Text == m.Text && reflect.DeepEqual(original.ReplyMarkup, m.ReplyMarkup) {
			s.fail(w, 400, method, "MESSAGE_NOT_MODIFIED")
			return
		}
		s.messages[m.MessageID] = m
		result = m
	case "answerCallbackQuery":
		if !s.issued[fields["callback_query_id"]] {
			s.fail(w, 400, method, "unknown callback_query_id")
			return
		}
		for key, value := range fields {
			switch key {
			case "callback_query_id":
			case "text":
				if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 200 {
					s.fail(w, 400, method, "invalid answer text")
					return
				}
			case "show_alert":
				if value != "true" && value != "false" {
					s.fail(w, 400, method, "invalid show_alert")
					return
				}
			case "cache_time":
				n, err := strconv.Atoi(value)
				if err != nil || n < 0 {
					s.fail(w, 400, method, "invalid cache_time")
					return
				}
			default:
				s.fail(w, 400, method, "unsupported answer field: "+key)
				return
			}
		}
		result = true
	default:
		s.fail(w, 400, method, "unknown Bot API method: "+method)
		return
	}
	s.record(method, fields, result, "")
	if message, ok := result.(tg.Message); ok {
		s.capture(message)
		if hook := s.Controls.BeforeMessageResponse; hook != nil && method == "sendMessage" && s.cards[message.MessageID] != nil {
			s.mu.Unlock()
			hook(r.Context(), message)
			s.mu.Lock()
		}
	}
	reply(w, 200, result, "")
}

func (s *Service) poll(w http.ResponseWriter, r *http.Request) {
	offset, err := strconv.Atoi(r.FormValue("offset"))
	if r.FormValue("offset") == "" {
		offset = 0
		err = nil
	}
	seconds, e := strconv.Atoi(r.FormValue("timeout"))
	if r.FormValue("timeout") == "" {
		seconds = 0
		e = nil
	}
	limit := 100
	if raw := r.FormValue("limit"); raw != "" {
		var limitErr error
		limit, limitErr = strconv.Atoi(raw)
		if limitErr != nil {
			e = limitErr
		}
	}
	if err != nil || e != nil || offset < 0 || seconds < 0 || limit < 1 || limit > 100 {
		s.mu.Lock()
		s.fail(w, 400, "getUpdates", "invalid polling parameters")
		s.mu.Unlock()
		return
	}
	// Bound shutdown latency while retaining long-poll semantics.
	if seconds > 1 {
		seconds = 1
	}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	timeout := s.Controls.PollTimeout
	if timeout == nil {
		timeout = timer.C
	}
	for {
		s.mu.Lock()
		n := 0
		for n < len(s.updates) && s.updates[n].UpdateID < offset {
			n++
		}
		s.updates = s.updates[n:]
		out := append([]tg.Update{}, s.updates...)
		if len(out) > limit {
			out = out[:limit]
		}
		changed := s.changed
		if len(out) > 0 || seconds == 0 {
			s.record("getUpdates", map[string]string{"offset": strconv.Itoa(offset)}, out, "")
			s.mu.Unlock()
			reply(w, 200, out, "")
			return
		}
		s.mu.Unlock()
		if s.Controls.PollWaiting != nil {
			s.Controls.PollWaiting()
		}
		select {
		case <-changed:
		case <-timeout:
			seconds = 0
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Service) enqueue(update tg.Update) int {
	s.nextUpdate++
	update.UpdateID = s.nextUpdate
	s.updates = append(s.updates, update)
	s.record("update", nil, update, "")
	close(s.changed)
	s.changed = make(chan struct{})
	return update.UpdateID
}

func (s *Service) capture(m tg.Message) {
	if s.cards[m.MessageID] != nil || m.ReplyMarkup == nil {
		return
	}
	callbacks := map[string]tg.CallbackQuery{}
	for _, row := range m.ReplyMarkup.InlineKeyboard {
		for _, button := range row {
			if button.CallbackData == nil {
				continue
			}
			action := ""
			label := strings.ToLower(button.Text)
			if strings.Contains(label, "approve") {
				action = "approve"
			} else if strings.Contains(label, "deny") {
				action = "deny"
			}
			if action == "" {
				continue
			}
			if _, exists := callbacks[action]; exists {
				return
			} // Ambiguous keyboard is not actionable.
			copyMessage := m
			callbacks[action] = tg.CallbackQuery{ID: fmt.Sprintf("card-%d-%s", m.MessageID, action), From: &tg.User{ID: s.userID, FirstName: "Operator"}, Message: &copyMessage, ChatInstance: "journey", Data: *button.CallbackData}
		}
	}
	if len(callbacks) != 2 {
		return
	}
	c := &card{callbacks: callbacks, policy: s.policy}
	s.cards[m.MessageID] = c
	switch c.policy {
	case "approve_now":
		s.deliver(c, "approve")
	case "deny":
		s.deliver(c, "deny")
	}
}
func (s *Service) deliver(c *card, action string) int {
	cb := c.callbacks[action]
	s.issued[cb.ID] = true
	c.delivered = true
	return s.enqueue(tg.Update{CallbackQuery: &cb})
}

// Only callback buttons are supported by the journey transport.
func parseKeyboard(raw string) (tg.InlineKeyboardMarkup, error) {
	var input *struct {
		Rows [][]*struct {
			Text *string `json:"text"`
			Data *string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input == nil || input.Rows == nil {
		return tg.InlineKeyboardMarkup{}, fmt.Errorf("invalid reply_markup")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return tg.InlineKeyboardMarkup{}, fmt.Errorf("invalid reply_markup")
	}
	markup := tg.InlineKeyboardMarkup{InlineKeyboard: make([][]tg.InlineKeyboardButton, 0, len(input.Rows))}
	for _, row := range input.Rows {
		if row == nil {
			return tg.InlineKeyboardMarkup{}, fmt.Errorf("invalid keyboard row")
		}
		buttons := make([]tg.InlineKeyboardButton, 0, len(row))
		for _, button := range row {
			if button == nil || button.Text == nil || *button.Text == "" || button.Data == nil {
				return tg.InlineKeyboardMarkup{}, fmt.Errorf("invalid keyboard button")
			}
			if len(*button.Data) < 1 || len(*button.Data) > 64 {
				return tg.InlineKeyboardMarkup{}, fmt.Errorf("invalid callback_data length")
			}
			buttons = append(buttons, tg.InlineKeyboardButton{Text: *button.Text, CallbackData: button.Data})
		}
		markup.InlineKeyboard = append(markup.InlineKeyboard, buttons)
	}
	return markup, nil
}
