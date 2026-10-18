package faketg

import (
	"encoding/json"
	"io"
	"net/http"

	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Admin must be reachable only by the journey controller, never remote targets.
func (s *Service) Admin(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/events" {
		reply(w, 200, map[string]any{"events": s.events, "failures": s.failures}, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var input struct {
		Policy    string `json:"policy"`
		ChatID    int64  `json:"chat_id"`
		MessageID int    `json:"message_id"`
		Action    string `json:"action"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		reply(w, 400, nil, "invalid admin JSON")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		reply(w, 400, nil, "extra admin JSON")
		return
	}
	var result any = true
	switch r.URL.Path {
	case "/policy":
		switch input.Policy {
		case "approve_now", "approve_after_sync_wait", "deny", "never", "hold":
		default:
			reply(w, 400, nil, "unknown policy")
			return
		}
		s.policy = input.Policy
	case "/start":
		if input.ChatID == 0 {
			reply(w, 400, nil, "chat_id required")
			return
		}
		s.nextMessage++
		result = s.enqueue(tg.Update{Message: &tg.Message{MessageID: s.nextMessage, From: &tg.User{ID: s.userID, FirstName: "Operator"}, Chat: &tg.Chat{ID: input.ChatID, Type: "private"}, Text: "/start", Entities: []tg.MessageEntity{{Type: "bot_command", Offset: 0, Length: 6}}}})
	case "/release", "/replay":
		c := s.cards[input.MessageID]
		if input.Action == "" {
			input.Action = "approve"
		}
		if c == nil || (input.Action != "approve" && input.Action != "deny") {
			reply(w, 400, nil, "unknown card or action")
			return
		}
		if r.URL.Path == "/release" && (c.delivered || c.policy == "never" || (c.policy != "hold" && c.policy != "approve_after_sync_wait")) {
			reply(w, 409, nil, "card cannot be released")
			return
		}
		result = s.deliver(c, input.Action)
	default:
		reply(w, 404, nil, "unknown admin route")
		return
	}
	s.record(r.URL.Path, map[string]string{"policy": input.Policy, "action": input.Action}, result, "")
	reply(w, 200, result, "")
}
