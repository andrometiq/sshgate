package backend

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

const approvalUpdateLimit = 100
const commandRefusalInterval = time.Minute

type commandRefusalState struct {
	origin                time.Time
	strangerDeadline      time.Duration
	wrongUser, notPrivate uint64
	replyAfter            time.Duration
	replyLimited          bool
}

// The poller flushes on its next iteration after the interval, including idle polls.
// Counts contain no message text, user identifiers or chat identifiers.
func (t *TelegramBackend) flushCommandRefusals() {
	s := &t.commandRefusals
	if (s.wrongUser == 0 && s.notPrivate == 0) || t.commandElapsed() < s.strangerDeadline {
		return
	}
	transition := fmt.Sprintf("command_refused{count=%d,wrong_user=%d,not_private=%d}", saturatingCommandCount(s.wrongUser, s.notPrivate), s.wrongUser, s.notPrivate)
	err := t.writeCommandRefusal(transition, false)
	t.logger.Printf("%s audit_failed=%t", transition, err != nil)
	s.wrongUser, s.notPrivate = 0, 0
}

func saturatingCommandCount(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func (t *TelegramBackend) commandElapsed() time.Duration {
	if t.approvalCallbacks != nil {
		return t.approvalCallbacks.runtime.Legacy().CallbackElapsed()
	}
	if t.commandRefusals.origin.IsZero() {
		t.commandRefusals.origin = time.Now()
	}
	return time.Since(t.commandRefusals.origin)
}

func (t *TelegramBackend) countCommandRefusal(reason string) {
	t.flushCommandRefusals()
	s := &t.commandRefusals
	if s.wrongUser == 0 && s.notPrivate == 0 {
		s.strangerDeadline = t.commandElapsed() + commandRefusalInterval
	}
	if reason == "wrong_user" {
		s.wrongUser = saturatingCommandCount(s.wrongUser, 1)
	} else {
		s.notPrivate = saturatingCommandCount(s.notPrivate, 1)
	}
}

func (t *TelegramBackend) writeCommandRefusal(transition string, replay bool) error {
	if t.CommandAudit != nil {
		return t.CommandAudit.Write(signerkit.AuditEvent{TS: time.Now(), Status: "approval-" + transition, Approval: &ap.AuditMetadata{Transition: transition, Replay: replay}})
	}
	return nil
}

// No lifecycle commands are registered in production yet. /start retains its legacy handler.
func (t *TelegramBackend) handleApprovalCommand(m *tgbotapi.Message, forwarded bool) {
	reason := "unknown_command"
	switch {
	case m.From == nil || m.From.ID != t.allowedUserID:
		reason = "wrong_user"
	case m.Chat == nil || !m.Chat.IsPrivate() || m.Chat.ID != t.allowedUserID:
		reason = "not_private"
	case forwarded || m.ForwardFrom != nil || m.ForwardFromChat != nil || m.ForwardFromMessageID != 0 || m.ForwardSignature != "" || m.ForwardSenderName != "" || m.ForwardDate != 0 || m.IsAutomaticForward:
		reason = "forwarded"
	case t.commandDrain:
		reason = "redelivered"
	default:
		if handler := t.approvalCommands[m.Command()]; handler != nil {
			handler(m)
			return
		}
	}
	if reason == "wrong_user" || reason == "not_private" {
		t.countCommandRefusal(reason)
		return
	}
	now := t.commandElapsed()
	t.flushCommandRefusals()
	s := &t.commandRefusals
	// One refusal per minute bounds both audit work and shared notification capacity.
	if s.replyLimited && now < s.replyAfter {
		return
	}
	s.replyLimited, s.replyAfter = true, now+commandRefusalInterval
	if err := t.writeCommandRefusal("command_refused{"+reason+"}", reason == "redelivered"); err != nil {
		t.logger.Print("telegram command refusal audit failed")
	}
	chat, err := t.approvalChat()
	if err != nil {
		return
	}
	t.enqueueNotification(func() {
		if _, err := t.bot.Send(tgbotapi.NewMessage(chat, "command refused: "+reason)); err != nil {
			t.logger.Printf("send command refusal: %s", redactToken(err))
		}
	})
}

// The pinned Bot API client predates forward_origin. Preserve it at intake.
type approvalTelegramUpdate struct {
	tgbotapi.Update
	forwarded bool
}

func (u *approvalTelegramUpdate) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &u.Update); err != nil {
		return err
	}
	var fields struct {
		Message struct {
			ForwardOrigin json.RawMessage `json:"forward_origin"`
		} `json:"message"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	u.forwarded = len(fields.Message.ForwardOrigin) != 0 && string(fields.Message.ForwardOrigin) != "null"
	return nil
}

func (t *TelegramBackend) fetchApprovalUpdates(config tgbotapi.UpdateConfig) ([]approvalTelegramUpdate, error) {
	response, err := t.bot.Request(config)
	if err != nil {
		return nil, err
	}
	var updates []approvalTelegramUpdate
	err = json.Unmarshal(response.Result, &updates)
	return updates, err
}
