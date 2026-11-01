package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
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

// AttachApprovalCallbacks registers /renotify; D1b adds the other commands.
// /start retains its legacy handler.
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

// handleRenotify runs only after the E64 gate. It applies Renotify to the one
// record the id resolves to; each refusal is audited without the argument.
func (t *TelegramBackend) handleRenotify(m *tgbotapi.Message) {
	reply, refusal := t.renotify(strings.TrimSpace(m.CommandArguments()))
	if refusal != "" {
		if err := t.writeCommandRefusal("renotify_refused{"+refusal+"}", false); err != nil {
			t.logger.Print("telegram renotify refusal audit failed")
		}
	}
	chat, err := t.approvalChat()
	if err != nil {
		return
	}
	t.enqueueNotification(func() {
		if _, err := t.bot.Send(tgbotapi.NewMessage(chat, reply)); err != nil {
			t.logger.Printf("send renotify reply: %s", redactToken(err))
		}
	})
}

// renotify returns the operator reply and, for a refusal, its audit reason.
func (t *TelegramBackend) renotify(id string) (string, string) {
	if id == "" || strings.ContainsAny(id, " \t\n") {
		return "usage: /renotify <handle from /pending>", "usage"
	}
	engine, handle, err := t.approvalCallbacks.runtime.ResolveAdmin(id)
	var answer ap.Answer
	if err == nil {
		answer, err = engine.Renotify(handle)
	}
	var coded *ap.CodeError
	switch {
	case callbackUnavailable(err):
		return "signer recovering — try again", "recovering"
	case errors.As(err, &coded) && coded.Code == ap.CodeNotFound:
		return "no record matches that id", "not_found"
	case errors.As(err, &coded) && coded.Code == ap.CodeInvalidRequest && strings.HasPrefix(coded.Msg, "ambiguous"):
		return coded.Msg, "ambiguous"
	case errors.As(err, &coded) && coded.Code == ap.CodeInvalidRequest:
		return "usage: /renotify <handle from /pending>", "usage"
	case err != nil && answer.Reason == "":
		return "renotify failed — try again", "error"
	case answer.Reason == "already_pending":
		return "re-notify already pending", answer.Reason
	case answer.Reason == "in_progress":
		return "a send is in progress — try again", answer.Reason
	case answer.Reason != "":
		return "renotify refused: " + answer.Reason, answer.Reason
	}
	return "re-notify accepted: a new review and card follow", ""
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
