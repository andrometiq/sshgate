package backend

import (
	"encoding/json"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

const approvalUpdateLimit = 100

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
	transition := "command_refused{" + reason + "}"
	if t.CommandAudit != nil {
		if err := t.CommandAudit.Write(signerkit.AuditEvent{TS: time.Now(), Status: "approval-" + transition, Approval: &ap.AuditMetadata{Transition: transition, Replay: true}}); err != nil {
			t.logger.Print("telegram command refusal audit failed")
		}
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
