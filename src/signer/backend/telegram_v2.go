package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	ar "github.com/karthikeyan5/sshgate/src/approvalreview"
)

var errApprovalSendBudget = errors.New("telegram: approval send budget exhausted")

var _ lifecycle.Notifier = (*TelegramBackend)(nil)

type approvalBurst struct {
	backend  *TelegramBackend
	deadline time.Time
}

// Burst holds the policy lock across transport calls and the actor's commits.
func (t *TelegramBackend) Burst(ctx context.Context, fn func(lifecycle.BurstSession) error) error {
	t.policyNotifyMu.Lock()
	defer t.policyNotifyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(&approvalBurst{backend: t, deadline: time.Now().Add(60 * time.Second)})
}

func (t *TelegramBackend) approvalChat() (int64, error) {
	chat, ok, err := t.chatStore.Load()
	if err != nil {
		return 0, errors.New("telegram: linked chat unavailable")
	}
	if !ok || chat != t.allowedUserID {
		return 0, errors.New("telegram: v2 approvals require the allowed user's private chat")
	}
	return chat, nil
}

func approvalView(n lifecycle.Notification) (ar.View, error) {
	snapshot, err := ar.DecodeSnapshot(n.Snapshot)
	if err != nil {
		return ar.View{}, err
	}
	if (n.Revision == 0 && n.AssistState != ap.AssistPreparing) || (n.Revision == 1 && n.AssistState != ap.AssistReady && n.AssistState != ap.AssistUnavailable) || n.Revision < 0 || n.Revision > 1 {
		return ar.View{}, errors.New("telegram: inconsistent assist revision")
	}
	view, err := ar.BuildView(snapshot, ar.Assist{State: n.AssistState, Result: n.Assist})
	if err != nil {
		return ar.View{}, err
	}
	if !ap.ValidRequesterSub(snapshot.Requester) {
		return ar.View{}, errors.New("telegram: invalid local snapshot principal")
	}
	view.Headlines = append(view.Headlines, "Record: "+ap.RecordHandle(ap.RecordKey(snapshot.Requester, snapshot.RequestID)))
	return view, nil
}

func (b *approvalBurst) SendParts(ctx context.Context, n lifecycle.Notification) ([]int64, error) {
	view, err := approvalView(n)
	if err != nil {
		return nil, err
	}
	parts, err := ar.PackParts(view, n.Handle)
	if err != nil {
		return nil, err
	}
	chat, err := b.backend.approvalChat()
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(parts))
	for _, part := range parts {
		id, err := b.send(ctx, tgbotapi.NewMessage(chat, part))
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func approvalCard(n lifecycle.Notification) (string, tgbotapi.InlineKeyboardMarkup, error) {
	if !ap.ValidCardHandle(n.Handle) || !ap.ValidChallenge(n.Challenge) {
		return "", tgbotapi.InlineKeyboardMarkup{}, errors.New("telegram: invalid card identity")
	}
	view, err := approvalView(n)
	if err != nil {
		return "", tgbotapi.InlineKeyboardMarkup{}, err
	}
	text, err := ar.DecisionCard(view, n.Handle, len(n.PartMessageIDs))
	if err != nil {
		return "", tgbotapi.InlineKeyboardMarkup{}, err
	}
	buttons := []tgbotapi.InlineKeyboardButton{}
	if n.Revision == 1 {
		buttons = append(buttons, tgbotapi.NewInlineKeyboardButtonData(view.ApproveLabel, "v:a:"+n.Handle+":"+n.Challenge))
	}
	buttons = append(buttons, tgbotapi.NewInlineKeyboardButtonData(view.DenyLabel, "v:d:"+n.Handle+":"+n.Challenge))
	return text, tgbotapi.NewInlineKeyboardMarkup(buttons), nil
}

func (b *approvalBurst) SendCard(ctx context.Context, n lifecycle.Notification) (int64, error) {
	text, keyboard, err := approvalCard(n)
	if err != nil {
		return 0, err
	}
	chat, err := b.backend.approvalChat()
	if err != nil {
		return 0, err
	}
	msg := tgbotapi.NewMessage(chat, text)
	msg.ReplyMarkup = keyboard
	return b.send(ctx, msg)
}

func (b *approvalBurst) send(ctx context.Context, msg tgbotapi.MessageConfig) (int64, error) {
	budget, cancel := context.WithDeadlineCause(ctx, b.deadline, errApprovalSendBudget)
	defer cancel()
	for {
		if budget.Err() != nil {
			return 0, context.Cause(budget)
		}
		response, err := b.backend.approvalRequest(budget, msg)
		if err != nil && budget.Err() != nil {
			return 0, context.Cause(budget)
		}
		if err == nil {
			var sent tgbotapi.Message
			if err = json.Unmarshal(response.Result, &sent); err != nil || sent.MessageID <= 0 {
				return 0, errors.New("telegram: invalid sent message receipt")
			}
			return int64(sent.MessageID), nil
		}
		var apiError *tgbotapi.Error
		if !errors.As(err, &apiError) || apiError.Code != 429 || apiError.RetryAfter <= 0 {
			return 0, fmt.Errorf("telegram: send approval: %s", redactToken(err))
		}
		// Bound conversion before multiplying Telegram's untrusted integer.
		delay := 61 * time.Second
		if apiError.RetryAfter <= 60 {
			delay = time.Duration(apiError.RetryAfter) * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-budget.Done():
			timer.Stop()
			return 0, context.Cause(budget)
		case <-timer.C:
		}
	}
}

// A per-call client copy attaches cancellation without changing the shared bot.
type approvalHTTPClient struct {
	context context.Context
	client  tgbotapi.HTTPClient
}

func (c approvalHTTPClient) Do(r *http.Request) (*http.Response, error) {
	return c.client.Do(r.WithContext(c.context))
}
func (t *TelegramBackend) approvalRequest(ctx context.Context, config tgbotapi.Chattable) (*tgbotapi.APIResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bot := *t.bot
	bot.Debug = false
	bot.Client = approvalHTTPClient{context: ctx, client: t.bot.Client}
	return bot.Request(config)
}

func (t *TelegramBackend) EditCard(ctx context.Context, id int64, n lifecycle.Notification) (lifecycle.EditOutcome, error) {
	text, keyboard, err := approvalCard(n)
	if err != nil {
		return lifecycle.EditFailed, err
	}
	chat, err := t.approvalChat()
	if err != nil {
		return lifecycle.EditFailed, err
	}
	if id <= 0 {
		return lifecycle.EditFailed, errors.New("telegram: invalid card message ID")
	}
	edit := tgbotapi.NewEditMessageTextAndMarkup(chat, int(id), text, keyboard)
	_, err = t.approvalRequest(ctx, edit)
	if err == nil {
		return lifecycle.EditConfirmed, nil
	}
	var apiError *tgbotapi.Error
	if errors.As(err, &apiError) {
		if apiError.Code == 400 && strings.Contains(apiError.Message, "message is not modified") {
			return lifecycle.EditConfirmed, nil
		}
		if apiError.Code >= 400 && apiError.Code < 500 && apiError.Code != 429 {
			return lifecycle.EditFailed, fmt.Errorf("telegram: edit approval: %s", redactToken(err))
		}
	}
	return lifecycle.EditPossible, fmt.Errorf("telegram: edit approval: %s", redactToken(err))
}

func (t *TelegramBackend) editApprovalText(ctx context.Context, id int64, text string) error {
	chat, err := t.approvalChat()
	if err != nil {
		return err
	}
	if id <= 0 {
		return errors.New("telegram: invalid message ID")
	}
	edit := tgbotapi.NewEditMessageTextAndMarkup(chat, int(id), text, tgbotapi.InlineKeyboardMarkup{InlineKeyboard: [][]tgbotapi.InlineKeyboardButton{}})
	_, err = t.approvalRequest(ctx, edit)
	var apiError *tgbotapi.Error
	if errors.As(err, &apiError) && apiError.Code == 400 && strings.Contains(apiError.Message, "message is not modified") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("telegram: edit approval: %s", redactToken(err))
	}
	return nil
}
func (t *TelegramBackend) MarkIncomplete(ctx context.Context, id int64) error {
	return t.editApprovalText(ctx, id, "INCOMPLETE — NOT APPROVABLE")
}
func (t *TelegramBackend) EditStatus(ctx context.Context, id int64, state string) error {
	text := "Approval: " + state
	switch state {
	case "approved", "denied", "canceled", "expired", "error":
	case "expired_unclaimed":
		text = "signer-derived: approved — not executed: nothing claimed it before its signatures expired"
	case "unreported":
		text = "signer-derived: approved and claimed — no execution report arrived; outcome unknown"
	default:
		if state == "not_executable" || strings.HasPrefix(state, "not_executable:") {
			text = "signer-derived: " + state
		} else {
			return errors.New("telegram: unsupported approval display state " + strconv.Quote(state))
		}
	}
	return t.editApprovalText(ctx, id, text)
}
