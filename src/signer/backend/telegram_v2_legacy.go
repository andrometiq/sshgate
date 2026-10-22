package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ar "github.com/karthikeyan5/sshgate/src/approvalreview"
)

// TelegramLegacyNotifier delivers the daemon's frozen shared-renderer artifact.
// Construct it with the linked destination; unlike v2, legacy allows group chats.
// The owner must Release each instance when its request finishes, including when
// preparation or delivery is abandoned. Release must follow any terminal edit.
type TelegramLegacyNotifier struct {
	backend     *TelegramBackend
	destination lifecycle.LegacyDestination
	mu          sync.Mutex
	entries     map[string]*legacyDeliveryEntry
}

type legacyDeliveryEntry struct {
	artifact  *lifecycle.PreparedLegacyApproval
	started   bool
	messageID int64
}

var _ lifecycle.LegacyNotifier = (*TelegramLegacyNotifier)(nil)

func NewTelegramLegacyNotifier(backend *TelegramBackend, destination lifecycle.LegacyDestination) (*TelegramLegacyNotifier, error) {
	if backend == nil || destination.ChatID == 0 || destination.TopicID < 0 {
		return nil, errors.New("telegram: invalid legacy destination")
	}
	return &TelegramLegacyNotifier{backend: backend, destination: destination, entries: make(map[string]*legacyDeliveryEntry)}, nil
}

func (n *TelegramLegacyNotifier) Destination() lifecycle.LegacyDestination { return n.destination }

// Prepare installs an independent immutable copy before lifecycle compares it.
func (n *TelegramLegacyNotifier) Prepare(artifact *lifecycle.PreparedLegacyApproval) error {
	if artifact == nil {
		return errors.New("telegram: missing legacy artifact")
	}
	data := artifact.Data()
	frozen := *artifact // Its private backing data is immutable; copy the replaceable value.
	if data.Context.Destination != n.destination {
		return errors.New("telegram: legacy destination mismatch")
	}
	if len(data.Payload) > ar.MaxMessages {
		return errors.New("telegram: legacy review too large")
	}
	total := 0
	for _, message := range data.Payload {
		total += len(message.Bytes)
		if len(message.Bytes) >= ar.PartBytes || !utf8.Valid(message.Bytes) {
			return errors.New("telegram: invalid legacy message")
		}
	}
	if total > ar.MaxReviewBytes {
		return errors.New("telegram: legacy review too large")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.entries[data.Instance]; exists {
		return errors.New("telegram: legacy instance already prepared")
	}
	n.entries[data.Instance] = &legacyDeliveryEntry{artifact: &frozen}
	return nil
}

func (n *TelegramLegacyNotifier) Prepared(instance string) (*lifecycle.PreparedLegacyApproval, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry := n.entries[instance]
	if entry == nil {
		return nil, errors.New("telegram: unknown legacy instance")
	}
	return lifecycle.NewPreparedLegacyApproval(entry.artifact.Data())
}

// Release forgets transport material, never the lifecycle's decision or tombstone.
func (n *TelegramLegacyNotifier) Release(instance string) {
	n.mu.Lock()
	delete(n.entries, instance)
	n.mu.Unlock()
}

func (n *TelegramLegacyNotifier) Deliver(ctx context.Context, artifact *lifecycle.PreparedLegacyApproval) (lifecycle.LegacyDelivery, error) {
	if artifact == nil {
		return lifecycle.LegacyDelivery{}, errors.New("telegram: missing legacy artifact")
	}
	data := artifact.Data()
	n.mu.Lock()
	entry := n.entries[data.Instance]
	if entry == nil || entry.started || !reflect.DeepEqual(entry.artifact.Data(), data) {
		n.mu.Unlock()
		return lifecycle.LegacyDelivery{}, errors.New("telegram: legacy artifact mismatch or already sent")
	}
	entry.started = true
	n.mu.Unlock()
	err := n.backend.Burst(ctx, func(_ lifecycle.BurstSession) error {
		burst := &approvalBurst{backend: n.backend, deadline: time.Now().Add(60 * time.Second)}
		ids := make([]int64, 0, len(data.Payload))
		for i, message := range data.Payload {
			params := tgbotapi.Params{"chat_id": strconv.FormatInt(data.Context.Destination.ChatID, 10), "text": string(message.Bytes)}
			if data.Context.Destination.TopicID != 0 {
				params["message_thread_id"] = strconv.FormatInt(data.Context.Destination.TopicID, 10)
			}
			if i == len(data.Payload)-1 {
				keyboard := tgbotapi.NewInlineKeyboardMarkup(tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData(message.ApproveLabel, "v:a:"+data.Context.Handle+":"+data.Context.Challenge),
					tgbotapi.NewInlineKeyboardButtonData(message.DenyLabel, "v:d:"+data.Context.Handle+":"+data.Context.Challenge)))
				raw, err := json.Marshal(keyboard)
				if err != nil {
					return err
				}
				params["reply_markup"] = string(raw)
			}
			id, err := burst.sendRequest(ctx, func(ctx context.Context) (*tgbotapi.APIResponse, error) { return n.request(ctx, "sendMessage", params) })
			if err != nil {
				return &legacyDeliveryError{cause: err, notifier: n, chat: data.Context.Destination.ChatID, ids: ids}
			}
			ids = append(ids, id)
		}
		n.mu.Lock()
		entry.messageID = ids[len(ids)-1]
		n.mu.Unlock()
		return nil
	})
	return lifecycle.LegacyDelivery{AllDelivered: err == nil}, err
}

// Cleanup material outlives the prepared entry; the lifecycle runs it only
// after recording failure, under its own bounded cancellation context.
type legacyDeliveryError struct {
	cause    error
	notifier *TelegramLegacyNotifier
	chat     int64
	ids      []int64
}

func (e *legacyDeliveryError) Error() string { return e.cause.Error() }
func (e *legacyDeliveryError) Unwrap() error { return e.cause }
func (e *legacyDeliveryError) MarkIncomplete(ctx context.Context) {
	for _, id := range e.ids {
		if ctx.Err() != nil {
			return
		}
		_ = e.notifier.edit(ctx, e.chat, id, "INCOMPLETE — NOT APPROVABLE")
	}
}

func (n *TelegramLegacyNotifier) request(ctx context.Context, method string, params tgbotapi.Params) (*tgbotapi.APIResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bot := *n.backend.bot
	bot.Debug = false
	bot.Client = approvalHTTPClient{context: ctx, client: bot.Client}
	return bot.MakeRequest(method, params)
}

func (n *TelegramLegacyNotifier) edit(ctx context.Context, chat, id int64, text string) error {
	_, err := n.request(ctx, "editMessageText", tgbotapi.Params{"chat_id": strconv.FormatInt(chat, 10), "message_id": strconv.FormatInt(id, 10), "text": text, "reply_markup": `{"inline_keyboard":[]}`})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var apiError *tgbotapi.Error
	if errors.As(err, &apiError) && apiError.Code == 400 && strings.Contains(apiError.Message, "message is not modified") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("telegram: edit legacy approval: %s", redactToken(err))
	}
	return nil
}

func (n *TelegramLegacyNotifier) EditStatus(ctx context.Context, artifact *lifecycle.PreparedLegacyApproval, status string) error {
	switch status {
	case "approved", "denied", "expired":
	default:
		return errors.New("telegram: invalid legacy status")
	}
	if artifact == nil {
		return errors.New("telegram: missing legacy artifact")
	}
	data := artifact.Data()
	n.mu.Lock()
	entry := n.entries[data.Instance]
	if entry == nil || entry.messageID <= 0 || !reflect.DeepEqual(entry.artifact.Data(), data) {
		n.mu.Unlock()
		return errors.New("telegram: legacy card not delivered")
	}
	id := entry.messageID
	n.mu.Unlock()
	return n.edit(ctx, data.Context.Destination.ChatID, id, string(data.Payload[len(data.Payload)-1].Bytes)+"\nApproval: "+status)
}
