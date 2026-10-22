package backend

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// ApprovalCallbackRuntime resolves the current generation for every tap.
// Wire once before starting the Telegram poller.
type ApprovalCallbackRuntime interface {
	Current() (*lifecycle.Engine, error)
	Legacy() *lifecycle.LegacyService
}

type telegramApprovalCallbacks struct {
	runtime ApprovalCallbackRuntime
	legacy  *TelegramLegacyNotifier
	mu      sync.Mutex
	queues  map[string][]*tgbotapi.CallbackQuery
	count   int
	ctx     context.Context
	cancel  context.CancelFunc
	joined  sync.WaitGroup
	closed  bool
}

func (t *TelegramBackend) AttachApprovalCallbacks(runtime ApprovalCallbackRuntime, legacy *TelegramLegacyNotifier) error {
	if runtime == nil || runtime.Legacy() == nil || legacy == nil || legacy.backend != t || t.approvalCallbacks != nil {
		return errors.New("telegram: invalid callback runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.approvalCallbacks = &telegramApprovalCallbacks{runtime: runtime, legacy: legacy, queues: make(map[string][]*tgbotapi.CallbackQuery), ctx: ctx, cancel: cancel}
	return nil
}

// CloseApprovalCallbacks stops intake and joins the bounded early-tap queues.
// Call it before closing the runtime so refusal audits can still be written.
func (t *TelegramBackend) CloseApprovalCallbacks() {
	c := t.approvalCallbacks
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.joined.Wait()
}

func parseApprovalCallback(data string) (string, string, string, bool) {
	fields := strings.Split(data, ":")
	if len(fields) != 4 || fields[0] != "v" || !ap.ValidCardHandle(fields[2]) || !ap.ValidChallenge(fields[3]) {
		return "", "", "", false
	}
	switch fields[1] {
	case "a":
		return ap.VoteApprove, fields[2], fields[3], true
	case "d":
		return ap.VoteDeny, fields[2], fields[3], true
	default:
		return "", "", "", false
	}
}

func (t *TelegramBackend) answerApprovalCallback(cb *tgbotapi.CallbackQuery, text string) {
	t.enqueueNotification(func() {
		if _, err := t.bot.Request(tgbotapi.NewCallback(cb.ID, text)); err != nil && t.logger != nil {
			t.logger.Printf("answer approval callback: %s", redactToken(err))
		}
	})
}

func (t *TelegramBackend) handleApprovalCallback(cb *tgbotapi.CallbackQuery) {
	_, handle, challenge, ok := parseApprovalCallback(cb.Data)
	if !ok {
		t.answerApprovalCallback(cb, "invalid request")
		return
	}
	c := t.approvalCallbacks
	if c == nil {
		t.answerApprovalCallback(cb, lifecycle.LegacyTapRefused)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ready, legacy, err := c.readiness(handle, challenge)
	bound := cb.From != nil && cb.From.ID == t.allowedUserID && cb.Message != nil && cb.Message.Chat != nil
	if bound {
		if legacy {
			bound = cb.Message.Chat.ID == ready.Destination.ChatID
		} else {
			bound = cb.Message.Chat.ID == t.allowedUserID && cb.Message.Chat.IsPrivate()
		}
	}
	if c.closed || !bound {
		t.castApprovalCallback(cb, true, nil, nil)
		return
	}
	if queue, exists := c.queues[handle]; exists {
		if len(queue) >= 4 || c.count >= 64 {
			t.answerApprovalCallback(cb, "not ready — tap again")
			return
		}
		c.queues[handle] = append(queue, cb)
		c.count++
		return
	}
	if err != nil || !ready.Pending {
		t.castApprovalCallback(cb, false, nil, nil)
		return
	}
	if c.count >= 64 {
		t.answerApprovalCallback(cb, "not ready — tap again")
		return
	}
	deadline := c.runtime.Legacy().CallbackElapsed() + 10*time.Second
	c.queues[handle] = []*tgbotapi.CallbackQuery{cb}
	c.count++
	c.joined.Add(1)
	go t.waitApprovalCallbacks(handle, challenge, ready, deadline)
}

func (c *telegramApprovalCallbacks) readiness(handle, challenge string) (lifecycle.CallbackReadiness, bool, error) {
	legacy := c.runtime.Legacy()
	engine, err := c.runtime.Current()
	var ready lifecycle.CallbackReadiness
	if err == nil {
		ready, err = engine.CallbackReadiness(handle, challenge)
	}
	if legacy.HasHandle(handle) {
		// A handle shared by both planes cannot identify a unique authority.
		if err == nil {
			return lifecycle.CallbackReadiness{}, true, errors.New("ambiguous callback handle")
		}
		ready, err = legacy.CallbackReadiness(handle, challenge)
		return ready, true, err
	}
	return ready, false, err
}

func (t *TelegramBackend) waitApprovalCallbacks(handle, challenge string, ready lifecycle.CallbackReadiness, deadline time.Duration) {
	c := t.approvalCallbacks
	defer c.joined.Done()
	timer := time.NewTimer(max(0, deadline-c.runtime.Legacy().CallbackElapsed()))
	defer timer.Stop()
	refused := false
	generationClosed := ready.Closed
	for ready.Pending && !refused {
		select {
		case <-c.ctx.Done():
			refused = true
		case <-ready.Closed:
			refused = true
		case <-timer.C:
			remaining := deadline - c.runtime.Legacy().CallbackElapsed()
			refused = remaining <= 0
			if !refused {
				timer.Reset(remaining)
			}
		case <-ready.Changed:
		}
		c.mu.Lock()
		select {
		case <-ready.Closed:
			refused = true
		default:
		}
		next, _, err := c.readiness(handle, challenge)
		if err != nil {
			refused = true
		}
		ready = next
		c.mu.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-generationClosed:
		refused = true
	default:
	}
	for _, cb := range c.queues[handle] {
		t.castApprovalCallback(cb, refused || c.closed, generationClosed, &deadline)
		c.count--
	}
	delete(c.queues, handle)
}

// The lifecycle owns replay, revision, expiry, and challenge validation. A failed
// transport binding is submitted with an invalid challenge solely for its audit.
func (t *TelegramBackend) castApprovalCallback(cb *tgbotapi.CallbackQuery, refuse bool, generation <-chan struct{}, deadline *time.Duration) {
	c := t.approvalCallbacks
	decision, handle, challenge, _ := parseApprovalCallback(cb.Data)
	vote := ap.CastVote{Operator: "telegram:" + strconv.FormatInt(t.allowedUserID, 10), Decision: decision, Authn: "telegram", Card: &ap.CardTap{Handle: handle, Challenge: challenge}}
	if cb.Message != nil {
		vote.Card.MsgID = int64(cb.Message.MessageID)
	}
	legacy := c.runtime.Legacy()
	engine, engineErr := c.runtime.Current()
	if generation != nil && engineErr != nil && !legacy.HasHandle(handle) {
		refuse = true
	}
	knownV2 := false
	var lookupErr error
	if engineErr == nil {
		var readiness lifecycle.CallbackReadiness
		readiness, lookupErr = engine.CallbackReadiness(handle, challenge)
		knownV2 = lookupErr == nil
		if generation != nil && readiness.Closed != generation && !legacy.HasHandle(handle) {
			refuse = true
		}
	}
	var lookupCode *ap.CodeError
	unknownV2 := errors.As(lookupErr, &lookupCode) && lookupCode.Code == ap.CodeNotFound
	if engineErr == nil && !knownV2 && !unknownV2 && !(legacy.HasHandle(handle) && callbackUnavailable(lookupErr)) {
		if generation != nil && callbackUnavailable(lookupErr) {
			t.refuseUnavailableCallback(cb, vote)
			return
		}
		t.answerApprovalCallback(cb, approvalVoteAnswer(ap.Answer{}, lookupErr, decision))
		return
	}
	if legacy.HasHandle(handle) && knownV2 {
		t.answerApprovalCallback(cb, lifecycle.LegacyTapRefused)
		return
	}
	if !knownV2 && (legacy.HasHandle(handle) || engineErr == nil || refuse) {
		if !c.legacy.matchesCallback(handle, cb) {
			refuse = true
		}
		if refuse || (deadline != nil && legacy.CallbackElapsed() >= *deadline) {
			vote.Card.Challenge = ""
		}
		_, err := legacy.VoteLegacy(vote, func(result lifecycle.LegacyTapResult) { t.answerApprovalCallback(cb, result.Answer) })
		if err != nil {
			t.answerApprovalCallback(cb, approvalVoteAnswer(ap.Answer{}, err, decision))
		}
		return
	}
	if cb.From == nil || cb.From.ID != t.allowedUserID || cb.Message == nil || cb.Message.Chat == nil || cb.Message.Chat.ID != t.allowedUserID || !cb.Message.Chat.IsPrivate() {
		refuse = true
	}
	if engineErr != nil {
		t.answerApprovalCallback(cb, approvalVoteAnswer(ap.Answer{}, engineErr, decision))
		return
	}
	if deadline != nil && legacy.CallbackElapsed() >= *deadline {
		refuse = true
	}
	if refuse {
		vote.Card.Challenge = ""
	}
	answer, err := engine.Vote(vote)
	var voteCode *ap.CodeError
	if generation != nil && errors.As(err, &voteCode) && voteCode.Code == ap.CodeLifecycleUnavailable {
		t.refuseUnavailableCallback(cb, vote)
		return
	}
	if err == nil && answer.Noise && !refuse {
		if state, readErr := engine.CallbackReadiness(handle, challenge); readErr == nil && state.Decision != "" && state.MessageID == vote.Card.MsgID {
			t.answerApprovalCallback(cb, state.Decision)
			return
		}
	}
	t.answerApprovalCallback(cb, approvalVoteAnswer(answer, err, decision))
}

func callbackUnavailable(err error) bool {
	var code *ap.CodeError
	return errors.As(err, &code) && (code.Code == ap.CodeLifecycleUnavailable || code.Code == ap.CodeStorageUncertain)
}

func (t *TelegramBackend) refuseUnavailableCallback(cb *tgbotapi.CallbackQuery, vote ap.CastVote) {
	vote.Card.Challenge = ""
	_, err := t.approvalCallbacks.runtime.Legacy().VoteLegacy(vote, func(result lifecycle.LegacyTapResult) { t.answerApprovalCallback(cb, result.Answer) })
	if err != nil {
		t.answerApprovalCallback(cb, approvalVoteAnswer(ap.Answer{}, err, vote.Decision))
	}
}

func approvalVoteAnswer(answer ap.Answer, err error, decision string) string {
	var code *ap.CodeError
	if errors.As(err, &code) && (code.Code == ap.CodeStorageUncertain || code.Code == ap.CodeLifecycleUnavailable) {
		return "not recorded yet — tap again"
	}
	if answer.Reason == "stale_revision" || answer.Reason == "retired" {
		return "card updated — tap again"
	}
	if err != nil || answer.Noise || answer.Reason != "" {
		return lifecycle.LegacyTapRefused
	}
	if decision == ap.VoteApprove {
		return "approved"
	}
	return "denied"
}

type legacyCallbackBinding struct{ chat, message int64 }

func (n *TelegramLegacyNotifier) matchesCallback(handle string, cb *tgbotapi.CallbackQuery) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if cb.From == nil || cb.From.ID != n.backend.allowedUserID || cb.Message == nil || cb.Message.Chat == nil {
		return false
	}
	for _, entry := range n.entries {
		data := entry.artifact.Data()
		if data.Context.Handle == handle {
			return entry.messageID > 0 && entry.messageID == int64(cb.Message.MessageID) && data.Context.Destination.ChatID == cb.Message.Chat.ID
		}
	}
	binding, ok := n.bindings[handle]
	return ok && binding.message == int64(cb.Message.MessageID) && binding.chat == cb.Message.Chat.ID
}
