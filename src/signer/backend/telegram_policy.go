package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	policyCommitRetryDelay       = 100 * time.Millisecond
	policyTerminalCommitAttempts = 3
)

type policyPendingKey struct {
	purpose   string
	requestID string
	challenge string
}

type policyPendingPhase uint8

const (
	policyPendingRegistered policyPendingPhase = iota
	policyPendingActive
	policyPendingResolved
	policyPendingUncertain
)

type policyPendingState struct {
	mu        sync.Mutex
	phase     policyPendingPhase
	hooks     signerkit.BaseManifestDecisionHooks
	chatID    int64
	messageID int
	cardText  string
	ch        chan signerkit.BaseManifestApprovalResult
	done      chan struct{}
	stopOnce  sync.Once
	pubOnce   sync.Once
}

func (ps *policyPendingState) stop() {
	ps.stopOnce.Do(func() { close(ps.done) })
}

func (ps *policyPendingState) publish(result signerkit.BaseManifestApprovalResult) {
	ps.pubOnce.Do(func() {
		ps.ch <- result
		close(ps.ch)
	})
}

// RequestBaseManifest implements the policy-only Telegram approval path. It
// deliberately does not use the ordinary command renderer, explainer, pending
// map, or approve:/deny: callback namespace.
func (t *TelegramBackend) RequestBaseManifest(ctx context.Context, req signerkit.BaseManifestApprovalRequest) (<-chan signerkit.BaseManifestApprovalResult, error) {
	chatID, ok, err := t.chatStore.Load()
	if err != nil {
		return nil, fmt.Errorf("telegram policy: chatstore load: %w", err)
	}
	if !ok {
		return nil, errors.New("telegram policy: no private DM captured — operator must /start the bot")
	}
	// A Telegram private chat with a user has that user's numeric ID. Refuse a
	// legacy/group linkage rather than exposing permanent-policy material there.
	if chatID != t.allowedUserID {
		return nil, errors.New("telegram policy: linked chat is not the allowed user's private DM")
	}
	action, requestID, challenge, parsed := parsePolicyCallbackData("p:a:" + req.RequestID + ":" + req.CallbackChallenge)
	if !parsed || action != "a" || requestID != req.RequestID || challenge != req.CallbackChallenge {
		return nil, errors.New("telegram policy: invalid request id or callback challenge")
	}

	review, err := renderPolicyReview(req, t.reqTimeout, t.RedactSalt, t.RedactRules)
	if err != nil {
		return nil, err
	}
	t.policyNotifyMu.Lock()
	defer t.policyNotifyMu.Unlock()
	// Render the entire bounded review before any network call. A renderer
	// failure therefore exposes neither a partial preview nor a decision card.
	for i, part := range review.DetailParts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("telegram policy: notification canceled before detail part %d: %w", i+1, err)
		}
		if _, err := t.bot.Send(tgbotapi.NewMessage(chatID, part)); err != nil {
			return nil, fmt.Errorf("telegram policy: send detail part %d: %s", i+1, redactToken(err))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("telegram policy: notification canceled before decision card: %w", err)
	}

	key := policyPendingKey{purpose: policywire.Purpose, requestID: req.RequestID, challenge: req.CallbackChallenge}
	ps := &policyPendingState{
		phase:    policyPendingRegistered,
		hooks:    req.DecisionHooks,
		chatID:   chatID,
		cardText: review.DecisionCard,
		ch:       make(chan signerkit.BaseManifestApprovalResult, 1),
		done:     make(chan struct{}),
	}
	if _, loaded := t.policyPending.LoadOrStore(key, ps); loaded {
		return nil, errors.New("telegram policy: duplicate live callback identity")
	}

	card := tgbotapi.NewMessage(chatID, review.DecisionCard)
	card.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✓ Approve PERMANENT POLICY", "p:a:"+req.RequestID+":"+req.CallbackChallenge),
			tgbotapi.NewInlineKeyboardButtonData("✗ Deny", "p:d:"+req.RequestID+":"+req.CallbackChallenge),
		),
	)
	sent, err := t.bot.Send(card)
	if err != nil {
		t.policyPending.CompareAndDelete(key, ps)
		ps.stop()
		return nil, fmt.Errorf("telegram policy: send decision card: %s", redactToken(err))
	}
	if sent.MessageID <= 0 {
		t.policyPending.CompareAndDelete(key, ps)
		ps.stop()
		return nil, errors.New("telegram policy: decision card returned an invalid message id")
	}
	ps.mu.Lock()
	ps.messageID = sent.MessageID
	ps.mu.Unlock()
	if err := ctx.Err(); err != nil {
		t.policyPending.CompareAndDelete(key, ps)
		ps.stop()
		t.editPolicyCard(ps, "⚠️ Policy request was canceled before activation; this card is disabled.")
		return nil, fmt.Errorf("telegram policy: notification canceled before activation: %w", err)
	}

	// The callback remains visibly retryable but inert until the journal has
	// durably activated the challenge.
	if err := req.DecisionHooks.Activate(ctx); err != nil {
		t.policyPending.CompareAndDelete(key, ps)
		ps.stop()
		t.editPolicyCard(ps, "⚠️ Policy request could not be activated; this card is disabled.")
		return nil, fmt.Errorf("telegram policy: activate decision card: %w", err)
	}
	ps.mu.Lock()
	ps.phase = policyPendingActive
	ps.mu.Unlock()

	go t.watchPolicyRequest(ctx, key, ps)
	return ps.ch, nil
}

func (t *TelegramBackend) watchPolicyRequest(ctx context.Context, key policyPendingKey, ps *policyPendingState) {
	timer := time.NewTimer(t.reqTimeout)
	defer timer.Stop()
	var result signerkit.BaseManifestApprovalResult
	select {
	case <-timer.C:
		result = signerkit.BaseManifestApprovalResult{Status: policywire.StatusTimeout, Kind: signerkit.BaseManifestResultLocalDecision}
	case <-ctx.Done():
		status := policywire.StatusTimeout
		if errors.Is(ctx.Err(), context.Canceled) {
			status = policywire.StatusInterrupted
		}
		result = signerkit.BaseManifestApprovalResult{Status: status, Kind: signerkit.BaseManifestResultLocalDecision}
	case <-ps.done:
		return
	}

	for attempts := 1; ; attempts++ {
		outcome := t.commitPolicyVerdict(key, ps, result)
		switch outcome {
		case policyCommitDurable:
			if result.Status == policywire.StatusTimeout {
				t.editPolicyCard(ps, "⏰ Policy decision expired.")
			} else {
				t.editPolicyCard(ps, "⚠️ Policy decision interrupted.")
			}
			return
		case policyCommitUncertain, policyCommitInactive:
			return
		case policyCommitRetryable:
			if attempts >= policyTerminalCommitAttempts {
				t.failPolicyTerminalCommit(key, ps, result)
				return
			}
			retry := time.NewTimer(policyCommitRetryDelay)
			select {
			case <-retry.C:
			case <-ps.done:
				if !retry.Stop() {
					<-retry.C
				}
				return
			}
		}
	}
}

func (t *TelegramBackend) failPolicyTerminalCommit(key policyPendingKey, ps *policyPendingState, result signerkit.BaseManifestApprovalResult) {
	ps.mu.Lock()
	if ps.phase != policyPendingActive {
		ps.mu.Unlock()
		return
	}
	ps.phase = policyPendingResolved
	t.policyPending.CompareAndDelete(key, ps)
	ps.stop()
	result.BackendError = errors.New("telegram policy: terminal verdict could not be durably committed")
	ps.publish(result)
	ps.mu.Unlock()
	t.editPolicyCard(ps, "⚠️ Policy decision could not be recorded; this card is disabled. Recovery will interrupt the request.")
}

type policyCommitOutcome uint8

const (
	policyCommitInactive policyCommitOutcome = iota
	policyCommitRetryable
	policyCommitDurable
	policyCommitUncertain
)

// commitPolicyVerdict serializes competing arbiters with ps.mu, but it never
// wraps the fallible durable CommitVerdict call in sync.Once. A clean
// pre-commit failure leaves the entry active and retryable; only an explicitly
// uncertain commit disables it and publishes a recovery-only backend error.
func (t *TelegramBackend) commitPolicyVerdict(key policyPendingKey, ps *policyPendingState, result signerkit.BaseManifestApprovalResult) policyCommitOutcome {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.phase != policyPendingActive {
		return policyCommitInactive
	}

	err := ps.hooks.CommitVerdict(context.Background(), result)
	if err != nil {
		if !errors.Is(err, signerkit.ErrPolicyVerdictCommitUncertain) {
			t.logger.Printf("policy verdict commit retryable request_id=%s: %v", key.requestID, err)
			return policyCommitRetryable
		}
		// A read-back acknowledgement can prove that an uncertain replacement
		// did install this exact verdict. Only then may it resolve normally.
		if ackErr := ps.hooks.AcknowledgeVerdict(context.Background(), result); ackErr == nil {
			ps.phase = policyPendingResolved
			t.policyPending.CompareAndDelete(key, ps)
			ps.stop()
			ps.publish(result)
			return policyCommitDurable
		} else {
			ps.phase = policyPendingUncertain
			t.policyPending.CompareAndDelete(key, ps)
			ps.stop()
			result.BackendError = fmt.Errorf("%w: commit=%v; acknowledge=%v", signerkit.ErrPolicyVerdictCommitUncertain, err, ackErr)
			ps.publish(result)
			go t.editPolicyCard(ps, "⚠️ Verdict durability is uncertain; this card is disabled. Recovery will reconcile the journal.")
			return policyCommitUncertain
		}
	}

	ackErr := ps.hooks.AcknowledgeVerdict(context.Background(), result)
	ps.phase = policyPendingResolved
	t.policyPending.CompareAndDelete(key, ps)
	ps.stop()
	if ackErr != nil {
		// Commit returned success, so this is not a pre-commit failure and an
		// opposite verdict is forbidden. Recovery can read the durable state.
		result.BackendError = fmt.Errorf("telegram policy: durable verdict acknowledgement: %w", ackErr)
	}
	ps.publish(result)
	return policyCommitDurable
}

func (t *TelegramBackend) handlePolicyCallback(cb *tgbotapi.CallbackQuery) {
	action, requestID, challenge, ok := parsePolicyCallbackData(cb.Data)
	if !ok {
		t.answerPolicyCallback(cb.ID, "invalid policy request", true)
		return
	}
	key := policyPendingKey{purpose: policywire.Purpose, requestID: requestID, challenge: challenge}
	raw, ok := t.policyPending.Load(key)
	if !ok {
		t.answerPolicyCallback(cb.ID, "expired or already resolved", false)
		return
	}
	ps := raw.(*policyPendingState)

	ps.mu.Lock()
	phase := ps.phase
	chatID, messageID := ps.chatID, ps.messageID
	ps.mu.Unlock()
	if phase == policyPendingRegistered {
		t.answerPolicyCallback(cb.ID, "request is still activating; tap again", false)
		return
	}
	if phase != policyPendingActive {
		t.answerPolicyCallback(cb.ID, "expired or already resolved", false)
		return
	}
	if cb.Message == nil || cb.Message.Chat == nil || cb.Message.Chat.Type != "private" ||
		cb.Message.Chat.ID != chatID || cb.Message.MessageID != messageID {
		t.answerPolicyCallback(cb.ID, "policy card mismatch", true)
		return
	}

	status := policywire.StatusDenied
	if action == "a" {
		status = policywire.StatusApproved
	}
	result := signerkit.BaseManifestApprovalResult{
		Status:             status,
		Kind:               signerkit.BaseManifestResultLocalDecision,
		ApprovedBy:         fmt.Sprintf("id:%d", cb.From.ID),
		OperatorAuthMethod: "telegram",
	}
	switch t.commitPolicyVerdict(key, ps, result) {
	case policyCommitRetryable:
		t.answerPolicyCallback(cb.ID, "could not record decision; tap again", true)
	case policyCommitDurable:
		t.answerPolicyCallback(cb.ID, "decision received; finalizing", false)
		t.editPolicyCard(ps, "Decision received and recorded; finalizing.")
	case policyCommitUncertain:
		t.answerPolicyCallback(cb.ID, "verdict state uncertain; card disabled", true)
	default:
		t.answerPolicyCallback(cb.ID, "expired or already resolved", false)
	}
}

func (t *TelegramBackend) answerPolicyCallback(callbackID, text string, alert bool) {
	var answer tgbotapi.CallbackConfig
	if alert {
		answer = tgbotapi.NewCallbackWithAlert(callbackID, text)
	} else {
		answer = tgbotapi.NewCallback(callbackID, text)
	}
	if _, err := t.bot.Request(answer); err != nil {
		t.logger.Printf("answer policy callback: %s", redactToken(err))
	}
}

func (t *TelegramBackend) editPolicyCard(ps *policyPendingState, footer string) {
	ps.mu.Lock()
	chatID, messageID, cardText := ps.chatID, ps.messageID, ps.cardText
	ps.mu.Unlock()
	if messageID == 0 {
		return
	}
	edit := tgbotapi.NewEditMessageText(chatID, messageID, cardText+"\n\n"+footer)
	if _, err := t.bot.Send(edit); err != nil {
		t.logger.Printf("edit policy card: %s", redactToken(err))
	}
}

func parsePolicyCallbackData(data string) (action, requestID, challenge string, ok bool) {
	parts := strings.Split(data, ":")
	if len(parts) != 4 || parts[0] != "p" || (parts[1] != "a" && parts[1] != "d") {
		return "", "", "", false
	}
	if len(parts[2]) != 35 || !strings.HasPrefix(parts[2], "pm_") || !isLowerHex(parts[2][3:]) {
		return "", "", "", false
	}
	if len(parts[3]) != 16 || !isLowerHex(parts[3]) {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

func isLowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

var _ signerkit.BaseManifestApprovalBackend = (*TelegramBackend)(nil)
