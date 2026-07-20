package backend_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

type policyHookSpy struct {
	mu           sync.Mutex
	events       []string
	commits      []signerkit.BaseManifestApprovalResult
	activateErr  error
	commitErrors []error
	ackError     error
}

type policyExplainerSpy struct {
	mu     sync.Mutex
	calls  int
	inputs [][]string
}

func (s *policyExplainerSpy) Explain(_ context.Context, commands []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.inputs = append(s.inputs, append([]string(nil), commands...))
	return nil, errors.New("policy content must never reach the explainer")
}

func (s *policyExplainerSpy) snapshot() (int, [][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([][]string(nil), s.inputs...)
}

func (h *policyHookSpy) Activate(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, "activate")
	return h.activateErr
}

func (h *policyHookSpy) CommitVerdict(_ context.Context, result signerkit.BaseManifestApprovalResult) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, "commit")
	h.commits = append(h.commits, result)
	if len(h.commitErrors) == 0 {
		return nil
	}
	err := h.commitErrors[0]
	h.commitErrors = h.commitErrors[1:]
	return err
}

func (h *policyHookSpy) AcknowledgeVerdict(context.Context, signerkit.BaseManifestApprovalResult) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, "ack")
	return h.ackError
}

func (h *policyHookSpy) snapshot() ([]string, []signerkit.BaseManifestApprovalResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...), append([]signerkit.BaseManifestApprovalResult(nil), h.commits...)
}

func telegramPolicyRequest(t *testing.T, hooks signerkit.BaseManifestDecisionHooks) signerkit.BaseManifestApprovalRequest {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	identity, err := policy.NewShellExactIdentity([]byte("printf policy-review"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthOutOfBand,
		Entries: []policy.BaseEntry{{
			ID: "pa_oob_55555555555555555555555555555555", Identity: identity,
			Source: policy.EntrySourceOutOfBand,
		}},
	}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return signerkit.BaseManifestApprovalRequest{
		RequestID: "pm_55555555555555555555555555555555", HostKeyFP: host,
		ExpectedSignerKeyID: keyID, Payload: payload, FrozenPublicKey: public,
		Bootstrap: true, CallbackChallenge: "5555555555555555", DecisionHooks: hooks,
	}
}

func telegramMultiPartPolicyRequest(t *testing.T, hooks signerkit.BaseManifestDecisionHooks) signerkit.BaseManifestApprovalRequest {
	t.Helper()
	req := telegramPolicyRequest(t, hooks)
	manifest, err := policy.ParseBaseManifest(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Entries = make([]policy.BaseEntry, 32)
	for i := range manifest.Entries {
		literal := []byte(fmt.Sprintf("printf policy-review-%02d", i))
		identity, err := policy.NewShellExactIdentity(literal)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Entries[i] = policy.BaseEntry{
			ID:       fmt.Sprintf("pa_oob_%032x", i+1),
			Identity: identity,
			Source:   policy.EntrySourceOutOfBand,
		}
	}
	req.Payload, err = policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func startPolicyBackend(t *testing.T, timeout time.Duration) (*backend.TelegramBackend, *fakeTelegram, context.CancelFunc) {
	t.Helper()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedUserID); err != nil {
		t.Fatal(err)
	}
	tb := newTestBackend(t, fake, store, timeout)
	runCtx, stop := context.WithCancel(context.Background())
	if err := tb.Run(runCtx); err != nil {
		stop()
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return tb, fake, stop
}

func TestTelegramPolicyCallbackValidatesCardAndCommitsInOrder(t *testing.T) {
	tb, fake, _ := startPolicyBackend(t, time.Second)
	hooks := &policyHookSpy{commitErrors: []error{errors.New("clean pre-commit failure")}}
	request := telegramPolicyRequest(t, hooks)
	ch, err := tb.RequestBaseManifest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	messages := fake.sentSnapshot()
	if len(messages) < 2 {
		t.Fatalf("messages = %d; want detail(s) plus card", len(messages))
	}
	for i, message := range messages[:len(messages)-1] {
		if message.ReplyMarkup != "" {
			t.Errorf("detail %d carried buttons", i+1)
		}
		if strings.Contains(message.Text, "printf policy-review") {
			t.Errorf("detail %d exposed raw literal without a configured policy redactor", i+1)
		}
	}
	card := messages[len(messages)-1]
	if card.ReplyMarkup == "" {
		t.Fatal("decision card has no buttons")
	}
	cardID := 1000 + len(messages) - 1
	callback := "p:a:" + request.RequestID + ":" + request.CallbackChallenge
	fake.pushCallback(allowedUserID+1, "intruder", callback, cardID, allowedUserID)
	fake.pushCallback(allowedUserID, "optional-name", "p:a:"+request.RequestID+":aaaaaaaaaaaaaaaa", cardID, allowedUserID)
	fake.pushCallback(allowedUserID, "optional-name", callback, cardID, allowedUserID+1)
	fake.pushCallback(allowedUserID, "optional-name", callback, cardID+1, allowedUserID)
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 4 })
	_, commits := hooks.snapshot()
	if len(commits) != 0 {
		t.Fatal("mismatched message id reached durable hook")
	}

	// The first linked click gets a clean pre-commit failure and stays live.
	fake.pushCallback(allowedUserID, "optional-name", callback, cardID, allowedUserID)
	waitFor(t, time.Second, func() bool {
		_, got := hooks.snapshot()
		return len(got) == 1
	})
	select {
	case got := <-ch:
		t.Fatalf("clean failure consumed arbitration: %#v", got)
	default:
	}
	fake.pushCallback(allowedUserID, "different-name", callback, cardID, allowedUserID)
	var result signerkit.BaseManifestApprovalResult
	select {
	case result = <-ch:
	case <-time.After(time.Second):
		t.Fatal("policy callback did not resolve")
	}
	if result.Status != policywire.StatusApproved || result.ApprovedBy != fmt.Sprintf("id:%d", allowedUserID) || result.OperatorAuthMethod != "telegram" {
		t.Fatalf("result = %#v", result)
	}
	events, commits := hooks.snapshot()
	if fmt.Sprint(events) != "[activate commit commit ack]" || len(commits) != 2 {
		t.Fatalf("hook events=%v commits=%d", events, len(commits))
	}
	waitFor(t, time.Second, func() bool { return len(fake.editsSnapshot()) > 0 })
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 6 })
	answers := fake.callbackAnswersSnapshot()
	if got := answers[len(answers)-1].Text; got != "decision received; finalizing" {
		t.Fatalf("durable callback answer = %q", got)
	}
	lastEdit := fake.editsSnapshot()[len(fake.editsSnapshot())-1].Text
	if !strings.Contains(lastEdit, "Decision received and recorded; finalizing") || strings.Contains(lastEdit, "Approved") || strings.Contains(lastEdit, "Denied") || strings.Contains(lastEdit, "delivered") {
		t.Fatalf("premature terminal policy UI: %q", lastEdit)
	}
}

func TestTelegramPolicyFinalSendAndActivationFailuresNeverCreateUsableDecision(t *testing.T) {
	t.Run("first-detail-send", func(t *testing.T) {
		fake := newFakeTelegram(t)
		store := &backend.MemChatStore{}
		if err := store.Save(allowedUserID); err != nil {
			t.Fatal(err)
		}
		tb := newTestBackend(t, fake, store, time.Second)
		fake.sendMessageFailCode = 500
		fake.sendMessageFailAt = 1
		hooks := &policyHookSpy{}
		if _, err := tb.RequestBaseManifest(context.Background(), telegramPolicyRequest(t, hooks)); err == nil {
			t.Fatal("detail failure returned success")
		}
		events, _ := hooks.snapshot()
		if len(events) != 0 || len(fake.sentSnapshot()) != 0 {
			t.Fatalf("detail failure exposed or activated policy: events=%v messages=%#v", events, fake.sentSnapshot())
		}
	})

	t.Run("final-send", func(t *testing.T) {
		fake := newFakeTelegram(t)
		store := &backend.MemChatStore{}
		if err := store.Save(allowedUserID); err != nil {
			t.Fatal(err)
		}
		tb := newTestBackend(t, fake, store, time.Second)
		fake.sendMessageFailCode = 500
		fake.sendMessageFailAt = 2 // one detail part succeeds; the final card fails
		hooks := &policyHookSpy{}
		if _, err := tb.RequestBaseManifest(context.Background(), telegramPolicyRequest(t, hooks)); err == nil {
			t.Fatal("final decision-card failure returned success")
		}
		events, _ := hooks.snapshot()
		if len(events) != 0 {
			t.Fatalf("send failure activated hooks: %v", events)
		}
		messages := fake.sentSnapshot()
		if len(messages) != 1 || messages[0].ReplyMarkup != "" {
			t.Fatalf("partial failure left usable decision: %#v", messages)
		}
	})

	t.Run("activate", func(t *testing.T) {
		tb, fake, _ := startPolicyBackend(t, time.Second)
		hooks := &policyHookSpy{activateErr: errors.New("activation rejected")}
		request := telegramPolicyRequest(t, hooks)
		if _, err := tb.RequestBaseManifest(context.Background(), request); err == nil {
			t.Fatal("activation failure returned success")
		}
		messages := fake.sentSnapshot()
		cardID := 1000 + len(messages) - 1
		fake.pushCallback(allowedUserID, "u", "p:a:"+request.RequestID+":"+request.CallbackChallenge, cardID, allowedUserID)
		waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) > 0 })
		_, commits := hooks.snapshot()
		if len(commits) != 0 {
			t.Fatalf("disabled activation-failed card committed: %#v", commits)
		}
		waitFor(t, time.Second, func() bool { return len(fake.editsSnapshot()) > 0 })
		if !strings.Contains(fake.editsSnapshot()[0].Text, "could not be activated") {
			t.Fatalf("activation failure card not disabled: %#v", fake.editsSnapshot())
		}
	})
}

func TestTelegramPolicyMultipartMiddleAndLastDetailSendFailures(t *testing.T) {
	// Probe the production packer once so this transport test stays correct if
	// fixed header sizes change. The fixture must produce at least three detail
	// parts, making "middle" and "last detail" distinct failure points.
	probeFake := newFakeTelegram(t)
	probeStore := &backend.MemChatStore{}
	if err := probeStore.Save(allowedUserID); err != nil {
		t.Fatal(err)
	}
	probeBackend := newTestBackend(t, probeFake, probeStore, time.Second)
	probeCtx, probeCancel := context.WithCancel(context.Background())
	probeCh, err := probeBackend.RequestBaseManifest(probeCtx, telegramMultiPartPolicyRequest(t, &policyHookSpy{}))
	if err != nil {
		probeCancel()
		t.Fatal(err)
	}
	detailCount := len(probeFake.sentSnapshot()) - 1
	if detailCount < 3 {
		probeCancel()
		t.Fatalf("multipart fixture produced %d detail parts; want at least 3", detailCount)
	}
	probeCancel()
	select {
	case <-probeCh:
	case <-time.After(time.Second):
		t.Fatal("probe request did not shut down")
	}

	middle := 1 + (detailCount-1)/2
	for _, tc := range []struct {
		name   string
		failAt int
	}{
		{"middle-detail", middle},
		{"last-detail", detailCount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeTelegram(t)
			store := &backend.MemChatStore{}
			if err := store.Save(allowedUserID); err != nil {
				t.Fatal(err)
			}
			tb := newTestBackend(t, fake, store, time.Second)
			fake.sendMessageFailCode = 500
			fake.sendMessageFailAt = tc.failAt
			hooks := &policyHookSpy{}
			if _, err := tb.RequestBaseManifest(context.Background(), telegramMultiPartPolicyRequest(t, hooks)); err == nil {
				t.Fatalf("detail send %d failure returned success", tc.failAt)
			}
			events, _ := hooks.snapshot()
			if len(events) != 0 {
				t.Fatalf("partial detail send activated hooks: %v", events)
			}
			messages := fake.sentSnapshot()
			if len(messages) != tc.failAt-1 {
				t.Fatalf("sent %d messages before failure at %d", len(messages), tc.failAt)
			}
			for i, message := range messages {
				if message.ReplyMarkup != "" {
					t.Fatalf("pre-failure detail %d carried a decision keyboard", i+1)
				}
			}
		})
	}
}

func TestTelegramPolicyTransportUncertaintyLeavesNoUsableChallenge(t *testing.T) {
	t.Run("accepted-detail-response-lost", func(t *testing.T) {
		fake := newFakeTelegram(t)
		store := &backend.MemChatStore{}
		if err := store.Save(allowedUserID); err != nil {
			t.Fatal(err)
		}
		tb := newTestBackend(t, fake, store, time.Second)
		fake.sendMessageDropAt = 1
		hooks := &policyHookSpy{}
		if _, err := tb.RequestBaseManifest(context.Background(), telegramMultiPartPolicyRequest(t, hooks)); err == nil {
			t.Fatal("accepted detail with lost response returned success")
		}
		messages := fake.sentSnapshot()
		if len(messages) != 1 || messages[0].ReplyMarkup != "" {
			t.Fatalf("uncertain detail send continued to a decision: %#v", messages)
		}
		events, _ := hooks.snapshot()
		if len(events) != 0 {
			t.Fatalf("uncertain detail send activated hooks: %v", events)
		}
	})

	t.Run("accepted-final-card-response-lost", func(t *testing.T) {
		tb, fake, _ := startPolicyBackend(t, time.Second)
		fake.sendMessageDropAt = 2
		hooks := &policyHookSpy{}
		request := telegramPolicyRequest(t, hooks)
		if _, err := tb.RequestBaseManifest(context.Background(), request); err == nil {
			t.Fatal("accepted decision card with lost response returned success")
		}
		messages := fake.sentSnapshot()
		if len(messages) != 2 || messages[1].ReplyMarkup == "" {
			t.Fatalf("fake did not model a visible uncertain decision card: %#v", messages)
		}
		cardID := 1000 + len(messages) - 1
		fake.pushCallback(allowedUserID, "u", "p:a:"+request.RequestID+":"+request.CallbackChallenge, cardID, allowedUserID)
		waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) > 0 })
		_, commits := hooks.snapshot()
		if len(commits) != 0 {
			t.Fatalf("accepted-but-unacknowledged card retained a usable challenge: %#v", commits)
		}
	})
}

func TestTelegramPolicyCancellationStopsMultipartNotification(t *testing.T) {
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedUserID); err != nil {
		t.Fatal(err)
	}
	tb := newTestBackend(t, fake, store, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	fake.sendMessageHook = func(call int) {
		if call == 1 {
			cancel()
		}
	}
	hooks := &policyHookSpy{}
	if _, err := tb.RequestBaseManifest(ctx, telegramMultiPartPolicyRequest(t, hooks)); !errors.Is(err, context.Canceled) {
		t.Fatalf("multipart cancellation error = %v", err)
	}
	messages := fake.sentSnapshot()
	if len(messages) != 1 || messages[0].ReplyMarkup != "" {
		t.Fatalf("canceled multipart notification exposed a decision: %#v", messages)
	}
	events, _ := hooks.snapshot()
	if len(events) != 0 {
		t.Fatalf("canceled multipart notification activated hooks: %v", events)
	}
}

func TestTelegramPolicyCancellationAfterFinalCardBeforeActivateDisablesCard(t *testing.T) {
	tb, fake, _ := startPolicyBackend(t, time.Second)
	hooks := &policyHookSpy{}
	request := telegramPolicyRequest(t, hooks)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The simple fixture renders one detail followed by the decision card.
	// The hook runs after the fake has accepted the card and immediately before
	// it returns the successful Telegram response to RequestBaseManifest.
	fake.sendMessageHook = func(call int) {
		if call == 2 {
			cancel()
		}
	}
	if _, err := tb.RequestBaseManifest(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-card cancellation error = %v, want context.Canceled", err)
	}
	events, commits := hooks.snapshot()
	if len(events) != 0 || len(commits) != 0 {
		t.Fatalf("post-card cancellation reached hooks: events=%v commits=%#v", events, commits)
	}
	messages := fake.sentSnapshot()
	if len(messages) != 2 || messages[1].ReplyMarkup == "" {
		t.Fatalf("fixture did not accept and return a final card: %#v", messages)
	}
	edits := fake.editsSnapshot()
	if len(edits) != 1 || !strings.Contains(edits[0].Text, "canceled before activation") || !strings.Contains(edits[0].Text, "card is disabled") {
		t.Fatalf("canceled final card was not visibly disabled: %#v", edits)
	}
	cardID := 1000 + len(messages) - 1
	fake.pushCallback(allowedUserID, "u", "p:a:"+request.RequestID+":"+request.CallbackChallenge, cardID, allowedUserID)
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) > 0 })
	_, commits = hooks.snapshot()
	if len(commits) != 0 {
		t.Fatalf("canceled card retained a usable callback entry: %#v", commits)
	}
	if got := fake.callbackAnswersSnapshot()[0].Text; got != "expired or already resolved" {
		t.Fatalf("canceled card callback answer = %q", got)
	}
}

func TestTelegramPolicyNeverInvokesConfiguredExplainer(t *testing.T) {
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedUserID); err != nil {
		t.Fatal(err)
	}
	tb := newTestBackend(t, fake, store, time.Second)
	spy := &policyExplainerSpy{}
	tb.Explainer = spy
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := tb.RequestBaseManifest(ctx, telegramPolicyRequest(t, &policyHookSpy{}))
	if err != nil {
		t.Fatal(err)
	}
	if calls, inputs := spy.snapshot(); calls != 0 || len(inputs) != 0 {
		t.Fatalf("policy review reached explainer: calls=%d inputs=%q", calls, inputs)
	}
	cancel()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("canceled policy request did not shut down")
	}
}

func TestTelegramPolicyConcurrentReviewsRemainContiguous(t *testing.T) {
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedUserID); err != nil {
		t.Fatal(err)
	}
	tb := newTestBackend(t, fake, store, time.Second)
	hooksA, hooksB := &policyHookSpy{}, &policyHookSpy{}
	requestA := telegramMultiPartPolicyRequest(t, hooksA)
	requestB := telegramMultiPartPolicyRequest(t, hooksB)
	requestB.RequestID = "pm_77777777777777777777777777777777"
	requestB.CallbackChallenge = "7777777777777777"
	manifestB, err := policy.ParseBaseManifest(requestB.Payload)
	if err != nil {
		t.Fatal(err)
	}
	requestB.HostKeyFP = "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	manifestB.Host = requestB.HostKeyFP
	requestB.Payload, err = policy.MarshalBaseManifest(manifestB)
	if err != nil {
		t.Fatal(err)
	}

	type requestResult struct {
		ch  <-chan signerkit.BaseManifestApprovalResult
		err error
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelA()
	defer cancelB()
	done := make(chan requestResult, 2)
	go func() {
		ch, err := tb.RequestBaseManifest(ctxA, requestA)
		done <- requestResult{ch: ch, err: err}
	}()
	go func() {
		ch, err := tb.RequestBaseManifest(ctxB, requestB)
		done <- requestResult{ch: ch, err: err}
	}()
	results := []requestResult{<-done, <-done}
	for _, result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	messages := fake.sentSnapshot()
	if len(messages) < 6 {
		t.Fatalf("concurrent fixture did not produce multipart reviews: %d messages", len(messages))
	}
	lastLabel := ""
	transitions := 0
	seen := map[string]bool{}
	for i, message := range messages {
		label := ""
		switch {
		case strings.Contains(message.Text, requestA.RequestID):
			label = "A"
		case strings.Contains(message.Text, requestB.RequestID):
			label = "B"
		default:
			t.Fatalf("message %d cannot be correlated to a review: %q", i+1, message.Text)
		}
		seen[label] = true
		if lastLabel != "" && label != lastLabel {
			transitions++
		}
		lastLabel = label
	}
	if !seen["A"] || !seen["B"] || transitions != 1 {
		t.Fatalf("multipart reviews interleaved: seen=%v transitions=%d", seen, transitions)
	}
	cancelA()
	cancelB()
	for _, result := range results {
		select {
		case <-result.ch:
		case <-time.After(time.Second):
			t.Fatal("concurrent policy request did not shut down")
		}
	}
}

func TestTelegramPolicyAndOrdinaryCallbackNamespacesAreDisjoint(t *testing.T) {
	tb, fake, _ := startPolicyBackend(t, time.Second)
	hooks := &policyHookSpy{}
	policyReq := telegramPolicyRequest(t, hooks)
	policyCh, err := tb.RequestBaseManifest(context.Background(), policyReq)
	if err != nil {
		t.Fatal(err)
	}
	policyCardID := 1000 + len(fake.sentSnapshot()) - 1
	fake.pushCallback(allowedUserID, "u", "approve:"+policyReq.RequestID, policyCardID, allowedUserID)
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) > 0 })
	select {
	case result := <-policyCh:
		t.Fatalf("ordinary namespace resolved policy: %#v", result)
	default:
	}

	ordinaryCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ordinaryCh, err := tb.Request(ordinaryCtx, signerkit.ApprovalRequest{
		RequestID: policyReq.RequestID, Commands: []signerkit.CommandReq{{Server: "srv", Cmd: "true", TTLSec: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ordinaryID := 1000 + len(fake.sentSnapshot()) - 1
	fake.pushCallback(allowedUserID, "u", "p:a:"+policyReq.RequestID+":aaaaaaaaaaaaaaaa", ordinaryID, allowedUserID)
	time.Sleep(30 * time.Millisecond)
	select {
	case result := <-ordinaryCh:
		t.Fatalf("policy namespace resolved ordinary request: %#v", result)
	default:
	}
	fake.pushCallback(allowedUserID, "u", "approve:"+policyReq.RequestID, ordinaryID, allowedUserID)
	select {
	case result := <-ordinaryCh:
		if result.Status != signerkit.StatusApproved {
			t.Fatalf("ordinary status = %v", result.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary namespace stopped working")
	}
	cancel()
}

func TestTelegramPolicyUncertainCommitDisablesWithoutOpposite(t *testing.T) {
	tb, fake, _ := startPolicyBackend(t, time.Second)
	hooks := &policyHookSpy{
		commitErrors: []error{fmt.Errorf("%w: injected", signerkit.ErrPolicyVerdictCommitUncertain)},
		ackError:     errors.New("read-back unavailable"),
	}
	request := telegramPolicyRequest(t, hooks)
	ch, err := tb.RequestBaseManifest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	cardID := 1000 + len(fake.sentSnapshot()) - 1
	callback := "p:a:" + request.RequestID + ":" + request.CallbackChallenge
	fake.pushCallback(allowedUserID, "u", callback, cardID, allowedUserID)
	result := <-ch
	if !errors.Is(result.BackendError, signerkit.ErrPolicyVerdictCommitUncertain) {
		t.Fatalf("BackendError = %v", result.BackendError)
	}
	fake.pushCallback(allowedUserID, "u", "p:d:"+request.RequestID+":"+request.CallbackChallenge, cardID, allowedUserID)
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 2 })
	_, commits := hooks.snapshot()
	if len(commits) != 1 || commits[0].Status != policywire.StatusApproved {
		t.Fatalf("uncertain click allowed opposite verdict: %#v", commits)
	}
}

func TestTelegramPolicyTimeoutAndCancellationAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
		want   policywire.Status
	}{
		{"timeout", false, policywire.StatusTimeout},
		{"cancel", true, policywire.StatusInterrupted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb, _, _ := startPolicyBackend(t, 40*time.Millisecond)
			hooks := &policyHookSpy{}
			request := telegramPolicyRequest(t, hooks)
			ctx, cancel := context.WithCancel(context.Background())
			ch, err := tb.RequestBaseManifest(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if tc.cancel {
				cancel()
			} else {
				defer cancel()
			}
			select {
			case result := <-ch:
				if result.Status != tc.want {
					t.Fatalf("status = %s, want %s", result.Status, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("terminal arbitration stranded")
			}
		})
	}
}

func TestTelegramPolicyRejectsNonPrivateStoredChatBeforeExposure(t *testing.T) {
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedChatID); err != nil {
		t.Fatal(err)
	}
	tb := newTestBackend(t, fake, store, time.Second)
	if _, err := tb.RequestBaseManifest(context.Background(), telegramPolicyRequest(t, &policyHookSpy{})); err == nil {
		t.Fatal("group/legacy chat linkage accepted for policy exposure")
	}
	if len(fake.sentSnapshot()) != 0 {
		t.Fatal("policy material exposed before private-chat validation")
	}
}
