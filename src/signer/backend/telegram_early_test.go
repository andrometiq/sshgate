package backend_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// Called with fake.mu held; wake every waiter when observable progress occurs.
func (fake *fakeTelegram) signalProgress() {
	if fake.progress != nil {
		close(fake.progress)
		fake.progress = nil
	}
}

func waitTelegramProgress(fake *fakeTelegram, ready func() bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for !ready() {
		if fake.progress == nil {
			fake.progress = make(chan struct{})
		}
		progress := fake.progress
		fake.mu.Unlock()
		<-progress
		fake.mu.Lock()
	}
}

// The next offset proves all queued callbacks were dispatched by the poller.
func drainEarlyCallbacks(t *testing.T, fake *fakeTelegram) {
	t.Helper()
	fake.mu.Lock()
	offset := fake.nextUpdateID + 1
	fake.mu.Unlock()
	waitTelegramProgress(fake, func() bool { return fake.processedOffset >= offset })
}

func waitEarlyAnswers(fake *fakeTelegram, count int) {
	waitTelegramProgress(fake, func() bool { return len(fake.callbackAnswers) >= count })
}

func TestTelegram_CallbackBeforeSendResponse(t *testing.T) {
	for _, kind := range cardBindKinds {
		for _, action := range []string{"approve", "deny"} {
			t.Run(kind.name+"/"+action, func(t *testing.T) {
				tb, fake, ctx := startCardBindBackend(t, time.Minute)
				entered, release := make(chan struct{}), make(chan struct{})
				releaseSend := sync.OnceFunc(func() { close(release) })
				t.Cleanup(releaseSend)
				fake.mu.Lock()
				fake.sendMessageHook = func(int) { close(entered); <-release }
				fake.mu.Unlock()
				returned := make(chan (<-chan signerkit.Result), 1)
				failed := make(chan error, 1)
				go func() { ch, err := kind.call(ctx, tb, "early"); returned <- ch; failed <- err }()
				<-entered
				// Read the opaque callback data from the actual rendered keyboard.
				var markup struct {
					Rows [][]struct {
						Data string `json:"callback_data"`
					} `json:"inline_keyboard"`
				}
				if err := json.Unmarshal([]byte(fake.sentSnapshot()[0].ReplyMarkup), &markup); err != nil {
					t.Fatal(err)
				}
				index := 0
				want := signerkit.StatusApproved
				if action == "deny" {
					index = 1
					want = signerkit.StatusDenied
				}
				data := markup.Rows[0][index].Data
				opposite := "deny:early"
				if action == "deny" {
					opposite = "approve:early"
				}
				fake.pushCallback(allowedUserID+1, "other", opposite, 1000, allowedChatID)
				fake.pushCallback(allowedUserID, "operator", opposite, 999, allowedChatID)
				fake.pushCallback(allowedUserID, "operator", opposite, 1000, allowedChatID+1)
				fake.pushCallback(allowedUserID, "operator", "approve:other-request", 1000, allowedChatID)
				fake.pushCallback(allowedUserID, "operator", data, 1000, allowedChatID)
				drainEarlyCallbacks(t, fake)
				releaseSend()
				ch := <-returned
				if err := <-failed; err != nil {
					t.Fatal(err)
				}
				expectEarlyResult(t, ch, want)
				waitEarlyAnswers(fake, 5)
				// Exactly one callback succeeds; mismatched early taps cannot win.
				count := 0
				for _, answer := range fake.callbackAnswersSnapshot() {
					if answer.Text == want.String() {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("answers = %+v", fake.callbackAnswersSnapshot())
				}
			})
		}
	}
}

func TestTelegram_EarlyCallbackExpiresBeforeBinding(t *testing.T) {
	for _, mode := range []string{"expiry", "cancel", "failed-send"} {
		t.Run(mode, func(t *testing.T) {
			duration := time.Minute
			if mode == "expiry" {
				duration = 100 * time.Millisecond
			}
			tb, fake, parent := startCardBindBackend(t, duration)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			releaseSend := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseSend)
			fake.mu.Lock()
			fake.sendMessageHook = func(int) { close(entered); <-release }
			if mode == "failed-send" {
				fake.sendMessageDropAt = 1
			}
			fake.mu.Unlock()
			returned := make(chan (<-chan signerkit.Result), 1)
			failed := make(chan error, 1)
			go func() { ch, err := cardBindKinds[0].call(ctx, tb, "early"); returned <- ch; failed <- err }()
			<-entered
			fake.pushCallback(allowedUserID, "operator", "approve:early", 1000, allowedChatID)
			drainEarlyCallbacks(t, fake)
			if mode == "cancel" {
				cancel()
			}
			if mode == "expiry" {
				<-time.After(duration)
			}
			releaseSend()
			ch, err := <-returned, <-failed
			if mode == "failed-send" {
				if err == nil || ch != nil {
					t.Fatalf("send result = %v, %v", ch, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				expectEarlyResult(t, ch, signerkit.StatusTimeout)
			}
			waitEarlyAnswers(fake, 1)
			if got := fake.callbackAnswersSnapshot()[0].Text; got != "expired or already resolved" {
				t.Fatalf("answer = %q", got)
			}
		})
	}
}

func TestTelegram_EarlyCallbackOverflowDenyThenApprove(t *testing.T) {
	tb, fake, ctx := startCardBindBackend(t, time.Minute)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseSend := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseSend)
	fake.mu.Lock()
	fake.sendMessageHook = func(int) { close(entered); <-release }
	fake.mu.Unlock()
	returned := make(chan (<-chan signerkit.Result), 1)
	failed := make(chan error, 1)
	go func() { ch, err := cardBindKinds[0].call(ctx, tb, "early"); returned <- ch; failed <- err }()
	<-entered
	for i := 0; i < 16; i++ {
		fake.pushCallback(allowedUserID, "operator", "deny:early", 999, allowedChatID)
	}
	fake.pushCallback(allowedUserID, "operator", "deny:early", 1000, allowedChatID)
	drainEarlyCallbacks(t, fake)
	waitEarlyAnswers(fake, 1)
	answers := fake.callbackAnswersSnapshot()
	if len(answers) != 1 || answers[0].Text != "expired or already resolved" {
		releaseSend()
		t.Fatalf("overflow answers = %+v", answers)
	}
	releaseSend()
	ch := <-returned
	if err := <-failed; err != nil {
		t.Fatal(err)
	}
	waitEarlyAnswers(fake, 17)
	for _, answer := range fake.callbackAnswersSnapshot() {
		if answer.Text != "expired or already resolved" {
			t.Fatalf("answer = %+v", answer)
		}
	}
	fake.pushCallback(allowedUserID, "operator", "approve:early", 1000, allowedChatID)
	expectEarlyResult(t, ch, signerkit.StatusDenied)
	waitFor(t, time.Second, func() bool { return len(fake.editsSnapshot()) == 1 })
	if got := fake.editsSnapshot()[0].Text; got != "Denied: early callback buffer overflow" {
		t.Fatalf("overflow reason = %q", got)
	}
	waitEarlyAnswers(fake, 18)
	for _, answer := range fake.callbackAnswersSnapshot() {
		if answer.Text == "approved" {
			t.Fatal("overflow request approved")
		}
	}
}

func TestTelegram_IdentifiableMismatchesDoNotExhaustEarlyBuffer(t *testing.T) {
	tb, fake, ctx := startCardBindBackend(t, time.Minute)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseSend := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseSend)
	fake.mu.Lock()
	fake.sendMessageHook = func(int) { close(entered); <-release }
	fake.mu.Unlock()
	returned := make(chan (<-chan signerkit.Result), 1)
	failed := make(chan error, 1)
	go func() { ch, err := cardBindKinds[0].call(ctx, tb, "early"); returned <- ch; failed <- err }()
	<-entered
	for i := 0; i < 17; i++ {
		fake.pushCallback(allowedUserID, "operator", "deny:early", 1000, allowedChatID+1)
		fake.pushCallback(allowedUserID+1, "other", "deny:early", 1000, allowedChatID)
		fake.pushCallback(allowedUserID, "operator", "invalid:early", 1000, allowedChatID)
	}
	fake.pushCallback(allowedUserID, "operator", "approve:early", 1000, allowedChatID)
	drainEarlyCallbacks(t, fake)
	releaseSend()
	ch := <-returned
	if err := <-failed; err != nil {
		t.Fatal(err)
	}
	expectEarlyResult(t, ch, signerkit.StatusApproved)
}

func expectEarlyResult(t *testing.T, ch <-chan signerkit.Result, want signerkit.ResultStatus) {
	t.Helper()
	if got := <-ch; got.Status != want {
		t.Fatalf("Status = %v; want %v", got.Status, want)
	}
}

func TestTelegram_ReplayAcknowledgementCannotBlockDecisionOrDeadline(t *testing.T) {
	for _, kind := range cardBindKinds {
		for _, first := range []string{"approve", "deny", "timeout"} {
			t.Run(kind.name+"/"+first, func(t *testing.T) {
				duration := time.Minute
				if first == "timeout" {
					duration = 300 * time.Millisecond
				}
				tb, fake, ctx := startCardBindBackend(t, duration)
				sending, sendRelease := make(chan struct{}), make(chan struct{})
				answering, answerRelease := make(chan struct{}), make(chan struct{})
				releaseSend := sync.OnceFunc(func() { close(sendRelease) })
				releaseAnswer := sync.OnceFunc(func() { close(answerRelease) })
				t.Cleanup(releaseSend)
				t.Cleanup(releaseAnswer)
				answerEntered := sync.OnceFunc(func() { close(answering) })
				fake.mu.Lock()
				fake.sendMessageHook = func(int) { close(sending); <-sendRelease }
				fake.answerCallbackHook = func() { answerEntered(); <-answerRelease }
				fake.mu.Unlock()
				returned := make(chan (<-chan signerkit.Result), 1)
				failed := make(chan error, 1)
				go func() { ch, err := kind.call(ctx, tb, "barrier"); returned <- ch; failed <- err }()
				<-sending
				// Replay's first acknowledgement stalls before the valid tap's notification.
				fake.pushCallback(allowedUserID, "operator", "approve:barrier", 999, allowedChatID)
				if first != "timeout" {
					fake.pushCallback(allowedUserID, "operator", first+":barrier", 1000, allowedChatID)
				}
				drainEarlyCallbacks(t, fake)
				releaseSend()
				<-answering
				var ch <-chan signerkit.Result
				select {
				case ch = <-returned:
				case <-time.After(time.Second):
					t.Fatal("Request blocked on acknowledgement")
				}
				if err := <-failed; err != nil {
					t.Fatal(err)
				}
				want := signerkit.StatusTimeout
				if first != "timeout" {
					opposite := "approve"
					want = signerkit.StatusDenied
					if first == "approve" {
						opposite = "deny"
						want = signerkit.StatusApproved
					}
					fake.pushCallback(allowedUserID, "operator", opposite+":barrier", 1000, allowedChatID)
					drainEarlyCallbacks(t, fake)
				}
				select {
				case got := <-ch:
					if got.Status != want {
						t.Fatalf("result = %+v; want %v", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("decision/deadline blocked on acknowledgement")
				}
				releaseAnswer()
			})
		}
	}
}
