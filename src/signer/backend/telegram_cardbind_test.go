package backend_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// A pending approval is bound to the exact card it posted. request_id is
// chosen by the socket client, so (1) a second request reusing a pending
// request_id is refused before any card is sent, and (2) a tap resolves a
// pending request only when it comes from that request's own chat+message.
// Without both, a client could send request A, then B with A's id, and the
// operator's tap on A's card would approve B.

// startCardBindBackend returns a running backend whose DM chat is linked.
// Cards are numbered from 1000 by the fake.
func startCardBindBackend(t *testing.T, reqTimeout time.Duration) (*backend.TelegramBackend, *fakeTelegram, context.Context) {
	t.Helper()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	if err := store.Save(allowedChatID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tb := newTestBackend(t, fake, store, reqTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return tb, fake, ctx
}

// cardBindKinds drives each pending-registration path: Request, RequestGrant,
// and dispatchApproval (via RequestTransfer and RequestRegisterKey).
var cardBindKinds = []struct {
	name string
	call func(ctx context.Context, tb *backend.TelegramBackend, id string) (<-chan signerkit.Result, error)
}{
	{"Request", func(ctx context.Context, tb *backend.TelegramBackend, id string) (<-chan signerkit.Result, error) {
		return tb.Request(ctx, signerkit.ApprovalRequest{
			RequestID: id,
			Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo " + id, TTLSec: 60}},
		})
	}},
	{"RequestGrant", func(ctx context.Context, tb *backend.TelegramBackend, id string) (<-chan signerkit.Result, error) {
		return tb.RequestGrant(ctx, signerkit.GrantApprovalRequest{RequestID: id, Alias: "x", Scope: "all", Duration: time.Hour})
	}},
	{"RequestTransfer", func(ctx context.Context, tb *backend.TelegramBackend, id string) (<-chan signerkit.Result, error) {
		return tb.RequestTransfer(ctx, signerkit.TransferApprovalRequest{
			RequestID: id, XferID: "AQ4bKDVCT1xpdoOQnaq3xA",
			SrcLabel: "a", SrcFP: "SHA256:a", SrcPath: "/etc/a",
			DestLabel: "b", DestFP: "SHA256:b", DestPath: "/etc/b", Mode: "0600",
		})
	}},
	{"RequestRegisterKey", func(ctx context.Context, tb *backend.TelegramBackend, id string) (<-chan signerkit.Result, error) {
		return tb.RequestRegisterKey(ctx, signerkit.RegisterApprovalRequest{
			RequestID: id, HostFP: "SHA256:h", Label: "h",
			BoxPub: "sshgate-xfer-box-x25519 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			IDPub:  "sshgate-xfer-id-ed25519 AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw=",
		})
	}},
}

func expectResult(t *testing.T, ch <-chan signerkit.Result, want signerkit.ResultStatus) {
	t.Helper()
	select {
	case got := <-ch:
		if got.Status != want {
			t.Fatalf("Status = %v; want %v", got.Status, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no Result within 2s; want %v", want)
	}
}

// expectNoResolution waits until the backend has answered `answers` callbacks
// in total, asserts the latest answer is the unknown-request text, and that ch
// has not resolved.
func expectNoResolution(t *testing.T, fake *fakeTelegram, ch <-chan signerkit.Result, answers int) {
	t.Helper()
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= answers })
	ans := fake.callbackAnswersSnapshot()
	if got := ans[answers-1].Text; got != "expired or already resolved" {
		t.Fatalf("callback answer = %q; want %q", got, "expired or already resolved")
	}
	select {
	case got := <-ch:
		t.Fatalf("mismatched tap resolved the pending request: %+v", got)
	default:
	}
}

func TestTelegram_DuplicatePendingRequestIDRefused(t *testing.T) {
	t.Parallel()
	for _, kind := range cardBindKinds {
		kind := kind
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			tb, fake, ctx := startCardBindBackend(t, 5*time.Second)

			first, err := kind.call(ctx, tb, "dup")
			if err != nil {
				t.Fatalf("first: %v", err)
			}
			waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })

			second, err := kind.call(ctx, tb, "dup")
			if err == nil || !strings.Contains(err.Error(), "request_id already pending") {
				t.Fatalf("duplicate err = %v; want 'request_id already pending'", err)
			}
			if second != nil {
				t.Errorf("duplicate returned a non-nil channel alongside the error")
			}
			if n := len(fake.sentSnapshot()); n != 1 {
				t.Fatalf("sent %d cards; want 1 (duplicate must not post a card)", n)
			}

			// The original request is untouched and resolves via its own card.
			fake.pushCallback(allowedUserID, "operator", "approve:dup", 1000, allowedChatID)
			expectResult(t, first, signerkit.StatusApproved)
		})
	}
}

// Every path that bails before publishing must release its reservation, or the
// request_id would be refused forever.
func TestTelegram_FailedSendReleasesRequestID(t *testing.T) {
	t.Parallel()
	for _, kind := range cardBindKinds {
		kind := kind
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			tb, fake, ctx := startCardBindBackend(t, 5*time.Second)
			fake.mu.Lock()
			fake.sendMessageFailCode = 500
			fake.sendMessageFailAt = 1
			fake.mu.Unlock()

			if _, err := kind.call(ctx, tb, "retry"); err == nil {
				t.Fatal("first call succeeded; want the scripted send failure")
			}
			ch, err := kind.call(ctx, tb, "retry")
			if err != nil {
				t.Fatalf("retry after failed send: %v; want the request_id released", err)
			}
			fake.pushCallback(allowedUserID, "operator", "approve:retry", 1000, allowedChatID)
			expectResult(t, ch, signerkit.StatusApproved)
		})
	}
}

// A tap on an older card that carried the same request_id (now resolved) must
// not resolve the request currently pending under that id.
func TestTelegram_StaleCardForReusedRequestIDResolvesNothing(t *testing.T) {
	t.Parallel()
	for _, kind := range cardBindKinds {
		kind := kind
		t.Run(kind.name, func(t *testing.T) {
			t.Parallel()
			tb, fake, ctx := startCardBindBackend(t, 5*time.Second)

			a, err := kind.call(ctx, tb, "x")
			if err != nil {
				t.Fatal(err)
			}
			fake.pushCallback(allowedUserID, "operator", "deny:x", 1000, allowedChatID)
			expectResult(t, a, signerkit.StatusDenied)
			// The result is sent before the pending entry is removed; the
			// callback answer comes after resolve returns.
			waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) == 1 })

			b, err := kind.call(ctx, tb, "x") // card 1001
			if err != nil {
				t.Fatal(err)
			}
			waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 2 })

			fake.pushCallback(allowedUserID, "operator", "approve:x", 1000, allowedChatID) // A's card
			expectNoResolution(t, fake, b, 2)
			fake.pushCallback(allowedUserID, "operator", "approve:x", 1002, allowedChatID) // a card never sent for x
			expectNoResolution(t, fake, b, 3)

			fake.pushCallback(allowedUserID, "operator", "deny:x", 1001, allowedChatID)
			expectResult(t, b, signerkit.StatusDenied)
		})
	}
}

func TestTelegram_TapFromOtherChatResolvesNothing(t *testing.T) {
	t.Parallel()
	tb, fake, ctx := startCardBindBackend(t, 5*time.Second)
	ch, err := cardBindKinds[0].call(ctx, tb, "r")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })

	// Right message id, wrong chat.
	fake.pushCallback(allowedUserID, "operator", "approve:r", 1000, allowedChatID+1)
	expectNoResolution(t, fake, ch, 1)

	fake.pushCallback(allowedUserID, "operator", "approve:r", 1000, allowedChatID)
	expectResult(t, ch, signerkit.StatusApproved)
}

func TestTelegram_TapWithoutMessageResolvesNothing(t *testing.T) {
	t.Parallel()
	tb, fake, ctx := startCardBindBackend(t, 5*time.Second)
	ch, err := cardBindKinds[0].call(ctx, tb, "r")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })

	// A callback with no message (e.g. from an inline-mode message) cannot be
	// tied to the card, so it must be refused.
	fake.mu.Lock()
	fake.nextUpdateID++
	uid := fake.nextUpdateID
	cb := fmt.Sprintf(`{"id":"cb%d","from":{"id":%d,"is_bot":false,"first_name":"u","username":"operator"},"chat_instance":"ci","inline_message_id":"im","data":"approve:r"}`, uid, allowedUserID)
	fake.pendingUpdates = append(fake.pendingUpdates, fakeUpdate{UpdateID: uid, CallbackQuery: json.RawMessage(cb)})
	fake.mu.Unlock()
	expectNoResolution(t, fake, ch, 1)

	fake.pushCallback(allowedUserID, "operator", "approve:r", 1000, allowedChatID)
	expectResult(t, ch, signerkit.StatusApproved)
}
