package backend_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// TestTelegram_RequestTransfer_LabelAndApprove drives RequestTransfer through
// the fake Telegram harness: the sent message must carry the distinct
// "✓ Approve SECRET TRANSFER" button (so the operator cannot tap through on
// muscle memory) and the SECRET TRANSFER banner, and an Approve tap must resolve
// the request as approved with no pre-canned signatures (the daemon signs the
// legs locally).
func TestTelegram_RequestTransfer_LabelAndApprove(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	ch, err := tb.RequestTransfer(ctx, signerkit.TransferApprovalRequest{
		RequestID: "x_t1",
		XferID:    "AQ4bKDVCT1xpdoOQnaq3xA",
		SrcLabel:  "ram-gcp",
		SrcFP:     "SHA256:src-fp-000000000000000000000000000000ab",
		SrcPath:   "/etc/secret.env",
		DestLabel: "host-gcp",
		DestFP:    "SHA256:dst-fp-111111111111111111111111111111cd",
		DestPath:  "/etc/default/ops-alerts",
		Mode:      "0600",
	})
	if err != nil {
		t.Fatalf("RequestTransfer: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	sent := fake.sentSnapshot()[0]
	if !strings.Contains(sent.Text, "SECRET TRANSFER") {
		t.Errorf("message missing SECRET TRANSFER banner: %q", sent.Text)
	}
	if !strings.Contains(sent.Text, "ram-gcp") || !strings.Contains(sent.Text, "host-gcp") {
		t.Errorf("message missing registry labels: %q", sent.Text)
	}
	if !strings.Contains(sent.ReplyMarkup, "✓ Approve SECRET TRANSFER") {
		t.Errorf("reply markup missing the SECRET TRANSFER approve label: %q", sent.ReplyMarkup)
	}
	if !strings.Contains(sent.ReplyMarkup, "approve:x_t1") {
		t.Errorf("reply markup missing approve callback: %q", sent.ReplyMarkup)
	}

	fake.pushCallback(allowedUserID, "operator", "approve:x_t1", 2000, allowedChatID)
	select {
	case got := <-ch:
		if got.Status != signerkit.StatusApproved {
			t.Errorf("status = %v; want approved", got.Status)
		}
		if got.Signatures != nil {
			t.Errorf("Signatures = %v; want nil (daemon signs the legs locally)", got.Signatures)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Result within 2s")
	}
}

// TestTelegram_RequestRegisterKey_Label drives RequestRegisterKey: the sent
// message must carry the distinct "✓ Approve XFER-KEY REGISTER" button and the
// register banner.
func TestTelegram_RequestRegisterKey_Label(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	ch, err := tb.RequestRegisterKey(ctx, signerkit.RegisterApprovalRequest{
		RequestID: "x_r1",
		HostFP:    "SHA256:reg-fp-2222222222222222222222222222222222",
		Label:     "new-host",
		BoxPub:    "sshgate-xfer-box-x25519 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		IDPub:     "sshgate-xfer-id-ed25519 AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw=",
	})
	if err != nil {
		t.Fatalf("RequestRegisterKey: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	sent := fake.sentSnapshot()[0]
	if !strings.Contains(sent.Text, "XFER-KEY REGISTER") {
		t.Errorf("message missing register banner: %q", sent.Text)
	}
	if !strings.Contains(sent.ReplyMarkup, "✓ Approve XFER-KEY REGISTER") {
		t.Errorf("reply markup missing the register approve label: %q", sent.ReplyMarkup)
	}

	fake.pushCallback(allowedUserID, "operator", "approve:x_r1", 2001, allowedChatID)
	select {
	case got := <-ch:
		if got.Status != signerkit.StatusApproved {
			t.Errorf("status = %v; want approved", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Result within 2s")
	}
}
