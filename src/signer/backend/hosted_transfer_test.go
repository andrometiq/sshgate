package backend_test

import (
	"context"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// TestHosted_TransferFailsClosed: box→box transfer + xfer-key registration are
// Tier-2 (local Telegram signer) only. The hosted (Tier-3) backend MUST reject
// both BEFORE any HTTP call — no channel, a clear error — exactly like it does
// for reveal and standing grants.
func TestHosted_TransferFailsClosed(t *testing.T) {
	t.Parallel()
	h := &backend.HostedServerBackend{
		BaseURL:  "https://signer.example.com",
		APIKey:   "k",
		ClientID: "laptop",
	}

	ch, err := h.RequestTransfer(context.Background(), backend.TransferApprovalRequest{RequestID: "t"})
	if err == nil {
		t.Fatal("RequestTransfer returned no error on the hosted backend")
	}
	if ch != nil {
		t.Error("RequestTransfer returned a non-nil channel on fail-closed")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("RequestTransfer error = %q; want a fail-closed message", err)
	}

	ch2, err2 := h.RequestRegisterKey(context.Background(), backend.RegisterApprovalRequest{RequestID: "r"})
	if err2 == nil {
		t.Fatal("RequestRegisterKey returned no error on the hosted backend")
	}
	if ch2 != nil {
		t.Error("RequestRegisterKey returned a non-nil channel on fail-closed")
	}
	if !strings.Contains(err2.Error(), "not supported") {
		t.Errorf("RequestRegisterKey error = %q; want a fail-closed message", err2)
	}
}
