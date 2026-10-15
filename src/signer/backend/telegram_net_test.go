package backend_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func TestApprovalMessageNetBanner(t *testing.T) {
	for _, alias := range []string{"test-host", "test host λ"} {
		t.Run(alias, func(t *testing.T) {
			commands := []signerkit.CommandReq{{Server: alias, Cmd: "curl https://example.com", Net: true, Reason: "check the public endpoint"}}
			card := requestNetworkCard(t, commands, "✓ Approve READ WITH NETWORK")
			want := "🌐 READ WITH NETWORK on " + alias + ": may connect anywhere, including services on " + alias + " itself that can change state."
			if !strings.HasPrefix(card, want+"\n\n") || strings.Count(card, want) != 1 {
				t.Errorf("network banner missing, duplicated or not first: %q", card)
			}
			if strings.Contains(card, "SECRET-REVEAL") {
				t.Errorf("network-only card shows reveal: %q", card)
			}
		})
	}
}

func TestApprovalMessageRevealNetBanner(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands []signerkit.CommandReq
	}{
		{"combined", []signerkit.CommandReq{{Server: "test-host", Cmd: "curl https://example.com", Reveal: true, Net: true, Reason: "inspect the raw response"}}},
		// Exercise the renderer's defensive scan independently of daemon admission.
		{"separate", []signerkit.CommandReq{
			{Server: "test-host", Cmd: "cat /etc/example.env", Reveal: true, Reason: "inspect the configuration"},
			{Server: "test-host", Cmd: "curl https://example.com", Net: true, Reason: "check endpoint connectivity"},
			{Server: "test-host", Cmd: "echo ordinary", Reason: "ordinary reason stays omitted"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := requestNetworkCard(t, tc.commands, "✓ Approve SECRET-REVEAL + NETWORK")
			reveal := "⚠️ SECRET-REVEAL — output will NOT be redacted; raw secret values go to the agent, the AI provider, and this chat."
			network := "🌐 READ WITH NETWORK on test-host: may connect anywhere, including services on test-host itself that can change state."
			if !strings.HasPrefix(card, reveal+"\n\n"+network+"\n\n") || strings.Count(card, network) != 1 {
				t.Errorf("combined card must show reveal then network banners: %q", card)
			}
		})
	}
}

func requestNetworkCard(t *testing.T, commands []signerkit.CommandReq, approveLabel string) string {
	t.Helper()
	tb, fake, ctx := startCardBindBackend(t, time.Minute)
	const requestID = "network-card"
	ch, err := tb.Request(ctx, signerkit.ApprovalRequest{RequestID: requestID, Commands: commands})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	cards := fake.sentSnapshot()
	if len(cards) != 1 {
		t.Fatalf("sent %d cards; want one", len(cards))
	}
	card := cards[0]
	if card.ChatID != allowedChatID {
		t.Errorf("card sent to chat %d; want %d", card.ChatID, allowedChatID)
	}
	var keyboard struct {
		Rows [][]struct {
			Text string `json:"text"`
			Data string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if err := json.Unmarshal([]byte(card.ReplyMarkup), &keyboard); err != nil {
		t.Fatalf("keyboard: %v", err)
	}
	if len(keyboard.Rows) != 1 || len(keyboard.Rows[0]) != 2 {
		t.Fatalf("unexpected keyboard: %s", card.ReplyMarkup)
	}
	if button := keyboard.Rows[0][0]; button.Text != approveLabel || button.Data != "approve:"+requestID {
		t.Errorf("approve button = %+v; want %q and request callback", button, approveLabel)
	}
	if button := keyboard.Rows[0][1]; button.Text != "✗ Deny" || button.Data != "deny:"+requestID {
		t.Errorf("deny button = %+v", button)
	}
	for _, command := range commands {
		if !strings.Contains(card.Text, command.Cmd) {
			t.Errorf("card missing command %q", command.Cmd)
		}
		wantCount := 0
		if command.Reveal || command.Net {
			wantCount = 1
		}
		if got := strings.Count(card.Text, "Reason: "+command.Reason+"\n"); got != wantCount {
			t.Errorf("reason %q rendered %d times; want %d", command.Reason, got, wantCount)
		}
		if wantCount == 1 && strings.Index(card.Text, "Reason: "+command.Reason) > strings.Index(card.Text, "1. ") {
			t.Errorf("reason appears after commands: %q", card.Text)
		}
	}
	fake.pushCallback(allowedUserID, "operator", "deny:"+requestID, 1000, allowedChatID)
	expectResult(t, ch, signerkit.StatusDenied)
	return card.Text
}
