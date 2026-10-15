package backend_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"encoding/json"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
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

type networkSocketResponse struct {
	Status     string `json:"status"`
	Error      string `json:"error"`
	Signatures []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"signatures"`
}
type networkSocketResult struct {
	response networkSocketResponse
	err      error
}

// Observe Request completion: the fake records sendMessage before the backend
// receives its reply and publishes the pending card.
type networkReadyBackend struct {
	*backend.TelegramBackend
	ready chan struct{}
}

func (b *networkReadyBackend) Request(ctx context.Context, req signerkit.ApprovalRequest) (<-chan signerkit.Result, error) {
	result, err := b.TelegramBackend.Request(ctx, req)
	if err == nil {
		b.ready <- struct{}{}
	}
	return result, err
}

func awaitNetworkCardReady(t *testing.T, d *signerkit.Daemon) {
	t.Helper()
	select {
	case <-d.Backend.(*networkReadyBackend).ready:
	case <-time.After(5 * time.Second):
		t.Fatal("Telegram backend did not publish the card")
	}
}

func startNetworkDaemon(t *testing.T) (*signerkit.Daemon, ed25519.PublicKey, *fakeTelegram, context.Context) {
	t.Helper()
	tb, fake, ctx := startCardBindBackend(t, time.Minute)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := signerkit.NewMemAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	return &signerkit.Daemon{Key: key, Backend: &networkReadyBackend{TelegramBackend: tb, ready: make(chan struct{}, 4)}, Audit: audit, NowFunc: func() time.Time { return time.Unix(1000, 0) }}, pub, fake, ctx
}

func startNetworkSocket(t *testing.T, ctx context.Context, d *signerkit.Daemon, id string, network, reveal bool) <-chan networkSocketResult {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	dir, err := os.MkdirTemp("", "net-sign-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "signer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	handled := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			handled <- err
			return
		}
		defer conn.Close()
		handled <- d.HandleSignRequest(ctx, conn)
	}()
	conn, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"kind": "sign", "request_id": id, "commands": []map[string]any{{"server": "test-host", "cmd": "curl https://example.com", "ttl_seconds": 60, "host": "SHA256:test-host", "net": network, "reveal": reveal, "reason": "check endpoint connectivity"}}}
	if err := json.NewEncoder(conn).Encode(body); err != nil {
		t.Fatal(err)
	}
	result := make(chan networkSocketResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var r networkSocketResult
		r.err = json.NewDecoder(conn).Decode(&r.response)
		if err := <-handled; r.err == nil {
			r.err = err
		}
		result <- r
	}()
	t.Cleanup(func() { cancel(); conn.Close(); <-done })
	return result
}

func awaitNetworkSocket(t *testing.T, ch <-chan networkSocketResult) networkSocketResponse {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.response
	case <-time.After(5 * time.Second):
		t.Fatal("signer socket did not respond")
	}
	return networkSocketResponse{}
}

func checkNetworkSignature(t *testing.T, resp networkSocketResponse, pub ed25519.PublicKey, network, reveal bool) {
	t.Helper()
	if resp.Status != "approved" || len(resp.Signatures) != 1 {
		t.Fatalf("response=%+v", resp)
	}
	verified, err := gate.Verify(resp.Signatures[0].Sig, pub, time.Unix(1000, 0), []string{"SHA256:test-host"})
	if err != nil || verified.Cmd != "curl https://example.com" || verified.Net != network || verified.Reveal != reveal {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
}

func checkNetworkActivationCard(t *testing.T, card sentMessage, reveal bool) {
	t.Helper()
	banner := "🌐 READ WITH NETWORK on test-host: may connect anywhere, including services on test-host itself that can change state."
	if card.ChatID != allowedChatID || strings.Count(card.Text, banner) != 1 || strings.Count(card.Text, "Reason: check endpoint connectivity\n") != 1 || !strings.Contains(card.Text, "curl https://example.com") {
		t.Fatalf("network card=%+v", card)
	}
	label := "✓ Approve READ WITH NETWORK"
	if reveal {
		label = "✓ Approve SECRET-REVEAL + NETWORK"
		if !strings.HasPrefix(card.Text, "⚠️ SECRET-REVEAL") || strings.Index(card.Text, "SECRET-REVEAL") > strings.Index(card.Text, banner) {
			t.Fatalf("reveal/network ordering: %q", card.Text)
		}
	} else if !strings.HasPrefix(card.Text, banner) {
		t.Fatalf("banner not first: %q", card.Text)
	}
	var keyboard struct {
		Rows [][]struct {
			Text string `json:"text"`
			Data string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if err := json.Unmarshal([]byte(card.ReplyMarkup), &keyboard); err != nil {
		t.Fatal(err)
	}
	if len(keyboard.Rows) != 1 || len(keyboard.Rows[0]) != 2 || keyboard.Rows[0][0].Text != label || keyboard.Rows[0][0].Data != "approve:x" || keyboard.Rows[0][1].Data != "deny:x" {
		t.Fatalf("keyboard=%s", card.ReplyMarkup)
	}
}

func TestNetActivationTelegramCard(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		for _, action := range []string{"approve", "deny"} {
			t.Run(fmt.Sprintf("reveal=%t/%s", reveal, action), func(t *testing.T) {
				d, pub, fake, ctx := startNetworkDaemon(t)
				ch := startNetworkSocket(t, ctx, d, "x", true, reveal)
				waitFor(t, 2*time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
				awaitNetworkCardReady(t, d)
				checkNetworkActivationCard(t, fake.sentSnapshot()[0], reveal)
				fake.pushCallback(allowedUserID, "operator", action+":x", 1000, allowedChatID)
				resp := awaitNetworkSocket(t, ch)
				if action == "approve" {
					checkNetworkSignature(t, resp, pub, true, reveal)
				} else if resp.Status != "denied" || len(resp.Signatures) != 0 {
					t.Fatalf("denial=%+v", resp)
				}
				if len(fake.sentSnapshot()) != 1 {
					t.Fatal("network request sent more than one card")
				}
			})
		}
	}
}

func TestNetCardStaleOrDuplicateRefused(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		t.Run(fmt.Sprintf("reveal=%t", reveal), func(t *testing.T) {
			d, pub, fake, ctx := startNetworkDaemon(t)
			ordinary := startNetworkSocket(t, ctx, d, "x", false, false)
			waitFor(t, 2*time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
			awaitNetworkCardReady(t, d)
			duplicate := awaitNetworkSocket(t, startNetworkSocket(t, ctx, d, "x", true, reveal))
			if duplicate.Status != "error" || !strings.Contains(duplicate.Error, "request_id already pending") || len(duplicate.Signatures) != 0 || len(fake.sentSnapshot()) != 1 {
				t.Fatalf("duplicate=%+v cards=%d", duplicate, len(fake.sentSnapshot()))
			}
			fake.pushCallback(allowedUserID, "operator", "approve:x", 1000, allowedChatID)
			checkNetworkSignature(t, awaitNetworkSocket(t, ordinary), pub, false, false)
			waitFor(t, 2*time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) == 1 })
			current := startNetworkSocket(t, ctx, d, "x", true, reveal)
			waitFor(t, 2*time.Second, func() bool { return len(fake.sentSnapshot()) == 2 })
			awaitNetworkCardReady(t, d)
			checkNetworkActivationCard(t, fake.sentSnapshot()[1], reveal)
			for _, tap := range []struct {
				message int
				chat    int64
			}{{1000, allowedChatID}, {1001, allowedChatID + 1}} {
				answers := len(fake.callbackAnswersSnapshot())
				fake.pushCallback(allowedUserID, "operator", "approve:x", tap.message, tap.chat)
				waitFor(t, 2*time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) > answers })
				if got := fake.callbackAnswersSnapshot()[answers].Text; got != "expired or already resolved" {
					t.Fatalf("mismatched card answer=%q", got)
				}
				select {
				case r := <-current:
					t.Fatalf("mismatched tap resolved network request: %+v", r)
				default:
				}
			}
			fake.pushCallback(allowedUserID, "operator", "approve:x", 1001, allowedChatID)
			checkNetworkSignature(t, awaitNetworkSocket(t, current), pub, true, reveal)
			if len(fake.sentSnapshot()) != 2 {
				t.Fatal("unexpected additional card")
			}
		})
	}
}
