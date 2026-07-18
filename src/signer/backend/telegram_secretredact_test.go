package backend_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// F5 — the Telegram approval MESSAGE is the fourth command-string sink. The
// secret embedded IN the command must be replaced by the per-session redaction
// marker before the message text is sent to Telegram, while the command SHAPE
// (and a benign command) stays visible so the human still sees what runs. This
// is display-only: the daemon signs/executes the RAW command — these tests
// assert only the rendered message body. fixtureSalt is a fixed non-zero salt
// so the marker is deterministic across the suite.
var fixtureSalt = [32]byte{0x5f}

// secretFixture is a fake secret in the assignment shape the Combined() ruleset
// catches (PASSWORD=...). NOT a real credential — publish-safe.
const secretFixture = "hunter2secret"

// newSecretRedactBackend builds a wired-up backend whose Request/RequestGrant
// send to the fake server, with the F5 salt + ruleset set on the struct the
// same way cmd/main wires them. A nil-rules variant proves the verbatim
// fast-path.
func newSecretRedactBackend(t *testing.T, fake *fakeTelegram, rules []redact.Rule) *backend.TelegramBackend {
	t.Helper()
	store := &backend.MemChatStore{}
	if err := store.Save(allowedChatID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tb := newTestBackend(t, fake, store, 5*time.Second)
	tb.RedactSalt = fixtureSalt
	tb.RedactRules = rules
	return tb
}

// TestTelegram_ApprovalMessageRedactsSecret asserts the secret-bearing command
// is redacted in the approval message (marker present, secret absent) while a
// benign command in the same request survives verbatim.
func TestTelegram_ApprovalMessageRedactsSecret(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newSecretRedactBackend(t, fake, redactrules.Combined())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if _, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_secret",
		Commands: []signerkit.CommandReq{
			{Server: "prod", Cmd: `printf 'PASSWORD=` + secretFixture + `'`, TTLSec: 60},
			{Server: "prod", Cmd: "systemctl restart nginx", TTLSec: 60}, // benign, must survive
		},
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text

	if strings.Contains(body, secretFixture) {
		t.Errorf("approval message leaked the secret:\n%s", body)
	}
	if !strings.Contains(body, redact.MarkerPrefix) {
		t.Errorf("approval message missing redaction marker:\n%s", body)
	}
	// The command SHAPE stays visible — the human still sees a PASSWORD= and the
	// benign command runs verbatim.
	if !strings.Contains(body, "PASSWORD=") {
		t.Errorf("approval message dropped the command shape (PASSWORD=):\n%s", body)
	}
	if !strings.Contains(body, "systemctl restart nginx") {
		t.Errorf("benign command altered in approval message:\n%s", body)
	}
}

// TestTelegram_ApprovalMessageNilRulesVerbatim proves a backend with no ruleset
// wired (nil) renders the command verbatim — RedactString fast-paths nil rules,
// the safe default for any test/stub backend.
func TestTelegram_ApprovalMessageNilRulesVerbatim(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newSecretRedactBackend(t, fake, nil) // no rules

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	cmd := `printf 'PASSWORD=` + secretFixture + `'`
	if _, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_nilrules",
		Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: cmd, TTLSec: 60}},
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text
	if !strings.Contains(body, cmd) {
		t.Errorf("nil-rules backend should render command verbatim:\n%s", body)
	}
	if strings.Contains(body, redact.MarkerPrefix) {
		t.Errorf("nil-rules backend unexpectedly redacted:\n%s", body)
	}
}

// TestTelegram_GrantMessageRedactsSecret asserts the secret-bearing command in
// a scope="commands" grant approval message is redacted (marker present, secret
// absent) while the command shape stays visible.
func TestTelegram_GrantMessageRedactsSecret(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newSecretRedactBackend(t, fake, redactrules.Combined())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if _, err := tb.RequestGrant(ctx, signerkit.GrantApprovalRequest{
		RequestID: "g_secret",
		Alias:     "prod",
		Scope:     "commands",
		Commands: []string{
			`printf 'PASSWORD=` + secretFixture + `'`,
			"systemctl restart nginx", // benign, must survive
		},
		Duration: time.Hour,
	}); err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text

	if strings.Contains(body, secretFixture) {
		t.Errorf("grant approval message leaked the secret:\n%s", body)
	}
	if !strings.Contains(body, redact.MarkerPrefix) {
		t.Errorf("grant approval message missing redaction marker:\n%s", body)
	}
	if !strings.Contains(body, "PASSWORD=") {
		t.Errorf("grant approval message dropped the command shape (PASSWORD=):\n%s", body)
	}
	if !strings.Contains(body, "systemctl restart nginx") {
		t.Errorf("benign grant command altered:\n%s", body)
	}
}

// TestTelegram_GrantMessageNilRulesVerbatim is the nil-rules twin for the grant
// approval message.
func TestTelegram_GrantMessageNilRulesVerbatim(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newSecretRedactBackend(t, fake, nil) // no rules

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	cmd := `printf 'PASSWORD=` + secretFixture + `'`
	if _, err := tb.RequestGrant(ctx, signerkit.GrantApprovalRequest{
		RequestID: "g_nilrules",
		Alias:     "prod",
		Scope:     "commands",
		Commands:  []string{cmd},
		Duration:  time.Hour,
	}); err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })
	body := fake.sentSnapshot()[0].Text
	if !strings.Contains(body, cmd) {
		t.Errorf("nil-rules grant backend should render command verbatim:\n%s", body)
	}
	if strings.Contains(body, redact.MarkerPrefix) {
		t.Errorf("nil-rules grant backend unexpectedly redacted:\n%s", body)
	}
}

// TestTelegram_ApprovalMessageDoesNotMutateRequest proves the redaction is
// DISPLAY-ONLY: the CommandReq.Cmd in the request the caller built is untouched
// after Request renders the (redacted) message. The daemon signs/executes from
// this same struct, so it must keep the RAW command.
func TestTelegram_ApprovalMessageDoesNotMutateRequest(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newSecretRedactBackend(t, fake, redactrules.Combined())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rawCmd := `printf 'PASSWORD=` + secretFixture + `'`
	req := signerkit.ApprovalRequest{
		RequestID: "r_nomutate",
		Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: rawCmd, TTLSec: 60}},
	}
	if _, err := tb.Request(ctx, req); err != nil {
		t.Fatalf("Request: %v", err)
	}
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })

	// The underlying request command must still be the RAW secret-bearing
	// string — only the DISPLAY copy in the message was redacted.
	if req.Commands[0].Cmd != rawCmd {
		t.Errorf("Request mutated the underlying command: got %q want %q", req.Commands[0].Cmd, rawCmd)
	}
}

// TestTelegram_GrantMessageDoesNotMutateRequest is the grant twin: the
// GrantApprovalRequest.Commands slice the caller built is untouched.
func TestTelegram_GrantMessageDoesNotMutateRequest(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newSecretRedactBackend(t, fake, redactrules.Combined())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rawCmd := `printf 'PASSWORD=` + secretFixture + `'`
	req := signerkit.GrantApprovalRequest{
		RequestID: "g_nomutate",
		Alias:     "prod",
		Scope:     "commands",
		Commands:  []string{rawCmd},
		Duration:  time.Hour,
	}
	if _, err := tb.RequestGrant(ctx, req); err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) == 1 })

	if req.Commands[0] != rawCmd {
		t.Errorf("RequestGrant mutated the underlying command: got %q want %q", req.Commands[0], rawCmd)
	}
}
