package backend

import (
	"context"
	"io"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/src/redact"
)

type explainerCapture struct {
	calls    int
	commands []string
}

func (e *explainerCapture) Explain(_ context.Context, commands []string) ([]string, error) {
	e.calls++
	e.commands = append([]string(nil), commands...)
	return []string{"advisory"}, nil
}

func TestRunExplainerRedactionGate(t *testing.T) {
	rules := []redact.Rule{redact.CompileRule("secret", "", `planted-secret`, nil, 0, 0, 0)}
	for _, tc := range []struct {
		name   string
		rules  []redact.Rule
		second string
	}{
		{"nil", nil, "echo safe"},
		{"empty", []redact.Rule{}, "echo safe"},
		{"broken", []redact.Rule{{ID: "broken"}}, "echo safe"},
		{"oversize second command", rules, strings.Repeat("x", redact.MaxSpanInput+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &explainerCapture{}
			b := &TelegramBackend{Explainer: provider, RedactRules: tc.rules, logger: log.New(io.Discard, "", 0)}
			commands := []signerkit.CommandReq{{Cmd: "echo planted-secret"}, {Cmd: tc.second}}
			lines, err := b.runExplainer(context.Background(), commands)
			if provider.calls != 0 || len(lines) != 0 || err == nil || err.Error() != assist.ReasonRedaction {
				t.Fatalf("calls=%d lines=%v err=%v", provider.calls, lines, err)
			}
			if len(tc.rules) != 0 {
				return
			}
			body := formatApprovalMessage(signerkit.ApprovalRequest{Commands: commands}, time.Minute, lines, err, b.RedactSalt, b.RedactRules)
			if !strings.Contains(body, "(no explanations: redaction unavailable)") {
				t.Fatal("missing redaction skip footer")
			}
			if len(tc.rules) == 0 && !strings.Contains(body, "echo planted-secret") {
				t.Fatal("nil-rules display changed")
			}
		})
	}
}

func TestRunExplainerProviderSafeCommands(t *testing.T) {
	provider := &explainerCapture{}
	b := &TelegramBackend{Explainer: provider, RedactRules: []redact.Rule{redact.CompileRule("secret", "", `planted-secret`, nil, 0, 0, 0)}}
	commands := []signerkit.CommandReq{{Cmd: "echo planted-secret"}, {Cmd: "echo unmatched"}}
	before := append([]signerkit.CommandReq(nil), commands...)
	lines, err := b.runExplainer(context.Background(), commands)
	want := []string{"echo ⟦hidden 14 bytes · secret⟧", "echo unmatched"}
	if err != nil || provider.calls != 1 || !reflect.DeepEqual(provider.commands, want) || !reflect.DeepEqual(lines, []string{"advisory"}) {
		t.Fatalf("calls=%d commands=%q lines=%v err=%v", provider.calls, provider.commands, lines, err)
	}
	if !reflect.DeepEqual(commands, before) {
		t.Fatal("provider redaction changed approval commands")
	}
}
