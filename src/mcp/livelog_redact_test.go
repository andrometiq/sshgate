package mcp

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/livelog"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// mcpRedactSalt is a fixed salt for the MCP command-string redaction tests
// (determinism in test; production wires a per-process random salt).
var mcpRedactSalt = [32]byte{0x42}

// TestRunHandlerRedactsCommandInLiveLog (F5): a secret embedded in the
// COMMAND STRING must be scrubbed before it lands in the Tier-6b MCP live
// log — previously only the OUTPUT was redacted, so a `printf 'PASSWORD=...'`
// command landed verbatim.
func TestRunHandlerRedactsCommandInLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	srv := &Server{
		Runner:      runner,
		Logger:      log.New(io.Discard, "", 0),
		LiveLog:     ll,
		RedactSalt:  mcpRedactSalt,
		RedactRules: redactrules.Combined(),
	}

	const secret = "hunter2secretvalue"
	// `sh -c ...` is a write, but the live-log command-string redaction is
	// independent of read/write — drive it directly so the test pins the
	// command field, not the approval path.
	cmd := `sh -c "printf 'PASSWORD=` + secret + `'"`
	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: cmd}); err != nil {
		t.Fatalf("runHandler: %v", err)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	gotCmd, _ := recs[0]["command"].(string)
	if strings.Contains(gotCmd, secret) {
		t.Errorf("live-log command leaked the secret: %q", gotCmd)
	}
	if !strings.Contains(gotCmd, redact.MarkerPrefix) {
		t.Errorf("live-log command not redacted (no marker): %q", gotCmd)
	}
	// Defence in depth: secret absent anywhere in the file.
	raw, _ := os.ReadFile(logPath)
	if strings.Contains(string(raw), secret) {
		t.Errorf("secret persisted in live log:\n%s", raw)
	}
}

// TestRunHandlerRedactsTelegramTokenInLiveLog (2026-07 default-deny widening,
// cross-sink check): a Telegram bot token embedded in a command string — here
// in the glued `.../bot<id>:<body>/…` API-URL form that no word-boundary regex
// can match — must be scrubbed by the engine's generic net (digit-suffix peel)
// before it lands in the MCP live log.
func TestRunHandlerRedactsTelegramTokenInLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	srv := &Server{
		Runner:      runner,
		Logger:      log.New(io.Discard, "", 0),
		LiveLog:     ll,
		RedactSalt:  mcpRedactSalt,
		RedactRules: redactrules.Combined(),
	}

	// Assemble a telegram bot token at runtime (no contiguous literal):
	// <10-digit id>:AA<33 base64url> = the exact real shape.
	token := "1234567890:AA" + strings.Repeat("Zk9", 11)
	cmd := `sh -c "curl https://api.telegram.org/bot` + token + `/sendMessage"`
	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: cmd}); err != nil {
		t.Fatalf("runHandler: %v", err)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	gotCmd, _ := recs[0]["command"].(string)
	if strings.Contains(gotCmd, token) {
		t.Errorf("live-log leaked the telegram token: %q", gotCmd)
	}
	if !strings.Contains(gotCmd, redact.MarkerPrefix) {
		t.Errorf("telegram token not redacted in live log: %q", gotCmd)
	}
	raw, _ := os.ReadFile(logPath)
	if strings.Contains(string(raw), token) {
		t.Errorf("telegram token persisted in live log:\n%s", raw)
	}
}

// TestRunBatchHandlerRedactsCommandInLiveLog (F5): the per-result live-log
// entries in run_batch must redact each command string too.
func TestRunBatchHandlerRedactsCommandInLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	srv := &Server{
		Runner:      runner,
		Logger:      log.New(io.Discard, "", 0),
		LiveLog:     ll,
		RedactSalt:  mcpRedactSalt,
		RedactRules: redactrules.Combined(),
	}

	const secret = "ghp_abcd1234efghbatch"
	secretCmd := `export GITHUB_TOKEN=` + secret
	if _, _, err := srv.runBatchHandler(context.Background(), nil, tools.RunBatchInput{
		Alias:    "web1",
		Commands: []string{"ls", secretCmd},
	}); err != nil {
		t.Fatalf("runBatchHandler: %v", err)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("got %d live-log records, want 2", len(recs))
	}
	var sawBenign, sawRedacted bool
	for _, rec := range recs {
		gotCmd, _ := rec["command"].(string)
		if strings.Contains(gotCmd, secret) {
			t.Errorf("run_batch live-log leaked the secret: %q", gotCmd)
		}
		if gotCmd == "ls" {
			sawBenign = true
		}
		if strings.Contains(gotCmd, redact.MarkerPrefix) {
			sawRedacted = true
		}
	}
	if !sawBenign {
		t.Errorf("benign `ls` command was altered in the live log")
	}
	if !sawRedacted {
		t.Errorf("secret-bearing command was not redacted in the live log")
	}
}

// TestRunHandlerBenignCommandUnchangedInLiveLog proves the command-string
// redaction does NOT over-redact: a benign command keeps its verbatim text
// (no marker) in the live log.
func TestRunHandlerBenignCommandUnchangedInLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	srv := &Server{
		Runner:      runner,
		Logger:      log.New(io.Discard, "", 0),
		LiveLog:     ll,
		RedactSalt:  mcpRedactSalt,
		RedactRules: redactrules.Combined(),
	}

	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: "cat /etc/hostname"}); err != nil {
		t.Fatalf("runHandler: %v", err)
	}
	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	gotCmd, _ := recs[0]["command"].(string)
	if gotCmd != "cat /etc/hostname" {
		t.Errorf("benign command altered: got %q", gotCmd)
	}
	if strings.Contains(gotCmd, redact.MarkerPrefix) {
		t.Errorf("benign command carries a marker: %q", gotCmd)
	}
}

// TestRunHandlerNoRedactRulesPassThrough proves a Server with no RedactRules
// configured (nil) logs the command verbatim — RedactString fast-paths nil
// rules, so the live-log hook is safe and unchanged for a server that did not
// wire a ruleset.
func TestRunHandlerNoRedactRulesPassThrough(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	// No RedactSalt / RedactRules wired.
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	cmd := `export GITHUB_TOKEN=ghp_unredactedwhenrulesnil`
	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: cmd}); err != nil {
		t.Fatalf("runHandler: %v", err)
	}
	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	if recs[0]["command"] != cmd {
		t.Errorf("nil-rules server should log command verbatim: got %q want %q", recs[0]["command"], cmd)
	}
}
