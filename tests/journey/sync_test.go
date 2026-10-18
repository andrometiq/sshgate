//go:build journey

package journey

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	tg "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	tool "github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/tests/journey/faketg"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type journeyCall struct {
	result    *mcp.CallToolResult
	err       error
	completed time.Time
}
type journeyCard struct {
	id        int
	at        time.Time
	requestID string
	text      string
}

func startCall(c *journeyMCP, name string, args map[string]any) <-chan journeyCall {
	done := make(chan journeyCall, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
		defer cancel()
		result, err := c.session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		completed := time.Now()
		if c.evidence != nil {
			if captureErr := c.evidence.append(name, map[string]any{"result": result, "transport_error": fmt.Sprint(err), "completed_at": completed}); captureErr != nil {
				err = captureErr
			}
		}
		done <- journeyCall{result, err, completed}
	}()
	return done
}
func finishCall(t *testing.T, e *journeyEvidence, done <-chan journeyCall, output any, wantError bool) journeyCall {
	t.Helper()
	select {
	case call := <-done:
		if call.err != nil {
			t.Fatalf("MCP transport: %v", call.err)
		}
		e.record(t, call.result)
		if call.result.IsError != wantError {
			t.Fatalf("MCP isError=%v, want %v", call.result.IsError, wantError)
		}
		if output != nil {
			data, err := json.Marshal(call.result.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) == "null" {
				t.Fatal("missing structured result")
			}
			if err = json.Unmarshal(data, output); err != nil {
				t.Fatal(err)
			}
		}
		return call
	case <-time.After(7 * time.Minute):
		t.Fatal("MCP completion deadline")
	}
	return journeyCall{}
}
func (r *journeyRig) events(t *testing.T) []faketg.Event {
	t.Helper()
	raw := r.exec(t, "controller", "curl", "--fail", "--silent", "--max-time", "5", "http://127.0.0.1:18081/events")
	var response struct {
		OK     bool
		Result struct {
			Events   []faketg.Event
			Failures []string
		}
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || len(response.Result.Failures) != 0 {
		t.Fatalf("fake Telegram failures: %v", response.Result.Failures)
	}
	if r.evidence != nil {
		for _, event := range response.Result.Events {
			if event.Sequence > r.eventSequence {
				r.evidence.record(t, map[string]any{"telegram": event})
				r.eventSequence = event.Sequence
			}
		}
	}
	return response.Result.Events
}
func cards(events []faketg.Event) map[int]journeyCard {
	found := map[int]journeyCard{}
	for _, event := range events {
		if event.Method != "sendMessage" && event.Method != "editMessageText" && event.Method != "editMessageReplyMarkup" {
			continue
		}
		var keyboard tg.InlineKeyboardMarkup
		if json.Unmarshal([]byte(event.Fields["reply_markup"]), &keyboard) != nil {
			continue
		}
		approve, deny := false, false
		requestID := ""
		for _, row := range keyboard.InlineKeyboard {
			for _, button := range row {
				if button.CallbackData == nil {
					continue
				}
				if strings.HasPrefix(*button.CallbackData, "approve:") {
					requestID = strings.TrimPrefix(*button.CallbackData, "approve:")
				}
				approve = approve || strings.Contains(strings.ToLower(button.Text), "approve")
				deny = deny || strings.Contains(strings.ToLower(button.Text), "deny")
			}
		}
		if !approve || !deny {
			continue
		}
		var message tg.Message
		if json.Unmarshal(event.Result, &message) != nil {
			continue
		}
		if message.MessageID != 0 {
			if _, ok := found[message.MessageID]; !ok {
				found[message.MessageID] = journeyCard{message.MessageID, event.Time, requestID, message.Text}
			}
		}
	}
	return found
}
func pollJourney(t *testing.T, description string, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if predicate() {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("deadline: %s", description)
		}
	}
}
func (r *journeyRig) nextCard(t *testing.T, before map[int]journeyCard) journeyCard {
	t.Helper()
	var card journeyCard
	pollJourney(t, "actionable card", 30*time.Second, func() bool {
		for id, value := range cards(r.events(t)) {
			if _, ok := before[id]; !ok {
				card = value
				return true
			}
		}
		return false
	})
	return card
}
func (r *journeyRig) cardEdit(t *testing.T, card journeyCard, text string) {
	t.Helper()
	pollJourney(t, "terminal card "+text, 30*time.Second, func() bool {
		for _, event := range r.events(t) {
			if event.Method == "editMessageText" && event.Fields["message_id"] == fmt.Sprint(card.id) && strings.Contains(event.Fields["text"], text) {
				return true
			}
		}
		return false
	})
}
func (r *journeyRig) tap(t *testing.T, card journeyCard, action string, replay bool) {
	if r.evidence != nil {
		r.evidence.record(t, map[string]any{"timeline": "tap", "message_id": card.id, "action": action, "replay": replay})
	}
	route := "/release"
	if replay {
		route = "/replay"
	}
	r.telegramAdmin(t, route, fmt.Sprintf(`{"message_id":%d,"action":%q}`, card.id, action))
}
func (r *journeyRig) replayRefused(t *testing.T, card journeyCard, action string) {
	before := r.events(t)
	sequence := 0
	if len(before) > 0 {
		sequence = before[len(before)-1].Sequence
	}
	r.tap(t, card, action, true)
	pollJourney(t, "stale callback refusal", 30*time.Second, func() bool {
		events := r.events(t)
		callbackID := ""
		for _, event := range events {
			if event.Sequence <= sequence || event.Method != "getUpdates" {
				continue
			}
			var updates []tg.Update
			if json.Unmarshal(event.Result, &updates) != nil {
				t.Fatal("invalid callback delivery evidence")
			}
			for _, update := range updates {
				cb := update.CallbackQuery
				if cb != nil && cb.Message != nil && cb.Message.MessageID == card.id && cb.Data == action+":"+card.requestID {
					callbackID = cb.ID
				}
			}
		}
		if callbackID == "" {
			return false
		}
		for _, event := range events {
			if event.Sequence > sequence && event.Method == "answerCallbackQuery" && event.Fields["callback_query_id"] == callbackID && strings.Contains(event.Fields["text"], "expired or already resolved") {
				return true
			}
		}
		return false
	})
}
func (r *journeyRig) absent(t *testing.T, host, path string) {
	t.Helper()
	r.exec(t, host, "test", "!", "-e", path)
}
func (r *journeyRig) health(t *testing.T, want string) {
	t.Helper()
	got := r.exec(t, "target-a", "curl", "--silent", "--show-error", "--max-time", "5", "-w", "%{http_code}", "http://127.0.0.1:8080/")
	if got != want {
		t.Fatalf("health=%q, want %q", got, want)
	}
}
func (r *journeyRig) audit(t *testing.T, host string) []map[string]any {
	t.Helper()
	path := "/home/user/.sshgate-gate/audit.log"
	if host == "controller" {
		path = "/var/lib/sshgatesigner/log/approvals.log"
	}
	raw := r.exec(t, host, "cat", path)
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if r.evidence != nil && raw != r.auditSnapshots[host] {
		r.evidence.record(t, map[string]any{"audit_host": host, "rows": rows})
		if r.auditSnapshots == nil {
			r.auditSnapshots = make(map[string]string)
		}
		r.auditSnapshots[host] = raw
	}
	return rows
}
func (r *journeyRig) auditCount(t *testing.T, host, command, status string, want int) {
	t.Helper()
	pollJourney(t, "audit "+host+" "+command, 30*time.Second, func() bool {
		count := 0
		for _, row := range r.audit(t, host) {
			match := row["command"] == command
			if host == "controller" {
				match = false
				if commands, ok := row["commands"].([]any); ok {
					for _, c := range commands {
						match = match || c == command
					}
				}
			}
			if !match {
				continue
			}
			field := "approval_status"
			if host == "controller" {
				field = "status"
			}
			if status == "" || row[field] == status || (status == "approved" && strings.HasPrefix(fmt.Sprint(row[field]), "approved")) {
				if status == "approved" && want > 0 && (row[field] != "approved" || row["auth_mode"] != "human" || !nonemptyString(row["request_id"])) {
					t.Fatal("signer approval was not delivered with human authorization")
				}
				if status == "signed" && row["exit_code"] != float64(0) {
					t.Fatal("signed gate execution failed")
				}
				count++
			}
		}
		if count > want {
			t.Fatalf("%s audit count=%d, want %d", host, count, want)
		}
		return count == want
	})
}
func assertRun(t *testing.T, out tool.RunOutput, stdout string) {
	t.Helper()
	if out.Stdout != stdout || out.Stderr != "" || out.ExitCode != 0 || !out.Approved || out.AuthMode != "human" || out.Denial != nil {
		t.Fatalf("unexpected approved result: %+v", out)
	}
}
func assertDenial(t *testing.T, out tool.RunOutput, verdict string) {
	t.Helper()
	if out.Denial == nil || out.Denial.VerdictClass != verdict || out.Approved {
		t.Fatalf("unexpected denial: %+v", out)
	}
	if verdict == "approval_denied" && out.Denial.Retryable {
		t.Fatal("denial must not be retryable")
	}
}
func runArgs(command string) map[string]any {
	return map[string]any{"alias": "web1", "command": command}
}

// Re-tiering follows the documented human-only deprovision/re-add procedure.
func (r *journeyRig) signedCandidate(t *testing.T) {
	publicKey := strings.TrimSpace(r.operator(t, "sshgate pubkey 2>/dev/null"))
	if strings.ContainsAny(publicKey, "'\r\n") {
		t.Fatal("invalid public key")
	}
	r.exec(t, "target-a", "bash", "-ec", "printf '%s\\n' '"+publicKey+"' > /home/user/.ssh/authorized_keys")
	r.operator(t, `python3 - <<'PY'
import json
from pathlib import Path
p = Path.home()/".config/sshgate/servers.json"
data = json.loads(p.read_text())
del data["web1"]
p.write_text(json.dumps(data))
PY`)
	r.telegramAdmin(t, "/policy", `{"policy":"approve_now"}`)
	enrollment := r.operator(t, "SSHGATE_GATE_BIN=$HOME/src/SSHGate/bin/sshgate-gate-linux-amd64 sshgate add web1 user@target-a")
	if !strings.Contains(enrollment, `transfer:    registered (label "web1")`) {
		t.Fatal("web1 transfer enrollment failed")
	}
	r.telegramAdmin(t, "/policy", `{"policy":"hold"}`)
	// update_gate tests the candidate on the already enrolled second target.
	client := r.mcp(t)
	r.operator(t, "cp ~/src/SSHGate/bin/sshgate-gate-linux-amd64 ~/.config/sshgate/bin/sshgate-gate-linux-amd64")
	r.telegramAdmin(t, "/policy", `{"policy":"approve_now"}`)
	client.call(t, "update_gate", map[string]any{"alias": "web2"}, nil)
	r.telegramAdmin(t, "/policy", `{"policy":"hold"}`)
	client.close(t)
	expected := strings.Fields(r.operator(t, "sha256sum ~/src/SSHGate/bin/sshgate-gate-linux-amd64"))[0]
	for _, host := range []string{"target-a", "target-b"} {
		got := strings.Fields(r.exec(t, host, "sha256sum", "/home/user/.sshgate-gate/gate"))[0]
		if got != expected {
			t.Fatal("candidate gate hash mismatch")
		}
		r.exec(t, host, "runuser", "-u", "user", "--", "sh", "-c", "printf 'all\\n' > /home/user/.sshgate-gate/audit-level")
	}
}

func TestJourneyMain(t *testing.T) {
	evidence := &journeyEvidence{directory: os.Getenv("JOURNEY_ARTIFACT_DIR")}
	evidence.record(t, map[string]any{"timeline": "starting rig"})
	t.Cleanup(func() { evidence.summary(t) })
	r := newJourneyRig(t)
	r.evidence = evidence
	r.addReadOnly(t)
	r.candidateReadOnly(t)
	client := r.mcp(t)
	if !t.Run("useful_diagnosis", func(t *testing.T) {
		r.exec(t, "controller", "test", "!", "-e", "/etc/systemd/system/sshgate-signer-telegram.service")
		var status tool.StatusOutput
		if result := client.call(t, "status", map[string]any{}, &status); result.IsError || status.SignerSocket.Configured || status.SignerSocket.Reachable {
			t.Fatal("diagnosis requires a signer-free installation")
		}
		r.wait(t, "target-a", "curl", "--silent", "--max-time", "2", "http://127.0.0.1:8080/")
		r.health(t, "disabled: enabled=0\n503")
		for _, read := range []struct{ command, contains string }{
			{"cat /home/user/health.conf", "enabled=0"},
			{"cat /home/user/health.log", "unhealthy: enabled=0"},
			{"df -h", "Filesystem"}, {"ps -ef", "sshd"},
		} {
			var out tool.RunOutput
			result := client.call(t, "run", runArgs(read.command), &out)
			evidence.record(t, result)
			if result.IsError || out.Denial != nil || out.Stderr != "" || out.ExitCode != 0 || out.Kind != "read" || out.Approved || !strings.Contains(out.Stdout, read.contains) {
				t.Fatalf("diagnostic result: %+v", out)
			}
		}
		var denied tool.RunOutput
		finishCall(t, evidence, startCall(client, "run", runArgs("touch /home/user/tier1-marker")), &denied, true)
		assertDenial(t, denied, "read_only_server")
		r.absent(t, "target-a", "/home/user/tier1-marker")
		r.operator(t, `set +e
ssh -o UserKnownHostsFile=$HOME/.config/sshgate/known_hosts -o BatchMode=yes -o StrictHostKeyChecking=yes -i ~/.config/sshgate/ssh/sshgate_ed25519 user@target-a 'touch /home/user/unsigned-marker'
code=$?
test "$code" = 77`)
		r.absent(t, "target-a", "/home/user/unsigned-marker")
	}) {
		return
	}
	client.close(t)
	r.installSigner(t)
	t.Cleanup(func() {
		r.events(t)
		for _, host := range []string{"target-a", "target-b", "controller"} {
			r.audit(t, host)
		}
	})
	r.signedCandidate(t)
	client = r.mcp(t)
	// Candidate doctor and actual read audit must agree on the intentional fallback.
	doctor := r.exec(t, "target-a", "runuser", "-u", "user", "--", "/home/user/.sshgate-gate/gate", "doctor", "--json")
	var report map[string]any
	if err := json.Unmarshal([]byte(doctor), &report); err != nil {
		t.Fatal(err)
	}
	if report["enforcement"] != "classifier" || report["pinned"] != false {
		t.Fatalf("unexpected doctor fallback: %s", doctor)
	}
	evidence.record(t, report)
	var read tool.RunOutput
	result := client.call(t, "run", runArgs("head -n 1 /home/user/health.conf"), &read)
	if result.IsError || read.ExitCode != 0 || read.Stdout != "enabled=0\n" || read.Stderr != "" || read.Denial != nil {
		t.Fatal("candidate head failed")
	}
	pollJourney(t, "successful candidate read audit", 30*time.Second, func() bool {
		found := false
		for _, row := range r.audit(t, "target-a") {
			if row["command"] == "head -n 1 /home/user/health.conf" {
				found = true
				if row["exit_code"] != float64(0) || row["enforcement"] != "classifier" || row["pinned"] != false || row["jail_absent"] == nil || row["jail_absent"] == "" {
					t.Fatal("read audit does not establish classifier fallback")
				}
			}
		}
		return found
	})
	if !t.Run("approve_immediately", func(t *testing.T) {
		command := "printf 'marker\\n' > /home/user/immediate; printf 'approved\\n'"
		r.absent(t, "target-a", "/home/user/immediate")
		before := cards(r.events(t))
		r.telegramAdmin(t, "/policy", `{"policy":"hold"}`)
		done := startCall(client, "run", runArgs(command))
		card := r.nextCard(t, before)
		r.absent(t, "target-a", "/home/user/immediate")
		select {
		case <-done:
			t.Fatal("call completed before tap")
		default:
		}
		r.tap(t, card, "approve", false)
		var out tool.RunOutput
		finishCall(t, evidence, done, &out, false)
		assertRun(t, out, "approved\n")
		r.cardEdit(t, card, "Approved")
		if len(cards(r.events(t))) != len(before)+1 {
			t.Fatal("expected one decision")
		}
		if r.exec(t, "target-a", "cat", "/home/user/immediate") != "marker\n" {
			t.Fatal("marker bytes differ")
		}
		r.signerDecision(t, card, []string{command}, []string{"web1"}, "approved")
		r.auditCount(t, "target-a", command, "signed", 1)
	}) {
		return
	}
	if !t.Run("deny_and_replay", func(t *testing.T) {
		command := "touch /home/user/denied"
		before := cards(r.events(t))
		r.telegramAdmin(t, "/policy", `{"policy":"deny"}`)
		var out tool.RunOutput
		finishCall(t, evidence, startCall(client, "run", runArgs(command)), &out, true)
		assertDenial(t, out, "approval_denied")
		card := r.nextCard(t, before)
		r.cardEdit(t, card, "Denied")
		r.replayRefused(t, card, "deny")
		r.absent(t, "target-a", "/home/user/denied")
		r.signerDecision(t, card, []string{command}, []string{"web1"}, "denied")
		r.auditCount(t, "controller", command, "", 1)
		r.auditCount(t, "target-a", command, "", 0)
		if len(cards(r.events(t))) != len(before)+1 {
			t.Fatal("duplicate decision")
		}
	}) {
		return
	}
	if !t.Run("concurrent_approval_window", func(t *testing.T) { testJourneyWindow(t, r, client, evidence) }) {
		return
	}
	if !t.Run("restart_pending", func(t *testing.T) {
		r.telegramAdmin(t, "/policy", `{"policy":"hold"}`)
		command := "touch /home/user/restart-marker"
		before := cards(r.events(t))
		done := startCall(client, "run", runArgs(command))
		card := r.nextCard(t, before)
		r.absent(t, "target-a", "/home/user/restart-marker")
		r.exec(t, "controller", "systemctl", "restart", "sshgate-signer-telegram")
		r.wait(t, "controller", "systemctl", "is-active", "sshgate-signer-telegram")
		// The old socket must terminate; a transport failure is also fail-closed.
		select {
		case call := <-done:
			evidence.record(t, map[string]any{"result": call.result, "transport_error": fmt.Sprint(call.err)})
			if call.err == nil && call.result != nil && !call.result.IsError {
				t.Fatal("pending request succeeded across restart")
			}
		case <-time.After(40 * time.Second):
			t.Fatal("old request did not terminate after restart")
		}
		r.replayRefused(t, card, "approve")
		r.absent(t, "target-a", "/home/user/restart-marker")
		r.auditCount(t, "target-a", command, "", 0)
		r.auditCount(t, "controller", command, "approved", 0)
		if len(cards(r.events(t))) != len(before)+1 {
			t.Fatal("restart automatically resubmitted")
		}
	}) {
		return
	}
	t.Run("secret_transfer", func(t *testing.T) { testJourneyTransfer(t, r, client, evidence) })
}

func testJourneyWindow(t *testing.T, r *journeyRig, client *journeyMCP, evidence *journeyEvidence) {
	r.telegramAdmin(t, "/policy", `{"policy":"hold"}`)
	before := cards(r.events(t))
	commands := []string{"printf 'enabled=1\\n' > /home/user/health.conf; printf 'configured\\n'", "printf 'once\\n' >> /home/user/fix-counter; printf 'counted\\n'"}
	late := startCall(client, "run_batch", map[string]any{"alias": "web1", "commands": commands})
	lateCard := r.nextCard(t, before)
	r.telegramAdmin(t, "/policy", `{"policy":"never"}`)
	beforeNever := cards(r.events(t))
	neverCommand := "touch /home/user/never-marker"
	never := startCall(client, "run", runArgs(neverCommand))
	neverCard := r.nextCard(t, beforeNever)
	r.telegramAdmin(t, "/policy", `{"policy":"approve_after_sync_wait"}`)
	beforeExpired := cards(r.events(t))
	expiredCommand := "touch /home/user/expired-marker"
	expired := startCall(client, "run", runArgs(expiredCommand))
	expiredCard := r.nextCard(t, beforeExpired)
	// Continuously observe invariants; the timer is anchored to delivered-card evidence.
	pollJourney(t, "240 seconds after card delivery", 250*time.Second, func() bool {
		r.health(t, "disabled: enabled=0\n503")
		if r.exec(t, "target-a", "cat", "/home/user/health.conf") != "enabled=0\n" {
			t.Fatal("configuration changed before approval")
		}
		r.absent(t, "target-a", "/home/user/fix-counter")
		r.absent(t, "target-a", "/home/user/never-marker")
		r.absent(t, "target-a", "/home/user/expired-marker")
		return time.Since(lateCard.at) >= 240*time.Second
	})
	r.tap(t, lateCard, "approve", false)
	var batch tool.RunBatchOutput
	finishCall(t, evidence, late, &batch, false)
	if !batch.Approved || batch.AuthMode != "human" || len(batch.Results) != 2 {
		t.Fatalf("batch result: %+v", batch)
	}
	for i, want := range []string{"configured\n", "counted\n"} {
		result := batch.Results[i]
		if result.Stdout != want || result.Stderr != "" || result.ExitCode != 0 || result.Skipped {
			t.Fatalf("batch command: %+v", result)
		}
		r.auditCount(t, "target-a", commands[i], "signed", 1)
	}
	r.signerDecision(t, lateCard, commands, []string{"web1", "web1"}, "approved")
	r.health(t, "ok\n200")
	if r.exec(t, "target-a", "cat", "/home/user/health.conf") != "enabled=1\n" || r.exec(t, "target-a", "cat", "/home/user/fix-counter") != "once\n" {
		t.Fatal("repair effects differ")
	}
	r.cardEdit(t, lateCard, "Approved")
	for _, request := range []struct {
		done          <-chan journeyCall
		card          journeyCard
		command, path string
	}{
		{never, neverCard, neverCommand, "/home/user/never-marker"},
		{expired, expiredCard, expiredCommand, "/home/user/expired-marker"},
	} {
		var out tool.RunOutput
		call := finishCall(t, evidence, request.done, &out, true)
		assertWindow(t, request.card, call.completed)
		evidence.record(t, map[string]any{"request_id": request.card.requestID, "card_at": request.card.at, "completed_at": call.completed})
		assertDenial(t, out, "approval_timeout")
		r.cardEdit(t, request.card, "Expired")
		for _, event := range r.events(t) {
			if event.Method == "editMessageText" && event.Fields["message_id"] == fmt.Sprint(request.card.id) && strings.Contains(event.Fields["text"], "Expired") {
				assertWindow(t, request.card, event.Time)
			}
		}
		r.absent(t, "target-a", request.path)
		r.auditCount(t, "target-a", request.command, "", 0)
		r.signerDecision(t, request.card, []string{request.command}, []string{"web1"}, "timeout")
		r.auditCount(t, "controller", request.command, "approved", 0)
	}
	r.replayRefused(t, expiredCard, "approve")
	r.absent(t, "target-a", "/home/user/expired-marker")
	r.auditCount(t, "controller", expiredCommand, "approved", 0)
	r.auditCount(t, "target-a", expiredCommand, "", 0)
	if len(cards(r.events(t))) != len(before)+3 {
		t.Fatal("expected one decision per independent request")
	}
}

func nonemptyString(value any) bool { s, ok := value.(string); return ok && s != "" }

func assertWindow(t *testing.T, card journeyCard, completed time.Time) {
	t.Helper()
	if !strings.Contains(card.text, "5m0s") {
		t.Fatal("card does not advertise five-minute validity")
	}
	elapsed := completed.Sub(card.at)
	if elapsed < 295*time.Second || elapsed > 330*time.Second {
		t.Fatalf("approval window elapsed %s, want 300s with transport tolerance", elapsed)
	}
}

func (r *journeyRig) signerDecision(t *testing.T, card journeyCard, commands, servers []string, status string) {
	t.Helper()
	if card.requestID == "" {
		t.Fatal("card has no request identity")
	}
	pollJourney(t, "correlated signer decision", 30*time.Second, func() bool {
		count := 0
		for _, row := range r.audit(t, "controller") {
			if row["request_id"] != card.requestID {
				continue
			}
			count++
			encodedCommands, _ := json.Marshal(row["commands"])
			wantCommands, _ := json.Marshal(commands)
			encodedServers, _ := json.Marshal(row["servers"])
			wantServers, _ := json.Marshal(servers)
			if string(encodedCommands) != string(wantCommands) || string(encodedServers) != string(wantServers) || row["status"] != status || (status == "approved" && row["auth_mode"] != "human") {
				t.Fatal("correlated signer decision differs")
			}
		}
		if count > 1 {
			t.Fatal("duplicate signer decision")
		}
		return count == 1
	})
}

func (r *journeyRig) candidateReadOnly(t *testing.T) {
	publicKey := strings.TrimSpace(r.operator(t, "sshgate pubkey 2>/dev/null"))
	if strings.ContainsAny(publicKey, "'\r\n") {
		t.Fatal("invalid public key")
	}
	r.exec(t, "target-a", "bash", "-ec", "printf '%s\\n' '"+publicKey+"' > /home/user/.ssh/authorized_keys; rm -rf /home/user/.sshgate-gate")
	r.operator(t, `python3 - <<'PYTHON'
import json
from pathlib import Path
p=Path.home()/".config/sshgate/servers.json"
data=json.loads(p.read_text()); del data["web1"]; p.write_text(json.dumps(data))
PYTHON`)
	r.operator(t, "SSHGATE_GATE_BIN=$HOME/src/SSHGate/bin/sshgate-gate-linux-amd64 sshgate add web1 user@target-a --read-only")
	r.exec(t, "target-a", "test", "!", "-e", "/home/user/.sshgate-gate/gate.pub")
	expected := strings.Fields(r.operator(t, "sha256sum ~/src/SSHGate/bin/sshgate-gate-linux-amd64"))[0]
	if strings.Fields(r.exec(t, "target-a", "sha256sum", "/home/user/.sshgate-gate/gate"))[0] != expected {
		t.Fatal("Tier-1 candidate hash mismatch")
	}
}
