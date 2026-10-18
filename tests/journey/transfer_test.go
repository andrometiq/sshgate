//go:build journey

package journey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	tool "github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const journeySentinel = "JOURNEY_SYNTHETIC_PLAINTEXT_MUST_NOT_ESCAPE"

func testJourneyTransfer(t *testing.T, r *journeyRig, client *journeyMCP, evidence *journeyEvidence) {
	const source = "/home/user/source.bin"
	const destination = "/home/user/received.bin"
	// Seed only through the observer, never through the MCP or a command approval.
	r.exec(t, "target-a", "python3", "-c", `from pathlib import Path
import os
p=Path("/home/user/source.bin")
p.write_bytes(bytes(range(256)) + b"JOURNEY_SYNTHETIC_PLAINTEXT_MUST_NOT_ESCAPE" + b"\x00\xff\n")
os.chmod(p,0o600)
`)
	r.exec(t, "target-a", "chown", "user:user", source)
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}
	secret = append(secret, []byte(journeySentinel)...)
	secret = append(secret, 0, 255, '\n')
	hash := fmt.Sprintf("%x", sha256.Sum256(secret))
	metadata := func(host, path string) string {
		return r.exec(t, host, "python3", "-c", `import hashlib, pathlib, sys
p=pathlib.Path(sys.argv[1])
data=p.read_bytes()
print(len(data), hashlib.sha256(data).hexdigest(), oct(p.stat().st_mode & 0o7777))
`, path)
	}
	expected := fmt.Sprintf("%d %s 0o600\n", len(secret), hash)
	if metadata("target-a", source) != expected {
		t.Fatal("seed metadata mismatch")
	}
	r.absent(t, "target-b", destination)
	r.telegramAdmin(t, "/policy", `{"policy":"approve_now"}`)
	before := cards(r.events(t))
	args := map[string]any{"src_alias": "web1", "src_path": source, "dest_alias": "web2", "dest_path": destination}
	var out tool.TransferOutput
	call := finishCall(t, evidence, startCall(client, "transfer", args), &out, false)
	if !transferMetadataOnly(call.result, out) {
		t.Fatal("transfer returned non-metadata content")
	}
	if out.XferID == "" || out.Bytes != int64(len(secret)) || out.AuthMode != "human" || out.Mode != "0600" ||
		out.SrcAlias != "web1" || out.DestAlias != "web2" || out.SrcPath != source || out.DestPath != destination {
		t.Fatal("transfer metadata mismatch")
	}
	if metadata("target-a", source) != expected || metadata("target-b", destination) != expected {
		t.Fatal("transfer changed source or destination metadata differs")
	}
	card := r.nextCard(t, before)
	r.cardEdit(t, card, "Approved")
	if len(cards(r.events(t))) != len(before)+1 {
		t.Fatal("transfer required more than one decision")
	}
	banner := false
	for _, event := range r.events(t) {
		var message struct {
			ID int `json:"message_id"`
		}
		if json.Unmarshal(event.Result, &message) != nil || message.ID != card.id {
			continue
		}
		if strings.Contains(event.Fields["text"], "SECRET TRANSFER") {
			banner = true
		}
	}
	if !banner {
		t.Fatal("missing SECRET TRANSFER banner")
	}
	for _, host := range []string{"target-a", "target-b"} {
		pollJourney(t, "transfer gate audit", 30*time.Second, func() bool {
			count := 0
			for _, row := range r.audit(t, host) {
				command, _ := row["command"].(string)
				if host == "target-a" {
					// The gate audit redacts the leg's key fields, so match the plain
					// base64url id and path tokens instead of parsing the leg.
					if !auditLegHas(command, "SSHGATE_XFER_SEND", out.XferID) {
						continue
					}
					if !auditLegHas(command, "SSHGATE_XFER_SEND", source) {
						t.Fatal("SEND path mismatch")
					}
				} else {
					if !auditLegHas(command, "SSHGATE_XFER_RECV", out.XferID) {
						continue
					}
					if !auditLegHas(command, "SSHGATE_XFER_RECV", destination) {
						t.Fatal("RECV path mismatch")
					}
				}
				count++
				if row["approval_status"] != "signed" || row["exit_code"] != float64(0) {
					t.Fatal("transfer gate leg failed")
				}
			}
			if count > 1 {
				t.Fatal("duplicate transfer gate leg")
			}
			return count == 1
		})
	}
	r.transferDecision(t, card, out.XferID, "approved")
	before = cards(r.events(t))
	signerBefore := len(r.audit(t, "controller"))
	gateA := len(r.audit(t, "target-a"))
	gateB := len(r.audit(t, "target-b"))
	r.telegramAdmin(t, "/policy", `{"policy":"deny"}`)
	args["dest_path"] = "/home/user/denied-transfer.bin"
	finishCall(t, evidence, startCall(client, "transfer", args), nil, true)
	denied := r.nextCard(t, before)
	r.cardEdit(t, denied, "Denied")
	r.absent(t, "target-b", "/home/user/denied-transfer.bin")
	r.transferDecision(t, denied, "", "denied")
	if len(r.audit(t, "controller")) != signerBefore+1 {
		t.Fatal("denied transfer signer count mismatch")
	}
	if len(cards(r.events(t))) != len(before)+1 {
		t.Fatal("denied transfer decision count mismatch")
	}
	if len(r.audit(t, "target-a")) != gateA || len(r.audit(t, "target-b")) != gateB {
		t.Fatal("denied transfer reached a gate")
	}
	if metadata("target-a", source) != expected {
		t.Fatal("denial changed source")
	}

	client.close(t)
	// Scan before persisting any evidence. Never print the offending content.
	surfaces := []any{evidence.transcript, r.events(t), r.audit(t, "controller"), r.audit(t, "target-a"), r.audit(t, "target-b")}
	surfaces = append(surfaces, r.exec(t, "controller", "journalctl", "--no-pager", "-u", "sshgate-signer-telegram", "-u", "journey-fake-telegram", "-o", "cat", "-n", "10000"))
	surfaces = append(surfaces, r.operator(t, `find ~/.config/sshgate -type f -name '*log*' -exec cat {} +`))
	for _, surface := range surfaces {
		data, err := json.Marshal(surface)
		if err != nil {
			t.Fatal(err)
		}
		if containsSecret(data) {
			evidence.transcript = nil
			t.Fatal("synthetic plaintext leaked into an agent-visible surface")
		}
	}
}

// auditLegHas reports whether a gate-audited transfer leg of the given verb
// carries value as one of its base64url fields.
func auditLegHas(command, verb, value string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 || fields[0] != verb {
		return false
	}
	return slices.Contains(fields[1:], base64.RawURLEncoding.EncodeToString([]byte(value)))
}

func transferMetadataOnly(result *mcp.CallToolResult, out tool.TransferOutput) bool {
	expected := map[string]any{"src_alias": out.SrcAlias, "src_path": out.SrcPath, "dest_alias": out.DestAlias, "dest_path": out.DestPath, "mode": out.Mode, "xfer_id": out.XferID, "bytes": out.Bytes, "auth_mode": out.AuthMode}
	actualJSON, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return false
	}
	expectedJSON, _ := json.Marshal(expected)
	var actual, want any
	if json.Unmarshal(actualJSON, &actual) != nil || json.Unmarshal(expectedJSON, &want) != nil || !reflect.DeepEqual(actual, want) {
		return false
	}
	text := fmt.Sprintf("transferred %s:%s → %s:%s (xfer=%s bytes=%d mode=%s auth=%s)", out.SrcAlias, out.SrcPath, out.DestAlias, out.DestPath, out.XferID, out.Bytes, out.Mode, out.AuthMode)
	return !result.IsError && reflect.DeepEqual(result.Content, []mcp.Content{&mcp.TextContent{Text: text}})
}

func (r *journeyRig) transferDecision(t *testing.T, card journeyCard, id, status string) {
	t.Helper()
	// Resolve the identities from the operator's registry, independently of the audit.
	var registry map[string]struct {
		HostKeyFingerprint string `json:"fingerprint"`
	}
	raw := r.operator(t, "cat ~/.config/sshgate/servers.json")
	if err := json.Unmarshal([]byte(raw), &registry); err != nil {
		t.Fatal(err)
	}
	src, dest := registry["web1"].HostKeyFingerprint, registry["web2"].HostKeyFingerprint
	if src == "" || dest == "" {
		t.Fatal("missing transfer host identities")
	}
	cardID := ""
	for _, line := range strings.Split(card.text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Xfer:") {
			cardID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Xfer:"))
		}
	}
	if cardID == "" || (id != "" && cardID != id) {
		t.Fatal("transfer ID does not match card")
	}
	id = cardID
	command := fmt.Sprintf("transfer src=%s dest=%s xfer=%s mode=0600", src, dest, id)
	r.signerDecision(t, card, []string{command}, []string{src, dest}, status)
}

func TestTransferMetadataOnly(t *testing.T) {
	out := tool.TransferOutput{SrcAlias: "a", DestAlias: "b", XferID: "id", Bytes: 12, Mode: "0600", AuthMode: "human"}
	encoded, _ := json.Marshal(out)
	var structured map[string]any
	_ = json.Unmarshal(encoded, &structured)
	result := &mcp.CallToolResult{StructuredContent: structured, Content: []mcp.Content{&mcp.TextContent{Text: "transferred a: → b: (xfer=id bytes=12 mode=0600 auth=human)"}}}
	if !transferMetadataOnly(result, out) {
		t.Fatal("valid metadata rejected")
	}
	result.Content = append(result.Content, &mcp.TextContent{Text: base64.StdEncoding.EncodeToString([]byte(journeySentinel))})
	if transferMetadataOnly(result, out) {
		t.Fatal("extra content accepted")
	}
	result.Content = result.Content[:1]
	structured["secret"] = "unexpected"
	if transferMetadataOnly(result, out) {
		t.Fatal("extra field accepted")
	}
}
