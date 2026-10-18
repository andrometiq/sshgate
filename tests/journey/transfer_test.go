//go:build journey

package journey

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tool "github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/xferwire"
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
print(len(data), hashlib.sha256(data).hexdigest(), oct(p.stat().st_mode & 0o777))
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
	finishCall(t, evidence, startCall(client, "transfer", args), &out, false)
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
		count := 0
		for _, row := range r.audit(t, host) {
			command, _ := row["command"].(string)
			if host == "target-a" {
				leg, err := xferwire.ParseSend(command)
				if err != nil || leg.XferID != out.XferID {
					continue
				}
				if leg.SrcPath != source {
					t.Fatal("SEND path mismatch")
				}
			} else {
				leg, err := xferwire.ParseRecv(command)
				if err != nil || leg.XferID != out.XferID {
					continue
				}
				if leg.DestPath != destination {
					t.Fatal("RECV path mismatch")
				}
			}
			count++
			if row["approval_status"] != "signed" || row["exit_code"] != float64(0) {
				t.Fatal("transfer gate leg failed")
			}
		}
		if count != 1 {
			t.Fatalf("%s: expected exactly one correlated transfer leg, got %d", host, count)
		}
	}
	approved := 0
	for _, row := range r.audit(t, "controller") {
		commands, _ := row["commands"].([]any)
		for _, command := range commands {
			if strings.Contains(fmt.Sprint(command), "xfer="+out.XferID+" ") {
				if row["status"] != "approved" || row["auth_mode"] != "human" {
					t.Fatal("transfer signer verdict mismatch")
				}
				approved++
			}
		}
	}
	if approved != 1 {
		t.Fatal("expected one correlated signer approval")
	}
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
	signerAfter := r.audit(t, "controller")
	if len(signerAfter) != signerBefore+1 || signerAfter[signerBefore]["status"] != "denied" {
		t.Fatal("denied transfer signer audit mismatch")
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

	// Scan before persisting any evidence. Never print the offending content.
	surfaces := []any{evidence.transcript, r.events(t), r.audit(t, "controller"), r.audit(t, "target-a"), r.audit(t, "target-b")}
	surfaces = append(surfaces, r.exec(t, "controller", "journalctl", "--no-pager", "-u", "sshgate-signer-telegram", "-u", "journey-fake-telegram", "-o", "cat", "-n", "10000"))
	surfaces = append(surfaces, r.operator(t, `find ~/.config/sshgate -type f -name '*log*' -exec cat {} +`))
	for _, surface := range surfaces {
		data, err := json.Marshal(surface)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(journeySentinel)) {
			evidence.transcript = nil
			t.Fatal("synthetic plaintext leaked into an agent-visible surface")
		}
	}
}
