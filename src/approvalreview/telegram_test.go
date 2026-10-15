package approvalreview

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Parity list: every line of the v1 banners (src/signer/backend/telegram.go)
// and where it lives in the shared renderer. This table is the spec of the
// port (r5.8 A3); "changed" rows are the intended changes.
//
// | v1 banner line (telegram.go)                                   | Shared renderer                                                   |
// |----------------------------------------------------------------|-------------------------------------------------------------------|
// | update :989 "⚠️ GATE BINARY UPDATE — approving this REPLACES…"  | headlineUpdate, part 1 and card                                   |
// | update :998 "🔐 SSHGate GATE UPDATE — <server>"                  | changed: partTitle/cardTitle + item heading "Command 1/1 [signed_admin] <alias> …" |
// | update :1010 "New gate SHA-256: <hash>" (raw, from the command)  | note "New gate SHA-256 (from the signed command bytes): <hash>"   |
// | update :1012 "<malformed hash — the gate will reject this update>"| same marker in that note (legacy only; v2 validates the hash)     |
// | update :1015 "Build: <reason>" (raw)                             | changed (E8c/E33): v1 "Build metadata (v1 client-supplied)", v2 "Build metadata (client-supplied, signer-unverified)", redacted+neutralized, quoted |
// | all :1018/:1069 "Request ID: <id>"                                | "Request: <id> · Card: <handle> · Plan: <prefix>" on every part; card "Request: … · Card: …" + "Plan hash: <64hex>" |
// | all :1019/:1070 "Expires in <timeout>"                            | changed: absolute "Submitted: <t>" and "Expires: <t>" (spec §9.1) |
// | reveal :1060 "⚠️ SECRET-REVEAL — output will NOT be redacted…"   | headlineReveal, part 1 and card                                   |
// | reveal :1063 "🔓 SSHGate SECRET-REVEAL — <server>"               | changed: route "[signed_reveal]" in the item heading + approve label "(SECRET-REVEAL)" |
// | write :1065 "🔐 SSHGate approval — <server>"                     | changed: partTitle/cardTitle; the server is in each item heading |
// | reveal :1080 "Reason: <c.Reason>" (raw)                          | changed (E8c): "Reveal justification (agent-stated, unverified, legacy per-command field)", redacted+neutralized, quoted |
// | write :1084 "<n> commands queued:"                               | "Request: <n> command(s): <s> signed, <r> unsigned read(s); …"    |
// | write :1093 "<i>. <redacted cmd>"                                | changed: "Command i/N [route] alias → user@host:port fp=… ttl=…s sha256=…", K20 or exact label, quoted escaped display with ⟦hidden N bytes · rules⟧ |
// | write :1096 "   → <explanation>" / "(no explanation)"            | changed: AI advisory section of the card (summary, concerns by severity, effects) |
// | write :1104 "(no explanations: <err>)"                           | card "AI advisory: unavailable. … Reason:" + quoted reason        |
// | grant :1134 "⚠️ STANDING GRANT — approving this auto-signs …"    | v2: HeadlineGrantAutoSigns. Legacy: changed (OQ3 (b)), REPLACED by HeadlineGrantLegacy "… Older client: this grant will not auto-sign. Each write still asks for approval." |
// | grant :1135 "🟠 SSHGate STANDING GRANT — <alias>"                | item heading "Standing grant on <alias>"                          |
// | grant :1138 "Scope: ALL commands on <alias>"                     | same note                                                         |
// | grant :1140 "Scope: ONLY these exact commands:" + "<i>. <cmd>"   | note "Scope: ONLY the <n> exact command(s) below" + "Grant command i/n sha256=…" items |
// | grant :1148 "Scope: <scope>"                                     | same note (legacy unknown scope, neutralized)                     |
// | grant :1150 "Duration: <d>"                                      | "Duration: <d> (<s> s), counted from approval"                    |
// | grant :1152 "Expires at: <now+d>"                                | changed: dropped; the grant's expiry is decided_at + duration (E9), unknown at render |
// | grant :1155 "Approval expires in <timeout>"                      | "Expires: <t>"                                                    |
// | transfer :1167 "⚠️ SECRET TRANSFER — approving this MOVES…" + :1168 | headlineTransfer (one line)                                      |
// | transfer :1169 "🔐 SSHGate SECRET TRANSFER"                      | item heading "Secret transfer <xfer id>"                          |
// | transfer :1170/:1172 "From:/To: <label> (<fp…>)"                 | changed: full fp, "From: key \"<label>\" (signer registry) fp=…"; v2 adds the route and public-key sha256 |
// | transfer :1171/:1173 "<path>" "mode <m>"                         | "Source path"/"Destination path" items (redacted, neutralized; "requester-supplied, signer-validated") + "Mode: <m>" |
// | transfer :1174 "Xfer: <id>"                                      | item heading                                                      |
// | register :1187 "⚠️ XFER-KEY REGISTER — approving this ADDS…" + :1188 | headlineRegister (one line)                                      |
// | register :1189 "🔐 SSHGate XFER-KEY REGISTER"                     | item heading "Transfer-key registration"                          |
// | register :1190-1192 "Host:/Box:/ID:"                             | same notes, full fp, neutralized instead of "<malformed>"         |
// | buttons :547-555, :638 "✓ Approve all/SECRET-REVEAL/GATE UPDATE/STANDING GRANT" | E46: View.ApproveLabel "✓ Approve all displayed commands" + kind suffix; "✗ Deny" |
// | (new) | reason label (K3/K4/E39), sync notice (E25), route label (E35), K16 warning (E46), K20 label, part numbering and continuations (K19) |

var forgeries = []string{
	"PART 2/3", "Command 2/3", "command 1, chunk 2/2", "Exact command (no hidden bytes)",
	"⟦hidden 0 bytes⟧", "✓ Approve all displayed commands", approvalplan.LabelRedactedDisplay,
	"🔐 SSHGate approval — DECISION CARD", "AI advisory: unavailable",
}

// forgeSites renders the same request with text placed in one
// attacker-controlled field.
var forgeSites = map[string]func(t *testing.T, text string) rendered{
	"command": func(t *testing.T, text string) rendered {
		return render(t, mustSnapshot(t, withSteps(t, signed("echo "+text))), readyAssist())
	},
	"reason": func(t *testing.T, text string) rendered {
		return render(t, mustSnapshot(t, withReason(t, loadPlan(t, "write"), "Deploy "+text)), readyAssist())
	},
	"assist summary": func(t *testing.T, text string) rendered {
		a := readyAssist()
		a.Result.Summary = "Summary " + text
		return render(t, mustSnapshot(t, loadPlan(t, "write")), a)
	},
	"assist effect": func(t *testing.T, text string) rendered {
		a := readyAssist()
		a.Result.Effects = []string{"Effect " + text}
		return render(t, mustSnapshot(t, loadPlan(t, "write")), a)
	},
	"assist concern": func(t *testing.T, text string) rendered {
		a := readyAssist()
		a.Result.Concerns = []approvalplan.Concern{{Severity: approvalplan.SeverityHigh, Text: "Concern " + text}}
		return render(t, mustSnapshot(t, loadPlan(t, "write")), a)
	},
	"assist unavailable reason": func(t *testing.T, text string) rendered {
		r := render(t, mustSnapshot(t, loadPlan(t, "write")), Assist{State: approvalplan.AssistUnavailable, Reason: "provider " + text})
		return r
	},
	"legacy reveal reason": func(t *testing.T, text string) rendered {
		req := legacyBase()
		req.Commands = []LegacyCommand{{Server: "db-1", Command: "cat /etc/token", TTLSeconds: 60, Reveal: true, Reason: "need " + text}}
		return render(t, mustLegacy(t, req), readyAssist())
	},
	"legacy alias": func(t *testing.T, text string) rendered {
		req := legacyBase()
		req.Commands = []LegacyCommand{{Server: "web\n" + text, Command: "true", TTLSeconds: 60}}
		return render(t, mustLegacy(t, req), readyAssist())
	},
}

// structuralCount counts s on lines that do not quote untrusted text.
func structuralCount(texts []string, s string) int {
	n := 0
	for _, text := range texts {
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(line, QuotePrefix) {
				n += strings.Count(line, s)
			}
		}
	}
	return n
}

func totalCount(texts []string, s string) int {
	n := 0
	for _, text := range texts {
		n += strings.Count(text, s)
	}
	return n
}

// TestForgingAttempts places renderer text in every attacker-controlled
// field. Text with a glyph must never come out verbatim; ASCII text may
// appear only on quoted lines, so the renderer's own lines are unchanged.
func TestForgingAttempts(t *testing.T) {
	for site, build := range forgeSites {
		baseline := build(t, "BENIGN")
		telegram := func(r rendered) []string { return append(append([]string(nil), r.parts...), r.preparing, r.ready) }
		for _, f := range forgeries {
			forged := build(t, f)
			if utf8.RuneCountInString(f) != len(f) {
				if got, want := totalCount(forged.texts(), f), totalCount(baseline.texts(), f); got != want {
					t.Errorf("%s: %q appears %d times, baseline %d", site, f, got, want)
				}
			}
			if got, want := structuralCount(telegram(forged), f), structuralCount(telegram(baseline), f); got != want {
				t.Errorf("%s: %q on %d unquoted lines, baseline %d", site, f, got, want)
			}
			if got, want := structuralCount(viewLines(forged.view), f), structuralCount(viewLines(baseline.view), f); got != want {
				t.Errorf("%s: %q in %d unquoted view lines, baseline %d", site, f, got, want)
			}
		}
	}
}

// viewLines are the view's renderer-authored single-line fields.
func viewLines(v View) []string {
	lines := append([]string{v.ReasonLabel, v.Summary, v.SyncNotice, v.ApproveLabel, v.DenyLabel}, v.Headlines...)
	for _, it := range v.Items {
		lines = append(append(lines, it.Heading, it.TextLabel), it.Notes...)
	}
	return lines
}

func TestEveryOutputLineIsSingleLineASCIIOrRendererGlyph(t *testing.T) {
	r := render(t, mustSnapshot(t, withReason(t, withSteps(t, signed("a\u202Eb\u200Bc\x1b\x7f\u0430\\")), "x\u200By ⟦")), readyAssist())
	for _, text := range r.texts() {
		for _, bad := range []string{"\u202E", "\u200B", "\x1b", "\x7f", "\u0430", "\r"} {
			if strings.Contains(text, bad) {
				t.Fatalf("output carries %q", bad)
			}
		}
	}
}

func TestLongCommandChunks(t *testing.T) {
	cmd := strings.Repeat("\x01", approvalplan.MaxStepBytes)
	r := render(t, mustSnapshot(t, withSteps(t, signed(cmd))), readyAssist())
	chunkLine := regexp.MustCompile(`^↳ command 1, chunk (\d+)/(\d+) sha256=` + sha256Hex(cmd) + `$`)
	var joined strings.Builder
	chunks := 0
	for _, p := range r.parts {
		lines := strings.Split(p, "\n")
		for i, line := range lines {
			if !chunkLine.MatchString(line) {
				continue
			}
			chunks++
			text := strings.TrimPrefix(lines[i+2], QuotePrefix)
			if !regexp.MustCompile(`^(\\x01)+$`).MatchString(text) {
				t.Fatalf("chunk %d splits an escape: %.40q", chunks, text)
			}
			joined.WriteString(text)
		}
	}
	if chunks < 2 || joined.String() != escapeCommand(cmd) {
		t.Fatalf("%d chunks; reassembled %d bytes, want %d", chunks, joined.Len(), len(escapeCommand(cmd)))
	}
}

func TestChunkDisplayKeepsTokensWhole(t *testing.T) {
	text := escapeCommand("a\\b\x01") + approvalplan.HiddenMarker(12, []string{"r"}) + NeutralizeText("\u00e9") + "z"
	boundaries := map[int]bool{}
	for i := 0; i < len(text); i += tokenLen(text[i:]) {
		boundaries[i] = true
	}
	if len(boundaries) != 7 {
		t.Fatalf("%q tokenizes into %d tokens; want 7", text, len(boundaries))
	}
	for max := 1; max < len(text)+2; max++ {
		chunks := chunkDisplay(text, max)
		if strings.Join(chunks, "") != text {
			t.Fatalf("max %d: chunks do not reassemble", max)
		}
		at := 0
		for _, c := range chunks[:len(chunks)-1] {
			at += len(c)
			if !boundaries[at] {
				t.Fatalf("max %d: a chunk ends inside a token at %d", max, at)
			}
		}
	}
}

func TestDecisionCardStates(t *testing.T) {
	s := mustSnapshot(t, loadPlan(t, "write"))
	card := func(a Assist) string {
		v, err := BuildView(s, a)
		if err != nil {
			t.Fatal(err)
		}
		c, err := DecisionCard(v, testHandle, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) >= PartBytes {
			t.Fatalf("card is %d bytes", len(c))
		}
		return c
	}
	if c := card(Assist{State: approvalplan.AssistPreparing}); !strings.Contains(c, "preparing") || !strings.Contains(c, "Plan hash: "+s.PlanHash) {
		t.Fatalf("preparing card:\n%s", c)
	}
	if c := card(Assist{State: approvalplan.AssistUnavailable, Reason: "assist deadline"}); !strings.Contains(c, "unavailable") || !strings.Contains(c, "\n"+QuotePrefix+"assist deadline") {
		t.Fatalf("unavailable card:\n%s", c)
	}
	ready := card(readyAssist())
	if hi, info := strings.Index(ready, "[high]"), strings.Index(ready, "[info]"); hi < 0 || info < hi {
		t.Fatalf("concerns are not ordered by severity:\n%s", ready)
	}

	big := readyAssist()
	big.Result.Summary = strings.Repeat("é", approvalplan.MaxAssistSummaryBytes/2)
	big.Result.Effects = nil
	big.Result.Concerns = nil
	for range approvalplan.MaxAssistConcerns {
		big.Result.Concerns = append(big.Result.Concerns, approvalplan.Concern{Severity: approvalplan.SeverityCaution, Text: strings.Repeat("é", 120)})
	}
	for range 10 {
		big.Result.Effects = append(big.Result.Effects, strings.Repeat("ü", 120))
	}
	c := card(big)
	if !strings.Contains(c, "advisory item(s) omitted to fit this card.") || !strings.Contains(c, "Alignment: aligned") {
		t.Fatalf("overfull card has no omission notice:\n%s", c)
	}
	if !strings.Contains(c, "Summary:") {
		t.Fatal("the summary, first in priority, was dropped")
	}

	for _, bad := range []Assist{
		{State: approvalplan.AssistReady},
		{State: approvalplan.AssistPreparing, Reason: "x"},
		{State: approvalplan.AssistNotApplicable},
		{State: approvalplan.AssistReady, Result: &approvalplan.AssistResult{Alignment: "sure"}},
	} {
		if _, err := BuildView(s, bad); err == nil {
			t.Errorf("assist %+v accepted", bad)
		}
	}
}

func TestLegacyAlignmentIsNotAssessed(t *testing.T) {
	req := legacyBase()
	req.Commands = []LegacyCommand{{Server: "web-1", Command: "true", TTLSeconds: 60}}
	v, err := BuildView(mustLegacy(t, req), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	if v.Assist.Alignment != AlignmentLegacyMsg || v.ReasonLabel != approvalplan.LabelLegacyIntent {
		t.Fatalf("alignment %q, label %q", v.Assist.Alignment, v.ReasonLabel)
	}
}

func TestGrantHeadlines(t *testing.T) {
	v2, err := BuildView(mustSnapshot(t, loadPlan(t, "grant-commands")), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	req := legacyBase()
	req.Grant = &LegacyGrant{Alias: "web-1", Scope: "all", Duration: 3600e9}
	legacy, err := BuildView(mustLegacy(t, req), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	all := func(v View) string {
		parts, err := PackParts(v, testHandle)
		if err != nil {
			t.Fatal(err)
		}
		card, _ := DecisionCard(v, testHandle, len(parts))
		return strings.Join(append(parts, card), "\n")
	}
	if text := all(v2); !strings.Contains(text, HeadlineGrantAutoSigns) {
		t.Fatal("v2 grant lacks the auto-sign headline")
	}
	text := all(legacy)
	if strings.Contains(text, "WITHOUT further taps") || strings.Contains(text, "auto-signs") {
		t.Fatalf("legacy grant claims to auto-sign:\n%s", text)
	}
	if !strings.Contains(text, "Older client: this grant will not auto-sign. Each write still asks for approval.") {
		t.Fatal("legacy grant lacks the no-auto-sign line")
	}
}

func TestPackPartsRefusesABadHandle(t *testing.T) {
	v, err := BuildView(mustSnapshot(t, loadPlan(t, "write")), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"", "ABCDEFGHJKLM", "k7m2q3x4c5v6\n"} {
		if _, err := PackParts(v, h); err == nil {
			t.Errorf("handle %q accepted", h)
		}
		if _, err := DecisionCard(v, h, 1); err == nil {
			t.Errorf("card handle %q accepted", h)
		}
	}
}

func TestNeutralizeText(t *testing.T) {
	cases := map[string]string{
		"plain <a&b>":   "plain <a&b>",
		`back\slash`:    `back\\slash`,
		"nl\nx":         `nl\x0ax`,
		"esc\x1b":       `esc\x1b`,
		"nul\x00":       `nul\x00`,
		"del\x7f":       `del\x7f`,
		"bidi\u202Ex":   `bidi\u{202E}x`,
		"zw\u200Bj":     `zw\u{200B}j`,
		"\u0430dmin":    `\u{0430}dmin`,
		"⟦x⟧ ✓":         `\u{27E6}x\u{27E7} \u{2713}`,
		"🔐":             `\u{1F510}`,
		"bad\xffbyte":   `bad\xffbyte`,
		"c1\u0085":      `c1\u{0085}`,
		`\u{202E}`:      `\\u{202E}`,
		"line\u2028sep": `line\u{2028}sep`,
	}
	for in, want := range cases {
		if got := NeutralizeText(in); got != want {
			t.Errorf("NeutralizeText(%q) = %q, want %q", in, got, want)
		}
	}
	rng := rand.New(rand.NewSource(1))
	for range 2000 {
		b := make([]byte, rng.Intn(64))
		rng.Read(b)
		if out := NeutralizeText(string(b)); !isPrintableASCII(out) {
			t.Fatalf("NeutralizeText(%q) = %q is not printable ASCII", b, out)
		}
	}
}
