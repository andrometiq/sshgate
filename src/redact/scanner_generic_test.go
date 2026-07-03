package redact

import (
	"strings"
	"testing"
)

// White-box unit tests for the generic default-deny net (scanner_generic.go).
// These call the unexported engine functions directly so the gate arithmetic,
// the telegram stitch (including the glued-URL digit-suffix peel), and the
// generic run detector are pinned in isolation — the writer/dedup interplay is
// pinned separately through the public API in scanner_generic_writer_test.go.
//
// Convention: every secret-shaped fixture is ASSEMBLED AT RUNTIME (no
// contiguous token literal in source) and uses synthetic shapes only.

// mixed3 builds an n-char run guaranteed to be 3-class (upper+lower+digit)
// and high-entropy: a coprime stride over a 62-char interleaved alphabet
// samples n distinct characters, so Shannon entropy is ~log2(min(n,62)).
func mixed3(n int) string {
	const a = "aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = a[(i*37+5)%len(a)]
	}
	return string(b)
}

// digitsStr builds an n-digit run (spread, not constant).
func digitsStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + (i*7+3)%10)
	}
	return string(b)
}

// hexLowerStr builds an n-char lowercase-hex run (2-class: digit+lower).
func hexLowerStr(n int) string {
	const h = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = h[(i*11+2)%16]
	}
	return string(b)
}

// b64urlBody builds an n-char base64url-alphabet run.
func b64urlBody(n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[(i*29+7)%64]
	}
	return string(b)
}

// tgBody returns a valid telegram body: 'A'-prefixed, 35 chars.
func tgBody() string { return "AA" + b64urlBody(33) }

func TestHas3Class(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{mixed3(40), true},
		{"Abc123", true},
		{"abc", false},          // lower only
		{"ABC", false},          // upper only
		{"123", false},          // digit only
		{hexLowerStr(40), false}, // digit+lower = 2-class
		{"AbCdEf", false},       // upper+lower, no digit
		{"Ab1", true},           // minimal 3-class
		{"", false},
	}
	for _, tc := range cases {
		if got := has3Class([]byte(tc.in)); got != tc.want {
			t.Errorf("has3Class(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy(nil); e != 0 {
		t.Errorf("empty entropy = %v, want 0", e)
	}
	if e := shannonEntropy([]byte(strings.Repeat("Z", 64))); e != 0 {
		t.Errorf("constant-run entropy = %v, want 0", e)
	}
	// A repetitive 3-class run has low entropy (only 7 distinct symbols).
	if e := shannonEntropy([]byte(strings.Repeat("Test123", 7))); e >= genericEntropy {
		t.Errorf("repetitive run entropy = %v, want < %v", e, genericEntropy)
	}
	// A high-variety run clears the floor comfortably.
	if e := shannonEntropy([]byte(mixed3(40))); e < genericEntropy {
		t.Errorf("mixed3(40) entropy = %v, want >= %v", e, genericEntropy)
	}
}

func TestSSHLineContext(t *testing.T) {
	// A pubkey body preceded on the same line by a key-type marker is vetoed.
	line := "ssh-ed25519 " + mixed3(40) + " user@host"
	buf := []byte(line)
	pos := strings.Index(line, mixed3(40))
	if !sshLineContext(buf, pos) {
		t.Errorf("ssh-ed25519 line not detected as ssh context")
	}
	// The same candidate on a fresh line (marker on the PREVIOUS line only)
	// is NOT vetoed — the look-back never crosses '\n'.
	line2 := "ssh-rsa AAAA...\n" + mixed3(40) + "\n"
	buf2 := []byte(line2)
	pos2 := strings.Index(line2, mixed3(40))
	if sshLineContext(buf2, pos2) {
		t.Errorf("veto crossed a newline boundary")
	}
	// A benign line is not vetoed.
	line3 := "value=" + mixed3(40)
	if sshLineContext([]byte(line3), strings.Index(line3, mixed3(40))) {
		t.Errorf("benign line wrongly vetoed")
	}
}

func TestPassesSecretGate(t *testing.T) {
	gate := func(s string) bool {
		return passesSecretGate([]byte(s), 0, 0, len(s), genericEntropy)
	}
	if !gate(mixed3(40)) {
		t.Errorf("mixed3(40) should pass the gate")
	}
	if gate(hexLowerStr(40)) {
		t.Errorf("lowercase hex should fail (not 3-class)")
	}
	if gate(strings.Repeat("Test123", 7)) {
		t.Errorf("repetitive 3-class run should fail (entropy)")
	}
	// ssh-line veto: candidate span is judged with matchStart on an
	// ssh-marker line.
	sshLine := "ssh-rsa " + mixed3(40)
	off := strings.Index(sshLine, mixed3(40))
	if passesSecretGate([]byte(sshLine), off, off, len(sshLine), genericEntropy) {
		t.Errorf("candidate on an ssh-rsa line should be vetoed")
	}
}

// TestScanGenericRunsStitch pins the telegram-bot-token detector: bare and
// glued (digit-suffix peel) positives, plus the epoch:hex negative.
func TestScanGenericRunsStitch(t *testing.T) {
	id := digitsStr(9)
	body := tgBody()

	t.Run("bare", func(t *testing.T) {
		in := "token " + id + ":" + body + " end"
		ms := scanGenericRuns([]byte(in))
		tg := onlyRule(t, ms, telegramTokenRuleID)
		if string(tg.Secret) != id+":"+body {
			t.Errorf("bare stitch secret = %q, want %q", tg.Secret, id+":"+body)
		}
		if tg.MatchStart != tg.Start {
			t.Errorf("telegram MatchStart %d != Start %d", tg.MatchStart, tg.Start)
		}
	})

	t.Run("glued-url", func(t *testing.T) {
		// The glued form no \b regex can reach: `.../bot<id>:<body>/…`.
		in := "https://api.telegram.org/bot" + id + ":" + body + "/sendMessage"
		ms := scanGenericRuns([]byte(in))
		tg := onlyRule(t, ms, telegramTokenRuleID)
		if string(tg.Secret) != id+":"+body {
			t.Errorf("glued stitch secret = %q, want %q (digit-suffix peel dropped bot prefix?)", tg.Secret, id+":"+body)
		}
		// The `bot` prefix sits before the peeled id and must NOT be redacted.
		if got := in[tg.Start-3 : tg.Start]; got != "bot" {
			t.Errorf("expected 'bot' immediately before the redacted span, got %q", got)
		}
	})

	t.Run("epoch-hex-negative", func(t *testing.T) {
		// 10-digit epoch + ':' + 36 lowercase hex: the A-pin (body must
		// start 'A') deliberately misses it, and hex is 2-class so the
		// generic branch also declines. No match at all.
		in := "ts=" + digitsStr(10) + ":" + hexLowerStr(36) + " done"
		if ms := scanGenericRuns([]byte(in)); len(ms) != 0 {
			t.Errorf("epoch:hex should not stitch or match generically, got %d matches: %+v", len(ms), ms)
		}
	})
}

// TestScanGenericRunsGeneric pins the generic high-entropy detector: bare
// and path-segment positives, and the full negative battery.
func TestScanGenericRunsGeneric(t *testing.T) {
	t.Run("bare-positive", func(t *testing.T) {
		run := mixed3(40)
		in := "value=" + run
		m := onlyRule(t, scanGenericRuns([]byte(in)), genericEntropyRuleID)
		if string(m.Secret) != run {
			t.Errorf("generic secret = %q, want %q", m.Secret, run)
		}
		if m.MatchStart != m.Start {
			t.Errorf("generic MatchStart %d != Start %d", m.MatchStart, m.Start)
		}
	})

	t.Run("path-segment-positive", func(t *testing.T) {
		// Documented-bias: a token-shaped path segment redacts (see spec §6).
		seg := mixed3(40)
		in := "/tmp/" + seg + "/data.txt"
		m := onlyRule(t, scanGenericRuns([]byte(in)), genericEntropyRuleID)
		if string(m.Secret) != seg {
			t.Errorf("path-segment secret = %q, want %q", m.Secret, seg)
		}
	})

	negatives := []struct {
		name string
		in   string
	}{
		{"git-log-oneline", "e54da87 docs commit " + hexLowerStr(40) + " author"},
		{"docker-digest", "nginx@sha256:" + hexLowerStr(64)},
		{"dashed-uuid", "id=" + hexLowerStr(8) + "-" + hexLowerStr(4) + "-" + hexLowerStr(4) + "-" + hexLowerStr(4) + "-" + hexLowerStr(12)},
		{"nix-store", "/nix/store/" + hexLowerStr(32) + "-glibc-2.39"},
		{"ssh-rsa-authorized-keys", "ssh-rsa AAAA" + b64urlBody(60) + " user@host"},
		{"itanium-mangled", "_ZN4absl12lts_2023abcDEF123ghiJKLmno456pqr"},
		{"repetitive-3class", "x=" + strings.Repeat("Test123", 7)},
		{"z-padding-9k", strings.Repeat("Z", 9*1024)},
	}
	for _, tc := range negatives {
		tc := tc
		t.Run("neg/"+tc.name, func(t *testing.T) {
			for _, m := range scanGenericRuns([]byte(tc.in)) {
				if m.RuleID == genericEntropyRuleID {
					t.Errorf("false positive: generic net fired on %q: span=%q", tc.in, m.Secret)
				}
			}
		})
	}
}

// TestDedupMatchesInterplay pins how the linear pass output merges with regex
// matches under dedupMatches (earliest-start-wins, tie -> longest).
func TestDedupMatchesInterplay(t *testing.T) {
	// Telegram stitch (starts at the digits) beats a generic hit on the body.
	tg := match{Start: 0, End: 38, MatchStart: 0, RuleID: telegramTokenRuleID}
	gen := match{Start: 11, End: 38, MatchStart: 11, RuleID: genericEntropyRuleID}
	got := dedupMatches([]match{gen, tg})
	if len(got) != 1 || got[0].RuleID != telegramTokenRuleID {
		t.Errorf("telegram should win over body-generic, got %+v", got)
	}

	// An assignment-value match and a generic hit on the SAME span collapse
	// to one marker.
	asg := match{Start: 5, End: 20, MatchStart: 0, RuleID: "sshgate-sensitive-assignment"}
	gen2 := match{Start: 5, End: 20, MatchStart: 5, RuleID: genericEntropyRuleID}
	got2 := dedupMatches([]match{gen2, asg})
	if len(got2) != 1 {
		t.Errorf("same-span assignment+generic should collapse, got %d: %+v", len(got2), got2)
	}
}

// onlyRule asserts exactly one match with the given RuleID is present and
// returns it (ignoring any incidental others of a different rule).
func onlyRule(t *testing.T, ms []match, ruleID string) match {
	t.Helper()
	var found []match
	for _, m := range ms {
		if m.RuleID == ruleID {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s match, got %d (all: %+v)", ruleID, len(found), ms)
	}
	return found[0]
}
