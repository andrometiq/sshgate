package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

// Writer-level pins for the generic default-deny net: they exercise the net
// through the PUBLIC Writer/dedup/ringMax path (the unexported engine
// functions are pinned in scanner_generic_test.go). Fixtures are assembled at
// runtime.

// run3class builds an n-char 3-class high-entropy run (coprime stride over a
// 62-char alphabet -> n distinct chars -> entropy ~log2(n)).
func run3class(n int) string {
	const a = "aA0bB1cC2dD3eE4fF5gG6hH7iI8jJ9kKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = a[(i*37+5)%len(a)]
	}
	return string(b)
}

// hexRun builds an n-char lowercase-hex run (2-class: digit+lower).
func hexRun(n int) string {
	const h = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = h[(i*11+2)%16]
	}
	return string(b)
}

// mkTelegramToken builds a bare telegram bot token `<id>:AA<33 base64url>`.
func mkTelegramToken() string {
	id := make([]byte, 10)
	for i := range id {
		id[i] = byte('0' + (i*7+3)%10)
	}
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	body := make([]byte, 33)
	for i := range body {
		body[i] = a[(i*29+7)%64]
	}
	return string(id) + ":AA" + string(body)
}

// TestGenericPassRunsInForgeryOnlyWriter pins the intended behaviour that a
// Writer built with NO caller rules (only the always-prepended marker-forgery
// rule) still runs the generic pass: findMatches' len(rules)==0 early return is
// unreachable inside a real Writer, so a qualifying >=32-char 3-class run is
// redacted. (This is the deliberate consequence documented in spec §1c — a
// "forgery-only" Writer is no longer pure pass-through for such a run.)
func TestGenericPassRunsInForgeryOnlyWriter(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 3)
	}
	run := run3class(40)
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil)
	if _, err := w.Write([]byte("prefix " + run + " suffix\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s := out.String()
	if strings.Contains(s, run) {
		t.Errorf("qualifying run leaked from forgery-only writer: %q", s)
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("no marker emitted by forgery-only writer: %q", s)
	}
	if !strings.Contains(s, "prefix ") || !strings.Contains(s, " suffix") {
		t.Errorf("benign framing mangled: %q", s)
	}
}

// TestRingMaxGenericMatchStartPreservesBenignPrefix pins MatchStart = Start for
// a generic run: a >64 KiB benign prefix followed by a tail-reaching generic
// run must emit the benign prefix verbatim and redact ONLY the run. A wrong
// MatchStart (e.g. a zero default) would drive the ringMax tail path to redact
// from offset 0 and swallow the benign prefix wholesale.
func TestRingMaxGenericMatchStartPreservesBenignPrefix(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 9)
	}
	prefix := strings.Repeat("benign00 ", 8000) // 72000 bytes, ends with a space
	run := run3class(40)
	input := prefix + run // run reaches the buffer tail (no trailing delimiter)
	if len(input) <= redact.RingMax() {
		t.Fatalf("test input (%d) must exceed ringMax (%d)", len(input), redact.RingMax())
	}
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, rules.Combined())
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s := out.String()
	if !strings.HasPrefix(s, prefix) {
		head := s
		if len(head) > 80 {
			head = head[:80]
		}
		t.Errorf("benign prefix swallowed into the marker: out len=%d, prefix len=%d, head=%q", len(s), len(prefix), head)
	}
	if strings.Contains(s, run) {
		t.Errorf("tail run leaked raw")
	}
	if c := strings.Count(s, redact.MarkerPrefix); c != 1 {
		t.Errorf("want exactly one marker, got %d", c)
	}
}

// TestStitchBodyNotLeakedWhenDedupedAway is the review-found F1 regression: a
// >=32-char 3-class run whose TAIL is 6-10 digits, immediately followed by
// `:AA<33 base64url>`, produces BOTH a generic match on the run AND a telegram
// stitch that peels the run's trailing digits as the bot id. The stitch starts
// INSIDE the (earlier-starting) generic run, so a drop-the-remainder dedup
// discarded the stitch and left the token body raw. The fix (union-merge in
// dedupMatches) must redact the whole span. Pinned through the real Writer.
func TestStitchBodyNotLeakedWhenDedupedAway(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 13)
	}
	// run = 30 3-class chars + 6 digits (36 chars, one [A-Za-z0-9] run,
	// 3-class, >= genericMinLen, ends in a 6-digit peelable id).
	run := run3class(30) + "123456"
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	body := make([]byte, 33)
	for i := range body {
		body[i] = a[(i*29+7)%64]
	}
	token := run + ":AA" + string(body)
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, rules.Combined())
	if _, err := w.Write([]byte("v=" + token + " end\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s := out.String()
	if strings.Contains(s, "AA"+string(body)) {
		t.Errorf("telegram token body leaked raw: %q", s)
	}
	if strings.Contains(s, run) {
		t.Errorf("generic run leaked raw: %q", s)
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("no marker emitted: %q", s)
	}
}

// TestOpenAIBroadFiresOnSSHMarkerLine is the review-found F2 regression: the
// entropy-gated NAMED rule openai-broad must still fire on a line that also
// carries an ssh key-type marker (the ssh-line veto belongs only to the generic
// net, not to named rules — 3-class alone already rejects the lowercase FIDO
// key-type markers the veto was meant for). Before the fix the sk- key leaked.
func TestOpenAIBroadFiresOnSSHMarkerLine(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 17)
	}
	// sk- + 48 base62 (run3class is [A-Za-z0-9] only -> real base62, 3-class,
	// high entropy). On a line that also contains "ssh-rsa".
	key := "sk-" + run3class(48)
	line := "ssh-rsa AAAAB3NzaC1yc2E deploy@host " + key + "\n"
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, rules.Combined())
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s := out.String(); strings.Contains(s, key) {
		t.Errorf("openai-broad key leaked on an ssh-marker line: %q", s)
	}

	// The lowercase FIDO key-type marker must STILL be left alone (3-class
	// rejects it — no ssh veto needed).
	fido := "sk-ecdsa-sha2-nistp256@openssh.com"
	var out2 bytes.Buffer
	w2 := redact.NewWriter(&out2, salt, rules.Combined())
	if _, err := w2.Write([]byte("type " + fido + "\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s := out2.String(); !strings.Contains(s, "sk-ecdsa-sha2-nistp256") {
		t.Errorf("FIDO key-type marker over-redacted: %q", s)
	}
}

// TestGenericAndTelegramChunkSweeps drives a telegram stitch and a >=32-char
// generic run through many chunk sizes and asserts exactly-one-marker with the
// secret gone — the streaming safe-prefix (4 KiB) always holds a <=101-byte
// token, so an incomplete arrival can never flush early. NOTE: these fixtures
// are <safePrefix (4 KiB), so each chunk size buffers-until-Close and scans
// once; a genuine mid-stream straddler flush is pinned by
// TestRingMaxGenericMatchStartPreservesBenignPrefix.
func TestGenericAndTelegramChunkSweeps(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 5)
	}
	cases := []struct {
		name, secret, in string
	}{
		{"telegram", mkTelegramToken(), "before " + mkTelegramToken() + " after\n"},
		{"generic", run3class(40), "before " + run3class(40) + " after\n"},
	}
	chunks := []int{8, 16, 32, 64, 256, 1024, 4096, 64 * 1024}
	for _, tc := range cases {
		for _, chunk := range chunks {
			tc, chunk := tc, chunk
			t.Run(tc.name+"/chunk-"+itoa(chunk), func(t *testing.T) {
				var out bytes.Buffer
				w := redact.NewWriter(&out, salt, rules.Combined())
				in := []byte(tc.in)
				for i := 0; i < len(in); i += chunk {
					end := i + chunk
					if end > len(in) {
						end = len(in)
					}
					if _, err := w.Write(in[i:end]); err != nil {
						t.Fatalf("Write: %v", err)
					}
				}
				if err := w.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				s := out.String()
				if strings.Contains(s, tc.secret) {
					t.Errorf("chunk=%d: secret leaked: %q", chunk, s)
				}
				if c := strings.Count(s, redact.MarkerPrefix); c != 1 {
					t.Errorf("chunk=%d: want exactly one marker, got %d: %q", chunk, c, s)
				}
			})
		}
	}
}
