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

// TestGenericAndTelegramChunkSweeps drives a telegram stitch and a >=32-char
// generic run through many chunk sizes and asserts exactly-one-marker with the
// secret gone — the streaming safe-prefix (4 KiB) always holds a <=101-byte
// token, so an incomplete arrival can never flush early.
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
