package approvalplan

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidateRationale(t *testing.T) {
	ok := map[string]string{
		"Restart nginx":                      "Restart nginx",
		"  padded\t":                         "padded",
		"café — naïve 日本":                    "café — naïve 日本",
		strings.Repeat("x", 500):             strings.Repeat("x", 500),
		" " + strings.Repeat("é", 250) + " ": strings.Repeat("é", 250),
		"<script>&amp;":                      "<script>&amp;",
	}
	for in, want := range ok {
		got, err := ValidateRationale(in)
		if err != nil || got != want {
			t.Errorf("ValidateRationale(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	refused := []string{
		"", "   ", strings.Repeat("x", 501), strings.Repeat("é", 251),
		"two\nlines", "cr\rhere", "tab\there", "nul\x00", "esc\x1b[31m", "del\x7f",
		"c1 \u0085 nel inside", "c1 \u009b csi",
		"bidi \u202e override", "bidi \u2066 isolate", "bidi \u2069 pop", "lrm \u200e", "rlm \u200f", "alm \u061c",
		"lre \u202a", "pdf \u202c", "ls \u2028 inside", "ps \u2029 inside",
		"bad \xff utf8", "half \xc3",
	}
	for _, in := range refused {
		if _, err := ValidateRationale(in); codeOf(err) != CodeInvalidRequest || fieldOf(err) != "reason" {
			t.Errorf("ValidateRationale(%q) = %v, want invalid_request at reason", in, err)
		}
	}
}

func FuzzValidateRationale(f *testing.F) {
	for _, s := range []string{"Restart nginx", " x ", "a\nb", "\u202e", "\xff", strings.Repeat("y", 501)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ValidateRationale(s)
		if err != nil {
			return
		}
		if got != strings.TrimSpace(got) || len(got) < 1 || len(got) > MaxRationaleBytes || !utf8.ValidString(got) {
			t.Fatalf("accepted %q as %q", s, got)
		}
		for _, r := range got {
			if forbiddenRune(r) {
				t.Fatalf("accepted forbidden rune %U in %q", r, s)
			}
		}
		if again, err := ValidateRationale(got); err != nil || again != got {
			t.Fatalf("not idempotent on %q", got)
		}
	})
}
