package classify

import "testing"

// TestClassify_BackslashEscapeBypass pins the CRITICAL read-only-gate bypass
// found by the 2026-06-14 adversarial review: the quote scanners
// (tokenize / splitSegments / hasWritingRedirect / containsSubstitution)
// did not honor a backslash before a quote, but /bin/sh treats `\'` and `\"`
// as LITERAL characters, not quote openers. So a single `\'` after a read
// head opened a phantom quote in the classifier that swallowed the rest of
// the line — separators, redirects, and `$(...)` all vanished — while
// /bin/sh ran it all live. That turned the read-only gate into UNSIGNED RCE.
//
// The fix: a backslash escapes the next byte everywhere except inside single
// quotes (where sh treats backslash as literal). The escaped byte is literal
// data and cannot open/close a quote, separate a command, redirect, or start
// a substitution.
func TestClassify_BackslashEscapeBypass(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- the confirmed RCE / write bypasses: must be WRITE ---
		// (The escaped quote no longer swallows the `&&`, so the second
		// command is seen and classified; a write/unknown head => WRITE.
		// Note `id` itself is an allowlisted READ, so the payload must be a
		// real write to demonstrate the catch.)
		{"escaped quote then && exec", `ls \' && rm -rf /tmp/x`, KindWrite},
		{"escaped quote then ; write", `cat /etc/passwd \' ; echo OWNED > /tmp/x`, KindWrite},
		{"escaped dquote hides redirect", `head f \" > /tmp/clobber`, KindWrite},
		{"escaped quote hides substitution", `stat f \'$(touch x)`, KindWrite},
		{"escaped quote after env-assign then ;", `A=1 cat realfile \' ; touch MARKER`, KindWrite},
		{"escaped dquote hides pipe-to-write", `cat f \" | tee /tmp/x`, KindWrite},
		{"escaped quote hides backtick sub", "cat f \\'`touch y`", KindWrite},

		// --- non-regressions: backslashes that are legitimately part of a
		//     READ command must STAY read (no false positives) ---
		// Backslash inside single quotes is literal (sh) — must not be
		// treated as an escape that changes anything.
		{"single-quoted regex escape stays read", `grep '\.txt' file`, KindRead},
		{"unquoted escaped dot stays read", `grep \.txt file`, KindRead},
		{"find escaped glob stays read", `find . -name \*.go`, KindRead},
		{"echo escaped quotes stays read", `echo \"hi\"`, KindRead},
		{"escaped space in one token stays read", `cat /tmp/a\ b`, KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
