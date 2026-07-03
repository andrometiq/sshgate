package redact_test

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

// scrubSalt is a fixed (non-random) salt so the determinism assertions
// below are reproducible. RedactString itself takes the salt as a
// parameter; production callers supply a per-process random salt.
var scrubSalt = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// TestRedactStringScrubsCommandSecrets is the F5 unit contract: the
// one-shot string redactor runs the SAME Combined() ruleset that scrubs
// command OUTPUT, so a secret embedded in a COMMAND STRING about to be
// logged is replaced with a marker and never persisted verbatim. Benign
// commands (and the load-bearing PWD= false-positive guard) must pass
// through unchanged.
func TestRedactStringScrubsCommandSecrets(t *testing.T) {
	ruleset := rules.Combined()

	cases := []struct {
		name   string
		cmd    string
		secret string // substring that MUST be absent after redaction
		redact bool   // true: a marker must appear and the secret must be gone
	}{
		// --- MUST redact (secret embedded in the command string) ---
		{"printf PASSWORD assignment", `printf 'PASSWORD=hunter2secret'`, "hunter2secret", true},
		{"export GITHUB_TOKEN", `export GITHUB_TOKEN=ghp_abcd1234efgh`, "ghp_abcd1234efgh", true},
		{"curl Authorization Bearer", `curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9xxxxx'`, "eyJhbGciOiJIUzI1NiJ9xxxxx", true},
		{"PGPASSWORD inline", `PGPASSWORD=hunter2secret psql -h db -U admin -c 'select 1'`, "hunter2secret", true},

		// --- MUST NOT redact (benign commands survive verbatim) ---
		{"ls -la", `ls -la`, "ls -la", false},
		{"df -h", `df -h`, "df -h", false},
		// The known load-bearing false-positive guard: PWD= is the cwd env
		// var, present in every env dump and many commands; its value must
		// never be scrubbed (mirrors sensitive_assignment_test.go).
		{"PWD cwd guard", `env PWD=/home/user/project ls`, "/home/user/project", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, ok := redact.RedactString(tc.cmd, scrubSalt, ruleset)
			if !ok {
				t.Fatalf("RedactString returned ok=false for %q", tc.cmd)
			}
			if tc.redact {
				if strings.Contains(out, tc.secret) {
					t.Errorf("secret leaked: in=%q out=%q (expected %q absent)", tc.cmd, out, tc.secret)
				}
				if !strings.Contains(out, redact.MarkerPrefix) {
					t.Errorf("expected a redaction marker; in=%q out=%q", tc.cmd, out)
				}
			} else {
				if out != tc.cmd {
					t.Errorf("OVER-REDACTION: benign command altered.\nin:  %q\nout: %q", tc.cmd, out)
				}
			}
		})
	}
}

// TestRedactStringEdgeCases pins the fast-path / fail-open contract.
func TestRedactStringEdgeCases(t *testing.T) {
	ruleset := rules.Combined()

	// Empty string: input + ok=true, no work.
	if out, ok := redact.RedactString("", scrubSalt, ruleset); out != "" || !ok {
		t.Errorf("empty string: got (%q, %v), want (%q, true)", out, ok, "")
	}

	// Nil rules: nothing to redact, input returned verbatim + ok=true.
	if out, ok := redact.RedactString("export GITHUB_TOKEN=ghp_abcd1234efgh", scrubSalt, nil); !ok {
		t.Errorf("nil rules: ok=false, want true")
	} else if out != "export GITHUB_TOKEN=ghp_abcd1234efgh" {
		t.Errorf("nil rules: out=%q, want input verbatim", out)
	}

	// Empty (non-nil) rules slice: same fast path as nil.
	if out, ok := redact.RedactString("export GITHUB_TOKEN=ghp_abcd1234efgh", scrubSalt, []redact.Rule{}); !ok {
		t.Errorf("empty rules: ok=false, want true")
	} else if out != "export GITHUB_TOKEN=ghp_abcd1234efgh" {
		t.Errorf("empty rules: out=%q, want input verbatim", out)
	}
}

// TestRedactStringDeterministic pins the recognise-same-secret property:
// the SAME (salt, secret) yields the SAME marker key, so two redactions of
// the same command produce byte-identical output. Stable WITHIN a log is
// the only guarantee required (cross-log correlation is explicitly out of
// scope).
func TestRedactStringDeterministic(t *testing.T) {
	ruleset := rules.Combined()
	cmd := `export GITHUB_TOKEN=ghp_abcd1234efgh`

	a, okA := redact.RedactString(cmd, scrubSalt, ruleset)
	b, okB := redact.RedactString(cmd, scrubSalt, ruleset)
	if !okA || !okB {
		t.Fatalf("ok=false (a=%v b=%v)", okA, okB)
	}
	if a != b {
		t.Errorf("non-deterministic: a=%q b=%q", a, b)
	}
	if strings.Contains(a, "ghp_abcd1234efgh") {
		t.Errorf("secret leaked: %q", a)
	}
}

// TestRedactStringMysqlFlagGapXFAIL documents a KNOWN, OUT-OF-SCOPE
// ruleset gap: a password supplied as a CLI FLAG VALUE (`mysql -psecret`)
// is NOT covered by any current rule (only the URL-userinfo form
// mysql://u:pw@host is). F5 reuses the existing Combined() ruleset over the
// command string, so it inherits this gap unchanged. This test PINS the
// gap so a future ruleset change that closes it is noticed here (the test
// will start failing, prompting a deliberate update) rather than being
// silently assumed already fixed.
func TestRedactStringMysqlFlagGapXFAIL(t *testing.T) {
	ruleset := rules.Combined()
	cmd := `mysql -psecretpassword -h db`

	out, ok := redact.RedactString(cmd, scrubSalt, ruleset)
	if !ok {
		t.Fatalf("RedactString ok=false for %q", cmd)
	}
	// KNOWN GAP: the secret survives today. If this assertion ever fails,
	// the password-as-CLI-flag class started being redacted — update this
	// test (and note it) rather than deleting it.
	if !strings.Contains(out, "secretpassword") {
		t.Errorf("XFAIL no longer holds: `mysql -p<secret>` is now redacted (out=%q). "+
			"The password-as-CLI-flag ruleset gap appears closed — revisit this pinned test.", out)
	}
}
