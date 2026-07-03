package redact_test

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// TestSensitiveAssignmentBoundary pins the boundary behaviour of the
// sshgate-sensitive-assignment rule (rules.go) against an
// over-redaction regression: the rule's keyword stem
// (KEY/TOKEN/SECRET/PASSWORD/PASS/PWD/…) must sit at the END of the
// variable name, not match as a trailing word-suffix inside a longer
// name. Before the fix, PWD=/home/... (the universal cwd env var,
// present in every `env`/`printenv` dump) had its value redacted —
// blinding the operator to its own working directory. MONKEY=,
// WHISKEY=, COMPASS=, BYPASS= tripped the bare KEY/PASS alternatives
// the same way.
//
// This runs the REAL combined-ruleset redactor (redactString lives in
// leak_test.go and mirrors the production Writer/scan path), not a
// hand-rolled regex, so it also guards the interaction with the
// neighbouring sshgate-password-kv rule.
func TestSensitiveAssignmentBoundary(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string // the value substring whose fate we assert
		redact bool   // true: value MUST be scrubbed; false: MUST survive verbatim
	}{
		// --- MUST redact (secret coverage preserved) ---
		{"API_KEY", "API_KEY=abcd1234efgh", "abcd1234efgh", true},
		{"export GITHUB_TOKEN", "export GITHUB_TOKEN=ghp_abcd1234efgh", "ghp_abcd1234efgh", true},
		{"DB_PASSWORD", "DB_PASSWORD=hunter2secret", "hunter2secret", true},
		{"MY_DB_PASSWORD multi-underscore", "MY_DB_PASSWORD=hunter2secret", "hunter2secret", true},
		{"AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcd", "wJalrXUtnFEMIabcd", true},
		{"client_secret", "client_secret=abcd1234efgh", "abcd1234efgh", true},
		{"bare password", "password=hunter2secret", "hunter2secret", true},
		{"bare quoted PASSWORD with spaces", `PASSWORD = "my secret value"`, "my secret value", true},
		{"bare secret colon form", "secret: topsecretvalue", "topsecretvalue", true},
		{"bare token", "token=abcdef123456", "abcdef123456", true},
		{"DB_PWD suffix with separator", "DB_PWD=hunter2secret", "hunter2secret", true},
		{"MYSQL_PWD", "MYSQL_PWD=hunter2secret", "hunter2secret", true},
		{"DB_PASS suffix with separator", "DB_PASS=hunter2secret", "hunter2secret", true},

		// --- 2026-07 widening: JSON-quoted / camelCase / new-stem MUST redact ---
		// (every redact=true value is >= 4 chars — the MinLen-4 floor on
		// the secret group.)
		{"JSON botToken", `{"botToken": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON apiKey", `{"apiKey": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON api_key", `{"api_key": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON client_secret", `{"client_secret": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON token", `{"token": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON refresh_token", `{"refresh_token": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON nested auth.token", `{"auth": {"token": "abcd1234efgh"}}`, "abcd1234efgh", true},
		{"JSON api_hash", `{"api_hash": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON session", `{"session": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"JSON cookie", `{"cookie": "abcd1234efgh"}`, "abcd1234efgh", true},
		{"single-quoted botToken", `'botToken': 'abcd1234'`, "abcd1234", true},
		{"camelCase YAML botToken", "botToken: abcd1234", "abcd1234", true},
		{"camelCase YAML authToken", "authToken: abcd1234", "abcd1234", true},
		{"camelCase YAML apiKey", "apiKey: abcd1234", "abcd1234", true},
		{"EXAMPLE_API_HASH", "EXAMPLE_API_HASH=" + strings.Repeat("ab12", 8), strings.Repeat("ab12", 8), true},
		{"EXAMPLE_SESSION", "EXAMPLE_SESSION=abcd1234", "abcd1234", true},
		{"Cookie header sessionid", "Cookie: sessionid=abc123def456", "abc123def456", true},
		// Documented-bias row: the SESSION stem over-redacts DESKTOP_SESSION
		// (accepted — see spec §2a; 2 lines per env dump).
		{"DESKTOP_SESSION (documented bias)", "DESKTOP_SESSION=gnome", "gnome", true},

		// --- MUST NOT redact (false positives being fixed) ---
		{"PWD cwd (load-bearing)", "PWD=/home/karthi/arogara/SSHGate", "/home/karthi/arogara/SSHGate", false},
		{"OLDPWD", "OLDPWD=/home/karthi/arogara", "/home/karthi/arogara", false},
		{"MONKEY", "MONKEY=banana123456", "banana123456", false},
		{"WHISKEY", "WHISKEY=lagavulin16yr", "lagavulin16yr", false},
		{"COMPASS", "COMPASS=northbynorth", "northbynorth", false},
		{"BYPASS", "BYPASS=enabledvalue", "enabledvalue", false},
		{"KEYBOARD", "KEYBOARD=qwertyuiop", "qwertyuiop", false},

		// --- 2026-07 widening: SESSION/COOKIE survivors + camelCase whitelist ---
		{"SESSION_MANAGER", "SESSION_MANAGER=localunixsocket", "localunixsocket", false},
		{"GDMSESSION", "GDMSESSION=gnome-xorg", "gnome-xorg", false},
		{"XDG_SESSION_TYPE", "XDG_SESSION_TYPE=wayland", "wayland", false},
		{"SSH_AUTH_SOCK", "SSH_AUTH_SOCK=/run/user/1000/keyring/ssh", "/run/user/1000/keyring/ssh", false},
		{"SESSION_TIMEOUT", "SESSION_TIMEOUT=3000", "3000", false},
		{"possession English word", "possession: myhouse12345", "myhouse12345", false},
		{"expression English word", "expression: a+b*c1234", "a+b*c1234", false},
		{"JSON region", `{"region": "ap-south-1"}`, "ap-south-1", false},
		{"JSON status", `{"status": "ok"}`, "ok", false},
		// Multi-line names-only output pins the [ \t]* newline fix: with the
		// old \s* separator, A_API_KEY's "value" spilled onto the next line
		// and redacted B_API_KEY. This row FAILS against master.
		{"names-only multi-line block", "A_API_KEY=\nB_API_KEY=\nDB_PASSWORD=", "B_API_KEY", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out := redactString(t, tc.in+"\n")
			leaked := strings.Contains(out, tc.secret)
			if tc.redact {
				if leaked {
					t.Errorf("value should have been redacted but leaked.\nin:  %q\nout: %q", tc.in, out)
				}
				if !strings.Contains(out, redact.MarkerPrefix) {
					t.Errorf("expected a redaction marker; out=%q", out)
				}
			} else {
				if !leaked {
					t.Errorf("OVER-REDACTION: value should have survived verbatim but was scrubbed.\nin:  %q\nout: %q", tc.in, out)
				}
			}
		})
	}
}
