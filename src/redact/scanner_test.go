package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

// scanString is a convenience: feed s through a fresh writer with the
// combined rule set and return the redacted output.
func scanString(t *testing.T, s string) string {
	t.Helper()
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, rules.Combined())
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.String()
}

// TestRuleGoldens exercises one positive and one negative case per
// rule in the combined set. The positive case must produce a marker
// and remove the secret. The negative case must pass through
// unchanged.
//
// Goldens are inline (not testdata files): every fixture is a
// handful of bytes and lives next to its test for the kind of clarity
// a separate testdata file destroys. testdata fixtures (R7) cover the
// larger E2E corpus.
func TestRuleGoldens(t *testing.T) {
	cases := []struct {
		name       string
		ruleID     string
		positive   string
		secret     string
		negative   string
		negNotMark string // a substring whose presence in negative means we false-positived
	}{
		{
			name:       "sshgate-aws-access-key",
			ruleID:     "sshgate-aws-access-key",
			positive:   "AKIA1234567890ABCDEF",
			secret:     "AKIA1234567890ABCDEF",
			negative:   "AKIAtoo-short and not-AKIA1234567890ABCDEFX (too long suffix)",
			negNotMark: "",
		},
		{
			name:     "sshgate-github-pat",
			ruleID:   "sshgate-github-pat",
			positive: "token=ghp_" + strings.Repeat("a", 40) + " (40 chars)",
			secret:   "ghp_" + strings.Repeat("a", 40),
			negative: "deadbeef-12345678-abcd not a github token", // a UUID-ish thing
		},
		{
			name:     "sshgate-gitlab-pat",
			ruleID:   "sshgate-gitlab-pat",
			positive: "GITLAB_TOKEN=glpat-abcdef1234567890abcd",
			secret:   "glpat-abcdef1234567890abcd",
			negative: "glmat-something-not-a-real-token",
		},
		{
			name:     "sshgate-jwt",
			ruleID:   "sshgate-jwt",
			positive: "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signaturepart",
			secret:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signaturepart",
			negative: "this is not.eyJ-shaped-because-no-prefix garbage.text",
		},
		{
			name:     "sshgate-auth-bearer",
			ruleID:   "sshgate-auth-bearer",
			positive: "Authorization: Bearer abcdef1234567890",
			secret:   "abcdef1234567890",
			// Negative: a bearer-keyword line with no token value. (The
			// old "auth: token=anonymous" negative was retired when the
			// broader sshgate-sensitive-assignment rule landed — a
			// `token=<value>` assignment is now redacted on purpose, the
			// bias-toward-redacting call.)
			negative: "Authorization: Bearer",
		},
		{
			name:     "sshgate-password-kv",
			ruleID:   "sshgate-password-kv",
			positive: "password=hunter2-mysecret",
			secret:   "hunter2-mysecret",
			negative: "user input shown: password field blank",
		},
		{
			name:     "sshgate-slack-token",
			ruleID:   "sshgate-slack-token",
			positive: "SLACK_TOKEN=xoxb-1234567890-abcdefABCDEF",
			secret:   "xoxb-1234567890-abcdefABCDEF",
			negative: "xixb-not-real",
		},
		{
			name:     "sshgate-stripe-live",
			ruleID:   "sshgate-stripe-live",
			positive: "STRIPE_KEY=sk_live_" + strings.Repeat("a", 24),
			secret:   "sk_live_" + strings.Repeat("a", 24),
			negative: "sk_test_xxxxx (test key — should not match)",
		},
		{
			name:     "sshgate-google-oauth",
			ruleID:   "sshgate-google-oauth",
			positive: "Bearer ya29.a0AfH6SMBabcdefghij123456789",
			secret:   "ya29.a0AfH6SMBabcdefghij123456789",
			negative: "ya30.not-google-oauth",
		},
		{
			name:     "sshgate-azure-account-key",
			ruleID:   "sshgate-azure-account-key",
			positive: "AccountKey=" + strings.Repeat("a", 40),
			secret:   strings.Repeat("a", 40),
			negative: "AccountName=publicvalue",
		},

		// --- 2026-07 default-deny widening: new detectors ---
		{
			// BROAD sk-<base62>; the entropy gate lets a real base62 key
			// through but vetoes the lowercase FIDO2 key-type marker.
			name:     "sshgate-openai-broad",
			ruleID:   "sshgate-openai-broad",
			positive: "value sk-" + run3class(40),
			secret:   "sk-" + run3class(40),
			negative: "sk-ecdsa-sha2-nistp256@openssh.com",
		},
		{
			name:     "sshgate-github-fine-pat",
			ruleID:   "sshgate-github-fine-pat",
			positive: "pat github_pat_" + run3class(82),
			secret:   "github_pat_" + run3class(82),
			negative: "github_pat (not a token, just words)",
		},
		{
			name:     "sshgate-zoho-token",
			ruleID:   "sshgate-zoho-token",
			positive: "tok 1000." + hexRun(32) + "." + hexRun(32),
			secret:   "1000." + hexRun(32) + "." + hexRun(32),
			negative: "1000.50 price in the invoice",
		},
		{
			// Generic net telegram stitch (bare form).
			name:     "sshgate-telegram-bot-token/bare",
			ruleID:   "sshgate-telegram-bot-token",
			positive: "before " + mkTelegramToken() + " after",
			secret:   mkTelegramToken(),
			negative: "ts=1700000000:" + hexRun(36) + " (epoch:hex, A-pin miss)",
		},
		{
			// Glued URL form (fires via the digit-suffix peel). Assert the
			// full <id>:<body> is gone + a marker exists; do NOT assert
			// which detector fired.
			name:     "sshgate-telegram-bot-token/glued",
			ruleID:   "sshgate-telegram-bot-token",
			positive: "https://api.telegram.org/bot" + mkTelegramToken() + "/sendMessage",
			secret:   mkTelegramToken(),
			negative: "not a telegram url at all",
		},
		{
			name:     "sshgate-generic-high-entropy/bare",
			ruleID:   "sshgate-generic-high-entropy",
			positive: "value=" + run3class(40),
			secret:   run3class(40),
			negative: "commit e54da87 " + hexRun(40) + " author (lowercase hex, 2-class)",
		},
		{
			// Documented-bias: a token-shaped path segment redacts (spec §6).
			name:     "sshgate-generic-high-entropy/path-segment",
			ruleID:   "sshgate-generic-high-entropy",
			positive: "/tmp/" + run3class(40) + "/data.txt",
			secret:   run3class(40),
			negative: "uuid " + hexRun(8) + "-" + hexRun(4) + "-" + hexRun(4) + "-" + hexRun(4) + "-" + hexRun(12),
		},

		// gitleaks-vendored
		{
			name:     "gitleaks-aws-secret-key",
			ruleID:   "gitleaks-aws-secret-key",
			positive: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			secret:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			negative: "secret-but-not-aws: hellohelloworldworld",
		},
		{
			// Assemble the SK-prefix shape at runtime so the source file
			// never contains a contiguous Twilio-key-shaped literal —
			// GitHub's push-protection scanner cannot tell test fixtures
			// from real secrets and would block this push otherwise.
			name:     "gitleaks-twilio-api-key",
			ruleID:   "gitleaks-twilio-api-key",
			positive: "TWILIO=" + "SK" + strings.Repeat("0", 32),
			secret:   "SK" + strings.Repeat("0", 32),
			negative: "SK-notlongenoughhex",
		},
		{
			name:     "gitleaks-sendgrid-api-key",
			ruleID:   "gitleaks-sendgrid-api-key",
			positive: "SENDGRID=SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
			secret:   "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
			negative: "SG.short.fragment",
		},
		{
			// Same reason as gitleaks-twilio-api-key: assemble at runtime.
			name:     "gitleaks-square-access-token",
			ruleID:   "gitleaks-square-access-token",
			positive: "sq0atp-" + strings.Repeat("0", 22),
			secret:   "sq0atp-" + strings.Repeat("0", 22),
			negative: "sq0atp-too-short",
		},
		{
			name:     "gitleaks-mailgun-api-key",
			ruleID:   "gitleaks-mailgun-api-key",
			positive: "MAILGUN=key-1234567890abcdef1234567890abcdef",
			secret:   "key-1234567890abcdef1234567890abcdef",
			negative: "key-not-32-hex",
		},
		{
			name:     "gitleaks-heroku-api-key",
			ruleID:   "gitleaks-heroku-api-key",
			positive: `heroku_api_key="deadbeef-1234-5678-9abc-def012345678"`,
			secret:   "deadbeef-1234-5678-9abc-def012345678",
			negative: "deadbeef-1234-5678-9abc-def012345678 (UUID, no heroku keyword)",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"/positive", func(t *testing.T) {
			out := scanString(t, tc.positive)
			if strings.Contains(out, tc.secret) {
				t.Errorf("%s: secret %q leaked through:\nin:  %q\nout: %q", tc.ruleID, tc.secret, tc.positive, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("%s: no marker emitted; out=%q", tc.ruleID, out)
			}
		})
		t.Run(tc.name+"/negative", func(t *testing.T) {
			out := scanString(t, tc.negative)
			if strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("%s: false positive on %q; out=%q", tc.ruleID, tc.negative, out)
			}
		})
	}
}

func TestCombinedRulesValidate(t *testing.T) {
	if err := redact.Validate(rules.Combined()); err != nil {
		t.Errorf("combined ruleset failed validation: %v", err)
	}
}

func TestCombinedRulesNonEmpty(t *testing.T) {
	if got := len(rules.Combined()); got < 10 {
		t.Errorf("combined ruleset size = %d, want >= 10", got)
	}
}
