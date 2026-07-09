// Package gitleaks holds the vendored subset of named-format
// redaction rules transcribed from upstream gitleaks
// (see PROVENANCE.md for the source SHA and curation notes).
//
// Rule IDs are prefixed `gitleaks-` to keep the namespace distinct
// from sshgate-native rules. When sshgate-native and gitleaks rules
// detect the same secret format, the SortRules combiner does NOT
// pick one over the other — both fire, the scanner de-overlaps the
// resulting matches by byte range. Two rule hits on the same span
// produce one marker.
package gitleaks

import "github.com/karthikeyan5/sshgate/src/redact"

// Rules returns the gitleaks-vendored ruleset.
func Rules() []redact.Rule {
	return []redact.Rule{
		// AWS access key — gitleaks's `aws-access-token`. The
		// SSHGate-native sshgate-aws-access-key rule covers the
		// same format; both fire and the scanner de-overlaps.
		redact.CompileRule(
			"gitleaks-aws-access-token",
			"AWS access token (gitleaks)",
			`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`,
			[]string{"AKIA", "ABIA", "ACCA", "ASIA"},
			1, 20, 20,
		),

		// AWS secret access key — keyword-anchored. Without a
		// structural prefix, the rule requires the literal token
		// `aws_secret_access_key` (env or config form).
		redact.CompileRule(
			"gitleaks-aws-secret-key",
			"AWS secret access key (env/config form)",
			`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`,
			[]string{"aws_secret_access_key"},
			1, 40, 40,
		),

		// PEM private key — the canonical begin-end armoured key
		// block. Note: PEM blocks are also caught by the dedicated
		// pem.go accumulator in the writer; this rule exists for the
		// edge case of a PEM block compressed onto a single line
		// (unusual but seen in JSON-quoted config dumps).
		// High-confidence: a `-----BEGIN ...PRIVATE KEY-----...-----END`
		// span is unmistakable — redact regardless of length so a key
		// larger than MaxLen still can't leak (MINOR 7).
		redact.CompileRule(
			"gitleaks-pem-private-key",
			"PEM-armoured private key (single-line form)",
			`(-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END [A-Z ]*PRIVATE KEY-----)`,
			[]string{"-----BEGIN", "PRIVATE KEY"},
			1, 100, 16384,
		).WithHighConfidence(),

		// SSH private key — OpenSSH format.
		redact.CompileRule(
			"gitleaks-ssh-private-key",
			"OpenSSH private key armoured block (single line)",
			`(-----BEGIN OPENSSH PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END OPENSSH PRIVATE KEY-----)`,
			[]string{"OPENSSH PRIVATE KEY"},
			1, 100, 16384,
		).WithHighConfidence(),

		// Twilio API key.
		redact.CompileRule(
			"gitleaks-twilio-api-key",
			"Twilio API key (SK-prefix 32 hex)",
			`\b(SK[0-9a-fA-F]{32})\b`,
			[]string{"SK"},
			1, 34, 34,
		),

		// SendGrid API key.
		redact.CompileRule(
			"gitleaks-sendgrid-api-key",
			"SendGrid API key (SG.<22>.<43>)",
			`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`,
			[]string{"SG."},
			1, 69, 69,
		),

		// Square access token.
		redact.CompileRule(
			"gitleaks-square-access-token",
			"Square OAuth access token (sq0atp-...)",
			`\b(sq0atp-[A-Za-z0-9_\-]{22})\b`,
			[]string{"sq0atp-"},
			1, 29, 29,
		),

		// Mailgun API key.
		redact.CompileRule(
			"gitleaks-mailgun-api-key",
			"Mailgun API key (key-<32hex>)",
			`\b(key-[a-f0-9]{32})\b`,
			[]string{"key-"},
			1, 36, 36,
		),

		// Heroku API key (UUIDv4 shape under a known keyword).
		redact.CompileRule(
			"gitleaks-heroku-api-key",
			"Heroku API key (UUID-shaped, under heroku keyword)",
			`(?i)heroku[_\-\s]*(?:api[_\-\s]*)?key[\s'":=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`,
			[]string{"heroku"},
			1, 36, 36,
		),

		// Twitter Bearer token (long AAAA-prefixed).
		//
		// WithSSHLineVeto: the `AAAA…` pattern also matches an SSH
		// public-key body (the SSH wire format base64-encodes the key type
		// first: ed25519 -> AAAAC3NzaC1lZDI1NTE5…, rsa -> AAAAB3NzaC1yc2E…).
		// The veto suppresses the match on a genuine authorized_keys /
		// known_hosts pubkey line (SSH marker on the line AND an SSH
		// wire-format body prefix) so `cat authorized_keys` is marker-free,
		// while a real bearer token — which does not encode an SSH key type
		// — still redacts even if a fake `ssh-` marker is prepended.
		redact.CompileRule(
			"gitleaks-twitter-bearer",
			"Twitter API bearer token (AAAA-prefixed, ~100 char)",
			`\b(AAAA[A-Za-z0-9%]{60,200})\b`,
			[]string{"AAAA"},
			1, 64, 204,
		).WithSSHLineVeto(),

		// Generic private-key-style PKCS8 / RSA — same as above but
		// the catch-all "PRIVATE KEY" without algorithm prefix.
		redact.CompileRule(
			"gitleaks-private-key-generic",
			"Generic PRIVATE KEY armour (single line)",
			`(-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----)`,
			[]string{"BEGIN PRIVATE KEY"},
			1, 100, 16384,
		).WithHighConfidence(),
	}
}
