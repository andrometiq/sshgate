package redact_test

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// spec_acceptance_test mirrors the operator's acceptance list for the 2026-07
// default-deny widening (redaction-widening spec §3.3): the concrete shapes a
// production multi-server run showed leaking. Each scenario drives the real
// combined-ruleset writer (redactString, from leak_test.go). All secret-shaped
// fixtures are assembled at runtime (run3class / mkTelegramToken / hexRun live
// in scanner_generic_writer_test.go); no contiguous token literal in source.

func TestAcceptanceEnvDump(t *testing.T) {
	// `cat .env`: named secret values AND one UNKNOWN-named high-entropy
	// value are redacted; comments, names, and DEBUG=true survive.
	unknown := run3class(40) // caught by the generic net despite the benign name
	env := "# production config for the app\n" +
		"DEBUG=true\n" +
		"API_KEY=hunter2secretval\n" +
		"DB_PASSWORD=prodpass9999\n" +
		"DATA_BLOB=" + unknown + "\n" +
		"HOME=/home/appuser\n"
	out := redactString(t, env)

	// Survivors.
	for _, keep := range []string{"# production config for the app", "DEBUG=true", "HOME=/home/appuser", "API_KEY=", "DATA_BLOB="} {
		if !strings.Contains(out, keep) {
			t.Errorf("acceptance: expected %q to survive; out=%q", keep, out)
		}
	}
	// Redactions (named + unknown-named).
	for _, gone := range []string{"hunter2secretval", "prodpass9999", unknown} {
		if strings.Contains(out, gone) {
			t.Errorf("acceptance: secret %q leaked; out=%q", gone, out)
		}
	}
	if strings.Count(out, redact.MarkerPrefix) < 3 {
		t.Errorf("acceptance: expected >=3 markers; out=%q", out)
	}
}

func TestAcceptanceJSONDoc(t *testing.T) {
	// jq-style JSON with botToken / api_key / nested auth.token; region is a
	// benign value that must survive.
	json := `{"botToken": "tgsecret12345", "api_key": "apisecret6789", ` +
		`"auth": {"token": "nestedsecret42"}, "region": "ap-south-1"}`
	out := redactString(t, json)
	for _, gone := range []string{"tgsecret12345", "apisecret6789", "nestedsecret42"} {
		if strings.Contains(out, gone) {
			t.Errorf("acceptance JSON: %q leaked; out=%q", gone, out)
		}
	}
	if !strings.Contains(out, "ap-south-1") {
		t.Errorf("acceptance JSON: benign region value should survive; out=%q", out)
	}
	if strings.Count(out, redact.MarkerPrefix) < 3 {
		t.Errorf("acceptance JSON: expected >=3 markers; out=%q", out)
	}
}

func TestAcceptanceNamesOnlyByteIdentical(t *testing.T) {
	// `grep -oE '^[A-Za-z_]+=' .env` output: names with NO value. The
	// [ \t]* separator fix means none of these redact the next line's name;
	// the output is byte-identical.
	namesOnly := "A_API_KEY=\nB_SECRET=\nDB_PASSWORD=\n"
	out := redactString(t, namesOnly)
	if out != namesOnly {
		t.Errorf("acceptance names-only: output not byte-identical.\n got: %q\nwant: %q", out, namesOnly)
	}
	if strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("acceptance names-only: unexpected marker; out=%q", out)
	}
}

func TestAcceptanceGitRemoteUserinfo(t *testing.T) {
	// `git remote -v`: colon-less `https://<pat>@github.com/…` userinfo. The
	// url-userinfo-password rule does NOT fire (no ':' in the userinfo); the
	// token rules catch the PAT regardless of URL framing.
	ghp := "ghp_" + run3class(40)
	fine := "github_pat_" + run3class(82)
	gitRemote := "origin\thttps://" + ghp + "@github.com/org/repo.git (fetch)\n" +
		"origin\thttps://" + fine + "@github.com/org/repo.git (push)\n"
	out := redactString(t, gitRemote)
	for _, gone := range []string{ghp, fine} {
		if strings.Contains(out, gone) {
			t.Errorf("acceptance git remote: PAT leaked; out=%q", out)
		}
	}
	// The URL framing survives.
	if !strings.Contains(out, "@github.com/org/repo.git") {
		t.Errorf("acceptance git remote: URL framing mangled; out=%q", out)
	}
	if strings.Count(out, redact.MarkerPrefix) < 2 {
		t.Errorf("acceptance git remote: expected >=2 markers; out=%q", out)
	}

	// Colon form `https://<user>:<pat>@host` — the ':' before '@' makes this
	// the userinfo-password shape. The PAT must be redacted (the security
	// property). NOTE: the host+path may ALSO be redacted here — the
	// `x-access-token:` prefix reads as a `token: <value>` assignment and the
	// sensitive-assignment value class spans through `@host/path` — accepted
	// over-redaction (pre-existing, not introduced by the widening), so we
	// only assert the PAT is gone and a marker is present.
	pat := "github_pat_" + run3class(82)
	colonForm := "origin\thttps://x-access-token:" + pat + "@github.com/org/repo.git (fetch)\n"
	out2 := redactString(t, colonForm)
	if strings.Contains(out2, pat) {
		t.Errorf("acceptance git remote colon form: PAT leaked; out=%q", out2)
	}
	if !strings.Contains(out2, redact.MarkerPrefix) {
		t.Errorf("acceptance git remote colon form: no marker; out=%q", out2)
	}
}

// TestTwitterBearerRedactsPubkeyBody positively pins the PRE-EXISTING
// gitleaks-twitter-bearer behaviour that the generic net's ssh-line veto
// relies on for authorized_keys hygiene: an `AAAA…`-prefixed ed25519/rsa
// pubkey body is redacted by that rule (so the ssh veto keeping the GENERIC
// net off the line does not mean the line is marker-free). Pinning it guards
// against a future change silently dropping that coverage.
func TestTwitterBearerRedactsPubkeyBody(t *testing.T) {
	// AAAA + 96 base62 (>= the rule's 64-char floor, 3-class).
	body := "AAAA" + run3class(96)
	out := redactString(t, "ssh-ed25519 "+body+" user@host\n")
	if strings.Contains(out, body) {
		t.Errorf("twitter-bearer no longer redacts an AAAA pubkey body; out=%q", out)
	}
	if !strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("no marker on AAAA pubkey body; out=%q", out)
	}
}

func TestAcceptanceBareTokens(t *testing.T) {
	cases := []struct{ name, token string }{
		{"telegram", mkTelegramToken()},
		{"openai", "sk-" + run3class(40)},
		{"github-fine-pat", "github_pat_" + run3class(82)},
		{"zoho", "1000." + hexRun(32) + "." + hexRun(32)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out := redactString(t, "value is "+tc.token+" end\n")
			if strings.Contains(out, tc.token) {
				t.Errorf("bare %s token leaked; out=%q", tc.name, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("bare %s token: no marker; out=%q", tc.name, out)
			}
		})
	}
}
