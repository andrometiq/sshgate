package redact_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// sshEd25519Line returns a real authorized_keys ed25519 line
// (`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5… comment`) and its base64 body. The
// body is a genuine SSH wire-format blob, so it begins with the ed25519
// key-type prefix — the shape the twitter-bearer veto must recognise (and a
// synthetic `AAAA…` run must NOT).
func sshEd25519Line(t *testing.T) (line, body string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	authorized := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	fields := strings.Fields(authorized)
	if len(fields) < 2 {
		t.Fatalf("unexpected authorized_keys form: %q", authorized)
	}
	return authorized + " deploy@host", fields[1]
}

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

// TestTwitterBearerVetoedOnRealPubkeyLine is the W4-9 inversion of the old
// TestTwitterBearerRedactsPubkeyBody. The scoped ssh-line veto now suppresses
// gitleaks-twitter-bearer on a GENUINE authorized_keys / known_hosts pubkey
// line, so `cat authorized_keys` is marker-free — the ed25519 body passes
// through untouched. (Combined with the generic net's pre-existing veto the
// whole line is clean.) The veto is scoped: it fires only when an SSH marker
// precedes the body AND the body carries a real SSH wire-format prefix.
func TestTwitterBearerVetoedOnRealPubkeyLine(t *testing.T) {
	line, body := sshEd25519Line(t)
	out := redactString(t, line+"\n")
	if !strings.Contains(out, body) {
		t.Errorf("real ed25519 pubkey body was redacted (veto failed); out=%q", out)
	}
	if strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("authorized_keys line should be marker-free; out=%q", out)
	}
}

// TestTwitterBearerStillRedactsRealBearer is the adversarial still-redacts
// proof: a real Twitter/X bearer shape (`AAAAAAAAAAAAAAAAAAAAAM…`) on a line
// with NO SSH context still redacts. It also proves the veto is line-scoped,
// not a blanket disable of the rule.
func TestTwitterBearerStillRedactsRealBearer(t *testing.T) {
	bearer := "AAAAAAAAAAAAAAAAAAAAAM" + run3class(80) // high-entropy bearer body, not a pubkey prefix
	out := redactString(t, "authorization: Bearer "+bearer+"\n")
	if strings.Contains(out, bearer) {
		t.Errorf("real bearer token leaked; out=%q", out)
	}
	if !strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("real bearer token: no marker; out=%q", out)
	}
}

// TestTwitterBearerNotSpoofedBySSHPrefix is the anti-spoof proof: prefixing a
// real bearer token with a FAKE `ssh-rsa` marker must NOT smuggle it past
// redaction. The body does not carry an SSH wire-format prefix, so the veto's
// body-prefix half fails and the token is still redacted.
func TestTwitterBearerNotSpoofedBySSHPrefix(t *testing.T) {
	bearer := "AAAAAAAAAAAAAAAAAAAAAM" + run3class(80)
	out := redactString(t, "ssh-rsa "+bearer+" attacker@evil\n")
	if strings.Contains(out, bearer) {
		t.Errorf("bearer smuggled past redaction via fake ssh- prefix; out=%q", out)
	}
	if !strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("spoofed line: bearer should still be redacted; out=%q", out)
	}
}

// TestAuthorizedKeysKnownHostsMarkerFree is the end-to-end daily-driver check:
// `cat authorized_keys` and `cat known_hosts` emerge fully marker-free.
func TestAuthorizedKeysKnownHostsMarkerFree(t *testing.T) {
	line1, body1 := sshEd25519Line(t)
	line2, body2 := sshEd25519Line(t)

	authKeys := line1 + "\n" + line2 + "\n"
	if out := redactString(t, authKeys); strings.Contains(out, redact.MarkerPrefix) ||
		!strings.Contains(out, body1) || !strings.Contains(out, body2) {
		t.Errorf("authorized_keys not marker-free / bodies mangled; out=%q", out)
	}

	// known_hosts form: `<host> ssh-ed25519 AAAA…`.
	knownHosts := "[github.com]:22 " + line1 + "\n" + "example.com " + line2 + "\n"
	if out := redactString(t, knownHosts); strings.Contains(out, redact.MarkerPrefix) ||
		!strings.Contains(out, body1) || !strings.Contains(out, body2) {
		t.Errorf("known_hosts not marker-free / bodies mangled; out=%q", out)
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
