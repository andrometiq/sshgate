package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// F5: the gate-side authoritative audit log (the forensic system-of-record)
// must redact a secret embedded in the COMMAND STRING before persisting it.
// Previously only command OUTPUT was scrubbed; a `printf 'PASSWORD=...'`
// landed verbatim in audit.log. These tests pin the command-string redaction
// at both at-rest gate sinks: execAndAudit (a command that ran) and
// auditNoExec (a denial that did not run).

// TestGateAuditRedactsCommandStringOnSignedWrite drives a SIGNED write whose
// command embeds a secret-shaped assignment through execAndAudit, and asserts
// the persisted JSON `command` field carries a redaction marker, not the
// secret.
func TestGateAuditRedactsCommandStringOnSignedWrite(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)
	// default all+meta level — the command field is logged at every
	// non-off level, so the default is sufficient.

	const secret = "hunter2secretvalue"
	// `sh -c ...` classifies as a write (the classifier treats sh -c as a
	// write head), so this exercises the signed-write execAndAudit path.
	// The secret rides in the command text itself.
	cmd := `sh -c "printf 'PASSWORD=` + secret + `'"`
	line := signedLine(t, priv, freshPayload(cmd))
	code, _, _ := runWith(t, line)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1", len(recs))
	}
	gotCmd, _ := recs[0]["command"].(string)
	if strings.Contains(gotCmd, secret) {
		t.Errorf("audit command field leaked the secret: %q", gotCmd)
	}
	if !strings.Contains(gotCmd, redact.MarkerPrefix) {
		t.Errorf("audit command field not redacted (no marker): %q", gotCmd)
	}
	// Also assert it is absent anywhere in the raw log file (defence in depth).
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	if strings.Contains(string(raw), secret) {
		t.Errorf("secret persisted somewhere in audit.log:\n%s", raw)
	}
}

// TestGateAuditNoExecRedactsCommandStringOnDenial drives an UNSIGNED write
// whose command embeds a secret. The gate denies it (exit 77) WITHOUT running
// a child, recording it via auditNoExec — which must also redact the command
// string before persisting.
func TestGateAuditNoExecRedactsCommandStringOnDenial(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)
	setAuditLevel(t, dir, "writes") // denials are logged from writes up

	const secret = "hunter2secretvalue"
	// An unsigned write (rm head makes it a write) carrying a secret-shaped
	// assignment in its text. It is denied at the gate (exit 77) and recorded
	// via auditNoExec.
	cmd := `rm -rf /tmp/x; export GITHUB_TOKEN=ghp_` + secret
	code, _, _ := runWith(t, cmd)
	if code != exitNoPermVal {
		t.Fatalf("exit = %d, want %d (denied write)", code, exitNoPermVal)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1 (the denial)", len(recs))
	}
	if recs[0]["approval_status"] != "denied" {
		t.Fatalf("expected denied record, got %v", recs[0])
	}
	gotCmd, _ := recs[0]["command"].(string)
	if strings.Contains(gotCmd, secret) {
		t.Errorf("auditNoExec command field leaked the secret: %q", gotCmd)
	}
	if !strings.Contains(gotCmd, redact.MarkerPrefix) {
		t.Errorf("auditNoExec command field not redacted (no marker): %q", gotCmd)
	}
}

// TestGateAuditBenignCommandUnchanged proves the command-string redaction does
// NOT over-redact a benign command — the audit `command` field stays verbatim
// (no marker, full text), so an operator's forensic handle is preserved.
func TestGateAuditBenignCommandUnchanged(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	// Use a SHORT data-file path, NOT one under t.TempDir(): the tempdir
	// name embeds this test's 45-char function name — a 3-class run the
	// 2026-07 generic default-deny net now redacts (accepted over-redaction
	// posture: token-shaped path segments redact — see the redaction-widening
	// spec §3.6 / §6). A short "x<digits>" segment (2-class, <32 chars) keeps
	// the test meaning "a genuinely benign command is unchanged".
	base, err := os.MkdirTemp("", "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	f := filepath.Join(base, "data.txt")
	if err := os.WriteFile(f, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := "cat " + f
	line := signedLine(t, priv, freshPayload(cmd))
	code, _, _ := runWith(t, line)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1", len(recs))
	}
	gotCmd, _ := recs[0]["command"].(string)
	if gotCmd != cmd {
		t.Errorf("benign command altered in audit: got %q, want %q", gotCmd, cmd)
	}
	if strings.Contains(gotCmd, redact.MarkerPrefix) {
		t.Errorf("benign command carries a redaction marker: %q", gotCmd)
	}
}
