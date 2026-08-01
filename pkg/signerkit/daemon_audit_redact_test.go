package signerkit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// readAuditEvents reads back the JSON-Lines audit log written to path.
func readAuditEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	var evs []AuditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit json %q: %v", line, err)
		}
		evs = append(evs, e)
	}
	return evs
}

// newRedactingDaemon builds a Daemon wired with a fixed redaction salt + the
// real Combined() ruleset and an on-disk audit log at path.
func newRedactingDaemon(t *testing.T, path string) *Daemon {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	al, err := OpenAuditLog(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return &Daemon{
		Key:         priv,
		Backend:     NewMockBackend(),
		Audit:       al,
		NowFunc:     func() time.Time { return time.Unix(1000, 0) },
		RedactSalt:  [32]byte{0x7e},
		RedactRules: redactrules.Combined(),
	}
}

// TestSignerAuditRedactsCommandString (F5): a secret embedded in a write
// command's text must be scrubbed before it is recorded in the signer audit
// log — previously the full command text landed verbatim (audit.go documents
// this is why the file is 0600, but 0600 is not redaction).
func TestSignerAuditRedactsCommandString(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	d := newRedactingDaemon(t, path)

	const secret = "hunter2secretvalue"
	req := signRequest{
		Kind:      "sign",
		RequestID: "r_secret",
		Commands: []signRequestCmd{
			{Server: "prod", Cmd: `printf 'PASSWORD=` + secret + `'`, TTLSec: 60},
			{Server: "prod", Cmd: "ls -la", TTLSec: 60}, // benign, must survive
		},
	}
	if err := d.audit(req, "approved", "operator"); err != nil {
		t.Fatalf("audit: %v", err)
	}

	evs := readAuditEvents(t, path)
	if len(evs) != 1 {
		t.Fatalf("got %d audit events, want 1", len(evs))
	}
	cmds := evs[0].Commands
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2", len(cmds))
	}
	// [0] carried the secret → must be redacted.
	if strings.Contains(cmds[0], secret) {
		t.Errorf("signer audit leaked the secret: %q", cmds[0])
	}
	if !strings.Contains(cmds[0], redact.MarkerPrefix) {
		t.Errorf("signer audit command not redacted (no marker): %q", cmds[0])
	}
	// [1] was benign → must survive verbatim (forensic handle preserved).
	if cmds[1] != "ls -la" {
		t.Errorf("benign command altered in signer audit: got %q, want %q", cmds[1], "ls -la")
	}
	// Defence in depth: secret absent anywhere in the file.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secret) {
		t.Errorf("secret persisted in signer audit log:\n%s", raw)
	}
}

// TestSignerAuditNoRulesPassThrough proves a Daemon with no redactRules wired
// (nil) records commands verbatim — RedactString fast-paths nil rules, so a
// Daemon built without F5 wiring keeps the existing behaviour.
func TestSignerAuditNoRulesPassThrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	al, err := OpenAuditLog(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer al.Close()
	d := &Daemon{
		Key:     priv,
		Backend: NewMockBackend(),
		Audit:   al,
		NowFunc: func() time.Time { return time.Unix(1000, 0) },
		// no redactSalt / redactRules
	}

	cmd := `export GITHUB_TOKEN=ghp_unredactedwhenrulesnil`
	req := signRequest{
		Kind:      "sign",
		RequestID: "r_nilrules",
		Commands:  []signRequestCmd{{Server: "prod", Cmd: cmd, TTLSec: 60}},
	}
	if err := d.audit(req, "approved", "operator"); err != nil {
		t.Fatalf("audit: %v", err)
	}
	evs := readAuditEvents(t, path)
	if len(evs) != 1 || len(evs[0].Commands) != 1 {
		t.Fatalf("unexpected audit events: %+v", evs)
	}
	if evs[0].Commands[0] != cmd {
		t.Errorf("nil-rules daemon should record command verbatim: got %q want %q", evs[0].Commands[0], cmd)
	}
}
