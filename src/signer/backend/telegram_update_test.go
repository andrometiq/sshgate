package backend

import (
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// updateHashFixture is a valid 64-lowercase-hex SHA-256 (a fake, publish-safe
// digest). The whole point of the update banner is that this exact string
// reaches the operator's eyes byte-for-byte — it is what the master key signed.
const updateHashFixture = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"

// TestFormatApprovalMessage_UpdateBanner pins the distinct, scary rendering a
// gate-binary update (SSHGATE_UPDATE <sha256>) gets: an alarming banner naming
// the consequence (the new gate governs every future command), the target
// server, the RAW 64-hex hash shown verbatim (never a redaction marker — the
// operator must see exactly the bytes that were signed, R2/Finding-7), and the
// operator-facing Build line carried in Reason so a downgrade is spottable.
func TestFormatApprovalMessage_UpdateBanner(t *testing.T) {
	t.Parallel()
	req := ApprovalRequest{
		RequestID: "r_update",
		Commands: []CommandReq{
			{
				Server: "prod-web",
				Cmd:    "SSHGATE_UPDATE " + updateHashFixture,
				TTLSec: 300,
				Reason: "sshgate-gate-linux-amd64 · version v1.3.0 · running version v1.2.9",
			},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, [32]byte{}, nil)

	// Scary update banner naming the danger.
	if !strings.Contains(got, "GATE BINARY UPDATE") {
		t.Errorf("update message missing GATE BINARY UPDATE banner:\n%s", got)
	}
	if !strings.Contains(got, "REPLACES the SSHGate gate binary") {
		t.Errorf("update message missing the REPLACES warning:\n%s", got)
	}
	// The target server must be named.
	if !strings.Contains(got, "prod-web") {
		t.Errorf("update message missing the server alias:\n%s", got)
	}
	// Distinct header line.
	if !strings.Contains(got, "🔐 SSHGate GATE UPDATE") {
		t.Errorf("update message missing the GATE UPDATE header:\n%s", got)
	}
	// The RAW hash must appear verbatim, labelled.
	if !strings.Contains(got, "New gate SHA-256: "+updateHashFixture) {
		t.Errorf("update message missing the raw SHA-256 line:\n%s", got)
	}
	// The Build line carries the Reason verbatim.
	if !strings.Contains(got, "Build: sshgate-gate-linux-amd64 · version v1.3.0 · running version v1.2.9") {
		t.Errorf("update message missing the Build (reason) line:\n%s", got)
	}
	// The usual footer still renders.
	if !strings.Contains(got, "Request ID: r_update") {
		t.Errorf("update message missing the Request ID line:\n%s", got)
	}
	if !strings.Contains(got, "Expires in") {
		t.Errorf("update message missing the Expires line:\n%s", got)
	}
	// It is NOT a reveal and NOT a normal write.
	if strings.Contains(got, "SECRET-REVEAL") {
		t.Errorf("update message wrongly rendered a reveal banner:\n%s", got)
	}
	if strings.Contains(got, "🔐 SSHGate approval") {
		t.Errorf("update message wrongly rendered the plain approval banner:\n%s", got)
	}
}

// TestFormatApprovalMessage_UpdateNoReason proves an empty Reason omits the
// Build line entirely, while the banner + raw hash still render.
func TestFormatApprovalMessage_UpdateNoReason(t *testing.T) {
	t.Parallel()
	req := ApprovalRequest{
		RequestID: "r_update_noreason",
		Commands: []CommandReq{
			{Server: "prod-web", Cmd: "SSHGATE_UPDATE " + updateHashFixture, TTLSec: 300},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, [32]byte{}, nil)

	if !strings.Contains(got, "GATE BINARY UPDATE") {
		t.Errorf("update message missing GATE BINARY UPDATE banner:\n%s", got)
	}
	if !strings.Contains(got, "New gate SHA-256: "+updateHashFixture) {
		t.Errorf("update message missing the raw SHA-256 line:\n%s", got)
	}
	if strings.Contains(got, "Build:") {
		t.Errorf("empty Reason must omit the Build line:\n%s", got)
	}
}

// TestFormatApprovalMessage_UpdateMalformedHash proves the update banner
// format-validates the committed hash before rendering: a crafted c.Cmd that
// smuggles a newline (or is otherwise not a clean 64-lowercase-hex string) is
// replaced by a single-line marker so it can never inject fake banner lines
// (phishing), while a valid 64-hex hash still renders verbatim (WYSIWYG,
// R2/Finding-7). The gate rejects a non-64-hex update too, so nothing installs
// either way.
func TestFormatApprovalMessage_UpdateMalformedHash(t *testing.T) {
	t.Parallel()
	// A "hash" carrying an injected newline plus a forged extra banner line.
	evil := "deadbeef\nApprove: yes — trust me"
	req := ApprovalRequest{
		RequestID: "r_update_evil",
		Commands: []CommandReq{
			{Server: "prod-web", Cmd: "SSHGATE_UPDATE " + evil, TTLSec: 300},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, [32]byte{}, nil)

	// The malformed marker renders on a single line...
	if !strings.Contains(got, "New gate SHA-256: <malformed hash — the gate will reject this update>") {
		t.Errorf("malformed hash did not render the marker:\n%s", got)
	}
	// ...and exactly once (an injection would add more "New gate SHA-256:" lines).
	if n := strings.Count(got, "New gate SHA-256:"); n != 1 {
		t.Errorf("expected exactly one 'New gate SHA-256:' line; got %d (injection?):\n%s", n, got)
	}
	// The attacker-injected line must NOT appear as a raw banner line.
	if strings.Contains(got, "Approve: yes") {
		t.Errorf("attacker-injected line leaked into the banner:\n%s", got)
	}

	// A valid 64-hex hash still renders verbatim and is NOT flagged malformed.
	reqOK := ApprovalRequest{
		RequestID: "r_update_ok",
		Commands: []CommandReq{
			{Server: "prod-web", Cmd: "SSHGATE_UPDATE " + updateHashFixture, TTLSec: 300},
		},
		Submitted: time.Now(),
	}
	gotOK := formatApprovalMessage(reqOK, 5*time.Second, nil, nil, [32]byte{}, nil)
	if !strings.Contains(gotOK, "New gate SHA-256: "+updateHashFixture) {
		t.Errorf("valid hash was not rendered verbatim:\n%s", gotOK)
	}
	if strings.Contains(gotOK, "malformed hash") {
		t.Errorf("valid hash wrongly flagged as malformed:\n%s", gotOK)
	}
}

// TestFormatApprovalMessage_UpdateNormalWriteUnaffected proves an ordinary write
// still gets the plain approval banner and NEVER the update banner. The scary
// update UX must be reserved for real updates so it keeps its signal.
func TestFormatApprovalMessage_UpdateNormalWriteUnaffected(t *testing.T) {
	t.Parallel()
	req := ApprovalRequest{
		RequestID: "r_write",
		Commands: []CommandReq{
			{Server: "prod", Cmd: "systemctl restart nginx", TTLSec: 60},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, [32]byte{}, nil)

	if !strings.Contains(got, "🔐 SSHGate approval") {
		t.Errorf("normal write missing the plain approval banner:\n%s", got)
	}
	if strings.Contains(got, "GATE BINARY UPDATE") {
		t.Errorf("normal write wrongly rendered the update banner:\n%s", got)
	}
	if !strings.Contains(got, "systemctl restart nginx") {
		t.Errorf("normal write missing the command:\n%s", got)
	}
}

// TestFormatApprovalMessage_UpdateRevealUnaffected proves a SECRET-REVEAL still
// renders its own banner (unchanged) and NEVER the update banner.
func TestFormatApprovalMessage_UpdateRevealUnaffected(t *testing.T) {
	t.Parallel()
	req := ApprovalRequest{
		RequestID: "r_reveal",
		Commands: []CommandReq{
			{
				Server: "prod-db",
				Cmd:    "cat /etc/secret.env",
				TTLSec: 60,
				Reveal: true,
				Reason: "need the DB password to debug an auth failure",
			},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, [32]byte{}, nil)

	if !strings.Contains(got, "SECRET-REVEAL") {
		t.Errorf("reveal message missing SECRET-REVEAL banner:\n%s", got)
	}
	if strings.Contains(got, "GATE BINARY UPDATE") {
		t.Errorf("reveal message wrongly rendered the update banner:\n%s", got)
	}
	if !strings.Contains(got, "cat /etc/secret.env") {
		t.Errorf("reveal message missing the command:\n%s", got)
	}
}

// TestFormatApprovalMessage_UpdateHashRawUnderRealRuleset is the Finding-7 pin:
// under the FULL production ruleset (redactrules.Combined()) with a real
// non-zero salt, the 64-hex hash must still render verbatim — never masked by
// the redaction marker. This proves the hash is rendered OUTSIDE the redaction
// sink, so "what you see is what you approve" holds regardless of ruleset drift.
func TestFormatApprovalMessage_UpdateHashRawUnderRealRuleset(t *testing.T) {
	t.Parallel()
	salt := [32]byte{0x5f}
	rules := redactrules.Combined()
	req := ApprovalRequest{
		RequestID: "r_update_realrules",
		Commands: []CommandReq{
			{
				Server: "prod-web",
				Cmd:    "SSHGATE_UPDATE " + updateHashFixture,
				TTLSec: 300,
				Reason: "sshgate-gate-linux-amd64 · version v1.3.0 · running version v1.2.9",
			},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, salt, rules)

	if !strings.Contains(got, updateHashFixture) {
		t.Errorf("hash was not rendered verbatim under the real ruleset:\n%s", got)
	}
	if strings.Contains(got, redact.MarkerPrefix) {
		t.Errorf("hash was masked by the redaction marker under the real ruleset:\n%s", got)
	}
}
