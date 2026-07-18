package backend

import (
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// TestFormatApprovalMessage_RevealBanner pins the distinct, scary rendering a
// SECRET-REVEAL approval gets: an unmistakable banner warning that output will
// NOT be redacted, plus the mandatory operator-supplied reason. The human must
// be able to tell a reveal apart from a normal write at a glance — that visual
// distinction is the whole point of routing reveal through a separate UX.
func TestFormatApprovalMessage_RevealBanner(t *testing.T) {
	t.Parallel()
	req := signerkit.ApprovalRequest{
		RequestID: "r_reveal",
		Commands: []signerkit.CommandReq{
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

	// A reveal-specific banner that names the danger.
	if !strings.Contains(got, "SECRET-REVEAL") {
		t.Errorf("reveal message missing SECRET-REVEAL banner:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "not be redacted") {
		t.Errorf("reveal message must warn output will NOT be redacted:\n%s", got)
	}
	// The mandatory reason must be shown to the human.
	if !strings.Contains(got, "need the DB password to debug an auth failure") {
		t.Errorf("reveal message missing the operator reason:\n%s", got)
	}
	// The command itself is still shown.
	if !strings.Contains(got, "cat /etc/secret.env") {
		t.Errorf("reveal message missing the command:\n%s", got)
	}
}

// TestFormatApprovalMessage_NormalWriteNoBanner pins that an ordinary write
// renders EXACTLY as before — no reveal banner, no "not be redacted" warning.
// The scary UX must be reserved for actual reveals so it never loses its
// signal.
func TestFormatApprovalMessage_NormalWriteNoBanner(t *testing.T) {
	t.Parallel()
	req := signerkit.ApprovalRequest{
		RequestID: "r_write",
		Commands: []signerkit.CommandReq{
			{Server: "prod", Cmd: "systemctl restart nginx", TTLSec: 60},
		},
		Submitted: time.Now(),
	}
	got := formatApprovalMessage(req, 5*time.Second, nil, nil, [32]byte{}, nil)
	if strings.Contains(got, "SECRET-REVEAL") {
		t.Errorf("normal write wrongly rendered a reveal banner:\n%s", got)
	}
	if strings.Contains(strings.ToLower(got), "not be redacted") {
		t.Errorf("normal write wrongly warned about redaction:\n%s", got)
	}
	if !strings.Contains(got, "systemctl restart nginx") {
		t.Errorf("normal write missing the command:\n%s", got)
	}
}
