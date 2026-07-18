package signer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// realDenyBackend is a backend stub that mirrors the REAL Telegram backend's
// behaviour on a DENY: it resolves with StatusDenied AND a NON-EMPTY
// ApprovedBy (the denier's "@user"/"id:N"). The shipped MockBackend.Deny
// leaves ApprovedBy empty, which masked C1 — the helper keyed on
// non-emptiness, so an empty deny never tripped the "human" branch. This stub
// reproduces what production actually does. The Result is fully configurable
// so the same stub drives the approved-undelivered over-correction check.
type realDenyBackend struct {
	result signerkit.Result
}

func (b realDenyBackend) Request(context.Context, signerkit.ApprovalRequest) (<-chan signerkit.Result, error) {
	ch := make(chan signerkit.Result, 1)
	ch <- b.result
	return ch, nil
}

func (b realDenyBackend) RequestGrant(context.Context, signerkit.GrantApprovalRequest) (<-chan signerkit.Result, error) {
	ch := make(chan signerkit.Result, 1)
	ch <- b.result
	return ch, nil
}

func (b realDenyBackend) RequestTransfer(context.Context, signerkit.TransferApprovalRequest) (<-chan signerkit.Result, error) {
	ch := make(chan signerkit.Result, 1)
	ch <- b.result
	return ch, nil
}

func (b realDenyBackend) RequestRegisterKey(context.Context, signerkit.RegisterApprovalRequest) (<-chan signerkit.Result, error) {
	ch := make(chan signerkit.Result, 1)
	ch <- b.result
	return ch, nil
}

// failWriteConn reads a request normally but FAILS every Write, so the daemon
// takes its write-failure branch (which records the "<verdict>-undelivered"
// audit row). It captures nothing on the wire — only the audit row matters
// for the approved-undelivered assertion.
type failWriteConn struct {
	in *bytes.Reader
}

func (c *failWriteConn) Read(p []byte) (int, error) { return c.in.Read(p) }
func (c *failWriteConn) Write([]byte) (int, error)  { return 0, errors.New("write failed (test)") }

// TestAuthMode_RealDeny_NotRecordedAsHuman is the C1 regression. A REAL deny
// carries a non-empty approver (the denier). The OLD helper keyed only on
// non-emptiness and stamped auth_mode="human" on it — implying the write was
// authorised. This must be "" on BOTH the socket response AND the audit row.
//
// On the OLD authModeFromApprovedBy(approvedBy) helper this test FAILS:
// approvedBy="@denier" is non-empty, so both the socket AuthMode and the audit
// auth_mode come back "human".
func TestAuthMode_RealDeny_NotRecordedAsHuman(t *testing.T) {
	t.Parallel()
	bk := realDenyBackend{result: signerkit.Result{
		Status:     signerkit.StatusDenied,
		ApprovedBy: "@denier", // real Telegram backend behaviour on a DENY
	}}
	d, _, audit, auditPath, _ := newGrantDaemon(t, bk, time.Unix(1000, 0))
	defer audit.Close()

	// Drive a real deny through respond() (no grant covers it; backend resolves
	// denied with a non-empty approver).
	resp := signOne(t, d, "s_deny", "prod", "rm -rf /srv", grantHost, false, "")
	if resp.Status != "denied" {
		t.Fatalf("sign status = %q; want denied", resp.Status)
	}
	// Socket response: a denied verdict authorised NOTHING.
	if resp.AuthMode != "" {
		t.Errorf("socket auth_mode = %q; want \"\" (a DENY authorised nothing, even with a non-empty denier name)", resp.AuthMode)
	}
	// Audit row: same — must NOT read as "human".
	if got := authModeFor(t, auditPath, "s_deny"); got != "" {
		t.Errorf("audit auth_mode = %q; want \"\" (a DENY must never be logged as human-authorised)", got)
	}
	// approved_by still carries the denier (WHO), unchanged — only auth_mode
	// (HOW) is gated on the verdict.
	if got := approverFor(t, auditPath, "s_deny"); got != "@denier" {
		t.Errorf("approved_by = %q; want @denier (the WHO field is untouched)", got)
	}
}

// TestAuthMode_ApprovedUndelivered_StillHuman pins that the C1 fix does NOT
// over-correct: an approve whose response write FAILS (approved-undelivered)
// must STILL record auth_mode="human" (the daemon decided to authorise; only
// the delivery failed). The audit status is "approved-undelivered", and the
// helper keys on HasPrefix(status,"approved"), so it still resolves "human".
func TestAuthMode_ApprovedUndelivered_StillHuman(t *testing.T) {
	t.Parallel()
	bk := realDenyBackend{result: signerkit.Result{
		Status:     signerkit.StatusApproved,
		ApprovedBy: "karthi",
	}}
	d, _, audit, auditPath, _ := newGrantDaemon(t, bk, time.Unix(1000, 0))
	defer audit.Close()

	req := signReqLine(t, "s_appundel", "prod", "systemctl restart nginx", grantHost)
	conn := &failWriteConn{in: bytes.NewReader(req)}
	// The write fails, so HandleSignRequest returns a non-nil "write response"
	// error — that is the expected path, not a test failure.
	if err := d.HandleSignRequest(context.Background(), conn); err == nil {
		t.Fatal("HandleSignRequest returned nil; want a write-response error (the write must fail)")
	}

	// The audit row must be approved-undelivered AND auth_mode="human".
	if got := statusFor(t, auditPath, "s_appundel"); got != "approved-undelivered" {
		t.Fatalf("audit status = %q; want approved-undelivered", got)
	}
	if got := authModeFor(t, auditPath, "s_appundel"); got != "human" {
		t.Errorf("audit auth_mode = %q; want human (an approved-undelivered is still an authorisation)", got)
	}
}

// TestAuthMode_GrantUndelivered_StillGrant is the grant twin of the above: a
// grant auto-sign whose response write fails must STILL record
// auth_mode="grant:<id>" (the C1 fix must not strip an approved-undelivered's
// grant marker either).
func TestAuthMode_GrantUndelivered_StillGrant(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved (err=%q)", gr.Status, gr.Error)
	}

	// Sign reqID UNARMED — only the grant can resolve it — but the write fails.
	req := signReqLine(t, "s_grantundel", "prod", "systemctl restart nginx", grantHost)
	conn := &failWriteConn{in: bytes.NewReader(req)}
	if err := d.HandleSignRequest(context.Background(), conn); err == nil {
		t.Fatal("HandleSignRequest returned nil; want a write-response error")
	}

	if got := statusFor(t, auditPath, "s_grantundel"); got != "approved-undelivered" {
		t.Fatalf("audit status = %q; want approved-undelivered", got)
	}
	got := authModeFor(t, auditPath, "s_grantundel")
	if !strings.HasPrefix(got, "grant:") {
		t.Errorf("audit auth_mode = %q; want grant:<id> (an approved-undelivered grant keeps its marker)", got)
	}
	if got != "grant:"+gr.GrantID {
		t.Errorf("audit auth_mode = %q; want grant:%s", got, gr.GrantID)
	}
}

// signReqLine builds a single-command sign request line (newline-terminated)
// for driving the daemon directly against a custom conn.
func signReqLine(t *testing.T, reqID, alias, cmd, host string) []byte {
	t.Helper()
	body := map[string]any{
		"kind":       "sign",
		"request_id": reqID,
		"commands": []any{map[string]any{
			"server":      alias,
			"cmd":         cmd,
			"ttl_seconds": 60,
			"host":        host,
		}},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal sign req: %v", err)
	}
	return append(raw, '\n')
}

// statusFor scans the audit log for the row matching reqID and returns its
// status string.
func statusFor(t *testing.T, auditPath, reqID string) string {
	t.Helper()
	for _, ev := range readAudit(t, auditPath) {
		if ev.RequestID == reqID {
			return ev.Status
		}
	}
	t.Fatalf("no audit row for request_id %q", reqID)
	return ""
}

// Compile-time assertion that failWriteConn is an io.ReadWriter (what
// HandleSignRequest expects).
var _ io.ReadWriter = (*failWriteConn)(nil)
