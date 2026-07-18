package signer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// memConn is an in-memory full-duplex pipe wrapper with separate
// request/response buffers. Suitable for unit-testing Daemon.
// HandleSignRequest without spinning a real socket.
type memConn struct {
	in  *bytes.Reader
	out *bytes.Buffer
}

func (m *memConn) Read(p []byte) (int, error)  { return m.in.Read(p) }
func (m *memConn) Write(p []byte) (int, error) { return m.out.Write(p) }

func newDaemon(t *testing.T, bk signerkit.Backend) (*signerkit.Daemon, ed25519.PublicKey, *signerkit.AuditLog, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := signerkit.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	d := &signerkit.Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
		NowFunc: func() time.Time { return time.Unix(1000, 0) },
	}
	return d, pub, audit, auditPath
}

func TestDaemon_ApprovePath_SignaturesVerify(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, pub, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()

	req := `{"kind":"sign","request_id":"r_a1","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60},{"server":"prod","cmd":"apt install -y certbot","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}

	// Pre-arrange approval so the daemon's Request call resolves
	// immediately when it reaches the backend.
	mock.Approve("r_a1", "karthi")

	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}

	var resp struct {
		RequestID  string `json:"request_id"`
		Status     string `json:"status"`
		Signatures []struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nraw=%q", err, conn.out.String())
	}
	if resp.RequestID != "r_a1" {
		t.Errorf("RequestID = %q; want r_a1", resp.RequestID)
	}
	if resp.Status != "approved" {
		t.Fatalf("Status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 2 {
		t.Fatalf("got %d sigs; want 2", len(resp.Signatures))
	}

	// Each sig must verify with the public key.
	for i, s := range resp.Signatures {
		if !sigwire.IsSigned(s.Sig) {
			t.Errorf("sig %d missing prefix: %q", i, s.Sig)
			continue
		}
		sig, payload, err := sigwire.DecodeSigned(s.Sig)
		if err != nil {
			t.Errorf("decode sig %d: %v", i, err)
			continue
		}
		if payload.Cmd != s.Cmd {
			t.Errorf("payload cmd mismatch: %q vs %q", payload.Cmd, s.Cmd)
		}
		// Re-marshal payload to recover the exact bytes that were
		// signed (same trick gate.VerifySigned uses).
		signedBytes, _ := json.Marshal(payload)
		if !ed25519.Verify(pub, signedBytes, sig) {
			t.Errorf("sig %d failed to verify", i)
		}
		// TS / Exp sanity: TS == NowFunc, Exp = TS + TTLSec.
		if payload.TS != 1000 {
			t.Errorf("payload.TS = %d; want 1000 (NowFunc)", payload.TS)
		}
		if payload.Exp-payload.TS != 60 {
			t.Errorf("exp - ts = %d; want 60", payload.Exp-payload.TS)
		}
		if payload.Nonce == "" {
			t.Errorf("payload.Nonce empty")
		}
	}

	// Audit event present.
	audit.Close() // flush + release
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "approved" || got[0].RequestID != "r_a1" {
		t.Errorf("audit = %+v; want one approved event for r_a1", got)
	}
}

// TestDaemon_SignsHostBinding pins that the daemon copies each command's
// host-key fingerprint from the request into the SIGNED payload's Host field.
// The MCP reads that fingerprint from its trusted registry (never an agent
// parameter) and the gate enforces it, so this binding is what makes an
// "approve on server X" signature un-replayable on server Y. A regression that
// dropped the field would silently un-bind every signature.
func TestDaemon_SignsHostBinding(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, pub, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	const wantHost = "SHA256:prodServerHostKeyFingerprintAAAAAAAAAAAAAAAA"
	req := `{"kind":"sign","request_id":"r_h1","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60,"host":"` + wantHost + `"}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	mock.Approve("r_h1", "karthi")

	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}

	var resp struct {
		Status     string `json:"status"`
		Signatures []struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "approved" {
		t.Fatalf("Status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("got %d sigs; want 1", len(resp.Signatures))
	}
	sig, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if payload.Host != wantHost {
		t.Errorf("payload.Host = %q; want %q (daemon must sign the request's host binding in)", payload.Host, wantHost)
	}
	// The binding is part of the SIGNED bytes, not just appended: re-marshal
	// and verify against the public key.
	signedBytes, _ := json.Marshal(payload)
	if !ed25519.Verify(pub, signedBytes, sig) {
		t.Errorf("signature does not verify over the host-bound payload")
	}
}

func TestDaemon_DenyPath(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	mock.Deny("r_d1")
	req := `{"kind":"sign","request_id":"r_d1","commands":[{"server":"prod","cmd":"rm /tmp/x","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "denied" || resp.RequestID != "r_d1" {
		t.Errorf("resp = %+v; want denied for r_d1", resp)
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "denied" {
		t.Errorf("audit = %+v; want one denied", got)
	}
}

func TestDaemon_TimeoutPath(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	mock.Timeout("r_t1")
	req := `{"kind":"sign","request_id":"r_t1","commands":[{"server":"prod","cmd":"reboot","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "timeout" {
		t.Errorf("Status = %q; want timeout", resp.Status)
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "timeout" {
		t.Errorf("audit = %+v; want one timeout", got)
	}
}

func TestDaemon_MalformedRequest(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	// Garbled JSON: missing closing brace, then newline.
	conn := &memConn{in: bytes.NewReader([]byte(`{"kind":"sign"` + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest unexpectedly returned err: %v", err)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error; full=%+v", resp.Status, resp)
	}
	if resp.Error == "" {
		t.Errorf("Error field empty")
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "error" {
		t.Errorf("audit = %+v; want one error", got)
	}
}

func TestDaemon_ConcurrentRequestsDontCross(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	const N = 10
	// Pre-arrange all outcomes before launching the daemon calls so we
	// don't race on Approve-vs-Request ordering.
	for i := 0; i < N; i++ {
		mock.Approve(fmt.Sprintf("r_%d", i), "")
	}

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			req := fmt.Sprintf(`{"kind":"sign","request_id":"r_%d","commands":[{"server":"s","cmd":"echo %d","ttl_seconds":60}]}`+"\n", i, i)
			conn := &memConn{in: bytes.NewReader([]byte(req)), out: &bytes.Buffer{}}
			if err := d.HandleSignRequest(context.Background(), conn); err != nil {
				t.Errorf("req %d: %v", i, err)
				return
			}
			var resp struct {
				RequestID string `json:"request_id"`
				Status    string `json:"status"`
			}
			if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
				t.Errorf("req %d unmarshal: %v", i, err)
				return
			}
			want := fmt.Sprintf("r_%d", i)
			if resp.RequestID != want {
				t.Errorf("req %d: got RequestID %q; want %q", i, resp.RequestID, want)
			}
			if resp.Status != "approved" {
				t.Errorf("req %d: status %q; want approved", i, resp.Status)
			}
		}()
	}
	wg.Wait()
}

func TestDaemon_AuditRecordsServerFieldVerbatim(t *testing.T) {
	t.Parallel()
	// Regression for audit M7: the wire `server` field must be
	// recorded verbatim in the audit log's Servers slot. Tools/run
	// is responsible for passing the alias rather than the host;
	// this test pins the daemon side of that contract so a future
	// daemon refactor can't silently mangle the field.
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	mock.Approve("r_alias1", "karthi")

	const wantAlias = "prod-db"
	req := `{"kind":"sign","request_id":"r_alias1","commands":[{"server":"` + wantAlias + `","cmd":"systemctl restart nginx","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(got))
	}
	if len(got[0].Servers) != 1 || got[0].Servers[0] != wantAlias {
		t.Errorf("audit Servers = %v; want [%q] (the wire 'server' field, which the MCP-side spec defines as the alias)", got[0].Servers, wantAlias)
	}
}

// failingWriter accepts a write of any size for the request line on
// the read side, but returns an io.ErrClosedPipe from Write so the
// daemon's response write fails. Used to exercise the audit-on-
// write-failure path (M3).
type failingWriter struct {
	in *bytes.Reader
}

func (f *failingWriter) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *failingWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDaemon_ApprovedButWriteFails_AuditRecordsUndelivered(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()
	mock.Approve("r_und1", "karthi")

	req := `{"kind":"sign","request_id":"r_und1","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60}]}`
	conn := &failingWriter{in: bytes.NewReader([]byte(req + "\n"))}

	err := d.HandleSignRequest(context.Background(), conn)
	if err == nil {
		t.Fatal("expected HandleSignRequest to return a write error; got nil")
	}
	// The handler's contract is "non-nil error only on hard I/O
	// failure where no response was written" — this is exactly that
	// case, so a non-nil error is expected. We just need the audit
	// row to record the asymmetry.

	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 {
		t.Fatalf("audit rows = %d; want 1: %+v", len(got), got)
	}
	if got[0].RequestID != "r_und1" {
		t.Errorf("audit RequestID = %q; want r_und1", got[0].RequestID)
	}
	if got[0].Status != "approved-undelivered" {
		t.Errorf("audit Status = %q; want approved-undelivered (the operator approved but the MCP never received the signature)", got[0].Status)
	}
	if got[0].ApprovedBy != "karthi" {
		t.Errorf("audit ApprovedBy = %q; want karthi", got[0].ApprovedBy)
	}
}

// TestDaemon_VerdictWriteFails_AuditRecordsUndelivered is the F1 audit-
// completeness guard: when the response write fails, the asymmetry must be
// logged distinctly for EVERY verdict, not just approved. A write-lost DENY
// recorded as a plain "denied" would hide that the human's NO never reached
// the agent; it must read "denied-undelivered". Same for timeout.
func TestDaemon_VerdictWriteFails_AuditRecordsUndelivered(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		reqID      string
		arm        func(m *signerkit.MockBackend, reqID string)
		wantStatus string
	}{
		{
			name:       "denied write-lost",
			reqID:      "r_deny_und",
			arm:        func(m *signerkit.MockBackend, id string) { m.Deny(id) },
			wantStatus: "denied-undelivered",
		},
		{
			name:       "timeout write-lost",
			reqID:      "r_to_und",
			arm:        func(m *signerkit.MockBackend, id string) { m.Timeout(id) },
			wantStatus: "timeout-undelivered",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mock := signerkit.NewMockBackend()
			d, _, audit, auditPath := newDaemon(t, mock)
			defer audit.Close()
			tc.arm(mock, tc.reqID)

			req := `{"kind":"sign","request_id":"` + tc.reqID + `","commands":[{"server":"prod","cmd":"rm -rf /srv","ttl_seconds":60}]}`
			conn := &failingWriter{in: bytes.NewReader([]byte(req + "\n"))}

			if err := d.HandleSignRequest(context.Background(), conn); err == nil {
				t.Fatal("expected a write error; got nil")
			}
			audit.Close()
			got := readAudit(t, auditPath)
			if len(got) != 1 {
				t.Fatalf("audit rows = %d; want 1: %+v", len(got), got)
			}
			if got[0].Status != tc.wantStatus {
				t.Errorf("audit Status = %q; want %q (a write-lost %s must be logged distinctly, not as a delivered verdict)",
					got[0].Status, tc.wantStatus, tc.name)
			}
		})
	}
}

func TestDaemon_RemoteSignPath_PassesSignaturesVerbatim(t *testing.T) {
	t.Parallel()
	// Simulates a HostedServerBackend that returned pre-signed wire
	// strings. The daemon must pass them through unmodified — NOT
	// re-sign with d.Key.
	mock := signerkit.NewMockBackend()
	d, pub, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()

	cannedSigs := []signerkit.SignedCmd{
		{Cmd: "systemctl restart nginx", Sig: "SSHGATE_SIG:remote-sig-1"},
		{Cmd: "apt install -y certbot", Sig: "SSHGATE_SIG:remote-sig-2"},
	}
	mock.ApproveWithSignatures("r_remote1", cannedSigs, "karthi")

	req := `{"kind":"sign","request_id":"r_remote1","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60},{"server":"prod","cmd":"apt install -y certbot","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}

	var resp struct {
		RequestID  string `json:"request_id"`
		Status     string `json:"status"`
		Signatures []struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "approved" {
		t.Fatalf("Status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 2 {
		t.Fatalf("got %d sigs; want 2", len(resp.Signatures))
	}
	for i, s := range resp.Signatures {
		if s.Cmd != cannedSigs[i].Cmd {
			t.Errorf("sig %d Cmd = %q; want %q", i, s.Cmd, cannedSigs[i].Cmd)
		}
		if s.Sig != cannedSigs[i].Sig {
			t.Errorf("sig %d Sig = %q; want %q (daemon must pass canned remote sig through verbatim, NOT re-sign locally)", i, s.Sig, cannedSigs[i].Sig)
		}
	}
	// Pubkey-derived from d.Key is referenced to keep the linter from
	// flagging the unused return from newDaemon; the assertion above is
	// the real check (canned strings ≠ d.Key-derived signatures).
	_ = pub

	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "approved" || got[0].ApprovedBy != "karthi" {
		t.Errorf("audit = %+v; want one approved event by karthi", got)
	}
}

func TestDaemon_RemoteSign_LengthMismatch_RespondsError(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()

	// Two commands in request, one signature returned.
	mock.ApproveWithSignatures("r_mismatch_len",
		[]signerkit.SignedCmd{{Cmd: "echo a", Sig: "SSHGATE_SIG:x"}},
		"karthi")
	req := `{"kind":"sign","request_id":"r_mismatch_len","commands":[{"server":"p","cmd":"echo a","ttl_seconds":60},{"server":"p","cmd":"echo b","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error", resp.Status)
	}
	if resp.Error == "" {
		t.Errorf("Error empty; want length-mismatch reason")
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "error" {
		t.Errorf("audit = %+v; want one error", got)
	}
}

func TestDaemon_RemoteSign_CmdMismatch_RespondsError(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, auditPath := newDaemon(t, mock)
	defer audit.Close()

	// Length matches but the second sig's Cmd doesn't match the
	// request's second command — defence against a misbehaving server.
	mock.ApproveWithSignatures("r_mismatch_cmd",
		[]signerkit.SignedCmd{
			{Cmd: "echo a", Sig: "SSHGATE_SIG:x1"},
			{Cmd: "WRONG", Sig: "SSHGATE_SIG:x2"},
		},
		"karthi")
	req := `{"kind":"sign","request_id":"r_mismatch_cmd","commands":[{"server":"p","cmd":"echo a","ttl_seconds":60},{"server":"p","cmd":"echo b","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error", resp.Status)
	}
	if !bytes.Contains([]byte(resp.Error), []byte("cmd mismatch")) {
		t.Errorf("Error = %q; want a cmd-mismatch reason", resp.Error)
	}
	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "error" {
		t.Errorf("audit = %+v; want one error", got)
	}
}

// readAudit re-opens the audit log file and parses all lines.
func readAudit(t *testing.T, path string) []signerkit.AuditEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var out []signerkit.AuditEvent
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var ev signerkit.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("bad audit line: %v\n%q", err, sc.Text())
		}
		out = append(out, ev)
	}
	return out
}
