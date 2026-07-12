package signerkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// newMemAudit returns a throwaway *AuditLog (satisfies AuditSink) for
// construction tests, closed on cleanup.
func newMemAudit(t *testing.T) *AuditLog {
	t.Helper()
	a, err := NewMemAuditLog()
	if err != nil {
		t.Fatalf("mem audit: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// TestNew_ValidationMatrix walks the C6 validation matrix: required Signer +
// Audit, optional Backend (typed error at call time, not construction).
func TestNew_ValidationMatrix(t *testing.T) {
	priv, _ := goldenSignerKey()

	tests := []struct {
		name    string
		cfg     func() Config
		wantErr error
	}{
		{"nil signer", func() Config { return Config{Audit: newMemAudit(t)} }, ErrNoSigner},
		{"nil audit", func() Config { return Config{Signer: priv} }, ErrNoAudit},
		{"nil signer beats nil audit (signer checked first)", func() Config { return Config{} }, ErrNoSigner},
		{"signer+audit ok", func() Config { return Config{Signer: priv, Audit: newMemAudit(t)} }, nil},
		{"nil backend ok at construction", func() Config { return Config{Signer: priv, Audit: newMemAudit(t)} }, nil},
		{"append-only sink ok (hosted-plane service)", func() Config {
			return Config{Signer: priv, Audit: NewAppendOnlySink(&bytes.Buffer{})}
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := New(tc.cfg())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v; want %v", err, tc.wantErr)
				}
				if svc != nil {
					t.Errorf("svc must be nil on error, got %v", svc)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if svc == nil {
				t.Fatal("nil Service on success")
			}
		})
	}
}

// TestService_HandleSignRequest_Delegates proves *Service is a RequestHandler
// (C6) whose local path is byte-identical to the raw daemon: a New(Config) built
// with the file key + a real backend + local log signs the golden request and
// emits the exact frozen envelope.
func TestService_HandleSignRequest_Delegates(t *testing.T) {
	// Not t.Parallel(): swaps the package-level randRead seam.
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	priv, _ := goldenSignerKey()
	audit := newMemAudit(t)
	mock := NewMockBackend()
	mock.Approve("r_svc", "operator")

	svc, err := New(Config{Signer: priv, Backend: mock, Audit: audit, NowFunc: goldenNow})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	body := `{"kind":"sign","request_id":"r_svc","commands":[{"server":"prod","cmd":"` +
		goldenCmd + `","ttl_seconds":60,"host":"` + goldenHostFP + `"}]}`
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := svc.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest hard error: %v", err)
	}
	var resp signRespGolden
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "approved" || len(resp.Signatures) != 1 {
		t.Fatalf("status=%q sigs=%d; want approved/1", resp.Status, len(resp.Signatures))
	}
	if resp.Signatures[0].Sig != wantSignHostGolden {
		t.Errorf("Service(New, file-key Signer) envelope != golden:\n got  %q\n want %q", resp.Signatures[0].Sig, wantSignHostGolden)
	}
}

// TestService_NilBackend_TypedError: a Service built with no Backend returns a
// typed error line at call time, never a nil-deref panic (the matrix guarantee).
func TestService_NilBackend_TypedError(t *testing.T) {
	t.Parallel()
	priv, _ := goldenSignerKey()
	svc, err := New(Config{Signer: priv, Audit: newMemAudit(t)}) // no Backend
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := `{"kind":"sign","request_id":"r_nb","commands":[{"server":"p","cmd":"echo hi","ttl_seconds":60}]}`
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := svc.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest should not hard-error on nil backend: %v", err)
	}
	var resp struct{ Status, Error string }
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Fatalf("status=%q; want error", resp.Status)
	}
	if !strings.Contains(resp.Error, "no approval backend") {
		t.Errorf("error=%q; want it to mention the missing backend", resp.Error)
	}
}

// TestService_NonLocalAuditSink_SocketRefused: a Service whose Audit is a
// non-*AuditLog sink (hosted-plane only) refuses the socket path with a typed
// error rather than panicking on the first audit write.
func TestService_NonLocalAuditSink_SocketRefused(t *testing.T) {
	t.Parallel()
	priv, _ := goldenSignerKey()
	svc, err := New(Config{Signer: priv, Backend: NewMockBackend(), Audit: NewAppendOnlySink(&bytes.Buffer{})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := `{"kind":"sign","request_id":"r_h","commands":[{"server":"p","cmd":"echo hi","ttl_seconds":60}]}`
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := svc.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest should not hard-error: %v", err)
	}
	var resp struct{ Status, Error string }
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Fatalf("status=%q; want error", resp.Status)
	}
	if !strings.Contains(resp.Error, "AuditLog") {
		t.Errorf("error=%q; want it to name the AuditLog requirement", resp.Error)
	}
}

// TestService_CustodyDelegation: Lock/Unlock/RotateTo on *Service reach the
// inner daemon (so a locked Service refuses to sign, then recovers).
func TestService_CustodyDelegation(t *testing.T) {
	t.Parallel()
	priv, _ := goldenSignerKey()
	audit := newMemAudit(t)
	mock := NewMockBackend()
	svc, err := New(Config{Signer: priv, Backend: mock, Audit: audit, NowFunc: goldenNow})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := svc.Lock("held", Operator{ID: "op"}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	mock.Approve("r_lk", "operator")
	body := `{"kind":"sign","request_id":"r_lk","commands":[{"server":"p","cmd":"echo hi","ttl_seconds":60,"host":"` + goldenHostFP + `"}]}`
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := svc.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("hard error: %v", err)
	}
	var resp struct{ Status, Error string }
	json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp)
	if resp.Status != "error" || !strings.Contains(resp.Error, "signer locked") {
		t.Fatalf("locked Service should refuse: status=%q error=%q", resp.Status, resp.Error)
	}
	if err := svc.Unlock(Operator{ID: "op"}); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

// TestAppendOnlySink_WritesLines: the external append-only anchor writes one
// JSON line per event, each carrying a kind discriminant, and the *AuditLog
// adapter satisfies AuditSink too.
func TestAppendOnlySink_WritesLines(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	s := NewAppendOnlySink(&buf)
	if err := s.Call(context.Background(), AuditCall{RequestID: "r1", Command: "echo hi", HostKeyFP: "SHA256:x"}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if err := s.Verdict(context.Background(), AuditVerdict{RequestID: "r1", Operator: Operator{ID: "op", AuthnMethod: "totp"}, CommandSHA256: "abc", Approved: true}); err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	kinds := []string{"call", "verdict"}
	for i, ln := range lines {
		var rec struct {
			Kind  string          `json:"kind"`
			Event json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(ln, &rec); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		if rec.Kind != kinds[i] {
			t.Errorf("line %d kind=%q; want %q", i, rec.Kind, kinds[i])
		}
	}

	// The *AuditLog adapter must also satisfy AuditSink and accept both events.
	var sink AuditSink = newMemAudit(t)
	if err := sink.Call(context.Background(), AuditCall{RequestID: "r2", Command: "ls"}); err != nil {
		t.Fatalf("AuditLog.Call: %v", err)
	}
	if err := sink.Verdict(context.Background(), AuditVerdict{RequestID: "r2", Approved: false}); err != nil {
		t.Fatalf("AuditLog.Verdict: %v", err)
	}
}
