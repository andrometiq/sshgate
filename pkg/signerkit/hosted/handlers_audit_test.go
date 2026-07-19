package hosted_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
)

type callCaptureSink struct {
	mu       sync.Mutex
	calls    []signerkit.AuditCall
	failCall bool
}

func (s *callCaptureSink) Call(_ context.Context, e signerkit.AuditCall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failCall {
		return errors.New("call sink down")
	}
	s.calls = append(s.calls, e)
	return nil
}

func (s *callCaptureSink) Verdict(context.Context, signerkit.AuditVerdict) error { return nil }

func signAuditFixture(t *testing.T, sink signerkit.AuditSink) (*httptest.Server, *sqlitestore.DB) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "sign-audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	core, err := signerkit.New(signerkit.Config{Signer: priv, Audit: sink})
	if err != nil {
		t.Fatalf("signerkit.New: %v", err)
	}
	srv := hosted.NewServer("audit-key", db, log.New(io.Discard, "", 0))
	srv.Signer = core
	srv.MachineClientID = "client-a"
	srv.RequiredApprovals = 2
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, db
}

func postAuditedSign(t *testing.T, ts *httptest.Server) *http.Response {
	t.Helper()
	body := []byte(`{"client_id":"client-a","commands":[{"server":"prod","cmd":"uptime","ttl_seconds":60,"host_key_fp":"SHA256:abc"}]}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sign", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer audit-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestSign_AuditsBeforeQueueing(t *testing.T) {
	t.Parallel()
	sink := &callCaptureSink{}
	ts, db := signAuditFixture(t, sink)
	resp := postAuditedSign(t, ts)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d; want 202", resp.StatusCode)
	}
	rows, err := db.ListPending(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("pending = %d, err=%v; want 1", len(rows), err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.calls) != 1 {
		t.Fatalf("audit calls = %d; want 1", len(sink.calls))
	}
	wantHash := sha256.Sum256(rows[0].Commands)
	if sink.calls[0].RequestID != rows[0].RequestID || sink.calls[0].Command != "" || sink.calls[0].CommandsSHA256 != hex.EncodeToString(wantHash[:]) || sink.calls[0].CommandCount != 1 || len(sink.calls[0].HostKeyFPs) != 1 || sink.calls[0].HostKeyFPs[0] != "SHA256:abc" || sink.calls[0].Phase != "submit_attempt" {
		t.Fatalf("audit call = %+v; pending id=%s", sink.calls[0], rows[0].RequestID)
	}
	if rows[0].RequiredApprovals != 2 {
		t.Fatalf("stored required approvals = %d; want configured 2", rows[0].RequiredApprovals)
	}
}

func TestSign_RejectsCallerSelectedClientIdentity(t *testing.T) {
	t.Parallel()
	sink := &callCaptureSink{}
	ts, db := signAuditFixture(t, sink)
	body := []byte(`{"client_id":"somebody-else","commands":[{"server":"prod","cmd":"uptime","ttl_seconds":60}]}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sign", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer audit-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched client_id status = %d; want 403", resp.StatusCode)
	}
	rows, err := db.ListPending(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("mismatched identity queued request: rows=%d err=%v", len(rows), err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.calls) != 0 {
		t.Fatalf("mismatched identity emitted audit calls: %+v", sink.calls)
	}
}

func TestSign_AuditFailureLeavesQueueEmpty(t *testing.T) {
	t.Parallel()
	sink := &callCaptureSink{failCall: true}
	ts, db := signAuditFixture(t, sink)
	resp := postAuditedSign(t, ts)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500", resp.StatusCode)
	}
	rows, err := db.ListPending(context.Background())
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("audit failure queued %d requests; want 0", len(rows))
	}
}
