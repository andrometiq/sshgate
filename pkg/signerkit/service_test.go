package signerkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

type recordingAuditSink struct {
	mu       sync.Mutex
	calls    []AuditCall
	verdicts []AuditVerdict
	failCall bool
}

type blockingLifecycleSink struct {
	mu      sync.Mutex
	calls   []AuditCall
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (s *blockingLifecycleSink) Call(_ context.Context, e AuditCall) error {
	s.mu.Lock()
	s.calls = append(s.calls, e)
	s.mu.Unlock()
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return nil
}

func (*blockingLifecycleSink) Verdict(context.Context, AuditVerdict) error { return nil }

func (s *recordingAuditSink) Call(_ context.Context, e AuditCall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failCall {
		return errors.New("lifecycle sink down")
	}
	s.calls = append(s.calls, e)
	return nil
}

func (s *recordingAuditSink) setFailCall(fail bool) {
	s.mu.Lock()
	s.failCall = fail
	s.mu.Unlock()
}

func (s *recordingAuditSink) Verdict(_ context.Context, e AuditVerdict) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verdicts = append(s.verdicts, e)
	return nil
}

// TestService_CustodyLifecycleUsesGenericSink proves New(Config) sends every
// lifecycle transition through a non-*AuditLog sink, including the rotation
// reason and authorizing operator.
func TestService_CustodyLifecycleUsesGenericSink(t *testing.T) {
	t.Parallel()
	priv1, _ := goldenSignerKey()
	priv2, _ := altSignerKey()
	sink := &recordingAuditSink{}
	svc, err := New(Config{Signer: priv1, Audit: sink, NowFunc: goldenNow})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	op := Operator{ID: "op1", DisplayName: "Operator One", Verified: true, AuthnMethod: "webauthn"}
	if err := svc.Lock("incident", op); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := svc.Unlock(op); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := svc.RotateToWithAudit(priv2, "scheduled rollover", op); err != nil {
		t.Fatalf("RotateTo: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.calls) != 3 {
		t.Fatalf("lifecycle calls=%d; want 3: %+v", len(sink.calls), sink.calls)
	}
	wantEvents := []string{"lock", "unlock", "rotate"}
	for i, want := range wantEvents {
		got := sink.calls[i]
		if got.Lifecycle != want {
			t.Errorf("call %d lifecycle=%q; want %q", i, got.Lifecycle, want)
		}
		if got.Operator == nil || *got.Operator != op {
			t.Errorf("call %d operator=%+v; want %+v", i, got.Operator, op)
		}
		if !got.Time.Equal(goldenNow()) {
			t.Errorf("call %d time=%v; want %v", i, got.Time, goldenNow())
		}
	}
	if sink.calls[0].Reason != "incident" || sink.calls[2].Reason != "scheduled rollover" {
		t.Errorf("lifecycle reasons lost: %+v", sink.calls)
	}
	if len(sink.verdicts) != 0 {
		t.Fatalf("custody lifecycle emitted verdicts: %+v", sink.verdicts)
	}
}

func TestService_CustodyLifecycleTransitionsCannotAuditOutOfOrder(t *testing.T) {
	priv, _ := goldenSignerKey()
	sink := &blockingLifecycleSink{entered: make(chan struct{}), release: make(chan struct{})}
	svc, err := New(Config{Signer: priv, Audit: sink, NowFunc: goldenNow})
	if err != nil {
		t.Fatal(err)
	}

	lockDone := make(chan error, 1)
	go func() { lockDone <- svc.Lock("incident", Operator{ID: "locker"}) }()
	<-sink.entered
	if _, err := svc.daemon.signBytes([]byte("during audit")); !errors.Is(err, ErrLocked) {
		t.Fatalf("Lock state not installed before lifecycle audit: %v", err)
	}

	unlockDone := make(chan error, 1)
	go func() { unlockDone <- svc.Unlock(Operator{ID: "unlocker"}) }()
	select {
	case err := <-unlockDone:
		t.Fatalf("Unlock crossed the blocked Lock audit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(sink.release)
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	if err := <-unlockDone; err != nil {
		t.Fatal(err)
	}
	if _, err := svc.daemon.signBytes([]byte("after unlock")); err != nil {
		t.Fatalf("sign after serialized Unlock: %v", err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.calls) != 2 || sink.calls[0].Lifecycle != "lock" || sink.calls[1].Lifecycle != "unlock" {
		t.Fatalf("lifecycle audit order = %+v; want lock then unlock", sink.calls)
	}
}

func TestService_CustodyLifecycleFailuresRemainFailOpen(t *testing.T) {
	t.Parallel()
	priv1, _ := goldenSignerKey()
	priv2, pub2 := altSignerKey()
	sink := &recordingAuditSink{failCall: true}
	svc, err := New(Config{Signer: priv1, Audit: sink, NowFunc: goldenNow})
	if err != nil {
		t.Fatal(err)
	}

	// Local lifecycle audit is best-effort: each transition applies and returns
	// success even while the generic sink is unavailable. Hosted vote audit has
	// the separate fail-closed contract.
	if err := svc.Lock("incident", Operator{ID: "op"}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := svc.daemon.signBytes([]byte("locked")); !errors.Is(err, ErrLocked) {
		t.Fatalf("failed-audit Lock did not apply: %v", err)
	}

	if err := svc.Unlock(Operator{ID: "op"}); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := svc.daemon.signBytes([]byte("unlocked")); err != nil {
		t.Fatalf("failed-audit Unlock did not apply: %v", err)
	}

	if err := svc.RotateToWithAudit(priv2, "rollover", Operator{ID: "op"}); err != nil {
		t.Fatalf("RotateTo: %v", err)
	}
	sig, err := svc.daemon.signBytes([]byte("new key active"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub2, []byte("new key active"), sig) {
		t.Fatal("failed-audit rotation did not apply")
	}
}

// TestService_LocalLifecycleNoDoubleWrite pins the local adapter path: New sets
// both Daemon.Audit and lifecycleSink when Config.Audit is an *AuditLog, but the
// exclusive routing produces one legacy-shaped row, not two.
func TestService_LocalLifecycleNoDoubleWrite(t *testing.T) {
	t.Parallel()
	priv1, _ := goldenSignerKey()
	priv2, _ := altSignerKey()
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := OpenAuditLog(path)
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	svc, err := New(Config{Signer: priv1, Audit: audit, NowFunc: goldenNow})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	op := Operator{ID: "op2", DisplayName: "Operator Two", AuthnMethod: "totp"}
	if err := svc.RotateToWithAudit(priv2, "routine", op); err != nil {
		t.Fatalf("RotateTo: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("lifecycle wrote %d rows; want exactly 1: %s", len(lines), raw)
	}
	var ev AuditEvent
	if err := json.Unmarshal(lines[0], &ev); err != nil {
		t.Fatalf("decode lifecycle row: %v", err)
	}
	if ev.Status != "rotate" || ev.ApprovedBy != op.DisplayName || ev.AuthMode != op.AuthnMethod {
		t.Fatalf("legacy lifecycle row lost metadata: %+v", ev)
	}
	if len(ev.Commands) != 1 || !strings.Contains(ev.Commands[0], "routine") {
		t.Fatalf("legacy lifecycle row lost reason: %+v", ev)
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
	if err := s.Call(context.Background(), AuditCall{Lifecycle: "lock", Reason: "incident", Operator: &Operator{ID: "op"}}); err != nil {
		t.Fatalf("Lifecycle: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), buf.String())
	}
	kinds := []string{"call", "verdict", "lifecycle"}
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
	if bytes.Contains(lines[0], []byte(`"lifecycle"`)) || bytes.Contains(lines[0], []byte(`"operator"`)) {
		t.Errorf("ordinary call serialization gained lifecycle metadata: %s", lines[0])
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

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestAppendOnlySink_RejectsShortWrite(t *testing.T) {
	t.Parallel()
	sink := NewAppendOnlySink(shortWriter{})
	if err := sink.Call(context.Background(), AuditCall{RequestID: "r-short", CommandSHA256: "abc"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write err=%v; want io.ErrShortWrite", err)
	}
}
