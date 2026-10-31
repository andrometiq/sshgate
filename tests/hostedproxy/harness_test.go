package hostedproxy_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	sk "github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// This file is the reference harness for A13b and C2: all components are built
// through public constructors, and all hosted dependencies are test-only.
type recordingTransport struct {
	next   http.RoundTripper
	mu     sync.Mutex
	bodies map[string][][]byte
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.mu.Lock()
	r.bodies[req.Method+" "+req.URL.Path] = append(r.bodies[req.Method+" "+req.URL.Path], bytes.Clone(body))
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}
func (r *recordingTransport) recorded(path string) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.bodies[path]...)
}

type proxyFreezer struct{}

func (proxyFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, client, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	return ap.FreezeDraft(d, ap.FreezeInputs{RequesterPrincipal: client, RequesterSub: sub, Now: now, Validity: ap.ValidityMin})
}

type proxySnapshot struct{}

func (proxySnapshot) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	snapshot, err := hosted.BuildApprovalSnapshot(p)
	if err != nil {
		return nil, "", err
	}
	view, err := approvalreview.BuildView(snapshot, approvalreview.Assist{State: ap.AssistPreparing})
	if err != nil {
		return nil, "", err
	}
	body, err := snapshot.Encode()
	return body, view.Reason, err
}

type countingMinter struct {
	lifecycle.Minter
	count atomic.Int32
}

func (m *countingMinter) Mint(ctx context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	m.count.Add(1)
	return m.Minter.Mint(ctx, p, at)
}

type proxyHarness struct {
	t         *testing.T
	db        *sqlitestore.DB
	database  string
	clock     *elapsedtest.Fake
	server    *hosted.Server
	http      *httptest.Server
	transport *recordingTransport
	minter    *countingMinter
	session   string
}

func newProxyHarness(t *testing.T) *proxyHarness { return newHarness(t, true) }

func newHarness(t *testing.T, sockets bool) *proxyHarness {
	t.Helper()
	h := &proxyHarness{t: t, database: filepath.Join(t.TempDir(), "hosted.db"), clock: elapsedtest.NewFake(time.Now().UTC().Truncate(time.Second))}
	var err error
	h.db, err = sqlitestore.Open(h.database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.db.Close() })
	for _, id := range []string{"client", "operator"} {
		if err = h.db.CreateUser(context.Background(), &store.User{ID: id, Username: id, Role: "operator", CreatedAt: h.clock.Wall()}); err != nil {
			t.Fatal(err)
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := sk.New(sk.Config{Signer: key, Audit: sk.NewAppendOnlySink(io.Discard)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	h.minter = &countingMinter{Minter: core.ApprovalMinter()}
	engine, err := hosted.NewApprovalV2Engine(hosted.ApprovalV2Config{Store: h.db, Clock: h.clock, Freezer: proxyFreezer{}, SnapshotBuilder: proxySnapshot{}, Minter: h.minter, AuditSink: sk.NewAppendOnlySink(io.Discard), Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	h.server = hosted.NewServer("test-key", h.db, log.New(io.Discard, "", 0))
	h.server.MachineClientID = "client"
	h.server.RequiredApprovals = 1
	if err = h.server.AttachApprovals(engine); err != nil {
		t.Fatal(err)
	}
	auth, err := hosted.NewAuthManager(h.db, hosted.AuthConfig{RPID: "localhost", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.IssueSession(context.Background(), "operator")
	if err != nil {
		t.Fatal(err)
	}
	h.session = session.ID
	h.server.AttachHuman(&hosted.HumanAPI{Auth: auth, Store: h.db})
	if err = h.server.StartOrdinaryWorkers(engine); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.server.Close() })
	var transport http.RoundTripper = handlerTransport{h.server}
	if sockets {
		h.http = httptest.NewServer(h.server)
		t.Cleanup(h.http.Close)
		transport = h.http.Client().Transport
	} else {
		h.http = &httptest.Server{URL: "https://signer.example"}
	}
	h.transport = &recordingTransport{next: transport, bodies: make(map[string][][]byte)}
	return h
}
func (h *proxyHarness) draft(n int) ap.ApprovalDraft {
	d := statetest.JobDraft(statetest.ID(n), ap.CoordinatorExecutor, h.clock.Wall(), statetest.Write("true", 60))
	for i := range d.CommandJob.Steps {
		s := &d.CommandJob.Steps[i]
		hash := sha256.Sum256([]byte(s.Target.ServerAlias))
		s.Target.TrustedHostFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
		s.RegistryEntryDigest = s.Target.Digest()
	}
	return d
}
func (h *proxyHarness) row(uid uint32, id string) *sqlitestore.V2Row {
	h.t.Helper()
	r, err := h.db.ReadV2(context.Background(), sqlitestore.V2Key{ClientID: "client", SubPrincipal: fmt.Sprintf("local-uid:%d", uid), RequestID: id})
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

// The public peer-aware handler is the injection boundary; each listener has
// its own immutable uid, so simultaneous callers cannot race a global hook.
type injectedPeer struct {
	service *sk.Service
	uid     uint32
	drop    atomic.Bool
	// inflight counts running handlers; a Cond (not a WaitGroup) lets a new
	// connection start while auditRows is waiting without a WaitGroup reuse race.
	mu       sync.Mutex
	idle     *sync.Cond
	inflight int
}

func (p *injectedPeer) begin() {
	p.mu.Lock()
	p.inflight++
	p.mu.Unlock()
}

func (p *injectedPeer) end() {
	p.mu.Lock()
	p.inflight--
	if p.inflight == 0 && p.idle != nil {
		p.idle.Broadcast()
	}
	p.mu.Unlock()
}

// waitIdle blocks until no handler is running.
func (p *injectedPeer) waitIdle() {
	p.mu.Lock()
	if p.idle == nil {
		p.idle = sync.NewCond(&p.mu)
	}
	for p.inflight > 0 {
		p.idle.Wait()
	}
	p.mu.Unlock()
}

func (p *injectedPeer) HandleSignRequest(ctx context.Context, conn io.ReadWriter) error {
	p.begin()
	defer p.end()
	if p.drop.Swap(false) {
		return p.service.HandleSignRequestWithPeer(ctx, discardResponse{Reader: conn}, &sk.PeerCredentials{UID: p.uid})
	}
	return p.service.HandleSignRequestWithPeer(ctx, conn, &sk.PeerCredentials{UID: p.uid})
}

type discardResponse struct{ io.Reader }

func (discardResponse) Write(p []byte) (int, error) { return len(p), nil }

type proxySocket struct {
	client *sign.ApprovalClient
	peer   *injectedPeer
	audit  string
	close  func()
}

func (h *proxyHarness) direct(uid uint32) *proxySocket {
	h.t.Helper()
	t := h.t
	backend := &sk.HostedServerBackend{BaseURL: h.http.URL, APIKey: "test-key", ClientID: "client", HTTPClient: &http.Client{Transport: h.transport}}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := sk.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := sk.New(sk.Config{Signer: key, Backend: backend, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := sk.NewApprovalRuntime(sk.ApprovalRuntimeConfig{Forwarder: backend})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.AttachApprovals(runtime); err != nil {
		t.Fatal(err)
	}
	peer := &injectedPeer{service: service, uid: uid}
	closeDirect := func() { runtime.Close(); service.Close(); audit.Close() }
	t.Cleanup(closeDirect)
	return &proxySocket{peer: peer, audit: auditPath, close: closeDirect}
}
func (h *proxyHarness) socket(uid uint32) *proxySocket { return h.socketAs(uid, nil) }

func (h *proxyHarness) socketAs(uid uint32, shared *proxySocket) *proxySocket {
	h.t.Helper()
	t := h.t
	var p *proxySocket
	if shared == nil {
		p = h.direct(uid)
	} else {
		p = &proxySocket{peer: &injectedPeer{service: shared.peer.service, uid: uid}, audit: shared.audit, close: func() {}}
	}
	peer := p.peer
	closeDirect := p.close
	path := filepath.Join(t.TempDir(), "daemon.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var listenErr error
	go func() { listenErr = (&sk.Server{Path: path, Handler: peer}).Listen(ctx); close(done) }()
	var once sync.Once
	closeSocket := func() { once.Do(func() { cancel(); <-done; closeDirect() }) }
	t.Cleanup(closeSocket)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	ready := false
	for !ready {
		select {
		case <-done:
			t.Fatalf("daemon listen: %v", listenErr)
		case <-deadline.C:
			t.Fatal("daemon socket did not become ready")
		case <-ticker.C:
			info, err := os.Stat(path)
			ready = err == nil && info.Mode()&os.ModeSocket != 0
		}
	}
	return &proxySocket{client: &sign.ApprovalClient{SocketPath: path}, peer: peer, audit: p.audit, close: closeSocket}
}
func (p *proxySocket) auditRows(t *testing.T) []json.RawMessage {
	t.Helper()
	p.peer.waitIdle()
	data, err := os.ReadFile(p.audit)
	if err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) > 0 {
			rows = append(rows, bytes.Clone(line))
		}
	}
	return rows
}
func (h *proxyHarness) approve(uid uint32, id string) {
	h.t.Helper()
	h.clock.Advance(6 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for {
		row := h.row(uid, id)
		if row.Record.Header.Assist != nil {
			break
		}
		if time.Now().After(deadline) {
			h.t.Fatal("assist did not freeze")
		}
		time.Sleep(10 * time.Millisecond)
	}
	path := "/ui/v2/request/" + h.row(uid, id).RecordHandle
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Origin", "https://localhost")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: hosted.SessionCookieName, Value: h.session})
		w := httptest.NewRecorder()
		h.server.ServeHTTP(w, r)
		return w
	}
	detail := request("GET", path, nil)
	if detail.Code != 200 {
		h.t.Fatalf("human detail: %d %s", detail.Code, detail.Body)
	}
	var view struct {
		VoteChallenge struct {
			Challenge string `json:"challenge"`
		} `json:"vote_challenge"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &view); err != nil {
		h.t.Fatal(err)
	}
	if view.VoteChallenge.Challenge == "" {
		h.t.Fatal("missing vote challenge")
	}
	body, _ := json.Marshal(map[string]string{"challenge": view.VoteChallenge.Challenge})
	vote := request("POST", path+"/approve", body)
	if vote.Code != 200 {
		h.t.Fatalf("human vote: %d %s", vote.Code, vote.Body)
	}
}
func (h *proxyHarness) holdWriter() func() {
	h.t.Helper()
	db, err := sqlitestore.Open(h.database)
	if err != nil {
		h.t.Fatal(err)
	}
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		db.Close()
		h.t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			if err := tx.Rollback(); err != nil {
				h.t.Error(err)
			}
			db.Close()
		})
	}
	h.t.Cleanup(release)
	return release
}
func successfulReport() aw.Report {
	states := []ap.StepStatus{ap.StepSucceeded}
	return aw.Report{ReportSequence: 1, Steps: []ap.StepReport{{Ordinal: 1, Status: ap.StepSucceeded}}, Class: ap.AggregateJobClass(states), ExecutedOrdinals: ap.ExecutedOrdinals(states), ResultDigest: fmt.Sprintf("%064x", 1)}
}

// handlerTransport exercises the same HTTP handlers without opening a listener.
type handlerTransport struct{ handler http.Handler }

func (r handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, req)
	return w.Result(), nil
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
