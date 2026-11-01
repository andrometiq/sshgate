//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// A minimal copy of tests/hostedproxy/harness_test.go (S:1864): an in-process
// hosted.Server on a file-backed store behind the local daemon socket, built
// from public constructors as test-only imports.

type proxyExchange struct {
	body, answer []byte
	status       int
	held         time.Duration
}

// contendingTransport records every request body and, on the first POST to
// each contended path, holds BEGIN IMMEDIATE on a second connection for the
// whole forwarded request, so that one attempt meets the busy timeout.
type contendingTransport struct {
	next     http.RoundTripper
	database string
	mu       sync.Mutex
	contend  map[string]bool
	seen     map[string][]proxyExchange
}

func (c *contendingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	key := req.Method + " " + req.URL.Path
	c.mu.Lock()
	hold := c.contend[key]
	c.contend[key] = false
	c.mu.Unlock()
	var release func() error
	if hold {
		var err error
		if release, err = holdWriter(c.database); err != nil {
			return nil, err
		}
	}
	start := time.Now()
	resp, err := c.next.RoundTrip(req)
	exchange := proxyExchange{body: body}
	if release != nil {
		exchange.held = time.Since(start)
		if releaseErr := release(); releaseErr != nil && err == nil {
			err = releaseErr
		}
	}
	if resp != nil {
		exchange.status = resp.StatusCode
		answer, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(answer))
		if readErr != nil && err == nil {
			err = readErr
		}
		exchange.answer = answer
	}
	c.mu.Lock()
	c.seen[key] = append(c.seen[key], exchange)
	c.mu.Unlock()
	return resp, err
}

func (c *contendingTransport) exchanges(key string) []proxyExchange {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]proxyExchange(nil), c.seen[key]...)
}

func holdWriter(database string) (func() error, error) {
	db, err := sqlitestore.Open(database)
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		db.Close()
		return nil, err
	}
	return func() error { return errors.Join(tx.Rollback(), db.Close()) }, nil
}

type proxyFreezer struct{}

func (proxyFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, client, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	return ap.FreezeDraft(d, ap.FreezeInputs{RequesterPrincipal: client, RequesterSub: sub, Now: now, Validity: ap.ValidityMin})
}

func (proxyFreezer) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
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

type peerHandler struct {
	service *sk.Service
	uid     uint32
}

func (p peerHandler) HandleSignRequest(ctx context.Context, conn io.ReadWriter) error {
	return p.service.HandleSignRequestWithPeer(ctx, conn, &sk.PeerCredentials{UID: p.uid})
}

type hostedProxy struct {
	t         *testing.T
	db        *sqlitestore.DB
	clock     *elapsedtest.Fake
	server    *hosted.Server
	transport *contendingTransport
	minter    *countingMinter
	session   string
	client    *sign.ApprovalClient
	audit     string
}

const proxyUID = 7

func newHostedProxy(t *testing.T, contend ...string) *hostedProxy {
	t.Helper()
	ctx := context.Background()
	database := filepath.Join(t.TempDir(), "hosted.db")
	h := &hostedProxy{t: t, clock: elapsedtest.NewFake(time.Now().UTC().Truncate(time.Second))}
	var err error
	if h.db, err = sqlitestore.Open(database); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.db.Close() })
	for _, id := range []string{"client", "operator"} {
		if err = h.db.CreateUser(ctx, &store.User{ID: id, Username: id, Role: "operator", CreatedAt: h.clock.Wall()}); err != nil {
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
	quiet := log.New(io.Discard, "", 0)
	engine, err := hosted.NewApprovalV2Engine(hosted.ApprovalV2Config{Store: h.db, Clock: h.clock, Freezer: proxyFreezer{}, SnapshotBuilder: proxyFreezer{}, Minter: h.minter, AuditSink: sk.NewAppendOnlySink(io.Discard), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	h.server = hosted.NewServer("test-key", h.db, quiet)
	h.server.MachineClientID = "client"
	h.server.RequiredApprovals = 1
	if err = h.server.AttachApprovals(engine); err != nil {
		t.Fatal(err)
	}
	auth, err := hosted.NewAuthManager(h.db, hosted.AuthConfig{RPID: "localhost", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.IssueSession(ctx, "operator")
	if err != nil {
		t.Fatal(err)
	}
	h.session = session.ID
	h.server.AttachHuman(&hosted.HumanAPI{Auth: auth, Store: h.db})
	if err = h.server.StartOrdinaryWorkers(engine); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.server.Close() })
	listener := httptest.NewServer(h.server)
	t.Cleanup(listener.Close)
	h.transport = &contendingTransport{next: listener.Client().Transport, database: database, contend: make(map[string]bool), seen: make(map[string][]proxyExchange)}
	for _, key := range contend {
		h.transport.contend[key] = true
	}

	backend := &sk.HostedServerBackend{BaseURL: listener.URL, APIKey: "test-key", ClientID: "client", HTTPClient: &http.Client{Transport: h.transport}}
	h.audit = filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := sk.OpenAuditLog(h.audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
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
	path := filepath.Join(t.TempDir(), "daemon.sock")
	listenCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- (&sk.Server{Path: path, Handler: peerHandler{service, proxyUID}}).Listen(listenCtx) }()
	t.Cleanup(func() { cancel(); <-done; runtime.Close(); service.Close(); audit.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon socket did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	h.client = &sign.ApprovalClient{SocketPath: path}
	return h
}

func (h *hostedProxy) row(id string) (*sqlitestore.V2Row, error) {
	return h.db.ReadV2(context.Background(), sqlitestore.V2Key{ClientID: "client", SubPrincipal: fmt.Sprintf("local-uid:%d", proxyUID), RequestID: id})
}

// approve waits for the record and its assist freeze, then casts the
// operator's vote through the human API.
func (h *hostedProxy) approve(id string) {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var row *sqlitestore.V2Row
	for {
		var err error
		if row, err = h.row(id); err == nil {
			break
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("record did not appear: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.clock.Advance(6 * time.Second)
	for row.Record.Header.Assist == nil {
		if time.Now().After(deadline) {
			h.t.Fatal("assist did not freeze")
		}
		time.Sleep(10 * time.Millisecond)
		var err error
		if row, err = h.row(id); err != nil {
			h.t.Fatal(err)
		}
	}
	path := "/ui/v2/request/" + row.RecordHandle
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
	if detail.Code != http.StatusOK {
		h.t.Fatalf("human detail: %d %s", detail.Code, detail.Body)
	}
	var view struct {
		VoteChallenge struct {
			Challenge string `json:"challenge"`
		} `json:"vote_challenge"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &view); err != nil || view.VoteChallenge.Challenge == "" {
		h.t.Fatalf("vote challenge: %v %s", err, detail.Body)
	}
	body, _ := json.Marshal(map[string]string{"challenge": view.VoteChallenge.Challenge})
	if vote := request("POST", path+"/approve", body); vote.Code != http.StatusOK {
		h.t.Fatalf("human vote: %d %s", vote.Code, vote.Body)
	}
}

func (h *hostedProxy) busyAudits() int {
	h.t.Helper()
	data, err := os.ReadFile(h.audit)
	if err != nil {
		h.t.Fatal(err)
	}
	return bytes.Count(data, []byte(`"transition":"refused{busy}"`))
}

// C-61: the real executor job path (Submit, JobNext, Claim, step, Report)
// through the hosted proxy, with one SQLite busy answer on each signer write.
func TestCommandJobThroughHostedProxyBusy(t *testing.T) {
	id := st.ID(1)
	submit, claim, report := "POST "+aw.HostedRoot, "POST "+aw.HostedRoot+"/"+id+"/claim", "POST "+aw.HostedRoot+"/"+id+"/report"
	h := newHostedProxy(t, submit, claim, report)

	_, jobs, _ := jobStore(t)
	servers, err := registry.New(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256([]byte("server"))
	if err = servers.Add("server", registry.Entry{Host: "203.0.113.10", Port: 22, User: "deploy", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fingerprint[:]), AddedAt: h.clock.Wall()}); err != nil {
		t.Fatal(err)
	}
	s, err := NewService(Config{Store: jobs, Servers: servers, Signer: h.client, Clock: h.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var dispatched []string
	var dispatchMu sync.Mutex
	ssh := commandSSHFunc(func(c context.Context, wire string, guard func() error, out, stderr io.Writer) (int, error) {
		if err := guard(); err != nil {
			return -1, &gatessh.PhasedError{Class: "guard_refused"}
		}
		dispatchMu.Lock()
		dispatched = append(dispatched, wire)
		dispatchMu.Unlock()
		io.WriteString(out, "done")
		return 0, nil
	})
	if err = s.StartCommandJobs(h.client, ssh); err != nil {
		t.Fatal(err)
	}

	in := executorwire.Input{RequestID: id, SubmitNotAfter: h.clock.Wall().Add(time.Hour), Tool: "run", Server: "server", Command: "touch /tmp/job", Reason: "Create the requested file", MaxOutputBytes: 1024}
	submitted := make(chan error, 1)
	go func() {
		response, err := s.SubmitAndNotify(context.Background(), requestWith(t, in))
		if err == nil && (response.Job == nil || response.Job.RequestID != id) {
			err = fmt.Errorf("exec_submit answered %+v", response)
		}
		submitted <- err
	}()
	h.approve(id)

	deadline := time.Now().Add(3 * time.Minute)
	var final ap.R2
	for {
		final = commandJob(t, s, id)
		if commandFinal(final) {
			break
		}
		select {
		case err := <-s.fatal:
			t.Fatal(err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish: %+v", ap.JobView(final, s.epoch))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := <-submitted; err != nil {
		t.Fatalf("exec_submit: %v", err)
	}
	view := ap.JobView(final, s.epoch)
	if final.Outcome != nil || view.Class != ap.ClassSucceeded || final.ReportResult == nil || final.ReportResult.State != ap.ReportAcked {
		t.Fatalf("job ended outcome=%+v class=%s report=%+v; want succeeded with an acked report", final.Outcome, view.Class, final.ReportResult)
	}
	dispatchMu.Lock()
	defer dispatchMu.Unlock()
	if len(dispatched) != 1 {
		t.Fatalf("dispatches = %d; want 1", len(dispatched))
	}

	for _, key := range []string{submit, claim, report} {
		exchanges := h.transport.exchanges(key)
		if len(exchanges) != 2 {
			t.Fatalf("%s: %d hosted requests; want one busy and one resend", key, len(exchanges))
		}
		first, resend := exchanges[0], exchanges[1]
		if first.status != http.StatusServiceUnavailable || first.held < 4*time.Second {
			t.Errorf("%s: first answer %d after %s; want 503 busy past the busy timeout", key, first.status, first.held)
		}
		if resend.status != http.StatusOK {
			t.Errorf("%s: resend answered %d", key, resend.status)
		}
		if !bytes.Equal(first.body, resend.body) {
			t.Errorf("%s: resent body differs:\n%s\n%s", key, first.body, resend.body)
		}
	}
	if n := h.busyAudits(); n != 3 {
		t.Errorf("refused{busy} audit rows = %d; want 3", n)
	}

	summaries, _, err := h.client.List(context.Background(), 10, "")
	if err != nil || len(summaries) != 1 {
		t.Fatalf("hosted records = %+v, %v; want one", summaries, err)
	}
	row, err := h.row(id)
	if err != nil {
		t.Fatal(err)
	}
	// The busy Claim's mint precedes its failed transaction and is discarded
	// (approvals_v2_engine.go claimOnce); the one answered set is the evidence.
	if minted := h.minter.count.Load(); minted < 1 || minted > 2 {
		t.Errorf("mints = %d; want one, plus at most the discarded busy attempt", minted)
	}
	envelope, _ := json.Marshal(dispatched[0])
	if answered := h.transport.exchanges(claim)[1].answer; !bytes.Contains(answered, bytes.Trim(envelope, `"`)) {
		t.Errorf("claim answer %s does not carry the dispatched envelope", answered)
	}
	accepted := row.Record.Header.FinalReport
	if accepted == nil || accepted.Class != ap.ClassSucceeded || len(accepted.Steps) != 1 || accepted.Steps[0].Status != ap.StepSucceeded {
		t.Fatalf("accepted report = %+v; want one succeeded step", accepted)
	}
}
