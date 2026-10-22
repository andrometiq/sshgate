//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

type waiterFreezer struct{}

func (waiterFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, _ string, now time.Time) (ap.ApprovalPlanV1, error) {
	return st.Freeze(d, principal, now, time.Hour), nil
}

type waiterSnapshot struct{}

func (waiterSnapshot) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	return []byte(`{"segments":[]}`), p.Rationale, nil
}

// WaitMany consults Done after installing its published-state registrations.
type registeredWaitContext struct {
	context.Context
	once       sync.Once
	registered func()
}

func (c *registeredWaitContext) Done() <-chan struct{} {
	c.once.Do(c.registered)
	return c.Context.Done()
}

type waiterSocketHandler struct {
	engine  *lifecycle.Engine
	mu      sync.Mutex
	active  int
	peak    int
	entered chan []string
}

func (h *waiterSocketHandler) HandleSignRequest(ctx context.Context, conn io.ReadWriter) error {
	var request approvalwire.WaitRequest
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		return err
	}
	tracked := &registeredWaitContext{Context: ctx, registered: func() {
		h.mu.Lock()
		h.active++
		h.peak = max(h.peak, h.active)
		h.mu.Unlock()
		h.entered <- append([]string(nil), request.RequestIDs...)
	}}
	result, err := h.engine.WaitMany(tracked, st.PrincipalA, request.RequestIDs, time.Duration(request.WaitSeconds)*time.Second)
	h.mu.Lock()
	h.active--
	h.mu.Unlock()
	if err != nil {
		return err
	}
	frame, err := approvalwire.MarshalLocalResponse(approvalwire.KindWait, approvalwire.Response{ApprovalProto: approvalwire.Proto, OK: true, Summaries: result.Summaries})
	if err != nil {
		return err
	}
	_, err = conn.Write(frame)
	return err
}
func (h *waiterSocketHandler) counts() (int, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active, h.peak
}

func TestWaiterRealClientMembershipChurnAndCancellation(t *testing.T) {
	engine, err := lifecycle.New(lifecycle.Config{Store: &lifecycle.MemStore{}, Clock: elapsedtest.NewFake(st.T0), Freezer: waiterFreezer{}, SnapshotBuilder: waiterSnapshot{}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	handler := &waiterSocketHandler{engine: engine, entered: make(chan []string, 64)}
	socket := filepath.Join(t.TempDir(), "signer.sock")
	server := &signerkit.Server{Path: socket, Handler: handler, HandlerTimeout: 2 * time.Minute}
	serverContext, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	var serverErr error
	go func() { defer close(serverDone); serverErr = server.Listen(serverContext) }()
	defer func() { stopServer(); <-serverDone }()
	s, store := waiterService(t, 1, &sign.ApprovalClient{SocketPath: socket})
	defer s.Close()
	first, err := engine.Submit(context.Background(), st.PrincipalA, store.jobs[st.ID(1)].Draft)
	if err != nil {
		t.Fatal(err)
	}
	s.startWaiter()
	select {
	case ids := <-handler.entered:
		if len(ids) != 1 {
			t.Fatal(ids)
		}
	case <-serverDone:
		t.Fatal(serverErr)
	case <-time.After(3 * time.Second):
		t.Fatal("first real WaitMany did not register")
	}
	for id := 2; id <= 21; id++ {
		request := submitRequest(t, id)
		if _, err := s.Submit(request); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		job, err := store.Load(request.Input.RequestID)
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		summary, err := engine.Submit(context.Background(), st.PrincipalA, job.Draft)
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		_, err = s.commitSubmission(job, ap.SignerAck{PlanHash: summary.PlanHash})
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	// A tick after the commits proves the supervisor progressed while A stayed pending.
	drainNudge(s, st.ID(21))
	s.mu.Lock()
	flag := s.jobNudges[st.ID(21)]
	s.mu.Unlock()
	receiveWait(t, flag)
	if active, peak := handler.counts(); active != 1 || peak != 1 {
		t.Fatalf("membership abandoned server waits: active=%d peak=%d", active, peak)
	}
	if _, err := engine.AdminCancel(first.RecordHandle, ap.AdminCancel{PlanHash: first.PlanHash, Admin: st.Operator}); err != nil {
		t.Fatal(err)
	}
	next := receiveWait(t, handler.entered)
	if len(next) != 21 {
		t.Fatal("natural reply did not refresh membership", next)
	}
	s.Close()
	// Local cancellation does not cancel the real server's registered wait.
	if active, peak := handler.counts(); active != 1 || peak != 1 {
		t.Fatalf("server context/overlap: active=%d peak=%d", active, peak)
	}
	stopServer()
	receiveWait(t, serverDone)
	if active, _ := handler.counts(); active != 0 {
		t.Fatal("server shutdown leaked registered waits", active)
	}
}
