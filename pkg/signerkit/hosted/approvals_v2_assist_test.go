package hosted

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"go.uber.org/goleak"
)

type hostedAssessorFunc func(context.Context, assist.Input) (ap.AssistResult, error)

func (f hostedAssessorFunc) Assess(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
	return f(ctx, in)
}

type hostedAssistBuilderFunc func(ap.ApprovalPlanV1) (assist.Input, error)

func (f hostedAssistBuilderFunc) BuildAssistInput(p ap.ApprovalPlanV1) (assist.Input, error) {
	return f(p)
}

func configureHostedAssist(t *testing.T, e *ApprovalV2Engine, assessor assist.Assessor) {
	t.Helper()
	e.config.AssistPool = assist.NewPool(1, assist.Timers{Now: e.config.Clock.Wall})
	e.config.AssistInputBuilder = hostedAssistInputBuilder{}
	e.config.Assessor = assessor
	t.Cleanup(func() { e.assistCancel(); e.config.AssistPool.Close() })
}
func hostedAssistResult(in assist.Input) ap.AssistResult {
	effects := make([]string, len(in.Commands))
	for i := range effects {
		effects[i] = "Runs the requested command."
	}
	return ap.AssistResult{Alignment: ap.AlignmentAligned, Summary: "Runs commands.", Effects: effects, Model: "test", PromptVersion: assist.PromptVersion, GeneratedAt: time.Now().UTC()}
}

func TestApprovalV2AssistOneAttempt(t *testing.T) {
	for _, mode := range []string{"ready", "error", "redaction", "full", "closed"} {
		t.Run(mode, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			var calls atomic.Int32
			configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
				calls.Add(1)
				if mode == "error" {
					return ap.AssistResult{}, context.Canceled
				}
				return hostedAssistResult(in), nil
			}))
			if mode == "redaction" {
				e.config.AssistInputBuilder = hostedAssistBuilderFunc(func(ap.ApprovalPlanV1) (assist.Input, error) { return assist.Input{}, errors.New("redaction failed") })
			}
			if mode == "closed" {
				e.config.AssistPool.Close()
			}
			if mode == "full" {
				e.config.AssistPool.TrySubmit(context.Background(), hostedAssessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
					<-ctx.Done()
					return ap.AssistResult{}, ctx.Err()
				}), assist.Input{}, e.now().Wall.Add(time.Hour), func(assist.Snapshot) {})
			}
			submitApproval(t, e, 1)
			submitApproval(t, e, 1)
			if mode == "closed" {
				if readApproval(t, db, 1).Record.Header.Assist != nil {
					t.Fatal("closed pool committed a slot")
				}
			} else {
				awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
				slot := readApproval(t, db, 1).Record.Header.Assist
				want := map[string]string{"error": assist.ReasonFailed, "redaction": assist.ReasonRedaction, "full": assist.ReasonBusy}[mode]
				if slot.Reason != want || (slot.State == ap.AssistReady) != (mode == "ready") {
					t.Fatalf("slot: %+v", slot)
				}
			}
			wantCalls := int32(0)
			if mode == "ready" || mode == "error" {
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Fatalf("provider calls = %d, want %d", calls.Load(), wantCalls)
			}
		})
	}
}

func TestApprovalV2AssistUncertainSubmitDoesNotDispatch(t *testing.T) {
	for _, lands := range []bool{false, true} {
		t.Run(fmt.Sprint(lands), func(t *testing.T) {
			e, _, _ := approvalEngineFixture(t, false)
			var calls atomic.Int32
			configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
				calls.Add(1)
				return hostedAssistResult(in), nil
			}))
			commit := e.commit
			e.commit = func(tx *sql.Tx) error {
				if lands {
					if err := tx.Commit(); err != nil {
						return err
					}
				}
				return errors.New("lost commit")
			}
			_, err := e.Submit(context.Background(), "client", "", approvalDraft(1))
			requireApprovalCode(t, err, ap.CodeStorageUncertain)
			e.config.AssistPool.Close()
			if calls.Load() != 0 {
				t.Fatal("unconfirmed submit dispatched provider")
			}
			e.commit = commit
		})
	}
}

// Process transport exists outside Server. Its blocking writer is deliberately
// released only after Close has joined every server-owned goroutine.
func TestApprovalV2ServerCloseStrict(t *testing.T) {
	for _, policy := range []bool{false, true} {
		for _, success := range []bool{false, true} {
			t.Run(fmt.Sprintf("policy=%t/provider-success=%t", policy, success), func(t *testing.T) {
				defer goleak.VerifyNone(t)
				e, db, clock := approvalEngineFixture(t, true)
				defer db.Close()
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				sink := newProcessAuditSink(auditWriterFunc(func(p []byte) (int, error) { once.Do(func() { close(entered) }); <-release; return len(p), nil }), false)
				defer func() { close(release); close(sink.requests); <-sink.joined }()
				e.config.AuditSink = sink
				e.config.Logger = log.New(io.Discard, "", 0)
				providerStarted := make(chan struct{})
				var calls atomic.Int32
				configureHostedAssist(t, e, hostedAssessorFunc(func(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
					calls.Add(1)
					close(providerStarted)
					<-ctx.Done()
					if success {
						return hostedAssistResult(in), nil
					}
					return ap.AssistResult{}, ctx.Err()
				}))
				server := NewServer("secret", db, log.New(io.Discard, "", 0))
				defer server.Close()
				if policy {
					attachOrdinaryTestPolicy(t, server)
				}
				if err := server.StartOrdinaryWorkers(e); err != nil {
					t.Fatal(err)
				}
				submitApproval(t, e, 1)
				select {
				case <-providerStarted:
				case <-time.After(time.Second):
					t.Fatal("provider not called")
				}
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("flusher not blocked in production transport")
				}
				closed := make(chan struct{})
				go func() { defer close(closed); _ = server.Close() }()
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("Close did not join with blocked process writer")
				}
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-sink.joined:
					t.Fatal("Server closed the process writer")
				default:
				}
				row := readApproval(t, db, 1)
				if row.Record.Header.Assist != nil {
					t.Fatal("interrupted provider committed assist")
				}
				if row.Record.Header.AuditedThrough != 0 {
					t.Fatal("interrupted flush acknowledged unwritten event")
				}
				if err := server.StartOrdinaryWorkers(e); err == nil {
					t.Fatal("started after Close")
				}
				// A still-running handler may commit after Close until the DB is closed.
				submitApproval(t, e, 2)
				if row := readApproval(t, db, 2); row.Record.Header.Assist != nil || row.Record.Header.Decision != nil {
					t.Fatal("post-cut submit did not stay preparing/pending")
				}
				restarted, reopened := restartApprovalEngine(t, e, db)
				defer reopened.Close()
				// Restart never dispatches the provider, even with a fresh available pool.
				restarted.config.AssistPool = assist.NewPool(1, assist.Timers{Now: clock.Wall})
				defer restarted.config.AssistPool.Close()
				defer restarted.assistCancel()
				clock.Advance(6 * time.Second)
				nextServer := NewServer("secret", reopened, log.New(io.Discard, "", 0))
				defer nextServer.Close()
				if err := nextServer.StartOrdinaryWorkers(restarted); err != nil {
					t.Fatal(err)
				}
				awaitApprovalState(t, func() bool { return readApproval(t, reopened, 2).Record.Header.Assist != nil })
				for _, id := range []int{1, 2} {
					slot := readApproval(t, reopened, id).Record.Header.Assist
					if slot == nil || slot.State != ap.AssistUnavailable || slot.Reason != assist.ReasonDeadline {
						t.Fatalf("restart slot: %+v", slot)
					}
				}
				if calls.Load() != 1 {
					t.Fatalf("provider called %d times", calls.Load())
				}
			})
		}
	}
}

func attachOrdinaryTestPolicy(t *testing.T, server *Server) {
	t.Helper()
	audit := &testPolicyAudit{}
	st := &workerPolicyStore{rosterSignal: make(chan struct{}, 1), recoverySignal: make(chan struct{}, 1)}
	engine, err := NewPolicyEngine(PolicyEngineConfig{AuthorityID: testPolicyAuthority, WorkerID: "ordinary-close-test", Store: st, Core: newTestPolicyCore(t), Audit: audit, Sleep: sleepPolicyContext, Jitter: func(d time.Duration) time.Duration { return d }})
	if err != nil {
		t.Fatal(err)
	}
	lease, archive := testPolicyArchive(t)
	t.Cleanup(func() { archive.Close(); lease.Close() })
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	server.policyRosterWait = time.Millisecond
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: http.NotFoundHandler(), Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.StartPolicyWorkers(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, signal := range []chan struct{}{st.rosterSignal, st.recoverySignal} {
		select {
		case <-signal:
		case <-time.After(time.Second):
			t.Fatal("policy worker did not run")
		}
	}
}

type assistBusyStore struct {
	ApprovalV2Store
	armed     atomic.Bool
	attempts  atomic.Int32
	attempted chan struct{}
	always    bool
}

func (s *assistBusyStore) BeginV2(ctx context.Context) (*sql.Tx, error) {
	if s.armed.Load() {
		n := s.attempts.Add(1)
		if n == 1 {
			close(s.attempted)
		}
		if s.always || n == 1 {
			return nil, approvalBusy(5)
		}
	}
	return s.ApprovalV2Store.BeginV2(ctx)
}
func TestApprovalV2AssistRetriesBusyWithoutProviderReplay(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	st := &assistBusyStore{ApprovalV2Store: db, attempted: make(chan struct{})}
	e.config.Store = st
	var calls atomic.Int32
	configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		st.armed.Store(true)
		return hostedAssistResult(in), nil
	}))
	started := time.Now()
	submitApproval(t, e, 1)
	awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
	if slot := readApproval(t, db, 1).Record.Header.Assist; slot.State != ap.AssistReady {
		t.Fatalf("slot: %+v", slot)
	}
	if st.attempts.Load() != 2 || calls.Load() != 1 || time.Since(started) < 250*time.Millisecond {
		t.Fatalf("attempts=%d calls=%d elapsed=%s", st.attempts.Load(), calls.Load(), time.Since(started))
	}
}
func TestApprovalV2AssistCloseDuringBackoff(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	st := &assistBusyStore{ApprovalV2Store: db, attempted: make(chan struct{}), always: true}
	e.config.Store = st
	configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		st.armed.Store(true)
		return hostedAssistResult(in), nil
	}))
	server := NewServer("secret", db, log.New(io.Discard, "", 0))
	// Keep only the assist callback active, avoiding unrelated worker transactions.
	server.ordinaryEngine = e
	server.ordinaryCancel = func() {}
	server.ordinaryJoined = make(chan struct{})
	close(server.ordinaryJoined)
	defer server.Close()
	submitApproval(t, e, 1)
	select {
	case <-st.attempted:
	case <-time.After(time.Second):
		t.Fatal("no assist attempt")
	}
	started := time.Now()
	server.Close()
	if time.Since(started) > 200*time.Millisecond {
		t.Fatal("Close waited for retry timer")
	}
	if st.attempts.Load() != 1 || readApproval(t, db, 1).Record.Header.Assist != nil {
		t.Fatal("interrupted callback retried or committed")
	}
}
func TestApprovalV2AssistRequestCancellationIndependent(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	release := make(chan struct{})
	configureHostedAssist(t, e, hostedAssessorFunc(func(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
		select {
		case <-release:
			return hostedAssistResult(in), nil
		case <-ctx.Done():
			return ap.AssistResult{}, ctx.Err()
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := e.Submit(ctx, "client", "", approvalDraft(1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	close(release)
	awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
	if readApproval(t, db, 1).Record.Header.Assist.State != ap.AssistReady {
		t.Fatal("request cancellation interrupted provider")
	}
}
func TestApprovalV2AssistLateResultUsesClock(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	release := make(chan struct{})
	configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		<-release
		return hostedAssistResult(in), nil
	}))
	submitApproval(t, e, 1)
	clock.Advance(6 * time.Second)
	close(release)
	e.config.AssistPool.Close()
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	slot := readApproval(t, db, 1).Record.Header.Assist
	if slot == nil || slot.Reason != assist.ReasonDeadline {
		t.Fatalf("slot: %+v", slot)
	}
}
func TestApprovalV2OrdinaryStartAndCloseRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		e, db, _ := approvalEngineFixture(t, false)
		approvalWorkerSink(e)
		s := NewServer("secret", db, log.New(io.Discard, "", 0))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = s.StartOrdinaryWorkers(e) }()
		go func() { defer wg.Done(); _ = s.Close() }()
		wg.Wait()
		s.Close()
		if err := s.StartOrdinaryWorkers(e); err == nil {
			t.Fatal("admission reopened")
		}
	}
}
func TestHostedAssistBuilderRedacts(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	config := e.config
	config.AssistPool = assist.NewPool(1, assist.Timers{Now: clock.Wall})
	defer config.AssistPool.Close()
	assessed := make(chan assist.Input, 1)
	config.Assessor = hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		assessed <- in
		return hostedAssistResult(in), nil
	})
	configured, err := NewApprovalV2Engine(config)
	if err != nil {
		t.Fatal(err)
	}
	defer configured.assistCancel()
	draft := approvalDraft(1)
	draft.Rationale = "Use token ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	if _, err := configured.Submit(context.Background(), "client", "", draft); err != nil {
		t.Fatal(err)
	}
	var in assist.Input
	select {
	case in = <-assessed:
	case <-time.After(time.Second):
		t.Fatal("provider not called")
	}
	if bytes.Contains([]byte(in.Reason), []byte("ghp_abcdefghijklmnopqrstuvwxyz1234567890")) {
		t.Fatal("raw token sent to provider")
	}
	awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
	if readApproval(t, db, 1).Record.Payload.Plan.Rationale != draft.Rationale {
		t.Fatal("redaction mutated immutable plan")
	}
}

func TestApprovalV2AssistCommitUncertainNeverRetries(t *testing.T) {
	for _, lands := range []bool{false, true} {
		t.Run(fmt.Sprint(lands), func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			release := make(chan struct{})
			configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
				<-release
				return hostedAssistResult(in), nil
			}))
			submitApproval(t, e, 1)
			var commits atomic.Int32
			attempted := make(chan struct{})
			e.commit = func(tx *sql.Tx) error {
				commits.Add(1)
				defer close(attempted)
				if lands {
					if err := tx.Commit(); err != nil {
						return err
					}
				}
				return approvalBusy(5)
			}
			close(release)
			select {
			case <-attempted:
			case <-time.After(time.Second):
				t.Fatal("assist commit not attempted")
			}
			// Join the completed callback; COMMIT busy is uncertain, never a retry.
			e.config.AssistPool.Close()
			if commits.Load() != 1 {
				t.Fatal("uncertain assist commit retried")
			}
			if got := readApproval(t, db, 1).Record.Header.Assist; (got != nil) != lands {
				t.Fatalf("slot=%+v lands=%t", got, lands)
			}
		})
	}
}

func TestApprovalV2AssistSQLiteLockPastDeadline(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, true)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		close(started)
		<-release
		return hostedAssistResult(in), nil
	}))
	submitApproval(t, e, 1)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider not started")
	}
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	close(release)
	// The real driver's busy timeout is five seconds. Keep the writer lock for six.
	timer := time.NewTimer(6 * time.Second)
	<-timer.C
	clock.Advance(6 * time.Second)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	server := NewServer("secret", db, log.New(io.Discard, "", 0))
	defer server.Close()
	if err := server.StartOrdinaryWorkers(e); err != nil {
		t.Fatal(err)
	}
	awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
	if slot := readApproval(t, db, 1).Record.Header.Assist; slot.Reason != assist.ReasonDeadline {
		t.Fatalf("late result replaced Clock: %+v", slot)
	}
	if calls.Load() != 1 {
		t.Fatal("provider retried under contention")
	}
}

// Test-only HTTP glue exercises the shutdown boundary without adding v2 routes
// ahead of commit 6. Both handlers have entered before Shutdown stops intake.
func TestApprovalV2SubmitAfterHTTPShutdownCut(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	var calls atomic.Int32
	configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		return hostedAssistResult(in), nil
	}))
	server := NewServer("secret", db, log.New(io.Discard, "", 0))
	if err := server.StartOrdinaryWorkers(e); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	submitApproval(t, e, 1)
	awaitApprovalState(t, func() bool {
		row := readApproval(t, db, 1).Record
		return calls.Load() == 1 && row.Header.Assist != nil && len(row.Header.Outbox) == 0
	})
	release, submitEntered := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			_, err := e.WaitMany(r.Context(), "client", "", []string{approvalKey(1).RequestID}, 55*time.Second)
			if err != nil {
				w.WriteHeader(http.StatusRequestTimeout)
			}
			return
		}
		close(submitEntered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if _, err := e.Submit(r.Context(), "client", "", approvalDraft(2)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer httpServer.Close()
	defer releaseOnce.Do(func() { close(release) })
	waitCtx, cancelWait := context.WithCancel(context.Background())
	defer cancelWait()
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		req, _ := http.NewRequestWithContext(waitCtx, http.MethodGet, httpServer.URL+"/wait", nil)
		res, err := httpServer.Client().Do(req)
		if err == nil {
			res.Body.Close()
		}
	}()
	awaitApprovalState(t, func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.waiters[approvalKey(1)]) == 1 })
	submitDone := make(chan error, 1)
	go func() {
		res, err := httpServer.Client().Get(httpServer.URL + "/submit")
		if err == nil {
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				err = fmt.Errorf("submit status %d", res.StatusCode)
			}
		}
		submitDone <- err
	}()
	select {
	case <-submitEntered:
	case <-time.After(time.Second):
		t.Fatal("submit handler not entered")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := httpServer.Config.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-waitDone:
		t.Fatal("long poll ended before the shutdown cut")
	default:
	}
	server.Close()
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-submitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-cut handler did not commit")
	}
	row := readApproval(t, db, 2)
	if row.Record.Header.Assist != nil || row.Record.Header.Decision != nil {
		t.Fatal("post-cut Submit committed an assist slot or decision")
	}
	cancelWait()
	<-waitDone
	clock.Advance(6 * time.Second)
	next, err := NewApprovalV2Engine(e.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.reconcileStartup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slot := readApproval(t, db, 2).Record.Header.Assist; slot == nil || slot.Reason != assist.ReasonDeadline {
		t.Fatalf("restart slot: %+v", slot)
	}
	if calls.Load() != 1 {
		t.Fatal("post-cut Submit dispatched a provider")
	}
}

func TestApprovalV2CloseJoinsProviderAndConcurrentClosers(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	configureHostedAssist(t, e, hostedAssessorFunc(func(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return hostedAssistResult(in), nil
	}))
	s := NewServer("secret", db, log.New(io.Discard, "", 0))
	defer s.Close()
	defer releaseOnce.Do(func() { close(release) })
	if err := s.StartOrdinaryWorkers(e); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 1)
	<-started
	closed := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() { s.Close(); closed <- struct{}{} }()
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("provider not canceled")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before provider joined")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < 2; i++ {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("Close failed to join")
		}
	}
	if readApproval(t, db, 1).Record.Header.Assist != nil {
		t.Fatal("late success committed during Close")
	}
}

type ordinaryJoinStore struct {
	ApprovalV2Store
	flusher                    bool
	entered, canceled, release chan struct{}
	once                       sync.Once
}

func (s *ordinaryJoinStore) hold(ctx context.Context) {
	s.once.Do(func() { close(s.entered); <-ctx.Done(); close(s.canceled); <-s.release })
}
func (s *ordinaryJoinStore) BeginV2(ctx context.Context) (*sql.Tx, error) {
	if !s.flusher {
		s.hold(ctx)
	}
	return s.ApprovalV2Store.BeginV2(ctx)
}
func (s *ordinaryJoinStore) UnflushedV2(ctx context.Context, limit int) ([]*sqlitestore.V2Row, error) {
	if s.flusher {
		s.hold(ctx)
	}
	return s.ApprovalV2Store.UnflushedV2(ctx, limit)
}
func TestApprovalV2CloseJoinsWorkerAndFlusher(t *testing.T) {
	for _, flusher := range []bool{false, true} {
		t.Run(fmt.Sprintf("flusher=%t", flusher), func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			approvalWorkerSink(e)
			st := &ordinaryJoinStore{ApprovalV2Store: db, flusher: flusher, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
			e.config.Store = st
			s := NewServer("secret", db, log.New(io.Discard, "", 0))
			defer s.Close()
			var once sync.Once
			defer once.Do(func() { close(st.release) })
			if err := s.StartOrdinaryWorkers(e); err != nil {
				t.Fatal(err)
			}
			select {
			case <-st.entered:
			case <-time.After(time.Second):
				t.Fatal("worker not entered")
			}
			closed := make(chan struct{})
			go func() { defer close(closed); s.Close() }()
			select {
			case <-st.canceled:
			case <-time.After(time.Second):
				t.Fatal("worker not canceled")
			}
			select {
			case <-closed:
				t.Fatal("Close returned before worker joined")
			case <-time.After(50 * time.Millisecond):
			}
			once.Do(func() { close(st.release) })
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("worker failed to join")
			}
		})
	}
}

func TestApprovalV2AssistReplayWhileProviderInFlight(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int32
	configureHostedAssist(t, e, hostedAssessorFunc(func(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return hostedAssistResult(in), nil
		case <-ctx.Done():
			return ap.AssistResult{}, ctx.Err()
		}
	}))
	submitApproval(t, e, 1)
	<-entered
	submitApproval(t, e, 1)
	if slot := readApproval(t, db, 1).Record.Header.Assist; slot != nil {
		t.Fatalf("replay started a second attempt: %+v", slot)
	}
	once.Do(func() { close(release) })
	awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
	if slot := readApproval(t, db, 1).Record.Header.Assist; slot.State != ap.AssistReady || calls.Load() != 1 {
		t.Fatalf("slot=%+v calls=%d", slot, calls.Load())
	}
}

type fullAssistJoinStore struct {
	*ordinaryJoinStore
	armed atomic.Bool
}

func (s *fullAssistJoinStore) BeginV2(ctx context.Context) (*sql.Tx, error) {
	if s.armed.Load() {
		s.hold(ctx)
	}
	return s.ApprovalV2Store.BeginV2(ctx)
}
func TestApprovalV2CloseJoinsFullPoolCompletion(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	configureHostedAssist(t, e, nil)
	e.config.AssistPool.TrySubmit(context.Background(), hostedAssessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
		<-ctx.Done()
		return ap.AssistResult{}, ctx.Err()
	}), assist.Input{}, e.now().Wall.Add(time.Hour), func(assist.Snapshot) {})
	st := &fullAssistJoinStore{ordinaryJoinStore: &ordinaryJoinStore{ApprovalV2Store: db, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}}
	e.config.Store = st
	e.config.AssistInputBuilder = hostedAssistBuilderFunc(func(p ap.ApprovalPlanV1) (assist.Input, error) {
		st.armed.Store(true)
		return (hostedAssistInputBuilder{}).BuildAssistInput(p)
	})
	s := NewServer("secret", db, log.New(io.Discard, "", 0))
	// Isolate the handler's completion from the separately tested worker loop.
	s.ordinaryEngine = e
	s.ordinaryCancel = func() {}
	s.ordinaryJoined = make(chan struct{})
	close(s.ordinaryJoined)
	defer s.Close()
	var once sync.Once
	defer once.Do(func() { close(st.release) })
	submitted := make(chan error, 1)
	go func() { _, err := e.Submit(context.Background(), "client", "", approvalDraft(1)); submitted <- err }()
	select {
	case <-st.entered:
	case <-time.After(time.Second):
		t.Fatal("full-pool completion did not enter commit")
	}
	closed := make(chan struct{})
	go func() { defer close(closed); s.Close() }()
	select {
	case <-st.canceled:
	case <-time.After(time.Second):
		t.Fatal("full-pool completion not canceled")
	}
	select {
	case <-closed:
		t.Fatal("Close did not join full-pool completion")
	case <-time.After(50 * time.Millisecond):
	}
	once.Do(func() { close(st.release) })
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish")
	}
	if err := <-submitted; err != nil {
		t.Fatal(err)
	}
	if readApproval(t, db, 1).Record.Header.Assist != nil {
		t.Fatal("interrupted full-pool completion committed a slot")
	}
}

func TestApprovalV2CloseJoinsHeldPolicyWorkerForEveryCaller(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s := NewServer("secret", db, log.New(io.Discard, "", 0))
	defer s.Close()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	audit := &testPolicyAudit{}
	st := &workerPolicyStore{rosterSignal: make(chan struct{}, 1), recoverySignal: make(chan struct{}, 1)}
	engine, err := NewPolicyEngine(PolicyEngineConfig{
		AuthorityID: testPolicyAuthority, WorkerID: "held-policy-worker", Store: st,
		Core: newTestPolicyCore(t), Audit: audit,
		Sleep: func(ctx context.Context, _ time.Duration) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, archive := testPolicyArchive(t)
	t.Cleanup(func() { archive.Close(); lease.Close() })
	s.MachineClientID, s.Human = "machine", &HumanAPI{}
	if err := s.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: http.NotFoundHandler(), Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.StartPolicyWorkers(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("policy recovery worker did not enter")
	}
	closed := make(chan struct{}, 2)
	go func() { s.Close(); closed <- struct{}{} }()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("policy worker not canceled")
	}
	go func() { s.Close(); closed <- struct{}{} }()
	select {
	case <-closed:
		t.Fatal("Close returned before held policy worker joined")
	case <-time.After(50 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	for i := 0; i < 2; i++ {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not join")
		}
	}
	if err := s.StartPolicyWorkers(context.Background()); err == nil {
		t.Fatal("policy admission reopened")
	}
}

type assistStartupStore struct {
	ApprovalV2Store
	reconciled chan struct{}
	once       sync.Once
}

func (s *assistStartupStore) DueV2(ctx context.Context, now time.Time, limit int) ([]*sqlitestore.V2Row, error) {
	rows, err := s.ApprovalV2Store.DueV2(ctx, now, limit)
	s.once.Do(func() { close(s.reconciled) })
	return rows, err
}

func TestApprovalV2AssistRestartBeforeDeadline(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, true)
	approvalWorkerSink(e)
	started := make(chan struct{})
	var calls atomic.Int32
	configureHostedAssist(t, e, hostedAssessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return ap.AssistResult{}, ctx.Err()
	}))
	s := NewServer("secret", db, log.New(io.Discard, "", 0))
	defer s.Close()
	if err := s.StartOrdinaryWorkers(e); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 1)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider not started")
	}
	s.Close()
	next, reopened := restartApprovalEngine(t, e, db)
	configureHostedAssist(t, next, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		return hostedAssistResult(in), nil
	}))
	st := &assistStartupStore{ApprovalV2Store: reopened, reconciled: make(chan struct{})}
	next.config.Store = st
	restarted := NewServer("secret", reopened, log.New(io.Discard, "", 0))
	defer restarted.Close()
	if err := restarted.StartOrdinaryWorkers(next); err != nil {
		t.Fatal(err)
	}
	select {
	case <-st.reconciled:
	case <-time.After(time.Second):
		t.Fatal("restart startup did not complete")
	}
	// Leave time for an erroneous asynchronous redispatch while its deadline is live.
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 1 || readApproval(t, reopened, 1).Record.Header.Assist != nil {
		t.Fatal("restart dispatched provider or filled assist before deadline")
	}
	clock.Advance(5 * time.Second)
	bound := time.Now().Add(time.Second)
	for readApproval(t, reopened, 1).Record.Header.Assist == nil {
		if time.Now().After(bound) {
			t.Fatal("Clock missed assist_deadline + 1 second")
		}
		time.Sleep(time.Millisecond)
	}
	if time.Now().After(bound) {
		t.Fatal("Clock missed assist_deadline + 1 second")
	}
	view, err := next.Get(context.Background(), approvalKey(1))
	if err != nil || view.AssistRevision != 1 {
		t.Fatalf("restart view=%+v error=%v", view, err)
	}
	slot := readApproval(t, reopened, 1).Record.Header.Assist
	if slot.State != ap.AssistUnavailable || slot.Reason != assist.ReasonDeadline || calls.Load() != 1 {
		t.Fatalf("slot=%+v provider calls=%d", slot, calls.Load())
	}
}

func TestApprovalV2AssistBusyRetriesStopAtDeadline(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	st := &assistBusyStore{ApprovalV2Store: db, attempted: make(chan struct{}), always: true}
	e.config.Store = st
	var calls atomic.Int32
	configureHostedAssist(t, e, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		st.armed.Store(true)
		return hostedAssistResult(in), nil
	}))
	submitApproval(t, e, 1)
	select {
	case <-st.attempted:
	case <-time.After(time.Second):
		t.Fatal("assist BEGIN not attempted")
	}
	clock.Advance(6 * time.Second)
	// Admission is the public proof that the completion callback exited. No Close
	// or cancellation occurs until cleanup, and BEGIN remains busy throughout.
	completed := make(chan struct{})
	bound := time.Now().Add(time.Second)
	for {
		result := e.config.AssistPool.TrySubmit(context.Background(), nil, assist.Input{}, clock.Wall().Add(time.Second), func(assist.Snapshot) { close(completed) })
		if result == assist.Accepted {
			break
		}
		if result != assist.Full || time.Now().After(bound) {
			t.Fatal("deadline did not return pool capacity")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("replacement job did not complete")
	}
	attempts := st.attempts.Load()
	time.Sleep(300 * time.Millisecond)
	if st.attempts.Load() != attempts || calls.Load() != 1 || readApproval(t, db, 1).Record.Header.Assist != nil {
		t.Fatalf("retry did not stop without Close: attempts=%d then=%d calls=%d", attempts, st.attempts.Load(), calls.Load())
	}
}
