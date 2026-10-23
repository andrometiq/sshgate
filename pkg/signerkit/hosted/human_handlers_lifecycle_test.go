package hosted

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

func lifecycleUI(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB) *Server {
	t.Helper()
	s, ctx, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	s.Human.ordinaryEngine = func() *ApprovalV2Engine { return e }
	alignVoteSession(s, ctx, e.now().Wall)
	s.APIKey = "secret"
	if err := s.AttachApprovals(e); err != nil {
		t.Fatal(err)
	}
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{approvalHTTPSignature}, nil
	})
	return s
}

func lifecycleVote(t *testing.T, s *Server, db *sqlitestore.DB, id int, decision string) {
	t.Helper()
	row := readApproval(t, db, id)
	path := "/ui/v2/request/" + row.RecordHandle
	var token voteChallenge
	if err := json.Unmarshal(listJSON(t, s, path)["vote_challenge"], &token); err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, s, path+"/"+decision, token.Challenge); w.Code != 200 {
		t.Fatalf("vote: %d %s", w.Code, w.Body)
	}
}

func lifecycleClaim(t *testing.T, s *Server, db *sqlitestore.DB, id int) *aw.ClaimAnswer {
	t.Helper()
	token := statetest.Token(statetest.ID(id))
	body := approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, ClaimToken: hex.EncodeToString(token[:]), PlanHash: readApproval(t, db, id).Record.Header.PlanHash})
	response := approvalHTTPResponse(t, aw.KindClaim, approvalHTTPRequest(s, "POST", aw.HostedRoot+"/"+statetest.ID(id)+"/claim", body))
	return response.Claim
}

func TestHumanVoteV2AuditFailureAndFlushRetry(t *testing.T) {
	for _, failOnce := range []bool{false, true} {
		t.Run(map[bool]string{false: "dead-until-flush", true: "g-one-failure"}[failOnce], func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			approvalWorkerSink(e)
			s := lifecycleUI(t, e, db)
			submitApproval(t, e, 1)
			if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
				t.Fatal(err)
			}
			// Drain setup so the failing write belongs to this POST.
			if e.flushPass(context.Background()) {
				t.Fatal("setup flush")
			}
			lists := &approvalLists{ApprovalV2Store: db}
			e.config.Store = lists
			var mintPasses atomic.Int64
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				mintPasses.Store(lists.unflushed.Load())
				return []string{approvalHTTPSignature}, nil
			})
			var writes atomic.Int32
			var recovered atomic.Bool
			attempted := make(chan struct{}, 1)
			e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
				n := writes.Add(1)
				if (!failOnce && !recovered.Load()) || (failOnce && n == 1) {
					select {
					case attempted <- struct{}{}:
					default:
					}
					return errors.New("sink unavailable")
				}
				return nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- e.Run(ctx) }()
			defer func() { cancel(); <-done }()
			lifecycleVote(t, s, db, 1, "approve")
			select {
			case <-attempted:
			case <-time.After(5 * time.Second):
				t.Fatal("POST did not nudge flush")
			}
			if !failOnce {
				if got := lifecycleClaim(t, s, db, 1); got.Status != ap.ClaimNotReady || len(got.Signatures) != 0 {
					t.Fatalf("unflushed claim: %+v", got)
				}
				if !ap.Unflushed(readApproval(t, db, 1).Record) {
					t.Fatal("failed audit marked complete")
				}
				recovered.Store(true)
			}
			if failOnce {
				clock.Advance(time.Second)
				bound := time.Now().Add(5 * time.Second)
				for {
					got := lifecycleClaim(t, s, db, 1)
					if got.Status == ap.ClaimSignatures {
						break
					}
					if got.Status != ap.ClaimNotReady || time.Now().After(bound) {
						t.Fatalf("executor claim retry: %+v", got)
					}
					clock.Advance(time.Second)
				}
				if !clock.Wall().Before(readApproval(t, db, 1).Record.Header.Decision.DecidedAt.Add(60 * time.Second)) {
					t.Fatal("claim missed TTL window")
				}
			}
			deadline := time.Now().Add(5 * time.Second)
			for ap.Unflushed(readApproval(t, db, 1).Record) {
				if time.Now().After(deadline) {
					t.Fatal("outbox did not drain")
				}
				time.Sleep(5 * time.Millisecond)
			}
			pending, err := e.approvalKeys(context.Background(), `SELECT client_id,sub_principal,request_id FROM approvals_v2 WHERE audited_complete=0`)
			if err != nil || len(pending) != 0 {
				t.Fatalf("audit index did not drain: %v %v", pending, err)
			}
			if failOnce && mintPasses.Load() != 2 {
				t.Fatalf("decision flush needed %d selected passes before mint, want 2", mintPasses.Load())
			}
			got := lifecycleClaim(t, s, db, 1)
			if got.Status != ap.ClaimSignatures || !reflect.DeepEqual(got.Signatures, []string{approvalHTTPSignature}) {
				t.Fatalf("flushed claim: %+v", got)
			}
		})
	}
}

func TestHumanVoteV2SynchronousFlush(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	s := lifecycleUI(t, e, db)
	submitApproval(t, e, 1)
	if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runFlusher(ctx) }()
	defer func() { cancel(); <-done }()
	lifecycleVote(t, s, db, 1, "approve")
	if got := lifecycleClaim(t, s, db, 1); got.Status != ap.ClaimSignatures {
		t.Fatalf("tick paused: %+v", got)
	}
}

func TestHumanVoteV2ConcurrentFlush(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.SnapshotBuilder = approvalCachedSnapshot{rules: redactrules.Combined()}
	s := lifecycleUI(t, e, db)
	for id := 1; id <= 50; id++ {
		submitApproval(t, e, id)
		if _, _, err := e.mutate(context.Background(), approvalKey(id), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := map[string]int{}
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		mu.Lock()
		defer mu.Unlock()
		seen[c.Approval.EventKey]++
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer func() { cancel(); <-done }()
	var wg sync.WaitGroup
	for id := 1; id <= 50; id++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); lifecycleVote(t, s, db, id, "approve") }(id)
	}
	wg.Wait()
	deadline := time.Now().Add(30 * time.Second)
	for {
		rows, err := e.approvalKeys(context.Background(), `SELECT client_id,sub_principal,request_id FROM approvals_v2 WHERE audited_complete=0`)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("outboxes did not drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 200 {
		t.Fatalf("events=%d", len(seen))
	}
	for key, n := range seen {
		if n != 1 {
			t.Fatalf("event %s written %d times", key, n)
		}
	}
}

func TestHumanVoteV2BackwardClock(t *testing.T) {
	for _, delta := range []time.Duration{10 * time.Second, time.Hour} {
		t.Run(delta.String(), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			approvalWorkerSink(e)
			s := lifecycleUI(t, e, db)
			submitApproval(t, e, 1)
			if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
				t.Fatal(err)
			}
			clock.StepWall(-delta)
			lifecycleVote(t, s, db, 1, "approve")
			if e.flushPass(context.Background()) {
				t.Fatal("flush")
			}
			if got := lifecycleClaim(t, s, db, 1); got.Status != ap.ClaimSignatures {
				t.Fatalf("claim after clock step: %+v", got)
			}
		})
	}
}

func TestUIV2AssistRestartChallenge(t *testing.T) {
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
	server := NewServer("secret", db, log.New(io.Discard, "", 0))
	if err := server.StartOrdinaryWorkers(e); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 1)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider not started")
	}
	server.Close()
	next, reopened := restartApprovalEngine(t, e, db)
	configureHostedAssist(t, next, hostedAssessorFunc(func(_ context.Context, in assist.Input) (ap.AssistResult, error) {
		calls.Add(1)
		return hostedAssistResult(in), nil
	}))
	s := lifecycleUI(t, next, reopened)
	if err := s.StartOrdinaryWorkers(next); err != nil {
		t.Fatal(err)
	}
	deadline := readApproval(t, reopened, 1).Record.Header.AssistDeadline
	clock.Advance(deadline.Add(time.Second).Sub(clock.Wall()))
	bound := time.Now().Add(5 * time.Second)
	for readApproval(t, reopened, 1).Record.Header.Assist == nil {
		if time.Now().After(bound) {
			t.Fatal("assist deadline did not reconcile")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var token voteChallenge
	path := "/ui/v2/request/" + readApproval(t, reopened, 1).RecordHandle
	if err := json.Unmarshal(listJSON(t, s, path)["vote_challenge"], &token); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(token.AllowedActions, []string{"approve", "deny"}) || calls.Load() != 1 {
		t.Fatalf("actions=%v provider calls=%d", token.AllowedActions, calls.Load())
	}
	lifecycleVote(t, s, reopened, 1, "approve")
}

func TestUIV2AuditBindingAfterShedRestart(t *testing.T) {
	for _, mode := range []string{"ready", "deny-preparing", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, true)
			approvalWorkerSink(e)
			s := lifecycleUI(t, e, db)
			s.Human.Cfg.ApprovalPolicy.DenyVeto = true
			submitApproval(t, e, 1)
			switch mode {
			case "ready":
				result := statetest.Assist(clock.Wall())
				if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Result: &result}, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
			case "unavailable":
				clock.Advance(6 * time.Second)
				if err := e.reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			decision := "approve"
			if mode == "deny-preparing" {
				decision = "deny"
			}
			lifecycleVote(t, s, db, 1, decision)
			var event *ap.AuditMetadata
			var voteEvents []ap.AuditMetadata
			e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
				if c.Approval.Transition == ap.EventDecision {
					copy := *c.Approval
					event = &copy
				}
				if c.Approval.Transition == "vote{operator:operator}" {
					voteEvents = append(voteEvents, *c.Approval)
				}
				return nil
			})
			if e.flushPass(context.Background()) {
				t.Fatal("flush")
			}
			if event == nil || event.Assist == nil || len(voteEvents) != 1 {
				t.Fatal("decision evidence missing")
			}
			before := listJSON(t, s, "/ui/audit")["v2_entries"]
			e.config.AuditSink = signerkit.NewAppendOnlySink(io.Discard)
			clock.Advance(8 * 24 * time.Hour)
			if err := e.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.flushPass(context.Background()) {
				t.Fatal("clock flush")
			}
			if err := e.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			s.Close()
			next, reopened := restartApprovalEngine(t, e, db)
			if !readApproval(t, reopened, 1).Record.Header.Shed {
				t.Fatal("record not shed")
			}
			restarted := lifecycleUI(t, next, reopened)
			after := listJSON(t, restarted, "/ui/audit")["v2_entries"]
			if string(before) != string(after) {
				t.Fatalf("audit changed after shed/restart: %s", after)
			}
			var rows []uiV2AuditEntry
			if err := json.Unmarshal(after, &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].RationaleRedacted != event.RationaleRedacted || rows[0].DecidedBy != event.DecidedBy || rows[0].AssistBound != *event.Assist || len(rows[0].Votes) != 1 || rows[0].Votes[0].Decision != voteEvents[0].Decision || rows[0].Votes[0].Operator != "operator" {
				t.Fatalf("UI differs from flushed evidence: %s", after)
			}
		})
	}
}
