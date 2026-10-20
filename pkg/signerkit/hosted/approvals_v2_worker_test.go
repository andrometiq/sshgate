package hosted

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

type approvalSinkFunc func(context.Context, signerkit.AuditCall) error

func (f approvalSinkFunc) Call(ctx context.Context, c signerkit.AuditCall) error { return f(ctx, c) }
func (f approvalSinkFunc) Verdict(context.Context, signerkit.AuditVerdict) error {
	return errors.New("v2 must not write Verdict")
}

func approvalDeny(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB, id int) {
	t.Helper()
	r := readApproval(t, db, id).Record
	_, err := e.Vote(context.Background(), approvalKey(id), ap.CastVote{Operator: "operator", Decision: ap.VoteDeny, Authn: "webauthn", Flags: ap.VoteFlags{DenyVeto: true}, Hosted: &ap.HostedTap{PlanHash: r.Header.PlanHash, Actions: ap.ActionsAt(0)}})
	if err != nil {
		t.Fatal(err)
	}
}
func approvalWorkerSink(e *ApprovalV2Engine) {
	e.config.AuditSink = signerkit.NewAppendOnlySink(io.Discard)
	e.config.Logger = log.New(io.Discard, "", 0)
}

func approvalUnflushedReady(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB) ap.Claim {
	t.Helper()
	submitApproval(t, e, 1)
	if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	approvalVote(t, e, db, "operator", ap.VoteApprove, ap.VoteFlags{})
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{"signature"}, nil
	})
	return ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: readApproval(t, db, 1).Record.Header.PlanHash}
}

func TestApprovalV2MintTransientNeverCommits(t *testing.T) {
	for _, mode := range []string{"canceled", "deadline", "unavailable", "cancel-success"} {
		t.Run(mode, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			claim := approvalReady(t, e, db)
			before := readApproval(t, db, 1).RecordJSON
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				switch mode {
				case "canceled":
					cancel()
					return nil, ctx.Err()
				case "deadline":
					return nil, context.DeadlineExceeded
				case "cancel-success":
					cancel()
					return []string{"signature"}, nil
				default:
					return nil, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
				}
			})
			_, err := e.Claim(ctx, approvalKey(1), claim)
			code := ap.CodeStorageUncertain
			if mode == "unavailable" {
				code = ap.CodeLifecycleUnavailable
			}
			requireApprovalCode(t, err, code)
			if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
				t.Fatal("transient mint changed record")
			}
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				return []string{"retry-signature"}, nil
			})
			a, err := e.Claim(context.Background(), approvalKey(1), claim)
			if err != nil || a.Claim != ap.ClaimSignatures {
				t.Fatalf("retry: %+v %v", a, err)
			}
		})
	}
}

func TestApprovalV2ClaimContextCodes(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			submitApproval(t, e, 1)
			approvalDeny(t, e, db, 1)
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			_, err := e.Claim(ctx, approvalKey(1), ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: readApproval(t, db, 1).Record.Header.PlanHash})
			requireApprovalCode(t, err, ap.CodeStorageUncertain)
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) {
				t.Fatalf("context cause lost: %v", err)
			}
		})
	}
}

type approvalLists struct {
	ApprovalV2Store
	due, unflushed atomic.Int64
}

func (s *approvalLists) DueV2(ctx context.Context, now time.Time, n int) ([]*sqlitestore.V2Row, error) {
	rows, err := s.ApprovalV2Store.DueV2(ctx, now, n)
	s.due.Add(int64(len(rows)))
	return rows, err
}
func (s *approvalLists) UnflushedV2(ctx context.Context, n int) ([]*sqlitestore.V2Row, error) {
	rows, err := s.ApprovalV2Store.UnflushedV2(ctx, n)
	s.unflushed.Add(int64(len(rows)))
	return rows, err
}

func TestApprovalV2FlushRetryWithoutMutation(t *testing.T) {
	for _, recoverAt := range []time.Duration{time.Second, 50 * time.Second} {
		t.Run(recoverAt.String(), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			claim := approvalUnflushedReady(t, e, db)
			counting := &approvalLists{ApprovalV2Store: db}
			e.config.Store = counting
			approvalWorkerSink(e)
			attempts := 0
			decisions := 0
			e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
				attempts++
				if clock.Elapsed() < recoverAt {
					return errors.New("sink unavailable")
				}
				if c.Approval.Transition == ap.EventDecision {
					decisions++
				}
				return nil
			})
			for second := time.Duration(0); second <= recoverAt; second += time.Second {
				if err := e.reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
				failed := e.flushPass(context.Background())
				if (second < recoverAt) != failed {
					t.Fatalf("failed at %s: %v", second, failed)
				}
				if second < recoverAt {
					clock.Advance(time.Second)
				}
			}
			if attempts != int(recoverAt/time.Second)+4 || decisions != 1 || counting.due.Load() != 0 {
				t.Fatalf("retry attempts=%d decisions=%d due=%d", attempts, decisions, counting.due.Load())
			}
			before := counting.unflushed.Load()
			if e.flushPass(context.Background()) {
				t.Fatal("drained pass failed")
			}
			if counting.unflushed.Load() != before {
				t.Fatal("drained row selected")
			}
			a, err := e.Claim(context.Background(), approvalKey(1), claim)
			if err != nil || a.Claim != ap.ClaimSignatures {
				t.Fatalf("claim before window end: %+v %v", a, err)
			}
		})
	}
}

func TestApprovalV2WorkerDeadlineIndependentOfDeadSink(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalReady(t, e, db)
	approvalWorkerSink(e)
	// More than one flush batch, all unaudited, must not crowd out the due index.
	for id := 2; id <= 301; id++ {
		if _, err := e.Submit(context.Background(), fmt.Sprintf("client-%d", id), "", approvalDraft(id)); err != nil {
			t.Fatal(err)
		}
		key := sqlitestore.V2Key{ClientID: fmt.Sprintf("client-%d", id), RequestID: statetest.ID(id)}
		if _, _, err := e.mutate(context.Background(), key, ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
	}
	attempts := 0
	e.config.AuditSink = approvalSinkFunc(func(context.Context, signerkit.AuditCall) error { attempts++; return errors.New("dead") })
	clock.Advance(61 * time.Second)
	// Only the claim end is due; unflushed rows have their own independent list.
	for pass := 0; pass < 1; pass++ {
		if err := e.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !e.flushPass(context.Background()) {
			t.Fatal("dead sink succeeded")
		}
	}
	r := readApproval(t, db, 1).Record
	if r.Header.Mint == nil || r.Header.Mint.Reason != "window_closed" || attempts != 1 {
		t.Fatalf("clock starved: mint=%+v writes=%d", r.Header.Mint, attempts)
	}
}

func TestApprovalV2OneFlusherConcurrentVotes(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.SnapshotBuilder = approvalCachedSnapshot{rules: redactrules.Combined()}
	for id := 1; id <= 50; id++ {
		submitApproval(t, e, id)
		if _, _, err := e.mutate(context.Background(), approvalKey(id), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := map[string]int{}
	duplicates := 0
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		mu.Lock()
		defer mu.Unlock()
		seen[c.Approval.EventKey]++
		if seen[c.Approval.EventKey] > 1 {
			duplicates++
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer func() { cancel(); <-done }()
	var wg sync.WaitGroup
	for id := 1; id <= 50; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := readApproval(t, db, id).Record
			_, err := e.Vote(context.Background(), approvalKey(id), ap.CastVote{Operator: "operator", Decision: ap.VoteApprove, Authn: "webauthn", Hosted: &ap.HostedTap{PlanHash: r.Header.PlanHash, Revision: 1, Digest: r.Header.Assist.Digest, Actions: ap.ActionsAt(1)}})
			if err != nil {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	deadline := time.Now().Add(30 * time.Second)
	for {
		// Poll the index without decoding the backlog on this single-connection fixture.
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
	if duplicates != 0 || len(seen) != 200 {
		t.Fatalf("duplicates=%d events=%d", duplicates, len(seen))
	}
}

func TestApprovalV2SinkOutsideTransactionAndJoined(t *testing.T) {
	e, _, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	submitApproval(t, e, 1)
	entered := make(chan struct{})
	var once sync.Once
	e.config.AuditSink = approvalSinkFunc(func(ctx context.Context, _ signerkit.AuditCall) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer cancel()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sink not entered")
	}
	writeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := e.Submit(writeCtx, "client", "", approvalDraft(2)); err != nil {
		t.Fatalf("sink held SQLite lock: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not join flusher")
	}
}

func TestApprovalV2LifecycleAuditLines(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	var output bytes.Buffer
	e.config.AuditSink = signerkit.NewAppendOnlySink(&output)
	approvalUnflushedReady(t, e, db)
	// Use actual replay/refusal transitions, retaining the decided row.
	approvalVote(t, e, db, "operator", ap.VoteApprove, ap.VoteFlags{})
	approvalVote(t, e, db, "another", ap.VoteApprove, ap.VoteFlags{})
	if e.flushPass(context.Background()) {
		t.Fatal("flush failed")
	}
	text := output.String()
	if strings.Contains(text, `"kind":"verdict"`) || !strings.Contains(text, "approval-vote_replay") || !strings.Contains(text, "approval-vote_refused") || strings.Count(text, `"kind":"lifecycle"`) != 6 || !strings.Contains(text, "approval-decision") {
		t.Fatalf("audit lines: %s", text)
	}
}

func TestApprovalV2WorkerRetentionAndHorizon(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	claim := approvalReady(t, e, db)
	if _, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(context.Background()) {
		t.Fatal("flush")
	}
	clock.Advance(61 * time.Second)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := readApproval(t, db, 1)
	if r.Class != ap.ClassAwaitingReport || len(r.Record.Payload.Signatures) != 0 {
		t.Fatalf("window: %+v", r)
	}
	if e.flushPass(context.Background()) {
		t.Fatal("erase flush")
	}
	before := readApproval(t, db, 1).RecordJSON
	clock.Advance(e.config.Settings.ReportHorizon)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = readApproval(t, db, 1)
	if r.Class != ap.ClassSettled || r.ViewStatus != "unreported" || !bytes.Equal(before, r.RecordJSON) {
		t.Fatalf("horizon: class=%s status=%s unchanged=%v", r.Class, r.ViewStatus, bytes.Equal(before, r.RecordJSON))
	}
	rows, err := db.DueV2(context.Background(), clock.Wall(), 256)
	if err != nil || len(rows) != 0 {
		t.Fatalf("horizon selected again: %d %v", len(rows), err)
	}
	clock.Advance(8 * 24 * time.Hour)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = readApproval(t, db, 1)
	if !r.Record.Header.Shed || r.Record.Header.Decision == nil || len(r.Record.Header.Votes) == 0 {
		t.Fatal("shed lost evidence")
	}
	e.config.Settings.MaxAge = 24 * time.Hour
	// A changed retention config needs a pass over existing rows at startup/config wiring.
	if err := e.reconcileRow(context.Background(), approvalKey(1), false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(context.Background(), approvalKey(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
}

func TestApprovalV2PressureReclaimsAndPreservesReplay(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.MaxFullRows = 1
	submitApproval(t, e, 1)
	approvalDeny(t, e, db, 1)
	clock.Advance(5 * time.Second)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(context.Background()) {
		t.Fatal("flush")
	}
	if _, err := e.Submit(context.Background(), "client", "", approvalDraftAt(2, clock.Wall())); err != nil {
		t.Fatal(err)
	}
	r := readApproval(t, db, 1)
	if !r.Record.Header.Shed {
		t.Fatal("pressure did not shed")
	}
	summary, err := e.Submit(context.Background(), "client", "", approvalDraft(1))
	if err != nil || summary.ApprovalStatus != ap.ApprovalDenied || !summary.Pruned {
		t.Fatalf("shed replay: %+v %v", summary, err)
	}
	changed := approvalDraft(1)
	changed.Rationale = "changed"
	_, err = e.Submit(context.Background(), "client", "", changed)
	requireApprovalCode(t, err, ap.CodeConflict)
	_, err = e.Submit(context.Background(), "client", "", approvalDraftAt(3, clock.Wall()))
	requireApprovalCode(t, err, ap.CodeQueueFull)
	if _, err := db.ReadV2(context.Background(), approvalKey(3)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("protected-only admission wrote a row")
	}
}

func TestApprovalV2WorkerLegacyUnauditedVote(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.LegacyStore = db
	end := clock.Wall().Add(time.Second)
	r := &store.Request{RequestID: "legacy", ClientID: "client", Status: store.StatusPending, CreatedAt: clock.Wall(), ExpiresAt: &end, Commands: []byte(`[]`), RequiredApprovals: 2}
	if err := db.Insert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PrepareVote(context.Background(), &store.Vote{RequestID: r.RequestID, Operator: "operator", Decision: "approve", AuthnMethod: "webauthn", TS: clock.Wall()}); err != nil {
		t.Fatal(err)
	}
	var calls []signerkit.AuditCall
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error { calls = append(calls, c); return nil })
	clock.Advance(2 * time.Second)
	for i := 0; i < 2; i++ {
		if err := e.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if e.flushPass(context.Background()) {
		t.Fatal("flush failed")
	}
	got, err := db.GetByID(context.Background(), r.RequestID)
	if err != nil || got.Status != store.StatusError || got.TerminalReason != "expired" {
		t.Fatalf("legacy: %+v %v", got, err)
	}
	if len(calls) != 1 || calls[0].LegacyExpiry == nil || len(calls[0].LegacyExpiry.Votes) != 1 || calls[0].LegacyExpiry.Votes[0].Operator != "operator" || calls[0].LegacyExpiry.Votes[0].Audited {
		t.Fatalf("expiry evidence: %+v", calls)
	}
}

func TestApprovalV2ClockAndFlushUncertain(t *testing.T) {
	for _, command := range []string{"clock", "flush"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", command, landed), func(t *testing.T) {
				e, db, clock := approvalEngineFixture(t, false)
				approvalWorkerSink(e)
				submitApproval(t, e, 1)
				if command == "clock" {
					clock.Advance(6 * time.Second)
				}
				before := readApproval(t, db, 1).RecordJSON
				ready, unregister := e.registerWaiter([]sqlitestore.V2Key{approvalKey(1)})
				defer unregister()
				e.commit = func(tx *sql.Tx) error {
					if landed {
						if err := tx.Commit(); err != nil {
							return err
						}
					}
					return errors.New("uncertain")
				}
				if command == "clock" {
					_, _, err := e.mutate(context.Background(), approvalKey(1), ap.Tick{}, ap.Inputs{})
					requireApprovalCode(t, err, ap.CodeStorageUncertain)
				} else {
					e.flushPass(context.Background())
				}
				select {
				case <-ready:
					t.Fatal("uncertain commit woke waiter")
				default:
				}
				if bytes.Equal(before, readApproval(t, db, 1).RecordJSON) == landed {
					t.Fatal("fault did not model commit outcome")
				}
				e.commit = func(tx *sql.Tx) error { return tx.Commit() }
				if command == "clock" {
					if err := e.reconcile(context.Background()); err != nil {
						t.Fatal(err)
					}
				} else if e.flushPass(context.Background()) {
					t.Fatal("retry flush failed")
				}
			})
		}
	}
}

func TestApprovalV2AdmissionClockPass(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	approvalReady(t, e, db)
	ctx := context.Background()
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<99) INSERT INTO requests(request_id,status,client_id,commands,created_at) SELECT 'legacy-'||n,'pending','client','[]',? FROM ids`, clock.Wall().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	clock.Advance(60*time.Second + 500*time.Millisecond)
	if _, err := e.Submit(ctx, "client", "", approvalDraftAt(2, clock.Wall())); err != nil {
		t.Fatalf("X5 did not free live slot: %v", err)
	}
	if r := readApproval(t, db, 1).Record; r.Header.Mint == nil || r.Header.Mint.Reason != "window_closed" {
		t.Fatal("X5 did not commit window closure")
	}
}

func TestApprovalV2NewestGrantNeverRegresses(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.Settings.MaxAge = time.Hour
	ctx := context.Background()
	for id := 1; id <= 2; id++ {
		draft := statetest.GrantDraft(statetest.ID(id), "web-1", 24*time.Hour, clock.Wall())
		target := approvalDraft(id).CommandJob.Steps[0].Target
		draft.StandingGrant.TrustedHostFingerprint = target.TrustedHostFingerprint
		draft.StandingGrant.RegistryEntryDigest = target.Digest()
		if _, err := e.Submit(ctx, "client", "", draft); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.mutate(ctx, approvalKey(id), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
		r := readApproval(t, db, id).Record
		if _, err := e.Vote(ctx, approvalKey(id), ap.CastVote{Operator: "operator", Decision: ap.VoteApprove, Authn: "webauthn", Hosted: &ap.HostedTap{PlanHash: r.Header.PlanHash, Revision: 1, Digest: r.Header.Assist.Digest, Actions: ap.ActionsAt(1)}}); err != nil {
			t.Fatal(err)
		}
	}
	owner := approvalGrantOwner{"client", "web-1"}
	if e.newest[owner] != approvalKey(2) || e.grantLive(readApproval(t, db, 1).Record) || !e.grantLive(readApproval(t, db, 2).Record) {
		t.Fatal("grant did not supersede in commit order")
	}
	if _, _, err := e.mutate(ctx, approvalKey(2), ap.Revoke{}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(ctx) {
		t.Fatal("flush")
	}
	if _, _, err := e.mutate(ctx, approvalKey(2), ap.ShedRecord{Pressure: true}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	if !readApproval(t, db, 2).Record.Header.Shed {
		t.Fatal("superseder not shed")
	}
	clock.Advance(25 * time.Hour)
	if _, a, err := e.mutate(ctx, approvalKey(2), ap.Delete{Pressure: true}, ap.Inputs{}); err != nil || !a.Removed {
		t.Fatalf("delete superseder: %+v %v", a, err)
	}
	clock.StepWall(-25 * time.Hour)
	if e.newest[owner] != approvalKey(2) || e.grantLive(readApproval(t, db, 1).Record) {
		t.Fatal("pruning/step back revived older grant")
	}
}

func TestApprovalV2BackwardClock(t *testing.T) {
	for _, step := range []time.Duration{10 * time.Second, time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			approvalWorkerSink(e)
			clock.StepWall(-step)
			if _, err := e.Submit(context.Background(), "client", "", approvalDraftAt(1, clock.Wall())); err != nil {
				t.Fatal(err)
			}
			if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
				t.Fatal(err)
			}
			approvalVote(t, e, db, "operator", ap.VoteApprove, ap.VoteFlags{})
			if e.flushPass(context.Background()) {
				t.Fatal("flush")
			}
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				return []string{"signature"}, nil
			})
			r := readApproval(t, db, 1).Record
			claim := ap.Claim{Token: statetest.Token(statetest.ID(1)), PlanHash: r.Header.PlanHash}
			a, err := e.Claim(context.Background(), approvalKey(1), claim)
			if err != nil || a.Claim != ap.ClaimSignatures {
				t.Fatalf("decision after step: %+v %v", a, err)
			}
			clock.Advance(61 * time.Second)
			if err := e.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			clock.StepWall(-7 * time.Minute)
			a, err = e.Claim(context.Background(), approvalKey(1), claim)
			if err != nil || a.Claim != ap.ClaimExpired {
				t.Fatalf("erased bytes revived: %+v %v", a, err)
			}
		})
	}
}

func TestApprovalV2WorkerBusySkipsUntilNextPass(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	submitApproval(t, e, 1)
	clock.Advance(6 * time.Second)
	before := readApproval(t, db, 1).RecordJSON
	e.config.Store = approvalFaultStore{ApprovalV2Store: db, beginErr: approvalBusy(5)}
	err := e.reconcile(context.Background())
	requireApprovalCode(t, err, ap.CodeBusy)
	if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("busy worker changed record")
	}
	e.config.Store = db
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readApproval(t, db, 1).Record.Header.Assist == nil {
		t.Fatal("next pass lost Clock work")
	}
}

func TestApprovalV2NudgeFlushesBeforeWorkerTick(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runFlusher(ctx) }()
	defer func() { cancel(); <-done }()
	claim := approvalUnflushedReady(t, e, db)
	a, err := e.Claim(context.Background(), approvalKey(1), claim)
	if err != nil || a.Claim != ap.ClaimSignatures {
		t.Fatalf("post-commit nudge: %+v %v", a, err)
	}
}

func TestApprovalV2DeadSinkIgnoresNudges(t *testing.T) {
	e, _, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	submitApproval(t, e, 1)
	calls := make(chan struct{}, 20)
	e.config.AuditSink = approvalSinkFunc(func(context.Context, signerkit.AuditCall) error { calls <- struct{}{}; return errors.New("dead") })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runFlusher(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("no initial pass")
	}
	for i := 0; i < 20; i++ {
		select {
		case e.flushNudge <- struct{}{}:
		default:
		}
	}
	select {
	case <-calls:
		t.Fatal("dead sink retried on nudge")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("dead sink not retried on tick")
	}
}

// Keep the real snapshot/redaction path, compiling its immutable rules once.
// Recompiling them 20,000 times would benchmark regex setup rather than retention.
type approvalCachedSnapshot struct{ rules []redact.Rule }

func (s approvalCachedSnapshot) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	var salt [32]byte
	defer clear(salt[:])
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, "", err
	}
	snapshot, err := approvalreview.BuildSnapshot(p, &salt, s.rules)
	if err != nil {
		return nil, "", err
	}
	view, err := approvalreview.BuildView(snapshot, approvalreview.Assist{State: ap.AssistPreparing})
	if err != nil {
		return nil, "", err
	}
	data, err := snapshot.Encode()
	return data, view.Reason, err
}

// Use the same opaque review fixture as lifecycle/lifecycletest: this load
// case exercises SQLite retention, while the other cases use real snapshots.
type approvalLoadSnapshot struct{}

func (approvalLoadSnapshot) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	return statetest.Review, p.Rationale, nil
}

// Slow race-instrumented SQLite runs can select successive batch ranges over
// the same isolated file. Each invocation stays bounded; all 20 batches retain
// their records and clock across process restarts. The full stress is explicit
// so the ordinary race suite does not exceed its process timeout.
var approvalLoadDB = flag.String("approval-load-db", "", "isolated SQLite file for segmented approval load verification")

func TestApprovalV2RetentionSustainedLoad(t *testing.T) {
	if *approvalLoadDB == "" {
		t.Skip("run all batch ranges with -approval-load-db for the 20,000-record stress check")
	}
	db, err := sqlitestore.Open(*approvalLoadDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	clock := elapsedtest.NewFake(statetest.T0)
	e, err := NewApprovalV2Engine(ApprovalV2Config{
		Store: db, Clock: clock, Freezer: &approvalTestFreezer{}, SnapshotBuilder: approvalLoadSnapshot{},
		MaxFullRows: 20, MaxRows: 20, Settings: ap.Settings{MaxAge: time.Hour},
		AuditSink: signerkit.NewAppendOnlySink(io.Discard), Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id := 1
	started := false
	for batch := 0; batch < 20; batch++ {
		if !t.Run(fmt.Sprintf("batch-%02d", batch), func(t *testing.T) {
			if !started {
				id = batch*1000 + 1
				tx, err := db.BeginV2(ctx)
				if err != nil {
					t.Fatal(err)
				}
				counts, err := db.CountV2(ctx, tx)
				tx.Rollback()
				if err != nil {
					t.Fatal(err)
				}
				if id == 1 {
					if counts.All != 0 {
						t.Fatal("first load segment requires an empty database")
					}
				} else {
					if counts.All != 20 || counts.Full != 20 {
						t.Fatalf("persisted segment counts: %+v", counts)
					}
					for previous := id - 20; previous < id; previous++ {
						row := readApproval(t, db, previous)
						if row.Record.Header.Decision == nil || row.Record.Header.Decision.Status != ap.ApprovalDenied || ap.Unflushed(row.Record) {
							t.Fatal("previous segment did not persist its decisions and audit acknowledgements")
						}
					}
					last := readApproval(t, db, id-1)
					clock.StepWall(last.Record.Header.CreatedAt.Add(5 * time.Second).Sub(clock.Wall()))
				}
			}
			started = true
			for count := 0; count < 1000; count++ {
				if id > 1 && (id-1)%20 == 0 {
					// Every row is settled, but the replay floor still protects all of them.
					if id == 21 {
						_, err := e.Submit(ctx, "client", "", approvalDraftAt(id, clock.Wall()))
						requireApprovalCode(t, err, ap.CodeQueueFull)
					}
					clock.Advance(25 * time.Hour)
					if err := e.reconcile(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := e.Submit(ctx, "client", "", approvalDraftAt(id, clock.Wall())); err != nil {
					t.Fatalf("submit %d: %v", id, err)
				}
				approvalDeny(t, e, db, id)
				clock.Advance(5 * time.Second)
				if err := e.reconcile(ctx); err != nil {
					t.Fatal(err)
				}
				if e.flushPass(ctx) {
					t.Fatal("flush failed")
				}
				tx, err := db.BeginV2(ctx)
				if err != nil {
					t.Fatal(err)
				}
				counts, err := db.CountV2(ctx, tx)
				tx.Rollback()
				if err != nil || counts.Full > 20 || counts.All > 20 || counts.All != int64((id-1)%20+1) {
					t.Fatalf("load %d counts=%+v err=%v", id, counts, err)
				}
				if id%1000 == 0 {
					t.Logf("completed %d submits and decisions", id)
				}
				id++
			}
		}) {
			return
		}
	}
}

func TestApprovalV2PressureShedStillAcceptsLateReport(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprint(late), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			approvalWorkerSink(e)
			claim := approvalReady(t, e, db)
			ctx := context.Background()
			if _, err := e.Claim(ctx, approvalKey(1), claim); err != nil {
				t.Fatal(err)
			}
			clock.Advance(20 * time.Minute)
			if err := e.reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			if e.flushPass(ctx) {
				t.Fatal("flush")
			}
			e.config.MaxFullRows = 1
			if _, err := e.Submit(ctx, "client", "", approvalDraftAt(2, clock.Wall())); err != nil {
				t.Fatal(err)
			}
			if !readApproval(t, db, 1).Record.Header.Shed {
				t.Fatal("awaiting report not shed under pressure")
			}
			if late {
				clock.Advance(e.config.Settings.ReportHorizon)
				if err := e.reconcile(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.Report(ctx, approvalKey(1), approvalReport(claim)); err != nil {
				t.Fatalf("shed report late=%v: %v", late, err)
			}
			if readApproval(t, db, 1).Record.Header.FinalReport == nil {
				t.Fatal("report not persisted")
			}
		})
	}
}

type approvalLogLines chan string

func (c approvalLogLines) Write(p []byte) (int, error) { c <- string(p); return len(p), nil }

func TestApprovalV2WorkerLogsCeilingAndClockSteps(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.MaxRows = 1
	submitApproval(t, e, 1)
	approvalDeny(t, e, db, 1)
	clock.Advance(6 * time.Second)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(context.Background()) {
		t.Fatal("flush")
	}
	lines := make(approvalLogLines, 20)
	e.config.Logger = log.New(lines, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer func() { cancel(); <-done }()
	await := func(part string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case line := <-lines:
				if strings.Contains(line, part) {
					return
				}
			case <-deadline:
				t.Fatalf("no log containing %s", part)
			}
		}
	}
	await("--approval-max-rows")
	select {
	case line := <-lines:
		t.Fatalf("repeated ceiling warning: %s", line)
	case <-time.After(1200 * time.Millisecond):
	}
	clock.StepWall(-time.Hour)
	await("clock wall step")
	clock.Advance(time.Hour)
	await("--approval-max-rows")
	_, err := e.Submit(context.Background(), "client", "", approvalDraftAt(2, clock.Wall()))
	requireApprovalCode(t, err, ap.CodeQueueFull)
	if _, err := db.ReadV2(context.Background(), approvalKey(1)); err != nil {
		t.Fatal("default MaxAge deleted row")
	}
}

func TestApprovalV2AuditFailureProtectsRetention(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.MaxRows = 1
	e.config.MaxFullRows = 1
	e.config.Settings.MaxAge = time.Hour
	claim := approvalUnflushedReady(t, e, db)
	e.config.AuditSink = approvalSinkFunc(func(context.Context, signerkit.AuditCall) error { return errors.New("dead") })
	if !e.flushPass(context.Background()) {
		t.Fatal("sink unexpectedly worked")
	}
	a, err := e.Claim(context.Background(), approvalKey(1), claim)
	if err != nil || a.Claim != ap.ClaimNotReady {
		t.Fatalf("unaudited claim: %+v %v", a, err)
	}
	clock.Advance(25 * time.Hour)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = e.Submit(context.Background(), "client", "", approvalDraftAt(2, clock.Wall()))
	requireApprovalCode(t, err, ap.CodeQueueFull)
	if readApproval(t, db, 1).Record.Payload == nil {
		t.Fatal("unaudited payload shed")
	}
	e.config.AuditSink = signerkit.NewAppendOnlySink(io.Discard)
	if e.flushPass(context.Background()) {
		t.Fatal("recovered sink failed")
	}
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(context.Background(), approvalKey(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovered audit did not unblock deletion: %v", err)
	}
}

func TestApprovalV2ReclamationRechecksPressure(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.Settings.MaxAge = 30 * 24 * time.Hour
	submitApproval(t, e, 1)
	approvalDeny(t, e, db, 1)
	clock.Advance(6 * time.Second)
	if err := e.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(context.Background()) {
		t.Fatal("flush")
	}
	before := readApproval(t, db, 1).RecordJSON
	// A candidate listed under pressure must survive if another writer made room.
	if _, a, err := e.reclaim(context.Background(), approvalKey(1), false, true); err != nil || a.Changed {
		t.Fatalf("stale full pressure: %+v %v", a, err)
	}
	clock.Advance(25 * time.Hour)
	if _, a, err := e.reclaim(context.Background(), approvalKey(1), true, true); err != nil || a.Removed {
		t.Fatalf("stale row pressure: %+v %v", a, err)
	}
	if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("stale pressure changed record")
	}
}

func TestApprovalV2PressureStillClocksRemainingDueRows(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.MaxFullRows = 2
	ctx := context.Background()
	submitApproval(t, e, 1)
	approvalDeny(t, e, db, 1)
	clock.Advance(5 * time.Second)
	if err := e.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(ctx) {
		t.Fatal("flush")
	}
	if _, err := e.Submit(ctx, "client", "", approvalDraftAt(2, clock.Wall())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.mutate(ctx, approvalKey(2), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	r := readApproval(t, db, 2).Record
	if _, err := e.Vote(ctx, approvalKey(2), ap.CastVote{Operator: "operator", Decision: ap.VoteApprove, Authn: "webauthn", Hosted: &ap.HostedTap{PlanHash: r.Header.PlanHash, Revision: 1, Digest: r.Header.Assist.Digest, Actions: ap.ActionsAt(1)}}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<99) INSERT INTO requests(request_id,status,client_id,commands,created_at) SELECT 'legacy-'||n,'pending','client','[]',? FROM ids`, clock.Wall().Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	clock.Advance(61 * time.Second)
	if _, err := e.Submit(ctx, "client", "", approvalDraftAt(3, clock.Wall())); err != nil {
		t.Fatalf("reclamation stopped before remaining due Clock: %v", err)
	}
	if !readApproval(t, db, 1).Record.Header.Shed {
		t.Fatal("oldest row was not shed")
	}
	if r := readApproval(t, db, 2).Record; r.Header.Mint == nil || r.Header.Mint.Reason != "window_closed" {
		t.Fatal("remaining due row not clocked")
	}
}

func TestApprovalV2TenSecondClockSkew(t *testing.T) {
	for _, after := range []time.Duration{2 * time.Second, 6 * time.Second} {
		t.Run(after.String(), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			claim := approvalReady(t, e, db)
			clock.Advance(time.Second)
			clock.StepWall(-10 * time.Second)
			clock.Advance(after - time.Second)
			answer, err := e.Claim(context.Background(), approvalKey(1), claim)
			if err != nil {
				t.Fatal(err)
			}
			if after == 2*time.Second {
				if answer.Claim != ap.ClaimMaterializationError || answer.Reason != "clock_skew" || readApproval(t, db, 1).Record.Header.Mint == nil {
					t.Fatalf("10-second skew: %+v", answer)
				}
			} else if answer.Claim != ap.ClaimSignatures {
				t.Fatalf("within release skew: %+v", answer)
			}
		})
	}
}

func TestApprovalV2InjectedEightTwentyCeilings(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.SnapshotBuilder = approvalLoadSnapshot{}
	e.config.MaxFullRows = 8
	e.config.MaxRows = 20
	e.config.Settings.MaxAge = time.Hour
	ctx := context.Background()
	for id := 1; id <= 20; id++ {
		if _, err := e.Submit(ctx, "client", "", approvalDraftAt(id, clock.Wall())); err != nil {
			t.Fatal(err)
		}
		approvalDeny(t, e, db, id)
		clock.Advance(5 * time.Second)
		if err := e.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if e.flushPass(ctx) {
			t.Fatal("flush")
		}
		tx, err := db.BeginV2(ctx)
		if err != nil {
			t.Fatal(err)
		}
		counts, err := db.CountV2(ctx, tx)
		tx.Rollback()
		if err != nil || counts.Full > 8 || counts.All != int64(id) {
			t.Fatalf("caps: %+v %v", counts, err)
		}
	}
	if !readApproval(t, db, 1).Record.Header.Shed {
		t.Fatal("oldest full row not reclaimed")
	}
	clock.Advance(2 * time.Hour)
	if err := e.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := e.Submit(ctx, "client", "", approvalDraftAt(21, clock.Wall()))
	requireApprovalCode(t, err, ap.CodeQueueFull)
	if _, err := db.ReadV2(ctx, approvalKey(21)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("protected admission persisted a row")
	}
	clock.Advance(24 * time.Hour)
	if err := e.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit(ctx, "client", "", approvalDraftAt(21, clock.Wall())); err != nil {
		t.Fatal(err)
	}
}
