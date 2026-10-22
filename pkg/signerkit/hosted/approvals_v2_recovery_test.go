package hosted

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func restartApprovalEngine(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB) (*ApprovalV2Engine, *sqlitestore.DB) {
	t.Helper()
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var seq int
	var name, path string
	err = tx.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path)
	tx.Rollback()
	if err != nil || path == "" {
		t.Fatalf("file-backed database: %q %v", path, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	config := e.config
	config.Store = reopened
	if config.LegacyStore != nil {
		config.LegacyStore = reopened
	}
	next, err := NewApprovalV2Engine(config)
	if err != nil {
		t.Fatal(err)
	}
	return next, reopened
}

func runApprovalWorker(t *testing.T, e *ApprovalV2Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("worker failed to join")
		}
	})
}
func awaitApprovalState(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker did not reach required state without another command")
}

func TestApprovalV2StartupRecomputesSettings(t *testing.T) {
	for _, mode := range []string{"delete-null-deadline", "shorten-retention", "shorten-horizon"} {
		t.Run(mode, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, true)
			approvalWorkerSink(e)
			if mode == "shorten-horizon" {
				claim := approvalReady(t, e, db)
				if _, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil {
					t.Fatal(err)
				}
			} else {
				submitApproval(t, e, 1)
				approvalDeny(t, e, db, 1)
			}
			clock.Advance(2 * time.Hour)
			if err := e.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.flushPass(context.Background()) {
				t.Fatal("flush")
			}
			switch mode {
			case "delete-null-deadline":
				clock.Advance(8 * 24 * time.Hour)
				if err := e.reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
				row := readApproval(t, db, 1)
				if !row.Record.Header.Shed || row.NextDueAt != nil {
					t.Fatalf("expected shed without deadline: %+v", row)
				}
				e.config.Settings.MaxAge = 24 * time.Hour
			case "shorten-retention":
				e.config.Settings.Retention = time.Hour
			case "shorten-horizon":
				e.config.Settings.ReportHorizon = time.Hour
			}
			e, db = restartApprovalEngine(t, e, db)
			runApprovalWorker(t, e)
			awaitApprovalState(t, func() bool {
				row, err := db.ReadV2(context.Background(), approvalKey(1))
				if mode == "delete-null-deadline" {
					return errors.Is(err, store.ErrNotFound)
				}
				if err != nil {
					t.Fatal(err)
				}
				if mode == "shorten-retention" {
					return row.Record.Header.Shed
				}
				return row.Class == ap.ClassSettled && row.ViewStatus == "unreported"
			})
		})
	}
}

func TestApprovalV2PressureDecisionOrder(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, tie := range []bool{false, true} {
			name := "shed"
			if remove {
				name = "delete"
			}
			if tie {
				name += "-key-tie"
			}
			t.Run(name, func(t *testing.T) {
				e, db, clock := approvalEngineFixture(t, false)
				approvalWorkerSink(e)
				// ID 2 is submitted first, but ID 1 is decided first (or at the same second).
				submitApproval(t, e, 2)
				clock.Advance(time.Second)
				if _, err := e.Submit(context.Background(), "client", "", approvalDraftAt(1, clock.Wall())); err != nil {
					t.Fatal(err)
				}
				approvalDeny(t, e, db, 1)
				if !tie {
					clock.Advance(time.Second)
				}
				approvalDeny(t, e, db, 2)
				clock.Advance(25 * time.Hour)
				if err := e.reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
				if e.flushPass(context.Background()) {
					t.Fatal("flush")
				}
				if remove {
					e.config.MaxRows = 2
					e.config.Settings.MaxAge = 365 * 24 * time.Hour
				} else {
					e.config.MaxFullRows = 2
				}
				if _, err := e.Submit(context.Background(), "client", "", approvalDraftAt(3, clock.Wall())); err != nil {
					t.Fatal(err)
				}
				older, err := db.ReadV2(context.Background(), approvalKey(1))
				if remove {
					if !errors.Is(err, store.ErrNotFound) {
						t.Fatalf("oldest decision not deleted: %v", err)
					}
				} else if err != nil || !older.Record.Header.Shed {
					t.Fatalf("oldest decision not shed: %v", err)
				}
				newer := readApproval(t, db, 2)
				if newer.Record.Header.Shed {
					t.Fatal("newer decision reclaimed first")
				}
			})
		}
	}
}

func TestApprovalV2LegacyAuditRecovery(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "retry"
		if restart {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, true)
			approvalWorkerSink(e)
			e.config.LegacyStore = db
			end := clock.Wall().Add(time.Second)
			req := &store.Request{RequestID: "legacy", ClientID: "client", Status: store.StatusPending, CreatedAt: clock.Wall(), ExpiresAt: &end, Commands: []byte(`[]`), RequiredApprovals: 2}
			if err := db.Insert(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.PrepareVote(context.Background(), &store.Vote{RequestID: req.RequestID, Operator: "operator", Decision: "approve", AuthnMethod: "webauthn", TS: clock.Wall()}); err != nil {
				t.Fatal(err)
			}
			attempts := 0
			var delivered signerkit.AuditCall
			e.config.AuditSink = approvalSinkFunc(func(_ context.Context, call signerkit.AuditCall) error {
				attempts++
				if attempts == 1 {
					return errors.New("one failed write")
				}
				delivered = call
				return nil
			})
			clock.Advance(2 * time.Second)
			if err := e.expireLegacy(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !e.flushPass(context.Background()) {
				t.Fatal("expected sink failure")
			}
			expired, err := db.GetByID(context.Background(), req.RequestID)
			if err != nil || expired.Status != store.StatusError || expired.TerminalReason != "expired" {
				t.Fatalf("unaudited vote blocked expiry: %+v %v", expired, err)
			}
			if restart {
				e, db = restartApprovalEngine(t, e, db)
			}
			if e.flushPass(context.Background()) {
				t.Fatal("flush failed")
			}
			if e.flushPass(context.Background()) {
				t.Fatal("flush failed")
			}
			if attempts != 2 || delivered.Lifecycle != "legacy-expired" {
				t.Fatalf("delivery lost or repeated: %d %+v", attempts, delivered)
			}
			votes := delivered.LegacyExpiry.Votes
			if len(votes) != 1 || votes[0].Operator != "operator" || votes[0].Decision != "approve" || votes[0].Audited {
				t.Fatalf("lost vote evidence: %+v", votes)
			}

		})
	}
}

func TestApprovalV2AdvisoryBindingSurvivesReopen(t *testing.T) {
	for _, mode := range []string{"ready", "deny-preparing", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, true)
			approvalWorkerSink(e)
			draft := approvalDraft(1)
			draft.Rationale = "Perform the requested maintenance"
			if _, err := e.Submit(context.Background(), "client", "", draft); err != nil {
				t.Fatal(err)
			}
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
			decision := ap.VoteApprove
			if mode == "deny-preparing" {
				decision = ap.VoteDeny
			}
			approvalVote(t, e, db, "operator", decision, ap.VoteFlags{DenyVeto: true})
			before := readApproval(t, db, 1).Record.Header
			var event *ap.AuditMetadata
			var voteEvents []ap.AuditMetadata
			e.config.AuditSink = approvalSinkFunc(func(_ context.Context, call signerkit.AuditCall) error {
				if call.Approval.Transition == ap.EventDecision {
					copy := *call.Approval
					event = &copy
				}
				if strings.HasPrefix(call.Approval.Transition, "vote{operator:") {
					voteEvents = append(voteEvents, *call.Approval)
				}
				return nil
			})
			if e.flushPass(context.Background()) {
				t.Fatal("Flush")
			}
			if event == nil || event.Assist == nil {
				t.Fatal("missing flushed decision binding")
			}
			// Subsequent writes are discarded, as is the production sink after delivery.
			e.config.AuditSink = signerkit.NewAppendOnlySink(io.Discard)
			clock.Advance(8 * 24 * time.Hour)
			if err := e.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if e.flushPass(context.Background()) {
				t.Fatal("flush Clock")
			}
			if err := e.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			e, db = restartApprovalEngine(t, e, db)
			h := readApproval(t, db, 1).Record.Header
			if !h.Shed || h.RationaleRedacted == "" || h.RationaleRedacted != event.RationaleRedacted || h.Decision.DecidedBy != event.DecidedBy || h.Decision.AssistBound != *event.Assist || !reflect.DeepEqual(h.Votes, before.Votes) {
				t.Fatalf("persisted binding differs from flushed decision: header=%+v event=%+v", h, event)
			}
			// Decision metadata has no vote array; its separate vote events bind the actors and choices.
			if len(voteEvents) != len(h.Votes) {
				t.Fatalf("vote evidence count: %d vs %d", len(voteEvents), len(h.Votes))
			}
			for i, vote := range h.Votes {
				if voteEvents[i].Decision != vote.Decision || voteEvents[i].Transition != "vote{operator:"+vote.Operator+"}" {
					t.Fatal("persisted vote differs from flushed vote event")
				}
			}
			want := ap.AssistReady
			revision := 1
			if mode == "deny-preparing" {
				want = ap.AssistPreparing
				revision = 0
			}
			if mode == "unavailable" {
				want = ap.AssistUnavailable
			}
			if h.Decision.AssistBound.State != want || h.Decision.AssistBound.Revision != revision {
				t.Fatalf("wrong test binding: %+v", h.Decision.AssistBound)
			}
		})
	}
}

func TestApprovalV2StartupVisitsEveryBatch(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, true)
	approvalWorkerSink(e)
	ctx := context.Background()
	initial := e.now()
	clock.Advance(8 * 24 * time.Hour)
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	inputs := ap.Inputs{Epoch: e.epoch, Settings: e.config.Settings}
	for id := 1; id <= ap.FlushBatch+1; id++ {
		rec, answer := ap.Apply(nil, statetest.SubmitOf(approvalDraft(id), "client", initial.Wall, ap.ValidityMin), initial, inputs)
		if answer.Code != "" {
			t.Fatal(answer)
		}
		rec, answer = ap.Apply(&rec, ap.Tick{}, e.now(), inputs)
		if answer.Code != "" {
			t.Fatal(answer)
		}
		rec, answer = ap.Apply(&rec, ap.Flush{Through: rec.Header.OutboxSeq}, e.now(), inputs)
		if answer.Code != "" {
			t.Fatal(answer)
		}
		rec, answer = ap.Apply(&rec, ap.ShedRecord{}, e.now(), inputs)
		if answer.Code != "" || !rec.Header.Shed {
			t.Fatalf("shed fixture: %+v", answer)
		}
		if err := db.PutV2(ctx, tx, approvalKey(id), rec, sqlitestore.V2Projection{Now: e.now(), Epoch: e.epoch, Settings: e.config.Settings}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	e.config.Settings.MaxAge = 24 * time.Hour
	e, db = restartApprovalEngine(t, e, db)
	if err := e.reconcileStartup(ctx); err != nil {
		t.Fatal(err)
	}
	counts, err := e.approvalCounts(ctx)
	if err != nil || counts.All != 0 {
		t.Fatalf("startup missed a batch: %+v %v", counts, err)
	}
}

func TestApprovalV2StartupRejectsCorruptRecord(t *testing.T) {
	for _, mode := range []string{"identity", "encoding"} {
		t.Run(mode, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			submitApproval(t, e, 1)
			ctx := context.Background()
			tx, err := db.BeginV2(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if mode == "identity" {
				_, err = tx.Exec(`UPDATE approvals_v2 SET request_id=?`, statetest.ID(2))
			} else {
				_, err = tx.Exec(`UPDATE approvals_v2 SET record_json='{}'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			requireApprovalCode(t, e.reconcileStartup(ctx), ap.CodeRecordCorrupt)
			counts, err := e.approvalCounts(ctx)
			if err != nil || counts.All != 1 {
				t.Fatalf("corrupt row was removed: %+v %v", counts, err)
			}
		})
	}
}
