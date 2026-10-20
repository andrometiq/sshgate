package hosted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
)

type approvalTestFreezer struct{ calls atomic.Int32 }

func (f *approvalTestFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, client, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	f.calls.Add(1)
	return ap.FreezeDraft(d, ap.FreezeInputs{RequesterPrincipal: client, RequesterSub: sub, Now: now, Validity: ap.ValidityMin})
}

type approvalTestSnapshot struct{}

func (approvalTestSnapshot) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	snapshot, err := BuildApprovalSnapshot(p)
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
func approvalEngineFixture(t *testing.T, file bool) (*ApprovalV2Engine, *sqlitestore.DB, *elapsedtest.Fake) {
	t.Helper()
	name := ":memory:"
	if file {
		name = filepath.Join(t.TempDir(), "approvals.db")
	}
	db, err := sqlitestore.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clock := elapsedtest.NewFake(statetest.T0)
	e, err := NewApprovalV2Engine(ApprovalV2Config{Store: db, Clock: clock, Freezer: &approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshot{}})
	if err != nil {
		t.Fatal(err)
	}
	return e, db, clock
}
func approvalDraft(id int) ap.ApprovalDraft {
	return approvalDraftAt(id, statetest.T0)
}

func approvalDraftAt(id int, now time.Time) ap.ApprovalDraft {
	draft := statetest.JobDraft(statetest.ID(id), ap.CoordinatorExecutor, now, statetest.Write("true", 60))
	for i := range draft.CommandJob.Steps {
		step := &draft.CommandJob.Steps[i]
		digest := sha256.Sum256([]byte(step.Target.ServerAlias))
		step.Target.TrustedHostFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
		step.RegistryEntryDigest = step.Target.Digest()
	}
	return draft
}
func approvalKey(id int) sqlitestore.V2Key {
	return sqlitestore.V2Key{ClientID: "client", RequestID: statetest.ID(id)}
}
func requireApprovalCode(t *testing.T, err error, want ap.Code) {
	t.Helper()
	var coded *ap.CodeError
	if !errors.As(err, &coded) || coded.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}
func submitApproval(t *testing.T, e *ApprovalV2Engine, id int) {
	t.Helper()
	if _, err := e.Submit(context.Background(), "client", "", approvalDraft(id)); err != nil {
		t.Fatal(err)
	}
}
func readApproval(t *testing.T, db *sqlitestore.DB, id int) *sqlitestore.V2Row {
	t.Helper()
	row, err := db.ReadV2(context.Background(), approvalKey(id))
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestApprovalV2SubmitReplayAndClock(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	ctx := context.Background()
	e.config.RequiredApprovals = 2
	submitApproval(t, e, 1)
	first := readApproval(t, db, 1)
	if first.Record.Header.RequiredApprovals != 2 || first.Record.Header.Assist != nil {
		t.Fatalf("header: %+v", first.Record.Header)
	}
	if _, err := e.Submit(ctx, "client", "", approvalDraft(1)); err != nil {
		t.Fatal(err)
	}
	if got := readApproval(t, db, 1); !bytes.Equal(first.RecordJSON, got.RecordJSON) {
		t.Fatal("replay changed record")
	}
	clock.Advance(ap.SubmitWindowMax + time.Second)
	// A replay ignores the closed submit window, but advances Clock atomically.
	summary, err := e.Submit(ctx, "client", "", approvalDraft(1))
	if err != nil || summary.ApprovalStatus != ap.ApprovalExpired {
		t.Fatalf("expired replay: %+v %v", summary, err)
	}
	row := readApproval(t, db, 1)
	if row.Record.Header.Assist == nil || row.Record.Header.Decision == nil {
		t.Fatal("Clock facts not committed")
	}
	if e.config.Freezer.(*approvalTestFreezer).calls.Load() != 1 {
		t.Fatal("replay refroze plan")
	}
	changed := approvalDraft(1)
	changed.Rationale = "Different rationale"
	_, err = e.Submit(ctx, "client", "", changed)
	requireApprovalCode(t, err, ap.CodeConflict)
	_, err = e.Submit(ctx, "client", "", approvalDraft(2))
	requireApprovalCode(t, err, ap.CodeSubmitWindowClosed)
}

func TestApprovalV2ReadsDoNotAdvanceClock(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	before := readApproval(t, db, 1).RecordJSON
	clock.Advance(ap.ValidityMin + time.Second)
	ctx := context.Background()
	got, err := e.Get(ctx, approvalKey(1))
	if err != nil || got.ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("Get: %+v %v", got, err)
	}
	list, err := e.List(ctx, "client", "", nil, 10)
	if err != nil || len(list) != 1 || list[0].ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("List: %+v %v", list, err)
	}
	wait, err := e.WaitMany(ctx, "client", "", []string{statetest.ID(1)}, time.Millisecond)
	if err != nil || !wait.WaitElapsed || wait.Summaries[0].ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("Wait: %+v %v", wait, err)
	}
	if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("read wrote Clock")
	}
}

func TestApprovalV2OwnerScope(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	ctx := context.Background()
	for _, sub := range []string{"", "local-uid:1000", "local-uid:1001"} {
		if _, err := e.Submit(ctx, "client", sub, approvalDraft(1)); err != nil {
			t.Fatal(err)
		}
		list, err := e.List(ctx, "client", sub, nil, 10)
		if err != nil || len(list) != 1 {
			t.Fatalf("owner list: %v %v", list, err)
		}
	}
	for _, key := range []sqlitestore.V2Key{{ClientID: "other", RequestID: statetest.ID(1)}, {ClientID: "client", SubPrincipal: "local-uid:1002", RequestID: statetest.ID(1)}, approvalKey(2)} {
		_, err := e.Get(ctx, key)
		requireApprovalCode(t, err, ap.CodeNotFound)
		_, err = e.WaitMany(ctx, key.ClientID, key.SubPrincipal, []string{key.RequestID}, time.Second)
		requireApprovalCode(t, err, ap.CodeNotFound)
	}
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	counts, err := db.CountV2(ctx, tx)
	if err != nil || counts.All != 3 {
		t.Fatalf("counts: %+v %v", counts, err)
	}
}

type approvalBusy int

func (e approvalBusy) Error() string { return "injected SQLite error" }
func (e approvalBusy) Code() int     { return int(e) }

type approvalFaultStore struct {
	ApprovalV2Store
	beginErr, readErr, listErr, putErr error
}

func (s approvalFaultStore) BeginV2(ctx context.Context) (*sql.Tx, error) {
	if s.beginErr != nil {
		return nil, s.beginErr
	}
	return s.ApprovalV2Store.BeginV2(ctx)
}
func (s approvalFaultStore) ReadV2(ctx context.Context, key sqlitestore.V2Key) (*sqlitestore.V2Row, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	return s.ApprovalV2Store.ReadV2(ctx, key)
}
func (s approvalFaultStore) ListV2(ctx context.Context, client, sub string, cursor *sqlitestore.V2Cursor, limit int) ([]*sqlitestore.V2Row, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.ApprovalV2Store.ListV2(ctx, client, sub, cursor, limit)
}
func (s approvalFaultStore) PutV2(ctx context.Context, tx *sql.Tx, key sqlitestore.V2Key, rec ap.R1, projection sqlitestore.V2Projection) error {
	if s.putErr != nil {
		return s.putErr
	}
	return s.ApprovalV2Store.PutV2(ctx, tx, key, rec, projection)
}

func TestApprovalV2BusyClassification(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	ctx := context.Background()
	for _, code := range []int{5, 5 | (2 << 8)} {
		err := fmt.Errorf("driver: %w", approvalBusy(code))
		if !IsApprovalBusy(err) || IsApprovalBusy(approvalBusy(6)) || IsApprovalBusy(errors.New("SQLITE_BUSY")) {
			t.Fatal("busy classifier")
		}
		e.config.Store = approvalFaultStore{ApprovalV2Store: db, beginErr: err, readErr: err, listErr: err}
		_, got := e.Submit(ctx, "client", "", approvalDraft(2))
		requireApprovalCode(t, got, ap.CodeBusy)
		_, got = e.Get(ctx, approvalKey(1))
		requireApprovalCode(t, got, ap.CodeBusy)
		_, got = e.List(ctx, "client", "", nil, 10)
		requireApprovalCode(t, got, ap.CodeBusy)
		_, got = e.WaitMany(ctx, "client", "", []string{statetest.ID(1)}, time.Second)
		requireApprovalCode(t, got, ap.CodeBusy)
	}
	e.config.Store = approvalFaultStore{ApprovalV2Store: db, putErr: approvalBusy(5)}
	_, err := e.Submit(ctx, "client", "", approvalDraft(2))
	requireApprovalCode(t, err, ap.CodeStorageUncertain)
	if _, err := db.ReadV2(ctx, approvalKey(2)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed write landed")
	}
}

func TestApprovalV2UncertainCommitHasNoEffects(t *testing.T) {
	for _, lands := range []bool{false, true} {
		t.Run(fmt.Sprint(lands), func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			ready := make(chan struct{}, 1)
			e.waiters[approvalKey(1)] = map[chan struct{}]struct{}{ready: {}}
			commit := e.commit
			e.commit = func(tx *sql.Tx) error {
				if lands {
					if err := tx.Commit(); err != nil {
						return err
					}
				}
				return approvalBusy(5)
			}
			summary, err := e.Submit(context.Background(), "client", "", approvalDraft(1))
			requireApprovalCode(t, err, ap.CodeStorageUncertain)
			if summary.RequestID != "" {
				t.Fatal("uncertain answer carried record")
			}
			select {
			case <-ready:
				t.Fatal("uncertain commit woke waiter")
			default:
			}
			select {
			case <-e.flushNudge:
				t.Fatal("uncertain commit nudged flusher")
			default:
			}
			_, err = db.ReadV2(context.Background(), approvalKey(1))
			if lands && err != nil || !lands && !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("landed=%v: %v", lands, err)
			}
			e.commit = commit
			submitApproval(t, e, 1)
			row := readApproval(t, db, 1)
			if row.Record.Header.OutboxSeq != 1 {
				t.Fatal("retry duplicated submit")
			}
		})
	}
}

func TestApprovalV2ReadsDuringWriterContention(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, true)
	ctx := context.Background()
	submitApproval(t, e, 1)
	submitApproval(t, e, 2)
	// A terminal record lets Wait answer without waiting for a new commit.
	if _, _, err := e.mutate(ctx, approvalKey(2), ap.AdminCancel{Admin: "operator", PlanHash: readApproval(t, db, 2).Record.Header.PlanHash}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	before := readApproval(t, db, 1).RecordJSON
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := e.Get(readCtx, approvalKey(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.List(readCtx, "client", "", nil, 10); err != nil {
		t.Fatal(err)
	}
	if result, err := e.WaitMany(readCtx, "client", "", []string{statetest.ID(2)}, time.Second); err != nil || result.WaitElapsed {
		t.Fatalf("decided Wait: %+v %v", result, err)
	}
	start := time.Now()
	waitCtx, cancelWait := context.WithTimeout(ctx, 2*time.Second)
	defer cancelWait()
	result, err := e.WaitMany(waitCtx, "client", "", []string{statetest.ID(1)}, time.Second)
	if err != nil || !result.WaitElapsed || time.Since(start) > 2*time.Second {
		t.Fatalf("pending Wait: %+v %v", result, err)
	}
	if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("contention read mutated row")
	}
	// The real driver waits for its busy timeout; no transaction or row lands.
	_, err = e.Submit(ctx, "client", "", approvalDraft(3))
	requireApprovalCode(t, err, ap.CodeBusy)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 3)
}

func TestApprovalV2WaitAllowsWriterAndWakesAfterCommit(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Return the pending snapshot only after cancellation commits and notifies.
	entered, release := make(chan struct{}), make(chan struct{})
	e.config.Store = &approvalReadGate{ApprovalV2Store: db, entered: entered, release: release}
	done := make(chan error, 1)
	go func() {
		result, err := e.WaitMany(ctx, "client", "", []string{statetest.ID(1)}, ap.AwaitMaxWait)
		if err == nil && (result.WaitElapsed || result.Summaries[0].ApprovalStatus != ap.ApprovalCanceled) {
			err = fmt.Errorf("wait: %+v", result)
		}
		done <- err
	}()
	<-entered
	row := readApproval(t, db, 1)
	if _, _, err := e.mutate(ctx, approvalKey(1), ap.AdminCancel{Admin: "operator", PlanHash: row.Record.Header.PlanHash}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("waiter missed committed cancellation")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.waiters) != 0 {
		t.Fatal("waiter leaked")
	}
}

type approvalReadGate struct {
	ApprovalV2Store
	once             sync.Once
	entered, release chan struct{}
}

func (s *approvalReadGate) ReadV2(ctx context.Context, key sqlitestore.V2Key) (*sqlitestore.V2Row, error) {
	row, err := s.ApprovalV2Store.ReadV2(ctx, key)
	if err != nil {
		return nil, err
	}
	s.once.Do(func() {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
		}
	})
	return row, nil
}

func TestApprovalV2ConcurrentCeiling(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, true)
	e.config.MaxRows = 3
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 1; i <= 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := e.Submit(context.Background(), "client", "", approvalDraft(id))
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			requireApprovalCode(t, err, ap.CodeQueueFull)
		}
	}
	if accepted != 3 {
		t.Fatalf("accepted %d", accepted)
	}
	rows, err := db.ListV2(context.Background(), "client", "", nil, 20)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
}

func TestApprovalV2MutationAdvancesClock(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	clock.Advance(ap.ValidityMin + time.Second)
	// Cancel must first commit expiry; it cannot overwrite that terminal fact.
	_, answer, err := e.mutate(context.Background(), approvalKey(1), ap.AdminCancel{Admin: "operator", PlanHash: readApproval(t, db, 1).Record.Header.PlanHash}, ap.Inputs{})
	if err != nil || answer.Reason != "already_resolved" {
		t.Fatalf("cancel: %+v %v", answer, err)
	}
	row := readApproval(t, db, 1)
	if row.Record.Header.Decision.Status != ap.ApprovalExpired || row.Record.Header.Assist == nil {
		t.Fatal("mutation skipped Clock")
	}
}

func TestApprovalV2SubmitValidationAndFrozenThreshold(t *testing.T) {
	for _, n := range []int{-1, 0, 256} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			cfg := e.config
			cfg.RequiredApprovals = n
			e, err := NewApprovalV2Engine(cfg)
			if err != nil {
				t.Fatal(err)
			}
			submitApproval(t, e, 1)
			if got := readApproval(t, db, 1).Record.Header.RequiredApprovals; got != max(n, 1) {
				t.Fatalf("threshold=%d", got)
			}
		})
	}
	e, db, _ := approvalEngineFixture(t, false)
	for _, draft := range []ap.ApprovalDraft{
		statetest.JobDraft(statetest.ID(1), ap.CoordinatorExecutor, statetest.T0, statetest.Write("true", 61)),
		statetest.JobDraft(statetest.ID(2), ap.CoordinatorExecutor, statetest.T0, statetest.Write("SSHGATE_XFER_SEND x", 60)),
	} {
		if _, err := e.Submit(context.Background(), "client", "", draft); err == nil {
			t.Fatal("invalid draft accepted")
		}
	}
	draft := approvalDraft(3)
	draft.ExecutorClaimTokenHash = ""
	if _, err := e.Submit(context.Background(), "client", "", draft); err == nil {
		t.Fatal("missing claim hash accepted")
	}
	rows, err := db.ListV2(context.Background(), "client", "", nil, 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("invalid intake persisted: %d %v", len(rows), err)
	}
}

func TestApprovalV2MixedQuotaUsesSlots(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	ctx := context.Background()
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<99)
 INSERT INTO requests(request_id,status,client_id,commands,created_at) SELECT 'legacy-'||n,'pending','client','[]',? FROM ids`, statetest.T0.Unix())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 1)
	tx, err = db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE approvals_v2 SET class='settled'`); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_, err = e.Submit(ctx, "client", "local-uid:1001", approvalDraft(2))
	requireApprovalCode(t, err, ap.CodeQueueFull)
	// Idempotency precedes admission, including a ceiling shared with v1.
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	if _, _, err = e.mutate(ctx, approvalKey(1), ap.AdminCancel{Admin: "operator", PlanHash: row.Record.Header.PlanHash}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE approvals_v2 SET class='live'`); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 2)
}

func TestApprovalV2GlobalQuotaAndFullCeiling(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprint(global), func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			ctx := context.Background()
			if global {
				tx, err := db.BeginV2(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				_, err = tx.ExecContext(ctx, `WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<1000)
 INSERT INTO requests(request_id,status,client_id,commands,created_at) SELECT 'legacy-'||n,'pending','other-'||n,'[]',? FROM ids`, statetest.T0.Unix())
				if err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			} else {
				e.config.MaxFullRows = 1
				submitApproval(t, e, 1)
			}
			_, err := e.Submit(ctx, "client", "", approvalDraft(2))
			requireApprovalCode(t, err, ap.CodeQueueFull)
			if _, err := db.ReadV2(ctx, approvalKey(2)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("quota row: %v", err)
			}
		})
	}
}

func TestApprovalV2MissingMutation(t *testing.T) {
	e, _, _ := approvalEngineFixture(t, false)
	_, _, err := e.mutate(context.Background(), approvalKey(1), ap.Tick{}, ap.Inputs{})
	requireApprovalCode(t, err, ap.CodeNotFound)
}

type approvalCountingStore struct {
	ApprovalV2Store
	puts, deletes int
	transactions  []*sql.Tx
}

func (s *approvalCountingStore) BeginV2(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.ApprovalV2Store.BeginV2(ctx)
	if err == nil {
		s.transactions = append(s.transactions, tx)
	}
	return tx, err
}

func (s *approvalCountingStore) PutV2(ctx context.Context, tx *sql.Tx, key sqlitestore.V2Key, record ap.R1, projection sqlitestore.V2Projection) error {
	s.puts++
	return s.ApprovalV2Store.PutV2(ctx, tx, key, record, projection)
}

func (s *approvalCountingStore) DeleteV2(ctx context.Context, tx *sql.Tx, key sqlitestore.V2Key) error {
	s.deletes++
	return s.ApprovalV2Store.DeleteV2(ctx, tx, key)
}

func TestApprovalV2NoOpRollsBackWithoutWrites(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	counting := &approvalCountingStore{ApprovalV2Store: db}
	e.config.Store = counting
	commits := 0
	e.commit = func(tx *sql.Tx) error {
		commits++
		return tx.Commit()
	}
	ctx := context.Background()
	for _, name := range []string{"replay", "tick", "flush", "delete"} {
		t.Run(name, func(t *testing.T) {
			if name == "replay" {
				submitApproval(t, e, 1)
			} else {
				commands := map[string]ap.Command{"tick": ap.Tick{}, "flush": ap.Flush{}, "delete": ap.Delete{Pressure: true}}
				_, answer, err := e.mutate(ctx, approvalKey(1), commands[name], ap.Inputs{})
				if err != nil || answer.Changed || answer.Removed {
					t.Fatalf("no-op: %+v %v", answer, err)
				}
			}
			if counting.puts != 0 || counting.deletes != 0 || commits != 0 {
				t.Fatalf("no-op wrote: puts=%d deletes=%d commits=%d", counting.puts, counting.deletes, commits)
			}
			for _, tx := range counting.transactions {
				if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
					t.Fatalf("transaction not rolled back: %v", err)
				}
			}
		})
	}
}

func TestApprovalV2DeleteDoesNotAdvanceClock(t *testing.T) {
	for _, settled := range []bool{false, true} {
		t.Run(fmt.Sprint(settled), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			e.config.Settings.MaxAge = time.Hour
			ctx := context.Background()
			submitApproval(t, e, 1)
			if settled {
				row := readApproval(t, db, 1)
				if _, _, err := e.mutate(ctx, approvalKey(1), ap.AdminCancel{Admin: "operator", PlanHash: row.Record.Header.PlanHash}, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
				row = readApproval(t, db, 1)
				if _, _, err := e.mutate(ctx, approvalKey(1), ap.Flush{Through: row.Record.Header.OutboxSeq}, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
			}
			before := readApproval(t, db, 1)
			if before.Record.Header.Assist != nil || settled && ap.Unflushed(before.Record) {
				t.Fatal("fixture must precede assist deadline and have flushed cancellation")
			}
			clock.Advance(48 * time.Hour)
			_, answer, err := e.mutate(ctx, approvalKey(1), ap.Delete{Pressure: true}, ap.Inputs{})
			if err != nil || answer.Removed != settled || answer.Changed {
				t.Fatalf("delete: %+v %v", answer, err)
			}
			if settled {
				if _, err := db.ReadV2(ctx, approvalKey(1)); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("deleted row: %v", err)
				}
			} else if !bytes.Equal(before.RecordJSON, readApproval(t, db, 1).RecordJSON) {
				t.Fatal("protected Delete changed record")
			}
		})
	}
}
