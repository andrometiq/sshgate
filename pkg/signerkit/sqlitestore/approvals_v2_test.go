package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func fixtureV2(t *testing.T, id int, client, sub string) ap.R1 {
	t.Helper()
	draft := statetest.JobDraft(statetest.ID(id), ap.CoordinatorExecutor, statetest.T0, statetest.Write("true", 60))
	cmd := statetest.SubmitOf(draft, client, statetest.T0, ap.ValidityMin)
	cmd.Plan.RequesterSub = sub
	rec, ans := ap.Apply(nil, cmd, ap.Now{Wall: statetest.T0}, ap.Inputs{Epoch: statetest.Epoch(1), Settings: v2TestSettings()})
	if !ans.Changed {
		t.Fatalf("submit: %+v", ans)
	}
	return rec
}

func projectionV2(now time.Time) V2Projection {
	return V2Projection{Now: ap.Now{Wall: now}, Epoch: statetest.Epoch(1), Settings: v2TestSettings()}
}

func putV2(t *testing.T, db *DB, rec ap.R1) {
	t.Helper()
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := db.PutV2(context.Background(), tx, keyV2(rec), rec, projectionV2(statetest.T0)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestV2TransactionRoundTrip(t *testing.T) {
	db := legacyDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rec := fixtureV2(t, 1, "client", "")
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := db.PutV2(ctx, tx, keyV2(rec), rec, projectionV2(statetest.T0)); err != nil {
		t.Fatal(err)
	}
	row, err := db.GetV2(ctx, tx, keyV2(rec))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := ap.EncodeR1(rec)
	if !bytes.Equal(row.RecordJSON, encoded) {
		t.Fatal("canonical bytes changed")
	}
	counts, err := db.CountV2(ctx, tx)
	if err != nil || counts != (V2Counts{1, 1}) {
		t.Fatalf("counts=%+v: %v", counts, err)
	}
	if err := db.DeleteV2(ctx, tx, keyV2(rec)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetV2(ctx, tx, keyV2(rec)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(ctx, keyV2(rec)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rollback: %v", err)
	}
	putV2(t, db, rec)
	tx, err = db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := db.DeleteV2(ctx, tx, keyV2(rec)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(ctx, keyV2(rec)); err != nil {
		t.Fatal("delete escaped rollback", err)
	}
	tx, err = db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := db.DeleteV2(ctx, tx, keyV2(rec)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(ctx, keyV2(rec)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("committed delete: %v", err)
	}
}

func TestV2PlainReadsUnderWriter(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "wal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec := fixtureV2(t, 1, "client", "local-uid:1")
	putV2(t, db, rec)
	handle := ap.RecordHandle(ap.RecordKeyOf(rec.Header, true))
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Hide a deletion behind an active writer. Every plain read must still see
	// the last committed pending row, including when asked for a much later due pass.
	if err := db.DeleteV2(context.Background(), tx, keyV2(rec)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	check := func(row *V2Row, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := ap.EncodeR1(rec)
		if !bytes.Equal(row.RecordJSON, encoded) || row.Record.Header.Decision != nil {
			t.Fatal("plain read advanced or changed committed state")
		}
	}
	check(db.ReadV2(ctx, keyV2(rec)))
	check(db.ByHandleV2(ctx, handle))
	for _, read := range []func() ([]*V2Row, error){
		func() ([]*V2Row, error) { return db.ListV2(ctx, "client", "local-uid:1", nil, 10) },
		func() ([]*V2Row, error) { return db.DueV2(ctx, statetest.T0.Add(48*time.Hour), 10) },
		func() ([]*V2Row, error) { return db.UnflushedV2(ctx, 10) },
	} {
		rows, err := read()
		if err != nil || len(rows) != 1 {
			t.Fatalf("plain list length=%d: %v", len(rows), err)
		}
		check(rows[0], nil)
	}
	rows, err := db.RecentDecidedV2(ctx, 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("recent: %d %v", len(rows), err)
	}
}

func TestV2ListingAndHandleCollision(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	for i := 1; i <= 4; i++ {
		putV2(t, db, fixtureV2(t, i, "client", "local-uid:1"))
	}
	putV2(t, db, fixtureV2(t, 1, "other", "local-uid:1"))
	putV2(t, db, fixtureV2(t, 1, "client", "local-uid:2"))
	isolated, err := db.ListV2(ctx, "client", "local-uid:1", nil, 100)
	if err != nil || len(isolated) != 4 {
		t.Fatalf("scoped listing: %d rows: %v", len(isolated), err)
	}
	for _, row := range isolated {
		if row.Key.ClientID != "client" || row.Key.SubPrincipal != "local-uid:1" {
			t.Fatal("listing crossed identity boundary")
		}
	}
	var cursor *V2Cursor
	for i := 1; i <= 4; i++ {
		rows, err := db.ListV2(ctx, "client", "local-uid:1", cursor, 1)
		if err != nil || len(rows) != 1 || rows[0].Key.RequestID != statetest.ID(i) {
			t.Fatalf("page %d: %+v %v", i, rows, err)
		}
		cursor = &V2Cursor{rows[0].Record.Header.CreatedAt, rows[0].Key.RequestID}
	}
	rows, err := db.ListV2(ctx, "client", "local-uid:1", cursor, 1)
	if err != nil || len(rows) != 0 {
		t.Fatal("pagination end", err)
	}
	if _, err := db.ByHandleV2(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE approvals_v2 SET record_handle='collision' WHERE client_id='client' AND sub_principal='local-uid:1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ByHandleV2(ctx, "collision"); !errors.Is(err, ErrV2AmbiguousHandle) {
		t.Fatalf("collision: %v", err)
	}
	if limitV2(-1) != 100 || limitV2(300) != 256 || limitV2(1) != 1 {
		t.Fatal("unbounded list")
	}
}

func TestV2RejectsCorruptRecords(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	rec := fixtureV2(t, 1, "client", "")
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	wrong := keyV2(rec)
	wrong.SubPrincipal = "other"
	if err := db.PutV2(ctx, tx, wrong, rec, projectionV2(statetest.T0)); err == nil {
		t.Fatal("accepted wrong key")
	}
	bad := rec
	bad.Header.Version = 99
	if err := db.PutV2(ctx, tx, keyV2(bad), bad, projectionV2(statetest.T0)); err == nil {
		t.Fatal("accepted corrupt record")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	putV2(t, db, rec)
	if _, err := db.db.Exec(`UPDATE approvals_v2 SET sub_principal='other'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(ctx, wrong); err == nil {
		t.Fatal("returned mismatched stored identity")
	}
	if _, err := db.db.Exec(`UPDATE approvals_v2 SET record_json='{}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadV2(ctx, wrong); err == nil {
		t.Fatal("returned corrupt stored record")
	}
}

func TestV2ConcurrentAdmission(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ceiling.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const ceiling = 3
	records := make([]ap.R1, 12)
	for i := range records {
		records[i] = fixtureV2(t, i+1, "client", "")
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(records))
	for _, rec := range records {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := db.BeginV2(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback()
			counts, err := db.CountV2(ctx, tx)
			if err != nil {
				errs <- err
				return
			}
			if counts.All >= ceiling {
				return
			}
			if err := db.PutV2(ctx, tx, keyV2(rec), rec, projectionV2(statetest.T0)); err != nil {
				errs <- err
				return
			}
			errs <- tx.Commit()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	counts, err := db.CountV2(context.Background(), tx)
	if err != nil || counts != (V2Counts{ceiling, ceiling}) {
		t.Fatalf("admission: %+v %v", counts, err)
	}
}

func TestV2UnflushedOrderAndIndex(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	for i := 1; i <= 4; i++ {
		putV2(t, db, fixtureV2(t, i, "client", ""))
	}
	// Scheduling is worker-maintained; include a retry with no time-driven work.
	for i, due := range []any{nil, int64(20), int64(10), int64(1)} {
		if _, err := db.db.Exec(`UPDATE approvals_v2 SET next_due_at=?,audited_complete=? WHERE request_id=?`, due, i == 3, statetest.ID(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.UnflushedV2(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("unflushed count=%d", len(rows))
	}
	for i, id := range []int{3, 2, 1} {
		if rows[i].Key.RequestID != statetest.ID(id) {
			t.Fatal("wrong flush order")
		}
	}
	rows, err = db.DueV2(ctx, time.Unix(10, 0), 10)
	if err != nil || len(rows) != 2 || rows[1].Key.RequestID != statetest.ID(3) {
		t.Fatalf("due boundary: %v %v", rows, err)
	}
	plan, err := db.db.Query(`EXPLAIN QUERY PLAN `+unflushedV2Query, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	var details string
	for plan.Next() {
		var a, b, c int
		var detail string
		if err := plan.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		details += detail
	}
	if err := plan.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, "idx_approvals_v2_unflushed") {
		t.Fatalf("partial index unused: %s", details)
	}
}

func TestV2NilTransactions(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	rec := fixtureV2(t, 1, "client", "")
	if err := db.PutV2(ctx, nil, keyV2(rec), rec, projectionV2(statetest.T0)); err == nil {
		t.Fatal("nil Put")
	}
	if _, err := db.GetV2(ctx, nil, keyV2(rec)); err == nil {
		t.Fatal("nil Get")
	}
	if err := db.DeleteV2(ctx, nil, keyV2(rec)); err == nil {
		t.Fatal("nil Delete")
	}
	if _, err := db.CountV2(ctx, nil); err == nil {
		t.Fatal("nil Count")
	}
}

func v2TestSettings() ap.Settings { s := ap.LocalSettings; s.Hosted = true; return s }

func TestV2RecentDecidedAndUpsert(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		rec := fixtureV2(t, i, "client", "")
		putV2(t, db, rec)
		rec, ans := ap.Apply(&rec, ap.AdminCancel{Admin: "admin", PlanHash: rec.Header.PlanHash}, ap.Now{Wall: statetest.T0.Add(time.Duration(i) * time.Second)}, ap.Inputs{Epoch: statetest.Epoch(1), Settings: v2TestSettings()})
		if !ans.Changed {
			t.Fatalf("cancel: %+v", ans)
		}
		putV2(t, db, rec)
	}
	putV2(t, db, fixtureV2(t, 4, "client", ""))
	rows, err := db.RecentDecidedV2(ctx, 2)
	if err != nil || len(rows) != 2 {
		t.Fatalf("recent: %v %v", rows, err)
	}
	for i, id := range []int{3, 2} {
		if rows[i].Key.RequestID != statetest.ID(id) || rows[i].ViewStatus != "canceled" {
			t.Fatalf("recent order/status: %+v", rows[i])
		}
	}
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	counts, err := db.CountV2(ctx, tx)
	if err != nil || counts.All != 4 {
		t.Fatalf("upsert counts: %+v %v", counts, err)
	}
}
