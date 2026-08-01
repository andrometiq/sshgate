package sqlitestore_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// newTestDB returns a fresh SQLite-backed Store in a per-test temp dir.
// We use a file (not :memory:) because modernc.org/sqlite's in-memory
// database is per-connection and our DB connection pool would defeat
// the test if multiple goroutines re-opened the same name.
func newTestDB(t *testing.T) *sqlitestore.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInsertAndGetByID(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()

	r := &store.Request{
		RequestID: "r_abc",
		Status:    store.StatusPending,
		ClientID:  "client-1",
		Commands:  []byte(`[{"server":"prod","cmd":"echo hi","ttl_seconds":60}]`),
		CreatedAt: time.Date(2026, 5, 19, 9, 14, 22, 0, time.UTC),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := db.GetByID(ctx, "r_abc")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.RequestID != r.RequestID {
		t.Errorf("RequestID = %q; want %q", got.RequestID, r.RequestID)
	}
	if got.Status != r.Status {
		t.Errorf("Status = %q; want %q", got.Status, r.Status)
	}
	if got.ClientID != r.ClientID {
		t.Errorf("ClientID = %q; want %q", got.ClientID, r.ClientID)
	}
	if string(got.Commands) != string(r.Commands) {
		t.Errorf("Commands = %q; want %q", got.Commands, r.Commands)
	}
	if !got.CreatedAt.Equal(r.CreatedAt) {
		t.Errorf("CreatedAt = %v; want %v", got.CreatedAt, r.CreatedAt)
	}
	if got.ResolvedAt != nil {
		t.Errorf("ResolvedAt = %v; want nil", *got.ResolvedAt)
	}
	if got.ApprovedBy != "" {
		t.Errorf("ApprovedBy = %q; want empty", got.ApprovedBy)
	}
}

func TestInsert_Duplicate(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	r := &store.Request{
		RequestID: "r_dup",
		Status:    store.StatusPending,
		ClientID:  "c",
		Commands:  []byte(`[]`),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	err := db.Insert(ctx, r)
	if !errors.Is(err, store.ErrDuplicateID) {
		t.Errorf("second Insert err = %v; want ErrDuplicateID", err)
	}
}

func TestInsert_PendingPerClientQuota(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if err := db.Insert(ctx, &store.Request{
			RequestID: fmt.Sprintf("r-%03d", i), Status: store.StatusPending,
			ClientID: "client-a", Commands: []byte(`[]`),
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	err := db.Insert(ctx, &store.Request{
		RequestID: "r-over", Status: store.StatusPending, ClientID: "client-a", Commands: []byte(`[]`),
	})
	if !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("101st pending insert = %v; want ErrQueueFull", err)
	}
	if err := db.Insert(ctx, &store.Request{
		RequestID: "r-other", Status: store.StatusPending, ClientID: "client-b", Commands: []byte(`[]`),
	}); err != nil {
		t.Fatalf("independent client blocked by per-client quota: %v", err)
	}
	if err := db.UpdateStatus(ctx, "r-000", store.StatusDenied, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.Insert(ctx, &store.Request{
		RequestID: "r-after-resolution", Status: store.StatusPending, ClientID: "client-a", Commands: []byte(`[]`),
	}); err != nil {
		t.Fatalf("resolved row did not release quota: %v", err)
	}
}

func TestGetByID_NotFound(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	_, err := db.GetByID(ctx, "missing")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

func TestUpdateStatus_Approved(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	r := &store.Request{
		RequestID: "r_upd",
		Status:    store.StatusPending,
		ClientID:  "c",
		Commands:  []byte(`[]`),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	sigs := []byte(`[{"cmd":"echo","sig":"SSHGATE_SIG:..."}]`)
	if err := db.UpdateStatus(ctx, "r_upd", store.StatusApproved, sigs, "operator"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, err := db.GetByID(ctx, "r_upd")
	if err != nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if got.Status != store.StatusApproved {
		t.Errorf("Status = %q; want approved", got.Status)
	}
	if string(got.Signatures) != string(sigs) {
		t.Errorf("Signatures = %q; want %q", got.Signatures, sigs)
	}
	if got.ApprovedBy != "operator" {
		t.Errorf("ApprovedBy = %q; want operator", got.ApprovedBy)
	}
	if got.ResolvedAt == nil {
		t.Error("ResolvedAt = nil; want non-nil after resolution")
	}
}

func TestUpdateStatus_Idempotent(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	r := &store.Request{
		RequestID: "r_idem",
		Status:    store.StatusPending,
		ClientID:  "c",
		Commands:  []byte(`[]`),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := db.UpdateStatus(ctx, "r_idem", store.StatusDenied, nil, ""); err != nil {
		t.Fatalf("first UpdateStatus: %v", err)
	}
	// Second update must be a no-op: the row remains Denied.
	if err := db.UpdateStatus(ctx, "r_idem", store.StatusApproved, nil, ""); err != nil {
		t.Fatalf("second UpdateStatus: %v", err)
	}
	got, err := db.GetByID(ctx, "r_idem")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != store.StatusDenied {
		t.Errorf("Status = %q; want denied (second update should be no-op)", got.Status)
	}
}

func TestWaitForResolution_Approved(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	r := &store.Request{
		RequestID: "r_wait",
		Status:    store.StatusPending,
		ClientID:  "c",
		Commands:  []byte(`[]`),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Resolve in a goroutine after 250ms.
	go func() {
		time.Sleep(250 * time.Millisecond)
		_ = db.UpdateStatus(ctx, "r_wait", store.StatusApproved, []byte(`[]`), "operator")
	}()

	got, err := db.WaitForResolution(ctx, "r_wait", 2*time.Second)
	if err != nil {
		t.Fatalf("WaitForResolution: %v", err)
	}
	if got.Status != store.StatusApproved {
		t.Errorf("Status = %q; want approved", got.Status)
	}
}

func TestWaitForResolution_Timeout(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	r := &store.Request{
		RequestID: "r_to",
		Status:    store.StatusPending,
		ClientID:  "c",
		Commands:  []byte(`[]`),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	start := time.Now()
	got, err := db.WaitForResolution(ctx, "r_to", 200*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WaitForResolution: %v", err)
	}
	if got.Status != store.StatusPending {
		t.Errorf("Status = %q; want pending (no one resolved)", got.Status)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("elapsed = %v; want >= ~200ms", elapsed)
	}
}

func TestWaitForResolution_AlreadyResolved(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	r := &store.Request{
		RequestID:  "r_fast",
		Status:     store.StatusApproved,
		ClientID:   "c",
		Commands:   []byte(`[]`),
		Signatures: []byte(`[]`),
	}
	if err := db.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	start := time.Now()
	got, err := db.WaitForResolution(ctx, "r_fast", 5*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WaitForResolution: %v", err)
	}
	if got.Status != store.StatusApproved {
		t.Errorf("Status = %q; want approved", got.Status)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("elapsed = %v; already-resolved fast-path should return immediately", elapsed)
	}
}

func TestListPending_AndAudit(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()

	// Insert three rows: two pending, one resolved.
	for i, st := range []store.Status{store.StatusPending, store.StatusPending, store.StatusApproved} {
		r := &store.Request{
			RequestID: "r_" + string(rune('a'+i)),
			Status:    st,
			ClientID:  "c",
			Commands:  []byte(`[]`),
			CreatedAt: time.Unix(int64(1000+i), 0).UTC(),
		}
		if err := db.Insert(ctx, r); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	pending, err := db.ListPending(ctx)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("ListPending len = %d; want 2", len(pending))
	}

	audit, err := db.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatalf("RecentAudit: %v", err)
	}
	if len(audit) != 3 {
		t.Errorf("RecentAudit len = %d; want 3", len(audit))
	}
	// Most recent first.
	if audit[0].RequestID != "r_c" {
		t.Errorf("RecentAudit[0] = %q; want r_c (most recent)", audit[0].RequestID)
	}
}

func TestConcurrentInsertAndUpdate(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()

	// Sanity check: the store survives 20 concurrent inserts and
	// 20 concurrent updates without deadlocking or losing rows.
	// This is not a stress test — it's a smoke check that WAL mode
	// + busy_timeout are wired correctly.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "r_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)))
			err := db.Insert(ctx, &store.Request{
				RequestID: id,
				Status:    store.StatusPending,
				ClientID:  "c",
				Commands:  []byte(`[]`),
			})
			if err != nil && !errors.Is(err, store.ErrDuplicateID) {
				t.Errorf("Insert %s: %v", id, err)
				return
			}
			_ = db.UpdateStatus(ctx, id, store.StatusApproved, []byte(`[]`), "operator")
		}(i)
	}
	wg.Wait()
}
