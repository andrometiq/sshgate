package sqlitestore_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

func TestOpenRefusesGroupOrWorldReadableDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitestore.Open(path); err == nil || !strings.Contains(err.Error(), "group/world bits must be off") {
		t.Fatalf("Open(0644) err=%v; want insecure-mode refusal", err)
	}
}

func TestOpenRefusesSymlinkAndURIDelimiterPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitestore.Open(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Open(symlink) err=%v; want refusal", err)
	}
	if _, err := sqlitestore.Open(filepath.Join(dir, "state.db?mode=memory")); err == nil || !strings.Contains(err.Error(), "reserved URI delimiter") {
		t.Fatalf("Open(uri-delimiter path) err=%v; want refusal", err)
	}
}

func request(id string) *store.Request {
	return &store.Request{
		RequestID: id,
		Status:    store.StatusPending,
		ClientID:  "hardening",
		Commands:  []byte(`[]`),
		CreatedAt: time.Now().UTC(),
	}
}

// TestMemoryOpenConcurrentAndIsolated proves the documented :memory: mode is
// one coherent database under concurrent use, while two independent Open calls
// do not accidentally share rows.
func TestMemoryOpenConcurrentAndIsolated(t *testing.T) {
	db1, err := sqlitestore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open db1: %v", err)
	}
	t.Cleanup(func() { _ = db1.Close() })
	db2, err := sqlitestore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open db2: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	ctx := context.Background()
	// The same primary key must be independently insertable in each DB.
	if err := db1.Insert(ctx, request("same")); err != nil {
		t.Fatalf("db1 insert: %v", err)
	}
	if err := db2.Insert(ctx, request("same")); err != nil {
		t.Fatalf("db2 insert (memory DBs leaked into each other): %v", err)
	}

	const workers = 24
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("r-%d", i)
			if err := db1.Insert(ctx, request(id)); err != nil {
				errCh <- fmt.Errorf("insert %s: %w", id, err)
				return
			}
			if _, err := db1.GetByID(ctx, id); err != nil {
				errCh <- fmt.Errorf("get %s: %w", id, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestCloseConcurrentWithOperations pins Close's concurrency contract. Queries
// may either finish or observe database/sql's closed-handle error, but Close is
// idempotent, no caller panics, and the race detector sees no mutable db pointer.
func TestCloseConcurrentWithOperations(t *testing.T) {
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "close.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	if err := db.Insert(ctx, request("r-close")); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	start := make(chan struct{})
	const readers = 24
	const closers = 24
	var wg sync.WaitGroup
	closeErrs := make(chan error, closers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				if _, err := db.GetByID(ctx, "r-close"); err != nil {
					return // Close won; any non-panic error is an allowed outcome.
				}
			}
		}()
	}
	for i := 0; i < closers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			closeErrs <- db.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(closeErrs)
	for err := range closeErrs {
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if _, err := db.GetByID(ctx, "r-close"); err == nil {
		t.Fatal("GetByID after Close unexpectedly succeeded")
	}
}

// TestMigration2ReapplyWithMissingLedgerRow reproduces the abnormal adoption
// case: the migration-2 schema exists but its bookkeeping row is gone. Re-open
// must conditionally skip the already-present column, re-run the idempotent
// table DDL, and restore the ledger entry instead of failing duplicate-column.
func TestMigration2ReapplyWithMissingLedgerRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration2-reapply.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("initial Close: %v", err)
	}

	raw, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path))
	if err != nil {
		t.Fatalf("raw Open: %v", err)
	}
	if _, err := raw.Exec(`DELETE FROM schema_migrations WHERE version = 2`); err != nil {
		_ = raw.Close()
		t.Fatalf("delete migration-2 ledger row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("raw Close: %v", err)
	}

	db2, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("re-Open with applied schema/missing ledger: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	ctx := context.Background()
	if err := db2.Insert(ctx, request("after-reapply")); err != nil {
		t.Fatalf("Insert after migration-2 reapply: %v", err)
	}
	got, err := db2.GetByID(ctx, "after-reapply")
	if err != nil {
		t.Fatalf("Get after migration-2 reapply: %v", err)
	}
	if got.RequiredApprovals != 1 {
		t.Fatalf("required_approvals=%d; want 1", got.RequiredApprovals)
	}

	check, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path))
	if err != nil {
		t.Fatalf("check Open: %v", err)
	}
	defer check.Close()
	var count int
	if err := check.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version = 2`).Scan(&count); err != nil {
		t.Fatalf("read restored ledger: %v", err)
	}
	if count != 1 {
		t.Fatalf("migration-2 ledger rows=%d; want 1", count)
	}
}
