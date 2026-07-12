package sqlitestore_test

import (
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/storetest"
)

// TestSQLiteStore_Conformance runs the signerkit Store conformance hammer
// against the SQLite reference implementation. It is the executable proof that
// the impl's `UPDATE ... WHERE status='pending'` satisfies the C10 atomic-CAS
// single-sign guarantee: concurrent approve/deny transitions resolve to exactly
// one immutable winner.
func TestSQLiteStore_Conformance(t *testing.T) {
	t.Parallel()
	storetest.RunConcurrentFlip(t, func(t *testing.T) store.Store {
		db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "conformance.db"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	})
}
