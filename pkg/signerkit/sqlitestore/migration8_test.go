package sqlitestore

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

func TestMigration8LegacyEvidenceUpgradeAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate a version-7 database, including a historical expiry. No backfill.
	migration7Exec(t, db.db, `DROP TABLE legacy_expiry_outbox`)
	migration7Exec(t, db.db, `DELETE FROM schema_migrations WHERE version=8`)
	migration7Exec(t, db.db, `INSERT INTO requests(request_id,status,client_id,commands,created_at,resolved_at,terminal_reason) VALUES ('historical','error','client','[]',1,2,'expired')`)
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.db.QueryRow(`SELECT count(*) FROM legacy_expiry_outbox`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("backfill: %d %v", count, err)
	}
	migration7Exec(t, db.db, `INSERT INTO requests(request_id,status,client_id,commands,created_at,request_expires_at) VALUES ('pending','pending','client','[]',1,2)`)
	migration7Exec(t, db.db, `INSERT INTO approvals VALUES ('pending','operator','approve','totp',1,0)`)
	changed, _, err := db.ExpireLegacy(context.Background(), "pending", time.Unix(3, 0))
	if err != nil || !changed {
		t.Fatalf("expire: %v %v", changed, err)
	}
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var key string
	var at int64
	var evidence []byte
	if err = db.db.QueryRow(`SELECT event_key,resolved_at,evidence FROM legacy_expiry_outbox`).Scan(&key, &at, &evidence); err != nil {
		t.Fatal(err)
	}
	var votes []*store.Vote
	if err = json.Unmarshal(evidence, &votes); err != nil {
		t.Fatal(err)
	}
	if key == "" || at != 3 || len(votes) != 1 || votes[0].Audited || votes[0].Operator != "operator" {
		t.Fatalf("evidence: %s %d %+v", key, at, votes)
	}
	changed, _, err = db.ExpireLegacy(context.Background(), "pending", time.Unix(4, 0))
	if err != nil || changed {
		t.Fatalf("expiry replay: %v %v", changed, err)
	}
	if err = db.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE '%expiry%'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("runtime trigger: %d %v", count, err)
	}
}

func TestLegacyExpiryOutboxFailureRollsBackTerminal(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migration7Exec(t, db.db, `INSERT INTO requests(request_id,status,client_id,commands,created_at,request_expires_at) VALUES ('pending','pending','client','[]',1,2)`)
	migration7Exec(t, db.db, `DROP TABLE legacy_expiry_outbox`)
	if _, _, err = db.ExpireLegacy(context.Background(), "pending", time.Unix(3, 0)); err == nil {
		t.Fatal("missing outbox accepted")
	}
	row, err := db.GetByID(context.Background(), "pending")
	if err != nil || row.Status != store.StatusPending {
		t.Fatalf("expiry without evidence: %+v %v", row, err)
	}
}
