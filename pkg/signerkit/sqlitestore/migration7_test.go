package sqlitestore

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func migration7Fixture(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v6.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	for _, migration := range migrations {
		if migration.Version < 7 {
			if err := applyOne(raw, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	return raw, path
}

func migration7Exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestMigration7UpgradeAndRepair(t *testing.T) {
	raw, path := migration7Fixture(t)
	migration7Exec(t, raw, `INSERT INTO requests(request_id,status,client_id,commands,signatures,created_at,resolved_at,approved_by) VALUES
 ('pending','pending','client','[]',NULL,123,NULL,NULL),
 ('terminal','approved','client','[]','["signature"]',100,200,'voter')`)
	migration7Exec(t, raw, `INSERT INTO users VALUES ('voter','voter','operator',1)`)
	migration7Exec(t, raw, `INSERT INTO approvals VALUES ('pending','voter','approve','totp',124,0)`)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var expiry int64
	if err := db.db.QueryRow(`SELECT request_expires_at FROM requests WHERE request_id='pending'`).Scan(&expiry); err != nil || expiry != 86523 {
		t.Fatalf("expiry=%d err=%v", expiry, err)
	}
	var terminalExpiry, reason sql.NullString
	var signatures, approvedBy, status string
	var resolved int64
	if err := db.db.QueryRow(`SELECT request_expires_at,terminal_reason,signatures,approved_by,status,resolved_at FROM requests WHERE request_id='terminal'`).Scan(&terminalExpiry, &reason, &signatures, &approvedBy, &status, &resolved); err != nil {
		t.Fatal(err)
	}
	if terminalExpiry.Valid || reason.Valid || signatures != `["signature"]` || approvedBy != "voter" || status != "approved" || resolved != 200 {
		t.Fatal("terminal row changed")
	}
	var audited int
	if err := db.db.QueryRow(`SELECT audited FROM approvals WHERE request_id='pending'`).Scan(&audited); err != nil || audited != 0 {
		t.Fatalf("vote changed: %d %v", audited, err)
	}
	migration7Exec(t, db.db, `UPDATE requests SET request_expires_at=999999 WHERE request_id='pending'`)
	migration7Exec(t, db.db, `DELETE FROM schema_migrations WHERE version=7`)
	if err := runMigrations(db.db); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(db.db); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT request_expires_at FROM requests WHERE request_id='pending'`).Scan(&expiry); err != nil || expiry != 999999 {
		t.Fatalf("reapply overwrote expiry: %d %v", expiry, err)
	}
	for _, reason := range []any{nil, "expired", "canceled"} {
		migration7Exec(t, db.db, `UPDATE requests SET terminal_reason=? WHERE request_id='pending'`, reason)
	}
	if _, err := db.db.Exec(`UPDATE requests SET terminal_reason='invalid' WHERE request_id='pending'`); err == nil {
		t.Fatal("invalid terminal reason accepted")
	}
}

func TestMigration7RoleGuards(t *testing.T) {
	for _, missingUsers := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "ledger-repair"}[missingUsers], func(t *testing.T) {
			raw, path := migration7Fixture(t)
			if missingUsers {
				migration7Exec(t, raw, `DROP TABLE users`)
			}
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			for _, role := range []string{"operator", "admin"} {
				migration7Exec(t, db.db, `INSERT INTO users VALUES (?,?,?,1)`, role, role, role)
			}
			for _, query := range []string{
				`INSERT INTO users VALUES ('bad','bad','auditor',1)`,
				`UPDATE users SET role='auditor' WHERE id='operator'`,
			} {
				if _, err := db.db.Exec(query); err == nil || !strings.Contains(err.Error(), "sshgate: users.role must be operator or admin") {
					t.Fatalf("role guard: %v", err)
				}
			}
			migration7Exec(t, db.db, `UPDATE users SET role='admin' WHERE id='operator'`)
		})
	}
}

func TestMigration7RejectsExistingBadRoleAtomically(t *testing.T) {
	raw, path := migration7Fixture(t)
	migration7Exec(t, raw, `INSERT INTO users VALUES ('bad','bad','auditor',1)`)
	db, err := Open(path)
	if db != nil {
		db.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "sshgate: users.role must be operator or admin") {
		t.Fatalf("bad role open: %v", err)
	}
	var count int
	if err := raw.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=7`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("migration recorded: %d %v", count, err)
	}
	exists, err := tableHasColumn(context.Background(), raw, "requests", "request_expires_at")
	if err != nil || exists {
		t.Fatalf("partial migration: %v %v", exists, err)
	}
	migration7Exec(t, raw, `UPDATE users SET role='operator'`)
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

const migration7InsertV2 = `INSERT INTO approvals_v2 (
 client_id,sub_principal,request_id,record_json,mint_state,claim_count,audited_complete,shed,payload_bytes,
 submit_not_after,created_at,request_expires_at,view_status,class,record_handle
) VALUES ('client',?,? ,?,'none',0,0,0,2,100,1,200,'pending','live','shared-handle')`

func TestMigration7V2Schema(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, key := range [][2]string{{"sub1", "id1"}, {"sub2", "id1"}, {"sub1", "id2"}} {
		migration7Exec(t, db.db, migration7InsertV2, key[0], key[1], []byte("{}"))
	}
	if _, err := db.db.Exec(migration7InsertV2, "sub1", "id1", []byte("{}")); err == nil {
		t.Fatal("duplicate key accepted")
	}
	migration7Exec(t, db.db, migration7InsertV2, "sub1", "max", make([]byte, 524288))
	if _, err := db.db.Exec(migration7InsertV2, "sub1", "large", make([]byte, 524289)); err == nil {
		t.Fatal("oversize record accepted")
	}
	for _, assignment := range []string{"mint_state='unknown'", "audited_complete=2", "shed=2"} {
		if _, err := db.db.Exec(`UPDATE approvals_v2 SET ` + assignment); err == nil {
			t.Fatalf("invalid slot accepted: %s", assignment)
		}
	}
	migration7Exec(t, db.db, `UPDATE approvals_v2 SET mint_state='error',mint_error_reason='window_closed',decision_status='approved',decided_at=3,last_window_end=4,final_class='failed',next_due_at=5`)
	for name, fragment := range map[string]string{
		"listing": "(client_id, sub_principal, created_at)", "due": "(next_due_at)",
		"full": "WHERE shed = 0", "delete": "(submit_not_after)", "handle": "(record_handle)",
		"decided": "(decided_at)", "unflushed": "WHERE audited_complete = 0",
	} {
		var ddl string
		if err := db.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, "idx_approvals_v2_"+name).Scan(&ddl); err != nil || !strings.Contains(ddl, fragment) {
			t.Fatalf("index %s: %q %v", name, ddl, err)
		}
	}
}

func TestMigration7SynchronousFull(t *testing.T) {
	for _, path := range []string{":memory:", filepath.Join(t.TempDir(), "full.db")} {
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer db.Close()
			ctx := context.Background()
			conn, err := db.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var synchronous int
			if err := conn.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil || synchronous != 2 {
				t.Fatalf("synchronous=%d err=%v", synchronous, err)
			}
			if path != ":memory:" {
				second, err := db.db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
				if err := second.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil || synchronous != 2 {
					t.Fatalf("second connection synchronous=%d err=%v", synchronous, err)
				}
			}
		}()
	}
}

func TestMigration7PartialColumnRepair(t *testing.T) {
	for _, column := range []string{"request_expires_at INTEGER", "terminal_reason TEXT CHECK (terminal_reason IS NULL OR terminal_reason IN ('expired','canceled'))"} {
		t.Run(strings.Fields(column)[0], func(t *testing.T) {
			raw, path := migration7Fixture(t)
			migration7Exec(t, raw, `ALTER TABLE requests ADD COLUMN `+column)
			migration7Exec(t, raw, `INSERT INTO requests(request_id,status,client_id,commands,created_at) VALUES ('pending','pending','client','[]',10)`)
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var expiry int64
			var reason sql.NullString
			if err := db.db.QueryRow(`SELECT request_expires_at,terminal_reason FROM requests`).Scan(&expiry, &reason); err != nil || expiry != 86410 || reason.Valid {
				t.Fatalf("partial repair: expiry=%d reason=%v err=%v", expiry, reason, err)
			}
		})
	}
}
