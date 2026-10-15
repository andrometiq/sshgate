package sqlitestore

import (
	"context"
	"fmt"
)

const approvalMigration7SQL = `
CREATE TRIGGER IF NOT EXISTS users_role_insert
BEFORE INSERT ON users
WHEN NEW.role NOT IN ('operator','admin')
BEGIN
  SELECT RAISE(ABORT,'sshgate: users.role must be operator or admin');
END;
CREATE TRIGGER IF NOT EXISTS users_role_update
BEFORE UPDATE OF role ON users
WHEN NEW.role NOT IN ('operator','admin')
BEGIN
  SELECT RAISE(ABORT,'sshgate: users.role must be operator or admin');
END;
CREATE TABLE IF NOT EXISTS approvals_v2 (
  client_id TEXT NOT NULL,
  sub_principal TEXT NOT NULL,
  request_id TEXT NOT NULL,
  record_json BLOB NOT NULL CHECK (length(CAST(record_json AS BLOB)) <= 524288),
  decision_status TEXT,
  decided_at INTEGER,
  mint_state TEXT NOT NULL CHECK (mint_state IN ('none','bytes','erased','error')),
  mint_error_reason TEXT,
  last_window_end INTEGER,
  claim_count INTEGER NOT NULL,
  final_class TEXT,
  audited_complete INTEGER NOT NULL CHECK (audited_complete IN (0,1)),
  shed INTEGER NOT NULL CHECK (shed IN (0,1)),
  payload_bytes INTEGER NOT NULL,
  submit_not_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  request_expires_at INTEGER NOT NULL,
  view_status TEXT NOT NULL,
  class TEXT NOT NULL,
  next_due_at INTEGER,
  record_handle TEXT NOT NULL,
  PRIMARY KEY (client_id, sub_principal, request_id)
);
CREATE INDEX IF NOT EXISTS idx_approvals_v2_listing ON approvals_v2(client_id, sub_principal, created_at);
CREATE INDEX IF NOT EXISTS idx_approvals_v2_due ON approvals_v2(next_due_at);
CREATE INDEX IF NOT EXISTS idx_approvals_v2_full ON approvals_v2(created_at) WHERE shed = 0;
CREATE INDEX IF NOT EXISTS idx_approvals_v2_delete ON approvals_v2(submit_not_after);
CREATE INDEX IF NOT EXISTS idx_approvals_v2_handle ON approvals_v2(record_handle);
CREATE INDEX IF NOT EXISTS idx_approvals_v2_decided ON approvals_v2(decided_at);
CREATE INDEX IF NOT EXISTS idx_approvals_v2_unflushed ON approvals_v2(next_due_at) WHERE audited_complete = 0;
`

func applyMigration7(ctx context.Context, connection migrationExecutor, remainingSQL string) error {
	// Ledger repair can reach this step without migration 2's users table.
	if _, err := connection.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  role        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);`); err != nil {
		return fmt.Errorf("create users: %w", err)
	}
	var invalidRoles int
	if err := connection.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role NOT IN ('operator','admin')`).Scan(&invalidRoles); err != nil {
		return fmt.Errorf("check users roles: %w", err)
	}
	if invalidRoles != 0 {
		return fmt.Errorf("sshgate: users.role must be operator or admin")
	}
	for _, column := range []struct{ name, definition string }{
		{"request_expires_at", "INTEGER"},
		{"terminal_reason", "TEXT CHECK (terminal_reason IS NULL OR terminal_reason IN ('expired','canceled'))"},
	} {
		exists, err := tableHasColumn(ctx, connection, "requests", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := connection.ExecContext(ctx, "ALTER TABLE requests ADD COLUMN "+column.name+" "+column.definition); err != nil {
				return fmt.Errorf("add requests.%s: %w", column.name, err)
			}
		}
	}
	if _, err := connection.ExecContext(ctx, `UPDATE requests SET request_expires_at = created_at + 86400 WHERE status = 'pending' AND request_expires_at IS NULL`); err != nil {
		return fmt.Errorf("backfill legacy request expiry: %w", err)
	}
	if _, err := connection.ExecContext(ctx, remainingSQL); err != nil {
		return fmt.Errorf("apply approval lifecycle schema: %w", err)
	}
	return nil
}
