package sqlitestore

import (
	"database/sql"
	"fmt"
)

// migration is one ordered, idempotent schema step. Version is the
// monotonically-increasing identity recorded in schema_migrations; SQL
// is applied verbatim inside the migration transaction. Every statement
// in SQL MUST be written defensively (CREATE TABLE IF NOT EXISTS, etc.)
// so that a half-applied migration — or a fresh runner pointed at an
// already-migrated DB whose bookkeeping row somehow went missing — does
// not error on re-apply. The transaction + the schema_migrations guard
// make double-application a no-op in the normal path; the IF NOT EXISTS
// belt-and-braces covers the abnormal one.
//
// Migrations are NEVER edited once shipped: a change to an already-
// applied schema is a NEW migration with the next version. Editing an
// existing entry would silently diverge an already-migrated database
// from a freshly-migrated one. Append only.
type migration struct {
	Version int
	Name    string
	SQL     string
}

// migrations is the ordered ledger of schema steps. Index order does
// not matter — runMigrations sorts by Version — but keep the slice in
// Version order for readability. Version numbers start at 1.
//
// Migration 1 is the v2.0 baseline: the original `requests` table from
// the scaffold's single-schema string, reproduced verbatim so a DB that
// the scaffold already created (table present, no schema_migrations row)
// is adopted cleanly by the IF NOT EXISTS guards rather than colliding.
//
// Migration 2 adds the multi-operator + auth-backend tables and the
// per-request required_approvals threshold column.
var migrations = []migration{
	{
		Version: 1,
		Name:    "baseline_requests",
		SQL: `
CREATE TABLE IF NOT EXISTS requests (
  request_id   TEXT PRIMARY KEY,
  status       TEXT NOT NULL,
  client_id    TEXT NOT NULL,
  commands     TEXT NOT NULL,
  signatures   TEXT,
  created_at   INTEGER NOT NULL,
  resolved_at  INTEGER,
  approved_by  TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_status  ON requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at);
`,
	},
	{
		Version: 2,
		Name:    "operators_auth_and_approvals",
		SQL: `
-- required_approvals (N): how many distinct approving operators a
-- request needs before it crosses into approved. The approval state
-- machine reads this column; it is MECHANISM-level (the value is a
-- product/policy decision made elsewhere, never defaulted here). A
-- column default of 1 keeps pre-existing rows and naive inserts valid;
-- it is NOT a policy claim, just a non-null fallback so the column is
-- always populated.
ALTER TABLE requests ADD COLUMN required_approvals INTEGER NOT NULL DEFAULT 1;

-- users: one row per operator who can authenticate and vote. role is a
-- free-form string the policy layer interprets (e.g. "admin",
-- "operator"); the store does not enforce a role enum.
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  role        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- webauthn_credentials: per-user passkey credential blobs. credential
-- is the opaque serialized credential (the auth layer owns its shape);
-- the store treats it as bytes. credential_id is the WebAuthn raw
-- credential ID, unique across all users so an assertion can resolve to
-- exactly one row.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        TEXT NOT NULL,
  credential_id  BLOB NOT NULL UNIQUE,
  credential     BLOB NOT NULL,
  created_at     INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- totp_secrets: at most one TOTP secret per user (user_id PK). secret
-- is the base32 shared secret; the store treats it as an opaque string.
CREATE TABLE IF NOT EXISTS totp_secrets (
  user_id     TEXT PRIMARY KEY,
  secret      TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- sessions: server-side session records. expires_at is an absolute Unix
-- second; GetSession treats a now >= expires_at row as not-found.
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- approvals: APPEND-ONLY vote ledger. At most one row per
-- (request_id, operator) — the composite UNIQUE collapses a duplicate
-- vote from the same operator. decision is 'approve' | 'deny';
-- authn_method records how the operator authenticated for this vote
-- (e.g. "webauthn", "totp") for the audit trail. ts is the vote time.
-- There is NO update path: a vote, once cast, is immutable; the state
-- machine reads the full vote set and computes the decision.
CREATE TABLE IF NOT EXISTS approvals (
  request_id   TEXT NOT NULL,
  operator     TEXT NOT NULL,
  decision     TEXT NOT NULL,
  authn_method TEXT NOT NULL,
  ts           INTEGER NOT NULL,
  PRIMARY KEY (request_id, operator)
);
CREATE INDEX IF NOT EXISTS idx_approvals_request ON approvals(request_id);
`,
	},
}

// schemaMigrationsDDL creates the bookkeeping table. It is applied
// outside the version ledger (and before it) because it is the ledger's
// own storage — it cannot itself be a versioned migration. IF NOT
// EXISTS makes it idempotent across re-opens.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version     INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  applied_at  INTEGER NOT NULL
);`

// runMigrations applies every pending migration in Version order inside
// its own transaction, recording each in schema_migrations. It is safe
// to call repeatedly: already-applied versions are skipped, so a second
// call on an up-to-date database performs no schema writes (a no-op).
//
// Ordering + idempotency contract:
//   - migrations are applied strictly in ascending Version order;
//   - a migration and its schema_migrations bookkeeping row commit in
//     ONE transaction, so a crash mid-migration leaves the DB at the
//     last fully-committed version (never half-applied-and-recorded);
//   - a version already present in schema_migrations is skipped.
func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(schemaMigrationsDDL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(db)
	if err != nil {
		return err
	}

	// Apply in ascending Version order. The ledger is authored in order
	// but we sort defensively so a mis-ordered append still applies
	// correctly.
	ordered := make([]migration, len(migrations))
	copy(ordered, migrations)
	sortMigrations(ordered)

	for _, m := range ordered {
		if applied[m.Version] {
			continue
		}
		if err := applyOne(db, m); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
	}
	return nil
}

// applyOne runs one migration's SQL and records it, atomically.
func applyOne(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	if _, err := tx.Exec(m.SQL); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.Version, m.Name, nowUnix(),
	); err != nil {
		return fmt.Errorf("record: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// appliedVersions reads the set of versions already recorded.
func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		out[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return out, nil
}

// sortMigrations sorts in ascending Version order. Implemented as a
// tiny insertion sort to avoid importing sort for a list that is, in
// practice, a handful of entries.
func sortMigrations(ms []migration) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j-1].Version > ms[j].Version; j-- {
			ms[j-1], ms[j] = ms[j], ms[j-1]
		}
	}
}
