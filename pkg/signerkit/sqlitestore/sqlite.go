package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"time"

	// Register the CGO-free SQLite driver under the name "sqlite".
	// modernc.org/sqlite is a pure-Go transpilation of upstream
	// SQLite — slower than the CGO build but cross-compile-friendly
	// (no host C toolchain required for `GOOS=linux GOARCH=amd64
	// go build`).
	_ "modernc.org/sqlite"
)

// The schema lives in store/migrations.go as a versioned, append-only
// migration ledger applied by runMigrations on Open. v2.0 shipped one
// CREATE-TABLE-IF-NOT-EXISTS string with a "drop + recreate" story; v2
// (Tier 3) replaces that with a real migration runner so the
// multi-operator + auth-backend tables can land additively without
// losing the existing requests data.

// pollInterval is how often WaitForResolution re-reads the row. 100ms
// is a deliberate compromise: tight enough that approvals feel near-
// instant to the human, loose enough that 100 concurrent waiters
// generate only ~1000 reads/sec on a SQLite that handles tens of
// thousands. v2.1 should replace this with a per-row channel wakeup.
const pollInterval = 100 * time.Millisecond

// DB is the SQLite-backed Store. It wraps *sql.DB; all methods are
// safe for concurrent use (sql.DB is, and our SQL is bounded queries
// only — no transactions that span calls).
type DB struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at path and runs every
// pending schema migration (see store/migrations.go). Path may be
// ":memory:" for tests; the journal mode is set to WAL so concurrent
// readers don't block the writer. busy_timeout is set to 5s to absorb
// transient lock contention without surfacing SQLITE_BUSY errors to
// handlers.
//
// Open is idempotent with respect to schema: re-opening an already-
// migrated database re-runs runMigrations, which finds every version
// already recorded in schema_migrations and applies nothing. Calling
// Open twice against the same path is a safe no-op on the second call.
func Open(path string) (*DB, error) {
	// modernc.org/sqlite accepts a DSN with `_pragma` query params
	// for one-shot startup configuration. We set:
	//   journal_mode=WAL      — concurrent readers + one writer.
	//   busy_timeout=5000     — wait up to 5s on a locked DB before
	//                            failing with SQLITE_BUSY.
	//   foreign_keys=on       — defensive; we don't use FKs yet but
	//                            future schema may.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", path)
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := d.Ping(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ping %s: %w", path, err)
	}
	if err := runMigrations(d); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return &DB{db: d}, nil
}

// Close closes the underlying *sql.DB. Idempotent: subsequent calls
// return nil.
func (s *DB) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Insert implements Store.Insert. The UNIQUE constraint on request_id
// surfaces a duplicate insert as ErrDuplicateID; other errors wrap
// the underlying driver message.
func (s *DB) Insert(ctx context.Context, r *store.Request) error {
	if r == nil {
		return errors.New("store: Insert: nil request")
	}
	if r.RequestID == "" {
		return errors.New("store: Insert: empty request_id")
	}
	if !r.Status.IsValid() {
		return fmt.Errorf("store: Insert: invalid status %q", r.Status)
	}
	if len(r.Commands) == 0 {
		return errors.New("store: Insert: empty commands")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	// RequiredApprovals defaults to 1 at the column level; mirror that
	// here so a zero-valued Request (the common handler path, which
	// does not set the field) stores a sane non-zero N rather than 0,
	// which would mean "approved with no votes". This is a non-null
	// fallback, NOT a policy claim — callers that want a different N
	// set the field (or call SetRequiredApprovals) explicitly.
	reqApprovals := r.RequiredApprovals
	if reqApprovals <= 0 {
		reqApprovals = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO requests (request_id, status, client_id, commands, signatures, created_at, resolved_at, approved_by, required_approvals)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		r.RequestID, string(r.Status), r.ClientID, string(r.Commands),
		nullableString(r.Signatures), r.CreatedAt.Unix(),
		nullableTime(r.ResolvedAt), nullableEmpty(r.ApprovedBy), reqApprovals,
	)
	if err != nil {
		// modernc.org/sqlite surfaces unique-violation as a generic
		// error with "UNIQUE constraint failed" in the message. We
		// match on the substring rather than the driver-specific
		// error code so the check survives driver upgrades.
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: %s", store.ErrDuplicateID, r.RequestID)
		}
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}

// GetByID implements Store.GetByID.
func (s *DB) GetByID(ctx context.Context, id string) (*store.Request, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT request_id, status, client_id, commands, signatures, created_at, resolved_at, approved_by, required_approvals
		FROM requests WHERE request_id = ?
	`, id)
	r, err := scanRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("get %s: %w", id, err)
	}
	return r, nil
}

// UpdateStatus implements Store.UpdateStatus. Updates only fire when
// the current status is pending; subsequent calls are no-ops (the
// row simply isn't updated). This is the idempotency hook the
// timeout path relies on.
func (s *DB) UpdateStatus(ctx context.Context, id string, status store.Status, signatures []byte, approvedBy string) error {
	if !status.IsValid() {
		return fmt.Errorf("store: UpdateStatus: invalid status %q", status)
	}
	now := time.Now().UTC().Unix()
	res, err := s.db.ExecContext(ctx, `
		UPDATE requests
		SET status = ?, signatures = ?, resolved_at = ?, approved_by = ?
		WHERE request_id = ? AND status = ?
	`,
		string(status), nullableString(signatures), now,
		nullableEmpty(approvedBy), id, string(store.StatusPending),
	)
	if err != nil {
		return fmt.Errorf("update %s: %w", id, err)
	}
	// We don't surface "no rows affected" as an error: that's the
	// idempotent path. Callers that care can read with GetByID
	// after the update.
	_, _ = res.RowsAffected()
	return nil
}

// WaitForResolution implements Store.WaitForResolution. v2.0 uses a
// polling loop; v2.1 should swap in a per-id channel.
func (s *DB) WaitForResolution(ctx context.Context, id string, timeout time.Duration) (*store.Request, error) {
	deadline := time.Now().Add(timeout)
	// First read: cheap fast path. If the row is already non-pending
	// we return immediately without entering the sleep loop.
	r, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Status != store.StatusPending {
		return r, nil
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			r, err := s.GetByID(ctx, id)
			if err != nil {
				return nil, err
			}
			if r.Status != store.StatusPending {
				return r, nil
			}
			if time.Now().After(deadline) {
				// Return the current (pending) row; the handler
				// decides whether to mark it as timed-out.
				return r, nil
			}
		}
	}
}

// ListPending implements Store.ListPending.
func (s *DB) ListPending(ctx context.Context) ([]*store.Request, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT request_id, status, client_id, commands, signatures, created_at, resolved_at, approved_by, required_approvals
		FROM requests WHERE status = ? ORDER BY created_at ASC
	`, string(store.StatusPending))
	if err != nil {
		return nil, fmt.Errorf("list pending: %w", err)
	}
	defer rows.Close()
	return scanRequests(rows)
}

// RecentAudit implements Store.RecentAudit.
func (s *DB) RecentAudit(ctx context.Context, limit int) ([]*store.Request, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT request_id, status, client_id, commands, signatures, created_at, resolved_at, approved_by, required_approvals
		FROM requests ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("recent audit: %w", err)
	}
	defer rows.Close()
	return scanRequests(rows)
}

// scanRequest decodes one row from a *sql.Row or *sql.Rows.
// The two callers (GetByID, scanRequests) both want the same shape.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRequest(s rowScanner) (*store.Request, error) {
	var (
		r            store.Request
		statusStr    string
		signatures   sql.NullString
		createdUnix  int64
		resolvedUnix sql.NullInt64
		approvedBy   sql.NullString
		commands     string
		reqApprovals int
	)
	if err := s.Scan(&r.RequestID, &statusStr, &r.ClientID, &commands, &signatures, &createdUnix, &resolvedUnix, &approvedBy, &reqApprovals); err != nil {
		return nil, err
	}
	r.RequiredApprovals = reqApprovals
	r.Status = store.Status(statusStr)
	r.Commands = []byte(commands)
	if signatures.Valid {
		r.Signatures = []byte(signatures.String)
	}
	r.CreatedAt = time.Unix(createdUnix, 0).UTC()
	if resolvedUnix.Valid {
		t := time.Unix(resolvedUnix.Int64, 0).UTC()
		r.ResolvedAt = &t
	}
	if approvedBy.Valid {
		r.ApprovedBy = approvedBy.String
	}
	return &r, nil
}

func scanRequests(rows *sql.Rows) ([]*store.Request, error) {
	var out []*store.Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// nullableString returns a sql.NullString that's invalid when b is
// empty. SQLite stores NULL rather than the empty string so absence
// can be distinguished from "explicitly empty" downstream.
func nullableString(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func nullableEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Unix()
}

// nowUnix is the single clock source for store-internal writes
// (migration timestamps, vote timestamps when the caller leaves them
// zero). UTC seconds, matching every other stored time column.
func nowUnix() int64 {
	return time.Now().UTC().Unix()
}

// isUniqueConstraintErr matches the modernc.org/sqlite UNIQUE
// violation message. The driver doesn't export a typed error, so a
// substring match is the documented workaround.
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	return containsCI(err.Error(), "UNIQUE constraint failed")
}

// containsCI is a tiny lowercase-substring check that avoids pulling
// in strings just for one substring test. It is case-insensitive only
// for ASCII (which is all SQLite's error messages contain).
func containsCI(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	// Case-insensitive ASCII scan.
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a := haystack[i+j]
			b := needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Compile-time interface check.
var _ store.Store = (*DB)(nil)
