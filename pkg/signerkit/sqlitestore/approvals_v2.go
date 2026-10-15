package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// V2Key is the hosted approval identity. SubPrincipal may be empty.
type V2Key struct{ ClientID, SubPrincipal, RequestID string }

// V2Projection supplies the engine's already captured time and policy. PutV2
// derives all columns itself; callers cannot supply inconsistent slot facts.
type V2Projection struct {
	Now       ap.Now
	Epoch     string
	Settings  ap.Settings
	GrantLive bool
}

// V2Row contains committed state and its worker-maintained caches. Reads never
// advance the lifecycle, even if a deadline has passed.
type V2Row struct {
	Key          V2Key
	Record       ap.R1
	RecordJSON   []byte
	ViewStatus   string
	Class        ap.RecordClass
	NextDueAt    *time.Time
	RecordHandle string
}

// V2Cursor continues a client's listing, oldest first, with request ID breaking
// ties at the same created_at second. It is scoped by ListV2's client and sub.
type V2Cursor struct {
	CreatedAt time.Time
	RequestID string
}

// V2Counts is the admission snapshot under the caller's write lock.
type V2Counts struct{ Full, All int64 }

var ErrV2AmbiguousHandle = errors.New("sqlitestore: ambiguous approval handle")

// BeginV2 takes SQLite's BEGIN IMMEDIATE lock. The caller owns Commit/Rollback
// and must use only the in-transaction primitives until it releases the lock.
func (s *DB) BeginV2(ctx context.Context) (*sql.Tx, error) { return s.db.BeginTx(ctx, nil) }

func keyV2(rec ap.R1) V2Key {
	return V2Key{rec.Header.Principal, rec.Header.SubPrincipal, rec.Header.RequestID}
}

// PutV2 upserts a validated canonical record and its derived columns atomically.
// It does not apply Clock; the engine must do that before persisting a command.
func (s *DB) PutV2(ctx context.Context, tx *sql.Tx, key V2Key, rec ap.R1, projection V2Projection) error {
	if tx == nil {
		return errors.New("sqlitestore: PutV2 requires a transaction")
	}
	if key != keyV2(rec) {
		return errors.New("sqlitestore: approval key does not match record")
	}
	data, err := ap.EncodeR1(rec)
	if err != nil {
		return err
	}
	settings := projection.Settings
	settings.Hosted = true
	view := ap.View(rec, projection.Now, projection.Epoch, settings, projection.GrantLive)
	work := ap.Next(rec, projection.Now, projection.Epoch, settings, projection.GrantLive)
	h := rec.Header
	var decision, decidedAt, mintReason, lastEnd, final any
	if h.Decision != nil {
		decision, decidedAt = string(h.Decision.Status), h.Decision.DecidedAt.Unix()
	}
	mint := "none"
	if h.Mint != nil {
		mint, mintReason = "error", h.Mint.Reason
		if h.Mint.State == ap.MintSignatures {
			mint, mintReason = "erased", nil
			if rec.Payload != nil && len(rec.Payload.Signatures) > 0 {
				mint = "bytes"
			}
		}
	}
	if end, ok := ap.LastEnd(rec); ok {
		lastEnd = end.Unix()
	}
	if h.FinalReport != nil {
		final = string(h.FinalReport.Class)
	}
	payloadBytes := 0
	if rec.Payload != nil {
		payload, err := ap.Canonical(rec.Payload)
		if err != nil {
			return err
		}
		payloadBytes = len(payload)
	}
	status := string(view.ApprovalStatus)
	if view.ExecutionStatus != ap.ExecutionNone && view.ExecutionStatus != ap.ExecutionNotApplicable {
		status = string(view.ExecutionStatus)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO approvals_v2 (
 client_id, sub_principal, request_id, record_json, decision_status, decided_at,
 mint_state, mint_error_reason, last_window_end, claim_count, final_class,
 audited_complete, shed, payload_bytes, submit_not_after, created_at, request_expires_at,
 view_status, class, next_due_at, record_handle
 ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(client_id,sub_principal,request_id) DO UPDATE SET
 record_json=excluded.record_json, decision_status=excluded.decision_status, decided_at=excluded.decided_at,
 mint_state=excluded.mint_state, mint_error_reason=excluded.mint_error_reason, last_window_end=excluded.last_window_end,
 claim_count=excluded.claim_count, final_class=excluded.final_class, audited_complete=excluded.audited_complete,
 shed=excluded.shed, payload_bytes=excluded.payload_bytes, submit_not_after=excluded.submit_not_after,
 created_at=excluded.created_at, request_expires_at=excluded.request_expires_at, view_status=excluded.view_status,
 class=excluded.class, next_due_at=excluded.next_due_at, record_handle=excluded.record_handle`,
		key.ClientID, key.SubPrincipal, key.RequestID, data, decision, decidedAt, mint, mintReason, lastEnd,
		h.ClaimCount, final, !ap.Unflushed(rec), h.Shed, payloadBytes, h.SubmitNotAfter.Unix(), h.CreatedAt.Unix(),
		h.RequestExpiresAt.Unix(), status, string(view.Class), nullableV2Time(work.DueAt), view.RecordHandle)
	return err
}

func nullableV2Time(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return at.Unix()
}

const selectV2 = `SELECT client_id,sub_principal,request_id,record_json,view_status,class,next_due_at,record_handle FROM approvals_v2`
const keyWhereV2 = ` WHERE client_id=? AND sub_principal=? AND request_id=?`
const orderV2 = `client_id,sub_principal,request_id`

func scanV2(scanner interface{ Scan(...any) error }) (*V2Row, error) {
	row := new(V2Row)
	var due sql.NullInt64
	if err := scanner.Scan(&row.Key.ClientID, &row.Key.SubPrincipal, &row.Key.RequestID, &row.RecordJSON,
		&row.ViewStatus, &row.Class, &due, &row.RecordHandle); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	rec, err := ap.DecodeR1(row.RecordJSON)
	if err != nil {
		return nil, err
	}
	if row.Key != keyV2(rec) {
		return nil, errors.New("sqlitestore: stored approval key does not match record")
	}
	row.Record = rec
	if due.Valid {
		at := time.Unix(due.Int64, 0).UTC()
		row.NextDueAt = &at
	}
	return row, nil
}

// GetV2 reads through the caller's transaction, including its uncommitted writes.
func (s *DB) GetV2(ctx context.Context, tx *sql.Tx, key V2Key) (*V2Row, error) {
	if tx == nil {
		return nil, errors.New("sqlitestore: GetV2 requires a transaction")
	}
	return scanV2(tx.QueryRowContext(ctx, selectV2+keyWhereV2, key.ClientID, key.SubPrincipal, key.RequestID))
}

// DeleteV2 removes a row; deletion eligibility belongs to approvalplan and the engine.
func (s *DB) DeleteV2(ctx context.Context, tx *sql.Tx, key V2Key) error {
	if tx == nil {
		return errors.New("sqlitestore: DeleteV2 requires a transaction")
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM approvals_v2`+keyWhereV2, key.ClientID, key.SubPrincipal, key.RequestID)
	return err
}

// CountV2 counts full and all rows in the same admission transaction as PutV2.
func (s *DB) CountV2(ctx context.Context, tx *sql.Tx) (V2Counts, error) {
	var counts V2Counts
	if tx == nil {
		return counts, errors.New("sqlitestore: CountV2 requires a transaction")
	}
	err := tx.QueryRowContext(ctx, `SELECT count(CASE WHEN shed=0 THEN 1 END),count(*) FROM approvals_v2`).Scan(&counts.Full, &counts.All)
	return counts, err
}

func (s *DB) ReadV2(ctx context.Context, key V2Key) (*V2Row, error) {
	return scanV2(s.db.QueryRowContext(ctx, selectV2+keyWhereV2, key.ClientID, key.SubPrincipal, key.RequestID))
}

// ByHandleV2 refuses a collision rather than choosing an arbitrary record.
func (s *DB) ByHandleV2(ctx context.Context, handle string) (*V2Row, error) {
	rows, err := s.queryV2(ctx, selectV2+` WHERE record_handle=? LIMIT 2`, handle)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, store.ErrNotFound
	}
	if len(rows) != 1 {
		return nil, ErrV2AmbiguousHandle
	}
	return rows[0], nil
}

func (s *DB) RecentDecidedV2(ctx context.Context, limit int) ([]*V2Row, error) {
	return s.queryV2(ctx, selectV2+` WHERE decided_at IS NOT NULL ORDER BY decided_at DESC,`+orderV2+` LIMIT ?`, limitV2(limit))
}

func (s *DB) ListV2(ctx context.Context, client, sub string, cursor *V2Cursor, limit int) ([]*V2Row, error) {
	query := selectV2 + ` WHERE client_id=? AND sub_principal=?`
	args := []any{client, sub}
	if cursor != nil {
		query += ` AND (created_at,request_id) > (?,?)`
		args = append(args, cursor.CreatedAt.Unix(), cursor.RequestID)
	}
	query += ` ORDER BY created_at,request_id LIMIT ?`
	return s.queryV2(ctx, query, append(args, limitV2(limit))...)
}

func (s *DB) DueV2(ctx context.Context, now time.Time, limit int) ([]*V2Row, error) {
	return s.queryV2(ctx, selectV2+` WHERE next_due_at<=? ORDER BY next_due_at,`+orderV2+` LIMIT ?`, now.Unix(), limitV2(limit))
}

const unflushedV2Query = selectV2 + ` WHERE audited_complete=0 ORDER BY next_due_at ASC NULLS LAST,` + orderV2 + ` LIMIT ?`

func (s *DB) UnflushedV2(ctx context.Context, limit int) ([]*V2Row, error) {
	return s.queryV2(ctx, unflushedV2Query, limitV2(limit))
}

func limitV2(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 256 {
		return 256
	}
	return limit
}

func (s *DB) queryV2(ctx context.Context, query string, args ...any) ([]*V2Row, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*V2Row, 0)
	for rows.Next() {
		row, err := scanV2(rows)
		if err != nil {
			return nil, fmt.Errorf("read approval: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
