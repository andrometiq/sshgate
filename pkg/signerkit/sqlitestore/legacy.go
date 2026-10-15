package sqlitestore

import (
	"context"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// ExpireLegacy ends an overdue pending request even if a vote's audit stalled.
func (s *DB) ExpireLegacy(ctx context.Context, id string, now time.Time) (bool, []*store.Vote, error) {
	return s.resolveLegacy(ctx, id, `UPDATE requests SET status='error', terminal_reason='expired', resolved_at=? WHERE request_id=? AND status='pending' AND request_expires_at<=?`, now.Unix(), id, now.Unix())
}

// CancelLegacy ends a pending request without waiting for vote audit completion.
func (s *DB) CancelLegacy(ctx context.Context, id string, now time.Time) (bool, []*store.Vote, error) {
	return s.resolveLegacy(ctx, id, `UPDATE requests SET status='denied', terminal_reason='canceled', resolved_at=? WHERE request_id=? AND status='pending'`, now.Unix(), id)
}

func (s *DB) resolveLegacy(ctx context.Context, id, query string, args ...any) (bool, []*store.Vote, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, nil, fmt.Errorf("resolve legacy: begin: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return false, nil, fmt.Errorf("resolve legacy: update: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, nil, fmt.Errorf("resolve legacy: rows affected: %w", err)
	}
	if changed == 0 {
		return false, nil, nil
	}
	// Hold the write reservation through the evidence read so a racing vote
	// cannot change the evidence belonging to this terminal transition.
	rows, err := tx.QueryContext(ctx, `SELECT request_id, operator, decision, authn_method, ts, audited FROM approvals WHERE request_id=? ORDER BY ts, operator`, id)
	if err != nil {
		return false, nil, fmt.Errorf("resolve legacy: votes: %w", err)
	}
	var votes []*store.Vote
	for rows.Next() {
		var vote store.Vote
		var ts int64
		var audited int
		if err := rows.Scan(&vote.RequestID, &vote.Operator, &vote.Decision, &vote.AuthnMethod, &ts, &audited); err != nil {
			rows.Close()
			return false, nil, fmt.Errorf("resolve legacy: scan vote: %w", err)
		}
		vote.TS = time.Unix(ts, 0).UTC()
		vote.Audited = audited == 1
		votes = append(votes, &vote)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, nil, fmt.Errorf("resolve legacy: iterate votes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return false, nil, fmt.Errorf("resolve legacy: close votes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("resolve legacy: commit: %w", err)
	}
	return true, votes, nil
}

var _ store.LegacyResolver = (*DB)(nil)
