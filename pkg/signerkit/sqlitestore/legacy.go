package sqlitestore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// ExpireLegacy ends an overdue pending request even if a vote's audit stalled.
func (s *DB) ExpireLegacy(ctx context.Context, id string, now time.Time) (bool, []*store.Vote, error) {
	return s.resolveLegacy(ctx, id, func(votes []*store.Vote) (string, []byte, error) {
		evidence, err := json.Marshal(votes)
		return legacyOutboxKey("legacy-expiry", id, now), evidence, err
	}, now, `UPDATE requests SET status='error', terminal_reason='expired', resolved_at=? WHERE request_id=? AND status='pending' AND request_expires_at<=?`, now.Unix(), id, now.Unix())
}

// LegacyCancelEvidence is the versioned outbox evidence of a hosted v1 admin
// cancel. Expiry evidence stays the v0 bare vote array.
type LegacyCancelEvidence struct {
	V      int           `json:"v"`
	Reason string        `json:"reason"`
	Admin  string        `json:"admin"`
	Votes  []*store.Vote `json:"votes"`
}

// CancelLegacy ends a pending request without waiting for vote audit completion.
// Its transaction writes admin-attributed evidence to the legacy outbox.
func (s *DB) CancelLegacy(ctx context.Context, id string, now time.Time, admin string) (bool, []*store.Vote, error) {
	if admin == "" {
		return false, nil, fmt.Errorf("resolve legacy: cancel requires an admin")
	}
	return s.resolveLegacy(ctx, id, func(votes []*store.Vote) (string, []byte, error) {
		if votes == nil {
			votes = []*store.Vote{}
		}
		evidence, err := json.Marshal(LegacyCancelEvidence{V: 1, Reason: "canceled", Admin: admin, Votes: votes})
		return legacyOutboxKey("legacy-cancel", id, now), evidence, err
	}, now, `UPDATE requests SET status='denied', terminal_reason='canceled', resolved_at=? WHERE request_id=? AND status='pending'`, now.Unix(), id)
}

func (s *DB) resolveLegacy(ctx context.Context, id string, evidence func([]*store.Vote) (string, []byte, error), at time.Time, query string, args ...any) (bool, []*store.Vote, error) {
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
	key, data, err := evidence(votes)
	if err != nil {
		return false, nil, fmt.Errorf("resolve legacy: evidence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO legacy_expiry_outbox(event_key,request_id,resolved_at,evidence) VALUES (?,?,?,?)`, key, id, at.Unix(), data); err != nil {
		return false, nil, fmt.Errorf("resolve legacy: outbox: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("resolve legacy: commit: %w", err)
	}
	return true, votes, nil
}

var _ store.LegacyResolver = (*DB)(nil)

// legacyOutboxKey is "<namespace>:<hex sha256(request_id)>:<unix>"; the
// flusher derives the audit lifecycle from the namespace.
func legacyOutboxKey(namespace, id string, at time.Time) string {
	return fmt.Sprintf("%s:%x:%d", namespace, sha256.Sum256([]byte(id)), at.Unix())
}
