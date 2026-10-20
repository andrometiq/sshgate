package hosted

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

func (e *ApprovalV2Engine) expireLegacy(ctx context.Context) error {
	if e.config.LegacyStore == nil {
		return nil
	}
	rows, err := e.config.LegacyStore.ListPending(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		now := e.now().Wall
		end := row.CreatedAt.Add(24 * time.Hour)
		if row.ExpiresAt != nil {
			end = *row.ExpiresAt
		}
		if now.Before(end) {
			continue
		}
		if _, _, err := e.config.LegacyStore.ExpireLegacy(ctx, row.RequestID, now); err != nil {
			return err
		}
	}
	select {
	case e.flushNudge <- struct{}{}:
	default:
	}
	return nil
}

func (e *ApprovalV2Engine) flushLegacyAudit(ctx context.Context) error {
	tx, err := e.config.Store.BeginV2(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT event_key,request_id,resolved_at,evidence FROM legacy_expiry_outbox WHERE event_key>? ORDER BY event_key LIMIT 256`, e.legacyAuditCursor)
	if err != nil {
		return err
	}
	var calls []signerkit.AuditCall
	count := 0
	cursor := e.legacyAuditCursor
	for rows.Next() {
		count++
		var call signerkit.AuditCall
		var at int64
		var evidence []byte
		var metadata signerkit.LegacyExpiryAuditMetadata
		if err := rows.Scan(&metadata.EventKey, &call.RequestID, &at, &evidence); err != nil {
			rows.Close()
			return err
		}
		cursor = metadata.EventKey
		call.Time = time.Unix(at, 0).UTC()
		call.Lifecycle = "legacy-expired"
		metadata.ResolvedAt = call.Time
		metadata.Votes = []signerkit.LegacyExpiryAuditVote{}
		var votes []*store.Vote
		decodeErr := json.Unmarshal(evidence, &votes)
		for _, vote := range votes {
			if vote == nil {
				decodeErr = errors.New("null vote")
				break
			}
			metadata.Votes = append(metadata.Votes, signerkit.LegacyExpiryAuditVote{Operator: vote.Operator, Decision: string(vote.Decision), AuthnMethod: vote.AuthnMethod, Time: vote.TS, Audited: vote.Audited})
		}
		if decodeErr != nil {
			e.config.Logger.Printf("legacy audit evidence corrupt; retained for repair: event_key=%q", metadata.EventKey)
			continue
		}
		call.LegacyExpiry = &metadata
		calls = append(calls, call)
	}
	err = rows.Err()
	rows.Close()
	tx.Rollback()
	if err != nil {
		return err
	}
	for _, call := range calls {
		if e.config.AuditSink == nil {
			return errors.New("hosted: legacy expiry audit sink unavailable")
		}
		if err := e.config.AuditSink.Call(ctx, call); err != nil {
			return err
		}
		tx, err := e.config.Store.BeginV2(ctx)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM legacy_expiry_outbox WHERE event_key=?`, call.LegacyExpiry.EventKey)
		if err == nil {
			err = tx.Commit()
		}
		tx.Rollback()
		if err != nil {
			return err
		}
	}
	// Advance only after all decodable lines in this page were acknowledged.
	// Corrupt rows remain intact and are retried on the next sweep after repair.
	e.legacyAuditCursor = cursor
	if count < 256 {
		e.legacyAuditCursor = ""
	}
	return nil
}
