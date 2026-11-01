package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
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
		metadata.ResolvedAt = call.Time
		metadata.Votes = []signerkit.LegacyExpiryAuditVote{}
		call.Lifecycle = "legacy-expired"
		canceled := strings.HasPrefix(metadata.EventKey, "legacy-cancel:")
		if canceled {
			call.Lifecycle = "legacy-canceled"
		}
		var votes []*store.Vote
		var admin string
		decodeErr := errors.New("unknown event key namespace")
		// Only this code writes keys; any other namespace fails closed.
		if canceled || strings.HasPrefix(metadata.EventKey, "legacy-expiry:") {
			votes, admin, decodeErr = decodeLegacyEvidence(evidence, canceled)
		}
		if decodeErr != nil {
			// Ruling 31: the line still reaches the sink, marked, so a bad row can
			// neither block the outbox nor vanish unaudited.
			e.config.Logger.Printf("legacy audit evidence malformed; flushed as evidence_malformed: event_key=%q", metadata.EventKey)
			call.Reason = "evidence_malformed"
		} else {
			for _, vote := range votes {
				metadata.Votes = append(metadata.Votes, signerkit.LegacyExpiryAuditVote{Operator: vote.Operator, Decision: string(vote.Decision), AuthnMethod: vote.AuthnMethod, Time: vote.TS, Audited: vote.Audited})
			}
			if canceled {
				call.Reason = "canceled"
				call.Operator = &signerkit.Operator{ID: admin, DisplayName: admin, Verified: true}
			}
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
	// Advance only after every line in this page was acknowledged.
	e.legacyAuditCursor = cursor
	if count < 256 {
		e.legacyAuditCursor = ""
	}
	return nil
}

// decodeLegacyEvidence reads outbox evidence. v0 (expiry) is a bare vote array,
// or null for no votes. v1 (cancel) is the versioned object naming the admin.
// Each shape is valid only under its own key namespace.
func decodeLegacyEvidence(evidence []byte, canceled bool) ([]*store.Vote, string, error) {
	var votes []*store.Vote
	admin := ""
	trimmed := bytes.TrimSpace(evidence)
	if canceled {
		var object sqlitestore.LegacyCancelEvidence
		if len(trimmed) == 0 || trimmed[0] != '{' || decodeStrictJSON(trimmed, &object) != nil {
			return nil, "", errors.New("not a v1 cancel object")
		}
		if object.V != 1 || object.Reason != "canceled" || object.Admin == "" {
			return nil, "", errors.New("unsupported cancel evidence")
		}
		votes, admin = object.Votes, object.Admin
	} else if len(trimmed) == 0 || trimmed[0] != '[' && !bytes.Equal(trimmed, []byte("null")) || json.Unmarshal(trimmed, &votes) != nil {
		return nil, "", errors.New("not a v0 vote array")
	}
	for _, vote := range votes {
		if vote == nil {
			return nil, "", errors.New("null vote")
		}
	}
	return votes, admin, nil
}
