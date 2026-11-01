package sqlitestore

import (
	"context"
	"time"
)

// V2PendingCursor continues the global human-plane list, including all tie breakers.
// HTTP callers receive an authenticated opaque encoding, never these fields.
type V2PendingCursor struct {
	CreatedAt time.Time
	Key       V2Key
}

// ListPendingV2 reads committed pending slots without advancing Clock.
func (s *DB) ListPendingV2(ctx context.Context, cursor *V2PendingCursor, limit int) ([]*V2Row, error) {
	query := selectV2 + ` WHERE decision_status IS NULL`
	var args []any
	if cursor != nil {
		query += ` AND (created_at,client_id,sub_principal,request_id) > (?,?,?,?)`
		args = append(args, cursor.CreatedAt.Unix(), cursor.Key.ClientID, cursor.Key.SubPrincipal, cursor.Key.RequestID)
	}
	query += ` ORDER BY created_at,client_id,sub_principal,request_id LIMIT ?`
	return s.queryV2(ctx, query, append(args, limitV2(limit))...)
}
