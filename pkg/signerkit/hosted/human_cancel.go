package hosted

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Admin cancel (spec D2, Q4). Admins cancel one pending request at a time;
// they never vote. Hosted deny-all is deferred to v0.3 (ruling 32).

var errCancelAdminRole = errors.New("hosted: admin role required")

// cancelV2Request binds a v2 cancel to the plan the admin reviewed.
type cancelV2Request struct {
	PlanHash string `json:"plan_hash"`
}

// requireAdmin answers 403 unless userID holds the admin role. busyIs503
// selects the v2 contention answer for a busy read; v1 keeps its 500.
func (h *HumanAPI) requireAdmin(w http.ResponseWriter, ctx context.Context, userID string, busyIs503 bool) bool {
	user, err := h.Store.GetUser(ctx, userID)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && (user == nil || user.Role != "admin"):
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return false
	case err != nil && busyIs503 && IsApprovalBusy(err):
		writeJSONError(w, http.StatusServiceUnavailable, "busy — retry")
		return false
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "get operator")
		return false
	}
	return true
}

// viewerIsAdmin is the display hint for the cancel control; the cancel routes
// enforce the role themselves.
func (h *HumanAPI) viewerIsAdmin(ctx context.Context, userID string) bool {
	user, err := h.Store.GetUser(ctx, userID)
	return err == nil && user != nil && user.Role == "admin"
}

// handleUICancel is POST /ui/request/{id}/cancel: a v1 row becomes denied with
// terminal_reason=canceled through CancelLegacy, whose transaction also
// writes the admin-attributed audit evidence (ruling 31). It does not wait
// for an unaudited vote (E4c).
func (h *HumanAPI) handleUICancel(w http.ResponseWriter, r *http.Request, userID string) {
	ctx := r.Context()
	if !h.requireAdmin(w, ctx, userID, false) {
		return
	}
	var body struct{}
	if r.ContentLength != 0 && !decodeJSON(w, r, &body) {
		return
	}
	resolver, ok := h.Store.(store.LegacyResolver)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "cancel request")
		return
	}
	id := r.PathValue("id")
	row, err := h.Store.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "unknown request_id")
		} else {
			writeJSONError(w, http.StatusInternalServerError, "get request")
		}
		return
	}
	now := h.Auth.now()
	changed := false
	if row.Status == store.StatusPending && !now.Before(legacyVoteExpiry(row)) {
		// An overdue row is expired, not canceled, as on the vote route.
		_, _, err = resolver.ExpireLegacy(ctx, id, now)
	} else if row.Status == store.StatusPending {
		changed, _, err = resolver.CancelLegacy(ctx, id, now, userID)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "cancel request")
		return
	}
	h.nudgeAuditFlush()
	if !changed {
		writeJSONError(w, http.StatusConflict, "request already resolved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"request_id": id, "status": string(store.StatusDenied), "terminal_reason": "canceled"})
}

// handleUIV2Cancel is POST /ui/v2/request/{handle}/cancel: one AdminCancel
// in its own transaction, keyed on the record's full (client_id,
// sub_principal, request_id). A busy BEGIN answers 503 and changes nothing.
func (h *HumanAPI) handleUIV2Cancel(w http.ResponseWriter, r *http.Request, userID string) {
	ctx := r.Context()
	if !h.requireAdmin(w, ctx, userID, true) {
		return
	}
	var req cancelV2Request
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.PlanHash == "" {
		writeJSONError(w, http.StatusBadRequest, "plan_hash is required")
		return
	}
	row := h.resolveUIV2(w, r)
	if row == nil {
		return
	}
	var engine *ApprovalV2Engine
	if h.ordinaryEngine != nil {
		engine = h.ordinaryEngine()
	}
	if engine == nil {
		// No running generation: the same answer as an absent approvals plane.
		writeJSONError(w, http.StatusServiceUnavailable, "approvals unavailable")
		return
	}
	after, answer, err := engine.transact(ctx, row.Key, func(tx *sql.Tx, before *ap.R1, _ ap.Now) (ap.Command, ap.Inputs, error) {
		if before == nil {
			return nil, ap.Inputs{}, &ap.CodeError{Code: ap.CodeNotFound}
		}
		var role string
		err := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", userID).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) || err == nil && role != "admin" {
			return nil, ap.Inputs{}, errCancelAdminRole
		}
		if err != nil {
			return nil, ap.Inputs{}, approvalTransactionError(err)
		}
		return ap.AdminCancel{PlanHash: req.PlanHash, Admin: userID}, ap.Inputs{}, nil
	})
	var coded *ap.CodeError
	switch {
	case errors.Is(err, errCancelAdminRole):
		writeJSONError(w, http.StatusForbidden, "admin role required")
	case errors.As(err, &coded) && coded.Code == ap.CodeBusy:
		writeJSONError(w, http.StatusServiceUnavailable, "busy — retry")
	case errors.As(err, &coded) && coded.Code == ap.CodeStorageUncertain:
		writeJSONError(w, http.StatusServiceUnavailable, "storage uncertain — retry")
	case errors.As(err, &coded) && coded.Code == ap.CodeNotFound:
		writeJSONError(w, http.StatusNotFound, "unknown handle")
	case errors.As(err, &coded) && coded.Code == ap.CodeConflict:
		writeJSONError(w, http.StatusConflict, "view changed")
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "cancel request")
	case answer.Reason == "already_resolved" || after.Header.Decision == nil || after.Header.Decision.Status != ap.ApprovalCanceled:
		writeJSONError(w, http.StatusConflict, "request already resolved")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"record_handle": row.RecordHandle, "approval_status": string(ap.ApprovalCanceled)})
	}
}

// nudgeAuditFlush wakes the flusher so a cancel's audit line is not left to
// the next tick.
func (h *HumanAPI) nudgeAuditFlush() {
	if h.ordinaryEngine == nil {
		return
	}
	if engine := h.ordinaryEngine(); engine != nil {
		select {
		case engine.flushNudge <- struct{}{}:
		default:
		}
	}
}
