package signerserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// signRequest is the body shape of POST /v1/sign. It mirrors the
// design spec §"v2 vision → Wire protocol" exactly so the
// HostedServerBackend client (commit 3 of the scaffold series) can
// encode/decode the same struct on both ends.
//
// Context is intentionally a free-form map for v2.0; v2.1 will define
// a typed shape (claude_session_id, user_intent, etc.) once the LLM
// explainer is wired up on the server side.
type signRequest struct {
	ClientID string                 `json:"client_id"`
	Commands []signRequestCmd       `json:"commands"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// signRequestCmd is one queued command. Field names match the v1 Unix-
// socket wire format (server, cmd, ttl_seconds) so a future migration
// from signer's local socket to /v1/sign needs only a transport
// swap, not a payload rewrite.
type signRequestCmd struct {
	Server     string `json:"server"`
	Cmd        string `json:"cmd"`
	TTLSeconds int64  `json:"ttl_seconds"`
	// HostKeyFP is the target server's SSH host-key fingerprint
	// ("SHA256:..."), sourced by the MCP from its trusted registry. It is
	// persisted verbatim in the stored commands blob and threaded to the
	// signer at approval time, which stamps it into SigPayload.Host so the
	// gate can enforce the per-server binding (fail-closed on a mismatch).
	// omitempty keeps the v1 wire shape unchanged for a caller that omits it.
	HostKeyFP string `json:"host_key_fp,omitempty"`
}

// signAcceptedResponse is the 202 Accepted body returned from POST
// /v1/sign. Clients then poll poll_url until a resolution arrives.
type signAcceptedResponse struct {
	RequestID string `json:"request_id"`
	PollURL   string `json:"poll_url"`
}

// pollResponse is the body of GET /v1/poll/{id}. status is one of
// "pending" | "approved" | "denied" | "timeout" | "error".
// signatures is populated only on approved; approved_by/at are
// populated on approved or denied.
type pollResponse struct {
	RequestID  string      `json:"request_id"`
	Status     string      `json:"status"`
	Signatures []signedCmd `json:"signatures,omitempty"`
	ApprovedBy string      `json:"approved_by_user,omitempty"`
	ApprovedAt *time.Time  `json:"approved_at,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// signedCmd is a single signed command in the poll response. The
// shape matches v1's signer socket response so the gate
// verification path needs no changes.
type signedCmd struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// auditResponse is the body of GET /v1/audit. v2.0 returns an empty
// list; v2.1 wires it to the SQLite store's RecentAudit query.
type auditResponse struct {
	Entries []auditEntry `json:"entries"`
}

// auditEntry mirrors the v1 audit-log row shape: one decision per
// row, with the original commands and the approving user (if any).
type auditEntry struct {
	RequestID  string     `json:"request_id"`
	Status     string     `json:"status"`
	ClientID   string     `json:"client_id"`
	Commands   []string   `json:"commands"`
	ApprovedBy string     `json:"approved_by_user,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// handleHealthz returns 200 with a one-line "ok" body. Liveness only;
// readiness (DB-up, key-loaded) is a v2.1 concern.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// handleSign accepts a /v1/sign request. Validates the body, inserts
// a pending row in the store, returns 202 with the poll URL. When
// Store is nil the handler skips persistence (commit-1 fallback).
//
// Approval itself is OUT of scope for v2.0 scaffold: there is no
// human-in-the-loop yet (no web UI, no WebAuthn). Rows stay pending
// until either an external mechanism flips them via UpdateStatus or
// /v1/poll times out. v2.1 wires the approval UI.
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if req.ClientID == "" {
		writeJSONError(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if len(req.Commands) == 0 {
		writeJSONError(w, http.StatusBadRequest, "commands must be non-empty")
		return
	}
	for i, c := range req.Commands {
		if c.Cmd == "" {
			writeJSONError(w, http.StatusBadRequest, "commands["+itoa(i)+"].cmd is empty")
			return
		}
		if c.TTLSeconds <= 0 {
			writeJSONError(w, http.StatusBadRequest, "commands["+itoa(i)+"].ttl_seconds must be > 0")
			return
		}
		// Cap the requested TTL at the door. The mint-time path
		// (signerkit.signApproved) already refuses an over-cap TTL, but if
		// we accept it here the row is inserted as pending, an approver's
		// vote reaches sign-time, and the mint fails — leaving the row
		// approvable-but-unmintable, i.e. stuck pending forever. Rejecting
		// up front (mirroring the local daemon, daemon.go) keeps that
		// poisoned row from ever being created. The gate re-checks
		// authoritatively (verify.go); the mint-time cap stays as
		// defense-in-depth.
		if c.TTLSeconds > int64(sigwire.MaxSigValidity/time.Second) {
			writeJSONError(w, http.StatusBadRequest, "commands["+itoa(i)+"].ttl_seconds exceeds max "+itoa(int(sigwire.MaxSigValidity/time.Second)))
			return
		}
	}

	rid := generateRequestID()

	if s.Store != nil {
		// Re-encode the commands as canonical JSON so the stored
		// blob matches what /v1/audit will serve back. We use the
		// validated req.Commands rather than r.Body so any
		// pretty-printed/whitespace-laden inputs normalise.
		blob, err := json.Marshal(req.Commands)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "marshal commands: "+err.Error())
			return
		}
		insertCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		ins := &store.Request{
			RequestID: rid,
			Status:    store.StatusPending,
			ClientID:  req.ClientID,
			Commands:  blob,
			CreatedAt: time.Now().UTC(),
		}
		if err := s.Store.Insert(insertCtx, ins); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store insert: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusAccepted, signAcceptedResponse{
		RequestID: rid,
		PollURL:   "/v1/poll/" + rid,
	})
}

// handlePoll long-polls for a resolution via Store.WaitForResolution.
// When Store is nil the handler returns {status: "timeout"} after a
// short synthetic wait (kept for commit-1 fallback test fixtures).
//
// The wait window is s.PollWait (default 30s) for now; v2.1 will
// honour a ?wait= query param per spec §"v2 vision → Wire protocol".
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("request_id")
	if rid == "" {
		writeJSONError(w, http.StatusBadRequest, "missing request_id in path")
		return
	}

	if s.Store == nil {
		// Commit-1 fallback path. The 100ms synthetic wait keeps
		// long-poll behaviour visible without slowing the suite.
		select {
		case <-time.After(100 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		writeJSON(w, http.StatusOK, pollResponse{
			RequestID: rid,
			Status:    "timeout",
		})
		return
	}

	res, err := s.Store.WaitForResolution(r.Context(), rid, s.PollWait)
	if err != nil {
		// Distinguish not-found (the only well-defined error in
		// the spec) from generic infrastructure failures.
		if isNotFound(err) {
			writeJSONError(w, http.StatusNotFound, "unknown request_id")
			return
		}
		// ctx cancellation surfaces as context.Canceled — the
		// client has gone, so writing a response is best-effort.
		writeJSONError(w, http.StatusInternalServerError, "wait: "+err.Error())
		return
	}

	resp := pollResponse{
		RequestID:  res.RequestID,
		Status:     string(res.Status),
		ApprovedBy: res.ApprovedBy,
		ApprovedAt: res.ResolvedAt,
	}
	if res.Status == store.StatusPending {
		// The poll window elapsed without a resolution. Report
		// "timeout" to the client; the row itself remains pending
		// in the store so a future poll can resume.
		resp.Status = string(store.StatusTimeout)
	} else if res.Status == store.StatusApproved && len(res.Signatures) > 0 {
		var sigs []signedCmd
		if err := json.Unmarshal(res.Signatures, &sigs); err == nil {
			resp.Signatures = sigs
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAudit returns the recent audit list. When Store is nil the
// handler returns an empty list (commit-1 fallback).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusOK, auditResponse{Entries: []auditEntry{}})
		return
	}
	rows, err := s.Store.RecentAudit(r.Context(), 100)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit: "+err.Error())
		return
	}
	out := auditResponse{Entries: make([]auditEntry, 0, len(rows))}
	for _, row := range rows {
		var cmdObjs []signRequestCmd
		_ = json.Unmarshal(row.Commands, &cmdObjs)
		cmds := make([]string, len(cmdObjs))
		for i, c := range cmdObjs {
			cmds[i] = c.Cmd
		}
		out.Entries = append(out.Entries, auditEntry{
			RequestID:  row.RequestID,
			Status:     string(row.Status),
			ClientID:   row.ClientID,
			Commands:   cmds,
			ApprovedBy: row.ApprovedBy,
			CreatedAt:  row.CreatedAt,
			ResolvedAt: row.ResolvedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// isNotFound is a thin alias for errors.Is against the store's
// not-found sentinel — kept inline so handlers.go expresses the
// transport-layer mapping ("404 if and only if the row was missing")
// in one spot.
func isNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}

// writeJSON marshals v and writes it with Content-Type set. Errors
// from the underlying Write are intentionally swallowed: by the time
// we're encoding, the response status has been committed and there
// is no useful recovery.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError is the common error-response renderer. We use a
// stable {error: "..."} shape so clients can pattern-match without
// regex'ing free-form bodies.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// itoa is a tiny strconv.Itoa alias kept inline so handlers.go has
// one std-lib import set. (encoding/json + net/http + time only.)
func itoa(i int) string {
	// Minimal positive-int formatter; the only callers pass small
	// indexes (commands[i]).
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
