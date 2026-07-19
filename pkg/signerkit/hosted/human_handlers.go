package hosted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// human_handlers.go is Phase E: the HUMAN-PLANE HTTP surface — the
// /auth/* (enroll, verify, register, login, logout) and /ui/* (pending,
// request detail, approve, deny, audit) routes — plus the session
// middleware that guards them. JSON only; no HTML yet (the browser UI is
// a later phase).
//
// PLANE SEPARATION (security-critical). There are two disjoint auth
// planes and they never cross:
//
//   - the MACHINE plane (/v1/sign, /v1/poll, /healthz) is gated by the
//     bearer APIKey via withAuth. It is BYTE-FROZEN (the wire contract in
//     src/signer/backend/hosted.go) and Phase E does not touch it.
//   - the HUMAN plane (/auth/*, /ui/*) is gated by a server-side session
//     via withSession. The bearer key is NEVER accepted here; a UI
//     session is NEVER accepted on /v1.
//
// The separation is STRUCTURAL, not conventional: withAuth reads only the
// Authorization header and withSession reads only the session cookie, so
// presenting the wrong credential to the wrong plane is simply ignored
// (→ 401). TestPlaneSeparation asserts this in both directions.
//
// MECHANISM, NOT POLICY. The handlers call the Phase-D AuthManager verbs
// and the Phase-C ApprovalEngine; the product decisions (whether a
// step-up is required per-approval, the approval threshold N, deny-veto,
// self-approve) are read from HumanAPIConfig, which the caller sets. The
// handlers bake in no default policy.

// maxHumanBody caps the bytes read from any human-plane request body.
// WebAuthn responses are the largest (a few KB of attestation); 64 KiB is
// comfortably above that and well below anything that could exhaust the
// server.
const maxHumanBody = 64 * 1024

// HumanAPI wires the Phase-D auth mechanism and the Phase-C approval
// engine into the human-plane routes. It is constructed alongside the
// machine-plane Server and mounted on the same mux (see Server.routes).
//
// It holds NO mutable state; all state lives in the store. Safe for
// concurrent use.
type HumanAPI struct {
	Auth   *AuthManager
	Engine *ApprovalEngine
	Store  store.Store
	Cfg    HumanAPIConfig

	limitOnce sync.Once
	limits    *authRateLimiter
}

// HumanAPIConfig is the per-deploy POLICY the human plane applies. Every
// field is a product decision the caller supplies; the handlers never
// default them to a policy of their own.
type HumanAPIConfig struct {
	// ApprovalPolicy carries the deny-veto / self-approve / requester
	// flags the approval state machine consumes. The handler passes it to
	// SubmitVote verbatim. (RequiredApprovals inside it is ignored by the
	// engine in favour of the stored per-request column.)
	ApprovalPolicy ApprovalPolicy

	// RequireStepUp, when true, demands a FRESH re-auth (a TOTP code, or a
	// just-completed passkey assertion) on every approve/deny — the
	// per-action step-up. When false, the session itself is sufficient.
	//
	// This is the ONE product decision the task explicitly flagged (#2:
	// step-up per-approval vs per-session). It is a CONFIG flag, not a
	// baked default: the mechanism (AuthManager.StepUp / FinishLogin)
	// supports per-action step-up unconditionally; whether to ENFORCE it
	// is left here for the deploy to set. Defaults to the zero value (false),
	// which is NOT a policy claim that step-up is unnecessary — it is the
	// inert default of a flag the deploy must consciously set.
	RequireStepUp bool

	// SecureCookie controls the Secure attribute on the session cookie.
	// Production (HTTPS, TLS-terminated upstream) sets it true; a local
	// plain-HTTP test/dev harness sets it false so the cookie survives.
	// It is a deploy property, not a policy: the mechanism is identical
	// either way.
	SecureCookie bool

	// TrustProxyHeaders permits X-Forwarded-For for abuse-control identity,
	// but only when the immediate TCP peer is loopback. Production enables it
	// when the signer is bound behind a same-host reverse proxy that overwrites
	// or appends X-Forwarded-For; direct/public deployments leave it false.
	TrustProxyHeaders bool
}

// withSession is the HUMAN-PLANE middleware, the parallel to withAuth. It
// reads ONLY the session cookie (never the Authorization header), so a
// bearer token presented here is structurally ignored. On a missing or
// invalid/expired session it writes 401. On success it injects the
// authenticated operator's user id into the request context for the
// downstream handler.
//
// This is the load-bearing half of plane separation: because it never
// consults the bearer key, the machine credential cannot authenticate a
// human-plane request.
func (h *HumanAPI) withSession(next func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sess, err := h.Auth.ValidateSession(r.Context(), cookie.Value)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, sess.UserID)
	})
}

// withSessionAuthLimit adds bounded per-IP and per-principal throttling to a
// session-gated authentication action (factor enrollment). UI reads are not
// throttled; vote step-up applies the same limiter in handleVote.
func (h *HumanAPI) withSessionAuthLimit(next func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return h.withSession(func(w http.ResponseWriter, r *http.Request, userID string) {
		if !h.allowMutation(w, r) {
			return
		}
		if !h.allowAuth(w, r, userID, "session") {
			return
		}
		next(w, r, userID)
	})
}

// withSessionMutation guards a cookie-authenticated state change with an
// exact Origin check and a JSON content-type requirement. SameSite cookies
// alone do not protect against a compromised or malicious same-site sibling
// origin; binding mutations to the configured RP origins closes that gap.
func (h *HumanAPI) withSessionMutation(next func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return h.withSession(func(w http.ResponseWriter, r *http.Request, userID string) {
		if !h.allowMutation(w, r) {
			return
		}
		next(w, r, userID)
	})
}

// withPublicAuthLimit applies an IP budget before parsing an unauthenticated
// login/verification request. Handlers add the principal budget after strict
// JSON decoding, so rotating usernames cannot bypass the IP ceiling.
func (h *HumanAPI) withPublicAuthLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.allowMutation(w, r) {
			return
		}
		if !h.allowAuth(w, r, "", "public") {
			return
		}
		next(w, r)
	}
}

// registerHumanRoutes mounts the human-plane routes on mux. It is called
// from Server.routes when a HumanAPI is configured. The /auth/enroll and
// /auth/webauthn/register|login/begin|finish and /auth/login routes are
// SESSION-GATED EXCEPT the bootstrap login routes, which cannot require a
// session (you have none yet when logging in):
//
//   - PUBLIC (no session): /auth/login, /auth/totp/verify,
//     /auth/webauthn/login/{begin,finish} — these ESTABLISH a session.
//   - SESSION-GATED: /auth/totp/enroll, /auth/webauthn/register/{begin,
//     finish}, /auth/logout, and all /ui/* — these require an existing
//     session (you enroll a second factor / approve while logged in).
//
// Note: who may log in, and with which factor, is the caller's policy;
// these routes provide the verbs. The login route here authenticates a
// username + a factor the AuthManager verifies; the gating of WHICH
// factor is required to mint a session is left to the route body's
// configuration in a fuller product (v2.1). For Phase E we wire a TOTP-
// or-passkey login and a session-gated approve.
func (h *HumanAPI) registerHumanRoutes(mux *http.ServeMux) {
	// --- auth: session-establishing (public) ---
	mux.HandleFunc("POST /auth/login", h.withPublicAuthLimit(h.handleLogin))
	mux.HandleFunc("POST /auth/totp/verify", h.withPublicAuthLimit(h.handleTOTPVerify))
	mux.HandleFunc("POST /auth/webauthn/login/begin", h.withPublicAuthLimit(h.handleWebAuthnLoginBegin))
	mux.HandleFunc("POST /auth/webauthn/login/finish", h.withPublicAuthLimit(h.handleWebAuthnLoginFinish))

	// --- auth: session-gated (enroll a factor / log out while logged in) ---
	mux.Handle("POST /auth/totp/enroll", h.withSessionAuthLimit(h.handleTOTPEnroll))
	mux.Handle("POST /auth/webauthn/register/begin", h.withSessionAuthLimit(h.handleWebAuthnRegisterBegin))
	mux.Handle("POST /auth/webauthn/register/finish", h.withSessionAuthLimit(h.handleWebAuthnRegisterFinish))
	mux.Handle("POST /auth/logout", h.withSessionMutation(h.handleLogout))

	// --- ui: all session-gated ---
	mux.Handle("GET /ui/pending", h.withSession(h.handleUIPending))
	mux.Handle("GET /ui/request/{id}", h.withSession(h.handleUIRequest))
	mux.Handle("POST /ui/request/{id}/approve", h.withSessionMutation(h.handleUIApprove))
	mux.Handle("POST /ui/request/{id}/deny", h.withSessionMutation(h.handleUIDeny))
	mux.Handle("GET /ui/audit", h.withSession(h.handleUIAudit))
}

// ---------------------------------------------------------------------
// auth routes
// ---------------------------------------------------------------------

// loginRequest is the POST /auth/login body. The operator supplies a
// username and ONE factor: a TOTP code (totp_code) drives a single-round-
// trip login. Passkey login is the dedicated /auth/webauthn/login/*
// two-step ceremony (it cannot be a one-shot POST), so this route handles
// the TOTP case; a passkey assertion mints its session in login/finish.
type loginRequest struct {
	Username string `json:"username"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// handleLogin authenticates a username + TOTP code and, on success,
// issues a session cookie. A failed factor returns 401 with an opaque
// message (never leaking whether the username or the code was wrong).
func (h *HumanAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !h.allowPrincipal(w, req.Username, "public") {
		return
	}
	if req.Username == "" || req.TOTPCode == "" {
		writeJSONError(w, http.StatusBadRequest, "username and totp_code are required")
		return
	}
	user, err := h.Store.GetUserByName(r.Context(), req.Username)
	if err != nil {
		// Unknown user → opaque 401 (no user-enumeration oracle).
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.Auth.VerifyTOTP(r.Context(), user.ID, req.TOTPCode); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	h.issueSessionCookie(w, r, user.ID)
}

// enrollmentAuthRequest carries a fresh proof of an EXISTING factor. HTTP
// self-bootstrap is deliberately absent: the first factor is provisioned
// out-of-band by the operator/deployer, after which factor additions and
// rotations require this step-up.
type enrollmentAuthRequest struct {
	CurrentTOTP string `json:"current_totp"`
}

// handleTOTPEnroll rotates a TOTP secret only after a fresh proof of the
// existing TOTP factor. A session alone is insufficient: a stolen long-lived
// cookie must not be able to replace every factor. Users with no factor must
// be bootstrapped out-of-band; the reference app intentionally has no
// self-enrollment flow.
func (h *HumanAPI) handleTOTPEnroll(w http.ResponseWriter, r *http.Request, userID string) {
	var auth enrollmentAuthRequest
	if !decodeJSON(w, r, &auth) {
		return
	}
	if auth.CurrentTOTP == "" {
		writeJSONError(w, http.StatusUnauthorized, "factor step-up required")
		return
	}
	if _, err := h.Auth.StepUp(r.Context(), userID, StepUpTOTP, auth.CurrentTOTP); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "factor step-up required")
		return
	}
	user, err := h.Store.GetUser(r.Context(), userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "load user")
		return
	}
	enr, err := h.Auth.EnrollTOTP(r.Context(), userID, user.Username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "enroll totp")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": enr.Secret,
		"uri":    enr.URI,
	})
}

// totpVerifyRequest is the POST /auth/totp/verify body. It verifies a
// code for an explicit username WITHOUT issuing a session — a primitive
// the UI uses to confirm a freshly enrolled secter works before relying
// on it, and the step-up path for a TOTP re-auth.
type totpVerifyRequest struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

// handleTOTPVerify checks a code and reports valid/invalid. It does NOT
// mint a session (that is /auth/login's job); it is the bare verify verb.
func (h *HumanAPI) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req totpVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !h.allowPrincipal(w, req.Username, "public") {
		return
	}
	if req.Username == "" || req.Code == "" {
		writeJSONError(w, http.StatusBadRequest, "username and code are required")
		return
	}
	user, err := h.Store.GetUserByName(r.Context(), req.Username)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := h.Auth.VerifyTOTP(r.Context(), user.ID, req.Code); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

// handleWebAuthnRegisterBegin (session-gated) starts a passkey
// registration for the logged-in operator. Returns the creation options
// (for navigator.credentials.create) and an opaque challenge_id the
// client returns on finish.
func (h *HumanAPI) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request, userID string) {
	var auth enrollmentAuthRequest
	if !decodeJSON(w, r, &auth) {
		return
	}
	if auth.CurrentTOTP == "" {
		writeJSONError(w, http.StatusUnauthorized, "factor step-up required")
		return
	}
	if _, err := h.Auth.StepUp(r.Context(), userID, StepUpTOTP, auth.CurrentTOTP); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "factor step-up required")
		return
	}
	options, challengeID, err := h.Auth.BeginRegistration(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrAuthRateLimited) {
			writeRateLimited(w)
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "begin registration")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge_id": challengeID,
		"options":      options,
	})
}

// webauthnFinishRequest is the body shape for both register/finish and
// login/finish: the opaque challenge_id plus the raw authenticator
// response JSON the browser produced. We keep response as RawMessage so
// the WebAuthn parsers receive the exact bytes the authenticator signed.
type webauthnFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Response    json.RawMessage `json:"response"`
}

// handleWebAuthnRegisterFinish (session-gated) completes registration:
// validates the authenticator response against the stored challenge and
// persists the credential for the logged-in operator.
func (h *HumanAPI) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request, userID string) {
	var req webauthnFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ChallengeID == "" || len(req.Response) == 0 {
		writeJSONError(w, http.StatusBadRequest, "challenge_id and response are required")
		return
	}
	if _, err := h.Auth.FinishRegistration(r.Context(), userID, req.ChallengeID, req.Response); err != nil {
		if errors.Is(err, ErrAuthFailed) {
			writeJSONError(w, http.StatusUnauthorized, "registration failed")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "finish registration")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"registered": true})
}

// webauthnLoginBeginRequest is the POST /auth/webauthn/login/begin body:
// the username whose passkeys we are asserting against. (Login is public
// — no session yet — so the username is explicit, not session-derived.)
type webauthnLoginBeginRequest struct {
	Username string `json:"username"`
}

// handleWebAuthnLoginBegin starts a passkey assertion for username.
// Public route (it establishes a session). Returns assertion options +
// an opaque challenge_id.
func (h *HumanAPI) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req webauthnLoginBeginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !h.allowPrincipal(w, req.Username, "public") {
		return
	}
	if req.Username == "" {
		writeJSONError(w, http.StatusBadRequest, "username is required")
		return
	}
	user, err := h.Store.GetUserByName(r.Context(), req.Username)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	options, challengeID, err := h.Auth.BeginLogin(r.Context(), user.ID)
	if err != nil {
		if errors.Is(err, ErrAuthRateLimited) {
			writeRateLimited(w)
			return
		}
		// No credentials registered, etc. — opaque to avoid an oracle.
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge_id": challengeID,
		"options":      options,
	})
}

// webauthnLoginFinishRequest is the login/finish body: the username, the
// challenge_id from begin, and the authenticator assertion response.
type webauthnLoginFinishRequest struct {
	Username    string          `json:"username"`
	ChallengeID string          `json:"challenge_id"`
	Response    json.RawMessage `json:"response"`
}

// handleWebAuthnLoginFinish completes a passkey assertion and, on
// success, issues a session cookie. Public route (it establishes the
// session).
func (h *HumanAPI) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req webauthnLoginFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !h.allowPrincipal(w, req.Username, "public") {
		return
	}
	if req.Username == "" || req.ChallengeID == "" || len(req.Response) == 0 {
		writeJSONError(w, http.StatusBadRequest, "username, challenge_id and response are required")
		return
	}
	user, err := h.Store.GetUserByName(r.Context(), req.Username)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if _, err := h.Auth.FinishLogin(r.Context(), user.ID, req.ChallengeID, req.Response); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	h.issueSessionCookie(w, r, user.ID)
}

// handleLogout (session-gated) revokes the current session and clears the
// cookie.
func (h *HumanAPI) handleLogout(w http.ResponseWriter, r *http.Request, _ string) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		_ = h.Auth.RevokeSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, h.clearCookie())
	writeJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
}

// ---------------------------------------------------------------------
// ui routes
// ---------------------------------------------------------------------

// uiRequestSummary is the JSON shape of a pending/audit row in the UI. It
// is DISTINCT from the machine-plane pollResponse/auditEntry shapes — the
// UI gets its own representation so changing it can never perturb the
// frozen wire contract.
//
// The render-integrity + tally fields (CommandDetails, RequiredApprovals,
// Tally) are ADDITIVE — every original field keeps its exact JSON name so
// existing consumers and the loose /ui tests stay valid. Commands (the
// flattened text slice) is retained verbatim; CommandDetails is the richer
// per-command view the browser cross-checks (server, host-key FP, exact
// bytes, per-command SHA-256).
type uiRequestSummary struct {
	RequestID      string      `json:"request_id"`
	Status         string      `json:"status"`
	ClientID       string      `json:"client_id"`
	Commands       []string    `json:"commands"`
	CommandDetails []uiCommand `json:"command_details"`
	ApprovedBy     string      `json:"approved_by_user,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	ResolvedAt     *time.Time  `json:"resolved_at,omitempty"`
	// RequiredApprovals is the N threshold stored on the request (the
	// number of distinct approving operators needed). Mirrored into
	// Tally.Required for the card.
	RequiredApprovals int `json:"required_approvals"`
	// ViewerVote is populated only on the detail route when the authenticated
	// operator has already cast an audited vote. It lets the reference app keep
	// controls disabled across reloads without exposing any new machine-plane
	// state.
	ViewerVote string `json:"viewer_vote,omitempty"`
	// Tally is the N-of-M vote progress, built from the append-only vote
	// ledger. It is populated with counts on the pending LIST rows (Voters
	// omitted for leanness) and with the full voter list on the
	// /ui/request/{id} detail. nil (omitted) where no tally is computed
	// (e.g. the audit list).
	Tally *uiTally `json:"tally,omitempty"`
}

// uiCommand is the per-command render-integrity view. It surfaces the
// fields summarize() previously dropped (Server, HostKeyFP, TTLSeconds)
// plus a per-command SHA-256 over the EXACT command bytes — the value a
// human cross-checks against what the agent showed them. Additive: it sits
// alongside the retained Commands []string, never replacing it.
type uiCommand struct {
	Server     string `json:"server"`                // signRequestCmd.Server (was dropped)
	Cmd        string `json:"cmd"`                   // exact command text
	HostKeyFP  string `json:"host_key_fp,omitempty"` // signRequestCmd.HostKeyFP (was dropped)
	TTLSeconds int64  `json:"ttl_seconds"`           // signRequestCmd.TTLSeconds (was dropped)
	SHA256     string `json:"sha256"`                // hex sha256([]byte(cmd)) — NEW
}

// uiTally is the N-of-M vote tally for a request. Required mirrors the
// stored RequiredApprovals (N); Approvals/Denials are the counts of votes
// cast so far; Voters is the per-vote list (populated only on the detail
// view). NOTE (per DESIGN §3b): the store tracks N and the votes actually
// cast, NOT an eligible-operator pool M — so "M" is rendered as votes
// cast, never a fabricated eligible count.
type uiTally struct {
	Required  int       `json:"required"`  // N (mirror of required_approvals)
	Approvals int       `json:"approvals"` // count of approve votes
	Denials   int       `json:"denials"`   // count of deny votes
	Voters    []uiVoter `json:"voters"`    // who voted (detail view only)
}

// uiVoter is one row of the vote ledger as surfaced to the UI.
type uiVoter struct {
	Operator    string    `json:"operator"`
	Decision    string    `json:"decision"`     // "approve" | "deny"
	AuthnMethod string    `json:"authn_method"` // "session" | "totp" | "webauthn"
	TS          time.Time `json:"ts"`
}

func summarize(r *store.Request) uiRequestSummary {
	var cmdObjs []signRequestCmd
	_ = json.Unmarshal(r.Commands, &cmdObjs)
	cmds := make([]string, len(cmdObjs))
	details := make([]uiCommand, len(cmdObjs))
	for i, c := range cmdObjs {
		cmds[i] = c.Cmd
		// Per-command SHA-256 over the EXACT command bytes (not the whole
		// blob) — this is the fingerprint a human eyeballs against the
		// agent's prompt.
		sum := sha256.Sum256([]byte(c.Cmd))
		details[i] = uiCommand{
			Server:     c.Server,
			Cmd:        c.Cmd,
			HostKeyFP:  c.HostKeyFP,
			TTLSeconds: c.TTLSeconds,
			SHA256:     hex.EncodeToString(sum[:]),
		}
	}
	return uiRequestSummary{
		RequestID:         r.RequestID,
		Status:            string(r.Status),
		ClientID:          r.ClientID,
		Commands:          cmds,
		CommandDetails:    details,
		ApprovedBy:        r.ApprovedBy,
		CreatedAt:         r.CreatedAt,
		ResolvedAt:        r.ResolvedAt,
		RequiredApprovals: r.RequiredApprovals,
	}
}

// buildTally computes the N-of-M vote tally for a request from the
// append-only vote ledger (Store.ListVotes). When includeVoters is false
// (the pending LIST rows) only the counts are populated and the voter list
// is left empty, keeping the list response lean; when true (the
// /ui/request/{id} detail) the full voter list is included so an approver
// sees who has already voted.
//
// COST: this issues ONE ListVotes query per call. On the pending list that
// is O(rows) queries (one per pending row). At v2.0 scale ListPending
// returns a handful of rows, so this is acceptable; a batched
// multi-request vote query is a v2.1 optimisation. On a ListVotes error we
// return nil (the tally is simply omitted) rather than failing the whole
// summary — the render-integrity fields still render.
func (h *HumanAPI) buildTally(ctx context.Context, requestID string, required int, includeVoters bool) *uiTally {
	votes, err := h.Store.ListVotes(ctx, requestID)
	if err != nil {
		return nil
	}
	t := &uiTally{Required: required, Voters: []uiVoter{}}
	for _, v := range votes {
		switch v.Decision {
		case store.DecisionApprove:
			t.Approvals++
		case store.DecisionDeny:
			t.Denials++
		}
		if includeVoters {
			t.Voters = append(t.Voters, uiVoter{
				Operator:    v.Operator,
				Decision:    string(v.Decision),
				AuthnMethod: v.AuthnMethod,
				TS:          v.TS,
			})
		}
	}
	return t
}

// handleUIPending lists the pending requests awaiting human decision.
func (h *HumanAPI) handleUIPending(w http.ResponseWriter, r *http.Request, _ string) {
	const pageSize = 50
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		var err error
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 1_000_000 {
			writeJSONError(w, http.StatusBadRequest, "invalid offset")
			return
		}
	}
	var (
		rows []*store.Request
		err  error
	)
	if pager, ok := h.Store.(interface {
		ListPendingPage(context.Context, int, int) ([]*store.Request, error)
	}); ok {
		rows, err = pager.ListPendingPage(r.Context(), pageSize+1, offset)
	} else {
		// Compatibility path for an external Store written before pagination.
		// Its ListPending implementation owns retrieval bounds; slice the result
		// before rendering so the HTTP response itself remains bounded.
		rows, err = h.Store.ListPending(r.Context())
		if err == nil {
			if offset >= len(rows) {
				rows = nil
			} else {
				rows = rows[offset:]
			}
		}
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list pending")
		return
	}
	hasMore := len(rows) > pageSize
	if hasMore {
		rows = rows[:pageSize]
	}
	out := make([]uiRequestSummary, 0, len(rows))
	for _, row := range rows {
		sum := summarize(row)
		// Counts-only tally per row (Voters omitted). One ListVotes per
		// row — O(rows), acceptable at v2.0 scale (see buildTally).
		sum.Tally = h.buildTally(r.Context(), row.RequestID, row.RequiredApprovals, false)
		out = append(out, sum)
	}
	response := map[string]interface{}{"pending": out, "has_more": hasMore}
	if hasMore {
		response["next_offset"] = offset + len(out)
	}
	writeJSON(w, http.StatusOK, response)
}

// handleUIRequest returns one request's detail by id.
func (h *HumanAPI) handleUIRequest(w http.ResponseWriter, r *http.Request, userID string) {
	id := r.PathValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing request id")
		return
	}
	row, err := h.Store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "unknown request_id")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "get request")
		return
	}
	sum := summarize(row)
	// Full tally including the voter list on the detail view.
	sum.Tally = h.buildTally(r.Context(), row.RequestID, row.RequiredApprovals, true)
	if sum.Tally != nil {
		for _, vote := range sum.Tally.Voters {
			if vote.Operator == userID {
				sum.ViewerVote = vote.Decision
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, sum)
}

// voteRequest is the body of approve/deny. step_up carries an optional
// fresh TOTP code for a per-action step-up; when HumanAPIConfig.
// RequireStepUp is set, a missing/invalid code is a 401 BEFORE the vote
// is cast. (A passkey step-up is performed via the login ceremony and
// then referenced — out of scope for the single POST; v2.1 ties an
// asserted-recently token here.)
type voteRequest struct {
	StepUpTOTP string `json:"step_up_totp,omitempty"`
}

// handleUIApprove records an APPROVE vote from the session operator,
// driving the Phase-C engine. When step-up is configured-on it enforces a
// fresh re-auth first. The authn method recorded on the vote reflects how
// the operator proved liveness for THIS action.
func (h *HumanAPI) handleUIApprove(w http.ResponseWriter, r *http.Request, userID string) {
	h.handleVote(w, r, userID, store.DecisionApprove)
}

// handleUIDeny records a DENY vote from the session operator.
func (h *HumanAPI) handleUIDeny(w http.ResponseWriter, r *http.Request, userID string) {
	h.handleVote(w, r, userID, store.DecisionDeny)
}

// handleVote is the shared approve/deny body. It (optionally) enforces a
// step-up, then submits the vote to the engine and renders the outcome.
func (h *HumanAPI) handleVote(w http.ResponseWriter, r *http.Request, userID string, decision store.Decision) {
	id := r.PathValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing request id")
		return
	}
	var req voteRequest
	// The frozen human contract permits an empty body when step-up is disabled.
	// The mutation middleware still requires an exact trusted Origin and an
	// application/json content type, closing CSRF without changing that body
	// contract. Non-empty bodies are decoded strictly and size-capped.
	if r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}

	// authnMethod records how the operator proved liveness for THIS vote,
	// for the audit trail. With step-up off, the session itself is the
	// proof; with it on, the fresh factor is.
	authnMethod := "session"
	if h.Cfg.RequireStepUp {
		if !h.allowAuth(w, r, userID, "vote") {
			return
		}
		// Per-action step-up enforcement (the #2 product flag). We support
		// a TOTP step-up inline; the mechanism's StepUp verb is the seam.
		if _, err := h.Auth.StepUp(r.Context(), userID, StepUpTOTP, req.StepUpTOTP); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "step-up required")
			return
		}
		authnMethod = string(StepUpTOTP)
	}

	outcome, err := h.Engine.SubmitVote(r.Context(), id, userID, decision, authnMethod, h.Cfg.ApprovalPolicy)
	if err != nil {
		switch {
		case errors.Is(err, ErrRequestNotFound):
			writeJSONError(w, http.StatusNotFound, "unknown request_id")
		case errors.Is(err, ErrAlreadyResolved):
			writeJSONError(w, http.StatusConflict, "request already resolved")
		case errors.Is(err, store.ErrVoteConflict):
			writeJSONError(w, http.StatusConflict, "operator already voted")
		default:
			writeJSONError(w, http.StatusInternalServerError, "submit vote")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": id,
		"decision":   string(outcome.Decision),
		"flipped":    outcome.Flipped,
	})
}

// handleUIAudit returns the recent decisions for the UI's audit view. It
// reuses the store's RecentAudit but renders the UI summary shape.
func (h *HumanAPI) handleUIAudit(w http.ResponseWriter, r *http.Request, _ string) {
	rows, err := h.Store.RecentAudit(r.Context(), 100)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit")
		return
	}
	out := make([]uiRequestSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, summarize(row))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": out})
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

// issueSessionCookie mints a session for userID and sets it as an
// HttpOnly cookie. The Secure attribute follows HumanAPIConfig (prod =
// true). On a store failure it 500s without setting a cookie.
func (h *HumanAPI) issueSessionCookie(w http.ResponseWriter, r *http.Request, userID string) {
	sess, err := h.Auth.IssueSession(r.Context(), userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "issue session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  sess.ExpiresAt,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"expires_at":    sess.ExpiresAt,
	})
}

// clearCookie returns an expired session cookie to clear the browser's
// copy on logout.
func (h *HumanAPI) clearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}

func (h *HumanAPI) allowMutation(w http.ResponseWriter, r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || !h.Auth.allowsOrigin(origin) {
		writeJSONError(w, http.StatusForbidden, "forbidden origin")
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "application/json required")
		return false
	}
	return true
}

// decodeJSON reads a size-capped JSON body into v with unknown fields
// rejected. On a malformed/oversize body it writes 400 and returns false
// so the caller can return early.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	body, err := readLimited(r.Body, maxHumanBody)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body: "+err.Error())
		return false
	}
	if err := decodeStrictJSON(body, v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return false
	}
	return true
}

// decodeStrictJSON accepts exactly one JSON value. Decoder.Decode alone
// silently accepts a valid object followed by another JSON value, which is a
// request-smuggling ambiguity between middleware and handlers.
func decodeStrictJSON(body []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// readLimited reads up to limit+1 bytes from rc and errors if the body
// exceeds limit. It always closes rc. Returning the bytes (rather than a
// reader) lets a handler both decode an envelope and hand the raw inner
// JSON to the WebAuthn parsers.
func readLimited(rc io.ReadCloser, limit int64) ([]byte, error) {
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("request body too large")
	}
	return b, nil
}

const (
	authRateWindow  = time.Minute
	authRateMax     = 12
	authRateEntries = 4096
)

type authRateBucket struct {
	windowStart time.Time
	count       int
}

// authRateLimiter is a bounded fixed-window limiter. It intentionally fails
// closed for a new key when its bounded table is full of live buckets; an
// attacker cannot turn spoofed usernames into unbounded server memory.
type authRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]authRateBucket
	now     func() time.Time
}

func newAuthRateLimiter() *authRateLimiter {
	return &authRateLimiter{buckets: make(map[string]authRateBucket), now: time.Now}
}

func (l *authRateLimiter) allow(key string) bool {
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok {
		if now.Sub(b.windowStart) >= authRateWindow {
			l.buckets[key] = authRateBucket{windowStart: now, count: 1}
			return true
		}
		if b.count >= authRateMax {
			return false
		}
		b.count++
		l.buckets[key] = b
		return true
	}
	if len(l.buckets) >= authRateEntries {
		for k, b := range l.buckets {
			if now.Sub(b.windowStart) >= authRateWindow {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) >= authRateEntries {
			return false
		}
	}
	l.buckets[key] = authRateBucket{windowStart: now, count: 1}
	return true
}

func (h *HumanAPI) authLimiter() *authRateLimiter {
	h.limitOnce.Do(func() { h.limits = newAuthRateLimiter() })
	return h.limits
}

func (h *HumanAPI) allowAuth(w http.ResponseWriter, r *http.Request, principal, scope string) bool {
	host := h.authClientIP(r)
	if !h.authLimiter().allow(scope + ":ip:" + host) {
		writeRateLimited(w)
		return false
	}
	if principal != "" && !h.allowPrincipal(w, principal, scope) {
		return false
	}
	return true
}

func (h *HumanAPI) authClientIP(r *http.Request) string {
	host := r.RemoteAddr
	if parsed, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsed
	}
	peer := net.ParseIP(strings.TrimSpace(host))
	if peer != nil {
		host = peer.String()
	}
	if !h.Cfg.TrustProxyHeaders || peer == nil || !peer.IsLoopback() {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if ip := net.ParseIP(strings.TrimSpace(parts[i])); ip != nil {
			return ip.String()
		}
	}
	return host
}

func (h *HumanAPI) allowPrincipal(w http.ResponseWriter, principal, scope string) bool {
	// Hash attacker-controlled names before using them as map keys: the table is
	// count-bounded and each key is fixed-size.
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(principal))))
	if !h.authLimiter().allow(scope + ":principal:" + hex.EncodeToString(sum[:])) {
		writeRateLimited(w)
		return false
	}
	return true
}

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSONError(w, http.StatusTooManyRequests, "too many authentication attempts")
}
