package hosted

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
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
// Persistent state lives in the store; the vote MAC key lives only in memory.
// Safe for concurrent use after attachment.
type HumanAPI struct {
	Auth   *AuthManager
	Engine *ApprovalEngine
	Store  store.Store
	Cfg    HumanAPIConfig

	legacyRedactor func(string, [32]byte, []redact.Rule) (string, bool)
	ordinaryEngine func() *ApprovalV2Engine
	voteMACKey     *[32]byte
	limitOnce      sync.Once
	limits         *authRateLimiter
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
// session ID and expiry into the request context and passes the operator ID
// to the downstream handler.
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
		ctx := context.WithValue(r.Context(), voteSessionContextKey{}, voteSession{ID: sess.ID, ExpiresAt: sess.ExpiresAt})
		next(w, r.WithContext(ctx), sess.UserID)
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
	mux.Handle("GET /ui/v2/request/{handle}", h.withSession(h.handleUIV2Request))
	mux.Handle("POST /ui/v2/request/{handle}/approve", h.withSessionMutation(h.handleUIV2Vote))
	mux.Handle("POST /ui/v2/request/{handle}/deny", h.withSessionMutation(h.handleUIV2Vote))
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
// existing consumers and the loose /ui tests stay valid. Both command fields
// carry redacted display text; the digest identifies the original bytes.
type uiRequestSummary struct {
	Redacted       bool        `json:"redacted"`
	DisplayFailed  bool        `json:"display_failed"`
	LegacyLabel    string      `json:"legacy_label"`
	TerminalReason string      `json:"terminal_reason,omitempty"`
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
	Tally         *uiTally       `json:"tally,omitempty"`
	VoteChallenge *voteChallenge `json:"vote_challenge,omitempty"`
}

// uiCommand is the per-command render-integrity view. It surfaces the
// fields summarize() previously dropped (Server, HostKeyFP, TTLSeconds)
// plus a per-command SHA-256 over the EXACT command bytes — the value a
// human cross-checks against what the agent showed them. Additive: it sits
// alongside the retained Commands []string, never replacing it.
type uiCommand struct {
	Redacted      bool   `json:"redacted"`
	RedactedLabel string `json:"redacted_label,omitempty"`
	Server        string `json:"server"`                // signRequestCmd.Server (was dropped)
	Cmd           string `json:"cmd"`                   // redacted display text
	HostKeyFP     string `json:"host_key_fp,omitempty"` // signRequestCmd.HostKeyFP (was dropped)
	TTLSeconds    int64  `json:"ttl_seconds"`           // signRequestCmd.TTLSeconds (was dropped)
	SHA256        string `json:"sha256"`                // hex sha256([]byte(cmd)) — NEW
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

func (h *HumanAPI) summarize(r *store.Request) uiRequestSummary {
	var salt [32]byte
	rand.Read(salt[:])
	defer clear(salt[:])
	redactor := h.legacyRedactor
	if redactor == nil {
		redactor = redact.RedactString
	}
	return summarizeWithRedactor(r, salt, redactor)
}

func summarizeWithSalt(r *store.Request, salt [32]byte) uiRequestSummary {
	return summarizeWithRedactor(r, salt, redact.RedactString)
}

func summarizeWithRedactor(r *store.Request, salt [32]byte, redactor func(string, [32]byte, []redact.Rule) (string, bool)) uiRequestSummary {
	defer clear(salt[:])
	var cmdObjs []signRequestCmd
	displayFailed := json.Unmarshal(r.Commands, &cmdObjs) != nil
	anyRedacted := false
	cmds := make([]string, len(cmdObjs))
	details := make([]uiCommand, len(cmdObjs))
	for i, c := range cmdObjs {
		display, ok := redactor(c.Cmd, salt, redactrules.Combined())
		if !ok {
			display = "[command unavailable]"
			displayFailed = true
		}
		isRedacted := display != c.Cmd
		anyRedacted = anyRedacted || isRedacted
		label := ""
		if isRedacted {
			label = ap.LabelRedactedDisplay
		}
		cmds[i] = display
		// Per-command SHA-256 over the EXACT command bytes (not the whole
		// blob) — this is the fingerprint a human eyeballs against the
		// agent's prompt.
		sum := sha256.Sum256([]byte(c.Cmd))
		details[i] = uiCommand{
			Redacted:      isRedacted,
			RedactedLabel: label,
			Server:        c.Server,
			Cmd:           cmds[i],
			HostKeyFP:     c.HostKeyFP,
			TTLSeconds:    c.TTLSeconds,
			SHA256:        hex.EncodeToString(sum[:]),
		}
	}
	return uiRequestSummary{
		Redacted:          anyRedacted,
		DisplayFailed:     displayFailed,
		LegacyLabel:       ap.LabelLegacyIntent,
		TerminalReason:    r.TerminalReason,
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
func (h *HumanAPI) handleUIPending(w http.ResponseWriter, r *http.Request, userID string) {
	v2, more, cursor, err := h.pendingV2(r, userID)
	if err != nil {
		writeUIListError(w, err)
		return
	}
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
	var rows []*store.Request
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
		sum := h.summarize(row)
		// Counts-only tally per row (Voters omitted). One ListVotes per
		// row — O(rows), acceptable at v2.0 scale (see buildTally).
		sum.Tally = h.buildTally(r.Context(), row.RequestID, row.RequiredApprovals, false)
		out = append(out, sum)
	}
	response := map[string]interface{}{"pending": out, "has_more": hasMore, "v2_pending": v2, "v2_has_more": more}
	if more {
		response["v2_next_cursor"] = cursor
	}
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
	sum := h.summarize(row)
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
	challenge, err := h.issueVoteChallenge(r.Context(), legacyVoteBinding(row, userID), legacyVoteExpiry(row))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "issue challenge")
		return
	}
	sum.VoteChallenge = &challenge
	writeJSON(w, http.StatusOK, sum)
}

// resolveUIV2 uses the operator-wide handle index, never a requester ID.
func (h *HumanAPI) resolveUIV2(w http.ResponseWriter, r *http.Request) *sqlitestore.V2Row {
	reader, ok := h.Store.(interface {
		ByHandleV2(context.Context, string) (*sqlitestore.V2Row, error)
	})
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable, "approvals unavailable")
		return nil
	}
	row, err := reader.ByHandleV2(r.Context(), r.PathValue("handle"))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeJSONError(w, http.StatusNotFound, "unknown handle")
		case IsApprovalBusy(err):
			writeJSONError(w, http.StatusServiceUnavailable, "busy — retry")
		case errors.Is(err, sqlitestore.ErrV2AmbiguousHandle):
			writeJSONError(w, http.StatusConflict, "ambiguous handle")
		default:
			writeJSONError(w, http.StatusInternalServerError, "get request")
		}
		return nil
	}
	return row
}

func (h *HumanAPI) handleUIV2Vote(w http.ResponseWriter, r *http.Request, userID string) {
	decision := store.DecisionApprove
	if strings.HasSuffix(r.URL.Path, "/deny") {
		decision = store.DecisionDeny
	}
	h.handleVote(w, r, userID, decision)
}

type uiV2Request struct {
	RecordHandle      string               `json:"record_handle"`
	SubPrincipal      string               `json:"sub_principal"`
	RequestID         string               `json:"request_id"`
	PlanHash          string               `json:"plan_hash"`
	ApprovalStatus    ap.ApprovalStatus    `json:"approval_status"`
	RequestExpiresAt  time.Time            `json:"request_expires_at"`
	RequiredApprovals int                  `json:"required_approvals"`
	Reason            string               `json:"rationale_redacted"`
	Votes             []ap.Vote            `json:"votes"`
	Pruned            bool                 `json:"pruned"`
	Details           string               `json:"details,omitempty"`
	Review            *approvalreview.View `json:"review,omitempty"`
	VoteChallenge     *voteChallenge       `json:"vote_challenge,omitempty"`
}

func (h *HumanAPI) handleUIV2Request(w http.ResponseWriter, r *http.Request, userID string) {
	row := h.resolveUIV2(w, r)
	if row == nil {
		return
	}
	out, err := renderUIV2(row)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "get review")
		return
	}
	binding := v2VoteBinding(row, userID)
	if row.Record.Header.Decision != nil {
		binding.AllowedActions = []string{}
	}
	challenge, err := h.issueVoteChallenge(r.Context(), binding, row.Record.Header.RequestExpiresAt)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "issue challenge")
		return
	}
	out.VoteChallenge = &challenge
	writeJSON(w, http.StatusOK, out)
}

func renderUIV2(row *sqlitestore.V2Row) (uiV2Request, error) {
	rec := row.Record
	header := rec.Header
	assist := approvalreview.Assist{State: ap.AssistPreparing}
	if header.Assist != nil {
		assist.State, assist.Reason = header.Assist.State, header.Assist.Reason
		if rec.Payload != nil {
			assist.Result = rec.Payload.AssistResult
		}
	}
	out := uiV2Request{
		RecordHandle: row.RecordHandle, SubPrincipal: approvalreview.NeutralizeText(header.SubPrincipal),
		RequestID: header.RequestID, PlanHash: header.PlanHash, ApprovalStatus: ap.ApprovalPending,
		RequestExpiresAt: header.RequestExpiresAt, RequiredApprovals: header.RequiredApprovals,
		Reason: header.RationaleRedacted, Pruned: header.Shed,
	}
	if header.Decision != nil {
		out.ApprovalStatus = header.Decision.Status
	}
	for _, vote := range header.Votes {
		vote.Operator = approvalreview.NeutralizeText(vote.Operator)
		out.Votes = append(out.Votes, vote)
	}
	if header.Shed {
		out.Details = "details pruned"
	} else {
		snapshot, err := approvalreview.DecodeSnapshot(rec.Payload.ReviewSnapshot)
		if err != nil {
			return uiV2Request{}, err
		}
		view, err := approvalreview.BuildView(snapshot, assist)
		if err != nil {
			return uiV2Request{}, err
		}
		out.Review = &view
	}
	return out, nil
}

// voteRequest is the body of approve/deny. step_up carries an optional
// fresh TOTP code for a per-action step-up; when HumanAPIConfig.
// RequireStepUp is set, a missing/invalid code is a 401 BEFORE the vote
// is cast. (A passkey step-up is performed via the login ceremony and
// then referenced — out of scope for the single POST; v2.1 ties an
// asserted-recently token here.)
type voteRequest struct {
	Challenge  string `json:"challenge"`
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

var errVoteOperatorRole = errors.New("hosted: operator role required")

// handleVote checks the live view before spending a step-up proof.
func (h *HumanAPI) handleVote(w http.ResponseWriter, r *http.Request, userID string, decision store.Decision) {
	ctx := r.Context()
	isV2 := r.PathValue("handle") != ""
	var legacy *store.Request
	var row *sqlitestore.V2Row
	var engine *ApprovalV2Engine
	var binding ap.ChallengeBinding
	authn := "session"
	if isV2 {
		row = h.resolveUIV2(w, r)
		if row == nil {
			return
		}
		if h.ordinaryEngine != nil {
			engine = h.ordinaryEngine()
		}
		if engine == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "busy — retry")
			return
		}
		rec, answer, err := engine.transact(ctx, row.Key, func(tx *sql.Tx, before *ap.R1, now ap.Now) (ap.Command, ap.Inputs, error) {
			if before == nil {
				return nil, ap.Inputs{}, &ap.CodeError{Code: ap.CodeNotFound}
			}
			after, _ := ap.Apply(before, ap.Tick{}, now, ap.Inputs{Epoch: engine.epoch, Settings: engine.config.Settings})
			var role string
			roleErr := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", userID).Scan(&role)
			if roleErr != nil && !errors.Is(roleErr, sql.ErrNoRows) {
				return nil, ap.Inputs{}, approvalTransactionError(roleErr)
			}
			if after.Header.Decision != nil && role == "operator" {
				return ap.CastVote{Operator: userID, Decision: string(decision), Authn: authn, Hosted: &ap.HostedTap{}}, ap.Inputs{}, nil
			}
			return ap.Tick{}, ap.Inputs{}, nil
		})
		if h.voteV2Error(w, err, false) {
			return
		}
		if answer.Noise || rec.Header.Decision != nil {
			writeJSONError(w, http.StatusConflict, "request already resolved")
			return
		}
		row.Record = rec
		binding = v2VoteBinding(row, userID)
	} else {
		id := r.PathValue("id")
		var err error
		legacy, err = h.Store.GetByID(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "unknown request_id")
			} else {
				writeJSONError(w, http.StatusInternalServerError, "get request")
			}
			return
		}
		if legacy.Status == store.StatusPending && !h.Auth.now().Before(legacyVoteExpiry(legacy)) {
			resolver, ok := h.Store.(store.LegacyResolver)
			if !ok {
				writeJSONError(w, http.StatusInternalServerError, "expire request")
				return
			}
			if _, _, err = resolver.ExpireLegacy(ctx, id, h.Auth.now()); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "expire request")
				return
			}
			legacy, err = h.Store.GetByID(ctx, id)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "get request")
				return
			}
		}
		if legacy.Status != store.StatusPending {
			if user, err := h.Store.GetUser(ctx, userID); err == nil && user.Role == "operator" {
				h.auditLegacyResolved(ctx, legacy, userID, decision, authn)
			}
			writeJSONError(w, http.StatusConflict, "request already resolved")
			return
		}
		binding = legacyVoteBinding(legacy, userID)
	}
	user, err := h.Store.GetUser(ctx, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		if isV2 && IsApprovalBusy(err) {
			writeJSONError(w, http.StatusServiceUnavailable, "busy — retry")
		} else {
			writeJSONError(w, http.StatusInternalServerError, "get operator")
		}
		return
	}
	if user == nil || user.Role != "operator" {
		writeJSONError(w, http.StatusForbidden, "operator role required")
		return
	}
	var req voteRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	if req.Challenge == "" {
		writeJSONError(w, http.StatusBadRequest, "challenge is required")
		return
	}
	now := h.Auth.now()
	if isV2 {
		now = engine.now().Wall
	}
	refusal := h.verifyVoteChallenge(ctx, binding, req.Challenge, now)
	vote := ap.CastVote{Operator: userID, Decision: string(decision), Authn: authn,
		Flags:  ap.VoteFlags{DenyVeto: h.Cfg.ApprovalPolicy.DenyVeto, AllowSelfApprove: h.Cfg.ApprovalPolicy.AllowSelfApprove},
		Hosted: &ap.HostedTap{Refusal: refusal, PlanHash: binding.PlanHash, Revision: binding.AssistRevision, Digest: binding.AssistDigest, Actions: binding.AllowedActions}}
	if isV2 {
		// Probe with Apply under the writer lock, but commit only Clock or a refusal.
		// A replay with a valid view belongs to step 7, after step-up.
		checked, answer, err := engine.transact(ctx, row.Key, func(_ *sql.Tx, before *ap.R1, now ap.Now) (ap.Command, ap.Inputs, error) {
			if before == nil {
				return nil, ap.Inputs{}, &ap.CodeError{Code: ap.CodeNotFound}
			}
			inputs := ap.Inputs{Epoch: engine.epoch, Settings: engine.config.Settings}
			probe := vote
			probe.Hosted = &ap.HostedTap{Refusal: h.verifyVoteChallenge(ctx, binding, req.Challenge, now.Wall), PlanHash: binding.PlanHash, Revision: binding.AssistRevision, Digest: binding.AssistDigest, Actions: binding.AllowedActions}
			_, answer := ap.Apply(before, probe, now, inputs)
			after, _ := ap.Apply(before, ap.Tick{}, now, inputs)
			if after.Header.Decision != nil || (answer.Noise && answer.Reason != "" && answer.Reason != "set_full") {
				return probe, ap.Inputs{}, nil
			}
			return ap.Tick{}, ap.Inputs{}, nil
		})
		if h.voteV2Error(w, err, false) {
			return
		}
		if checked.Header.Decision != nil {
			writeJSONError(w, http.StatusConflict, "request already resolved")
			return
		}
		if answer.Noise {
			writeJSONError(w, http.StatusConflict, "view changed")
			return
		}
	} else if refusal != "" {
		h.auditLegacyVote(ctx, legacy, userID, decision, authn, "vote_refused{"+refusal+"}")
		writeJSONError(w, http.StatusConflict, "view changed")
		return
	}
	if !isV2 && decision == store.DecisionApprove && h.summarize(legacy).DisplayFailed {
		h.auditLegacyVote(ctx, legacy, userID, decision, authn, "vote_refused{display_unavailable}")
		writeJSONError(w, http.StatusConflict, "command display unavailable; approval refused")
		return
	}
	if h.Cfg.RequireStepUp {
		if !h.allowAuth(w, r, userID, "vote") {
			return
		}
		if _, err := h.Auth.StepUp(ctx, userID, StepUpTOTP, req.StepUpTOTP); err != nil {
			if isV2 && IsApprovalBusy(err) {
				writeJSONError(w, http.StatusServiceUnavailable, "busy — retry with a fresh code")
			} else {
				writeJSONError(w, http.StatusUnauthorized, "step-up required")
			}
			return
		}
		authn = string(StepUpTOTP)
	}
	if isV2 {
		vote.Authn = authn
		after, answer, err := engine.transact(ctx, row.Key, func(tx *sql.Tx, _ *ap.R1, now ap.Now) (ap.Command, ap.Inputs, error) {
			var role string
			err := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", userID).Scan(&role)
			if errors.Is(err, sql.ErrNoRows) || (err == nil && role != "operator") {
				return nil, ap.Inputs{}, errVoteOperatorRole
			}
			if err != nil {
				return nil, ap.Inputs{}, approvalTransactionError(err)
			}
			vote.Hosted.Refusal = h.verifyVoteChallenge(ctx, binding, req.Challenge, now.Wall)
			return vote, ap.Inputs{}, nil
		})
		if h.voteV2Error(w, err, h.Cfg.RequireStepUp) {
			return
		}
		if answer.Noise {
			message := "operator already voted"
			switch answer.Reason {
			case "set_full":
				message = "vote limit reached: this vote cannot change the outcome"
			case "resolved", "expired", "canceled":
				message = "request already resolved"
			case "stale_challenge", "expired_challenge", "session_mismatch", "action_not_allowed":
				message = "view changed"
			}
			writeJSONError(w, http.StatusConflict, message)
			return
		}
		result := "pending"
		if after.Header.Decision != nil {
			result = string(after.Header.Decision.Status)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"request_id": row.Key.RequestID, "decision": result, "flipped": after.Header.Decision != nil})
		return
	}
	votes, err := h.Store.ListVotes(ctx, legacy.RequestID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list votes")
		return
	}
	audited := false
	for _, vote := range votes {
		if vote.Operator == userID {
			h.auditLegacyVote(ctx, legacy, userID, decision, authn, "vote_duplicate")
			audited = true
			break
		}
	}
	outcome, err := h.Engine.SubmitVote(ctx, legacy.RequestID, userID, decision, authn, h.Cfg.ApprovalPolicy)
	if err != nil {
		switch {
		case errors.Is(err, ErrRequestNotFound):
			writeJSONError(w, http.StatusNotFound, "unknown request_id")
		case errors.Is(err, ErrAlreadyResolved):
			if !audited {
				current, readErr := h.Store.GetByID(ctx, legacy.RequestID)
				if readErr == nil {
					h.auditLegacyResolved(ctx, current, userID, decision, authn)
				}
			}
			writeJSONError(w, http.StatusConflict, "request already resolved")
		case errors.Is(err, store.ErrVoteConflict):
			if !audited {
				h.auditLegacyVote(ctx, legacy, userID, decision, authn, "vote_duplicate")
			}
			writeJSONError(w, http.StatusConflict, "operator already voted")
		default:
			writeJSONError(w, http.StatusInternalServerError, "submit vote")
		}
		return
	}
	if !outcome.Flipped {
		current, err := h.Store.GetByID(ctx, legacy.RequestID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "get request")
			return
		}
		expected := store.StatusApproved
		if decision == store.DecisionDeny {
			expected = store.StatusDenied
		}
		if current.Status != store.StatusPending && (current.Status != expected || current.TerminalReason != "") {
			writeJSONError(w, http.StatusConflict, "request already resolved")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"request_id": legacy.RequestID, "decision": string(outcome.Decision), "flipped": outcome.Flipped})
}

func legacyVoteExpiry(row *store.Request) time.Time {
	if row.ExpiresAt != nil {
		return *row.ExpiresAt
	}
	return row.CreatedAt.Add(24 * time.Hour)
}

func legacyVoteBinding(row *store.Request, operator string) ap.ChallengeBinding {
	return ap.ChallengeBinding{Plane: ap.PlaneV1, RecordKey: row.RequestID, PlanHash: ap.LegacyHostedPlanHash(row.RequestID, row.ClientID, row.Commands, row.CreatedAt, row.RequiredApprovals), Operator: operator, AllowedActions: []string{ap.ActionApprove, ap.ActionDeny}}
}

func v2VoteBinding(row *sqlitestore.V2Row, operator string) ap.ChallengeBinding {
	header := row.Record.Header
	binding := ap.ChallengeBinding{Plane: ap.PlaneV2, RecordKey: ap.HostedRecordKey(row.Key.ClientID, row.Key.SubPrincipal, row.Key.RequestID), PlanHash: header.PlanHash, Operator: operator}
	if header.Assist != nil {
		binding.AssistRevision, binding.AssistDigest = 1, header.Assist.Digest
	}
	binding.AllowedActions = ap.ActionsAt(binding.AssistRevision)
	return binding
}

func (h *HumanAPI) auditLegacyVote(ctx context.Context, row *store.Request, operator string, decision store.Decision, authn, transition string) {
	if err := h.Engine.Core.Verdict(ctx, signerkit.AuditVerdict{Time: h.Auth.now().UTC(), RequestID: row.RequestID,
		Operator: signerkit.Operator{ID: operator, DisplayName: operator, Verified: true, AuthnMethod: authn}, CommandSHA256: commandsSHA256(row.Commands), Approved: decision == store.DecisionApprove,
		Approval: &ap.AuditMetadata{Transition: transition, Decision: string(decision), Replay: true}}); err != nil {
		log.Print("hosted: inert vote audit failed")
	}
}

func (h *HumanAPI) auditLegacyResolved(ctx context.Context, row *store.Request, operator string, decision store.Decision, authn string) {
	votes, err := h.Store.ListVotes(ctx, row.RequestID)
	if err != nil {
		log.Print("hosted: inert vote audit could not load votes")
		return
	}
	for _, vote := range votes {
		if vote.Operator == operator {
			h.auditLegacyVote(ctx, row, operator, decision, authn, "vote_duplicate")
			return
		}
	}
	reason := "resolved"
	if row.TerminalReason == "expired" || row.TerminalReason == "canceled" {
		reason = row.TerminalReason
	}
	h.auditLegacyVote(ctx, row, operator, decision, authn, "vote_refused{"+reason+"}")
}

func (h *HumanAPI) voteV2Error(w http.ResponseWriter, err error, spent bool) bool {
	if err == nil {
		return false
	}
	var coded *ap.CodeError
	if errors.Is(err, errVoteOperatorRole) {
		writeJSONError(w, http.StatusForbidden, "operator role required")
	} else if errors.As(err, &coded) && coded.Code == ap.CodeBusy {
		message := "busy — retry"
		if spent {
			message = "busy — retry with a fresh code"
		}
		writeJSONError(w, http.StatusServiceUnavailable, message)
	} else if errors.As(err, &coded) && coded.Code == ap.CodeStorageUncertain {
		writeJSONError(w, http.StatusServiceUnavailable, "storage uncertain — retry")
	} else if errors.As(err, &coded) && coded.Code == ap.CodeNotFound {
		writeJSONError(w, http.StatusNotFound, "unknown handle")
	} else {
		writeJSONError(w, http.StatusInternalServerError, "submit vote")
	}
	return true
}

// handleUIAudit returns the recent decisions for the UI's audit view. It
// reuses the store's RecentAudit but renders the UI summary shape.
func (h *HumanAPI) handleUIAudit(w http.ResponseWriter, r *http.Request, userID string) {
	v2, err := h.auditV2(r, userID)
	if err != nil {
		writeUIListError(w, err)
		return
	}
	rows, err := h.Store.RecentAudit(r.Context(), 100)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit")
		return
	}
	out := make([]uiRequestSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, h.summarize(row))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": out, "v2_entries": v2})
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

var (
	errUIListCursor = errors.New("invalid v2_cursor")
	errUIListRole   = errors.New("reader role required")
)

// Both human roles can inspect approvals; only operators can vote.
func (h *HumanAPI) authorizeUIList(ctx context.Context, userID string) error {
	user, err := h.Store.GetUser(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return errUIListRole
	}
	if err != nil {
		return err
	}
	if user == nil || (user.Role != "operator" && user.Role != "admin") {
		return errUIListRole
	}
	return nil
}

func writeUIListError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUIListCursor):
		writeJSONError(w, http.StatusBadRequest, errUIListCursor.Error())
	case errors.Is(err, errUIListRole):
		writeJSONError(w, http.StatusForbidden, errUIListRole.Error())
	case IsApprovalBusy(err):
		writeJSONError(w, http.StatusServiceUnavailable, "busy — retry")
	default:
		writeJSONError(w, http.StatusInternalServerError, "list approvals")
	}
}

// Domain and session binding keep cursors separate from vote tokens and other logins.
func (h *HumanAPI) pendingCursorCipher(ctx context.Context) (cipher.AEAD, []byte, error) {
	session, ok := ctx.Value(voteSessionContextKey{}).(voteSession)
	if !ok || session.ID == "" || h.voteMACKey == nil {
		return nil, nil, errUIListCursor
	}
	key, err := hkdf.Key(sha256.New, h.voteMACKey[:], nil, "sshgate-ui-pending-cursor-v2", 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, []byte("sshgate-ui-pending-v2\x00" + ap.SessionBinding(session.ID)), err
}

func (h *HumanAPI) encodePendingCursor(ctx context.Context, row *sqlitestore.V2Row) (string, error) {
	aead, binding, err := h.pendingCursorCipher(ctx)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(sqlitestore.V2PendingCursor{CreatedAt: row.Record.Header.CreatedAt, Key: row.Key})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, data, binding)), nil
}

func (h *HumanAPI) decodePendingCursor(ctx context.Context, raw string) (*sqlitestore.V2PendingCursor, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errUIListCursor
	}
	aead, binding, err := h.pendingCursorCipher(ctx)
	if err != nil {
		return nil, err
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(token) < aead.NonceSize()+aead.Overhead() || base64.RawURLEncoding.EncodeToString(token) != raw {
		return nil, errUIListCursor
	}
	data, err := aead.Open(nil, token[:aead.NonceSize()], token[aead.NonceSize():], binding)
	if err != nil {
		return nil, errUIListCursor
	}
	var cursor sqlitestore.V2PendingCursor
	if json.Unmarshal(data, &cursor) != nil || cursor.CreatedAt.IsZero() || cursor.Key.ClientID == "" || !ap.ValidRequestID(cursor.Key.RequestID) {
		return nil, errUIListCursor
	}
	return &cursor, nil
}

func (h *HumanAPI) pendingV2(r *http.Request, userID string) ([]uiV2Request, bool, string, error) {
	out := make([]uiV2Request, 0)
	var cursor *sqlitestore.V2PendingCursor
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false, "", errUIListCursor
	}
	if values, present := query["v2_cursor"]; present {
		if len(values) != 1 {
			return nil, false, "", errUIListCursor
		}
		var err error
		cursor, err = h.decodePendingCursor(r.Context(), values[0])
		if err != nil {
			return nil, false, "", err
		}
	}
	reader, ok := h.Store.(interface {
		ListPendingV2(context.Context, *sqlitestore.V2PendingCursor, int) ([]*sqlitestore.V2Row, error)
	})
	if !ok {
		return out, false, "", nil
	}
	if err := h.authorizeUIList(r.Context(), userID); err != nil {
		return nil, false, "", err
	}
	rows, err := reader.ListPendingV2(r.Context(), cursor, 51)
	if err != nil {
		return nil, false, "", err
	}
	more := len(rows) > 50
	if more {
		rows = rows[:50]
	}
	for _, row := range rows {
		item, err := renderUIV2(row)
		if err != nil {
			return nil, false, "", err
		}
		out = append(out, item)
	}
	next := ""
	if more {
		next, err = h.encodePendingCursor(r.Context(), rows[len(rows)-1])
	}
	return out, more, next, err
}

type uiV2AuditEntry struct {
	RecordHandle      string            `json:"record_handle"`
	SubPrincipal      string            `json:"sub_principal"`
	Decision          ap.ApprovalStatus `json:"decision"`
	DecidedAt         time.Time         `json:"decided_at"`
	DecidedBy         string            `json:"decided_by"`
	Votes             []ap.Vote         `json:"votes"`
	RationaleRedacted string            `json:"rationale_redacted"`
	AssistBound       ap.AssistBound    `json:"assist_bound"`
}

func (h *HumanAPI) auditV2(r *http.Request, userID string) ([]uiV2AuditEntry, error) {
	out := make([]uiV2AuditEntry, 0)
	reader, ok := h.Store.(interface {
		RecentDecidedV2(context.Context, int) ([]*sqlitestore.V2Row, error)
	})
	if !ok {
		return out, nil
	}
	if err := h.authorizeUIList(r.Context(), userID); err != nil {
		return nil, err
	}
	rows, err := reader.RecentDecidedV2(r.Context(), 100)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		header := row.Record.Header
		decision := header.Decision
		if decision == nil {
			return nil, errors.New("decided approval missing decision")
		}
		votes := make([]ap.Vote, 0, len(header.Votes))
		for _, vote := range header.Votes {
			vote.Operator = approvalreview.NeutralizeText(vote.Operator)
			votes = append(votes, vote)
		}
		out = append(out, uiV2AuditEntry{
			RecordHandle: row.RecordHandle, SubPrincipal: approvalreview.NeutralizeText(header.SubPrincipal),
			Decision: decision.Status, DecidedAt: decision.DecidedAt, DecidedBy: approvalreview.NeutralizeText(decision.DecidedBy),
			Votes: votes, RationaleRedacted: header.RationaleRedacted, AssistBound: decision.AssistBound,
		})
	}
	return out, nil
}
