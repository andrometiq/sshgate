package signerserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// auth.go is Phase D: the human-plane AUTH MECHANISM. It provides the
// primitives — TOTP enroll/verify, WebAuthn registration + assertion,
// and opaque server-side sessions — that the Phase-E human-plane routes
// (/auth/*, /ui/*) sit on top of.
//
// MECHANISM, NOT POLICY. This file owns no product decision. It does
// not decide who may enroll, whether TOTP or a passkey is required,
// whether a step-up is needed per-approval or per-session, or how long
// a session lives by default — those are the caller's (Karthi's product
// layer) to set. What lives here are the verbs: enroll a secret, verify
// a code, register a credential, assert a credential, issue a session,
// validate it, revoke it, and the re-auth (step-up) primitive the
// approve route CAN call. The enforcement decision of when to demand a
// step-up is deliberately left to the route wiring + its configuration,
// never hardcoded here.
//
// RP-ID / origin is CONFIG. Passkeys are origin-bound: a credential
// registered for rp-id "signer.example.com" only asserts against that
// origin. The hostname is Karthi's deploy decision, so AuthConfig takes
// it as a parameter; AuthManager refuses to construct without it (an
// empty RP would silently accept any origin, which the WebAuthn lib
// itself rejects — we surface that as a construction error, not a
// runtime 500).

// AuthConfig carries the deploy-time, origin-bound configuration the
// auth mechanism needs. Every field is a deploy decision the caller
// supplies; none is defaulted to a product policy here.
type AuthConfig struct {
	// RPID is the WebAuthn Relying Party ID: the effective domain the
	// passkeys are bound to (e.g. "signer.example.com"), WITHOUT scheme
	// or port. Required — a passkey deployment has exactly one RP-ID and
	// it is a deploy decision.
	RPID string

	// RPDisplayName is the human-facing name shown in the authenticator
	// prompt (e.g. "SSHGate Signer"). Required only in that the WebAuthn
	// lib wants a non-empty display name; it is cosmetic.
	RPDisplayName string

	// RPOrigins is the set of fully-qualified origins permitted to drive
	// a ceremony (e.g. "https://signer.example.com"). Required and
	// origin-bound: an assertion whose origin is not in this set is
	// rejected by the WebAuthn lib. The caller lists every origin the UI
	// is actually served from.
	RPOrigins []string

	// SessionTTL is how long an issued session is valid. It is a knob,
	// NOT a product default: NewAuthManager requires a positive value so
	// the caller makes the lifetime an explicit choice rather than
	// inheriting a silent constant. (The route layer decides the value;
	// the mechanism only refuses a non-positive one.)
	SessionTTL time.Duration

	// TOTPIssuer is the issuer label embedded in the otpauth:// URI
	// (shown in the authenticator app as the account's service name).
	// Defaults to RPDisplayName when empty — purely cosmetic, no
	// security or policy weight.
	TOTPIssuer string

	// ChallengeTTL bounds how long a begin-ceremony challenge lives in
	// the in-memory store before it is swept. WebAuthn challenges are
	// single-use and short-lived; the lib also stamps SessionData.Expires.
	// Defaults to 5 minutes when zero.
	ChallengeTTL time.Duration
}

// AuthManager is the human-plane auth mechanism. It is safe for
// concurrent use: the store is concurrency-safe, the *webauthn.WebAuthn
// handle is read-only after construction, and the in-memory challenge
// store has its own mutex.
//
// It holds NO product policy. Routes call its verbs and apply their own
// (configurable) policy on top.
type AuthManager struct {
	store store.Store
	wa    *webauthn.WebAuthn
	cfg   AuthConfig

	// challenges holds in-flight WebAuthn ceremony state (the SessionData
	// the lib hands back from a Begin* call) keyed by an opaque handle we
	// mint and hand to the client. The client returns the handle with the
	// Finish* call so we can pair the response with the right challenge.
	// Short-lived and single-use: a successful or expired Finish removes
	// the entry.
	challenges *challengeStore

	// now is the clock, overridable in tests. Production uses time.Now.
	now func() time.Time

	// randRead is the entropy source for session/challenge IDs,
	// overridable in tests; production uses crypto/rand.
	randRead func([]byte) (int, error)
}

// NewAuthManager builds an AuthManager. It refuses every misconfiguration
// that would weaken the mechanism: a nil store, an empty RP-ID/origin
// (origin-bound passkeys need both), or a non-positive session TTL (so
// the caller cannot accidentally issue immortal or already-expired
// sessions). RP config validity is enforced by the WebAuthn lib's own
// validator, surfaced here as a construction error.
func NewAuthManager(st store.Store, cfg AuthConfig) (*AuthManager, error) {
	if st == nil {
		return nil, errors.New("signerserver: NewAuthManager: nil Store")
	}
	if cfg.RPID == "" {
		return nil, errors.New("signerserver: NewAuthManager: RPID is required (passkeys are origin-bound; it is a deploy decision)")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, errors.New("signerserver: NewAuthManager: at least one RPOrigin is required")
	}
	if cfg.SessionTTL <= 0 {
		return nil, errors.New("signerserver: NewAuthManager: SessionTTL must be > 0 (the lifetime is the caller's choice, not a baked default)")
	}
	display := cfg.RPDisplayName
	if display == "" {
		display = cfg.RPID
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: display,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("signerserver: NewAuthManager: webauthn config: %w", err)
	}
	if cfg.TOTPIssuer == "" {
		cfg.TOTPIssuer = display
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 5 * time.Minute
	}
	return &AuthManager{
		store:      st,
		wa:         wa,
		cfg:        cfg,
		challenges: newChallengeStore(),
		now:        time.Now,
		randRead:   rand.Read,
	}, nil
}

// ---------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------

// TOTPEnrollment is the result of EnrollTOTP: the freshly generated
// shared secret (base32) plus the otpauth:// URI the operator scans into
// their authenticator app. The secret is ALSO persisted via the store
// (SetTOTP); it is returned here only so the route can render the URI/QR
// to the enrolling operator once.
type TOTPEnrollment struct {
	// Secret is the base32 shared secret. Returned so a route can show it
	// as a manual-entry fallback; it is already stored server-side.
	Secret string
	// URI is the otpauth://totp/... provisioning URI (issuer + account +
	// secret) that a QR code encodes.
	URI string
}

// EnrollTOTP generates a fresh TOTP secret for userID, persists it via
// the store, and returns the secret + provisioning URI. Re-enrolling
// replaces any prior secret (SetTOTP is an upsert) — the caller's policy
// decides whether re-enroll is permitted; the mechanism just does it.
func (m *AuthManager) EnrollTOTP(ctx context.Context, userID, accountName string) (*TOTPEnrollment, error) {
	if userID == "" {
		return nil, errors.New("signerserver: EnrollTOTP: empty user_id")
	}
	if accountName == "" {
		accountName = userID
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.cfg.TOTPIssuer,
		AccountName: accountName,
	})
	if err != nil {
		return nil, fmt.Errorf("signerserver: EnrollTOTP: generate: %w", err)
	}
	if err := m.store.SetTOTP(ctx, userID, key.Secret()); err != nil {
		return nil, fmt.Errorf("signerserver: EnrollTOTP: persist: %w", err)
	}
	return &TOTPEnrollment{Secret: key.Secret(), URI: key.URL()}, nil
}

// ErrTOTPNotEnrolled is returned by VerifyTOTP when the user has no
// stored secret. It is distinct from a wrong-code failure so the route
// can distinguish "you never enrolled" from "wrong code".
var ErrTOTPNotEnrolled = errors.New("signerserver: TOTP not enrolled for user")

// ErrAuthFailed is the generic, deliberately opaque auth-failure
// sentinel: a wrong TOTP code, a failed assertion, etc. Routes map it to
// 401 without leaking which factor failed or why.
var ErrAuthFailed = errors.New("signerserver: authentication failed")

// VerifyTOTP checks code against the user's stored secret using the
// standard 30s period with ±1 period of skew (the RFC-6238 reflex: a
// single step of clock drift on either side is tolerated, more is not).
// Returns nil on a valid code, ErrAuthFailed on a wrong/expired code,
// ErrTOTPNotEnrolled if the user has no secret.
func (m *AuthManager) VerifyTOTP(ctx context.Context, userID, code string) error {
	if userID == "" {
		return errors.New("signerserver: VerifyTOTP: empty user_id")
	}
	secret, err := m.store.GetTOTP(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrTOTPNotEnrolled
		}
		return fmt.Errorf("signerserver: VerifyTOTP: load secret: %w", err)
	}
	// Explicit Digits/Algorithm: ValidateCustom does NOT default Digits
	// (a zero Digits validates against a 0-digit code and always fails),
	// so we pin the standard Google-Authenticator-compatible parameters
	// that totp.Generate produced the secret under.
	ok, err := totp.ValidateCustom(code, secret, m.now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !ok {
		return ErrAuthFailed
	}
	return nil
}

// ---------------------------------------------------------------------
// WebAuthn (passkeys)
// ---------------------------------------------------------------------

// waUser adapts a store.User + its stored credentials to the WebAuthn
// lib's User interface. The lib reads WebAuthnID (the stable user handle)
// and WebAuthnCredentials (the registered passkeys) to drive both
// registration (exclude already-registered) and login (allowed creds).
type waUser struct {
	id    string
	name  string
	creds []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadWAUser builds a waUser from the store: the user row + all their
// decoded passkey credentials. ErrNotFound propagates if the user does
// not exist.
func (m *AuthManager) loadWAUser(ctx context.Context, userID string) (*waUser, error) {
	u, err := m.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	rows, err := m.store.ListCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(row.Blob, &c); err != nil {
			return nil, fmt.Errorf("decode stored credential %d: %w", row.ID, err)
		}
		creds = append(creds, c)
	}
	return &waUser{id: u.ID, name: u.Username, creds: creds}, nil
}

// BeginRegistration starts a passkey registration ceremony for userID.
// It returns the credential-creation options to hand the browser
// (json-encodable) plus an opaque challengeID the client MUST return on
// FinishRegistration so the server can pair the response with the right
// challenge. The challenge is held in the short-lived in-memory store.
func (m *AuthManager) BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := m.loadWAUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	options, session, err := m.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("signerserver: BeginRegistration: %w", err)
	}
	now := m.now()
	id, err := m.challenges.put(session, ceremonyRegister, userID, now, now.Add(m.cfg.ChallengeTTL), m.newID)
	if err != nil {
		return nil, "", err
	}
	return options, id, nil
}

// FinishRegistration completes a passkey registration: it parses the
// authenticator response from body, validates it against the stored
// challenge, and on success persists the resulting credential via
// AddCredential. challengeID is the handle returned by BeginRegistration.
// The credential is stored as an opaque JSON blob (the lib's
// webauthn.Credential), with credential_id as the lookup key.
func (m *AuthManager) FinishRegistration(ctx context.Context, userID, challengeID string, body []byte) (*store.Credential, error) {
	entry, ok := m.challenges.take(challengeID, m.now())
	if !ok || entry.ceremony != ceremonyRegister || entry.userID != userID {
		return nil, ErrAuthFailed
	}
	user, err := m.loadWAUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, ErrAuthFailed
	}
	cred, err := m.wa.CreateCredential(user, *entry.session, parsed)
	if err != nil {
		return nil, ErrAuthFailed
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("signerserver: FinishRegistration: marshal credential: %w", err)
	}
	row := &store.Credential{
		UserID:       userID,
		CredentialID: cred.ID,
		Blob:         blob,
	}
	if err := m.store.AddCredential(ctx, row); err != nil {
		return nil, fmt.Errorf("signerserver: FinishRegistration: store: %w", err)
	}
	return row, nil
}

// BeginLogin starts a passkey assertion ceremony for userID. It returns
// the assertion options (the allowed credentials + challenge) plus an
// opaque challengeID for FinishLogin. The user must already have at
// least one registered credential, else the lib errors.
func (m *AuthManager) BeginLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, string, error) {
	user, err := m.loadWAUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	options, session, err := m.wa.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("signerserver: BeginLogin: %w", err)
	}
	now := m.now()
	id, err := m.challenges.put(session, ceremonyLogin, userID, now, now.Add(m.cfg.ChallengeTTL), m.newID)
	if err != nil {
		return nil, "", err
	}
	return options, id, nil
}

// FinishLogin completes a passkey assertion: it parses the response,
// validates it against the stored challenge + the user's registered
// credentials, and on success returns the matched credential. It does
// NOT issue a session — that is the route's call (a login route issues
// one; a step-up route just wants the boolean success). challengeID is
// the handle from BeginLogin.
//
// On a successful assertion the credential's signature counter may have
// advanced; we persist the updated credential blob so a future assertion
// sees the new counter (clone/replay detection). A persistence failure
// after a valid assertion is surfaced as an error, not swallowed.
func (m *AuthManager) FinishLogin(ctx context.Context, userID, challengeID string, body []byte) (*webauthn.Credential, error) {
	entry, ok := m.challenges.take(challengeID, m.now())
	if !ok || entry.ceremony != ceremonyLogin || entry.userID != userID {
		return nil, ErrAuthFailed
	}
	user, err := m.loadWAUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, ErrAuthFailed
	}
	cred, err := m.wa.ValidateLogin(user, *entry.session, parsed)
	if err != nil {
		return nil, ErrAuthFailed
	}
	// Persist the (possibly counter-advanced) credential so replay /
	// clone detection works across assertions.
	if err := m.updateCredential(ctx, userID, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// updateCredential rewrites the stored blob for the credential the
// assertion matched, preserving the advanced signature counter. It
// matches by raw credential_id. A missing match is a no-op (the
// credential was just validated against the loaded set, so it should
// exist; we do not fabricate a row).
func (m *AuthManager) updateCredential(ctx context.Context, userID string, cred *webauthn.Credential) error {
	rows, err := m.store.ListCredentials(ctx, userID)
	if err != nil {
		return fmt.Errorf("signerserver: updateCredential: list: %w", err)
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("signerserver: updateCredential: marshal: %w", err)
	}
	for _, row := range rows {
		if bytes.Equal(row.CredentialID, cred.ID) {
			if err := m.store.UpdateCredential(ctx, row.ID, blob); err != nil {
				return fmt.Errorf("signerserver: updateCredential: store: %w", err)
			}
			return nil
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------

// SessionCookieName is the cookie the session token rides in. It is set
// HttpOnly + Secure + SameSite=Strict by the route layer; the name lives
// here so the middleware and the issuing route agree on one constant.
const SessionCookieName = "sshgate_session"

// IssueSession mints a fresh opaque session for userID, persists the row
// (with the configured TTL), and returns the session. The session ID is
// the opaque token the cookie carries; it is 256 bits of crypto/rand,
// base64url. The caller sets it as a cookie.
func (m *AuthManager) IssueSession(ctx context.Context, userID string) (*store.Session, error) {
	if userID == "" {
		return nil, errors.New("signerserver: IssueSession: empty user_id")
	}
	id, err := m.newID()
	if err != nil {
		return nil, fmt.Errorf("signerserver: IssueSession: mint id: %w", err)
	}
	now := m.now().UTC()
	sess := &store.Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.cfg.SessionTTL),
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("signerserver: IssueSession: persist: %w", err)
	}
	return sess, nil
}

// ValidateSession resolves a session token to its session row, or
// ErrAuthFailed if the token is unknown or expired (GetSession folds
// expiry into ErrNotFound). The returned session's UserID identifies the
// authenticated operator for the request.
func (m *AuthManager) ValidateSession(ctx context.Context, token string) (*store.Session, error) {
	if token == "" {
		return nil, ErrAuthFailed
	}
	sess, err := m.store.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrAuthFailed
		}
		return nil, fmt.Errorf("signerserver: ValidateSession: %w", err)
	}
	return sess, nil
}

// RevokeSession deletes the session (logout). Idempotent: revoking an
// unknown/already-revoked token is not an error.
func (m *AuthManager) RevokeSession(ctx context.Context, token string) error {
	return m.store.RevokeSession(ctx, token)
}

// ---------------------------------------------------------------------
// Step-up (re-auth) primitive
// ---------------------------------------------------------------------

// StepUpMethod names the factor a step-up was satisfied with. It is
// recorded on the vote's authn_method for the audit trail.
type StepUpMethod string

const (
	StepUpTOTP     StepUpMethod = "totp"
	StepUpWebAuthn StepUpMethod = "webauthn"
)

// StepUp is the fresh-reauth primitive the approve/deny route CAN call to
// require a live factor (passkey tap / TOTP code) at action time, on top
// of an existing session. It verifies ONE factor for userID and returns
// the method on success.
//
// This is a PRIMITIVE, not a policy: it performs a step-up when asked. It
// does NOT decide whether a step-up is required, nor whether it is needed
// per-approval or per-session — that enforcement choice belongs to the
// route's configuration (Karthi's product call, flagged #2). A route that
// wants per-action step-up calls this on every approve; a route that
// treats the session itself as sufficient simply never calls it.
//
// For TOTP the route passes the code in totpCode. For WebAuthn the route
// must already have driven Begin/FinishLogin (a passkey assertion is a
// multi-round-trip ceremony); a successful FinishLogin IS the step-up, so
// callers that did one need not call StepUp again. StepUp exists so the
// single-round-trip TOTP step-up has a first-class verb and so the
// audit-method recording is uniform.
func (m *AuthManager) StepUp(ctx context.Context, userID string, method StepUpMethod, totpCode string) (StepUpMethod, error) {
	switch method {
	case StepUpTOTP:
		if err := m.VerifyTOTP(ctx, userID, totpCode); err != nil {
			return "", err
		}
		return StepUpTOTP, nil
	case StepUpWebAuthn:
		// A WebAuthn step-up is the Begin/FinishLogin ceremony; the route
		// drives those directly. We reject here so a caller cannot mistake
		// StepUp for performing the assertion itself.
		return "", errors.New("signerserver: StepUp: webauthn step-up is performed via Begin/FinishLogin, not StepUp")
	default:
		return "", fmt.Errorf("signerserver: StepUp: unknown method %q", method)
	}
}

// ---------------------------------------------------------------------
// internal: ID minting + in-memory challenge store
// ---------------------------------------------------------------------

// newID mints a 256-bit crypto-random, URL-safe token used for both
// session IDs and challenge handles.
func (m *AuthManager) newID() (string, error) {
	var b [32]byte
	if _, err := m.randRead(b[:]); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ceremonyKind distinguishes a registration challenge from a login
// challenge so a register response cannot be replayed against a login
// challenge slot (or vice versa).
type ceremonyKind int

const (
	ceremonyRegister ceremonyKind = iota
	ceremonyLogin
)

// challengeEntry is one in-flight ceremony's server-side state.
type challengeEntry struct {
	session  *webauthn.SessionData
	ceremony ceremonyKind
	userID   string
	expires  time.Time
}

// challengeStore is a tiny, mutex-guarded, in-memory map of in-flight
// WebAuthn challenges. It is deliberately ephemeral: a server restart
// drops in-flight ceremonies (the client just re-begins), and entries are
// single-use (take removes them) and time-bounded. v2.1 may move this to
// the DB for multi-instance deploys; the interface stays the same.
type challengeStore struct {
	mu sync.Mutex
	m  map[string]challengeEntry
}

func newChallengeStore() *challengeStore {
	return &challengeStore{m: make(map[string]challengeEntry)}
}

// put stores session under a freshly minted handle and returns the
// handle. now is the wall clock; expiresAt is when the entry lapses. It
// opportunistically sweeps already-expired entries so the map does not
// grow unbounded under abandoned ceremonies.
func (c *challengeStore) put(session *webauthn.SessionData, kind ceremonyKind, userID string, now, expiresAt time.Time, mintID func() (string, error)) (string, error) {
	id, err := mintID()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	c.m[id] = challengeEntry{session: session, ceremony: kind, userID: userID, expires: expiresAt}
	return id, nil
}

// take removes and returns the entry for id, reporting ok=false if it is
// missing or already expired. Single-use: a found entry is always
// removed, even if expired, so a stale handle cannot be retried.
func (c *challengeStore) take(id string, now time.Time) (challengeEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[id]
	if !ok {
		return challengeEntry{}, false
	}
	delete(c.m, id)
	if !now.Before(e.expires) {
		return challengeEntry{}, false
	}
	return e, true
}

// sweepLocked drops every entry that has already expired as of now.
// Caller holds the mutex. Best-effort GC; take() enforces expiry
// authoritatively regardless of whether a sweep has run.
func (c *challengeStore) sweepLocked(now time.Time) {
	for id, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, id)
		}
	}
}

// compile-time assertion that waUser satisfies the lib's User interface.
var _ webauthn.User = (*waUser)(nil)
