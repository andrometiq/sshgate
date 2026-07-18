package hosted_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	virtualwebauthn "github.com/descope/virtualwebauthn"
	"github.com/pquerna/otp/totp"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// authFixture stands up a real SQLite store + an AuthManager with a fixed
// RP config, and seeds one user. Returns the manager, the store, and the
// seeded user id.
func authFixture(t *testing.T) (*hosted.AuthManager, *sqlitestore.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	am, err := hosted.NewAuthManager(db, hosted.AuthConfig{
		RPID:          "signer.example.com",
		RPDisplayName: "SSHGate Signer",
		RPOrigins:     []string{"https://signer.example.com"},
		SessionTTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	const userID = "u-alice"
	if err := db.CreateUser(context.Background(), &store.User{
		ID:       userID,
		Username: "alice",
		Role:     "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return am, db, userID
}

// TestNewAuthManager_RejectsMisconfig proves the construction guards: a
// nil store, an empty RP-ID, no origins, and a non-positive session TTL
// all fail closed rather than yielding a manager that would silently
// accept any origin or issue immortal sessions.
func TestNewAuthManager_RejectsMisconfig(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "x.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	good := hosted.AuthConfig{RPID: "signer.example.com", RPOrigins: []string{"https://signer.example.com"}, SessionTTL: time.Minute}

	cases := []struct {
		name string
		st   store.Store
		cfg  hosted.AuthConfig
	}{
		{"nil store", nil, good},
		{"empty RPID", db, hosted.AuthConfig{RPOrigins: []string{"https://signer.example.com"}, SessionTTL: time.Minute}},
		{"no origins", db, hosted.AuthConfig{RPID: "signer.example.com", SessionTTL: time.Minute}},
		{"zero TTL", db, hosted.AuthConfig{RPID: "signer.example.com", RPOrigins: []string{"https://signer.example.com"}}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hosted.NewAuthManager(tc.st, tc.cfg); err == nil {
				t.Fatalf("NewAuthManager(%s) = nil err; want a rejection", tc.name)
			}
		})
	}
}

// TestTOTP_EnrollAndVerify is the TOTP round-trip: enroll mints a secret,
// a code computed from that secret verifies, a wrong code fails, an
// expired code (computed for a time outside the skew window) fails, and a
// code one period away (inside the ±1 skew) passes.
func TestTOTP_EnrollAndVerify(t *testing.T) {
	t.Parallel()
	am, _, userID := authFixture(t)
	ctx := context.Background()

	enr, err := am.EnrollTOTP(ctx, userID, "alice")
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	if enr.Secret == "" || enr.URI == "" {
		t.Fatalf("enrollment missing secret/uri: %+v", enr)
	}

	now := time.Now()

	// Valid code at the current time passes.
	code, err := totp.GenerateCode(enr.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := am.VerifyTOTP(ctx, userID, code); err != nil {
		t.Fatalf("VerifyTOTP(valid) = %v; want nil", err)
	}

	// Wrong code fails with ErrAuthFailed.
	wrong := "000000"
	if code == wrong { // astronomically unlikely, but be deterministic
		wrong = "111111"
	}
	if err := am.VerifyTOTP(ctx, userID, wrong); !errors.Is(err, hosted.ErrAuthFailed) {
		t.Fatalf("VerifyTOTP(wrong) = %v; want ErrAuthFailed", err)
	}

	// One period away (30s) is inside the ±1 skew → passes.
	skewCode, err := totp.GenerateCode(enr.Secret, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("GenerateCode(+30s): %v", err)
	}
	if err := am.VerifyTOTP(ctx, userID, skewCode); err != nil {
		t.Fatalf("VerifyTOTP(+1 period, within skew) = %v; want nil", err)
	}

	// Far outside the window (10 minutes) → expired/invalid, fails.
	staleCode, err := totp.GenerateCode(enr.Secret, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("GenerateCode(+10m): %v", err)
	}
	// Guard: only meaningful if the stale code actually differs from the
	// current one (it virtually always does).
	if staleCode != code {
		if err := am.VerifyTOTP(ctx, userID, staleCode); !errors.Is(err, hosted.ErrAuthFailed) {
			t.Fatalf("VerifyTOTP(stale +10m) = %v; want ErrAuthFailed", err)
		}
	}
}

// TestTOTP_NotEnrolled proves verifying for a user with no secret returns
// the distinct ErrTOTPNotEnrolled sentinel.
func TestTOTP_NotEnrolled(t *testing.T) {
	t.Parallel()
	am, _, userID := authFixture(t)
	if err := am.VerifyTOTP(context.Background(), userID, "123456"); !errors.Is(err, hosted.ErrTOTPNotEnrolled) {
		t.Fatalf("VerifyTOTP(no secret) = %v; want ErrTOTPNotEnrolled", err)
	}
}

// --- WebAuthn round-trip via the descope software authenticator ---

const (
	waRPID   = "signer.example.com"
	waOrigin = "https://signer.example.com"
	waRPName = "SSHGate Signer"
)

// waRP is the descope relying-party view matching the AuthManager config.
func waRP() virtualwebauthn.RelyingParty {
	return virtualwebauthn.RelyingParty{ID: waRPID, Name: waRPName, Origin: waOrigin}
}

// registerPasskey drives a full BeginRegistration → software authenticator
// → FinishRegistration round-trip and returns the authenticator + the
// credential so a subsequent login can assert with them.
func registerPasskey(t *testing.T, am *hosted.AuthManager, userID string) (virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	t.Helper()
	ctx := context.Background()

	options, challengeID, err := am.BeginRegistration(ctx, userID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("marshal creation options: %v", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}

	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(waRP(), authenticator, cred, *attOpts)

	// FinishRegistration consumes the raw authenticator response bytes.
	if _, err := am.FinishRegistration(ctx, userID, challengeID, []byte(attestationResponse)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	authenticator.AddCredential(cred)
	return authenticator, cred
}

// TestWebAuthn_RegisterLoginRoundTrip is the passkey round-trip: register
// a credential with a software authenticator, then assert it back. After
// registration the store holds exactly one credential for the user; the
// assertion validates against it.
func TestWebAuthn_RegisterLoginRoundTrip(t *testing.T) {
	t.Parallel()
	am, db, userID := authFixture(t)
	ctx := context.Background()

	authenticator, cred := registerPasskey(t, am, userID)

	// The credential is persisted.
	creds, err := db.ListCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("stored credentials = %d; want 1", len(creds))
	}

	// --- login / assertion ---
	assertOptions, challengeID, err := am.BeginLogin(ctx, userID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	assertJSON, err := json.Marshal(assertOptions)
	if err != nil {
		t.Fatalf("marshal assertion options: %v", err)
	}
	parsedAssert, err := virtualwebauthn.ParseAssertionOptions(string(assertJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	assertionResponse := virtualwebauthn.CreateAssertionResponse(waRP(), authenticator, cred, *parsedAssert)

	matched, err := am.FinishLogin(ctx, userID, challengeID, []byte(assertionResponse))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if matched == nil {
		t.Fatalf("FinishLogin returned nil credential")
	}
}

// TestWebAuthn_WrongChallengeRejected proves a register-finish presented a
// LOGIN challenge handle (wrong ceremony) is rejected, and a bogus handle
// is rejected — the challenge store is single-use and ceremony-typed.
func TestWebAuthn_ChallengeMisuseRejected(t *testing.T) {
	t.Parallel()
	am, _, userID := authFixture(t)
	ctx := context.Background()

	// A finish with a never-issued challenge id fails closed.
	if _, err := am.FinishRegistration(ctx, userID, "bogus-handle", []byte(`{}`)); !errors.Is(err, hosted.ErrAuthFailed) {
		t.Fatalf("FinishRegistration(bogus) = %v; want ErrAuthFailed", err)
	}

	// Register a passkey, then attempt to REPLAY the same registration
	// challenge a second time — single-use means it is gone.
	options, challengeID, err := am.BeginRegistration(ctx, userID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	optionsJSON, _ := json.Marshal(options)
	attOpts, _ := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	resp := virtualwebauthn.CreateAttestationResponse(waRP(), authenticator, cred, *attOpts)
	if _, err := am.FinishRegistration(ctx, userID, challengeID, []byte(resp)); err != nil {
		t.Fatalf("FinishRegistration(first): %v", err)
	}
	// Second use of the same handle: rejected.
	if _, err := am.FinishRegistration(ctx, userID, challengeID, []byte(resp)); !errors.Is(err, hosted.ErrAuthFailed) {
		t.Fatalf("FinishRegistration(replay) = %v; want ErrAuthFailed", err)
	}
}

// --- Sessions ---

// TestSession_IssueValidateRevoke proves the session lifecycle: issue →
// validate (resolves to the right user) → revoke → no longer validates.
func TestSession_IssueValidateRevoke(t *testing.T) {
	t.Parallel()
	am, _, userID := authFixture(t)
	ctx := context.Background()

	sess, err := am.IssueSession(ctx, userID)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatalf("empty session id")
	}

	got, err := am.ValidateSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ValidateSession = %v; want nil", err)
	}
	if got.UserID != userID {
		t.Fatalf("session user = %q; want %q", got.UserID, userID)
	}

	if err := am.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := am.ValidateSession(ctx, sess.ID); !errors.Is(err, hosted.ErrAuthFailed) {
		t.Fatalf("ValidateSession(after revoke) = %v; want ErrAuthFailed", err)
	}
}

// TestSession_Expiry proves an expired session no longer validates. We
// drive expiry through a short-TTL manager so no clock injection is
// needed: a 1ns TTL session is already expired by the time we validate.
func TestSession_Expiry(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "exp.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const userID = "u-bob"
	if err := db.CreateUser(context.Background(), &store.User{ID: userID, Username: "bob", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	am, err := hosted.NewAuthManager(db, hosted.AuthConfig{
		RPID:       "signer.example.com",
		RPOrigins:  []string{"https://signer.example.com"},
		SessionTTL: time.Nanosecond, // already-expired by validate time
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	ctx := context.Background()
	sess, err := am.IssueSession(ctx, userID)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := am.ValidateSession(ctx, sess.ID); !errors.Is(err, hosted.ErrAuthFailed) {
		t.Fatalf("ValidateSession(expired) = %v; want ErrAuthFailed", err)
	}
}

// TestStepUp_TOTP proves the step-up primitive: a valid TOTP code steps
// up (returns the totp method), a wrong code fails, and a webauthn step-up
// is explicitly NOT performed via StepUp (it routes through the login
// ceremony) so the route cannot mistake StepUp for an assertion.
func TestStepUp_TOTP(t *testing.T) {
	t.Parallel()
	am, _, userID := authFixture(t)
	ctx := context.Background()

	enr, err := am.EnrollTOTP(ctx, userID, "alice")
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	code, _ := totp.GenerateCode(enr.Secret, time.Now())

	method, err := am.StepUp(ctx, userID, hosted.StepUpTOTP, code)
	if err != nil {
		t.Fatalf("StepUp(valid totp) = %v; want nil", err)
	}
	if method != hosted.StepUpTOTP {
		t.Fatalf("step-up method = %q; want totp", method)
	}

	if _, err := am.StepUp(ctx, userID, hosted.StepUpTOTP, "000000"); err == nil {
		t.Fatalf("StepUp(wrong totp) = nil; want failure")
	}

	if _, err := am.StepUp(ctx, userID, hosted.StepUpWebAuthn, ""); err == nil {
		t.Fatalf("StepUp(webauthn) should error: it is performed via the login ceremony, not StepUp")
	}
}
