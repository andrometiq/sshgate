package hosted_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	virtualwebauthn "github.com/descope/virtualwebauthn"
	"github.com/pquerna/otp/totp"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// humanFixture stands up a full server with BOTH planes wired: the
// machine plane (bearer APIKey) and the human plane (session-gated
// /auth/* + /ui/*), backed by a real store + a real Signer + the approval
// engine. It returns the httptest server, the bearer key, the store, the
// auth manager (for seeding TOTP), and the signer's public key (for the
// gate-valid approve-path proof).
func humanFixture(t *testing.T) (*httptest.Server, string, *sqlitestore.DB, *hosted.AuthManager, ed25519.PublicKey) {
	t.Helper()
	const apiKey = "test-bearer-key"

	path := filepath.Join(t.TempDir(), "human.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	svc, err := signerkit.New(signerkit.Config{
		Signer: priv,
		Audit:  signerkit.NewAppendOnlySink(io.Discard),
	})
	if err != nil {
		t.Fatalf("signerkit.New: %v", err)
	}
	engine, err := hosted.NewApprovalEngine(db, svc)
	if err != nil {
		t.Fatalf("NewApprovalEngine: %v", err)
	}
	am, err := hosted.NewAuthManager(db, hosted.AuthConfig{
		RPID:          waRPID,
		RPDisplayName: waRPName,
		RPOrigins:     []string{waOrigin},
		SessionTTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	logger := log.New(io.Discard, "test: ", 0)
	srv := hosted.NewServer(apiKey, db, logger)
	srv.Signer = svc
	srv.MachineClientID = "karthi-laptop"
	srv.RequiredApprovals = 1
	srv.AttachHuman(&hosted.HumanAPI{
		Auth:   am,
		Engine: engine,
		Store:  db,
		Cfg: hosted.HumanAPIConfig{
			// SecureCookie false so the cookie survives plain-HTTP httptest.
			SecureCookie: false,
		},
	})

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, apiKey, db, am, pub
}

// seedTOTPUser creates a user and enrolls a TOTP secret, returning the
// user id and secret so a test can log in.
func seedTOTPUser(t *testing.T, db *sqlitestore.DB, am *hosted.AuthManager, username string) (string, string) {
	t.Helper()
	ctx := context.Background()
	userID := "u-" + username
	if err := db.CreateUser(ctx, &store.User{ID: userID, Username: username, Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	enr, err := am.EnrollTOTP(ctx, userID, username)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	return userID, enr.Secret
}

// loginClient returns an *http.Client with a cookie jar that has
// authenticated as username via TOTP login. Subsequent requests on this
// client carry the session cookie automatically.
func loginClient(t *testing.T, ts *httptest.Server, username, totpSecret string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: originTransport{base: http.DefaultTransport, origin: waOrigin}}

	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	body := mustMarshal(t, map[string]string{"username": username, "totp_code": code})
	resp, err := client.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status = %d (%s); want 200", resp.StatusCode, got)
	}
	return client
}

type originTransport struct {
	base   http.RoundTripper
	origin string
}

func (t originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if clone.Method == http.MethodPost {
		clone.Header.Set("Origin", t.origin)
	}
	return t.base.RoundTrip(clone)
}

// seedPendingRequest inserts a pending sign request directly via the
// store, mirroring what /v1/sign persists, and returns its id.
func seedPendingRequest(t *testing.T, db *sqlitestore.DB, id string, n int, cmd string, ttl int64) {
	t.Helper()
	blob := mustMarshal(t, []cmdJSON{{Server: "prod", Cmd: cmd, TTLSeconds: ttl, HostKeyFP: testHostFP}})
	if err := db.Insert(context.Background(), &store.Request{
		RequestID:         id,
		Status:            store.StatusPending,
		ClientID:          "karthi-laptop",
		Commands:          blob,
		RequiredApprovals: n,
	}); err != nil {
		t.Fatalf("seed request: %v", err)
	}
}

// TestHuman_LoginAndUIHappyPath proves a logged-in operator can hit the
// session-gated /ui routes: list pending, fetch a request, view audit.
func TestHuman_LoginAndUIHappyPath(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	seedPendingRequest(t, db, "r-ui-1", 1, "systemctl restart nginx", 120)

	client := loginClient(t, ts, "alice", secret)

	// GET /ui/pending
	pending := getJSON(t, client, ts.URL+"/ui/pending", http.StatusOK)
	if !bytes.Contains(pending, []byte("r-ui-1")) {
		t.Fatalf("/ui/pending missing seeded request: %s", pending)
	}

	// GET /ui/request/{id}
	one := getJSON(t, client, ts.URL+"/ui/request/r-ui-1", http.StatusOK)
	if !bytes.Contains(one, []byte("systemctl restart nginx")) {
		t.Fatalf("/ui/request missing command: %s", one)
	}

	// GET /ui/audit
	getJSON(t, client, ts.URL+"/ui/audit", http.StatusOK)
}

// TestHuman_UIRequiresSession proves every /ui route and the session-gated
// /auth routes return 401 with NO session cookie.
func TestHuman_UIRequiresSession(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixture(t)

	gated := []struct {
		method, path string
	}{
		{http.MethodGet, "/ui/pending"},
		{http.MethodGet, "/ui/request/anything"},
		{http.MethodPost, "/ui/request/anything/approve"},
		{http.MethodPost, "/ui/request/anything/deny"},
		{http.MethodGet, "/ui/audit"},
		{http.MethodPost, "/auth/totp/enroll"},
		{http.MethodPost, "/auth/webauthn/register/begin"},
		{http.MethodPost, "/auth/webauthn/register/finish"},
		{http.MethodPost, "/auth/logout"},
	}
	for _, g := range gated {
		req, _ := http.NewRequest(g.method, ts.URL+g.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", g.method, g.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without session = %d; want 401", g.method, g.path, resp.StatusCode)
		}
	}
}

func TestHumanResponsesAreNeverCacheable(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixture(t)
	for _, path := range []string{"/ui/pending", "/auth/login"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s Cache-Control=%q; want no-store", path, got)
		}
	}
}

// TestPlaneSeparation is the security-critical proof that the two auth
// planes never cross:
//
//  1. the BEARER key is REJECTED on /ui/* and /auth/* (session-gated)
//     routes — presenting Authorization: Bearer <key> does not satisfy a
//     session.
//  2. a UI SESSION cookie is REJECTED on /v1/sign and /v1/poll — the
//     machine plane reads only the bearer header, never the cookie.
func TestPlaneSeparation(t *testing.T) {
	t.Parallel()
	ts, apiKey, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	seedPendingRequest(t, db, "r-sep-1", 1, "id", 60)

	// Direction 1: the bearer key must NOT authenticate a human-plane
	// route. We send the valid machine bearer to /ui/pending.
	{
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/pending", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("bearer->/ui: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bearer key accepted on /ui/pending: status %d; want 401", resp.StatusCode)
		}
	}

	// Also assert the bearer is rejected on the approve route (the most
	// sensitive human action).
	{
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/request/r-sep-1/approve", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("bearer->/ui approve: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bearer key accepted on /ui approve: status %d; want 401", resp.StatusCode)
		}
	}

	// Direction 2: a UI session must NOT authenticate a machine-plane
	// route. We log in (obtaining a session cookie) and replay that cookie
	// against /v1/sign and /v1/poll — both must 401 (the bearer-gated
	// machine plane ignores the cookie entirely).
	client := loginClient(t, ts, "alice", secret)
	sessionCookie := findSessionCookie(t, client, ts)

	// /v1/sign with the session cookie (and NO bearer) → 401.
	{
		body := []byte(`{"client_id":"x","commands":[{"server":"s","cmd":"echo","ttl_seconds":60}]}`)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sign", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(sessionCookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("session->/v1/sign: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("session cookie accepted on /v1/sign: status %d; want 401", resp.StatusCode)
		}
	}

	// /v1/poll with the session cookie (and NO bearer) → 401.
	{
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/poll/r-sep-1", nil)
		req.AddCookie(sessionCookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("session->/v1/poll: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("session cookie accepted on /v1/poll: status %d; want 401", resp.StatusCode)
		}
	}
}

func TestHuman_MutationsRequireTrustedOriginAndJSON(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	seedPendingRequest(t, db, "r-csrf-1", 1, "uptime", 60)

	trusted := loginClient(t, ts, "alice", secret)
	attacker := &http.Client{Jar: trusted.Jar}
	paths := []string{
		"/ui/request/r-csrf-1/approve",
		"/ui/request/r-csrf-1/deny",
		"/auth/totp/enroll",
		"/auth/webauthn/register/begin",
		"/auth/webauthn/register/finish",
		"/auth/logout",
	}
	for _, path := range paths {
		for _, origin := range []string{"", "https://evil.example"} {
			req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			resp, err := attacker.Do(req)
			if err != nil {
				t.Fatalf("POST %s origin %q: %v", path, origin, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("POST %s origin %q = %d; want 403", path, origin, resp.StatusCode)
			}
		}
	}

	badType, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/logout", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	badType.Header.Set("Origin", waOrigin)
	badType.Header.Set("Content-Type", "text/plain")
	resp, err := attacker.Do(badType)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("trusted-origin text/plain logout = %d; want 415", resp.StatusCode)
	}

	// The rejected requests did not revoke the session or resolve the request.
	getJSON(t, trusted, ts.URL+"/ui/request/r-csrf-1", http.StatusOK)
	got, err := db.GetByID(context.Background(), "r-csrf-1")
	if err != nil || got.Status != store.StatusPending {
		t.Fatalf("CSRF attempts changed request: status=%v err=%v", got.Status, err)
	}
}

func TestHuman_LoginRateLimitIsBoundedAndReturnsRetryAfter(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixture(t)
	client := &http.Client{Transport: originTransport{base: http.DefaultTransport, origin: waOrigin}}
	for attempt := 1; attempt <= 13; attempt++ {
		body := strings.NewReader(`{"username":"unknown","totp_code":"000000"}`)
		resp, err := client.Post(ts.URL+"/auth/login", "application/json", body)
		if err != nil {
			t.Fatalf("login attempt %d: %v", attempt, err)
		}
		resp.Body.Close()
		if attempt <= 12 && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("login attempt %d = %d; want 401 before budget exhaustion", attempt, resp.StatusCode)
		}
		if attempt == 13 {
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("login attempt 13 = %d; want 429", resp.StatusCode)
			}
			if got := resp.Header.Get("Retry-After"); got != "60" {
				t.Fatalf("Retry-After = %q; want 60", got)
			}
		}
	}
}

func TestHuman_PublicAuthRequiresTrustedOriginAndJSON(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixture(t)
	body := `{"username":"unknown","totp_code":"000000"}`
	for _, origin := range []string{"", "https://evil.example"} {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/login", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("login origin %q = %d; want 403", origin, resp.StatusCode)
		}
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", waOrigin)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("trusted-origin text login = %d; want 415", resp.StatusCode)
	}
}

func TestHuman_TrustedProxyRateLimitUsesClosestForwardedIP(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixtureWithPolicy(t, hosted.HumanAPIConfig{TrustProxyHeaders: true})
	client := &http.Client{}
	login := func(xff, username string) int {
		body := fmt.Sprintf(`{"username":%q,"totp_code":"000000"}`, username)
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/login", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", waOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 12; i++ {
		if got := login("203.0.113.77", "unknown"); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d; want 401", i+1, got)
		}
	}
	if got := login("198.51.100.2, 203.0.113.77", "unknown"); got != http.StatusTooManyRequests {
		t.Fatalf("forged leading XFF bypassed closest-IP budget: %d", got)
	}
	if got := login("203.0.113.78", "different-user"); got != http.StatusUnauthorized {
		t.Fatalf("independent forwarded client inherited proxy-wide budget: %d", got)
	}
}

func TestHuman_UntrustedProxyHeaderIsIgnored(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixture(t)
	client := &http.Client{}
	for i := 0; i < 13; i++ {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/login", strings.NewReader(`{"username":"unknown","totp_code":"000000"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", waOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113."+fmt.Sprint(i+1))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusUnauthorized
		if i == 12 {
			want = http.StatusTooManyRequests
		}
		if resp.StatusCode != want {
			t.Fatalf("attempt %d = %d; want %d", i+1, resp.StatusCode, want)
		}
	}
}

func TestHuman_FactorEnrollmentRequiresCurrentTOTP(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	userID, secret := seedTOTPUser(t, db, am, "alice")
	client := loginClient(t, ts, "alice", secret)

	for _, body := range []string{`{}`, `{"current_totp":"000000"}`} {
		resp, err := client.Post(ts.URL+"/auth/totp/enroll", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("enroll body %s = %d; want 401", body, resp.StatusCode)
		}
	}
	got, err := db.GetTOTP(context.Background(), userID)
	if err != nil || got != secret {
		t.Fatalf("rejected enrollment changed factor: got=%q err=%v", got, err)
	}
}

// TestHuman_ApproveDrivesGateValidSignature is the end-to-end approve
// proof: a logged-in operator approves a pending request via
// POST /ui/request/{id}/approve, which drives the Phase-C engine to a
// real approved+signed outcome; the persisted signatures verify under
// gate.VerifySigned. This is the load-bearing proof that the human plane
// produces gate-acceptable signatures, not plausible JSON.
func TestHuman_ApproveDrivesGateValidSignature(t *testing.T) {
	t.Parallel()
	ts, _, db, am, pub := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	const cmd = "systemctl restart nginx"
	seedPendingRequest(t, db, "r-approve-1", 1, cmd, 120)

	client := loginClient(t, ts, "alice", secret)

	// Approve.
	resp, err := client.Post(ts.URL+"/ui/request/r-approve-1/approve", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("approve POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve status = %d (%s); want 200", resp.StatusCode, got)
	}
	var out struct {
		Decision string `json:"decision"`
		Flipped  bool   `json:"flipped"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if out.Decision != "approved" || !out.Flipped {
		t.Fatalf("approve outcome = %+v; want approved/flipped", out)
	}

	// The persisted signatures verify under gate.
	got, err := db.GetByID(context.Background(), "r-approve-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != store.StatusApproved {
		t.Fatalf("status = %q; want approved", got.Status)
	}
	assertGateValid(t, got.Signatures, pub, cmd)

	// A second approve on the now-resolved request is a no-op → 409.
	resp2, err := client.Post(ts.URL+"/ui/request/r-approve-1/approve", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("second approve POST: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second approve status = %d; want 409 (already resolved)", resp2.StatusCode)
	}
}

// TestHuman_DenyResolves proves the deny route drives the engine to a
// denied terminal state (with deny-veto configured on).
func TestHuman_DenyResolves(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixtureWithPolicy(t, hosted.HumanAPIConfig{
		ApprovalPolicy: hosted.ApprovalPolicy{DenyVeto: true},
	})
	_, secret := seedTOTPUser(t, db, am, "alice")
	seedPendingRequest(t, db, "r-deny-1", 2, "rm -rf /tmp/x", 60)

	client := loginClient(t, ts, "alice", secret)
	resp, err := client.Post(ts.URL+"/ui/request/r-deny-1/deny", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("deny POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d; want 200", resp.StatusCode)
	}
	got, _ := db.GetByID(context.Background(), "r-deny-1")
	if got.Status != store.StatusDenied {
		t.Fatalf("status = %q; want denied", got.Status)
	}
	if len(got.Signatures) != 0 {
		t.Fatalf("denied request has signatures")
	}
}

// TestHuman_StepUpEnforced proves the #2 product flag: with
// RequireStepUp=true, an approve WITHOUT a fresh TOTP code is rejected
// 401 (step-up required), and one WITH a valid code succeeds. This proves
// the per-action step-up CAN be enforced when configured, without baking
// the policy in.
func TestHuman_StepUpEnforced(t *testing.T) {
	t.Parallel()
	ts, _, db, am, pub := humanFixtureWithPolicy(t, hosted.HumanAPIConfig{
		RequireStepUp: true,
	})
	_, secret := seedTOTPUser(t, db, am, "alice")
	const cmd = "uptime"
	seedPendingRequest(t, db, "r-step-1", 1, cmd, 60)

	client := loginClient(t, ts, "alice", secret)

	// Approve with no step-up code → 401.
	resp, err := client.Post(ts.URL+"/ui/request/r-step-1/approve", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("approve(no step-up): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("approve without step-up = %d; want 401", resp.StatusCode)
	}

	// Approve WITH a fresh TOTP code → 200, signed, gate-valid.
	// Login consumed the current TOTP step. Use the next accepted skew step to
	// prove step-up without a real 30-second sleep; production operators wait
	// for their authenticator to rotate to a new code.
	code, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	body := mustMarshal(t, map[string]string{"step_up_totp": code})
	resp2, err := client.Post(ts.URL+"/ui/request/r-step-1/approve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("approve(step-up): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(resp2.Body)
		t.Fatalf("approve with step-up = %d (%s); want 200", resp2.StatusCode, got)
	}
	got, _ := db.GetByID(context.Background(), "r-step-1")
	if got.Status != store.StatusApproved {
		t.Fatalf("status = %q; want approved", got.Status)
	}
	assertGateValid(t, got.Signatures, pub, cmd)

	// The vote's recorded authn_method reflects the step-up factor.
	votes, _ := db.ListVotes(context.Background(), "r-step-1")
	if len(votes) != 1 || votes[0].AuthnMethod != "totp" {
		t.Fatalf("vote authn_method = %+v; want one totp vote", votes)
	}
}

func TestUIRequest_ViewerVotePersistsAcrossReload(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	seedPendingRequest(t, db, "r-viewer-vote", 2, "uptime", 60)
	client := loginClient(t, ts, "alice", secret)

	getJSONPost(t, client, ts.URL+"/ui/request/r-viewer-vote/approve", []byte(`{}`), http.StatusOK)
	body := getJSON(t, client, ts.URL+"/ui/request/r-viewer-vote", http.StatusOK)
	var detail struct {
		Status     string `json:"status"`
		ViewerVote string `json:"viewer_vote"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Status != "pending" || detail.ViewerVote != "approve" {
		t.Fatalf("detail = %+v; want pending with viewer approve vote", detail)
	}
}

// TestHuman_WebAuthnRegisterRoundTripOverHTTP drives the passkey
// registration ceremony through the actual HTTP routes (begin → software
// authenticator → finish) for a logged-in operator, proving the route
// envelope ({challenge_id, options} / {challenge_id, response}) wires the
// mechanism correctly end to end.
func TestHuman_WebAuthnRegisterRoundTripOverHTTP(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	userID, secret := seedTOTPUser(t, db, am, "alice")
	client := loginClient(t, ts, "alice", secret)

	// begin
	// The login code is one-use across purposes. Generate the next accepted
	// skew step so the test need not sleep for an authenticator rotation.
	stepCode, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("GenerateCode(step-up): %v", err)
	}
	beginResp := getJSONPost(t, client, ts.URL+"/auth/webauthn/register/begin",
		mustMarshal(t, map[string]string{"current_totp": stepCode}), http.StatusOK)
	var begin struct {
		ChallengeID string          `json:"challenge_id"`
		Options     json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(beginResp, &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	if begin.ChallengeID == "" || len(begin.Options) == 0 {
		t.Fatalf("begin missing challenge_id/options: %s", beginResp)
	}

	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(begin.Options))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	attResp := virtualwebauthn.CreateAttestationResponse(waRP(), authenticator, cred, *attOpts)

	// finish
	finishBody := mustMarshal(t, map[string]json.RawMessage{
		"challenge_id": mustMarshal(t, begin.ChallengeID),
		"response":     json.RawMessage(attResp),
	})
	finishResp := getJSONPost(t, client, ts.URL+"/auth/webauthn/register/finish", finishBody, http.StatusOK)
	if !bytes.Contains(finishResp, []byte(`"registered":true`)) {
		t.Fatalf("register finish = %s; want registered:true", finishResp)
	}

	// The credential landed in the store for this user.
	creds, _ := db.ListCredentials(context.Background(), userID)
	if len(creds) != 1 {
		t.Fatalf("stored credentials = %d; want 1", len(creds))
	}
}

// TestUIPending_RenderIntegrityFields proves the pending LIST rows carry
// the additive render-integrity payload: per-command server, host-key FP,
// ttl_seconds and SHA-256, plus the row's required_approvals. These are the
// fields the browser needs to let a human cross-check the exact request.
func TestUIPending_RenderIntegrityFields(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	const cmd = "systemctl restart nginx"
	seedPendingRequest(t, db, "r-int-1", 2, cmd, 120)

	client := loginClient(t, ts, "alice", secret)
	body := getJSON(t, client, ts.URL+"/ui/pending", http.StatusOK)

	var out struct {
		Pending []struct {
			RequestID         string `json:"request_id"`
			RequiredApprovals int    `json:"required_approvals"`
			CommandDetails    []struct {
				Server     string `json:"server"`
				Cmd        string `json:"cmd"`
				HostKeyFP  string `json:"host_key_fp"`
				TTLSeconds int64  `json:"ttl_seconds"`
				SHA256     string `json:"sha256"`
			} `json:"command_details"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode /ui/pending: %v (%s)", err, body)
	}
	if len(out.Pending) != 1 {
		t.Fatalf("pending rows = %d; want 1 (%s)", len(out.Pending), body)
	}
	row := out.Pending[0]
	if row.RequestID != "r-int-1" {
		t.Fatalf("request_id = %q; want r-int-1", row.RequestID)
	}
	if row.RequiredApprovals != 2 {
		t.Errorf("required_approvals = %d; want 2", row.RequiredApprovals)
	}
	if len(row.CommandDetails) != 1 {
		t.Fatalf("command_details len = %d; want 1", len(row.CommandDetails))
	}
	cd := row.CommandDetails[0]
	if cd.Server != "prod" {
		t.Errorf("command_details[0].server = %q; want prod", cd.Server)
	}
	if cd.HostKeyFP == "" {
		t.Errorf("command_details[0].host_key_fp is empty; want the seeded FP")
	}
	if cd.TTLSeconds != 120 {
		t.Errorf("command_details[0].ttl_seconds = %d; want 120", cd.TTLSeconds)
	}
	if cd.SHA256 == "" {
		t.Errorf("command_details[0].sha256 is empty")
	}
	if cd.Cmd != cmd {
		t.Errorf("command_details[0].cmd = %q; want %q", cd.Cmd, cmd)
	}
}

func TestUIPending_PaginatesWithoutHidingBacklog(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	for i := 0; i < 55; i++ {
		seedPendingRequest(t, db, fmt.Sprintf("r-page-%02d", i), 1, "uptime", 60)
	}
	client := loginClient(t, ts, "alice", secret)
	first := getJSON(t, client, ts.URL+"/ui/pending?offset=0", http.StatusOK)
	var page1 struct {
		Pending    []json.RawMessage `json:"pending"`
		HasMore    bool              `json:"has_more"`
		NextOffset int               `json:"next_offset"`
	}
	if err := json.Unmarshal(first, &page1); err != nil {
		t.Fatal(err)
	}
	if len(page1.Pending) != 50 || !page1.HasMore || page1.NextOffset != 50 {
		t.Fatalf("first page = rows:%d more:%v next:%d", len(page1.Pending), page1.HasMore, page1.NextOffset)
	}
	second := getJSON(t, client, ts.URL+"/ui/pending?offset=50", http.StatusOK)
	var page2 struct {
		Pending []json.RawMessage `json:"pending"`
		HasMore bool              `json:"has_more"`
	}
	if err := json.Unmarshal(second, &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Pending) != 5 || page2.HasMore {
		t.Fatalf("second page = rows:%d more:%v", len(page2.Pending), page2.HasMore)
	}
}

// TestUIRequest_SHA256Matches proves the per-command SHA-256 in the detail
// view is exactly hex(sha256(exact command bytes)) — the value a human
// cross-checks against what the agent showed them (the render-integrity
// rule). If these ever disagree, an approver would be signing bytes that
// differ from the rendered text.
func TestUIRequest_SHA256Matches(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	const cmd = "rm -rf /var/tmp/cache && echo done"
	seedPendingRequest(t, db, "r-sha-1", 1, cmd, 60)

	client := loginClient(t, ts, "alice", secret)
	body := getJSON(t, client, ts.URL+"/ui/request/r-sha-1", http.StatusOK)

	var out struct {
		CommandDetails []struct {
			Cmd    string `json:"cmd"`
			SHA256 string `json:"sha256"`
		} `json:"command_details"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode /ui/request: %v (%s)", err, body)
	}
	if len(out.CommandDetails) != 1 {
		t.Fatalf("command_details len = %d; want 1", len(out.CommandDetails))
	}
	sum := sha256.Sum256([]byte(cmd))
	want := hex.EncodeToString(sum[:])
	if got := out.CommandDetails[0].SHA256; got != want {
		t.Fatalf("command_details[0].sha256 = %q; want %q", got, want)
	}
}

// TestUIRequest_Tally proves the detail view's N-of-M tally: after two
// approve votes land on an N=2 request, tally.required == 2,
// tally.approvals == 2, denials == 0, and the voter list carries both
// operators with their recorded authn methods. Votes are appended directly
// to the ledger so the tally reflects the raw vote set regardless of the
// engine's flip decision.
func TestUIRequest_Tally(t *testing.T) {
	t.Parallel()
	ts, _, db, am, _ := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")
	seedPendingRequest(t, db, "r-tally-1", 2, "uptime", 60)

	ctx := context.Background()
	if _, _, err := db.PrepareVote(ctx, &store.Vote{
		RequestID: "r-tally-1", Operator: "op-a", Decision: store.DecisionApprove,
		AuthnMethod: "session", TS: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("PrepareVote op-a: %v", err)
	}
	if err := db.MarkVoteAudited(ctx, "r-tally-1", "op-a"); err != nil {
		t.Fatalf("MarkVoteAudited op-a: %v", err)
	}
	if _, _, err := db.PrepareVote(ctx, &store.Vote{
		RequestID: "r-tally-1", Operator: "op-b", Decision: store.DecisionApprove,
		AuthnMethod: "totp", TS: time.Now().UTC().Add(time.Second),
	}); err != nil {
		t.Fatalf("PrepareVote op-b: %v", err)
	}
	if err := db.MarkVoteAudited(ctx, "r-tally-1", "op-b"); err != nil {
		t.Fatalf("MarkVoteAudited op-b: %v", err)
	}

	client := loginClient(t, ts, "alice", secret)
	body := getJSON(t, client, ts.URL+"/ui/request/r-tally-1", http.StatusOK)

	var out struct {
		ViewerVote string `json:"viewer_vote"`
		Tally      struct {
			Required  int `json:"required"`
			Approvals int `json:"approvals"`
			Denials   int `json:"denials"`
			Voters    []struct {
				Operator    string `json:"operator"`
				Decision    string `json:"decision"`
				AuthnMethod string `json:"authn_method"`
			} `json:"voters"`
		} `json:"tally"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode /ui/request: %v (%s)", err, body)
	}
	if out.Tally.Required != 2 {
		t.Errorf("tally.required = %d; want 2", out.Tally.Required)
	}
	if out.ViewerVote != "" {
		t.Errorf("viewer_vote = %q; alice did not cast either seeded vote", out.ViewerVote)
	}
	if out.Tally.Approvals != 2 {
		t.Errorf("tally.approvals = %d; want 2", out.Tally.Approvals)
	}
	if out.Tally.Denials != 0 {
		t.Errorf("tally.denials = %d; want 0", out.Tally.Denials)
	}
	if len(out.Tally.Voters) != 2 {
		t.Fatalf("tally.voters len = %d; want 2 (%s)", len(out.Tally.Voters), body)
	}
	methods := map[string]bool{}
	for _, v := range out.Tally.Voters {
		if v.Decision != "approve" {
			t.Errorf("voter %s decision = %q; want approve", v.Operator, v.Decision)
		}
		methods[v.AuthnMethod] = true
	}
	if !methods["session"] || !methods["totp"] {
		t.Errorf("voter authn methods = %v; want session+totp", methods)
	}
}

// --- helpers ---

// humanFixtureWithPolicy is humanFixture but with an explicit
// HumanAPIConfig (the default fixture uses the inert zero policy).
func humanFixtureWithPolicy(t *testing.T, cfg hosted.HumanAPIConfig) (*httptest.Server, string, *sqlitestore.DB, *hosted.AuthManager, ed25519.PublicKey) {
	t.Helper()
	const apiKey = "test-bearer-key"
	path := filepath.Join(t.TempDir(), "human.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	svc, err := signerkit.New(signerkit.Config{Signer: priv, Audit: signerkit.NewAppendOnlySink(io.Discard)})
	if err != nil {
		t.Fatalf("signerkit.New: %v", err)
	}
	engine, _ := hosted.NewApprovalEngine(db, svc)
	am, err := hosted.NewAuthManager(db, hosted.AuthConfig{
		RPID: waRPID, RPDisplayName: waRPName, RPOrigins: []string{waOrigin}, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	srv := hosted.NewServer(apiKey, db, log.New(io.Discard, "", 0))
	srv.Signer = svc
	srv.MachineClientID = "karthi-laptop"
	srv.RequiredApprovals = 1
	srv.AttachHuman(&hosted.HumanAPI{Auth: am, Engine: engine, Store: db, Cfg: cfg})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, apiKey, db, am, pub
}

func findSessionCookie(t *testing.T, client *http.Client, ts *httptest.Server) *http.Cookie {
	t.Helper()
	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse ts URL: %v", err)
	}
	for _, c := range client.Jar.Cookies(parsed) {
		if c.Name == hosted.SessionCookieName {
			return c
		}
	}
	t.Fatalf("no session cookie in jar after login")
	return nil
}

func getJSON(t *testing.T, client *http.Client, url string, wantStatus int) []byte {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s status = %d (%s); want %d", url, resp.StatusCode, body, wantStatus)
	}
	return body
}

func getJSONPost(t *testing.T, client *http.Client, url string, body []byte, wantStatus int) []byte {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	resp, err := client.Post(url, "application/json", r)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s status = %d (%s); want %d", url, resp.StatusCode, out, wantStatus)
	}
	return out
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
