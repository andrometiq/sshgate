package hosted_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	client := &http.Client{Jar: jar}

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
	resp, err := client.Post(ts.URL+"/ui/request/r-approve-1/approve", "application/json", nil)
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
	resp2, err := client.Post(ts.URL+"/ui/request/r-approve-1/approve", "application/json", nil)
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
	resp, err := client.Post(ts.URL+"/ui/request/r-deny-1/deny", "application/json", nil)
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
	resp, err := client.Post(ts.URL+"/ui/request/r-step-1/approve", "application/json", nil)
	if err != nil {
		t.Fatalf("approve(no step-up): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("approve without step-up = %d; want 401", resp.StatusCode)
	}

	// Approve WITH a fresh TOTP code → 200, signed, gate-valid.
	code, _ := totp.GenerateCode(secret, time.Now())
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
	beginResp := getJSONPost(t, client, ts.URL+"/auth/webauthn/register/begin", nil, http.StatusOK)
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
