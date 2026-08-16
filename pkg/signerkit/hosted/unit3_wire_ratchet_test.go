package hosted_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
)

// These ratchets intentionally duplicate the ordinary wire at the HTTP
// boundary. Unit 3 is additive; any missing, renamed, reordered, or extra key
// in a relied-on ordinary response must fail here before policy routes ship.
func TestUnit3WireRatchetMachineResponses(t *testing.T) {
	const apiKey = "test-bearer-key"
	handler := hosted.NewServer(apiKey, nil, log.New(io.Discard, "", 0))

	sign, _ := unit3JSONRequest(t, handler, http.MethodPost, "/v1/sign", apiKey, nil,
		[]byte(`{"client_id":"client-1","commands":[{"server":"prod","cmd":"echo hi","ttl_seconds":60}]}`),
		http.StatusAccepted)
	var accepted struct {
		RequestID string `json:"request_id"`
		PollURL   string `json:"poll_url"`
	}
	if err := json.Unmarshal(sign, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.RequestID == "" {
		t.Fatal("/v1/sign omitted request_id")
	}
	unit3AssertExactJSON(t, sign,
		fmt.Sprintf(`{"request_id":%q,"poll_url":%q}`+"\n", accepted.RequestID, "/v1/poll/"+accepted.RequestID),
		"request_id", "poll_url")

	poll, _ := unit3JSONRequest(t, handler, http.MethodGet, "/v1/poll/r_unit3", apiKey, nil, nil, http.StatusOK)
	unit3AssertExactJSON(t, poll, `{"request_id":"r_unit3","status":"timeout"}`+"\n", "request_id", "status")

	audit, _ := unit3JSONRequest(t, handler, http.MethodGet, "/v1/audit", apiKey, nil, nil, http.StatusOK)
	unit3AssertExactJSON(t, audit, `{"entries":[]}`+"\n", "entries")
}

func TestUnit3WireRatchetOrdinaryHumanMutationResponses(t *testing.T) {
	handler, db, auth := unit3HumanHandler(t)
	_, secret := seedTOTPUser(t, db, auth, "unit3-alice")
	_, verifySecret := seedTOTPUser(t, db, auth, "unit3-bob")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	login, loginRecorder := unit3JSONRequest(t, handler, http.MethodPost, "/auth/login", "", nil,
		[]byte(fmt.Sprintf(`{"username":"unit3-alice","totp_code":%q}`, code)), http.StatusOK)
	var sessionCookie *http.Cookie
	for _, cookie := range loginRecorder.Result().Cookies() {
		if cookie.Name == hosted.SessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login response omitted session cookie")
	}
	var session struct {
		Authenticated bool            `json:"authenticated"`
		ExpiresAt     json.RawMessage `json:"expires_at"`
	}
	if err := json.Unmarshal(login, &session); err != nil {
		t.Fatal(err)
	}
	if !session.Authenticated || len(session.ExpiresAt) == 0 {
		t.Fatalf("login response lost session fields: %s", login)
	}
	unit3AssertExactJSON(t, login,
		fmt.Sprintf(`{"authenticated":true,"expires_at":%s}`+"\n", session.ExpiresAt),
		"authenticated", "expires_at")

	verifyCode, err := totp.GenerateCode(verifySecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verified, _ := unit3JSONRequest(t, handler, http.MethodPost, "/auth/totp/verify", "", nil,
		[]byte(fmt.Sprintf(`{"username":"unit3-bob","code":%q}`, verifyCode)), http.StatusOK)
	unit3AssertExactJSON(t, verified, `{"verified":true}`+"\n", "verified")

	seedPendingRequest(t, db, "r-unit3-approve", 1, "echo approve", 60)
	approved, _ := unit3JSONRequest(t, handler, http.MethodPost, "/ui/request/r-unit3-approve/approve", "", sessionCookie, []byte(`{}`), http.StatusOK)
	unit3AssertExactJSON(t, approved,
		`{"decision":"approved","flipped":true,"request_id":"r-unit3-approve"}`+"\n",
		"decision", "flipped", "request_id")

	seedPendingRequest(t, db, "r-unit3-deny", 1, "echo deny", 60)
	denied, _ := unit3JSONRequest(t, handler, http.MethodPost, "/ui/request/r-unit3-deny/deny", "", sessionCookie, []byte(`{}`), http.StatusOK)
	unit3AssertExactJSON(t, denied,
		`{"decision":"pending","flipped":false,"request_id":"r-unit3-deny"}`+"\n",
		"decision", "flipped", "request_id")

	logout, _ := unit3JSONRequest(t, handler, http.MethodPost, "/auth/logout", "", sessionCookie, nil, http.StatusOK)
	unit3AssertExactJSON(t, logout, `{"logged_out":true}`+"\n", "logged_out")
}

func unit3HumanHandler(t *testing.T) (*hosted.Server, *sqlitestore.DB, *hosted.AuthManager) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "unit3-wire.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := signerkit.New(signerkit.Config{Signer: privateKey, Audit: signerkit.NewAppendOnlySink(io.Discard)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	engine, err := hosted.NewApprovalEngine(db, service)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := hosted.NewAuthManager(db, hosted.AuthConfig{
		RPID: waRPID, RPDisplayName: waRPName, RPOrigins: []string{waOrigin}, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := hosted.NewServer("test-bearer-key", db, log.New(io.Discard, "", 0))
	server.Signer = service
	server.MachineClientID = "client-1"
	server.RequiredApprovals = 1
	server.AttachHuman(&hosted.HumanAPI{Auth: auth, Engine: engine, Store: db})
	return server, db, auth
}

func unit3JSONRequest(t *testing.T, handler http.Handler, method, target, bearer string, cookie *http.Cookie, body []byte, wantStatus int) ([]byte, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body)).WithContext(context.Background())
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", waOrigin)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	got := recorder.Body.Bytes()
	if recorder.Code != wantStatus {
		t.Fatalf("%s %s status=%d body=%s; want %d", method, target, recorder.Code, got, wantStatus)
	}
	return got, recorder
}

func unit3AssertExactJSON(t *testing.T, got []byte, want string, wantKeys ...string) {
	t.Helper()
	if string(got) != want {
		t.Fatalf("ordinary JSON bytes drifted:\n got  %q\n want %q", got, want)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(got, &object); err != nil {
		t.Fatalf("decode ratcheted JSON: %v", err)
	}
	gotKeys := make([]string, 0, len(object))
	for key := range object {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	sort.Strings(wantKeys)
	if fmt.Sprint(gotKeys) != fmt.Sprint(wantKeys) {
		t.Fatalf("ordinary JSON key set drifted: got %v want %v", gotKeys, wantKeys)
	}
}
