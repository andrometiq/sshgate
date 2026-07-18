package hosted_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
)

// hosted_api_test.go exercises the New(Config) composition constructor
// (config.go). New is additive: NewServer + AttachHuman remain the low-level
// path (proven elsewhere by humanFixture + TestPlaneSeparation). These tests
// prove New (a) surfaces the typed sentinels on a missing dependency, (b)
// wires BOTH planes when Auth is set — with wrong-plane credentials ignored,
// and (c) mounts the machine plane ONLY when Auth is zero.

// newAPICore builds a real signerkit core + a real sqlite store — the exact
// dependencies a deploy injects into hosted.New.
func newAPICore(t *testing.T) (*signerkit.Service, *sqlitestore.DB) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	core, err := signerkit.New(signerkit.Config{
		Signer: priv,
		Audit:  signerkit.NewAppendOnlySink(io.Discard),
	})
	if err != nil {
		t.Fatalf("signerkit.New: %v", err)
	}
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return core, db
}

// getStatus issues a GET and returns the status code. A non-empty bearer is
// sent as the Authorization header.
func getStatus(t *testing.T, url, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestNew_ValidationMatrix proves each required dependency surfaces its typed
// sentinel, and that New returns a nil server on any validation failure.
func TestNew_ValidationMatrix(t *testing.T) {
	t.Parallel()
	core, db := newAPICore(t)

	cases := []struct {
		name string
		cfg  hosted.Config
		want error
	}{
		{"nil core", hosted.Config{Store: db, APIKey: "k"}, hosted.ErrNoCore},
		{"nil store", hosted.Config{Core: core, APIKey: "k"}, hosted.ErrNoStore},
		{"empty api key", hosted.Config{Core: core, Store: db}, hosted.ErrNoAPIKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := hosted.New(tc.cfg)
			if !errors.Is(err, tc.want) {
				t.Fatalf("New(%s) err = %v; want %v", tc.name, err, tc.want)
			}
			if srv != nil {
				t.Fatalf("New(%s) returned a non-nil server on validation error", tc.name)
			}
		})
	}
}

// TestNew_MachineOnly proves a zero-Auth Config mounts the MACHINE plane only:
// /healthz public, /v1/* bearer-gated, and NO human routes (a /ui/* path 404s
// because it was never mounted). This is the shape the shipped binary uses.
func TestNew_MachineOnly(t *testing.T) {
	t.Parallel()
	core, db := newAPICore(t)
	const apiKey = "machine-only-key"

	srv, err := hosted.New(hosted.Config{
		Core:   core,
		Store:  db,
		APIKey: apiKey,
		Logger: log.New(io.Discard, "", 0),
		// Auth zero ⇒ human plane NOT mounted.
	})
	if err != nil {
		t.Fatalf("New (machine-only): %v", err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	// Machine plane serves: /healthz is public 200.
	if code := getStatus(t, ts.URL+"/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz = %d; want 200", code)
	}
	// Machine plane is bearer-gated: 401 without a token (present, not absent).
	if code := getStatus(t, ts.URL+"/v1/audit", ""); code != http.StatusUnauthorized {
		t.Fatalf("/v1/audit (no token) = %d; want 401", code)
	}
	// Human plane is ABSENT: a /ui/* route 404s (never mounted), not 401.
	if code := getStatus(t, ts.URL+"/ui/pending", ""); code != http.StatusNotFound {
		t.Fatalf("/ui/pending (machine-only) = %d; want 404 (human plane not mounted)", code)
	}
}

// TestNew_WithAuth_BothPlanesAndSeparation proves that a non-zero Auth makes
// New build + attach the human plane, so BOTH planes respond — and that plane
// separation still holds: the bearer 401s the machine plane without a token,
// and is ignored on a human route (mirrors TestPlaneSeparation direction 1).
func TestNew_WithAuth_BothPlanesAndSeparation(t *testing.T) {
	t.Parallel()
	core, db := newAPICore(t)
	const apiKey = "both-planes-key"

	srv, err := hosted.New(hosted.Config{
		Core:   core,
		Store:  db,
		APIKey: apiKey,
		Logger: log.New(io.Discard, "", 0),
		Auth: hosted.AuthConfig{
			RPID:          waRPID,
			RPDisplayName: waRPName,
			RPOrigins:     []string{waOrigin},
			SessionTTL:    time.Hour,
		},
		Human: hosted.HumanAPIConfig{SecureCookie: false},
	})
	if err != nil {
		t.Fatalf("New (with Auth): %v", err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	// Machine plane mounted: /healthz public 200.
	if code := getStatus(t, ts.URL+"/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz = %d; want 200", code)
	}
	// Machine plane bearer-gated: 401 WITHOUT a token.
	if code := getStatus(t, ts.URL+"/v1/audit", ""); code != http.StatusUnauthorized {
		t.Fatalf("/v1/audit (no bearer) = %d; want 401", code)
	}
	// Machine plane accepts the bearer: /v1/audit WITH the token is served
	// (neither 401 nor 404).
	if code := getStatus(t, ts.URL+"/v1/audit", apiKey); code == http.StatusUnauthorized || code == http.StatusNotFound {
		t.Fatalf("/v1/audit (with bearer) = %d; want it served (not 401/404)", code)
	}
	// Human plane mounted (session-gated): /ui/pending WITHOUT a session is
	// 401 (present but unauthorized), NOT 404 (absent).
	if code := getStatus(t, ts.URL+"/ui/pending", ""); code != http.StatusUnauthorized {
		t.Fatalf("/ui/pending (no session) = %d; want 401 (human plane mounted)", code)
	}
	// Wrong-plane credential ignored: the machine bearer must NOT authenticate
	// a human route — withSession reads only the cookie, so it still 401s.
	if code := getStatus(t, ts.URL+"/ui/pending", apiKey); code != http.StatusUnauthorized {
		t.Fatalf("bearer accepted on /ui/pending = %d; want 401 (wrong-plane credential ignored)", code)
	}
}
