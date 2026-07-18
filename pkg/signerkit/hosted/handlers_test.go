package hosted_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
)

// newTestServer builds an httptest.Server wrapping our handler. The
// caller closes it; the API key is fixed so test bodies can use the
// same constant in their Authorization headers.
func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	const apiKey = "test-bearer-key"
	// Silence the per-request log line during tests; keep the prefix
	// so we can still find it if a test prints unexpected output.
	logger := log.New(io.Discard, "test: ", 0)
	srv := hosted.NewServer(apiKey, nil, logger)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, apiKey
}

func TestRoutes_TableDriven(t *testing.T) {
	t.Parallel()
	ts, key := newTestServer(t)

	// Each row exercises one route. Body is non-empty only for POST
	// /v1/sign; the rest carry no payload. wantStatus is the
	// expected HTTP status; wantBodyContains is a substring assertion
	// on the response (kept loose so the scaffold can evolve without
	// the test churning).
	cases := []struct {
		name             string
		method           string
		path             string
		auth             string // full Authorization header value; "" => omitted
		body             string
		wantStatus       int
		wantBodyContains string
	}{
		{
			name:             "healthz no auth",
			method:           http.MethodGet,
			path:             "/healthz",
			auth:             "",
			wantStatus:       http.StatusOK,
			wantBodyContains: "ok",
		},
		{
			name:       "v1/sign no auth -> 401",
			method:     http.MethodPost,
			path:       "/v1/sign",
			auth:       "",
			body:       `{"client_id":"x","commands":[{"server":"s","cmd":"echo","ttl_seconds":60}]}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "v1/sign wrong token -> 401",
			method:     http.MethodPost,
			path:       "/v1/sign",
			auth:       "Bearer not-the-key",
			body:       `{"client_id":"x","commands":[{"server":"s","cmd":"echo","ttl_seconds":60}]}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:             "v1/sign ok -> 202 with request_id",
			method:           http.MethodPost,
			path:             "/v1/sign",
			auth:             "Bearer " + key,
			body:             `{"client_id":"karthi-laptop","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60}]}`,
			wantStatus:       http.StatusAccepted,
			wantBodyContains: `"request_id":"r_`,
		},
		{
			name:       "v1/sign empty commands -> 400",
			method:     http.MethodPost,
			path:       "/v1/sign",
			auth:       "Bearer " + key,
			body:       `{"client_id":"x","commands":[]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "v1/sign missing client_id -> 400",
			method:     http.MethodPost,
			path:       "/v1/sign",
			auth:       "Bearer " + key,
			body:       `{"commands":[{"server":"s","cmd":"echo","ttl_seconds":60}]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			// TTL above sigwire.MaxSigValidity (300s) must be refused at
			// the door, not accepted and left approvable-but-unmintable.
			name:             "v1/sign ttl over cap -> 400",
			method:           http.MethodPost,
			path:             "/v1/sign",
			auth:             "Bearer " + key,
			body:             `{"client_id":"x","commands":[{"server":"s","cmd":"echo","ttl_seconds":301}]}`,
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "exceeds max",
		},
		{
			name:             "v1/poll/{id} ok -> 200 with status",
			method:           http.MethodGet,
			path:             "/v1/poll/r_abc",
			auth:             "Bearer " + key,
			wantStatus:       http.StatusOK,
			wantBodyContains: `"status":"timeout"`,
		},
		{
			name:             "v1/audit ok -> 200 empty list",
			method:           http.MethodGet,
			path:             "/v1/audit",
			auth:             "Bearer " + key,
			wantStatus:       http.StatusOK,
			wantBodyContains: `"entries":[]`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var body io.Reader
			if tc.body != "" {
				body = bytes.NewBufferString(tc.body)
			}
			req, err := http.NewRequest(tc.method, ts.URL+tc.path, body)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d; want %d", resp.StatusCode, tc.wantStatus)
			}
			got, _ := io.ReadAll(resp.Body)
			if tc.wantBodyContains != "" && !strings.Contains(string(got), tc.wantBodyContains) {
				t.Errorf("body = %q; want substring %q", string(got), tc.wantBodyContains)
			}
		})
	}
}

func TestSign_GeneratesUniqueRequestIDs(t *testing.T) {
	t.Parallel()
	ts, key := newTestServer(t)

	// Two sequential /v1/sign requests should get distinct request_id
	// values. We don't bother running them in parallel here — the
	// random ID generator is global crypto/rand, the test asserts
	// uniqueness not concurrency.
	postSign := func() string {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sign",
			bytes.NewBufferString(`{"client_id":"c","commands":[{"server":"s","cmd":"x","ttl_seconds":60}]}`))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		var body struct {
			RequestID string `json:"request_id"`
			PollURL   string `json:"poll_url"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.RequestID == "" {
			t.Fatal("empty request_id")
		}
		if !strings.HasPrefix(body.PollURL, "/v1/poll/") {
			t.Errorf("poll_url = %q; want /v1/poll/ prefix", body.PollURL)
		}
		return body.RequestID
	}
	a := postSign()
	b := postSign()
	if a == b {
		t.Errorf("request_ids should differ across calls; both = %q", a)
	}
}

func TestNewServer_PanicsOnEmptyAPIKey(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewServer with empty API key should panic")
		}
	}()
	_ = hosted.NewServer("", nil, nil)
}
