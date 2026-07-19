package hosted

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// Server is the hosted signer-server HTTP handler. It owns the route
// table, the bearer-token auth check, and the shared dependencies
// (logger, API key, store handle). A single Server instance serves an
// arbitrary number of concurrent requests; all fields are read-only
// after construction.
//
// Server itself implements http.Handler so callers can drop it into
// http.Server or httptest. cmd/signer-server wires the production
// server; handlers_test.go wires an httptest.Server in-process.
type Server struct {
	// APIKey is the single bearer token that gates /v1/* routes. The current
	// release uses one shared key file (managed by ops). Per-client machine keys
	// are future work; WebAuthn/TOTP protect the separate human surface today.
	APIKey string

	// MachineClientID is the immutable requester identity bound to APIKey.
	// Empty preserves the low-level NewServer compatibility surface; hosted.New
	// requires and sets it for production composition.
	MachineClientID string

	// RequiredApprovals is copied onto each accepted request. Zero preserves
	// low-level compatibility and is treated as one; hosted.New requires a
	// positive explicit value.
	RequiredApprovals int

	// RequireHostKeyFP rejects Host-less requests at intake so an approver can
	// never resolve a request whose envelope the gate will inevitably reject.
	// hosted.New enables it for production composition; false preserves the
	// frozen low-level fixture (including its manually attached human plane)
	// until that owner-gated wire revision is ratified.
	RequireHostKeyFP bool

	// Store is the persistence layer. Scaffold commit 2 wires this to
	// a sqlite-backed implementation in store/sqlite.go. When nil,
	// the /v1/sign and /v1/poll handlers fall back to in-memory
	// placeholder behaviour (kept for backward-compat with the
	// commit-1 test fixtures + smoke runs without a DB file).
	Store store.Store

	// Signer is the shared signerkit core that mints gate-valid SSHGATE_SIG
	// envelopes at approval time (via the approval engine's SignApproved) and
	// records verdicts on the required audit sink. Production wiring
	// (cmd/sshgate-signer-server) constructs it via signerkit.New over a file
	// key loaded with signerkit.LoadKey, and refuses to start if the key is
	// missing or insecure; the route/auth tests leave it nil because they
	// exercise transport, not signing. The one-codebase port (phase 5) deleted
	// the branch's own signer type — this is the same core the local Telegram
	// signer uses.
	Signer *signerkit.Service

	// PollWait bounds the long-poll wait inside /v1/poll/{id}. The
	// HTTP client may pass a shorter wait via ?wait= in a future release; today
	// this is the only knob. Defaults to 30s in NewServer.
	PollWait time.Duration

	// Logger receives one line per request (method, path, status,
	// duration). Defaults to log.Default() if nil.
	Logger *log.Logger

	// Human is the optional human-plane API (Phase E): the /auth/* and
	// /ui/* routes, gated by a server-side session (NOT the bearer key).
	// When nil the server exposes only the machine plane (/v1/*,
	// /healthz) — the v2.0 behaviour. Mount it via AttachHuman before the
	// server starts serving. The two planes share this mux but never share
	// credentials: see human_handlers.go's plane-separation contract.
	Human *HumanAPI

	mux *http.ServeMux

	// machineAttached guards AttachMachine against a double-attach — the
	// machine plane's counterpart to the s.Human != nil guard in
	// AttachHuman. Set true the first time AttachMachine registers the
	// /v1/* + /healthz routes.
	machineAttached    bool
	machineSubmitLimit *machineRateLimiter
	machinePollLimit   *machineRateLimiter
}

// NewServer builds a Server with routes registered. The Server's
// ServeHTTP method is safe for concurrent use.
//
// auth is the bearer token; passing the empty string is a programming
// error (the server would let every request through) and panics so the
// mistake surfaces during test setup, not in production traffic.
func NewServer(auth string, st store.Store, logger *log.Logger) *Server {
	if auth == "" {
		panic("hosted: NewServer: APIKey is required")
	}
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		APIKey:             auth,
		Store:              st,
		RequiredApprovals:  1,
		PollWait:           30 * time.Second,
		Logger:             logger,
		mux:                http.NewServeMux(),
		machineSubmitLimit: &machineRateLimiter{},
		machinePollLimit:   &machineRateLimiter{},
	}
	s.AttachMachine()
	return s
}

// AttachMachine registers the bearer-gated MACHINE plane on the server's
// mux:
//
//	GET  /healthz               (public — no auth; load balancers / monitoring)
//	POST /v1/sign               (withAuth bearer)
//	GET  /v1/poll/{request_id}  (withAuth bearer)
//	GET  /v1/audit              (withAuth bearer)
//
// The wire these routes speak is BYTE-FROZEN (wire_frozen_test.go); this is a
// byte-preserving extraction of the former routes(). Go 1.22+ ServeMux
// pattern syntax is used for the {request_id} wildcard on /v1/poll/. NewServer
// calls it, so a bare Server is already complete — it is exported only for
// symmetry with AttachHuman. It panics on a double-attach (a wiring mistake
// that should surface at startup, not silently), mirroring AttachHuman.
func (s *Server) AttachMachine() {
	if s.machineAttached {
		panic("hosted: AttachMachine: machine plane already attached")
	}
	s.machineAttached = true
	// Public route: liveness check. No auth — load balancers and
	// monitoring need to hit this without a token.
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Bearer-token-gated routes. We wrap each handler in withAuth so
	// the auth check sits next to the route registration and cannot
	// drift across handler files.
	s.mux.Handle("POST /v1/sign", s.withAuth(s.withMachineLimit(s.machineSubmitLimit, 120, http.HandlerFunc(s.handleSign))))
	s.mux.Handle("GET /v1/poll/{request_id}", s.withAuth(s.withMachineLimit(s.machinePollLimit, 600, http.HandlerFunc(s.handlePoll))))
	s.mux.Handle("GET /v1/audit", s.withAuth(http.HandlerFunc(s.handleAudit)))
}

type machineRateLimiter struct {
	mu          sync.Mutex
	windowStart time.Time
	count       int
}

func (l *machineRateLimiter) allow(max int) bool {
	now := time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windowStart.IsZero() || now.Sub(l.windowStart) >= time.Minute {
		l.windowStart = now
		l.count = 1
		return true
	}
	if l.count >= max {
		return false
	}
	l.count++
	return true
}

func (s *Server) withMachineLimit(limiter *machineRateLimiter, max int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(max) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "too many machine requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AttachHuman mounts the human-plane (Phase E) routes onto the server's
// mux and records the HumanAPI on the Server. It MUST be called before
// the server begins serving (mux route registration is not safe to race
// with ServeHTTP). It panics on a double-attach or a nil argument — both
// are wiring mistakes that should surface at startup, not silently.
//
// The human routes (/auth/*, /ui/*) are session-gated; they share this
// mux with the bearer-gated machine routes (/v1/*) but never share
// credentials. Mounting them does not touch the frozen /v1 handlers.
func (s *Server) AttachHuman(h *HumanAPI) {
	if h == nil {
		panic("hosted: AttachHuman: nil HumanAPI")
	}
	if s.Human != nil {
		panic("hosted: AttachHuman: human plane already attached")
	}
	if strings.TrimSpace(s.MachineClientID) == "" {
		panic("hosted: AttachHuman: MachineClientID must bind the bearer credential before mounting human approval")
	}
	if s.RequiredApprovals <= 0 {
		panic("hosted: AttachHuman: RequiredApprovals must be greater than zero")
	}
	s.Human = h
	h.registerHumanRoutes(s.mux)
}

// ServeHTTP makes Server an http.Handler. The wrapping logRequest produces one
// line per request; full metrics and tracing remain future work.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/ui/") {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	s.logRequest(w, r, s.mux.ServeHTTP)
}

// withAuth wraps next with a bearer-token check. On a missing or
// mismatching token it writes 401 with a JSON {"error":"unauthorized"}
// body. The token comparison uses crypto/subtle to defeat timing
// attacks; the difference is negligible at v2.0's QPS but it's the
// right reflex.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(hdr, prefix) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		got := hdr[len(prefix):]
		// Equal-length compare via subtle: if lengths differ, fail
		// without touching the token bytes.
		if len(got) != len(s.APIKey) || subtle.ConstantTimeCompare([]byte(got), []byte(s.APIKey)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
