package hosted

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// Construction sentinels for New. They are NEW to package hosted and distinct
// from signerkit's own errors on purpose: a caller wiring the hosted server
// matches on hosted.ErrNo* without taking a dependency on the signing core's
// error identities.
var (
	// ErrNoCore is returned by New when Config.Core is nil — the hosted server
	// cannot sign an approved request without the shared signerkit core.
	ErrNoCore = errors.New("hosted: New: Core is required")
	// ErrNoStore is returned by New when Config.Store is nil — every plane
	// reads and writes request/approval state through the store.
	ErrNoStore = errors.New("hosted: New: Store is required")
	// ErrNoAPIKey is returned by New when Config.APIKey is empty — the machine
	// plane is bearer-gated and an empty key would authenticate every request.
	ErrNoAPIKey = errors.New("hosted: New: APIKey is required")
)

// Config composes a complete hosted server in one call. It is the integrator /
// phase-7 surface; NewServer + AttachHuman remain the low-level composition
// path (and are exactly what New calls under the hood). A zero-value Auth
// mounts the MACHINE plane only — the shape today's binary ships.
type Config struct {
	// Core is the shared signing core (from signerkit.New). REQUIRED — nil
	// yields ErrNoCore. It satisfies HostedCore, so sign-at-approval routes
	// through Core.SignApproved and the custody choke point, unchanged.
	Core *signerkit.Service

	// Store is the persistence layer. REQUIRED — nil yields ErrNoStore. It
	// must satisfy the atomic pending→resolved CAS contract the store hammer
	// exercises.
	Store store.Store

	// APIKey is the machine-plane bearer token. REQUIRED non-empty — "" yields
	// ErrNoAPIKey.
	APIKey string

	// Auth configures the HUMAN plane. Its zero value (RPID == "") leaves the
	// human plane UNMOUNTED — machine-plane only. When RPID != "", New builds
	// the AuthManager + ApprovalEngine + HumanAPI and calls AttachHuman
	// internally, so both planes are served. AuthConfig holds a slice
	// (RPOrigins) and is therefore not ==-comparable; RPID is the required
	// non-empty field, so it is the zero-value discriminant (never a struct
	// comparison).
	Auth AuthConfig

	// Human carries the human-plane policy knobs (ApprovalPolicy,
	// RequireStepUp, SecureCookie). Threaded verbatim into the HumanAPI;
	// meaningful only when Auth is set, ignored otherwise.
	Human HumanAPIConfig

	// PollWait bounds /v1/poll's long-poll wait. Zero keeps NewServer's 30s
	// default (it is applied AFTER NewServer so the knob is not silently dead).
	PollWait time.Duration

	// Logger receives one line per request. Nil ⇒ log.Default() (defaulted by
	// NewServer).
	Logger *log.Logger
}

// New composes a hosted Server from Config. It validates the required
// dependencies (returning the typed ErrNo* sentinels), wires the machine plane
// via NewServer, and — only when Config.Auth is set (RPID != "") — builds the
// human plane and attaches it. It is additive: NewServer and AttachHuman remain
// the public low-level path, so existing wiring (including the frozen test
// fixtures) is unaffected.
func New(cfg Config) (*Server, error) {
	if cfg.Core == nil {
		return nil, ErrNoCore
	}
	if cfg.Store == nil {
		return nil, ErrNoStore
	}
	if cfg.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	// NewServer registers the machine plane, defaults the logger (nil ⇒
	// log.Default()) and PollWait (30s). It panics only on an empty APIKey,
	// which we have already rejected above with a typed error.
	s := NewServer(cfg.APIKey, cfg.Store, cfg.Logger)
	s.Signer = cfg.Core
	if cfg.PollWait != 0 {
		s.PollWait = cfg.PollWait
	}

	// Human plane is opt-in. A zero AuthConfig (RPID == "") leaves it
	// unmounted — the machine-only shape today's binary ships.
	if cfg.Auth.RPID != "" {
		am, err := NewAuthManager(cfg.Store, cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("hosted: New: auth: %w", err)
		}
		engine, err := NewApprovalEngine(cfg.Store, cfg.Core)
		if err != nil {
			return nil, fmt.Errorf("hosted: New: approval engine: %w", err)
		}
		s.AttachHuman(&HumanAPI{
			Auth:   am,
			Engine: engine,
			Store:  cfg.Store,
			Cfg:    cfg.Human,
		})
	}

	return s, nil
}
