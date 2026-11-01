package hosted

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
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
	// ErrNoMachineClientID prevents a shared bearer holder from choosing a
	// different requester identity per call and bypassing self-approval policy.
	ErrNoMachineClientID = errors.New("hosted: New: MachineClientID is required")
	// ErrInvalidRequiredApprovals prevents an implicit or impossible quorum
	// policy from reaching production request intake.
	ErrInvalidRequiredApprovals = fmt.Errorf("hosted: New: RequiredApprovals must be between 1 and %d", approvalplan.MaxRequiredApprovals)
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

	// MachineClientID is the immutable requester identity bound to APIKey.
	// POST /v1/sign must carry this exact client_id. For the current single-key
	// deployment, set it to the same stable operator ID used at bootstrap when
	// self-approval must be prohibited. Per-client credentials are future work.
	MachineClientID string

	// RequiredApprovals is the immutable quorum threshold copied onto every
	// request at intake. The maximum is approvalplan.MaxRequiredApprovals;
	// human-plane composition also requires a positive value. Changing the deploy flag affects
	// new requests only because pending rows retain their stored N.
	RequiredApprovals int

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

	// Policy is the additive post-construction policy plane. Nil preserves the
	// ordinary hosted surface. Production normally uses StartPolicy so lease,
	// database, archive, audit, scan, and worker ordering cannot be rearranged.
	Policy *PolicyAPIConfig

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
	if cfg.RequiredApprovals > approvalplan.MaxRequiredApprovals {
		return nil, ErrInvalidRequiredApprovals
	}
	if cfg.Auth.RPID != "" {
		if cfg.MachineClientID == "" {
			return nil, ErrNoMachineClientID
		}
		if cfg.RequiredApprovals <= 0 {
			return nil, ErrInvalidRequiredApprovals
		}
	}

	// NewServer registers the machine plane, defaults the logger (nil ⇒
	// log.Default()) and PollWait (30s). It panics only on an empty APIKey,
	// which we have already rejected above with a typed error.
	s := NewServer(cfg.APIKey, cfg.Store, cfg.Logger)
	s.Signer = cfg.Core
	if cfg.MachineClientID != "" {
		s.MachineClientID = cfg.MachineClientID
	}
	if cfg.RequiredApprovals > 0 {
		s.RequiredApprovals = cfg.RequiredApprovals
	}
	if cfg.PollWait != 0 {
		s.PollWait = cfg.PollWait
	}

	// Human plane is opt-in. A zero AuthConfig (RPID == "") leaves it
	// unmounted — the machine-only shape today's binary ships.
	if cfg.Auth.RPID != "" {
		s.RequireHostKeyFP = true
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
	if cfg.Policy != nil {
		if err := s.AttachPolicy(cfg.Policy); err != nil {
			return nil, fmt.Errorf("hosted: New: policy: %w", err)
		}
	}

	return s, nil
}

// BuildApprovalSnapshot redacts a request with the full ruleset and a fresh,
// ephemeral salt. Only the returned snapshot is suitable for persistence.
func BuildApprovalSnapshot(plan approvalplan.ApprovalPlanV1) (approvalreview.ReviewSnapshot, error) {
	var salt [32]byte
	defer clear(salt[:])
	if _, err := rand.Read(salt[:]); err != nil {
		return approvalreview.ReviewSnapshot{}, fmt.Errorf("hosted: generate review salt: %w", err)
	}
	return approvalreview.BuildSnapshot(plan, &salt, redactrules.Combined())
}

// The provider receives its own redacted copy, never the stored display snapshot.
type hostedAssistInputBuilder struct{}

func (hostedAssistInputBuilder) BuildAssistInput(plan approvalplan.ApprovalPlanV1) (assist.Input, error) {
	var salt [32]byte
	defer clear(salt[:])
	if _, err := rand.Read(salt[:]); err != nil {
		return assist.Input{}, err
	}
	return assist.RedactForProvider(plan, salt, redactrules.Combined())
}

// OrdinaryConfig configures the hosted approval lifecycle independently of policy.
type OrdinaryConfig struct {
	Validity, Retention, MaxAge, ReportHorizon, LegacyTTL, AssistTimeout time.Duration
	MaxFullRows, MaxRows                                                 int64
	Assist                                                               *assist.OpenAI
}

func (c OrdinaryConfig) Validate() error {
	if c.Validity < approvalplan.ValidityMin || c.Validity > approvalplan.ValidityMax {
		return errors.New("approval-validity must be between 5m and 168h")
	}
	if c.Retention <= 0 || c.MaxAge < 0 || c.LegacyTTL <= 0 {
		return errors.New("approval-retention and legacy-v1-pending-ttl must be positive; approval-max-age must be non-negative")
	}
	if c.ReportHorizon < approvalplan.ReportHorizonMin || c.ReportHorizon > approvalplan.ReportHorizonMax {
		return errors.New("approval-report-horizon must be between 1h and 168h")
	}
	if c.MaxFullRows <= 0 || c.MaxFullRows > c.MaxRows {
		return errors.New("approval row ceilings must be positive; full rows must not exceed total rows")
	}
	if c.AssistTimeout <= 0 {
		return errors.New("assist-timeout must be positive")
	}
	if c.Assist != nil {
		return c.Assist.Check()
	}
	return nil
}

// StartApprovals attaches the machine plane and transfers worker ownership to s.
func (s *Server) StartApprovals(database *sqlitestore.DB, core *signerkit.Service, audit signerkit.AuditSink, c OrdinaryConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if s.MachineClientID == "" {
		return ErrNoMachineClientID
	}
	config := ApprovalV2Config{
		Store: database, LegacyStore: database, Clock: elapsed.Real(),
		Freezer: ordinaryFreezer{c.Validity}, SnapshotBuilder: ordinarySnapshot{},
		Minter: ApprovalV2Minter{Core: core}, AuditSink: audit, Logger: s.Logger,
		RequiredApprovals: s.RequiredApprovals, AssistTimeout: c.AssistTimeout,
		Settings:    approvalplan.Settings{Hosted: true, Retention: c.Retention, MaxAge: c.MaxAge, ReportHorizon: c.ReportHorizon},
		MaxFullRows: c.MaxFullRows, MaxRows: c.MaxRows,
	}
	if c.Assist != nil {
		config.Assessor = c.Assist
		config.AssistPool = assist.NewPool(4, assist.Timers{})
	}
	engine, err := NewApprovalV2Engine(config)
	if err == nil {
		err = s.AttachApprovals(engine)
	}
	if err == nil {
		err = s.StartOrdinaryWorkers(engine)
	}
	if err != nil {
		if engine != nil {
			engine.assistCancel()
		}
		if config.AssistPool != nil {
			config.AssistPool.Close()
		}
		return err
	}
	s.LegacyPendingTTL = c.LegacyTTL
	return nil
}

type ordinaryFreezer struct{ validity time.Duration }

func (f ordinaryFreezer) Freeze(ctx context.Context, draft approvalplan.ApprovalDraft, client, sub string, now time.Time) (approvalplan.ApprovalPlanV1, error) {
	if err := ctx.Err(); err != nil {
		return approvalplan.ApprovalPlanV1{}, err
	}
	if err := draft.Validate(); err != nil {
		return approvalplan.ApprovalPlanV1{}, err
	}
	validity := f.validity
	if seconds := draft.RequestedValiditySeconds; seconds != nil {
		validity = min(validity, time.Duration(*seconds)*time.Second)
	}
	return approvalplan.FreezeDraft(draft, approvalplan.FreezeInputs{RequesterPrincipal: client, RequesterSub: sub, Now: now, Validity: validity})
}

type ordinarySnapshot struct{}

func (ordinarySnapshot) BuildSnapshot(ctx context.Context, plan approvalplan.ApprovalPlanV1) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	snapshot, err := BuildApprovalSnapshot(plan)
	if err != nil {
		return nil, "", err
	}
	view, err := approvalreview.BuildView(snapshot, approvalreview.Assist{State: approvalplan.AssistPreparing})
	if err != nil {
		return nil, "", err
	}
	encoded, err := snapshot.Encode()
	return encoded, view.Reason, err
}
