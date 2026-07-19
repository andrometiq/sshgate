package signerkit

import (
	"context"
	"crypto"
	"io"
	"time"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// Config is the single constructor input for New. It carries everything the
// shipped front-ends wire into a Daemon today (cmd/.../main.go builds a Daemon
// struct literal from exactly these pieces), so the local front-end can move
// onto New(Config) in phase 4 with no loss of wiring, and the hosted front-end
// (phase 5) shares the same constructor.
//
// The Signer seam (C7) keeps the raw key out of process memory: pass any
// crypto.Signer — a file key (ed25519.PrivateKey satisfies crypto.Signer), a
// KMS/HSM/ssh-agent-backed signer, etc. It MUST implement standard Ed25519 (the
// gate verifies with ed25519), and it wins over the legacy Daemon.Key field.
type Config struct {
	// Signer is the signing identity. REQUIRED non-nil — New returns ErrNoSigner
	// otherwise. (Config has no Key fallback field; the legacy raw-key path is
	// reachable only via a struct-literal Daemon.)
	Signer crypto.Signer
	// Backend is the approval channel (Telegram / hosted / stub / mock). May be
	// nil at construction; the socket RequestHandler then returns a typed error
	// at call time instead of panicking (see the validation matrix on New).
	Backend Backend
	// Audit is the required audit seam (REQUIRED non-nil — New returns
	// ErrNoAudit otherwise). Pass the local *AuditLog (which satisfies AuditSink)
	// to also drive the socket daemon's own rows; pass any other AuditSink for a
	// hosted-plane-only Service.
	Audit AuditSink
	// XferRegistry is the box→box transfer trust anchor. Optional: nil means
	// every transfer fails closed at lookup (today's behavior for a daemon with
	// no registry configured).
	XferRegistry *XferRegistry
	// RedactSalt + RedactRules are the single-sourced secret-redaction pair (D8).
	// The library carries them so the audit log and any front-end message text
	// cannot desynchronize; the invariant is single-sourced by construction only
	// in the shipped front-ends and documented for external integrators (C8).
	RedactSalt  [32]byte
	RedactRules []redact.Rule
	// NowFunc is the injected clock (nil ⇒ time.Now), matching Daemon.NowFunc.
	NowFunc func() time.Time
}

// Service is the constructed signing core returned by New. It wraps a Daemon
// and, per C6, implements RequestHandler by delegating HandleSignRequest to the
// inner core — so phase 4 wires signer.Server{Handler: svc} with no new socket
// types added to the frozen API. Its custody methods (Lock/Unlock/RotateTo)
// delegate to the Daemon so a *Service is the single frozen surface an
// integrator holds. The hosted HTTP planes live in pkg/signerkit/hosted
// (AttachMachine/AttachHuman on hosted.Server); whether the Submit/Pending/Vote
// + Attach* surface should instead be promoted onto this Service type is an
// open owner ratification (see carve-2026-07-18/DESIGN-carve.md S2).
type Service struct {
	daemon *Daemon
	audit  AuditSink
}

// New validates cfg and returns a *Service. Validation is New-ONLY and honest
// about it (C4): a struct-literal Daemon is still a supported compatibility path
// and keeps its documented panic-on-nil semantics — New does not change what
// raw Daemon construction does; it is the enforced alternative.
//
// Validation matrix (C6):
//
//	Config.Signer == nil        → ErrNoSigner   (always — a signer with no key is useless)
//	Config.Audit  == nil        → ErrNoAudit    (always — required-non-nil audit)
//	Config.Backend == nil       → OK at construction; *Service.HandleSignRequest
//	                              returns a typed error line at call time (never panics)
//	Config.XferRegistry == nil  → OK; transfer requests fail closed at lookup (as today)
//	Config.Audit not a *AuditLog → OK; hosted-plane-only Service — the socket
//	                              RequestHandler path returns a typed error line
//
// New never panics on a bad Config; every misuse is a typed error, either here
// or at first call.
func New(cfg Config) (*Service, error) {
	if cfg.Signer == nil {
		return nil, ErrNoSigner
	}
	if cfg.Audit == nil {
		return nil, ErrNoAudit
	}
	d := &Daemon{
		Signer:        cfg.Signer,
		Backend:       cfg.Backend,
		NowFunc:       cfg.NowFunc,
		RedactSalt:    cfg.RedactSalt,
		RedactRules:   cfg.RedactRules,
		XferRegistry:  cfg.XferRegistry,
		lifecycleSink: cfg.Audit,
	}
	// The concrete local-audit path (socket daemon: sign/grant/transfer rows)
	// writes AuditEvents through a *AuditLog, which stays concrete and is NOT
	// re-plumbed through AuditSink (C5). When the sink IS the local log (the
	// local front-end passes signerkit.OpenAuditLog's result), wire it straight
	// through so the socket path works; otherwise this is a hosted-plane-only
	// Service and the socket path reports a typed error.
	if log, ok := cfg.Audit.(*AuditLog); ok {
		d.Audit = log
	}
	return &Service{daemon: d, audit: cfg.Audit}, nil
}

// HandleSignRequest makes *Service a RequestHandler by delegating to the inner
// Daemon (C6). It first surfaces the two New-tolerated-but-call-time-invalid
// configs as typed error lines instead of the nil-deref panics a raw Daemon
// would produce: a non-*AuditLog sink (hosted-plane Service, no local log) and
// a nil Backend. When both are wired (the local front-end), it is a transparent
// pass-through — byte-for-byte the same behavior as calling the Daemon directly.
func (s *Service) HandleSignRequest(ctx context.Context, conn io.ReadWriter) error {
	if s.daemon.Audit == nil {
		return writeJSONLine(conn, signResponse{
			Status:       "error",
			Error:        "signer: RequestHandler needs Config.Audit to be a *signerkit.AuditLog (local front-end); this Service is hosted-plane only",
			ProtoVersion: sigwire.ProtoVersion,
		})
	}
	if s.daemon.Backend == nil {
		return s.daemon.respondError(conn, "", "signer: no approval backend configured (Config.Backend was nil)")
	}
	return s.daemon.HandleSignRequest(ctx, conn)
}

// Lock delegates to the inner Daemon (custody.go). See Daemon.Lock.
func (s *Service) Lock(reason string, op Operator) error { return s.daemon.Lock(reason, op) }

// Unlock delegates to the inner Daemon (custody.go). See Daemon.Unlock.
func (s *Service) Unlock(op Operator) error { return s.daemon.Unlock(op) }

// RotateTo delegates to the frozen one-argument Daemon.RotateTo surface.
func (s *Service) RotateTo(next crypto.Signer) error { return s.daemon.RotateTo(next) }

// RotateToWithAudit delegates to Daemon.RotateToWithAudit for callers that
// can supply the reason and authenticated operator metadata.
func (s *Service) RotateToWithAudit(next crypto.Signer, reason string, op Operator) error {
	return s.daemon.RotateToWithAudit(next, reason, op)
}

// Compile-time proof: a *Service is a drop-in socket Handler (C6) — the frozen
// API adds no socket-serving types.
var _ RequestHandler = (*Service)(nil)
