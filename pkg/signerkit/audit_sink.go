package signerkit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditSink is the integrator-facing audit seam for the hosted (Tier-3) plane
// (C5). Unlike the local daemon's concrete *AuditLog — which stays concrete and
// is NOT re-plumbed through this interface — AuditSink is what an embedding web
// app supplies so EVERY incoming sign request (Call) and EVERY vote/verdict
// (Verdict) is recorded. Both methods return error on purpose: a sink that
// cannot even report a write failure makes the required-non-nil-audit property
// hollow. The hosted vote path (phase 5) emits Verdict BEFORE flipping request
// state and fails CLOSED on a sink error — a compromised host app cannot
// silently suppress its own trail. Implementations MUST be safe for concurrent
// calls.
//
// The library ships two implementations: NewAppendOnlySink (an external,
// append-only anchor over any io.Writer) and *AuditLog (the local JSON-Lines
// file adapts to this interface via its Call/Verdict methods below).
type AuditSink interface {
	// Call records an incoming Submit / POST /v1/sign — the request entered the
	// approval queue. It carries no signature (none exists yet at submit time).
	Call(ctx context.Context, e AuditCall) error
	// Verdict records a single operator's resolution of a request: who, over
	// which command (by SHA-256, never the raw bytes on this ledger), how they
	// authenticated (Operator.AuthnMethod), and whether they approved.
	Verdict(ctx context.Context, e AuditVerdict) error
}

// AuditCall is the event recorded for every incoming sign request on the hosted
// machine plane, before any human has voted.
type AuditCall struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	HostKeyFP string    `json:"host_key_fp"`
	Command   string    `json:"command"`
}

// AuditVerdict is the event recorded for every vote on the hosted human plane.
// Command is identified by SHA-256 so the ledger can be shared/anchored without
// leaking the raw command; Operator carries the actor's identity and
// AuthnMethod (webauthn/totp).
type AuditVerdict struct {
	Time          time.Time `json:"time"`
	RequestID     string    `json:"request_id"`
	Operator      Operator  `json:"operator"`
	CommandSHA256 string    `json:"command_sha256"`
	Approved      bool      `json:"approved"`
}

// NewAppendOnlySink returns an AuditSink that appends one JSON line per event to
// w. It is the external/append-only anchor the TCB statement recommends: point
// it at a file the host app cannot rewrite, an append-only object store, or a
// remote log shipper, so a compromised host app cannot silently erase its own
// audit trail (J1 §4-Q4(iv)). Writes are serialized by an internal mutex; w is
// used verbatim (durability/fsync, if wanted, is w's responsibility).
func NewAppendOnlySink(w io.Writer) AuditSink {
	return &appendOnlySink{w: w}
}

type appendOnlySink struct {
	mu sync.Mutex
	w  io.Writer
}

// auditLine is the on-the-wire envelope for an append-only record: a discriminant
// plus the event, so a single stream can carry both kinds and still be parsed.
type auditLine struct {
	Kind  string `json:"kind"`
	Event any    `json:"event"`
}

func (s *appendOnlySink) Call(_ context.Context, e AuditCall) error {
	return s.write(auditLine{Kind: "call", Event: e})
}

func (s *appendOnlySink) Verdict(_ context.Context, e AuditVerdict) error {
	return s.write(auditLine{Kind: "verdict", Event: e})
}

func (s *appendOnlySink) write(v auditLine) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(b)
	return err
}

// Call adapts the local append-only *AuditLog to AuditSink (C5): the shapes
// differ (AuditLog speaks AuditEvent, the sink speaks Call/Verdict), so this is
// a thin adapter, not a coincidental match. It lets an integrator pass the
// local JSON-Lines log as Config.Audit and get one unified trail. The daemon's
// own local rows still go through AuditLog.Write directly — this adapter is only
// exercised on the hosted plane.
func (a *AuditLog) Call(_ context.Context, e AuditCall) error {
	return a.Write(AuditEvent{
		TS:        e.Time.UTC(),
		RequestID: e.RequestID,
		Status:    "call",
		Commands:  []string{e.Command},
		Servers:   []string{e.HostKeyFP},
	})
}

// Verdict adapts *AuditLog to AuditSink.Verdict (C5). The approver's display
// name lands in ApprovedBy and the authn method in AuthMode, mirroring the
// local sign-row schema so a grep over one file surfaces both planes.
func (a *AuditLog) Verdict(_ context.Context, e AuditVerdict) error {
	status := "denied"
	if e.Approved {
		status = "approved"
	}
	return a.Write(AuditEvent{
		TS:         e.Time.UTC(),
		RequestID:  e.RequestID,
		Status:     status,
		Commands:   []string{e.CommandSHA256},
		ApprovedBy: e.Operator.DisplayName,
		AuthMode:   e.Operator.AuthnMethod,
	})
}

// Compile-time proof the two shipped sinks satisfy the interface.
var (
	_ AuditSink = (*appendOnlySink)(nil)
	_ AuditSink = (*AuditLog)(nil)
)
