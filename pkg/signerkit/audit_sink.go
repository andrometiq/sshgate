package signerkit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditSink is the integrator-facing audit seam for the hosted (Tier-3) plane
// (C5). The local daemon's ordinary sign/grant/transfer rows stay on its
// concrete *AuditLog; only additive custody lifecycle events are also routed
// through this seam. AuditSink is what an embedding web
// app supplies so EVERY incoming sign request or custody lifecycle transition
// (Call) and EVERY vote/verdict (Verdict) is recorded. Both methods return error
// on purpose: a sink that
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
	// Call records either an incoming Submit / POST /v1/sign (the zero-value
	// Lifecycle field) or a custody lifecycle transition. See AuditCall for the
	// discriminated-union contract. Neither variant carries a signature.
	Call(ctx context.Context, e AuditCall) error
	// Verdict records a single operator's resolution of a request: who, over
	// which command (by SHA-256, never the raw bytes on this ledger), how they
	// authenticated (Operator.AuthnMethod), and whether they approved.
	Verdict(ctx context.Context, e AuditVerdict) error
}

// AuditCall is a backwards-compatible discriminated union. Lifecycle == "" is
// an incoming hosted sign request on the machine plane, before any human has
// voted; RequestID, HostKeyFP, and Command carry that request. A non-empty
// Lifecycle is a custody transition ("lock", "unlock", or "rotate"); Reason and
// Operator carry the authorization context and the request fields are empty.
// Existing AuditSink implementations that only understand hosted calls remain
// source-compatible and see zero values for the additive lifecycle fields.
type AuditCall struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id,omitempty"`
	HostKeyFP string    `json:"host_key_fp,omitempty"`
	Command   string    `json:"command,omitempty"`
	// CommandSHA256 is the hosted submission fingerprint. Production callers
	// use it instead of Command so command-embedded secrets never reach the
	// append-only system journal.
	CommandSHA256 string `json:"command_sha256,omitempty"`
	// CommandsSHA256 fingerprints the canonical JSON command array for one
	// submission attempt. Production emits one atomic attempt event rather than
	// partially auditing a multi-command request command-by-command.
	CommandsSHA256 string    `json:"commands_sha256,omitempty"`
	CommandCount   int       `json:"command_count,omitempty"`
	HostKeyFPs     []string  `json:"host_key_fps,omitempty"`
	Phase          string    `json:"phase,omitempty"`
	Lifecycle      string    `json:"lifecycle,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Operator       *Operator `json:"operator,omitempty"`
	// Policy carries the dedicated policy-authority event metadata. It is nil
	// for every ordinary/custody event, preserving their frozen encodings.
	Policy *PolicyAuditMetadata `json:"policy,omitempty"`
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
	// Policy is non-nil only for the dedicated base-manifest human-verdict
	// phase. Ordinary hosted verdict encodings remain byte-identical.
	Policy *PolicyAuditMetadata `json:"policy,omitempty"`
}

// PolicyAuditMetadata is the payload-free, additive policy-authority audit
// shape. Digests are lowercase hexadecimal; it never carries manifest bytes,
// command literals, signatures, or envelopes.
type PolicyAuditMetadata struct {
	EventID            string `json:"event_id"`
	Purpose            string `json:"purpose"`
	Principal          string `json:"principal"`
	TupleDigest        string `json:"tuple_digest"`
	Phase              string `json:"phase"`
	StateVersion       uint64 `json:"state_version"`
	RequestID          string `json:"request_id"`
	HostKeyFP          string `json:"host_key_fp"`
	PayloadSHA256      string `json:"payload_sha256"`
	CandidateDigest    string `json:"candidate_digest"`
	HeadDigest         string `json:"head_digest,omitempty"`
	Epoch              uint64 `json:"epoch"`
	Revision           uint64 `json:"revision"`
	MissAction         string `json:"miss_action"`
	Growth             string `json:"growth"`
	EntryCount         int    `json:"entry_count"`
	RevocationCount    int    `json:"revocation_count"`
	SignerKeyID        string `json:"signer_key_id"`
	ResultSHA256       string `json:"result_sha256,omitempty"`
	Outcome            string `json:"outcome,omitempty"`
	ErrorCode          string `json:"error_code,omitempty"`
	NoOp               bool   `json:"no_op,omitempty"`
	VerifiedOperator   string `json:"verified_operator,omitempty"`
	OperatorAuthMethod string `json:"operator_auth_method,omitempty"`
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
	kind := "call"
	if e.Lifecycle != "" {
		kind = "lifecycle"
	}
	return s.write(auditLine{Kind: kind, Event: e})
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
	n, err := s.w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

// Call adapts the local append-only *AuditLog to AuditSink (C5): the shapes
// differ (AuditLog speaks AuditEvent, the sink speaks Call/Verdict), so this is
// a thin adapter, not a coincidental match. It lets an integrator pass the
// local JSON-Lines log as Config.Audit and get one unified trail. A lifecycle
// variant preserves the legacy lock/unlock/rotate AuditEvent status while a
// normal call keeps the hosted-plane shape below.
func (a *AuditLog) Call(_ context.Context, e AuditCall) error {
	if e.Policy != nil {
		return a.Write(AuditEvent{
			TS:        e.Time.UTC(),
			RequestID: e.Policy.RequestID,
			Status:    "policy-" + e.Policy.Phase,
			Commands:  []string{},
			Servers:   []string{e.Policy.HostKeyFP},
			Policy:    e.Policy,
		})
	}
	if e.Lifecycle != "" {
		op := Operator{}
		if e.Operator != nil {
			op = *e.Operator
		}
		who := op.DisplayName
		if who == "" {
			who = op.ID
		}
		desc := "custody: " + e.Lifecycle
		if e.Reason != "" {
			desc += " (" + e.Reason + ")"
		}
		return a.Write(AuditEvent{
			TS:         e.Time.UTC(),
			Status:     e.Lifecycle,
			Commands:   []string{desc},
			ApprovedBy: who,
			AuthMode:   op.AuthnMethod,
		})
	}
	servers := e.HostKeyFPs
	if len(servers) == 0 && e.HostKeyFP != "" {
		servers = []string{e.HostKeyFP}
	}
	return a.Write(AuditEvent{
		TS:        e.Time.UTC(),
		RequestID: e.RequestID,
		Status:    "call",
		Commands:  []string{auditCallCommand(e)},
		Servers:   servers,
	})
}

func auditCallCommand(e AuditCall) string {
	if e.CommandsSHA256 != "" {
		return "sha256:" + e.CommandsSHA256
	}
	if e.CommandSHA256 != "" {
		return "sha256:" + e.CommandSHA256
	}
	return e.Command
}

// Verdict adapts *AuditLog to AuditSink.Verdict (C5). The approver's display
// name lands in ApprovedBy and the authn method in AuthMode, mirroring the
// local sign-row schema so a grep over one file surfaces both planes.
func (a *AuditLog) Verdict(_ context.Context, e AuditVerdict) error {
	if e.Policy != nil {
		status := "policy-denied"
		if e.Approved {
			status = "policy-approved"
		}
		return a.Write(AuditEvent{
			TS:         e.Time.UTC(),
			RequestID:  e.Policy.RequestID,
			Status:     status,
			Commands:   []string{},
			Servers:    []string{e.Policy.HostKeyFP},
			ApprovedBy: e.Operator.DisplayName,
			AuthMode:   e.Operator.AuthnMethod,
			Policy:     e.Policy,
		})
	}
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
