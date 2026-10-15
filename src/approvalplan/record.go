package approvalplan

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Record versions.
const (
	R1Version = 1
	R2Version = 1
)

// Encoded-size bounds (SA-3, SA-9). Every bound is on the encoded bytes,
// which is what securestate stores and limits. Each is derived from a
// worst-case record that the tests build and measure:
//   - R1Max: the worst K19-legal R1 record grown to every set and slot bound
//     encodes to about 1.10 MiB (TestR1WorstCaseWithinBound); R1Max keeps at
//     least 20% margin over it, rounded up to 64 KiB. r5.8 named 512 KiB and
//     told A1a to raise it if the measured record needed more.
//   - ShedMax: the worst shed R1 record, with one late report event and one
//     noise event, encodes to about 129 KiB (TestShedMaxCoversWorstShedRecord);
//     plus 20%, rounded up to 64 KiB.
//   - R2NonBodyMax: the worst R2 record without its bodies encodes to about
//     218 KiB (TestR2WorstCaseWithinBound); plus 20%, rounded up to 64 KiB.
//   - R2BodyOverhead: field names, quotes and base64 padding for 64 bodies.
const (
	R1Max          = 1408 << 10
	ShedMax        = 192 << 10
	R2NonBodyMax   = 320 << 10
	R2BodyOverhead = 4 << 10
	R2Max          = 4*((MaxJobOutputBytes+2)/3) + R2BodyOverhead + R2NonBodyMax
)

// Record set and field bounds (SA-3).
const (
	MaxBursts                 = 8
	MaxBurstParts             = 40 // Telegram multipart bound (E45)
	MaxCardEntries            = 16
	MaxStatusEdits            = 12
	MaxRationaleRedactedBytes = 2048
	// ReviewSnapshotMax bounds the encoded ReviewSnapshot that the renderer
	// builds at freeze (E37). A snapshot it cannot fit is request_unrenderable.
	ReviewSnapshotMax    = 256 << 10
	MaxAuthnBytes        = 32
	MaxReasonTokenBytes  = 64
	MaxAssistReasonBytes = 128
	MaxStatusStateBytes  = 32
	MaxAnnotationBytes   = 256
	// minDecidedByBytes covers the non-vote forms of decided_by:
	// "grant:<request id>", "clock" and an admin operator ID.
	minDecidedByBytes = 160
)

// outboxFixedEvents is the non-vote, non-noise events one record can append
// over its life (SA-3): one each for submission and the assist, decision,
// mint, final-report and revoked_at slots; two per burst (append, outcome);
// five per card entry (append and its four write-once fields); one per status
// edit; one per renotify raise; one for the Erase.
const outboxFixedEvents = 1 + 5 + 2*MaxBursts + 5*MaxCardEntries + MaxStatusEdits + MaxBursts + 1

// OutboxMax is the most unflushed non-noise events rec's outbox can hold, a
// pure function of its frozen quorum (SA-3). At most NoiseFold noise events
// come on top before the fold.
func OutboxMax(rec R1) int {
	return VoteCap(rec) + outboxFixedEvents
}

// R1 is an approval record: an immutable header with its write-once slots,
// bounded sets and counters, and a payload that Shed drops (SA-3). The outbox
// lives in the header because a shed record still appends a late report's
// event and folded noise (SA-9).
type R1 struct {
	Header  R1Header   `json:"header"`
	Payload *R1Payload `json:"payload,omitempty"`
}

// R1Header is kept for the record's whole life. Principal is
// "local-uid:<uid>" locally and the bearer client ID on hosted, where
// SubPrincipal is the optional requester_sub (E19).
type R1Header struct {
	Version           int             `json:"version"`
	Principal         string          `json:"principal"`
	SubPrincipal      string          `json:"sub_principal,omitempty"`
	RequestID         string          `json:"request_id"`
	Kind              Kind            `json:"kind"`
	DraftHash         string          `json:"draft_hash"`
	PlanHash          string          `json:"plan_hash"`
	RationaleOrigin   RationaleOrigin `json:"rationale_origin"`
	RationaleRedacted string          `json:"rationale_redacted"`
	ClaimTokenHash    string          `json:"claim_token_hash,omitempty"`
	Coordinator       Coordinator     `json:"coordinator,omitempty"`
	RequiredApprovals int             `json:"required_approvals"`
	CreatedAt         time.Time       `json:"created_at"`
	RequestExpiresAt  time.Time       `json:"request_expires_at"`
	AssistDeadline    time.Time       `json:"assist_deadline"`
	SubmitNotAfter    time.Time       `json:"submit_not_after"`
	StepCount         int             `json:"step_count"`
	StepTTLs          []int           `json:"step_ttls,omitempty"`
	GrantAlias        string          `json:"grant_alias,omitempty"`
	DurationSeconds   int             `json:"duration_seconds,omitempty"`
	GrantHostFP       string          `json:"trusted_host_fingerprint,omitempty"`

	Assist      *AssistSlot  `json:"assist,omitempty"`
	Decision    *Decision    `json:"decision,omitempty"`
	Mint        *MintSlot    `json:"mint,omitempty"`
	FinalReport *FinalReport `json:"final_report,omitempty"`
	RevokedAt   *time.Time   `json:"revoked_at,omitempty"`
	Votes       []Vote       `json:"votes,omitempty"`

	ClaimCount     int64  `json:"claim_count"`
	RenotifyGen    int    `json:"renotify_gen"`
	OutboxSeq      uint64 `json:"outbox_seq"`
	AuditedThrough uint64 `json:"audited_through"`
	NoiseDropped   uint64 `json:"noise_dropped"`

	Outbox []OutboxEvent `json:"outbox,omitempty"`
	Shed   bool          `json:"shed"`
}

// R1Payload is the sheddable part. Plan and ReviewSnapshot are immutable from
// freeze; ReviewSnapshot is the renderer's canonical JSON object (E37).
type R1Payload struct {
	Plan           ApprovalPlanV1  `json:"plan"`
	ReviewSnapshot json.RawMessage `json:"review_snapshot"`
	AssistResult   *AssistResult   `json:"assist_result,omitempty"`
	Signatures     []string        `json:"signatures,omitempty"`
	CardEntries    []CardEntry     `json:"card_entries,omitempty"`
	Bursts         []Burst         `json:"bursts,omitempty"`
	StatusEdits    []StatusEdit    `json:"status_edits,omitempty"`
}

// Vote decisions, the hosted store's spelling.
const (
	VoteApprove = "approve"
	VoteDeny    = "deny"
)

// Vote is one operator's vote. Authn names how the operator authenticated.
type Vote struct {
	Operator string    `json:"operator"`
	Decision string    `json:"decision"`
	TS       time.Time `json:"ts"`
	Authn    string    `json:"authn"`
}

// AssistBound is the assist a view showed when a decision committed (K8).
type AssistBound struct {
	State    AssistState `json:"state"`
	Revision int         `json:"revision"`
	Digest   string      `json:"digest,omitempty"`
}

// AssistSlot is the write-once assist slot: ready with the result's digest,
// or unavailable with a reason and UnavailableAssistDigest.
type AssistSlot struct {
	State       AssistState `json:"state"`
	Reason      string      `json:"reason,omitempty"`
	GeneratedAt time.Time   `json:"generated_at"`
	Digest      string      `json:"digest"`
}

// Decision is the write-once decision slot. DecidedBy is the approving
// operators comma-joined, "grant:<id>", "clock", or the deciding admin.
type Decision struct {
	Status         ApprovalStatus `json:"status"`
	DecidedAt      time.Time      `json:"decided_at"`
	DecidedBy      string         `json:"decided_by"`
	TerminalReason string         `json:"terminal_reason,omitempty"`
	Epoch          string         `json:"epoch"`
	AssistBound    AssistBound    `json:"assist_bound"`
}

// Mint slot states and its closed error reasons.
const (
	MintSignatures = "signatures"
	MintError      = "error"

	MintReasonWindowClosed     = "window_closed"
	MintReasonGrantNotLive     = "grant_not_live"
	MintReasonClockSkew        = "clock_skew"
	MintReasonStaleTransferKey = "stale_transfer_key"
	MintReasonReservedVerb     = "reserved_verb"
	MintReasonSigningFailed    = "signing_failed"
)

// MintSlot is the write-once mint summary: the minted set's digest, or the
// error that stops any set from being minted. The bytes are in the payload
// until the Erase.
type MintSlot struct {
	State  string `json:"state"`
	Digest string `json:"digest,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// FinalReport is the write-once final-report slot (E25, E38).
type FinalReport struct {
	Class            JobClass     `json:"class"`
	Steps            []StepReport `json:"steps"`
	ExecutedOrdinals []int        `json:"executed_ordinals,omitempty"`
	Partial          bool         `json:"partial,omitempty"`
	ResultDigest     string       `json:"result_digest"`
	BodyDigest       string       `json:"body_digest"`
}

// StepReport is one step of a report. A step without a stored result carries
// only its derived status; the other fields are omitted, never zero (E38).
type StepReport struct {
	Ordinal     int        `json:"ordinal"`
	Status      StepStatus `json:"status"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	StdoutBytes *int64     `json:"stdout_bytes,omitempty"`
	StderrBytes *int64     `json:"stderr_bytes,omitempty"`
	Truncated   *bool      `json:"truncated,omitempty"`
}

// Card entry kinds, actions and send outcomes (SA-3).
const (
	CardFirst       = "first"
	CardEdit        = "edit"
	CardReplacement = "replacement"
	ActionApprove   = "approve"
	ActionDeny      = "deny"
	OutcomeSent     = "sent"
	OutcomeError    = "error"
)

// CardEntry is one Telegram card send or edit. MsgID, Outcome, Confirmed and
// Retired are write-once fields.
type CardEntry struct {
	Handle    string   `json:"handle"`
	Rev       int      `json:"rev"`
	ChalHash  string   `json:"chal_hash"`
	Actions   []string `json:"actions"`
	Kind      string   `json:"kind"`
	Epoch     string   `json:"epoch"`
	MsgID     *int64   `json:"msg_id,omitempty"`
	Outcome   string   `json:"outcome,omitempty"`
	Confirmed bool     `json:"confirmed,omitempty"`
	Retired   bool     `json:"retired,omitempty"`
}

// Burst is one multipart send of a record's review parts.
type Burst struct {
	Epoch      string    `json:"epoch"`
	Gen        int       `json:"gen"`
	StartedAt  time.Time `json:"started_at"`
	PartMsgIDs []int64   `json:"part_msg_ids,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
}

// StatusEdit records the one best-effort edit made for a display state (E49).
type StatusEdit struct {
	State string `json:"state"`
}

// R2 is an executor job record (SA-3). Bodies are []byte (base64 in the
// encoding) because output is arbitrary bytes. Signatures are never stored.
type R2 struct {
	Version          int            `json:"version"`
	RequestID        string         `json:"request_id"`
	InputHash        string         `json:"input_hash"`
	Draft            ApprovalDraft  `json:"draft"`
	DraftHash        string         `json:"draft_hash"`
	CreatedAt        time.Time      `json:"created_at"`
	Reservation      int64          `json:"reservation"`
	ClaimToken       string         `json:"claim_token,omitempty"`
	SignerAck        string         `json:"signer_ack,omitempty"`
	Outcome          *JobOutcome    `json:"outcome,omitempty"`
	ReportResult     *ReportResult  `json:"report_result,omitempty"`
	FirstDeliveredAt *time.Time     `json:"first_delivered_at,omitempty"`
	BodiesRemoved    *BodiesRemoved `json:"bodies_removed,omitempty"`
	FinalAt          *time.Time     `json:"final_at,omitempty"`
	Steps            []JobStep      `json:"steps"`
}

// JobStep is step k's marker and result slots.
type JobStep struct {
	Ordinal int         `json:"ordinal"`
	Marker  *Marker     `json:"marker,omitempty"`
	Result  *StepResult `json:"result,omitempty"`
}

// Marker records that step k was dispatched in an epoch.
type Marker struct {
	Epoch string    `json:"epoch"`
	At    time.Time `json:"at"`
}

// StepResult commits together with its bodies (SA-3 R2). The digests stay
// after the bodies are removed. Annotation is one of the runner's fixed texts.
type StepResult struct {
	Status           StepStatus `json:"status"`
	ExitCode         *int       `json:"exit_code,omitempty"`
	StdoutBytes      int64      `json:"stdout_bytes"`
	StderrBytes      int64      `json:"stderr_bytes"`
	Truncated        bool       `json:"truncated,omitempty"`
	StdoutSHA256     string     `json:"stdout_sha256"`
	StderrSHA256     string     `json:"stderr_sha256"`
	Stdout           []byte     `json:"stdout,omitempty"`
	Stderr           []byte     `json:"stderr,omitempty"`
	BodiesUnstorable bool       `json:"bodies_unstorable,omitempty"`
	Annotation       string     `json:"annotation,omitempty"`
}

// Job outcome kinds, for a job that ends without a step result ending it.
const (
	OutcomeDenied       = "denied"
	OutcomeCanceled     = "canceled"
	OutcomeExpired      = "expired"
	OutcomeJobError     = "error"
	OutcomeApprovalLost = "approval_lost"
	OutcomeAdopted      = "adopted"
)

// JobOutcome is R2's write-once outcome slot. Code is the definitive signer
// answer that ended an error job; Class is an adopted job's reported class.
type JobOutcome struct {
	Kind  string   `json:"kind"`
	Code  Code     `json:"code,omitempty"`
	Class JobClass `json:"class,omitempty"`
}

// ReportResult is R2's write-once report settlement.
type ReportResult struct {
	State string `json:"state"`
	Code  Code   `json:"code,omitempty"`
}

// Report settlement states.
const (
	ReportAcked   = "acked"
	ReportRefused = "refused"
)

// BodiesRemoved records why a job's bodies were removed.
type BodiesRemoved struct {
	Cause string `json:"cause"`
}

// EncodeR1 validates rec and returns its canonical encoding, refusing a
// record over R1Max.
func EncodeR1(rec R1) ([]byte, error) {
	if err := rec.validate(); err != nil {
		return nil, err
	}
	b, err := Canonical(rec)
	if err != nil {
		return nil, err
	}
	if err := checkR1Size(rec, len(b)); err != nil {
		return nil, codeErr(CodeRequestTooLarge, "r1", "%s", err.Msg)
	}
	return b, nil
}

// checkR1Size enforces the encoded bounds at the codec: R1Max always, ShedMax
// for a shed record, and for a full record its own R1Reservation, so a record
// can never hold more bytes than the payload budget charged for it.
func checkR1Size(rec R1, n int) *CodeError {
	limit, name := R1Max, "R1Max"
	switch {
	case rec.Header.Shed:
		limit, name = ShedMax, "ShedMax"
	case n <= R1Max:
		limit, name = R1Reservation(rec), "its R1Reservation"
	}
	if n > limit {
		return codeErr(CodeRecordCorrupt, "r1", "is %d bytes encoded; %s is %d", n, name, limit)
	}
	return nil
}

// DecodeR1 decodes and validates one stored R1 record. Any failure means the
// file is quarantined (SA-8).
func DecodeR1(b []byte) (R1, error) {
	if len(b) > R1Max {
		return R1{}, codeErr(CodeRecordCorrupt, "r1", "is %d bytes; maximum is %d", len(b), R1Max)
	}
	var rec R1
	if err := decodeCanonical(b, &rec); err != nil {
		return R1{}, codeErr(CodeRecordCorrupt, "r1", "%v", err)
	}
	if err := rec.validate(); err != nil {
		return R1{}, corrupt("r1", err)
	}
	if err := checkR1Size(rec, len(b)); err != nil {
		return R1{}, err
	}
	return rec, nil
}

// EncodeR2 validates job and returns its canonical encoding, refusing a
// record over R2Max.
func EncodeR2(job R2) ([]byte, error) {
	if err := job.validate(); err != nil {
		return nil, err
	}
	b, err := Canonical(job)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > job.Reservation {
		return nil, codeErr(CodeRequestTooLarge, "r2", "is %d bytes encoded; its reservation is %d", len(b), job.Reservation)
	}
	return b, nil
}

// DecodeR2 decodes and validates one stored R2 record.
func DecodeR2(b []byte) (R2, error) {
	if len(b) > R2Max {
		return R2{}, codeErr(CodeRecordCorrupt, "r2", "is %d bytes; maximum is %d", len(b), R2Max)
	}
	var job R2
	if err := decodeCanonical(b, &job); err != nil {
		return R2{}, codeErr(CodeRecordCorrupt, "r2", "%v", err)
	}
	if err := job.validate(); err != nil {
		return R2{}, corrupt("r2", err)
	}
	if int64(len(b)) > job.Reservation {
		return R2{}, codeErr(CodeRecordCorrupt, "r2", "is %d bytes; its reservation is %d", len(b), job.Reservation)
	}
	return job, nil
}

func corrupt(prefix string, err error) error {
	if ce, ok := within(prefix, err).(*CodeError); ok {
		return &CodeError{Code: CodeRecordCorrupt, Field: ce.Field, Msg: ce.Msg}
	}
	return codeErr(CodeRecordCorrupt, prefix, "%v", err)
}

// Shed reduces rec to its header (SA-9). It is pure: the caller decides when
// a record may be shed.
func Shed(rec R1) R1 {
	rec.Payload = nil
	rec.Header.Shed = true
	return rec
}

// maxDecidedBy bounds decided_by for a quorum of n: n operator IDs joined by
// commas, or one of the non-vote forms.
func maxDecidedBy(n int) int {
	return max(n*(MaxOperatorIDBytes+1)-1, minDecidedByBytes)
}

func validDecidedBy(s string, maxBytes int) bool {
	return len(s) >= 1 && len(s) <= maxBytes && allBytes(s, func(c byte) bool {
		return isAlnum(c) || c == '.' || c == '_' || c == '@' || c == '-' || c == ':' || c == ','
	})
}

// stepTTLs is the per-step TTL list a plan freezes into its header: one per
// command_job step (0 for an unsigned read), one for a transfer, none
// otherwise.
func stepTTLs(p ApprovalPlanV1) []int {
	switch {
	case p.CommandJob != nil:
		ttls := make([]int, len(p.CommandJob.Steps))
		for i, s := range p.CommandJob.Steps {
			ttls[i] = s.SignatureTTLSeconds
		}
		return ttls
	case p.Transfer != nil:
		return []int{p.Transfer.SignatureTTLSeconds}
	}
	return nil
}

// signedLeg is one command a minted set signs, with its host binding.
type signedLeg struct{ command, host string }

func signedLegs(p ApprovalPlanV1) []signedLeg {
	var legs []signedLeg
	switch {
	case p.CommandJob != nil:
		for _, s := range p.CommandJob.Steps {
			if s.Route.Signed() {
				legs = append(legs, signedLeg{s.ExactCommand, s.Target.TrustedHostFingerprint})
			}
		}
	case p.Transfer != nil:
		legs = append(legs,
			signedLeg{p.Transfer.SendCommand, p.Transfer.Source.Target.TrustedHostFingerprint},
			signedLeg{p.Transfer.RecvCommand, p.Transfer.Destination.Target.TrustedHostFingerprint})
	}
	return legs
}

// maxSignatureLen bounds one minted signature envelope,
// "SSHGATE_SIG:" + base64url(64-byte sig) + ":" + base64url(payload JSON),
// without parsing sigwire: JSON escapes a byte to at most 6, and 256 bytes
// cover the payload's keys, ts, exp, nonce and reveal (src/sigwire/payload.go).
func maxSignatureLen(command, host string) int {
	payload := 6*len(command) + 6*len(host) + 256
	return len("SSHGATE_SIG:") + 86 + 1 + 4*((payload+2)/3)
}

func validRecordStamp(field string, t time.Time) error {
	if !validStamp(t, false) {
		return invalid(field, "must be an RFC 3339 UTC time")
	}
	return nil
}

func (rec R1) validate() error {
	h := rec.Header
	if err := h.validateFrozen(); err != nil {
		return err
	}
	if err := h.validateSlots(); err != nil {
		return err
	}
	if err := h.validateOutbox(VoteCap(rec)); err != nil {
		return err
	}
	if h.Shed != (rec.Payload == nil) {
		return invalid("shed", "a record has a payload exactly when it is not shed")
	}
	if h.Shed && len(h.Outbox) > 1+ShedNoiseFold {
		return invalid("outbox", "a shed record holds at most a late report event and %d noise event", ShedNoiseFold)
	}
	if rec.Payload != nil {
		return within("payload", rec.Payload.validate(h))
	}
	return nil
}

func (h R1Header) validateFrozen() error {
	if h.Version != R1Version {
		return invalid("version", "must be %d", R1Version)
	}
	if !isRouteToken(h.Principal, MaxPrincipalBytes) {
		return invalid("principal", "must be 1..%d plain ASCII bytes", MaxPrincipalBytes)
	}
	if h.SubPrincipal != "" && !ValidRequesterSub(h.SubPrincipal) {
		return invalid("sub_principal", "must match local-uid:<uid>")
	}
	if h.Kind == KindRegisterTransferKey {
		return invalid("kind", "register_transfer_key is never a v2 record")
	}
	if err := validateEnvelope(h.Kind, h.RequestID, h.ClaimTokenHash, h.Coordinator, h.SubmitNotAfter); err != nil {
		return err
	}
	if !ValidSHA256Hex(h.DraftHash) || !ValidSHA256Hex(h.PlanHash) {
		return invalid("draft_hash", "draft_hash and plan_hash must be 64 lowercase hex")
	}
	if h.RationaleOrigin != OriginAgent {
		return invalid("rationale_origin", "a v2 record's reason comes from the agent")
	}
	if err := validText("rationale_redacted", h.RationaleRedacted, 1, MaxRationaleRedactedBytes); err != nil {
		return err
	}
	if h.RequiredApprovals < 1 || h.RequiredApprovals > MaxRequiredApprovals {
		return invalid("required_approvals", "%d is outside 1..%d", h.RequiredApprovals, MaxRequiredApprovals)
	}
	for field, t := range map[string]time.Time{"created_at": h.CreatedAt, "request_expires_at": h.RequestExpiresAt, "assist_deadline": h.AssistDeadline} {
		if err := validRecordStamp(field, t); err != nil {
			return err
		}
	}
	return h.validateShape()
}

// validateShape checks the kind-specific frozen fields.
func (h R1Header) validateShape() error {
	if h.Kind == KindStandingGrant {
		if h.StepCount != 0 || len(h.StepTTLs) != 0 {
			return invalid("step_count", "a grant has no steps")
		}
		if !isRouteToken(h.GrantAlias, MaxAliasBytes) || !ValidFingerprint(h.GrantHostFP) {
			return invalid("grant_alias", "a grant needs its alias and host fingerprint")
		}
		if h.DurationSeconds < 1 || h.DurationSeconds > MaxGrantDurationSeconds {
			return invalid("duration_seconds", "%d is outside 1..%d", h.DurationSeconds, MaxGrantDurationSeconds)
		}
		return nil
	}
	if h.GrantAlias != "" || h.DurationSeconds != 0 || h.GrantHostFP != "" || h.RevokedAt != nil {
		return invalid("grant_alias", "grant fields are only for standing_grant")
	}
	if h.StepCount < 1 || h.StepCount > MaxSteps || len(h.StepTTLs) != h.StepCount {
		return invalid("step_count", "must be 1..%d with one TTL per step", MaxSteps)
	}
	for _, ttl := range h.StepTTLs {
		if ttl < 0 || ttl > MaxTransferTTLSeconds {
			return invalid("step_ttls", "%d is outside 0..%d", ttl, MaxTransferTTLSeconds)
		}
	}
	return nil
}

func (h R1Header) validateSlots() error {
	if h.Assist != nil {
		if err := within("assist", h.Assist.validate()); err != nil {
			return err
		}
	}
	if h.Decision != nil {
		if err := within("decision", h.Decision.validate(maxDecidedBy(h.RequiredApprovals))); err != nil {
			return err
		}
	}
	if h.Mint != nil {
		if err := within("mint", h.Mint.validate()); err != nil {
			return err
		}
	}
	if h.FinalReport != nil {
		if err := within("final_report", h.FinalReport.validate(h.StepCount)); err != nil {
			return err
		}
	}
	if h.RevokedAt != nil {
		if err := validRecordStamp("revoked_at", *h.RevokedAt); err != nil {
			return err
		}
	}
	if len(h.Votes) > h.RequiredApprovals+VoteSlack {
		return invalid("votes", "%d votes; maximum is %d", len(h.Votes), h.RequiredApprovals+VoteSlack)
	}
	seen := make(map[string]bool, len(h.Votes))
	for i, v := range h.Votes {
		if err := v.validate(); err != nil {
			return within(fmt.Sprintf("votes[%d]", i), err)
		}
		if seen[v.Operator] {
			return invalid(fmt.Sprintf("votes[%d]", i), "a second vote by one operator")
		}
		seen[v.Operator] = true
	}
	if h.ClaimCount < 0 {
		return invalid("claim_count", "is negative")
	}
	if h.RenotifyGen < 0 || h.RenotifyGen > MaxBursts+1 {
		return invalid("renotify_gen", "%d is outside 0..%d", h.RenotifyGen, MaxBursts+1)
	}
	return nil
}

func (h R1Header) validateOutbox(voteCap int) error {
	if h.AuditedThrough > h.OutboxSeq {
		return invalid("audited_through", "is past outbox_seq")
	}
	if len(h.Outbox) > voteCap+outboxFixedEvents+NoiseFold {
		return invalid("outbox", "%d events; maximum is %d", len(h.Outbox), voteCap+outboxFixedEvents+NoiseFold)
	}
	last, decisions := h.AuditedThrough, 0
	for i, e := range h.Outbox {
		if err := e.validate(maxDecidedBy(h.RequiredApprovals)); err != nil {
			return within(fmt.Sprintf("outbox[%d]", i), err)
		}
		if e.DecidedBy != "" {
			if decisions++; decisions > 1 {
				return invalid(fmt.Sprintf("outbox[%d].decided_by", i), "a record decides once")
			}
		}
		if e.Seq <= last || e.Seq > h.OutboxSeq {
			return invalid(fmt.Sprintf("outbox[%d].seq", i), "must ascend, above audited_through and at most outbox_seq")
		}
		last = e.Seq
	}
	return nil
}

func (v Vote) validate() error {
	if !ValidOperatorID(v.Operator) {
		return invalid("operator", "is not an operator ID")
	}
	if v.Decision != VoteApprove && v.Decision != VoteDeny {
		return invalid("decision", "must be approve or deny")
	}
	if !isEventToken(v.Authn, MaxAuthnBytes) {
		return invalid("authn", "must be 1..%d of [a-z0-9_]", MaxAuthnBytes)
	}
	return validRecordStamp("ts", v.TS)
}

func (a AssistBound) validate() error {
	if !a.State.Valid() {
		return invalid("state", "unknown assist state %q", a.State)
	}
	if a.Revision < 0 || a.Revision > 1 {
		return invalid("revision", "must be 0 or 1")
	}
	if a.Digest != "" && !ValidSHA256Hex(a.Digest) {
		return invalid("digest", "must be 64 lowercase hex")
	}
	return nil
}

func (s AssistSlot) validate() error {
	switch s.State {
	case AssistReady:
		if s.Reason != "" {
			return invalid("reason", "a ready slot has no reason")
		}
	case AssistUnavailable:
		if !isRouteTokenOrSpaced(s.Reason, MaxAssistReasonBytes) {
			return invalid("reason", "must be 1..%d printable ASCII bytes", MaxAssistReasonBytes)
		}
	default:
		return invalid("state", "must be ready or unavailable")
	}
	if !ValidSHA256Hex(s.Digest) {
		return invalid("digest", "must be 64 lowercase hex")
	}
	return validRecordStamp("generated_at", s.GeneratedAt)
}

func (d Decision) validate(maxBy int) error {
	if !d.Status.Valid() || d.Status == ApprovalPending {
		return invalid("status", "must be a terminal status")
	}
	if err := validRecordStamp("decided_at", d.DecidedAt); err != nil {
		return err
	}
	if !validDecidedBy(d.DecidedBy, maxBy) {
		return invalid("decided_by", "is not a decided-by list of at most %d bytes", maxBy)
	}
	if d.TerminalReason != "" && !isEventToken(d.TerminalReason, MaxReasonTokenBytes) {
		return invalid("terminal_reason", "must be 1..%d of [a-z0-9_]", MaxReasonTokenBytes)
	}
	if !ValidEpoch(d.Epoch) {
		return invalid("epoch", "is not an epoch")
	}
	return within("assist_bound", d.AssistBound.validate())
}

func (m MintSlot) validate() error {
	switch m.State {
	case MintSignatures:
		if !ValidSHA256Hex(m.Digest) || m.Reason != "" {
			return invalid("digest", "a minted set records its digest and no reason")
		}
	case MintError:
		switch m.Reason {
		case MintReasonWindowClosed, MintReasonGrantNotLive, MintReasonClockSkew,
			MintReasonStaleTransferKey, MintReasonReservedVerb, MintReasonSigningFailed:
		default:
			return invalid("reason", "unknown mint error %q", m.Reason)
		}
		if m.Digest != "" {
			return invalid("digest", "a mint error has no digest")
		}
	default:
		return invalid("state", "must be signatures or error")
	}
	return nil
}

func (f FinalReport) validate(stepCount int) error {
	if !f.Class.Valid() {
		return invalid("class", "unknown class %q", f.Class)
	}
	if len(f.Steps) != stepCount {
		return invalid("steps", "%d steps; the record has %d", len(f.Steps), stepCount)
	}
	statuses := make([]StepStatus, len(f.Steps))
	for i, s := range f.Steps {
		if s.Ordinal != i+1 || !s.Status.Valid() {
			return invalid(fmt.Sprintf("steps[%d]", i), "ordinal must be %d and status valid", i+1)
		}
		ran := s.Status != StepNotRun && s.Status != StepSkipped
		if !ran && (s.ExitCode != nil || s.StdoutBytes != nil || s.StderrBytes != nil || s.Truncated != nil) {
			return invalid(fmt.Sprintf("steps[%d]", i), "a step with no result carries only its status (E38)")
		}
		if s.StdoutBytes != nil && *s.StdoutBytes < 0 || s.StderrBytes != nil && *s.StderrBytes < 0 {
			return invalid(fmt.Sprintf("steps[%d]", i), "byte counts are non-negative")
		}
		statuses[i] = s.Status
	}
	if !WellFormedSteps(statuses) {
		return invalid("steps", "are not in E29's shape")
	}
	if f.Class != AggregateJobClass(statuses) || f.Partial != Partial(statuses) ||
		!slices.Equal(f.ExecutedOrdinals, ExecutedOrdinals(statuses)) && !(len(f.ExecutedOrdinals) == 0 && len(ExecutedOrdinals(statuses)) == 0) {
		return invalid("class", "class, executed_ordinals and partial must equal the values derived from the steps")
	}
	if !ValidSHA256Hex(f.ResultDigest) || !ValidSHA256Hex(f.BodyDigest) {
		return invalid("result_digest", "result_digest and body_digest must be 64 lowercase hex")
	}
	return nil
}

func (p *R1Payload) validate(h R1Header) error {
	if err := within("plan", p.Plan.Validate()); err != nil {
		return err
	}
	plan := p.Plan
	if plan.Kind != h.Kind || plan.RequestID != h.RequestID || plan.RequesterPrincipal != h.Principal ||
		plan.RequesterSub != h.SubPrincipal || plan.ExecutorClaimTokenHash != h.ClaimTokenHash ||
		plan.Coordinator != h.Coordinator || !plan.SubmittedAt.Equal(h.CreatedAt) ||
		!plan.SubmitNotAfter.Equal(h.SubmitNotAfter) || !plan.RequestExpiresAt.Equal(h.RequestExpiresAt) {
		return invalid("plan", "disagrees with the header")
	}
	if g := plan.StandingGrant; g != nil && (g.Alias != h.GrantAlias || g.DurationSeconds != h.DurationSeconds || g.TrustedHostFingerprint != h.GrantHostFP) {
		return invalid("plan", "grant fields disagree with the header")
	}
	if sum, err := PlanHash(plan); err != nil || sum != h.PlanHash {
		return invalid("plan", "does not hash to the header's plan_hash")
	}
	if !slices.Equal(stepTTLs(plan), h.StepTTLs) {
		return invalid("plan", "step TTLs disagree with the header")
	}
	if len(p.ReviewSnapshot) < 2 || p.ReviewSnapshot[0] != '{' || len(p.ReviewSnapshot) > ReviewSnapshotMax {
		return invalid("review_snapshot", "must be a JSON object of at most %d bytes", ReviewSnapshotMax)
	}
	if err := checkCanonicalJSON(p.ReviewSnapshot); err != nil {
		return invalid("review_snapshot", "%v", err)
	}
	if p.AssistResult != nil {
		if err := within("assist_result", ValidateAssist(*p.AssistResult)); err != nil {
			return err
		}
		if h.Assist == nil || h.Assist.State != AssistReady || h.Assist.Digest != AssistDigest(*p.AssistResult) {
			return invalid("assist_result", "needs a ready assist slot with its digest")
		}
	}
	legs := signedLegs(plan)
	if len(p.Signatures) > 0 && (h.Mint == nil || h.Mint.State != MintSignatures || len(p.Signatures) != len(legs)) {
		return invalid("signatures", "need a minted slot and one per signed leg")
	}
	for i, s := range p.Signatures {
		if len(s) < 1 || len(s) > maxSignatureLen(legs[i].command, legs[i].host) || !allBytes(s, isPlainByte) {
			return invalid(fmt.Sprintf("signatures[%d]", i), "is not a bounded signature envelope")
		}
	}
	return p.validateNotify()
}

func (p *R1Payload) validateNotify() error {
	if len(p.CardEntries) > MaxCardEntries || len(p.Bursts) > MaxBursts || len(p.StatusEdits) > MaxStatusEdits {
		return invalid("card_entries", "card entries, bursts or status edits exceed %d, %d or %d", MaxCardEntries, MaxBursts, MaxStatusEdits)
	}
	for i, c := range p.CardEntries {
		if err := c.validate(); err != nil {
			return within(fmt.Sprintf("card_entries[%d]", i), err)
		}
	}
	for i, b := range p.Bursts {
		if err := b.validate(); err != nil {
			return within(fmt.Sprintf("bursts[%d]", i), err)
		}
	}
	for i, s := range p.StatusEdits {
		if !isEventToken(s.State, MaxStatusStateBytes) {
			return invalid(fmt.Sprintf("status_edits[%d].state", i), "must be 1..%d of [a-z0-9_]", MaxStatusStateBytes)
		}
	}
	return nil
}

func (c CardEntry) validate() error {
	if !ValidCardHandle(c.Handle) || !ValidSHA256Hex(c.ChalHash) || !ValidEpoch(c.Epoch) {
		return invalid("handle", "handle, chal_hash and epoch must be well formed")
	}
	if c.Rev < 0 || c.Rev > 1 {
		return invalid("rev", "must be 0 or 1")
	}
	if c.Kind != CardFirst && c.Kind != CardEdit && c.Kind != CardReplacement {
		return invalid("kind", "unknown card kind %q", c.Kind)
	}
	if len(c.Actions) < 1 || len(c.Actions) > 2 {
		return invalid("actions", "must hold approve and/or deny")
	}
	for _, a := range c.Actions {
		if a != ActionApprove && a != ActionDeny {
			return invalid("actions", "unknown action %q", a)
		}
	}
	if c.MsgID != nil && *c.MsgID < 1 {
		return invalid("msg_id", "must be positive")
	}
	if c.Outcome != "" && c.Outcome != OutcomeSent && c.Outcome != OutcomeError {
		return invalid("outcome", "must be sent or error")
	}
	return nil
}

func (b Burst) validate() error {
	if !ValidEpoch(b.Epoch) {
		return invalid("epoch", "is not an epoch")
	}
	if b.Gen < 0 || b.Gen > MaxBursts+1 {
		return invalid("gen", "%d is outside 0..%d", b.Gen, MaxBursts+1)
	}
	if err := validRecordStamp("started_at", b.StartedAt); err != nil {
		return err
	}
	if len(b.PartMsgIDs) > MaxBurstParts {
		return invalid("part_msg_ids", "%d parts; maximum is %d", len(b.PartMsgIDs), MaxBurstParts)
	}
	for _, id := range b.PartMsgIDs {
		if id < 1 {
			return invalid("part_msg_ids", "must be positive")
		}
	}
	if b.Outcome != "" && b.Outcome != OutcomeSent && b.Outcome != OutcomeError {
		return invalid("outcome", "must be sent or error")
	}
	return nil
}

func (job R2) validate() error {
	if job.Version != R2Version {
		return invalid("version", "must be %d", R2Version)
	}
	if err := within("draft", job.Draft.Validate()); err != nil {
		return err
	}
	if !job.Draft.Kind.ExecutionApplicable() || job.Draft.Coordinator != CoordinatorExecutor || job.RequestID != job.Draft.RequestID {
		return invalid("draft", "must be an executor-coordinated, execution-applicable draft for this request ID")
	}
	if sum, err := DraftHash(job.Draft); err != nil || sum != job.DraftHash {
		return invalid("draft_hash", "does not match the draft")
	}
	if !ValidSHA256Hex(job.InputHash) {
		return invalid("input_hash", "must be 64 lowercase hex")
	}
	if err := validRecordStamp("created_at", job.CreatedAt); err != nil {
		return err
	}
	if floor := int64(R2Reservation(job.Draft, PermittedOutputBytes(job.Draft))); job.Reservation < floor || job.Reservation > R2Max {
		return invalid("reservation", "%d is outside %d..%d, the draft's own worst case and R2Max", job.Reservation, floor, R2Max)
	}
	if job.ClaimToken != "" && !ValidSHA256Hex(job.ClaimToken) {
		return invalid("claim_token", "must be 64 lowercase hex")
	}
	if job.SignerAck != "" && !ValidSHA256Hex(job.SignerAck) {
		return invalid("signer_ack", "must be a plan_hash")
	}
	if err := job.validateSlots(); err != nil {
		return err
	}
	return job.validateSteps()
}

func (job R2) validateSlots() error {
	if o := job.Outcome; o != nil {
		switch o.Kind {
		case OutcomeDenied, OutcomeCanceled, OutcomeExpired, OutcomeApprovalLost:
			if o.Code != "" || o.Class != "" {
				return invalid("outcome", "%s carries no code or class", o.Kind)
			}
		case OutcomeJobError:
			if o.Code != "" && !definitive(o.Code) || o.Class != "" {
				return invalid("outcome", "error carries at most a definitive code")
			}
		case OutcomeAdopted:
			if !o.Class.Valid() || o.Code != "" {
				return invalid("outcome", "adopted carries a class")
			}
		default:
			return invalid("outcome.kind", "unknown outcome %q", o.Kind)
		}
	}
	if r := job.ReportResult; r != nil {
		if !(r.State == ReportAcked && r.Code == "" || r.State == ReportRefused && definitive(r.Code)) {
			return invalid("report_result", "must be acked, or refused with a definitive code")
		}
	}
	if job.BodiesRemoved != nil && !isEventToken(job.BodiesRemoved.Cause, MaxReasonTokenBytes) {
		return invalid("bodies_removed.cause", "must be 1..%d of [a-z0-9_]", MaxReasonTokenBytes)
	}
	for field, t := range map[string]*time.Time{"first_delivered_at": job.FirstDeliveredAt, "final_at": job.FinalAt} {
		if t != nil {
			if err := validRecordStamp(field, *t); err != nil {
				return err
			}
		}
	}
	return nil
}

func (job R2) validateSteps() error {
	if len(job.Steps) != jobStepCount(job.Draft) {
		return invalid("steps", "%d steps; the draft has %d", len(job.Steps), jobStepCount(job.Draft))
	}
	var total int64
	streamCap := streamOutputCap(job.Draft)
	for i, s := range job.Steps {
		if s.Ordinal != i+1 {
			return invalid(fmt.Sprintf("steps[%d].ordinal", i), "must be %d", i+1)
		}
		if s.Marker != nil && (!ValidEpoch(s.Marker.Epoch) || !validStamp(s.Marker.At, false)) {
			return invalid(fmt.Sprintf("steps[%d].marker", i), "needs an epoch and a UTC time")
		}
		if s.Result == nil {
			continue
		}
		if err := s.Result.validate(streamCap, job.BodiesRemoved != nil); err != nil {
			return within(fmt.Sprintf("steps[%d].result", i), err)
		}
		total += int64(len(s.Result.Stdout) + len(s.Result.Stderr))
	}
	if permitted := PermittedOutputBytes(job.Draft); total > permitted {
		return invalid("steps", "%d body bytes; the job may hold %d", total, permitted)
	}
	return nil
}

// streamOutputCap is the most raw bytes one stored body may hold: the
// draft's max_output_bytes for a command_job, MaxStreamOutputBytes for a
// transfer.
func streamOutputCap(d ApprovalDraft) int64 {
	if d.CommandJob != nil && d.CommandJob.MaxOutputBytes > 0 {
		return min(d.CommandJob.MaxOutputBytes, MaxStreamOutputBytes)
	}
	return MaxStreamOutputBytes
}

// PermittedOutputBytes is the most raw output a job of draft d may store:
// two streams per step at the draft's per-stream cap, at most
// MaxJobOutputBytes. Executor admission reserves
// R2Reservation(d, PermittedOutputBytes(d)), and a job record must carry at
// least that reservation.
func PermittedOutputBytes(d ApprovalDraft) int64 {
	return min(2*int64(jobStepCount(d))*streamOutputCap(d), MaxJobOutputBytes)
}

// validate checks one step result. streamCap bounds each body, and
// bodiesRemoved says the job's bodies are gone. A retained body must agree
// with its metadata: its digest is the body's, and an untruncated body holds
// exactly the bytes counted. A removed or unstorable body keeps the digest
// and count of the output it replaced.
func (r StepResult) validate(streamCap int64, bodiesRemoved bool) error {
	if !r.Status.Valid() {
		return invalid("status", "unknown status %q", r.Status)
	}
	if r.ExitCode != nil && (*r.ExitCode < -1<<31 || *r.ExitCode > 1<<31-1) {
		return invalid("exit_code", "is outside the int32 range")
	}
	if r.StdoutBytes < 0 || r.StderrBytes < 0 {
		return invalid("stdout_bytes", "byte counts are non-negative")
	}
	if !ValidSHA256Hex(r.StdoutSHA256) || !ValidSHA256Hex(r.StderrSHA256) {
		return invalid("stdout_sha256", "digests must be 64 lowercase hex")
	}
	if (bodiesRemoved || r.BodiesUnstorable) && (len(r.Stdout) > 0 || len(r.Stderr) > 0) {
		return invalid("stdout", "bodies marked removed or unstorable must be empty")
	}
	if !bodiesRemoved && !r.BodiesUnstorable {
		if err := retainedBody("stdout", r.Stdout, r.StdoutBytes, r.StdoutSHA256, r.Truncated, streamCap); err != nil {
			return err
		}
		if err := retainedBody("stderr", r.Stderr, r.StderrBytes, r.StderrSHA256, r.Truncated, streamCap); err != nil {
			return err
		}
	}
	if r.Annotation != "" && !isRouteTokenOrSpaced(r.Annotation, MaxAnnotationBytes) {
		return invalid("annotation", "must be 1..%d printable ASCII bytes", MaxAnnotationBytes)
	}
	return nil
}

// jobStepCount is how many steps a job record holds: one per command_job
// step; a transfer is one step with two legs (E28).
func jobStepCount(d ApprovalDraft) int {
	if d.CommandJob != nil {
		return len(d.CommandJob.Steps)
	}
	return 1
}

// isRouteTokenOrSpaced is isRouteToken that also admits inner spaces: a
// fixed human-readable text that still needs no JSON escaping.
func isRouteTokenOrSpaced(s string, max int) bool {
	return len(s) >= 1 && len(s) <= max && s[0] != ' ' && s[len(s)-1] != ' ' &&
		allBytes(s, func(c byte) bool { return c == ' ' || isPlainByte(c) })
}

// definitive reports whether c is a known code that settles work for good.
// A transient code never becomes a stored refusal or outcome: the work stays
// owed and retryable (SA-5).
func definitive(c Code) bool { return c.Valid() && !c.Retryable() }

// retainedBody checks a stored body against its count and digest. Truncated
// applies to the step: a truncated stream produced at least what it kept.
func retainedBody(field string, body []byte, count int64, digest string, truncated bool, streamCap int64) error {
	if int64(len(body)) > streamCap {
		return invalid(field, "is %d bytes; the stream cap is %d", len(body), streamCap)
	}
	if digest != sha256Hex(string(body)) {
		return invalid(field+"_sha256", "is not the digest of the stored body")
	}
	if truncated && count < int64(len(body)) || !truncated && count != int64(len(body)) {
		return invalid(field+"_bytes", "%d does not account for the %d stored bytes", count, len(body))
	}
	return nil
}
