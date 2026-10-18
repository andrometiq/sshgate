package approvalplan

import (
	"encoding/json"
	"math"
	"strings"
	"time"
)

// K19 intake bounds, enforced on both planes and by the MCP before any signer
// contact.
const (
	MaxSteps      = 32
	MaxStepBytes  = 4096
	MaxTotalBytes = 24576
)

// Validity bounds (K12, E26). OQ1 permits a requested validity within these
// bounds; the signer caps it at the operator-configured validity.
const (
	ValidityMin     = 300 * time.Second
	ValidityDefault = 86400 * time.Second
	ValidityMax     = 604800 * time.Second
)

// Submit window (E73, SA-1 rule 3.5).
const (
	SubmitWindowMax = 3600 * time.Second
	// HostedSkew and LocalSkew are the allowance past SubmitWindowMax.
	HostedSkew = 300 * time.Second
	LocalSkew  = 5 * time.Second
	// SyncSubmitWindow is how far ahead the synchronous adapter sets
	// submit_not_after (E73).
	SyncSubmitWindow = 120 * time.Second
	// SyncClaimWindow is how long after created_at an in_process_sync record
	// may still be claimed: the 300 s wait budget plus 10 s of slack (E25).
	SyncClaimWindow = 310 * time.Second
)

// Report horizon (SA-6.2): default, minimum and maximum.
const (
	ReportHorizonDefault = 24 * time.Hour
	ReportHorizonMin     = time.Hour
	ReportHorizonMax     = 7 * 24 * time.Hour
)

// Votes (SA-3).
const (
	MaxRequiredApprovals = 256
	VoteSlack            = 64
)

// Await (E13, K9).
const (
	AwaitMaxIDs  = 100
	AwaitMaxWait = 55 * time.Second
)

// Signature TTLs (E60), in seconds. A TTL is never widened.
const (
	MaxWriteTTLSeconds    = 60
	MaxRevokeTTLSeconds   = 60
	MaxUpdateTTLSeconds   = 300
	MaxTransferTTLSeconds = 300
)

// MaxGrantDurationSeconds mirrors signerkit.MaxGrantDuration
// (pkg/signerkit/daemon.go:31).
const MaxGrantDurationSeconds = 86400

// Output capture (E56): raw bytes per stream per step, and per job.
const (
	MaxStreamOutputBytes = 1 << 20
	MaxJobOutputBytes    = 8 << 20
)

// SA-9 caps.
const (
	LocalLivePerPrincipal = 100
	LocalLiveTotal        = 256
	LocalFullRecords      = 512
	// LocalPayloadBudget is the byte budget that full-payload records reserve
	// against at R1Reservation. r5.8 named 32 MiB and told A1a to raise it if
	// 256 small live records reserve more than half of it; they reserve about
	// 41.8 MiB (TestR1ReservationSmallRecordBudget), so it is 96 MiB.
	LocalPayloadBudget = 96 << 20
	LocalRecordsTotal  = 65536
	HostedFullRows     = 4096
	HostedRows         = 200000
	ExecutorLiveJobs   = 100
	ExecutorBudget     = 256 << 20
	ExecutorJobFiles   = 10000
	// FlushBatch is how many unflushed records one flush pass retries.
	FlushBatch = 256
	// NoiseFold is how many unflushed noise events an outbox holds before
	// further ones fold into noise_dropped; a shed record folds beyond 1.
	NoiseFold     = 32
	ShedNoiseFold = 1
)

// Route-snapshot field bounds (r5.2), enforced by the strict draft decode.
const (
	MaxAliasBytes          = 64
	MaxHostBytes           = 253
	MaxUserBytes           = 64
	MaxFingerprintBytes    = 128 // xferwire.maxFingerprintLen (src/xferwire/xferwire.go:76)
	fingerprintPrefix      = "SHA256:"
	MaxStagedBasenameBytes = 255
	MaxVersionBytes        = 128
)

// VoteCap is the most votes rec may hold: its frozen quorum plus VoteSlack, so
// the vote set always has room for every approval still needed (SA-3).
func VoteCap(rec R1) int {
	return rec.Header.RequiredApprovals + VoteSlack
}

// MaxStepTTL is E60's route table: the longest signature TTL a step on route
// with this command may carry. An unsigned read carries none (0); so does a
// signed_admin step whose command is no admin form.
func MaxStepTTL(route Route, command string) int {
	switch route {
	case RouteSignedWrite, RouteSignedReveal:
		return MaxWriteTTLSeconds
	case RouteSignedAdmin:
		switch {
		case command == adminRevoke:
			return MaxRevokeTTLSeconds
		case isUpdateCommand(command):
			return MaxUpdateTTLSeconds
		}
	}
	return 0
}

// ValidateRouteSnapshot enforces the r5.2 bounds on one route snapshot. The
// fingerprint may be empty here (a registry entry written before fingerprints
// existed); a signed step refuses an empty one (E35).
func ValidateRouteSnapshot(r RouteSnapshot) error {
	if !isRouteToken(r.ServerAlias, MaxAliasBytes) {
		return invalid("server_alias", "must be 1..%d printable ASCII bytes without space, quote, backslash, <, > or &", MaxAliasBytes)
	}
	if !isRouteToken(r.ResolvedHost, MaxHostBytes) {
		return invalid("resolved_host", "must be 1..%d printable ASCII bytes without space, quote, backslash, <, > or &", MaxHostBytes)
	}
	if r.ResolvedPort < 1 || r.ResolvedPort > 65535 {
		return invalid("resolved_port", "%d is outside 1..65535", r.ResolvedPort)
	}
	if !isRouteToken(r.ResolvedUser, MaxUserBytes) {
		return invalid("resolved_user", "must be 1..%d printable ASCII bytes without space, quote, backslash, <, > or &", MaxUserBytes)
	}
	if r.TrustedHostFingerprint != "" && !ValidFingerprint(r.TrustedHostFingerprint) {
		return invalid("trusted_host_fingerprint", "is not an OpenSSH SHA256: fingerprint")
	}
	if !validStamp(r.AddedAt, true) {
		return invalid("added_at", "must be an RFC 3339 UTC time")
	}
	return nil
}

// ValidFingerprint mirrors xferwire.ValidFingerprint
// (src/xferwire/xferwire.go:321): "SHA256:" then printable ASCII without
// space, at most 128 bytes in all.
func ValidFingerprint(s string) bool {
	return len(s) <= MaxFingerprintBytes && strings.HasPrefix(s, fingerprintPrefix) &&
		allBytes(s, func(c byte) bool { return c > 0x20 && c < 0x7f })
}

// CheckSubmitWindow judges a new ID's submit_not_after at the wall clock
// (SA-1 rule 3.5): now ≤ submit_not_after ≤ now + SubmitWindowMax +
// allowance. allowance is LocalSkew or HostedSkew. An existing ID is returned
// whatever the time and never reaches this check.
func CheckSubmitWindow(now, submitNotAfter time.Time, allowance time.Duration) error {
	if now.After(submitNotAfter) {
		return codeErr(CodeSubmitWindowClosed, "submit_not_after", "the submit window closed at %s", submitNotAfter.Format(time.RFC3339))
	}
	if submitNotAfter.After(now.Add(SubmitWindowMax + allowance)) {
		return codeErr(CodeSubmitWindowAhead, "submit_not_after", "is more than %s ahead of the signer's clock", SubmitWindowMax+allowance)
	}
	return nil
}

// isRouteToken: 1..max printable ASCII bytes with none of space, '"', '\\',
// '<', '>' or '&', so the value never needs JSON or HTML escaping.
func isRouteToken(s string, max int) bool {
	return len(s) >= 1 && len(s) <= max && allBytes(s, isPlainByte)
}

func isPlainByte(c byte) bool {
	return c > 0x20 && c < 0x7f && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&'
}

// validStamp requires a UTC time that encodes as RFC 3339 (years 1..9999).
// zeroOK admits the zero time, which a pre-added_at registry entry carries.
func validStamp(t time.Time, zeroOK bool) bool {
	if t.IsZero() {
		return zeroOK
	}
	return t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999
}

// R1Reservation is rec's whole-life encoded worst case (SA-9): the record with
// every slot filled, every set and the outbox at its bound, and every value at
// the longest encoding its validator admits. It reads only the frozen header
// and the immutable payload (plan and review snapshot), so it is the same at
// every unshed state of one record. Local payload admission charges each
// full-payload record this much from Submit until Shed or Delete.
func R1Reservation(rec R1) int {
	b, err := json.Marshal(grownR1(rec))
	if err != nil {
		return R1Max
	}
	return len(b)
}

// R2Reservation is a job's encoded worst case for executor admission (SA-9):
// its own non-body record at every slot's bound, plus the base64 of
// maxOutputBytes of raw output and the per-body overhead. maxOutputBytes is
// the job's total raw output cap; a value outside 0..MaxJobOutputBytes
// reserves MaxJobOutputBytes.
func R2Reservation(d ApprovalDraft, maxOutputBytes int64) int {
	if maxOutputBytes < 0 || maxOutputBytes > MaxJobOutputBytes {
		maxOutputBytes = MaxJobOutputBytes
	}
	b, err := json.Marshal(worstR2(d))
	if err != nil {
		return R2Max
	}
	return len(b) + 4*int((maxOutputBytes+2)/3) + R2BodyOverhead
}

// Longest admitted values, for the reservations.
var (
	worstTime   = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	worstHex64  = strings.Repeat("f", 64)
	worstEpoch  = strings.Repeat("f", EpochLen)
	worstBound  = AssistBound{State: AssistNotApplicable, Revision: 1, Digest: worstHex64}
	worstInt32  = math.MinInt32
	worstInt64  = int64(math.MaxInt64)
	worstTrue   = true
	worstCode   = CodeLifecycleUnavailable
	worstStatus = StepExpiredUnexecuted
)

func plain(n int) string { return strings.Repeat("a", n) }

// grownR1 is rec at its whole-life bound: the frozen header and immutable
// payload kept, every mutable field replaced by its worst case.
func grownR1(rec R1) R1 {
	h := rec.Header
	voteCap := VoteCap(rec)
	h.Assist = &AssistSlot{State: AssistUnavailable, Reason: plain(MaxAssistReasonBytes), GeneratedAt: worstTime, Digest: worstHex64}
	h.Decision = &Decision{
		Status: ApprovalCanceled, DecidedAt: worstTime, DecidedBy: plain(maxDecidedBy(h.RequiredApprovals)),
		TerminalReason: plain(MaxReasonTokenBytes), Epoch: worstEpoch, AssistBound: worstBound,
	}
	h.Mint = &MintSlot{State: MintSignatures, Digest: worstHex64, Reason: MintReasonStaleTransferKey}
	h.FinalReport = worstFinalReport(h.StepCount)
	h.RevokedAt = &worstTime
	h.Votes = make([]Vote, voteCap)
	for i := range h.Votes {
		h.Votes[i] = Vote{Operator: plain(MaxOperatorIDBytes), Decision: VoteApprove, TS: worstTime, Authn: plain(MaxAuthnBytes)}
	}
	h.ClaimCount = worstInt64
	h.RenotifyGen = MaxBursts + 1
	h.OutboxSeq, h.AuditedThrough, h.NoiseDropped = math.MaxUint64, math.MaxUint64, math.MaxUint64
	h.Outbox = worstOutbox(voteCap+outboxFixedEvents+NoiseFold, h.RequiredApprovals)
	h.Shed = false
	grown := R1{Header: h}
	if p := rec.Payload; p != nil {
		grown.Payload = &R1Payload{
			Plan:           p.Plan,
			ReviewSnapshot: p.ReviewSnapshot,
			// Over MaxAssistBytes on its own, so above any valid result.
			AssistResult: &AssistResult{Summary: plain(MaxAssistBytes)},
			Signatures:   worstSignatures(p.Plan),
			CardEntries:  worstCards(),
			Bursts:       worstBursts(),
			StatusEdits:  worstStatusEdits(),
		}
	}
	return grown
}

// worstOutbox is n events with every field the validator admits at its
// longest, decided_by on the one event that may carry it.
func worstOutbox(n, requiredApprovals int) []OutboxEvent {
	event := OutboxEvent{
		Seq: math.MaxUint64, Kind: plain(MaxEventKindBytes), Replay: true, Operator: plain(MaxOperatorIDBytes),
		Decision: plain(MaxDecisionBytes), Detail: plain(MaxDetailBytes), Assist: &worstBound, NoiseDropped: math.MaxUint64,
	}
	out := make([]OutboxEvent, n)
	for i := range out {
		out[i] = event
	}
	if n > 0 {
		out[0].DecidedBy = plain(maxDecidedBy(requiredApprovals))
	}
	return out
}

func worstFinalReport(stepCount int) *FinalReport {
	f := &FinalReport{Class: ClassExpiredUnexecuted, Partial: true, ResultDigest: worstHex64, BodyDigest: worstHex64}
	for i := range stepCount {
		f.Steps = append(f.Steps, StepReport{
			Ordinal: i + 1, Status: worstStatus, ExitCode: &worstInt32,
			StdoutBytes: &worstInt64, StderrBytes: &worstInt64, Truncated: &worstTrue,
		})
		f.ExecutedOrdinals = append(f.ExecutedOrdinals, i+1)
	}
	return f
}

func worstSignatures(p ApprovalPlanV1) []string {
	var sigs []string
	for _, leg := range signedLegs(p) {
		sigs = append(sigs, strings.Repeat("A", maxSignatureLen(leg.command, leg.host)))
	}
	return sigs
}

func worstCards() []CardEntry {
	msgID := worstInt64
	cards := make([]CardEntry, MaxCardEntries)
	for i := range cards {
		cards[i] = CardEntry{
			Handle: plain(CardHandleLen), Rev: 1, ChalHash: worstHex64, Actions: []string{ActionApprove, ActionDeny},
			Kind: CardReplacement, Epoch: worstEpoch, MsgID: &msgID, Outcome: OutcomeError, Confirmed: true, Retired: true,
		}
	}
	return cards
}

func worstBursts() []Burst {
	parts := make([]int64, MaxBurstParts)
	for i := range parts {
		parts[i] = worstInt64
	}
	bursts := make([]Burst, MaxBursts)
	for i := range bursts {
		bursts[i] = Burst{Epoch: worstEpoch, Gen: MaxBursts + 1, StartedAt: worstTime, PartMsgIDs: parts, Outcome: OutcomeError}
	}
	return bursts
}

func worstStatusEdits() []StatusEdit {
	edits := make([]StatusEdit, MaxStatusEdits)
	for i := range edits {
		edits[i] = StatusEdit{State: plain(MaxStatusStateBytes)}
	}
	return edits
}

// worstR2 is d's job record at every slot's bound, without bodies.
func worstR2(d ApprovalDraft) R2 {
	steps := make([]JobStep, jobStepCount(d))
	for i := range steps {
		steps[i] = JobStep{
			Ordinal: i + 1,
			Marker:  &Marker{Epoch: worstEpoch, At: worstTime},
			Result: &StepResult{
				Status: worstStatus, ExitCode: &worstInt32, StdoutBytes: worstInt64, StderrBytes: worstInt64,
				Truncated: true, StdoutSHA256: worstHex64, StderrSHA256: worstHex64, BodiesUnstorable: true,
				Annotation: plain(MaxAnnotationBytes),
			},
		}
	}
	return R2{
		Version: R2Version, RequestID: d.RequestID, InputHash: worstHex64, Draft: d, DraftHash: worstHex64,
		CreatedAt: worstTime, Reservation: worstInt64, ClaimToken: worstHex64, SignerAck: worstHex64,
		Outcome:          &JobOutcome{Kind: OutcomeApprovalLost, Code: worstCode, Class: ClassExpiredUnexecuted},
		ReportResult:     &ReportResult{State: ReportRefused, Code: worstCode},
		FirstDeliveredAt: &worstTime, BodiesRemoved: &BodiesRemoved{Cause: plain(MaxReasonTokenBytes)}, FinalAt: &worstTime,
		Steps: steps,
	}
}
