package approvalplan

import (
	"strconv"
	"time"
)

// AuditMetadata is the approval payload appended to signerkit's AuditEvent,
// AuditCall and AuditVerdict as `approval,omitempty` (E23, E62). A line whose
// Replay is set is inert: it never records a resolution (E23, r5.8).
type AuditMetadata struct {
	Kind              Kind            `json:"kind,omitempty"`
	RequestID         string          `json:"request_id,omitempty"`
	Principal         string          `json:"principal,omitempty"`
	PlanHash          string          `json:"plan_hash,omitempty"`
	RationaleRedacted string          `json:"rationale_redacted,omitempty"`
	RationaleOrigin   RationaleOrigin `json:"rationale_origin,omitempty"`
	Assist            *AssistBound    `json:"assist,omitempty"`
	Transition        string          `json:"transition"`
	Decision          string          `json:"decision,omitempty"`
	DecidedAt         *time.Time      `json:"decided_at,omitempty"`
	DecidedBy         string          `json:"decided_by,omitempty"`
	Execution         *AuditExecution `json:"execution,omitempty"`
	Replay            bool            `json:"replay,omitempty"`
	EventKey          string          `json:"event_key,omitempty"`
}

// AuditExecution is the execution part of an audit line. ClientReported marks
// a class that came from a coordinator's report (E38).
type AuditExecution struct {
	State          ExecutionStatus `json:"state"`
	Class          JobClass        `json:"class,omitempty"`
	ClientReported bool            `json:"client_reported,omitempty"`
}

// OutboxEvent is one audit event appended to a record in the same commit as
// its transition (SA-7). The flusher joins it with the header (plan hash,
// redacted reason, origin) into AuditMetadata, with event_key "<record
// key>:<seq>". Replay marks a noise event (vote_replay, vote_refused,
// invalid_claim, invalid_report), the only kind the fold may drop.
type OutboxEvent struct {
	Seq          uint64       `json:"seq"`
	Kind         string       `json:"kind"`
	Replay       bool         `json:"replay,omitempty"`
	Operator     string       `json:"operator,omitempty"`
	Decision     string       `json:"decision,omitempty"`
	Detail       string       `json:"detail,omitempty"`
	Assist       *AssistBound `json:"assist,omitempty"`
	DecidedBy    string       `json:"decided_by,omitempty"`
	NoiseDropped uint64       `json:"noise_dropped,omitempty"`
}

// Event field bounds. Every bounded string is plain ASCII, which json.Marshal
// never escapes, so its encoded size is its length.
const (
	MaxEventKindBytes = 32
	MaxDecisionBytes  = 16
	MaxDetailBytes    = 128
)

// EventKey is an outbox event's audit key (SA-2, E23).
func EventKey(recordKey string, seq uint64) string {
	return recordKey + ":" + strconv.FormatUint(seq, 10)
}

func (e OutboxEvent) validate(maxDecidedBy int) error {
	if e.Seq == 0 {
		return invalid("seq", "starts at 1")
	}
	if !isEventToken(e.Kind, MaxEventKindBytes) {
		return invalid("kind", "must be 1..%d of [a-z0-9_]", MaxEventKindBytes)
	}
	if e.Operator != "" && !ValidOperatorID(e.Operator) {
		return invalid("operator", "is not an operator ID")
	}
	if e.Decision != "" && !isEventToken(e.Decision, MaxDecisionBytes) {
		return invalid("decision", "must be 1..%d of [a-z0-9_]", MaxDecisionBytes)
	}
	if e.Detail != "" && !isRouteToken(e.Detail, MaxDetailBytes) {
		return invalid("detail", "must be 1..%d plain ASCII bytes", MaxDetailBytes)
	}
	if e.Assist != nil {
		if err := e.Assist.validate(); err != nil {
			return within("assist", err)
		}
	}
	if e.DecidedBy != "" && !validDecidedBy(e.DecidedBy, maxDecidedBy) {
		return invalid("decided_by", "is not a decided-by list")
	}
	return nil
}

func isEventToken(s string, max int) bool {
	return len(s) >= 1 && len(s) <= max && allBytes(s, func(c byte) bool {
		return (c >= 'a' && c <= 'z') || isDigit(c) || c == '_'
	})
}
