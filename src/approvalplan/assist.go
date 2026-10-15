package approvalplan

import (
	"encoding/json"
	"time"
)

// Alignment is the assist's judgement of the reason against the commands
// (K5); not_assessed is a legacy request's, which carries no reason (E36).
type Alignment string

const (
	AlignmentAligned     Alignment = "aligned"
	AlignmentPartial     Alignment = "partial"
	AlignmentMismatch    Alignment = "mismatch"
	AlignmentUncertain   Alignment = "uncertain"
	AlignmentNotAssessed Alignment = "not_assessed"
)

// Valid reports whether a is one of the five alignments.
func (a Alignment) Valid() bool {
	switch a {
	case AlignmentAligned, AlignmentPartial, AlignmentMismatch, AlignmentUncertain, AlignmentNotAssessed:
		return true
	}
	return false
}

// Severity is a concern's advisory severity (K5).
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityCaution Severity = "caution"
	SeverityHigh    Severity = "high"
)

// Valid reports whether s is one of the three severities.
func (s Severity) Valid() bool {
	return s == SeverityInfo || s == SeverityCaution || s == SeverityHigh
}

// Concern is one advisory concern.
type Concern struct {
	Severity Severity `json:"severity"`
	Text     string   `json:"text"`
}

// AssistResult is a validated advisory snapshot (K5, K8). Model text in it is
// untrusted even after validation: surfaces neutralize it (E65).
type AssistResult struct {
	Alignment     Alignment `json:"alignment"`
	Summary       string    `json:"summary"`
	Effects       []string  `json:"effects,omitempty"`
	Concerns      []Concern `json:"concerns,omitempty"`
	Model         string    `json:"model"`
	PromptVersion string    `json:"prompt_version"`
	InputDigest   string    `json:"input_digest"`
	GeneratedAt   time.Time `json:"generated_at"`
}

// §8.2 limits.
const (
	MaxAssistSummaryBytes  = 400
	MaxAssistEffectBytes   = 240
	MaxAssistEffects       = MaxSteps + 1 // one per step, or per transfer leg
	MaxAssistConcerns      = 8
	MaxAssistConcernBytes  = 240
	MaxAssistModelBytes    = 128
	MaxAssistPromptVersion = 64
	MaxAssistBytes         = 8 << 10
)

// AssistDeadlineReason is the reason of the unavailable snapshot Clock writes
// at assist_deadline (E68).
const AssistDeadlineReason = "assist deadline"

// ValidateAssist enforces spec §8.2 on a result: closed enums, bounded text
// without controls or bidi overrides, provenance fields present, and at most
// 8 KiB canonical.
func ValidateAssist(a AssistResult) error {
	if !a.Alignment.Valid() {
		return invalid("alignment", "unknown alignment %q", a.Alignment)
	}
	if err := validText("summary", a.Summary, 1, MaxAssistSummaryBytes); err != nil {
		return err
	}
	if len(a.Effects) > MaxAssistEffects {
		return invalid("effects", "%d effects; maximum is %d", len(a.Effects), MaxAssistEffects)
	}
	for _, e := range a.Effects {
		if err := validText("effects", e, 1, MaxAssistEffectBytes); err != nil {
			return err
		}
	}
	if len(a.Concerns) > MaxAssistConcerns {
		return invalid("concerns", "%d concerns; maximum is %d", len(a.Concerns), MaxAssistConcerns)
	}
	for _, c := range a.Concerns {
		if !c.Severity.Valid() {
			return invalid("concerns.severity", "unknown severity %q", c.Severity)
		}
		if err := validText("concerns.text", c.Text, 1, MaxAssistConcernBytes); err != nil {
			return err
		}
	}
	if !isRouteToken(a.Model, MaxAssistModelBytes) {
		return invalid("model", "must be 1..%d plain ASCII bytes", MaxAssistModelBytes)
	}
	if !isRouteToken(a.PromptVersion, MaxAssistPromptVersion) {
		return invalid("prompt_version", "must be 1..%d plain ASCII bytes", MaxAssistPromptVersion)
	}
	if !ValidSHA256Hex(a.InputDigest) {
		return invalid("input_digest", "must be 64 lowercase hex")
	}
	if !validStamp(a.GeneratedAt, false) {
		return invalid("generated_at", "must be an RFC 3339 UTC time")
	}
	b, err := json.Marshal(a)
	if err != nil {
		return invalid("assist", "%v", err)
	}
	if len(b) > MaxAssistBytes {
		return invalid("assist", "is %d bytes canonical; maximum is %d", len(b), MaxAssistBytes)
	}
	return nil
}

// AssistDigest is SHA-256("sshgate-assist-result-v1\0" ‖ canonical(result)),
// the digest a ready assist slot records and a decision binds (K8). A result
// that cannot be encoded (a time outside years 1..9999) digests to "", which
// equals no valid digest.
func AssistDigest(a AssistResult) string {
	b, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return hashHex("sshgate-assist-result-v1\x00", b)
}

// unavailableAssist is the canonical form an unavailable snapshot digests.
type unavailableAssist struct {
	State       AssistState `json:"state"`
	Reason      string      `json:"reason"`
	GeneratedAt time.Time   `json:"generated_at"`
}

// UnavailableAssistDigest is the digest of an unavailable snapshot: a pure
// function of its reason and generation time, so Clock's snapshot at
// assist_deadline digests the same wherever it is computed (K8, E68).
func UnavailableAssistDigest(reason string, generatedAt time.Time) string {
	b, err := json.Marshal(unavailableAssist{State: AssistUnavailable, Reason: reason, GeneratedAt: generatedAt.UTC()})
	if err != nil {
		return ""
	}
	return hashHex("sshgate-assist-unavailable-v1\x00", b)
}
