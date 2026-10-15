// Package assist produces advisory assessments of provider-safe approval copies.
// It never signs or changes a plan. Callers must skip assessment if redaction fails.
package assist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// Unavailable reasons. The engines commit these exact strings; ReasonDeadline
// is Clock's (E68) and ReasonRedaction is E15's.
const (
	ReasonBusy      = "assist busy"
	ReasonDeadline  = approvalplan.AssistDeadlineReason
	ReasonRedaction = "redaction unavailable"
	ReasonFailed    = "assist failed"
	ReasonCanceled  = "assist canceled"
)

type redactionError string

func (e redactionError) Error() string { return ReasonRedaction }

// Both RedactForProvider errors read as E15's ReasonRedaction.
var (
	ErrNoPolicy     error = redactionError("no policy")
	ErrRedactFailed error = redactionError("failed")
)

// Input contains only provider-safe text. Build it with RedactForProvider:
// that is the K7 boundary, and the only way to mark a legacy request.
type Input struct {
	PlanHash string            `json:"plan_hash"`
	Kind     approvalplan.Kind `json:"kind"`
	Reason   string            `json:"reason"`
	// Commands run if the request is approved: command_job steps or the
	// signer-built transfer legs. Effects are one per entry (K5).
	Commands []string `json:"commands"`
	// Grant is set for standing_grant only. Its commands do not run now.
	Grant *Grant `json:"grant,omitempty"`
	// legacy marks a synthesized v1 request, whose alignment Run forces to
	// not_assessed (E36). It is not provider input.
	legacy bool
}

// Grant is what a standing grant would allow later without another approval.
type Grant struct {
	Scope           approvalplan.GrantScope `json:"scope"`
	DurationSeconds int                     `json:"duration_seconds"`
	AllowedCommands []string                `json:"allowed_commands,omitempty"`
}

const inputDigestDomain = "sshgate-assist-input-v1\x00"

// Digest is SHA-256("sshgate-assist-input-v1\0" ‖ json(in)), where json(in) is
// exactly the provider's user message. It is the result's InputDigest (K5).
func (in Input) Digest() string {
	body, err := json.Marshal(in)
	if err != nil {
		panic("assist: input encoding: " + err.Error())
	}
	h := sha256.New()
	h.Write([]byte(inputDigestDomain))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (in Input) clone() Input {
	in.Commands = slices.Clone(in.Commands)
	if in.Grant != nil {
		grant := *in.Grant
		grant.AllowedCommands = slices.Clone(grant.AllowedCommands)
		in.Grant = &grant
	}
	return in
}

// RedactForProvider fails closed, including on a broken rule or redactor panic.
func RedactForProvider(plan approvalplan.ApprovalPlanV1, salt [32]byte, rules []redact.Rule) (in Input, err error) {
	defer func() {
		if recover() != nil {
			in, err = Input{}, ErrRedactFailed
		}
	}()
	if len(rules) == 0 {
		return Input{}, ErrNoPolicy
	}
	if redact.Validate(rules) != nil {
		return Input{}, ErrRedactFailed
	}
	in, err = planInput(plan)
	if err != nil {
		return Input{}, err
	}
	in.PlanHash, err = approvalplan.PlanHash(plan)
	if err != nil {
		return Input{}, ErrRedactFailed
	}
	if in.Reason, err = providerText(plan.Rationale, salt, rules); err != nil {
		return Input{}, err
	}
	if err = providerTexts(in.Commands, salt, rules); err != nil {
		return Input{}, err
	}
	if in.Grant != nil {
		if err = providerTexts(in.Grant.AllowedCommands, salt, rules); err != nil {
			return Input{}, err
		}
	}
	return in, nil
}

// planInput copies the plan's provider-visible fields, still unredacted.
func planInput(plan approvalplan.ApprovalPlanV1) (Input, error) {
	in := Input{Kind: plan.Kind, Commands: []string{}}
	switch plan.RationaleOrigin {
	case approvalplan.OriginSynthesizedLegacyV1:
		if plan.Rationale != approvalplan.LegacyRationaleText {
			return Input{}, ErrRedactFailed
		}
		in.legacy = true
	case approvalplan.OriginAgent, approvalplan.OriginTrustedHumanCLI:
	default:
		return Input{}, ErrRedactFailed
	}
	switch {
	case plan.Kind == approvalplan.KindCommandJob && plan.CommandJob != nil:
		for _, step := range plan.CommandJob.Steps {
			in.Commands = append(in.Commands, step.ExactCommand)
		}
	case plan.Kind == approvalplan.KindStandingGrant && plan.StandingGrant != nil:
		grant := plan.StandingGrant
		in.Grant = &Grant{Scope: grant.Scope, DurationSeconds: grant.DurationSeconds, AllowedCommands: slices.Clone(grant.Commands)}
	case plan.Kind == approvalplan.KindTransfer && plan.Transfer != nil:
		in.Commands = append(in.Commands, plan.Transfer.SendCommand, plan.Transfer.RecvCommand)
	case plan.Kind == approvalplan.KindRegisterTransferKey && plan.RegisterTransferKey != nil:
	default:
		return Input{}, ErrRedactFailed
	}
	return in, nil
}

func providerTexts(texts []string, salt [32]byte, rules []redact.Rule) error {
	for i, text := range texts {
		out, err := providerText(text, salt, rules)
		if err != nil {
			return err
		}
		texts[i] = out
	}
	return nil
}

// literalText neutralizes forged redaction markers and hidden-span glyphs in
// unmatched text, so only HiddenMarker output carries them (E65's \u{XXXX}).
var literalText = strings.NewReplacer(
	redact.MarkerPrefix, redact.NeutralizedMarkerPrefix,
	approvalplan.GlyphHiddenOpen, `\u{27E6}`,
	approvalplan.GlyphHiddenClose, `\u{27E7}`,
)

func providerText(text string, salt [32]byte, rules []redact.Rule) (string, error) {
	result, ok := redact.RedactSpans(text, salt, rules)
	if !ok {
		return "", ErrRedactFailed
	}
	var out strings.Builder
	start := 0
	for _, span := range result.Spans {
		out.WriteString(literalText.Replace(text[start:span.Start]))
		out.WriteString(approvalplan.HiddenMarker(span.End-span.Start, span.RuleIDs))
		start = span.End
	}
	out.WriteString(literalText.Replace(text[start:]))
	return out.String(), nil
}
