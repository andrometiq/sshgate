package approvalreview

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// LegacyCommand is one command of a frozen v1 sign request.
type LegacyCommand struct {
	Server          string
	HostFingerprint string // empty when the v1 client sent none
	Command         string
	TTLSeconds      int64
	Reveal          bool
	Reason          string // the v1 per-command reason (E8c)
}

// LegacyGrant is a frozen v1 request_grant.
type LegacyGrant struct {
	Alias    string
	Scope    string
	Commands []string
	Duration time.Duration
}

// LegacyTransfer is a frozen v1 transfer. The labels come from the signer's
// registry.
type LegacyTransfer struct {
	TransferID        string
	SourceLabel       string
	SourceFingerprint string
	SourcePath        string
	DestLabel         string
	DestFingerprint   string
	DestPath          string
	Mode              string
}

// LegacyRequest is a frozen v1 approval (SA-10), rendered through the
// shared renderer with K3's legacy label, or E39's for a key registration.
// Exactly one of Commands, Grant, Transfer and Register is set.
type LegacyRequest struct {
	RequestID   string
	Requester   string
	SubmittedAt time.Time
	ExpiresAt   time.Time
	Commands    []LegacyCommand
	Grant       *LegacyGrant
	Transfer    *LegacyTransfer
	Register    *approvalplan.RegisterTransferKey
}

// BuildLegacySnapshot renders a frozen v1 request. v1 carries no reason, so
// the reason is LegacyRationaleText (or CLIRationaleText for a key
// registration). A value whose spans cannot be derived is shown as
// RedactString's output, labelled count-unavailable (E16); a value that
// cannot be redacted at all is request_unrenderable. K19 does not bound v1
// (E45): PackParts refuses what Telegram cannot carry.
func BuildLegacySnapshot(req LegacyRequest, salt [32]byte, rules []redact.Rule) (ReviewSnapshot, error) {
	b := &builder{salt: salt, rules: rules, legacy: true}
	defer clear(b.salt[:])
	snap := ReviewSnapshot{
		Version: SnapshotVersion, Legacy: true, RequestID: neutralizeToken(req.RequestID),
		Requester: neutralizeToken(req.Requester), SubmittedAt: req.SubmittedAt.UTC(), ExpiresAt: req.ExpiresAt.UTC(),
		Origin: approvalplan.OriginSynthesizedLegacyV1,
	}
	reason := approvalplan.LegacyRationaleText
	set := 0
	if len(req.Commands) > 0 {
		set++
		snap.Kind, snap.Steps = approvalplan.KindCommandJob, b.legacySteps(req.Commands)
	}
	if req.Grant != nil {
		set++
		snap.Kind, snap.Grant = approvalplan.KindStandingGrant, b.legacyGrant(*req.Grant)
	}
	if req.Transfer != nil {
		set++
		snap.Kind, snap.Transfer = approvalplan.KindTransfer, b.legacyTransfer(*req.Transfer)
	}
	if req.Register != nil {
		set++
		snap.Kind, snap.Register = approvalplan.KindRegisterTransferKey, registerOf(*req.Register)
		snap.Origin, reason = approvalplan.OriginTrustedHumanCLI, approvalplan.CLIRationaleText
	}
	if set != 1 {
		return ReviewSnapshot{}, errors.New("approvalreview: a legacy request needs exactly one payload")
	}
	snap.Reason = b.text("reason", reason)
	if b.err != nil {
		return ReviewSnapshot{}, b.err
	}
	return snap, nil
}

func (b *builder) legacySteps(cmds []LegacyCommand) []Step {
	out := make([]Step, len(cmds))
	for i, c := range cmds {
		route := approvalplan.RouteSignedWrite
		switch {
		case strings.HasPrefix(c.Command, approvalplan.AdminVerbPrefix):
			route = approvalplan.RouteSignedAdmin
		case c.Reveal:
			route = approvalplan.RouteSignedReveal
		}
		field := fmt.Sprintf("commands[%d]", i)
		step := Step{
			Ordinal: i + 1, Route: route, TTLSeconds: int(c.TTLSeconds),
			Target:        Route{Alias: neutralizeToken(c.Server), Fingerprint: neutralizeToken(c.HostFingerprint)},
			Command:       b.command(field+".cmd", c.Command),
			ExpiryWarning: i > 0,
		}
		if hash, ok := strings.CutPrefix(c.Command, updatePrefix); ok {
			step.IsUpdate = true
			if approvalplan.ValidSHA256Hex(hash) {
				step.UpdateSHA256 = hash
			}
		}
		if c.Reason != "" && (step.IsUpdate || c.Reveal) {
			reason := b.text(field+".reason", c.Reason)
			step.LegacyReason = &reason
		}
		out[i] = step
	}
	return out
}

func (b *builder) legacyGrant(g LegacyGrant) *Grant {
	out := &Grant{Alias: neutralizeToken(g.Alias), Scope: neutralizeToken(g.Scope), DurationSeconds: int64(g.Duration / time.Second)}
	for i, c := range g.Commands {
		out.Commands = append(out.Commands, b.command(fmt.Sprintf("commands[%d]", i), c))
	}
	return out
}

func (b *builder) legacyTransfer(t LegacyTransfer) *Transfer {
	return &Transfer{
		TransferID: neutralizeToken(t.TransferID), Mode: neutralizeToken(t.Mode),
		Source: TransferEnd{
			Label: neutralizeToken(t.SourceLabel), Fingerprint: neutralizeToken(t.SourceFingerprint),
			Path: b.text("source_path", t.SourcePath),
		},
		Destination: TransferEnd{
			Label: neutralizeToken(t.DestLabel), Fingerprint: neutralizeToken(t.DestFingerprint),
			Path: b.text("dest_path", t.DestPath),
		},
	}
}
