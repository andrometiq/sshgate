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
// registration). Unproven spans refuse the request. The caller's salt is
// zeroed on every path. K19 intake bounds do not apply to v1 (E45), but
// snapshot and review bounds are checked at freeze for both surfaces.
func BuildLegacySnapshot(req LegacyRequest, salt *[32]byte, rules []redact.Rule) (ReviewSnapshot, error) {
	if salt == nil {
		return ReviewSnapshot{}, errors.New("approvalreview: a redaction salt is required")
	}
	defer clear(salt[:])
	b := &builder{salt: *salt, rules: rules}
	defer clear(b.salt[:])

	snap := ReviewSnapshot{
		Version: SnapshotVersion, Legacy: true, RequestID: b.identity("request_id", req.RequestID),
		Requester: b.identity("requester", req.Requester), SubmittedAt: req.SubmittedAt.UTC(), ExpiresAt: req.ExpiresAt.UTC(),
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
		snap.Kind, snap.Register = approvalplan.KindRegisterTransferKey, b.legacyRegister(*req.Register)
		snap.Origin, reason = approvalplan.OriginTrustedHumanCLI, approvalplan.CLIRationaleText
	}
	if set != 1 {
		return ReviewSnapshot{}, errors.New("approvalreview: a legacy request needs exactly one payload")
	}
	snap.Reason = b.text("reason", reason)
	if b.err != nil {
		return ReviewSnapshot{}, b.err
	}
	if _, err := snap.Encode(); err != nil {
		return ReviewSnapshot{}, err
	}
	if err := snap.checkTelegramBounds(); err != nil {
		return ReviewSnapshot{}, err
	}
	return snap, nil
}

func (b *builder) legacySteps(cmds []LegacyCommand) []Step {
	out := make([]Step, len(cmds))
	for i, c := range cmds {
		route := approvalplan.RouteSignedWrite
		switch {
		case c.Command == "SSHGATE_REVOKE" || strings.HasPrefix(c.Command, updatePrefix) || strings.HasPrefix(c.Command, approvalplan.TransferVerbPrefix):
			route = approvalplan.RouteSignedAdmin
		case c.Reveal:
			route = approvalplan.RouteSignedReveal
		}
		field := fmt.Sprintf("commands[%d]", i)
		step := Step{
			Ordinal: i + 1, Route: route, Reveal: c.Reveal, TTLSeconds: int(c.TTLSeconds),
			Target:        Route{Alias: b.identity(field+".server", c.Server), Fingerprint: b.fingerprint(field+".host_fingerprint", c.HostFingerprint)},
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
	out := &Grant{Alias: b.identity("grant.alias", g.Alias), Scope: b.identity("grant.scope", g.Scope), DurationSeconds: int64(g.Duration / time.Second)}
	for i, c := range g.Commands {
		out.Commands = append(out.Commands, b.command(fmt.Sprintf("commands[%d]", i), c))
	}
	return out
}

func (b *builder) legacyTransfer(t LegacyTransfer) *Transfer {
	return &Transfer{
		TransferID: b.identity("transfer_id", t.TransferID), Mode: b.identity("mode", t.Mode),
		Source: TransferEnd{
			Label: b.identity("source.label", t.SourceLabel), Fingerprint: b.fingerprint("source.fingerprint", t.SourceFingerprint),
			Path: b.text("source_path", t.SourcePath),
		},
		Destination: TransferEnd{
			Label: b.identity("destination.label", t.DestLabel), Fingerprint: b.fingerprint("destination.fingerprint", t.DestFingerprint),
			Path: b.text("dest_path", t.DestPath),
		},
	}
}

func (b *builder) legacyRegister(r approvalplan.RegisterTransferKey) *Register {
	return &Register{HostFingerprint: b.fingerprint("register.host_fingerprint", r.HostFingerprint), Label: b.identity("register.label", r.Label), BoxPub: b.publicKey("register.box_pub", r.BoxPub, true), IDPub: b.publicKey("register.id_pub", r.IDPub, false)}
}
