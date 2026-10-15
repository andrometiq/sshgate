package approvalreview

import (
	"errors"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// LegacyMeta is the request metadata frozen before preparing a v1 sign review.
type LegacyMeta struct {
	RequestID   string
	Requester   string
	SubmittedAt time.Time
	ExpiresAt   time.Time
}

// BuildPreparedSignSnapshot binds a v1 sign review to its exact inputs and
// signer-generated instance. The caller must classify network commands as reads
// before calling it. The redaction salt is zeroed on every path.
func BuildPreparedSignSnapshot(instance string, inputs []approvalplan.LegacySignInput, meta LegacyMeta, salt *[32]byte, rules []redact.Rule) (ReviewSnapshot, error) {
	if salt == nil {
		return ReviewSnapshot{}, errors.New("approvalreview: a redaction salt is required")
	}
	defer clear(salt[:])
	if instance == "" || len(inputs) == 0 {
		return ReviewSnapshot{}, &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Field: "inputs", Msg: "instance and signing inputs are required"}
	}
	digest, ok := approvalplan.LegacySignDigest(instance, inputs)
	if !ok {
		return ReviewSnapshot{}, &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Field: "inputs", Msg: "command hash does not match signing input"}
	}
	commands := make([]LegacyCommand, len(inputs))
	for i, input := range inputs {
		if input.Net {
			if err := approvalplan.ValidateLegacyNet(len(inputs), i, input.Command, input.Reason); err != nil {
				return ReviewSnapshot{}, unrenderable(err.(*approvalplan.CodeError).Field, "invalid legacy network request")
			}
		}
		commands[i] = LegacyCommand{Server: input.Server, HostFingerprint: input.HostFingerprint, Command: input.Command, TTLSeconds: input.TTLSeconds, Reveal: input.Reveal, Reason: input.Reason}
	}
	b := &builder{salt: *salt, rules: rules}
	defer clear(b.salt[:])
	snap := ReviewSnapshot{
		Version: SnapshotVersion, Kind: approvalplan.KindCommandJob, Legacy: true, SignDigest: digest,
		RequestID: b.identity("request_id", meta.RequestID), Requester: b.identity("requester", meta.Requester),
		SubmittedAt: meta.SubmittedAt.UTC(), ExpiresAt: meta.ExpiresAt.UTC(),
		Origin: approvalplan.OriginSynthesizedLegacyV1, Reason: b.text("reason", approvalplan.LegacyRationaleText),
		Steps: b.legacySteps(commands),
	}
	for i, input := range inputs {
		snap.Steps[i].Net = input.Net
		if input.Net {
			reason := b.text("network.reason", input.Reason)
			snap.Steps[i].LegacyReason = &reason
		}
	}
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
