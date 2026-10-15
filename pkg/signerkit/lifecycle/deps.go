package lifecycle

import (
	"context"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// AuditWriter confirms an audit event reached the sink. Repeated event keys
// after a crash are permitted; an error must not advance audited_through.
type AuditWriter interface {
	WriteApproval(context.Context, approvalplan.AuditMetadata) error
}

// Minter signs in plan order at the persisted decision time. The adapter must
// revalidate the plan (including reserved verbs) before signing anything.
type Minter interface {
	Mint(context.Context, approvalplan.ApprovalPlanV1, time.Time) ([]string, error)
}

// Freezer supplies authoritative identity and registry facts. now is the same
// wall reading passed to Apply, never a fresh reading inside the adapter.
type Freezer interface {
	Freeze(context.Context, approvalplan.ApprovalDraft, string, string, time.Time) (approvalplan.ApprovalPlanV1, error)
}

// SnapshotBuilder returns encoded review bytes and the display-redacted reason.
// Its adapter owns rendering bounds and per-request redaction salt.
type SnapshotBuilder interface {
	BuildSnapshot(context.Context, approvalplan.ApprovalPlanV1) ([]byte, string, error)
}

// XferDigests reads both authoritative transfer key-entry digests inside the
// first Claim's critical section.
type XferDigests interface {
	Current(context.Context, approvalplan.Transfer) (approvalplan.XferDigests, error)
}

// Notification contains only display inputs, never the plan or signatures.
// Challenge is raw, memory-only callback material; only its hash is persisted.
type Notification struct {
	Snapshot       []byte
	Assist         *approvalplan.AssistResult
	AssistState    approvalplan.AssistState
	Revision       int
	Handle         string
	Challenge      string
	PartMessageIDs []int64
}

// EditOutcome distinguishes an uncertain edit (retry the same challenge) from
// a known failure (retire it). An unchanged message counts as EditConfirmed.
type EditOutcome uint8

const (
	EditFailed EditOutcome = iota
	EditConfirmed
	EditPossible
)

// BurstSession is usable only inside Notifier.Burst's callback. SendParts
// returns confirmed message IDs even on failure so they can be marked incomplete.
type BurstSession interface {
	SendParts(context.Context, Notification) ([]int64, error)
	SendCard(context.Context, Notification) (int64, error)
}

// Notifier holds its transport's burst lock until fn returns, including the
// engine's intervening commits. Other methods perform only the requested I/O.
type Notifier interface {
	Burst(context.Context, func(BurstSession) error) error
	EditCard(context.Context, int64, Notification) (EditOutcome, error)
	EditStatus(context.Context, int64, string) error
	MarkIncomplete(context.Context, int64) error
}

// PreparedLegacyApproval is the opaque artifact shared by the legacy request
// and notifier. Construction and copy accessors belong to legacy preparation.
type PreparedLegacyApproval struct {
	instance    string
	snapshot    []byte
	handle      string
	challenge   string
	destination int64
	assist      *approvalplan.AssistResult
	assistState approvalplan.AssistState
}

// LegacyNotifier delivers only the lifecycle's prepared artifact. Prepared
// resolves the artifact bound to an instance; delivery success means every
// part and the decision card were delivered, permitting activation.
type LegacyNotifier interface {
	Destination() int64
	Prepared(instance string) (*PreparedLegacyApproval, error)
	Deliver(context.Context, *PreparedLegacyApproval) error
	EditStatus(context.Context, *PreparedLegacyApproval, string) error
}

// AssistInputBuilder uses assist.RedactForProvider with the adapter's redaction
// policy and salt. An error skips the provider; raw plans must never be sent.
type AssistInputBuilder interface {
	BuildAssistInput(approvalplan.ApprovalPlanV1) (assist.Input, error)
}
