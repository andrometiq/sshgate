// Package approvalreview is the surface-neutral approval renderer (K19, K20,
// spec §9.1): it freezes a plan into a ReviewSnapshot, turns a snapshot into
// the View both surfaces show, and packs that view into bounded Telegram
// parts and a decision card.
//
// The display contract: every command shows its exact bytes, escaped to
// printable ASCII, except detector-matched secret spans, each replaced by
// approvalplan.HiddenMarker with its byte count, next to the SHA-256 of the
// exact original bytes. A v2 command that cannot be displayed that way is
// refused (request_unrenderable), never shown fully hidden. All agent-, client-
// and model-controlled text is neutralized, so renderer glyphs and line
// structure come only from the renderer.
package approvalreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// SnapshotVersion is the stored snapshot encoding's version.
const SnapshotVersion = 1

// Test seams: a forced failure of either redactor must fail closed.
var (
	redactSpans  = redact.RedactSpans
	redactString = redact.RedactString
)

// Segment is one piece of a display: visible text (already escaped or
// neutralized to printable ASCII) or one hidden span.
type Segment struct {
	Text    string   `json:"text,omitempty"`
	Hidden  int      `json:"hidden,omitempty"`
	RuleIDs []string `json:"rule_ids,omitempty"`
}

// Display is the redacted rendering of one exact value. SHA256 is the
// SHA-256 of the exact original bytes, set for signed or grant-covered
// command bytes only.
type Display struct {
	Segments    []Segment `json:"segments,omitempty"`
	Bytes       int       `json:"bytes"`
	HiddenBytes int       `json:"hidden_bytes"`
	FullyHidden bool      `json:"fully_hidden,omitempty"`
	// CountUnavailable marks a legacy v1 display built from RedactString's
	// output because the spans could not be derived (E16).
	CountUnavailable bool   `json:"count_unavailable,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
}

// Route is a step's target as the requester resolved it (E35).
type Route struct {
	Alias       string `json:"alias"`
	User        string `json:"user,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Build is an SSHGATE_UPDATE step's client-supplied build metadata (E33).
type Build struct {
	StagedBasename string `json:"staged_basename"`
	StagedVersion  string `json:"staged_version"`
	RunningVersion string `json:"running_version"`
	Size           int64  `json:"size"`
}

// Step is one command of a command job, in its batch position.
type Step struct {
	Ordinal    int                `json:"ordinal"`
	Route      approvalplan.Route `json:"route"`
	Target     Route              `json:"target"`
	TTLSeconds int                `json:"ttl_seconds"`
	Command    Display            `json:"command"`
	// IsUpdate marks an SSHGATE_UPDATE step. UpdateSHA256 is the hash taken
	// from the signed command bytes, empty when they carry a malformed one
	// (legacy only; a v2 plan cannot hold one).
	IsUpdate     bool   `json:"is_update,omitempty"`
	UpdateSHA256 string `json:"update_sha256,omitempty"`
	Build        *Build `json:"build_metadata,omitempty"`
	// LegacyReason is the v1 per-command reason of a reveal or update step (E8c).
	LegacyReason *Display `json:"legacy_reason,omitempty"`
	// ExpiryWarning is K16's: the step is signed and runs after earlier work.
	ExpiryWarning bool `json:"expiry_warning,omitempty"`
}

// Grant is a standing-grant request. AutoSigns is false for a v1 grant,
// which no longer auto-signs anything (OQ3 (b)).
type Grant struct {
	Alias           string    `json:"alias"`
	Scope           string    `json:"scope"`
	Commands        []Display `json:"commands,omitempty"`
	DurationSeconds int64     `json:"duration_seconds"`
	Fingerprint     string    `json:"fingerprint,omitempty"`
	AutoSigns       bool      `json:"auto_signs"`
}

// TransferEnd is one side of a transfer. Label and PublicKeySHA256 come
// from the signer's transfer registry; Target and Path from the requester.
type TransferEnd struct {
	Label           string  `json:"label"`
	Fingerprint     string  `json:"fingerprint"`
	Target          *Route  `json:"target,omitempty"`
	Path            Display `json:"path"`
	PublicKeySHA256 string  `json:"public_key_sha256,omitempty"`
}

// Transfer is a box-to-box transfer (E34). The leg hashes are of the exact
// signer-built legs the approval signs.
type Transfer struct {
	TransferID  string      `json:"transfer_id"`
	Source      TransferEnd `json:"source"`
	Destination TransferEnd `json:"destination"`
	Mode        string      `json:"mode"`
	TTLSeconds  int         `json:"ttl_seconds,omitempty"`
	SendSHA256  string      `json:"send_sha256,omitempty"`
	RecvSHA256  string      `json:"recv_sha256,omitempty"`
}

// Register is a transfer-key enrollment. The keys are public.
type Register struct {
	HostFingerprint string `json:"host_fingerprint"`
	Label           string `json:"label"`
	BoxPub          string `json:"box_pub"`
	IDPub           string `json:"id_pub"`
}

// ReviewSnapshot is what a surface renders: frozen at freeze, stored as
// canonical JSON (E37), and holding only printable-ASCII strings. It never
// holds the salt, a marker key or a hidden byte.
type ReviewSnapshot struct {
	Version           int                          `json:"version"`
	Kind              approvalplan.Kind            `json:"kind"`
	Legacy            bool                         `json:"legacy,omitempty"`
	RequestID         string                       `json:"request_id"`
	PlanHash          string                       `json:"plan_hash,omitempty"`
	Requester         string                       `json:"requester"`
	SubmittedAt       time.Time                    `json:"submitted_at"`
	ExpiresAt         time.Time                    `json:"expires_at"`
	SyncClaimDeadline *time.Time                   `json:"sync_claim_deadline,omitempty"`
	Origin            approvalplan.RationaleOrigin `json:"rationale_origin"`
	Reason            Display                      `json:"reason"`
	Steps             []Step                       `json:"steps,omitempty"`
	Grant             *Grant                       `json:"grant,omitempty"`
	Transfer          *Transfer                    `json:"transfer,omitempty"`
	Register          *Register                    `json:"register,omitempty"`
}

// unrenderable is the refusal for a request no surface can display faithfully.
func unrenderable(field, format string, args ...any) error {
	return &approvalplan.CodeError{Code: approvalplan.CodeRequestUnrenderable, Field: field, Msg: fmt.Sprintf(format, args...)}
}

// IsUnrenderable reports whether err is a request_unrenderable refusal.
func IsUnrenderable(err error) bool {
	var ce *approvalplan.CodeError
	return errors.As(err, &ce) && ce.Code == approvalplan.CodeRequestUnrenderable
}

// BuildSnapshot freezes a validated v2 plan into its review snapshot. salt is
// the request's redaction salt; BuildSnapshot zeroes it before returning, on
// every path (E37). It answers request_unrenderable when any displayed value
// has no proven span set, when the encoded snapshot exceeds
// approvalplan.ReviewSnapshotMax, or when the Telegram review would exceed
// its bounds (K19: the same request must be reviewable on either surface).
func BuildSnapshot(plan approvalplan.ApprovalPlanV1, salt *[32]byte, rules []redact.Rule) (ReviewSnapshot, error) {
	if salt == nil {
		return ReviewSnapshot{}, errors.New("approvalreview: a redaction salt is required")
	}
	defer clear(salt[:])
	if err := plan.Validate(); err != nil {
		return ReviewSnapshot{}, err
	}
	planHash, err := approvalplan.PlanHash(plan)
	if err != nil {
		return ReviewSnapshot{}, err
	}
	b := &builder{salt: *salt, rules: rules}
	defer clear(b.salt[:])
	requester := plan.RequesterPrincipal
	if plan.RequesterSub != "" {
		requester += " sub=" + plan.RequesterSub
	}
	snap := ReviewSnapshot{
		Version: SnapshotVersion, Kind: plan.Kind, RequestID: plan.RequestID, PlanHash: planHash,
		Requester: requester, SubmittedAt: plan.SubmittedAt, ExpiresAt: plan.RequestExpiresAt,
		Origin: plan.RationaleOrigin, Reason: b.text("reason", plan.Rationale),
	}
	if plan.Coordinator == approvalplan.CoordinatorInProcessSync {
		deadline := plan.SubmittedAt.Add(approvalplan.SyncClaimWindow)
		snap.SyncClaimDeadline = &deadline
	}
	switch plan.Kind {
	case approvalplan.KindCommandJob:
		snap.Steps = b.steps(plan.CommandJob.Steps)
	case approvalplan.KindStandingGrant:
		snap.Grant = b.grant(plan.StandingGrant)
	case approvalplan.KindTransfer:
		snap.Transfer = b.transfer(plan.Transfer)
	case approvalplan.KindRegisterTransferKey:
		snap.Register = registerOf(*plan.RegisterTransferKey)
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

// Encode returns the snapshot's canonical JSON, the bytes R1 stores. A
// snapshot over approvalplan.ReviewSnapshotMax is request_unrenderable.
func (s ReviewSnapshot) Encode() (json.RawMessage, error) {
	b, err := approvalplan.Canonical(s)
	if err != nil {
		return nil, err
	}
	if len(b) > approvalplan.ReviewSnapshotMax {
		return nil, unrenderable("review_snapshot", "is %d bytes encoded; maximum is %d", len(b), approvalplan.ReviewSnapshotMax)
	}
	if err := checkASCIIStrings(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeSnapshot strictly decodes stored snapshot bytes: one canonical value,
// no unknown field, the current version, within ReviewSnapshotMax, and every
// string printable ASCII. A renderer only ever renders what this accepts.
func DecodeSnapshot(b []byte) (ReviewSnapshot, error) {
	if len(b) > approvalplan.ReviewSnapshotMax {
		return ReviewSnapshot{}, fmt.Errorf("approvalreview: snapshot is %d bytes; maximum is %d", len(b), approvalplan.ReviewSnapshotMax)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s ReviewSnapshot
	if err := dec.Decode(&s); err != nil {
		return ReviewSnapshot{}, fmt.Errorf("approvalreview: snapshot: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ReviewSnapshot{}, errors.New("approvalreview: snapshot: trailing data")
	}
	if s.Version != SnapshotVersion {
		return ReviewSnapshot{}, fmt.Errorf("approvalreview: snapshot version %d; want %d", s.Version, SnapshotVersion)
	}
	again, err := approvalplan.Canonical(s)
	if err != nil || !bytes.Equal(again, b) {
		return ReviewSnapshot{}, errors.New("approvalreview: snapshot is not in canonical form")
	}
	if err := checkASCIIStrings(b); err != nil {
		return ReviewSnapshot{}, err
	}
	return s, nil
}

// checkASCIIStrings proves every string in canonical JSON b is printable
// ASCII: b itself must be printable ASCII, and its only escapes may be the
// ones json.Marshal writes for '"', '\\', '<', '>' and '&'. A control
// character, line break or non-ASCII rune in any string fails it.
func checkASCIIStrings(b []byte) error {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x20 || c > 0x7e {
			return fmt.Errorf("approvalreview: snapshot byte %d is 0x%02x, outside printable ASCII", i, c)
		}
		if c != '\\' {
			continue
		}
		rest := b[i:]
		switch {
		case bytes.HasPrefix(rest, []byte(`\\`)), bytes.HasPrefix(rest, []byte(`\"`)):
			i++
		case bytes.HasPrefix(rest, []byte(`\u003c`)), bytes.HasPrefix(rest, []byte(`\u003e`)), bytes.HasPrefix(rest, []byte(`\u0026`)):
			i += 5
		default:
			return fmt.Errorf("approvalreview: snapshot string escape at byte %d is not printable ASCII", i)
		}
	}
	return nil
}

// builder carries the salt and rules through one snapshot build and keeps
// its first failure.
type builder struct {
	salt   [32]byte
	rules  []redact.Rule
	legacy bool
	err    error
}

func (b *builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

// command displays exact command bytes, with their SHA-256.
func (b *builder) command(field, s string) Display {
	d := b.display(field, s, escapeCommand)
	sum := sha256.Sum256([]byte(s))
	d.SHA256 = hex.EncodeToString(sum[:])
	return d
}

// text displays requester- or client-supplied text.
func (b *builder) text(field, s string) Display {
	return b.display(field, s, NeutralizeText)
}

// display splits s at its proven hidden spans. When the spans cannot be
// derived, a v2 build fails request_unrenderable and a legacy build falls
// back to RedactString's output with the count unavailable (E16); no byte
// that no rule matched is ever hidden.
func (b *builder) display(field, s string, escape func(string) string) Display {
	result, ok := safeRedactSpans(s, b.salt, b.rules)
	if ok {
		ok = spansWellFormed(s, result)
	}
	if !ok {
		if b.legacy {
			return b.countUnavailable(field, s, escape)
		}
		b.fail(unrenderable(field, "no faithful display: the hidden spans could not be proven"))
		return Display{}
	}
	d := Display{Bytes: len(s), HiddenBytes: result.HiddenBytes}
	at := 0
	for _, span := range result.Spans {
		if span.Start > at {
			d.Segments = append(d.Segments, Segment{Text: escape(s[at:span.Start])})
		}
		ids := make([]string, len(span.RuleIDs))
		for i, id := range span.RuleIDs {
			ids[i] = neutralizeToken(id)
		}
		d.Segments = append(d.Segments, Segment{Hidden: span.End - span.Start, RuleIDs: ids})
		at = span.End
	}
	if at < len(s) {
		d.Segments = append(d.Segments, Segment{Text: escape(s[at:])})
	}
	d.FullyHidden = len(s) > 0 && result.HiddenBytes == len(s)
	return d
}

func (b *builder) countUnavailable(field, s string, escape func(string) string) Display {
	redacted, ok := safeRedactString(s, b.salt, b.rules)
	if !ok {
		b.fail(unrenderable(field, "no faithful display: redaction failed"))
		return Display{}
	}
	d := Display{Bytes: len(s), CountUnavailable: redacted != s}
	if redacted != "" {
		d.Segments = []Segment{{Text: escape(redacted)}}
	}
	return d
}

// spansWellFormed re-checks RedactSpans' result before it is trusted: spans
// ascending, non-empty, inside s and summing to HiddenBytes.
func spansWellFormed(s string, r redact.SpanResult) bool {
	at, hidden := 0, 0
	for _, span := range r.Spans {
		if span.Start < at || span.End <= span.Start || span.End > len(s) {
			return false
		}
		hidden += span.End - span.Start
		at = span.End
	}
	return hidden == r.HiddenBytes
}

func safeRedactSpans(s string, salt [32]byte, rules []redact.Rule) (result redact.SpanResult, ok bool) {
	defer func() {
		if recover() != nil {
			result, ok = redact.SpanResult{}, false
		}
	}()
	return redactSpans(s, salt, rules)
}

func safeRedactString(s string, salt [32]byte, rules []redact.Rule) (redacted string, ok bool) {
	defer func() {
		if recover() != nil {
			redacted, ok = "", false
		}
	}()
	return redactString(s, salt, rules)
}

func (b *builder) steps(steps []approvalplan.Step) []Step {
	out := make([]Step, len(steps))
	for i, s := range steps {
		target := s.Target
		out[i] = Step{
			Ordinal: s.Ordinal, Route: s.Route, TTLSeconds: s.SignatureTTLSeconds,
			Target: Route{
				Alias: target.ServerAlias, User: target.ResolvedUser, Host: target.ResolvedHost,
				Port: target.ResolvedPort, Fingerprint: target.TrustedHostFingerprint,
			},
			Command:       b.command(fmt.Sprintf("steps[%d].exact_command", i), s.ExactCommand),
			ExpiryWarning: i > 0 && s.Route.Signed(),
		}
		if hash, ok := strings.CutPrefix(s.ExactCommand, updatePrefix); ok {
			out[i].IsUpdate, out[i].UpdateSHA256 = true, hash
		}
		if td := s.TrustedDisplay; td != nil {
			out[i].Build = &Build{
				StagedBasename: NeutralizeText(td.StagedBasename), StagedVersion: NeutralizeText(td.StagedVersion),
				RunningVersion: NeutralizeText(td.RunningVersion), Size: td.Size,
			}
		}
	}
	return out
}

func (b *builder) grant(g *approvalplan.StandingGrant) *Grant {
	out := &Grant{
		Alias: g.Alias, Scope: string(g.Scope), DurationSeconds: int64(g.DurationSeconds),
		Fingerprint: g.TrustedHostFingerprint, AutoSigns: true,
	}
	for i, c := range g.Commands {
		out.Commands = append(out.Commands, b.command(fmt.Sprintf("exact_allowed_commands[%d]", i), c))
	}
	return out
}

func (b *builder) transfer(t *approvalplan.Transfer) *Transfer {
	end := func(field string, e approvalplan.TransferEndpoint) TransferEnd {
		return TransferEnd{
			Label: neutralizeToken(e.KeyLabel), Fingerprint: e.Target.TrustedHostFingerprint,
			Target: &Route{
				Alias: e.Target.ServerAlias, User: e.Target.ResolvedUser, Host: e.Target.ResolvedHost,
				Port: e.Target.ResolvedPort,
			},
			Path: b.text(field+".path", e.Path), PublicKeySHA256: e.PublicKeySHA256,
		}
	}
	return &Transfer{
		TransferID: t.TransferID, Source: end("source", t.Source), Destination: end("destination", t.Destination),
		Mode: t.Mode, TTLSeconds: t.SignatureTTLSeconds, SendSHA256: t.SendCommandSHA256, RecvSHA256: t.RecvCommandSHA256,
	}
}

func registerOf(r approvalplan.RegisterTransferKey) *Register {
	return &Register{
		HostFingerprint: neutralizeToken(r.HostFingerprint), Label: neutralizeToken(r.Label),
		BoxPub: neutralizeToken(r.BoxPub), IDPub: neutralizeToken(r.IDPub),
	}
}

// updatePrefix mirrors approvalplan's SSHGATE_UPDATE form.
const updatePrefix = approvalplan.AdminVerbPrefix + "UPDATE "
