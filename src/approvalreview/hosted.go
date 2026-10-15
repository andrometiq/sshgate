package approvalreview

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Renderer-authored labels and lines. The approvalplan labels are the
// contract's; these are this renderer's.
const (
	LabelRoute         = "Route (requester's registry; signer-unverified)"
	LabelExactCommand  = "Exact command (no hidden bytes)"
	LabelExactValue    = "Exact value (no hidden bytes)"
	LabelFullyHidden   = "Every byte of this value is hidden by display redaction"
	LabelPathSupplied  = "requester-supplied, signer-validated"
	LabelAIAdvisory    = "AI advisory"
	AlignmentLegacyMsg = "not assessed (legacy request carries no agent reason)"
	ApproveBase        = approvalplan.GlyphCheck + " Approve all displayed commands"
	DenyLabel          = approvalplan.GlyphCross + " Deny"
	// QuotePrefix opens every line that carries requester-, client- or
	// model-controlled text, so no such text ever starts a line.
	QuotePrefix = "│ "
)

// Kind headlines, carried over from the v1 banners (the parity table in
// telegram_test.go).
const (
	headlineReveal = "⚠️ SECRET-REVEAL — output will NOT be redacted; raw secret values go to the agent, the AI provider, and this chat."
	headlineUpdate = "⚠️ GATE BINARY UPDATE — approving this REPLACES the SSHGate gate binary on %s. The new gate governs every future command on this server. Only approve an update you initiated."
	// HeadlineGrantAutoSigns is the v2 grant headline: v2 grants auto-sign.
	HeadlineGrantAutoSigns = "⚠️ STANDING GRANT — approving this auto-signs the commands below for the whole window WITHOUT further taps."
	// HeadlineGrantLegacy replaces the auto-sign headline on a v1 grant,
	// which no longer auto-signs anything (OQ3 (b)).
	HeadlineGrantLegacy = "⚠️ STANDING GRANT — Older client: this grant will not auto-sign. Each write still asks for approval."
	headlineTransfer    = "⚠️ SECRET TRANSFER — approving this MOVES a secret file across hosts. The value is encrypted end-to-end; the agent only relays ciphertext."
	headlineRegister    = "⚠️ XFER-KEY REGISTER — approving this ADDS a box→box transfer trust anchor. These keys let the signer build transfer legs to/from this host. Only approve keys you provisioned."
)

// Assist is the advisory state a card or page shows (K5, K6).
type Assist struct {
	State  approvalplan.AssistState
	Result *approvalplan.AssistResult // set exactly when State is ready
	Reason string                     // the unavailable reason
}

// View is the surface-neutral review both surfaces render: the hosted JSON
// view model, and what the Telegram packer lays out. Every string is either
// renderer-authored or neutralized printable ASCII.
type View struct {
	RequestID    string     `json:"request_id"`
	PlanHash     string     `json:"plan_hash,omitempty"`
	Kind         string     `json:"kind"`
	Legacy       bool       `json:"legacy"`
	Headlines    []string   `json:"headlines,omitempty"`
	Requester    string     `json:"requester"`
	SubmittedAt  string     `json:"submitted_at"`
	ExpiresAt    string     `json:"expires_at"`
	SyncNotice   string     `json:"sync_notice,omitempty"`
	ReasonLabel  string     `json:"reason_label"`
	Reason       string     `json:"reason"`
	Summary      string     `json:"summary"`
	Items        []Item     `json:"items"`
	Assist       AssistView `json:"assist"`
	ApproveLabel string     `json:"approve_label"`
	DenyLabel    string     `json:"deny_label"`
}

// Item is one reviewed unit: a command, a grant, a transfer or a key
// registration. Heading and Notes are single lines; a Note that starts with
// QuotePrefix quotes untrusted text. Text is the value's display (hidden
// spans as approvalplan.HiddenMarker) under TextLabel; Ref and SHA256 name
// it on every continuation chunk.
type Item struct {
	Heading     string   `json:"heading"`
	Notes       []string `json:"notes,omitempty"`
	TextLabel   string   `json:"text_label,omitempty"`
	Text        string   `json:"text,omitempty"`
	Ref         string   `json:"ref,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	HiddenBytes int      `json:"hidden_bytes"`
}

// AssistView is the advisory section, every model string neutralized.
type AssistView struct {
	State     string   `json:"state"`
	Alignment string   `json:"alignment,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Concerns  []string `json:"concerns,omitempty"`
	Effects   []string `json:"effects,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// BuildView renders a snapshot and its advisory state. A ready state needs
// a result that passes approvalplan.ValidateAssist; a legacy record's
// alignment always reads not assessed (K3).
func BuildView(s ReviewSnapshot, assist Assist) (View, error) {
	av, err := assistView(s.Legacy, assist)
	if err != nil {
		return View{}, err
	}
	v := View{
		RequestID: s.RequestID, PlanHash: s.PlanHash, Kind: string(s.Kind), Legacy: s.Legacy,
		Requester: s.Requester, SubmittedAt: stamp(s.SubmittedAt), ExpiresAt: stamp(s.ExpiresAt),
		ReasonLabel: reasonLabel(s.Origin), Reason: renderDisplay(s.Reason),
		Assist: av, ApproveLabel: approveLabel(s), DenyLabel: DenyLabel,
	}
	if s.SyncClaimDeadline != nil {
		v.SyncNotice = "Synchronous request: it runs only if approved while the agent is still waiting (until " + stamp(*s.SyncClaimDeadline) + ")"
	}
	v.Headlines = headlines(s)
	switch {
	case s.Steps != nil:
		v.Items = stepItems(s)
	case s.Grant != nil:
		v.Items = grantItems(*s.Grant)
	case s.Transfer != nil:
		v.Items = transferItems(*s.Transfer)
	case s.Register != nil:
		v.Items = []Item{registerItem(*s.Register)}
	}
	v.Summary = summary(s, v.Items)
	return v, nil
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func reasonLabel(origin approvalplan.RationaleOrigin) string {
	switch origin {
	case approvalplan.OriginAgent:
		return approvalplan.LabelAgentReason
	case approvalplan.OriginTrustedHumanCLI:
		return approvalplan.LabelProgramReason
	}
	return approvalplan.LabelLegacyIntent
}

// renderDisplay joins a display's segments, each hidden span as its marker.
func renderDisplay(d Display) string {
	var b strings.Builder
	for _, seg := range d.Segments {
		if seg.Hidden > 0 {
			b.WriteString(approvalplan.HiddenMarker(seg.Hidden, seg.RuleIDs))
		} else {
			b.WriteString(seg.Text)
		}
	}
	return b.String()
}

// displayLabel is the label a display sits under: K20's whenever a byte is
// hidden in a command, a value label for other displays, and otherwise
// exact, the exact-command or exact-value label.
func displayLabel(d Display, exact string) string {
	switch {
	case d.HiddenBytes > 0:
		if exact == LabelExactValue {
			return "Display-redacted value — hidden bytes are not shown"
		}
		return approvalplan.LabelRedactedDisplay
	}
	return exact
}

func headlines(s ReviewSnapshot) []string {
	var out []string
	for _, step := range s.Steps {
		switch {
		case step.IsUpdate:
			out = append(out, fmt.Sprintf(headlineUpdate, step.Target.Alias))
		case step.Route == approvalplan.RouteSignedReveal && !slices.Contains(out, headlineReveal):
			out = append(out, headlineReveal)
		}
	}
	switch {
	case s.Grant != nil && s.Grant.AutoSigns:
		out = append(out, HeadlineGrantAutoSigns)
	case s.Grant != nil:
		out = append(out, HeadlineGrantLegacy)
	case s.Transfer != nil:
		out = append(out, headlineTransfer)
	case s.Register != nil:
		out = append(out, headlineRegister)
	}
	return out
}

// approveLabel is E46's: a kind-specific variant of "Approve all displayed
// commands", so the operator cannot tap through on muscle memory.
func approveLabel(s ReviewSnapshot) string {
	for _, step := range s.Steps {
		if step.IsUpdate {
			return ApproveBase + " (GATE UPDATE)"
		}
		if step.Route == approvalplan.RouteSignedReveal {
			return ApproveBase + " (SECRET-REVEAL)"
		}
	}
	switch {
	case s.Grant != nil:
		return ApproveBase + " (STANDING GRANT)"
	case s.Transfer != nil:
		return ApproveBase + " (SECRET TRANSFER)"
	case s.Register != nil:
		return ApproveBase + " (XFER-KEY REGISTER)"
	}
	return ApproveBase
}

func summary(s ReviewSnapshot, items []Item) string {
	hidden := 0
	for _, it := range items {
		hidden += it.HiddenBytes
	}
	what, byteScope := "", "command"
	switch {
	case s.Steps != nil:
		signed := 0
		for _, step := range s.Steps {
			if step.Route.Signed() {
				signed++
			}
		}
		what = fmt.Sprintf("%d command(s): %d signed, %d unsigned read(s)", len(s.Steps), signed, len(s.Steps)-signed)
	case s.Grant != nil:
		what = fmt.Sprintf("standing grant with %d listed command(s)", len(s.Grant.Commands))
	case s.Transfer != nil:
		what, byteScope = "one transfer (two signed legs)", "path"
	default:
		return "one transfer-key registration"
	}
	if hidden == 0 {
		return what + "; no " + byteScope + " bytes hidden"
	}
	return fmt.Sprintf("%s; %d %s byte(s) hidden by display redaction", what, hidden, byteScope)
}

func displayItem(heading, ref, exact string, notes []string, d Display) Item {
	if d.FullyHidden {
		notes = append(notes, LabelFullyHidden)
	}
	return Item{
		Heading: heading, Notes: notes, TextLabel: displayLabel(d, exact), Text: renderDisplay(d),
		Ref: ref, SHA256: d.SHA256, HiddenBytes: d.HiddenBytes,
	}
}

func routeText(r Route) string {
	var b strings.Builder
	b.WriteString(r.Alias)
	if r.Host != "" {
		fmt.Fprintf(&b, " → %s@%s:%d", r.User, r.Host, r.Port)
	}
	if r.Fingerprint != "" {
		b.WriteString(" fp=" + r.Fingerprint)
	}
	return b.String()
}

func stepItems(s ReviewSnapshot) []Item {
	items := make([]Item, len(s.Steps))
	for i, step := range s.Steps {
		ttl := "unsigned"
		if step.Route.Signed() {
			ttl = "ttl=" + strconv.Itoa(step.TTLSeconds) + "s"
		}
		heading := fmt.Sprintf("Command %d/%d [%s] %s sha256=%s",
			step.Ordinal, len(s.Steps), step.Route, ttl, step.Command.SHA256)
		notes := []string{LabelRoute, routeText(step.Target)}
		if step.IsUpdate {
			hash := step.UpdateSHA256
			if hash == "" {
				hash = "<malformed hash — the gate will reject this update>"
			}
			notes = append(notes, "New gate SHA-256 (from the signed command bytes): "+hash)
		}
		if b := step.Build; b != nil {
			notes = append(notes, approvalplan.LabelBuildMetadataClient+":",
				fmt.Sprintf("%sstaged_basename=%s staged_version=%s running_version=%s size=%d",
					QuotePrefix, renderDisplay(b.StagedBasename), renderDisplay(b.StagedVersion), renderDisplay(b.RunningVersion), b.Size))
		}
		if r := step.LegacyReason; r != nil {
			label := approvalplan.LabelRevealJustification
			if step.IsUpdate {
				label = approvalplan.LabelBuildMetadataV1
			}
			notes = append(notes, label+":", QuotePrefix+renderDisplay(*r))
		}
		if step.ExpiryWarning {
			notes = append(notes, fmt.Sprintf("⚠️ Step %d is signed and runs after earlier work; its signature may expire before it starts.", step.Ordinal))
		}
		items[i] = displayItem(heading, "command "+strconv.Itoa(step.Ordinal), LabelExactCommand, notes, step.Command)
	}
	return items
}

func grantItems(g Grant) []Item {
	head := Item{Heading: "Standing grant on " + g.Alias, Notes: []string{LabelRoute}}
	if g.Fingerprint != "" {
		head.Notes = append(head.Notes, "Host fingerprint: "+g.Fingerprint)
	}
	switch g.Scope {
	case string(approvalplan.GrantScopeAll):
		head.Notes = append(head.Notes, "Scope: ALL commands on "+g.Alias)
	case string(approvalplan.GrantScopeCommands):
		head.Notes = append(head.Notes, fmt.Sprintf("Scope: ONLY the %d exact command(s) below", len(g.Commands)))
	default:
		head.Notes = append(head.Notes, "Scope: "+g.Scope)
	}
	duration := time.Duration(g.DurationSeconds) * time.Second
	head.Notes = append(head.Notes, fmt.Sprintf("Duration: %s (%d s), counted from approval", duration, g.DurationSeconds))
	items := []Item{head}
	for i, c := range g.Commands {
		heading := fmt.Sprintf("Grant command %d/%d sha256=%s", i+1, len(g.Commands), c.SHA256)
		items = append(items, displayItem(heading, "grant command "+strconv.Itoa(i+1), LabelExactCommand, nil, c))
	}
	return items
}

func transferItems(t Transfer) []Item {
	endNotes := func(dir string, e TransferEnd) []string {
		notes := []string{fmt.Sprintf("%s: key %s (signer registry)", dir, e.Label), dir + " fingerprint (" + LabelPathSupplied + "): " + e.Fingerprint}
		if e.Target != nil {
			notes = append(notes, fmt.Sprintf("%s route %s: %s", dir, strings.TrimPrefix(LabelRoute, "Route "), routeText(*e.Target)))
		}
		if e.PublicKeySHA256 != "" {
			notes = append(notes, dir+" public key sha256="+e.PublicKeySHA256)
		}
		return notes
	}
	head := Item{Heading: "Secret transfer " + t.TransferID, Notes: append(endNotes("From", t.Source), endNotes("To", t.Destination)...)}
	head.Notes = append(head.Notes, "Mode: "+t.Mode)
	if t.SendSHA256 != "" {
		head.Notes = append(head.Notes,
			fmt.Sprintf("Signed SEND leg sha256=%s ttl=%ds (signer-built)", t.SendSHA256, t.TTLSeconds),
			fmt.Sprintf("Signed RECV leg sha256=%s ttl=%ds (signer-built)", t.RecvSHA256, t.TTLSeconds))
	}
	return []Item{
		head,
		displayItem("Source path ("+LabelPathSupplied+")", "source path", LabelExactValue, nil, t.Source.Path),
		displayItem("Destination path ("+LabelPathSupplied+")", "destination path", LabelExactValue, nil, t.Destination.Path),
	}
}

func registerItem(r Register) Item {
	return Item{Heading: "Transfer-key registration", Notes: []string{
		fmt.Sprintf("Host: %s fp=%s", r.Label, r.HostFingerprint),
		"Box key: " + r.BoxPub,
		"ID key: " + r.IDPub,
	}}
}

func assistView(legacy bool, a Assist) (AssistView, error) {
	v := AssistView{State: string(a.State)}
	switch a.State {
	case approvalplan.AssistPreparing:
		if a.Result != nil || a.Reason != "" {
			return AssistView{}, fmt.Errorf("approvalreview: a preparing assist carries no result or reason")
		}
	case approvalplan.AssistUnavailable:
		if a.Result != nil {
			return AssistView{}, fmt.Errorf("approvalreview: an unavailable assist carries no result")
		}
		v.Reason = NeutralizeText(a.Reason)
	case approvalplan.AssistReady:
		if a.Result == nil {
			return AssistView{}, fmt.Errorf("approvalreview: a ready assist needs its result")
		}
		if err := approvalplan.ValidateAssist(*a.Result); err != nil {
			return AssistView{}, err
		}
		readyView(&v, legacy, *a.Result)
	default:
		return AssistView{}, fmt.Errorf("approvalreview: assist state %q has no review rendering", a.State)
	}
	return v, nil
}

// readyView orders concerns by severity, high first, keeping the model's
// order within one severity.
func readyView(v *AssistView, legacy bool, r approvalplan.AssistResult) {
	v.Alignment = string(r.Alignment)
	if legacy {
		v.Alignment = AlignmentLegacyMsg
	} else if r.Alignment == approvalplan.AlignmentNotAssessed {
		v.Alignment = "not assessed"
	}
	v.Summary = NeutralizeText(r.Summary)
	for _, severity := range []approvalplan.Severity{approvalplan.SeverityHigh, approvalplan.SeverityCaution, approvalplan.SeverityInfo} {
		for _, c := range r.Concerns {
			if c.Severity == severity {
				v.Concerns = append(v.Concerns, "["+string(severity)+"] "+NeutralizeText(c.Text))
			}
		}
	}
	for _, e := range r.Effects {
		v.Effects = append(v.Effects, NeutralizeText(e))
	}
}
