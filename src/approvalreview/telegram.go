package approvalreview

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Telegram bounds (K19, E45), the policy review's (telegram_policy_review.go:18-22).
const (
	// PartBytes bounds every part and the decision card; each is strictly
	// smaller. Telegram counts UTF-16 units; the text is ASCII apart from a
	// few renderer glyphs, so bytes over-count and the bound is conservative.
	PartBytes = 3900
	// MaxMessages counts the parts and the decision card.
	MaxMessages = 40
	// MaxReviewBytes bounds the parts plus the decision card.
	MaxReviewBytes = 128 << 10
	// chunkTextBytes bounds one chunk of a value's display, leaving room in
	// its part for the headers, notes and labels of its item.
	chunkTextBytes = 2800
)

const (
	partTitle = "🔐 SSHGate approval review — PART %d/%d"
	cardTitle = "🔐 SSHGate approval — DECISION CARD"
)

// PackParts lays a view out as the numbered review parts sent before the
// decision card (K19): each part carries the request ID, the card handle,
// part i/N and the plan-hash prefix, and no Approve. A display longer than
// one chunk is split into chunks that each repeat its reference and SHA-256.
// A review over the bounds is request_unrenderable.
func PackParts(v View, handle string) ([]string, error) {
	if !approvalplan.ValidCardHandle(handle) {
		return nil, fmt.Errorf("approvalreview: invalid card handle %q", handle)
	}
	blocks := []string{requestBlock(v)}
	for _, it := range v.Items {
		blocks = append(blocks, itemBlocks(it)...)
	}
	identity := fmt.Sprintf("Request: %s · Card: %s · Plan: %s", v.RequestID, handle, planPrefix(v))
	budget := PartBytes - 1 - len(fmt.Sprintf(partTitle, MaxMessages, MaxMessages)) - 1 - len(identity) - 1
	bodies, err := packBodies(blocks, budget)
	if err != nil {
		return nil, err
	}
	if len(bodies)+1 > MaxMessages {
		return nil, unrenderable("telegram", "the review needs %d parts; at most %d fit with the decision card", len(bodies), MaxMessages-1)
	}
	parts := make([]string, len(bodies))
	total := 0
	for i, body := range bodies {
		parts[i] = fmt.Sprintf(partTitle, i+1, len(bodies)) + "\n" + identity + "\n" + body
		total += len(parts[i])
	}
	if total+PartBytes > MaxReviewBytes {
		return nil, unrenderable("telegram", "the review is %d bytes; at most %d fit with the decision card", total, MaxReviewBytes-PartBytes)
	}
	return parts, nil
}

func planPrefix(v View) string {
	if v.PlanHash == "" {
		return "none (legacy v1 request)"
	}
	return v.PlanHash[:16]
}

func requestBlock(v View) string {
	lines := append([]string(nil), v.Headlines...)
	lines = append(lines, "Requester: "+v.Requester, "Submitted: "+v.SubmittedAt, "Expires: "+v.ExpiresAt)
	if v.SyncNotice != "" {
		lines = append(lines, v.SyncNotice)
	}
	lines = append(lines, "Contents: "+v.Summary, v.ReasonLabel+":", QuotePrefix+v.Reason)
	return strings.Join(lines, "\n")
}

// itemBlocks is one block per chunk of the item's display.
func itemBlocks(it Item) []string {
	head := append([]string{it.Heading}, it.Notes...)
	if it.TextLabel == "" {
		return []string{strings.Join(head, "\n")}
	}
	chunks := chunkDisplay(it.Text, chunkTextBytes)
	if len(chunks) == 1 {
		return []string{strings.Join(append(head, it.TextLabel+":", QuotePrefix+it.Text), "\n")}
	}
	sha := ""
	if it.SHA256 != "" {
		sha = " sha256=" + it.SHA256
	}
	blocks := make([]string, len(chunks))
	for j, chunk := range chunks {
		chunkLine := fmt.Sprintf("↳ %s, chunk %d/%d%s", it.Ref, j+1, len(chunks), sha)
		lines := []string{chunkLine, it.TextLabel + ":", QuotePrefix + chunk}
		if j == 0 {
			lines = append(head, lines...)
		}
		blocks[j] = strings.Join(lines, "\n")
	}
	return blocks
}

// chunkDisplay splits a rendered display into chunks of at most max bytes,
// never inside an escape sequence or a hidden-span marker.
func chunkDisplay(text string, max int) []string {
	var chunks []string
	start := 0
	for i := 0; i < len(text); {
		n := tokenLen(text[i:])
		if i+n-start > max && i > start {
			chunks = append(chunks, text[start:i])
			start = i
		}
		i += n
	}
	return append(chunks, text[start:])
}

// tokenLen is the length of the display token at the start of s: an escape
// (`\\`, `\xNN`, `\u{X…}`), a hidden-span marker, or one character.
func tokenLen(s string) int {
	switch {
	case strings.HasPrefix(s, `\\`):
		return 2
	case strings.HasPrefix(s, `\x`) && len(s) >= 4:
		return 4
	case strings.HasPrefix(s, `\u{`):
		if end := strings.IndexByte(s, '}'); end > 0 {
			return end + 1
		}
	case strings.HasPrefix(s, approvalplan.GlyphHiddenOpen):
		if end := strings.Index(s, approvalplan.GlyphHiddenClose); end > 0 {
			return end + len(approvalplan.GlyphHiddenClose)
		}
	}
	_, size := utf8.DecodeRuneInString(s)
	return size
}

func packBodies(blocks []string, budget int) ([]string, error) {
	var bodies []string
	var current strings.Builder
	for _, block := range blocks {
		if len(block) > budget {
			return nil, unrenderable("telegram", "a review block of %d bytes exceeds one part", len(block))
		}
		if current.Len() > 0 && current.Len()+2+len(block) > budget {
			bodies = append(bodies, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteString("\n\n")
		}
		current.WriteString(block)
	}
	return append(bodies, current.String()), nil
}

// DecisionCard renders the card sent after every part was accepted (K19):
// the full plan hash, the card handle and the advisory state. Advisory text
// fills what is left of one part, in the order alignment, summary, concerns
// by severity, effects; whatever does not fit is counted in an explicit
// omission notice. The buttons (View.ApproveLabel, View.DenyLabel) are the
// notifier's; a preparing card carries Deny only (K6).
func DecisionCard(v View, handle string, parts int) (string, error) {
	if !approvalplan.ValidCardHandle(handle) {
		return "", fmt.Errorf("approvalreview: invalid card handle %q", handle)
	}
	lines := append([]string(nil), v.Headlines...)
	lines = append(lines, cardTitle,
		fmt.Sprintf("Review the %d numbered part(s) above before deciding; Approve covers every displayed command.", parts),
		"Request: "+v.RequestID+" · Card: "+handle)
	if v.PlanHash != "" {
		lines = append(lines, "Plan hash: "+v.PlanHash)
	} else {
		lines = append(lines, "Plan hash: none (legacy v1 request)")
	}
	lines = append(lines, "Requester: "+v.Requester, "Submitted: "+v.SubmittedAt, "Expires: "+v.ExpiresAt)
	if v.SyncNotice != "" {
		lines = append(lines, v.SyncNotice)
	}
	lines = append(lines, "Contents: "+v.Summary)
	card := strings.Join(append(lines, assistHead(v.Assist)...), "\n")
	if len(card) >= PartBytes {
		return "", unrenderable("telegram", "the decision card is %d bytes; it must be under %d", len(card), PartBytes)
	}
	if v.Assist.State != string(approvalplan.AssistReady) {
		return card, nil
	}
	return card + advisoryLines(v.Assist, PartBytes-1-len(card)), nil
}

func assistHead(a AssistView) []string {
	switch a.State {
	case string(approvalplan.AssistPreparing):
		return []string{LabelAIAdvisory + ": preparing. Approve appears once it is ready or unavailable."}
	case string(approvalplan.AssistUnavailable):
		return []string{LabelAIAdvisory + ": unavailable. Approve on your own review. Reason:", QuotePrefix + a.Reason}
	}
	return []string{LabelAIAdvisory + " (model output; unverified, not a check):", "Alignment: " + a.Alignment}
}

// advisoryLines adds the ready advisory's units in priority order while they
// fit in budget bytes, reserving room for the omission notice.
func advisoryLines(a AssistView, budget int) string {
	type unit struct{ section, line string }
	var units []unit
	units = append(units, unit{"Summary:", QuotePrefix + a.Summary})
	for _, c := range a.Concerns {
		units = append(units, unit{"Concerns (by severity):", QuotePrefix + c})
	}
	for i, e := range a.Effects {
		units = append(units, unit{"Effects:", fmt.Sprintf("%s%d. %s", QuotePrefix, i+1, e)})
	}
	const omissionReserve = 120
	var b strings.Builder
	section, omitted := "", 0
	for _, u := range units {
		add := "\n" + u.line
		if u.section != section {
			add = "\n" + u.section + add
		}
		if omitted > 0 || b.Len()+len(add) > budget-omissionReserve {
			omitted++
			continue
		}
		b.WriteString(add)
		section = u.section
	}
	if omitted > 0 {
		fmt.Fprintf(&b, "\n… %d advisory item(s) omitted to fit this card.", omitted)
	}
	return b.String()
}

// boundsHandle stands in for the card handle when a snapshot's review is
// measured at freeze; every handle has the same length.
const boundsHandle = "aaaaaaaaaaaa"

// checkTelegramBounds proves the snapshot's review fits Telegram's bounds.
func (s ReviewSnapshot) checkTelegramBounds() error {
	v, err := BuildView(s, Assist{State: approvalplan.AssistPreparing})
	if err != nil {
		return err
	}
	parts, err := PackParts(v, boundsHandle)
	if err != nil {
		return err
	}
	_, err = DecisionCard(v, boundsHandle, len(parts))
	return err
}
