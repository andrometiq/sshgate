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
)

const (
	partTitle = "🔐 SSHGate approval review — PART %d/%d"
	cardTitle = "🔐 SSHGate approval — DECISION CARD"
)

// PackParts lays a view out as the numbered review parts sent before the
// decision card (K19): each part carries the request ID, the card handle,
// part i/N and the plan-hash prefix, and no Approve. A display longer than
// one chunk is split into chunks that each repeat its reference and SHA-256.
// A review over the bounds is request_too_large.
func PackParts(v View, handle string) ([]string, error) {
	if !approvalplan.ValidCardHandle(handle) {
		return nil, fmt.Errorf("approvalreview: invalid card handle %q", handle)
	}
	identity := fmt.Sprintf("Request: %s · Card: %s · Plan: %s", v.RequestID, handle, planPrefix(v))
	budget := PartBytes - 1 - len(fmt.Sprintf(partTitle, MaxMessages, MaxMessages)) - 1 - len(identity) - 1
	bodies, err := packItems(v, budget)
	if err != nil {
		return nil, err
	}
	if len(bodies)+1 > MaxMessages {
		return nil, tooLarge("telegram", "the review needs %d parts; at most %d fit with the decision card", len(bodies), MaxMessages-1)
	}
	parts := make([]string, len(bodies))
	total := 0
	for i, body := range bodies {
		parts[i] = fmt.Sprintf(partTitle, i+1, len(bodies)) + "\n" + identity + "\n" + body
		total += len(parts[i])
	}
	if total+PartBytes > MaxReviewBytes {
		return nil, tooLarge("telegram", "the review is %d bytes; at most %d fit with the decision card", total, MaxReviewBytes-PartBytes)
	}
	return parts, nil
}

func planPrefix(v View) string {
	if v.PlanHash == "" {
		return "none (legacy v1 request)"
	}
	return v.PlanHash[:min(16, len(v.PlanHash))]
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

// packItems fills remaining space before opening a part. Display tokens are
// indivisible; every split repeats the item reference and original-byte hash.
func packItems(v View, budget int) ([]string, error) {
	bodies := []string{""}
	remaining := func() int {
		n := budget - len(bodies[len(bodies)-1])
		if bodies[len(bodies)-1] != "" {
			n -= 2
		}
		return n
	}
	appendBlock := func(block string) {
		i := len(bodies) - 1
		if bodies[i] != "" {
			bodies[i] += "\n\n"
		}
		bodies[i] += block
	}
	addWhole := func(block string) error {
		if len(block) > budget {
			return tooLarge("telegram", "a review block exceeds one part")
		}
		if len(block) > remaining() {
			bodies = append(bodies, "")
		}
		appendBlock(block)
		return nil
	}
	if err := addWhole(requestBlock(v)); err != nil {
		return nil, err
	}
	for _, it := range v.Items {
		head := strings.Join(append([]string{it.Heading}, it.Notes...), "\n")
		if it.TextLabel == "" {
			if err := addWhole(head); err != nil {
				return nil, err
			}
			continue
		}
		label := it.TextLabel + ":\n" + QuotePrefix
		whole := head + "\n" + label + it.Text
		if len(whole) <= remaining() {
			appendBlock(whole)
			continue
		}
		type piece struct {
			body         int
			prefix, text string
		}
		var pieces []piece
		text := it.Text
		for len(text) > 0 || len(pieces) == 0 {
			prefix := ""
			if len(pieces) == 0 {
				prefix = head + "\n"
			}
			line := fmt.Sprintf("↳ %s, chunk %d/99", it.Ref, len(pieces)+1)
			if it.SHA256 != "" {
				line += " sha256=" + it.SHA256
			}
			prefix += line + "\n" + label
			available := remaining() - len(prefix)
			end := 0
			for end < len(text) {
				n := tokenLen(text[end:])
				if end+n > available {
					break
				}
				end += n
			}
			if available < 0 || (end == 0 && len(text) > 0) {
				if bodies[len(bodies)-1] == "" {
					return nil, tooLarge("telegram", "an item header and display token exceed one part")
				}
				bodies = append(bodies, "")
				continue
			}
			pieces = append(pieces, piece{len(bodies) - 1, prefix, text[:end]})
			// Reserve the full prefix until the chunk count is known.
			appendBlock(prefix + text[:end])
			text = text[end:]
			if len(text) == 0 {
				break
			}
			if len(bodies) >= MaxMessages {
				return nil, tooLarge("telegram", "too many review parts")
			}
			bodies = append(bodies, "")
		}
		for _, p := range pieces {
			old := p.prefix + p.text
			at := strings.LastIndex(p.prefix, ", chunk ")
			prefix := p.prefix[:at] + strings.Replace(p.prefix[at:], "/99", fmt.Sprintf("/%d", len(pieces)), 1)
			// Replace only the just-appended suffix, never supplied text.
			body := bodies[p.body]
			bodies[p.body] = body[:len(body)-len(old)] + prefix + p.text
		}
	}
	return bodies, nil
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

// DecisionCard renders the card sent after every part was accepted (K19):
// the full plan hash, the card handle and the advisory state. Advisory text
// fills what is left of one part, in the order alignment, summary, concerns
// by severity, effects; whatever does not fit is counted in an explicit
// omission notice. The buttons (View.ApproveLabel, View.DenyLabel) are the
// notifier's; a preparing card carries Deny only (K6). The optional partsHandle
// identifies the original review parts when an edit or replacement rotates the handle.
func DecisionCard(v View, handle string, parts int, partsHandle ...string) (string, error) {
	if !approvalplan.ValidCardHandle(handle) {
		return "", fmt.Errorf("approvalreview: invalid card handle %q", handle)
	}
	lines := append([]string(nil), v.Headlines...)
	lines = append(lines, cardTitle,
		fmt.Sprintf("Review the %d numbered part(s) above before deciding; Approve covers every displayed command.", parts),
		"Request: "+v.RequestID+" · Card: "+handle)
	if len(partsHandle) > 1 || (len(partsHandle) == 1 && !approvalplan.ValidCardHandle(partsHandle[0])) {
		return "", fmt.Errorf("approvalreview: invalid review parts handle")
	}
	if len(partsHandle) == 1 && partsHandle[0] != handle {
		lines = append(lines, "Review parts were sent under card "+partsHandle[0])
	}
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
	if v.Assist.State == string(approvalplan.AssistUnavailable) && len(card) >= PartBytes {
		a := v.Assist
		a.Reason = "[advisory reason omitted to fit this card]"
		card = strings.Join(append(lines, assistHead(a)...), "\n")
	}
	if len(card) >= PartBytes {
		return "", tooLarge("telegram", "the decision card is %d bytes; it must be under %d", len(card), PartBytes)
	}
	if v.Assist.State != string(approvalplan.AssistReady) {
		return card, nil
	}
	card += advisoryLines(v.Assist, PartBytes-1-len(card))
	if len(card) >= PartBytes {
		return "", tooLarge("telegram", "the decision card including its omission notice exceeds one part")
	}
	return card, nil
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
	if _, err := DecisionCard(v, boundsHandle, len(parts)); err != nil {
		return err
	}
	// Reserve the longest alignment and the maximum omission count.
	alignment := "not assessed"
	if s.Legacy {
		alignment = AlignmentLegacyMsg
	}
	v.Assist = AssistView{State: string(approvalplan.AssistReady), Alignment: alignment,
		Summary: strings.Repeat("x", PartBytes), Concerns: make([]string, approvalplan.MaxAssistConcerns), Effects: make([]string, approvalplan.MaxAssistEffects)}
	if _, err := DecisionCard(v, boundsHandle, len(parts)); err != nil {
		return err
	}
	v.Assist = AssistView{State: string(approvalplan.AssistUnavailable), Reason: strings.Repeat("x", PartBytes)}
	_, err = DecisionCard(v, boundsHandle, len(parts))
	return err
}

func tooLarge(field, format string, args ...any) error {
	return &approvalplan.CodeError{Code: approvalplan.CodeRequestTooLarge, Field: field, Msg: fmt.Sprintf(format, args...) + "; split into smaller requests"}
}
