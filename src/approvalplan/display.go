package approvalplan

import (
	"slices"
	"strconv"
	"strings"
)

// Renderer glyphs. Only renderer-authored text may contain them: every
// requester- or model-controlled string is neutralized first (E65).
const (
	GlyphHiddenOpen  = "⟦"
	GlyphHiddenClose = "⟧"
	GlyphCheck       = "✓"
	GlyphCross       = "✗"
)

// HiddenMarker is the one rendering of a hidden span, shared by the approval
// cards and the assist provider input so both show the same text and the
// assist InputDigest hashes it: "⟦hidden N bytes · rule-a,rule-b⟧", rule IDs
// sorted and de-duplicated, and "⟦hidden N bytes⟧" when there are none.
func HiddenMarker(n int, ruleIDs []string) string {
	var b strings.Builder
	b.WriteString(GlyphHiddenOpen + "hidden " + strconv.Itoa(n) + " bytes")
	ids := slices.Compact(slices.Sorted(slices.Values(ruleIDs)))
	if len(ids) > 0 {
		b.WriteString(" · " + strings.Join(ids, ","))
	}
	b.WriteString(GlyphHiddenClose)
	return b.String()
}
