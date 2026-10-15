package approvalreview

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/src/policyreview"
)

// NeutralizeText renders agent-, client- or model-controlled text as
// printable ASCII (E65): printable ASCII stays as is, a backslash becomes
// `\\`, an ASCII control or an invalid UTF-8 byte becomes `\xNN` as
// policyreview.EscapeBytes writes it, and every non-ASCII code point becomes
// a visible `\u{XXXX}`. No renderer glyph, bidi control, zero-width or
// confusable character survives it, and it never yields a line break.
func NeutralizeText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1, r < utf8.RuneSelf:
			b.WriteString(policyreview.EscapeBytes([]byte{s[i]}))
		default:
			fmt.Fprintf(&b, `\u{%04X}`, r)
		}
		i += size
	}
	return b.String()
}

// neutralizeToken is NeutralizeText with spaces shown as `\x20`, for an
// untrusted value printed inline on a renderer line: it can then never carry
// a phrase that a line wrap could present as a renderer line.
func neutralizeToken(s string) string {
	return strings.ReplaceAll(NeutralizeText(s), " ", `\x20`)
}

// escapeCommand renders exact command bytes: EscapeBytes, so every byte
// outside printable ASCII shows as `\xNN` and the display maps back to the
// signed bytes one to one.
func escapeCommand(s string) string {
	return policyreview.EscapeBytes([]byte(s))
}

// isPrintableASCII reports whether s holds only bytes 0x20..0x7e.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
