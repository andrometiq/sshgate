package policyreview

import (
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// RedactString is the narrow redaction dependency accepted by LiteralPreview.
// Keeping it as input makes the review model independent of process globals and
// gives callers a deterministic failure seam.
type RedactString func(string, [32]byte, []redact.Rule) (string, bool)

// LiteralPreview produces one escaped, bounded display preview. It omits the
// preview on redaction failure, panic, or when redaction changed byte
// cardinality and an exact original hidden-byte count cannot be proven.
func LiteralPreview(literal []byte, maxBytes int, salt [32]byte, rules []redact.Rule, redactString RedactString) (preview string, hidden int, wasRedacted bool, ok bool) {
	if len(literal) == 0 || len(rules) == 0 || maxBytes <= 0 || redactString == nil {
		return "", 0, false, false
	}
	original := string(literal)
	redacted, redactOK := safeRedactString(redactString, original, salt, rules)
	if !redactOK {
		return "", 0, false, false
	}
	escaped := EscapeBytes([]byte(redacted))
	changed := redacted != original
	if len(escaped) <= maxBytes {
		if !changed {
			return escaped, 0, false, true
		}
		hidden, exact := redact.ExactRedactedBytes(original, salt, rules, redacted)
		if !exact {
			return "", 0, true, false
		}
		return escaped, hidden, true, true
	}
	if changed {
		return "", 0, true, false
	}
	var builder strings.Builder
	consumed := 0
	for consumed < len(literal) {
		piece := EscapeBytes(literal[consumed : consumed+1])
		if builder.Len()+len(piece) > maxBytes {
			break
		}
		builder.WriteString(piece)
		consumed++
	}
	if consumed == 0 {
		return "", 0, false, false
	}
	return builder.String(), len(literal) - consumed, false, true
}

// EscapeBytes renders display bytes without control characters or ambiguous
// backslashes.
func EscapeBytes(raw []byte) string {
	var builder strings.Builder
	for _, character := range raw {
		switch {
		case character >= 0x20 && character <= 0x7e && character != '\\':
			builder.WriteByte(character)
		case character == '\\':
			builder.WriteString(`\\`)
		default:
			fmt.Fprintf(&builder, `\x%02x`, character)
		}
	}
	return builder.String()
}

func safeRedactString(redactString RedactString, value string, salt [32]byte, rules []redact.Rule) (redacted string, ok bool) {
	defer func() {
		if recover() != nil {
			redacted = ""
			ok = false
		}
	}()
	return redactString(value, salt, rules)
}
