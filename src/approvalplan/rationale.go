package approvalplan

import (
	"strings"
	"unicode/utf8"
)

// MaxRationaleBytes is K2's upper bound on a trimmed reason.
const MaxRationaleBytes = 500

// Labels that surfaces render verbatim. They are part of the contract: an
// operator learns to read them, so a change is a named change.
const (
	// LabelAgentReason labels a v2 reason (K4).
	LabelAgentReason = "Agent-stated reason (unverified)"
	// LabelLegacyIntent labels LegacyRationaleText on a frozen v1 request (K3).
	LabelLegacyIntent = "Protocol-generated legacy intent (unverified; client supplied no reason)"
	// LegacyRationaleText is the reason the signer stores for a frozen v1
	// request, which carries none (K3).
	LegacyRationaleText = "Legacy v1 request (reason unavailable)"
	// LabelRedactedDisplay is shown wherever a command display hides bytes (K20).
	LabelRedactedDisplay = "Display-redacted command — signature covers undisplayed original bytes"
	// LabelRedactedNoCount marks a legacy display whose hidden-byte count is
	// unavailable (E16).
	LabelRedactedNoCount = "Display-redacted command — hidden-byte count unavailable"
	// LabelRevealJustification labels the v1 per-command reason on a reveal
	// step (E8c).
	LabelRevealJustification = "Reveal justification (agent-stated, unverified, legacy per-command field)"
	// LabelBuildMetadataV1 labels the v1 per-command reason on an
	// SSHGATE_UPDATE step (E8c).
	LabelBuildMetadataV1 = "Build metadata (v1 client-supplied)"
	// LabelBuildMetadataClient labels every v2 trusted_display field (E33).
	LabelBuildMetadataClient = "Build metadata (client-supplied, signer-unverified)"
	// CLIRationaleText is the program-generated reason of a sshgate CLI
	// transfer-key enrollment (E39).
	CLIRationaleText = "Transfer-key enrollment requested via sshgate CLI"
	// LabelProgramReason labels CLIRationaleText (E39).
	LabelProgramReason = "Program-generated reason (sshgate CLI; requester not authenticated as human)"
)

// ValidateRationale applies K2 to a requester's reason. It trims surrounding
// whitespace, then requires 1..500 bytes of valid UTF-8 on a single line with
// no C0 or C1 control, DEL, bidi control (U+061C, U+200E, U+200F,
// U+202A-U+202E, U+2066-U+2069) or line separator (U+2028, U+2029). It returns
// the trimmed reason.
func ValidateRationale(s string) (string, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", invalid("reason", "is required (1..%d bytes)", MaxRationaleBytes)
	}
	if len(t) > MaxRationaleBytes {
		return "", codeErr(CodeInvalidRequest, "reason", "is %d bytes; maximum is %d", len(t), MaxRationaleBytes)
	}
	if err := checkText(t); err != nil {
		return "", invalid("reason", "%s", err.Msg)
	}
	return t, nil
}

// forbiddenRune reports whether r may not appear in requester- or
// model-controlled text: C0 and C1 controls, DEL, bidi controls and the
// Unicode line and paragraph separators.
func forbiddenRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	}
	return false
}

// checkText requires valid UTF-8 with no forbidden rune.
func checkText(s string) *CodeError {
	if !utf8.ValidString(s) {
		return invalid("", "is not valid UTF-8")
	}
	for i, r := range s {
		if forbiddenRune(r) {
			return invalid("", "contains forbidden character U+%04X at byte %d", r, i)
		}
	}
	return nil
}

// validText checks one bounded text field, naming it on failure.
func validText(field, s string, minBytes, maxBytes int) error {
	if len(s) < minBytes || len(s) > maxBytes {
		return invalid(field, "is %d bytes; must be %d..%d", len(s), minBytes, maxBytes)
	}
	if err := checkText(s); err != nil {
		return invalid(field, "%s", err.Msg)
	}
	return nil
}
