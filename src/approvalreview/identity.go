package approvalreview

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// Identity fields cannot be partially hidden without changing what is approved.
func (b *builder) identity(field, value string) string {
	result, ok := safeRedactSpans(value, b.salt, b.rules)
	if !ok || !spansWellFormed(value, result) || len(result.Spans) > 0 {
		b.fail(unrenderable(field, "identity cannot be displayed safely"))
		return ""
	}
	return neutralizeToken(value)
}

func (b *builder) fingerprint(field, value string) string {
	if value == "" {
		return ""
	}
	encoded, hasPrefix := strings.CutPrefix(value, "SHA256:")
	raw, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if !hasPrefix || err != nil || len(raw) != sha256.Size || base64.RawStdEncoding.EncodeToString(raw) != encoded {
		b.fail(unrenderable(field, "invalid public-key fingerprint"))
		return ""
	}
	return value
}

// publicKey identifies the parsed public bytes; only its comment is redacted.
func (b *builder) publicKey(field, value string, boxKey bool) string {
	fields := strings.SplitN(value, " ", 3)
	if len(fields) < 2 {
		b.fail(unrenderable(field, "invalid public key"))
		return ""
	}
	line := fields[0] + " " + fields[1]
	var raw []byte
	var err error
	if boxKey {
		var key *[32]byte
		key, err = xfer.ParseBoxPublicText(line)
		if err == nil {
			raw = key[:]
		}
	} else {
		raw, err = xfer.ParseIDPublicText(line)
	}
	if err != nil {
		b.fail(unrenderable(field, "invalid transfer public key"))
		return ""
	}
	sum := sha256.Sum256(raw)
	identity := fields[0] + " SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if len(fields) == 3 {
		identity += " comment="
		for _, segment := range b.display(field+".comment", fields[2], neutralizeToken).Segments {
			if segment.Hidden > 0 {
				identity += NeutralizeText(approvalplan.HiddenMarker(segment.Hidden, segment.RuleIDs))
			} else {
				identity += segment.Text
			}
		}
	}
	return identity
}
