package approvalplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// LegacyNetBannerFormat is P4.3's network banner (#22, the READ WITH NETWORK
// card), byte for byte; %[1]s is the target alias.
const LegacyNetBannerFormat = "🌐 READ WITH NETWORK on %[1]s: may connect anywhere, including services on %[1]s itself that can change state."

// LabelNetworkJustification labels the v1 per-command reason of a network read,
// as LabelRevealJustification does for a reveal.
const LabelNetworkJustification = "Network justification (agent-stated, unverified, legacy per-command field)"

// NetworkBanner renders LegacyNetBannerFormat for alias (already neutralised by the caller).
func NetworkBanner(alias string) string {
	return fmt.Sprintf(LegacyNetBannerFormat, alias)
}

// LegacySignInput is the exact signing input of one command of a frozen v1
// sign request: what the signer will sign, and what the card must show.
type LegacySignInput struct {
	Server          string `json:"server"`
	HostFingerprint string `json:"host_fingerprint"`
	Command         string `json:"command"`        // exact bytes
	CommandSHA256   string `json:"command_sha256"` // lowercase hex of Command
	TTLSeconds      int64  `json:"ttl_seconds"`
	Reveal          bool   `json:"reveal,omitempty"`
	Net             bool   `json:"net,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// LegacySignDigest binds one request instance to its inputs: SHA-256 over
// "sshgate-legacy-sign-v1\x00" || Canonical({instance, inputs}). In memory
// only; never journaled. It refuses (empty string, false) an input whose
// CommandSHA256 is not the hash of its Command.
func LegacySignDigest(instance string, in []LegacySignInput) (string, bool) {
	for _, input := range in {
		sum := sha256.Sum256([]byte(input.Command))
		if input.CommandSHA256 != hex.EncodeToString(sum[:]) {
			return "", false
		}
	}
	digest, err := canonicalHash("sshgate-legacy-sign-v1\x00", struct {
		Instance string            `json:"instance"`
		Inputs   []LegacySignInput `json:"inputs"`
	}{instance, in})
	return digest, err == nil
}

// ValidateLegacyNet checks the structure of a legacy network request. The caller
// must already have classified the command as a read. Every refusal is an
// invalid_request at commands[i].net; the legacy reason has no length cap.
func ValidateLegacyNet(n, i int, command, reason string) error {
	field := fmt.Sprintf("commands[%d].net", i)
	if n != 1 {
		return invalid(field, "network requires a single-command request")
	}
	if err := validCommandBytes(field, command, MaxStepBytes); err != nil {
		return invalid(field, "%s", err.(*CodeError).Msg)
	}
	if strings.HasPrefix(command, AdminVerbPrefix) {
		return invalid(field, "network is not allowed on an SSHGATE_ command")
	}
	if strings.TrimSpace(reason) == "" || !utf8.ValidString(reason) {
		return invalid(field, "reason must be non-empty, non-whitespace and valid UTF-8")
	}
	return nil
}
