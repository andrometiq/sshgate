//go:build linux

package gate_test

import (
	"context"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// TestExecWithRedaction_Reveal pins the SECRET-REVEAL executor seam: with a
// non-empty ruleset configured, ExecOpts.Reveal=true runs the command output
// RAW (no redaction), while Reveal=false keeps the existing redacting
// behaviour. Reveal is a SEPARATE field from "Rules is empty": the rules are
// present in both subtests; only the explicit per-command Reveal flag changes
// whether the redactor is wired in.
func TestExecWithRedaction_Reveal(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	rules := redactrules.Combined()
	const secret = "AKIA1234567890ABCDEF" // an AWS access key the ruleset catches

	t.Run("Reveal=true with rules present -> NOT redacted (raw secret flows)", func(t *testing.T) {
		out := captureStdout(t, func() {
			_, err := gate.ExecWithRedaction(context.Background(), "echo "+secret, gate.ExecOpts{
				SessionSalt: salt,
				Rules:       rules,
				Reveal:      true,
			})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if !strings.Contains(out, secret) {
			t.Errorf("reveal=true must pass the raw secret through; got %q", out)
		}
		if strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("reveal=true wrongly emitted a redaction marker: %q", out)
		}
	})

	t.Run("Reveal=false with rules present -> redacted (existing behaviour preserved)", func(t *testing.T) {
		out := captureStdout(t, func() {
			_, err := gate.ExecWithRedaction(context.Background(), "echo "+secret, gate.ExecOpts{
				SessionSalt: salt,
				Rules:       rules,
				Reveal:      false,
			})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if strings.Contains(out, secret) {
			t.Errorf("reveal=false must redact the secret; it leaked: %q", out)
		}
		if !strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("reveal=false should emit a redaction marker; got %q", out)
		}
	})
}
