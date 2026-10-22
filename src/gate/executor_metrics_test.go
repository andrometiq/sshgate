//go:build linux

package gate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// TestExecResultMetrics pins the widened ExecWithRedaction return: in
// addition to the exit code it now reports output metadata (bytes on
// stdout/stderr, line count, and a non-zero wall-clock duration) so the
// gate-side audit log can record metrics WITHOUT capturing raw output.
//
// The counts are measured at the bytes that actually reach the SSH
// stream (post-redaction), which is exactly what the agent receives —
// the meaningful thing to audit.
func TestExecResultMetrics(t *testing.T) {
	t.Run("stdout bytes and lines are counted", func(t *testing.T) {
		var res gate.ExecResult
		var err error
		out := captureStdout(t, func() {
			res, err = gate.ExecWithRedaction(context.Background(), "printf 'a\\nbb\\nccc\\n'", gate.ExecOpts{})
		})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if res.ExitCode != 0 {
			t.Errorf("exit = %d, want 0", res.ExitCode)
		}
		// "a\nbb\nccc\n" = 1+1 + 2+1 + 3+1 = 9 bytes.
		if res.StdoutBytes != 9 {
			t.Errorf("StdoutBytes = %d, want 9 (out=%q)", res.StdoutBytes, out)
		}
		if res.StderrBytes != 0 {
			t.Errorf("StderrBytes = %d, want 0", res.StderrBytes)
		}
		// 3 newlines => 3 lines.
		if res.Lines != 3 {
			t.Errorf("Lines = %d, want 3", res.Lines)
		}
		if res.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", res.Duration)
		}
	})

	t.Run("stderr bytes are counted separately", func(t *testing.T) {
		var res gate.ExecResult
		_ = captureStdout(t, func() {
			res, _ = gate.ExecWithRedaction(context.Background(), "printf 'err' 1>&2", gate.ExecOpts{})
		})
		if res.StderrBytes != 3 {
			t.Errorf("StderrBytes = %d, want 3", res.StderrBytes)
		}
		if res.StdoutBytes != 0 {
			t.Errorf("StdoutBytes = %d, want 0", res.StdoutBytes)
		}
	})

	t.Run("duration reflects a slow command", func(t *testing.T) {
		var res gate.ExecResult
		_ = captureStdout(t, func() {
			res, _ = gate.ExecWithRedaction(context.Background(), "sleep 0.2", gate.ExecOpts{})
		})
		if res.Duration < 150*time.Millisecond {
			t.Errorf("Duration = %v, want >= ~200ms", res.Duration)
		}
	})

	t.Run("metrics count post-redaction bytes, redaction still applied", func(t *testing.T) {
		var salt [32]byte
		for i := range salt {
			salt[i] = byte(i + 1)
		}
		rules := redactrules.Combined()
		const secret = "AKIA1234567890ABCDEF"
		var res gate.ExecResult
		out := captureStdout(t, func() {
			res, _ = gate.ExecWithRedaction(context.Background(), "echo "+secret, gate.ExecOpts{
				SessionSalt: salt,
				Rules:       rules,
			})
		})
		// Redaction must still happen (existing behaviour unchanged).
		if strings.Contains(out, secret) {
			t.Errorf("secret leaked despite rules: %q", out)
		}
		// The byte count reflects the REDACTED stream (what reached the
		// SSH stream), so it equals len(out), not the raw secret length.
		if res.StdoutBytes != int64(len(out)) {
			t.Errorf("StdoutBytes = %d, want %d (len of redacted stream)", res.StdoutBytes, len(out))
		}
		if res.Lines != 1 {
			t.Errorf("Lines = %d, want 1", res.Lines)
		}
	})

	t.Run("empty command still errors, ExitCode -1", func(t *testing.T) {
		res, err := gate.ExecWithRedaction(context.Background(), "", gate.ExecOpts{})
		if err == nil {
			t.Errorf("err = nil, want error for empty command")
		}
		if res.ExitCode != -1 {
			t.Errorf("ExitCode = %d, want -1", res.ExitCode)
		}
	})
}
