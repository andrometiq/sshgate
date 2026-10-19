//go:build linux

package gate_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// captureStdout runs fn while temporarily redirecting os.Stdout to a
// pipe; it returns whatever fn wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()
	fn()
	_ = w.Close()
	wg.Wait()
	_ = r.Close()
	return buf.String()
}

// TestExec exercises the raw executor via ExecWithRedaction with an empty
// ExecOpts (the no-redaction pass-through path). It covers the core
// process-control surface: exit-code propagation, context cancellation,
// large-output streaming, and empty-command rejection.
func TestExec(t *testing.T) {
	t.Run("echo returns 0 and writes to stdout", func(t *testing.T) {
		var res gate.ExecResult
		var err error
		out := captureStdout(t, func() {
			res, err = gate.ExecWithRedaction(context.Background(), "echo hello", gate.ExecOpts{})
		})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if res.ExitCode != 0 {
			t.Errorf("exit = %d, want 0", res.ExitCode)
		}
		if out != "hello\n" {
			t.Errorf("stdout = %q, want %q", out, "hello\n")
		}
	})

	t.Run("false returns exit 1", func(t *testing.T) {
		res, err := gate.ExecWithRedaction(context.Background(), "false", gate.ExecOpts{})
		if err != nil {
			t.Fatalf("err = %v, want nil (false's nonzero exit is not a start error)", err)
		}
		if res.ExitCode != 1 {
			t.Errorf("exit = %d, want 1", res.ExitCode)
		}
	})

	t.Run("explicit exit code passes through", func(t *testing.T) {
		res, err := gate.ExecWithRedaction(context.Background(), "sh -c 'exit 42'", gate.ExecOpts{})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if res.ExitCode != 42 {
			t.Errorf("exit = %d, want 42", res.ExitCode)
		}
	})

	t.Run("nonexistent command exits nonzero", func(t *testing.T) {
		res, err := gate.ExecWithRedaction(context.Background(), "/nonexistent/path/binary", gate.ExecOpts{})
		if err != nil {
			t.Fatalf("err = %v, want nil (nonzero exit is not a start error)", err)
		}
		if res.ExitCode == 0 {
			t.Errorf("exit = 0, want nonzero")
		}
	})

	t.Run("context cancel terminates a long sleep", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		res, err := gate.ExecWithRedaction(ctx, "sleep 10", gate.ExecOpts{})
		dur := time.Since(start)
		if dur > 5*time.Second {
			t.Fatalf("exec ran %v, expected to be killed promptly", dur)
		}
		_ = err
		if res.ExitCode == 0 {
			t.Errorf("exit = 0, want nonzero (process should have been killed)")
		}
	})

	t.Run("large stdout streams without buffering", func(t *testing.T) {
		// Print ~64KB of output. captureStdout via os.Pipe is bounded by
		// pipe buffer; we read concurrently in captureStdout so the
		// child shouldn't block.
		out := captureStdout(t, func() {
			// 64 KB of "x" via printf — portable across sh/bash.
			_, err := gate.ExecWithRedaction(context.Background(), "yes x | head -c 65536", gate.ExecOpts{})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if len(out) < 65000 {
			t.Errorf("stdout len = %d, want ≥ 65000", len(out))
		}
		// Sanity check first chars.
		if !strings.HasPrefix(out, "x") {
			t.Errorf("stdout prefix = %q, want to start with x", out[:min(10, len(out))])
		}
	})

	t.Run("empty cmd is rejected", func(t *testing.T) {
		res, err := gate.ExecWithRedaction(context.Background(), "", gate.ExecOpts{})
		if err == nil {
			t.Errorf("err = nil, want error for empty cmd; exit=%d", res.ExitCode)
		}
	})
}

func TestExecWithRedaction(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	rules := redactrules.Combined()

	t.Run("AWS access key is redacted on stdout", func(t *testing.T) {
		out := captureStdout(t, func() {
			_, err := gate.ExecWithRedaction(context.Background(), "echo AKIA1234567890ABCDEF", gate.ExecOpts{
				SessionSalt: salt,
				Rules:       rules,
			})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if strings.Contains(out, "AKIA1234567890ABCDEF") {
			t.Errorf("AWS key leaked through executor: %q", out)
		}
		if !strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("no marker emitted; out=%q", out)
		}
	})

	t.Run("benign output passes through unchanged", func(t *testing.T) {
		out := captureStdout(t, func() {
			_, err := gate.ExecWithRedaction(context.Background(), "echo hello world", gate.ExecOpts{
				SessionSalt: salt,
				Rules:       rules,
			})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if out != "hello world\n" {
			t.Errorf("stdout = %q, want %q", out, "hello world\n")
		}
	})

	t.Run("empty ruleset is a pass-through", func(t *testing.T) {
		out := captureStdout(t, func() {
			_, err := gate.ExecWithRedaction(context.Background(), "echo AKIA1234567890ABCDEF", gate.ExecOpts{
				SessionSalt: salt,
				// Rules empty: pass-through path.
			})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if !strings.Contains(out, "AKIA1234567890ABCDEF") {
			t.Errorf("empty-ruleset path should pass through; got %q", out)
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
