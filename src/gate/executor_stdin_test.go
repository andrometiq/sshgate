//go:build linux

package gate_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
)

// TestExecStdinIsNotAgentControlled is the regression guard for the
// "stdin is an unsigned-exec vector" gate-audit finding.
//
// THE VECTOR: the gate classifies $SSH_ORIGINAL_COMMAND but NEVER inspects
// stdin. In the gated model the agent supplies a COMMAND STRING (content is
// in the command itself, run via `sh -c`); the MCP client (src/mcp/ssh/
// client.go) never sets sess.Stdin, so no legitimate gated command sends
// channel stdin. But the executor used to wire os.Stdin straight to the
// child — so an agent that opens an SSH channel with data on stdin could
// feed a PROGRAM to a child that reads its program from stdin
// (e.g. `awk -f /dev/stdin`, `sed -f -`), executing UNSIGNED code with no
// signature and no classifier visibility.
//
// THE FIX (executor.go): the child's stdin is set to nil (==/dev/null), so
// agent-controlled channel stdin can never reach a child. This closes the
// whole class structurally, independent of whether the classifier happens
// to catch a given `-f`/stdin form today.
//
// This test puts a marker program on os.Stdin and proves a child that reads
// stdin does NOT see it.
func TestExecStdinIsNotAgentControlled(t *testing.T) {
	// armStdin points os.Stdin at a fresh pipe carrying a marker + an awk
	// program that would exec system() if awk read its program from stdin,
	// then CLOSES the writer. Closing gives any child that DOES read
	// os.Stdin an EOF so it terminates — without this, the UNFIXED executor
	// (which wires os.Stdin to the child) would block a stdin-reading child
	// forever and hang the test instead of failing cleanly. With the FIX the
	// child's stdin is /dev/null and this data is never seen at all. Each
	// subtest gets its own pipe so one subtest draining stdin can't mask
	// another's assertion.
	armStdin := func(t *testing.T) {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		orig := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = orig; _ = r.Close() })
		go func() {
			_, _ = w.WriteString("MARKER_STDIN_REACHED\nBEGIN{system(\"echo PWNED_VIA_STDIN\")}\n")
			_ = w.Close()
		}()
	}

	// A bound so a regression that re-wires os.Stdin can never hang the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("cat sees empty stdin, not the agent marker", func(t *testing.T) {
		armStdin(t)
		// `cat` with no file argument reads stdin. If channel stdin reached
		// the child, its stdout would contain the marker.
		out := captureStdout(t, func() {
			_, err := gate.ExecWithRedaction(ctx, "cat", gate.ExecOpts{})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if strings.Contains(out, "MARKER_STDIN_REACHED") {
			t.Fatalf("agent-controlled stdin reached the child (unsigned-exec vector OPEN); stdout=%q", out)
		}
		if out != "" {
			t.Errorf("expected empty stdout from a /dev/null stdin, got %q", out)
		}
	})

	t.Run("awk -f /dev/stdin cannot execute a stdin-supplied program", func(t *testing.T) {
		armStdin(t)
		// This is the named vector: awk reads its PROGRAM from stdin. With the
		// fix, /dev/stdin is /dev/null → awk runs an empty program → the
		// stdin-supplied system("echo PWNED...") never executes.
		out := captureStdout(t, func() {
			// 2>/dev/null suppresses awk's own "no program" diagnostics on the
			// captured stdout stream; we only care that PWNED never prints.
			_, _ = gate.ExecWithRedaction(ctx, "awk -f /dev/stdin 2>/dev/null", gate.ExecOpts{})
		})
		if strings.Contains(out, "PWNED_VIA_STDIN") {
			t.Fatalf("stdin-supplied awk program EXECUTED — unsigned-exec vector OPEN; stdout=%q", out)
		}
	})
}

// TestExecNormalReadsAndWritesUnaffected proves the stdin fix does not break
// ordinary gated commands, which never rely on channel stdin (content is
// carried in the command string via `sh -c`).
func TestExecNormalReadsAndWritesUnaffected(t *testing.T) {
	t.Run("plain read still works", func(t *testing.T) {
		out := captureStdout(t, func() {
			res, err := gate.ExecWithRedaction(context.Background(), "echo hello", gate.ExecOpts{})
			if err != nil {
				t.Errorf("err = %v", err)
			}
			if res.ExitCode != 0 {
				t.Errorf("exit = %d, want 0", res.ExitCode)
			}
		})
		if out != "hello\n" {
			t.Errorf("stdout = %q, want %q", out, "hello\n")
		}
	})

	t.Run("write via command string (in-command pipe) still works", func(t *testing.T) {
		// The gated write model carries content IN the command, e.g.
		// `echo X | tee f` — an in-command pipe, NOT channel stdin. Confirm
		// such a command runs end to end with the fix in place.
		dir := t.TempDir()
		target := dir + "/out.txt"
		_, err := gate.ExecWithRedaction(context.Background(),
			"echo in-command-content | tee "+target+" >/dev/null", gate.ExecOpts{})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		b, rerr := os.ReadFile(target)
		if rerr != nil {
			t.Fatalf("read back: %v", rerr)
		}
		if strings.TrimSpace(string(b)) != "in-command-content" {
			t.Errorf("file = %q, want %q", string(b), "in-command-content")
		}
	})
}
