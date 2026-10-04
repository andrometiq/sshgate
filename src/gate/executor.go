package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// ExecOpts holds the optional redactor wiring for a single command.
//
// SessionSalt is a per-process 32-byte random value used for HMAC
// marker keys. Generated once at gate startup (see
// cmd/sshgate-gate/main.go) and never persisted.
//
// Rules is the compiled-in ruleset (typically rules.Combined()). When
// empty, both Stdout and Stderr pass through with no redaction —
// equivalent to v1.0 behaviour, useful for tests that exercise the
// raw executor.
//
// Reveal, when true, runs the command's output WITHOUT the redactor even
// when Rules is non-empty — the SECRET-REVEAL path, where raw secret values
// are intentionally allowed to flow to the agent. It is a SEPARATE, explicit
// field (NOT conflated with "Rules is empty"): an empty ruleset is a
// configuration state, whereas Reveal is a per-command, signed authorisation.
// The gate sets Reveal only from the verified signed payload (see
// gate.VerifySigned) on the signed path; the unsigned read path never sets it.
type ExecOpts struct {
	SessionSalt [32]byte
	Rules       []redact.Rule
	Reveal      bool
	// CaptureLimit, when > 0, makes ExecWithRedaction tee the bytes that
	// reach the SSH stream (post-redaction, or raw on the reveal path)
	// into in-memory buffers, returned as ExecResult.Stdout/Stderr,
	// capped at this many bytes PER STREAM. This is ONLY for the gate-side
	// audit `all+full` (verbose) level; the default path leaves it 0 so
	// the gate never pays the buffering cost. The cap bounds memory for a
	// huge command (we keep the head; a truncation marker is appended).
	CaptureLimit int
	// Confine, when non-nil, runs the command inside the kernel jail the Spec
	// describes (the ro-v1 profile) instead of a plain
	// /bin/sh -c. A nil Confine is byte-for-byte today's path (rung 3 / unset):
	// the gate passes nil on an unconfined host so this field is purely additive.
	// The jail only ADDS restrictions; stdout/stderr/stdin/redaction wiring below
	// is identical either way.
	Confine *confine.Spec
}

// ExecResult is the widened return of ExecWithRedaction. It carries the
// child's exit code plus output METADATA (byte counts, line count, and
// wall-clock duration) so the gate-side audit log can record what
// happened WITHOUT capturing raw output by default (Tier-6a `all+meta`).
//
// The byte counts are measured at the point the bytes actually reach the
// SSH stream — i.e. POST-redaction. That is deliberately what the agent
// receives, so an audit of "how much data flowed back" reflects reality
// (a redacted secret counts as the marker length, not the raw length).
//
// Lines counts '\n' bytes seen across stdout (the conventional
// line-count; a trailing partial line without a newline is not counted,
// matching `wc -l`). StderrBytes is tracked separately from StdoutBytes
// because the two streams are wrapped in independent writers.
//
// ExitCode follows the same convention as the old scalar return: the
// child's 0..255 code, 128+signum when signalled, or -1 if the process
// never started.
type ExecResult struct {
	ExitCode int
	// CleanupError reports post-execution cleanup failure without changing ExitCode.
	CleanupError string
	StdoutBytes  int64
	StderrBytes  int64
	Lines        int64
	Duration     time.Duration
	// Stdout/Stderr hold a (capped) copy of the bytes that reached the
	// SSH stream, populated ONLY when ExecOpts.CaptureLimit > 0 (the
	// audit `all+full` path). Empty otherwise.
	Stdout string
	Stderr string
}

// countingWriter forwards every Write to its underlying writer while
// tallying total bytes and newline count. It sits BELOW the redactor
// (redactor -> countingWriter -> os.Stdout) so the counts reflect the
// post-redaction bytes that actually reach the SSH stream. The counters
// are atomic so a future concurrent flush cannot race the tally, though
// today each stream's writer is single-goroutine.
//
// When captureLimit > 0 it also tees the forwarded bytes into cap (up to
// captureLimit bytes; the head is kept) for the audit all+full level.
type countingWriter struct {
	dst          io.Writer
	bytes        atomic.Int64
	lines        atomic.Int64
	captureLimit int
	cap          []byte // guarded by the single-goroutine-per-stream invariant
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.dst.Write(p)
	if n > 0 {
		c.bytes.Add(int64(n))
		var nl int64
		for _, b := range p[:n] {
			if b == '\n' {
				nl++
			}
		}
		c.lines.Add(nl)
		if c.captureLimit > 0 && len(c.cap) < c.captureLimit {
			room := c.captureLimit - len(c.cap)
			if room > n {
				room = n
			}
			c.cap = append(c.cap, p[:room]...)
		}
	}
	return n, err
}

// captured returns the captured bytes as a string, appending a
// truncation marker when the byte count exceeded what we kept.
func (c *countingWriter) captured() string {
	if c.captureLimit == 0 {
		return ""
	}
	s := string(c.cap)
	if c.bytes.Load() > int64(len(c.cap)) {
		s += "\n[SSHGATE_AUDIT_TRUNCATED]"
	}
	return s
}

var confinedCommand = func(spec *confine.Spec, ctx context.Context, command string) (*confine.Jailed, error) {
	return spec.Command(ctx, command)
}

// ExecWithRedaction runs cmd via "/bin/sh -c <cmd>", streaming the child's
// stdout and stderr to os.Stdout / os.Stderr. When opts.Rules is non-empty AND
// opts.Reveal is false, c.Stdout and c.Stderr are wrapped in redact.Writer
// instances so every byte the child emits passes through the streaming
// scrubber before reaching the SSH stream; when opts.Rules is empty — or
// opts.Reveal is true (the signed SECRET-REVEAL path) — both streams pass
// through unredacted. It blocks until the child exits or ctx is cancelled,
// whichever comes first.
//
// The redactor lives at the gate boundary by design (see
// docs/redaction-architecture.md §"Where
// it lives") — the MCP-side trust boundary is bypassable; the gate
// is the only physical choke point.
//
// Return values:
//
//   - res.ExitCode is the child's exit code in the range 0..255. When the
//     process is killed by a signal (including ctx cancellation), the
//     exit code is reported as 128+signum, matching the convention used
//     by shells. If the process never started (e.g. /bin/sh missing),
//     ExitCode is -1.
//   - res also carries output METADATA (StdoutBytes/StderrBytes/Lines/
//     Duration), measured at the bytes that reach the SSH stream
//     (post-redaction). This feeds the gate-side audit log's `all+meta`
//     level without ever capturing raw output. See ExecResult.
//   - err is non-nil only on start failures. A nonzero exit code from a
//     successfully-started child is NOT an error from gate's
//     perspective — the caller is expected to propagate ExitCode as
//     gate's own exit status.
//
// It sets a process group on the child so that ctx cancellation kills the
// whole group, not just the shell. This matters because the child may itself
// spawn subprocesses (e.g. pipelines) that would otherwise be reparented to
// PID 1 and outlive cancellation.
func ExecWithRedaction(ctx context.Context, cmd string, opts ExecOpts) (res ExecResult, err error) {
	if strings.TrimSpace(cmd) == "" {
		return ExecResult{ExitCode: -1}, errors.New("exec: empty command")
	}
	// Select the command: a confined Spec re-execs the gate into the jail (it
	// sets Path/Args/ExtraFiles AND SysProcAttr, including Setpgid); a nil Spec
	// is today's /bin/sh path. SysProcAttr is therefore set EXACTLY ONCE — the
	// unconditional Setpgid assignment that used to live further down is folded
	// into the else branch so it can never clobber the jail's clone flags.
	var c *exec.Cmd
	var jailed *confine.Jailed
	if opts.Confine != nil {
		var cerr error
		jailed, cerr = confinedCommand(opts.Confine, ctx, cmd)
		if cerr != nil {
			return ExecResult{ExitCode: -1}, fmt.Errorf("exec: build jail: %w", cerr)
		}
		c = jailed.Cmd
	} else {
		c = exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	return runRedacted(c, jailed, "/bin/sh", opts)
}

// ExecArgvWithRedaction runs argv directly — no shell, no jail — with exactly
// env as the child's environment, through the same stdout/stderr redaction,
// counting, /dev/null stdin and process-group plumbing as ExecWithRedaction.
// It is the shell-free exec for the gate's Lane-2 daemon-read allowlist: argv[0]
// must be an absolute path (never a $PATH lookup), and a nil env yields an EMPTY
// environment, never the gate's inherited one. opts.Confine must be nil — this
// door is unjailed by design. Return values follow ExecWithRedaction.
func ExecArgvWithRedaction(ctx context.Context, argv, env []string, opts ExecOpts) (ExecResult, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return ExecResult{ExitCode: -1}, errors.New("exec: argv[0] must be an absolute path")
	}
	if opts.Confine != nil {
		return ExecResult{ExitCode: -1}, errors.New("exec: argv exec is never confined")
	}
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.Env = append([]string{}, env...) // non-nil: os/exec inherits the gate's env only for a nil Env
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return runRedacted(c, nil, argv[0], opts)
}

// runRedacted is the shared tail of both exec entry points: it wires the
// redacting/counting writers and /dev/null stdin onto c, runs it, and maps the
// outcome to an ExecResult. jailed is non-nil only for a confined command; what
// names the program in a start-failure error.
func runRedacted(c *exec.Cmd, jailed *confine.Jailed, what string, opts ExecOpts) (res ExecResult, err error) {
	// Counting writers sit BELOW any redactor so the tally is the
	// post-redaction byte/line count that actually reaches the SSH
	// stream (see ExecResult). One per stream, never shared. CaptureLimit
	// (>0 only for the audit all+full path) makes them also tee a capped
	// copy of the forwarded bytes.
	outCount := &countingWriter{dst: os.Stdout, captureLimit: opts.CaptureLimit}
	errCount := &countingWriter{dst: os.Stderr, captureLimit: opts.CaptureLimit}

	// Stdout / Stderr: when a ruleset is configured (and not a reveal),
	// wrap each stream's counting writer in a redact.Writer. Stderr is
	// treated identically to stdout — the spec is explicit: both streams
	// pass through their own writer (no cross-stream coupling, no shared
	// buffer). When Rules is empty or Reveal is true, the redactor is
	// skipped but the counting writers still tally raw bytes.
	var stdoutCloser, stderrCloser io.Closer
	if !opts.Reveal && len(opts.Rules) > 0 {
		ow := redact.NewWriter(outCount, opts.SessionSalt, opts.Rules)
		ew := redact.NewWriter(errCount, opts.SessionSalt, opts.Rules)
		c.Stdout = ow
		c.Stderr = ew
		stdoutCloser = ow
		stderrCloser = ew
	} else {
		c.Stdout = outCount
		c.Stderr = errCount
	}
	// SECURITY: the child's stdin is /dev/null, NOT the gate's os.Stdin.
	//
	// The gate classifies $SSH_ORIGINAL_COMMAND but never inspects stdin. In
	// the gated model the agent supplies a COMMAND STRING (any content is in
	// the command itself, run via `sh -c`, e.g. `echo X | tee f`). Exactly ONE
	// gated command carries channel stdin: update_gate streams the new gate
	// binary's bytes (src/mcp/ssh/client.go RunWithStdin sets sess.Stdin). But
	// those bytes are consumed by handleUpdate as HASH-VERIFIED DATA, which
	// returns before ever reaching this exec path — so no exec child ever sees
	// channel stdin. Wiring the gate's os.Stdin — which the agent controls over
	// the SSH channel — to the child would open an unsigned-exec vector: a child
	// that reads its PROGRAM from stdin (`awk -f /dev/stdin`, `awk -f -`,
	// `awk -f /dev/fd/0`, `sed -f -`, …) would execute agent-supplied code with
	// no signature and no classifier visibility (the classifier sees only the
	// command string, never the piped program). Setting Stdin nil here
	// unconditionally makes os/exec attach /dev/null, closing the entire class
	// structurally — independent of whether the classifier happens to flag a
	// given program-from-stdin form.
	c.Stdin = nil
	if jailed != nil {
		if err := confine.EnableSubreaper(); err != nil {
			jailed.Abort()
			return ExecResult{ExitCode: -1}, fmt.Errorf("exec: gate subreaper: %w", err)
		}
		// WaitDelay escalates SIGTERM to SIGKILL and bounds pipes held by orphans.
		c.WaitDelay = 500 * time.Millisecond
		c.Cancel = func() error { return c.Process.Signal(syscall.SIGTERM) }
	} else {
		c.Cancel = func() error {
			if c.Process == nil {
				return os.ErrProcessDone
			}
			return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
	}

	start := time.Now()
	if err := c.Start(); err != nil {
		if jailed != nil {
			jailed.Abort()
			return ExecResult{ExitCode: -1, Duration: time.Since(start)}, fmt.Errorf("exec: start jail: %w", err)
		}
		// Nil-Confine path stays byte-identical to the pre-jail executor.
		return ExecResult{ExitCode: -1, Duration: time.Since(start)}, fmt.Errorf("exec: start %s: %w", what, err)
	}
	if jailed != nil {
		// Close the parent's child-side pipe ends and stream the command to the
		// worker on fd 3 (from a goroutine, so a large command cannot deadlock).
		_ = jailed.Started()
	}
	waitErr := c.Wait()
	var cleanupErr error
	if jailed != nil {
		cleanupErr = confine.CleanupDescendants()
	}

	// Flush the redact.Writer instances after the child exits so any
	// bytes still held inside the safe-prefix tail (or inside a
	// not-yet-completed PEM accumulator) reach the SSH stream — and the
	// counting writers below them. Close errors here are surfaced over
	// the wait error only when the child itself succeeded — a write error
	// after a successful exit is still an error the agent should see.
	if stdoutCloser != nil {
		if cerr := stdoutCloser.Close(); cerr != nil && waitErr == nil {
			waitErr = fmt.Errorf("redact stdout: %w", cerr)
		}
	}
	if stderrCloser != nil {
		if cerr := stderrCloser.Close(); cerr != nil && waitErr == nil {
			waitErr = fmt.Errorf("redact stderr: %w", cerr)
		}
	}
	dur := time.Since(start)

	// Metrics are read after Close so flushed tail bytes are included.
	res = ExecResult{
		StdoutBytes: outCount.bytes.Load(),
		StderrBytes: errCount.bytes.Load(),
		Lines:       outCount.lines.Load(),
		Duration:    dur,
		Stdout:      outCount.captured(),
		Stderr:      errCount.captured(),
	}

	// Fail closed on a jail setup failure: if the worker aborted before execve
	// (fd-4 status is not "reached exec"), NOTHING ran. The child's exit code
	// here is the setup-failure sentinel, not a command result, so we return -1
	// and the SetupError — never a success and never the sh exit code — so the
	// gate maps it to a deny rather than silently treating a half-built jail as a
	// completed command.
	if jailed != nil {
		if setupErr := jailed.Status(); setupErr != nil {
			res.ExitCode = -1
			return res, fmt.Errorf("exec: %w", setupErr)
		}
	}

	if jailed != nil {
		res.CleanupError = jailed.CleanupError
		if cleanupErr != nil {
			reason := strings.Join(strings.Fields(cleanupErr.Error()), " ")
			if res.CleanupError == "" {
				fmt.Fprintln(errCount, "gate-jail: cleanup:", reason)
			}
			if res.CleanupError != "" {
				res.CleanupError += "; "
			}
			res.CleanupError += reason
		}
		res.StderrBytes = errCount.bytes.Load()
		res.Stderr = errCount.captured()
		if errors.Is(waitErr, exec.ErrWaitDelay) {
			waitErr = nil
		}
	}
	if waitErr == nil {
		res.ExitCode = 0
		return res, nil
	}
	// Extract the exit code or signal status from the wait error.
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if ok {
			if ws.Signaled() {
				res.ExitCode = 128 + int(ws.Signal())
				return res, nil
			}
			res.ExitCode = ws.ExitStatus()
			return res, nil
		}
		// Fallback: ExitCode() returns -1 if signaled; use it as best effort.
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if jailed != nil {
		res.ExitCode = 1
		return res, fmt.Errorf("exec: confined wait after execution: %w", waitErr)
	}
	// Non-ExitError wait failure (e.g. waitpid syscall error). Treat as
	// a start/run failure so the caller can distinguish it.
	res.ExitCode = -1
	return res, fmt.Errorf("exec: wait: %w", waitErr)
}
