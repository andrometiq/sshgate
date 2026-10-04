package confine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
)

const (
	Execute        = "Execute"
	SetupAbort     = "SetupAbort"
	LaunchFailure  = "LaunchFailure"
	ControlledHang = "ControlledHang"
	ExpectedSignal = "ExpectedSignal"
	Interactive    = "Interactive"
	Cancelled      = "Cancelled"
)

type OpOutcome struct {
	Stdout, Stderr string
	Exit           int
}
type ProofOp struct {
	Name, Command string
	Outcomes      []OpOutcome
	// Validate is for variable-valued reports; it must validate every field and status.
	Validate func(stdout, stderr string, exit int) error
}
type RunPlan struct {
	Mode, Command, Stage string
	ReadyPoint           string
	Errno                syscall.Errno
	Signal               syscall.Signal
	Ops                  []ProofOp
	Configure            func(*Jailed)
	After, Timeout       time.Duration
	Release              func() error
	AfterReady           func()
	AfterStart           func(*Jailed) error
	Validate             func(stdout, stderr string, exit int) error
	AcceptFactsABI0      bool
	ExpectExit           int
	// CancelAfterReady initiates gate-side cancellation after the bounded handshake.
	CancelAfterReady bool
	CleanupEvidence  func() error
}

func proofShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func framedCommand(ops []ProofOp) (string, error) {
	if len(ops) == 0 {
		return "", fmt.Errorf("empty operation plan")
	}
	var command strings.Builder
	seen := map[string]bool{}
	for _, op := range ops {
		if op.Name == "" || strings.ContainsAny(op.Name, " \t\r\n") || seen[op.Name] || op.Command == "" || len(op.Outcomes) == 0 && op.Validate == nil {
			return "", fmt.Errorf("invalid or undeclared operation %q", op.Name)
		}
		seen[op.Name] = true
		// Keep each operation in a subshell: its exit cannot skip the frame trailer.
		fmt.Fprintf(&command, "printf 'OP-BEGIN %%s\\n' %s; ( %s\n ); proof_status=$?; printf '\\nOP-END %%s\\n' \"$proof_status\"; printf '%%s-done\\n' %s; ", proofShellQuote(op.Name), op.Command, proofShellQuote(op.Name))
	}
	command.WriteString("exit 0")
	return command.String(), nil
}
func validateFramed(result jailResult, ops []ProofOp) (string, error) {
	if result.setupErr != nil || result.exit != 0 {
		return "", fmt.Errorf("framed shell failed: exit %d setup %v", result.exit, result.setupErr)
	}
	rest := result.stdout
	var output strings.Builder
	for i, op := range ops {
		begin := "OP-BEGIN " + op.Name + "\n"
		if !strings.HasPrefix(rest, begin) {
			return "", fmt.Errorf("missing operation %s", op.Name)
		}
		rest = strings.TrimPrefix(rest, begin)
		body, tail, ok := strings.Cut(rest, "\nOP-END ")
		if !ok {
			return "", fmt.Errorf("unterminated operation %s", op.Name)
		}
		codeText, tail, ok := strings.Cut(tail, "\n")
		if !ok {
			return "", fmt.Errorf("missing status %s", op.Name)
		}
		code, err := strconv.Atoi(codeText)
		if err != nil || code < 0 || code > 125 {
			return "", fmt.Errorf("abnormal operation status %q", codeText)
		}
		done := op.Name + "-done\n"
		if !strings.HasPrefix(tail, done) {
			return "", fmt.Errorf("missing terminal report %s", op.Name)
		}
		rest = strings.TrimPrefix(tail, done)
		diagnostic := ""
		if len(ops) == 1 {
			diagnostic = result.stderr
		} else if result.stderr != "" {
			return "", fmt.Errorf("multi-operation stderr is not attributable: %q", result.stderr)
		}
		valid := false
		for _, want := range op.Outcomes {
			if body == want.Stdout && diagnostic == want.Stderr && code == want.Exit {
				valid = true
			}
		}
		if op.Validate != nil {
			if err := op.Validate(body, diagnostic, code); err != nil {
				return "", fmt.Errorf("operation %s: %w", op.Name, err)
			}
			valid = true
		}
		if !valid {
			return "", fmt.Errorf("operation %d %s unexpected output/status: %q %q %d", i, op.Name, body, diagnostic, code)
		}
		output.WriteString(body)
	}
	if rest != "" {
		return "", fmt.Errorf("unframed trailing output %q", rest)
	}
	return output.String(), nil
}

type proofOutput struct {
	mu sync.Mutex
	bytes.Buffer
	ready    chan struct{}
	notified bool
}

func (w *proofOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.Buffer.Write(data)
	if !w.notified && (strings.HasPrefix(w.Buffer.String(), "READY\n") || strings.Contains(w.Buffer.String(), "\nREADY\n")) {
		w.notified = true
		close(w.ready)
	}
	return n, err
}
func (w *proofOutput) snapshot() string { w.mu.Lock(); defer w.mu.Unlock(); return w.Buffer.String() }
func proofExit(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
func modeAllowed(p *proof, mode string) bool {
	if p.caseDef.Mode == mode {
		return true
	}
	for _, allowed := range p.caseDef.Modes {
		if allowed == mode {
			return true
		}
	}
	return false
}

func runJailed(t *testing.T, p *proof, spec Spec, plan RunPlan) JailedResult {
	t.Helper()
	if p == nil || p.finished || !modeAllowed(p, plan.Mode) {
		t.Fatalf("SETUP: undeclared execution mode %s", plan.Mode)
	}
	if (plan.Mode == LaunchFailure || plan.Mode == ControlledHang) && !proofMutationBuild {
		t.Fatal("SETUP: mutation-only completion mode")
	}
	if plan.AcceptFactsABI0 && (!proofMutationBuild || !p.caseDef.AcceptFactsABI0 || !jailmut.On("P-LL-REQUIRED")) {
		t.Fatal("SETUP: undeclared ABI0 exception")
	}
	token := new(bool)
	p.executions = append(p.executions, token)
	p.healthy()
	command := plan.Command
	if plan.Mode == Execute || plan.Mode == Interactive {
		var err error
		command, err = framedCommand(plan.Ops)
		if err != nil {
			t.Fatalf("SETUP: %v", err)
		}
	}
	handshake := plan.Mode == Interactive || plan.Mode == Cancelled
	if plan.Mode == Interactive && plan.ReadyPoint != "post-exec" && plan.ReadyPoint != "probe" {
		t.Fatal("SETUP: declare interactive READY point")
	}
	if handshake && plan.ReadyPoint != "probe" {
		command = "printf 'READY\\n'; " + command
		if plan.Mode == Interactive {
			command = "printf 'READY\\n'; read proof_release; " + strings.TrimPrefix(command, "printf 'READY\\n'; ")
		}
	}
	if command == "" {
		t.Fatal("SETUP: empty jail command")
	}
	timeout := plan.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	j, err := spec.Command(ctx, command)
	if err != nil {
		t.Fatalf("SETUP: prepare jailed command: %v", err)
	}
	defer j.Abort()
	if plan.Configure != nil {
		plan.Configure(j)
	}
	var cancellationDelivered atomic.Bool
	if plan.Mode == Cancelled {
		j.Cmd.Cancel = func() error {
			err := j.Cmd.Process.Signal(syscall.SIGTERM)
			if err == nil {
				cancellationDelivered.Store(true)
			}
			return err
		}
		j.Cmd.WaitDelay = time.Second
	}
	var stdout proofOutput
	stdout.ready = make(chan struct{})
	var stderr bytes.Buffer
	j.Cmd.Stdout = &stdout
	j.Cmd.Stderr = &stderr
	var release *os.File
	if handshake {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		j.Cmd.Stdin = reader
		release = writer
	}
	started := make(chan error, 1)
	go func() { started <- j.Cmd.Start() }()
	if plan.Mode == ControlledHang {
		if plan.After <= 0 || plan.Release == nil {
			t.Fatal("SETUP: controlled hang requires duration and release")
		}
		select {
		case err := <-started:
			if err == nil {
				_ = j.Started()
				cancel()
				_ = j.Cmd.Wait()
			}
			t.Fatalf("SETUP: launch did not hang: %v", err)
		case <-time.After(plan.After):
		}
		if err := plan.Release(); err != nil {
			t.Fatalf("SETUP: release controlled hang: %v", err)
		}
		select {
		case err = <-started:
		case <-ctx.Done():
			t.Fatal("SETUP: controlled launch not released")
		}
		if err == nil {
			_ = j.Started()
			err = j.Cmd.Wait()
			if err == nil {
				t.Fatal("SETUP: controlled hang worker unexpectedly succeeded")
			}
		}
		if stdout.snapshot() != "" || stderr.Len() != 0 {
			t.Fatal("SETUP: controlled hang produced output")
		}
		return JailedResult{jailResult: jailResult{exit: proofExit(err)}, validated: true, owner: p, token: token, mode: plan.Mode}
	}
	select {
	case err = <-started:
	case <-ctx.Done():
		t.Fatal("SETUP: launch timeout")
	}
	if plan.Mode == LaunchFailure {
		if !errors.Is(err, plan.Errno) || err == nil || stdout.snapshot() != "" || stderr.Len() != 0 {
			t.Fatalf("SETUP: launch failure mismatch: %v", err)
		}
		return JailedResult{jailResult: jailResult{exit: -1, setupErr: err}, validated: true, owner: p, token: token, mode: plan.Mode}
	}
	if err != nil {
		t.Fatalf("SETUP: jail launch: %v", err)
	}
	if err = j.Started(); err != nil {
		t.Fatalf("SETUP: release command: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- j.Cmd.Wait() }()

	if handshake {
		select {
		case <-stdout.ready:
			if plan.AfterReady != nil {
				plan.AfterReady()
			}
			if plan.Mode == Cancelled {
				if !plan.CancelAfterReady {
					t.Fatal("SETUP: cancellation not requested")
				}
				cancel()
			} else {
				if _, err := release.WriteString("go\n"); err != nil {
					t.Fatalf("SETUP: release interactive probe: %v", err)
				}
			}
		case err = <-done:
			t.Fatalf("SETUP: worker ended before READY: %v", err)
		case <-ctx.Done():
			t.Fatal("SETUP: READY timeout")
		}
	}
	if plan.AfterStart != nil {
		if err := plan.AfterStart(j); err != nil {
			t.Fatalf("SETUP: after start: %v", err)
		}
	}
	err = <-done
	facts, statusErr := j.Status()
	if plan.AcceptFactsABI0 && statusErr != nil {
		facts, statusErr = proofFactsABI0(j, spec)
	}
	result := JailedResult{jailResult: jailResult{exit: proofExit(err), stdout: stdout.snapshot(), stderr: stderr.String(), setupErr: statusErr}, Facts: facts, Worker: j.WorkerStatus(), ShimExit: proofExit(err), Cancelled: cancellationDelivered.Load(), owner: p, token: token, mode: plan.Mode}
	if handshake {
		result.stdout = strings.TrimPrefix(result.stdout, "READY\n")
	}
	const cwdNote = "gate: note: the working directory is not visible in the read view; the read ran from /\n"
	if facts.CwdReset {
		result.stderr = strings.Replace(result.stderr, cwdNote, "", 1)
	}
	if j.CleanupError != "" {
		t.Fatalf("SETUP: jail cleanup: %s", j.CleanupError)
	}
	switch plan.Mode {
	case Execute, Interactive:
		output, err := validateFramed(result.jailResult, plan.Ops)
		if err != nil {
			t.Fatalf("SETUP: %v", err)
		}
		result.stdout = output
		if len(plan.Ops) == 1 {
			_, tail, _ := strings.Cut(stdout.snapshot(), "\nOP-END ")
			code, _, _ := strings.Cut(tail, "\n")
			result.exit, _ = strconv.Atoi(code)
		}
	case SetupAbort:
		if err := validateSetupAbort(result, plan); err != nil {
			t.Fatalf("SETUP: %v", err)
		}
	case ExpectedSignal:
		if err := validateExpectedSignal(result, plan); err != nil {
			t.Fatalf("SETUP: %v", err)
		}
	case Cancelled:
		if err := validateCancellation(&result, plan); err != nil {
			t.Fatalf("SETUP: %v", err)
		}
	default:
		t.Fatalf("SETUP: unknown completion mode %s", plan.Mode)
	}
	result.validated = true
	return result
}

// The sole test-only exception revalidates the complete report, changing only ABI=0.
func proofFactsABI0(j *Jailed, spec Spec) (Facts, error) {
	raw := string(j.statusReport.data)
	line, tail, ok := strings.Cut(raw, "\n")
	if !ok || !strings.HasPrefix(line, "I") || !strings.HasPrefix(tail, "X") {
		return Facts{}, fmt.Errorf("invalid ABI0 report")
	}
	var facts Facts
	decoder := json.NewDecoder(strings.NewReader(line[1:]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&facts) != nil || facts.ABI != 0 || facts.Profile != spec.Profile || facts.Net != spec.Net || facts.Lane2 || len(facts.Unmet) != 0 {
		return Facts{}, fmt.Errorf("invalid ABI0 facts")
	}
	canonical, marshalErr := json.Marshal(facts)
	if marshalErr != nil || string(canonical) != line[1:] {
		return Facts{}, fmt.Errorf("noncanonical ABI0 facts")
	}
	// Reuse Status's authoritative parser for mandatory keys, tail and worker status.
	fields := map[string]json.RawMessage{}
	if json.Unmarshal([]byte(line[1:]), &fields) != nil {
		return Facts{}, fmt.Errorf("invalid ABI0 facts")
	}
	fields["abi"] = json.RawMessage("1")
	patched, err := json.Marshal(fields)
	if err != nil {
		return Facts{}, err
	}
	saved := j.statusReport.data
	j.statusReport.data = []byte("I" + string(patched) + "\n" + tail)
	defer func() { j.statusReport.data = saved }()
	validated, err := j.Status()
	validated.ABI = 0
	return validated, err
}

func validateExpectedSignal(result JailedResult, plan RunPlan) error {
	if plan.Signal <= 0 || result.setupErr != nil || !result.Worker.Known || result.Worker.Exited || result.Worker.Signal != plan.Signal || result.stderr != "" || plan.Validate == nil {
		return fmt.Errorf("worker signal evidence invalid: %+v", result)
	}
	if err := plan.Validate(result.stdout, result.stderr, 128+int(plan.Signal)); err != nil {
		return fmt.Errorf("presignal report: %w", err)
	}
	return nil
}

func validateSetupAbort(result JailedResult, plan RunPlan) error {
	var setup *SetupError
	if !errors.As(result.setupErr, &setup) || setup.Stage != plan.Stage || setup.Errno != plan.Errno || result.exit != ExitSetupFailed || result.stdout != "" {
		return fmt.Errorf("wrong setup abort: %+v", result)
	}
	return nil
}
func validateCancellation(result *JailedResult, plan RunPlan) error {
	code := 143
	if result.Worker.Known {
		if result.Worker.Exited {
			code = result.Worker.Code
		} else {
			code = 128 + int(result.Worker.Signal)
		}
	}
	if !result.Cancelled || result.setupErr != nil || code != plan.ExpectExit || result.stderr != "" || plan.CleanupEvidence == nil {
		return fmt.Errorf("cancellation evidence mismatch: %+v", result)
	}
	if err := plan.CleanupEvidence(); err != nil {
		return fmt.Errorf("cancellation descendants: %w", err)
	}
	result.exit = code
	return nil
}
