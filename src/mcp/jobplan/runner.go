package jobplan

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// PhasedRunner drains output into the supplied writers and checks preStart
// after session setup, immediately before sending the exec request.
type PhasedRunner interface {
	RunPhasedTo(context.Context, string, string, int, string, io.Reader, func() error, io.Writer, io.Writer) (int, error)
}

type CurrentRegistry interface {
	ReadCurrent(string) (approvalplan.RouteSnapshot, string, error)
}

// StepJournal must finish each durable commit before returning. A failed hook
// stops the caller; it must resolve storage uncertainty before doing more work.
type StepJournal interface {
	BeforeStep(int) error
	AfterStep(int, approvalplan.StepResult) error
}

// Dispatch is ephemeral: signed wire bytes and stdin never enter a journal.
// WireCommand is ignored for unsigned steps, which use the frozen command.
type Dispatch struct {
	WireCommand string
	Stdin       io.Reader
}

type StepExecution struct {
	Result  approvalplan.StepResult
	Outcome Outcome
}

type RunResult struct {
	Summary approvalplan.JobSummary
	Steps   []StepExecution
}

// Runner is single-flight and scoped to one command job in one process.
// Call HoldWindows on each successful Claim, with both clocks sampled before
// sending that Claim. Repeat answers never renew an acquired window.
type Runner struct {
	draft      approvalplan.ApprovalDraft
	ssh        PhasedRunner
	registry   CurrentRegistry
	clock      elapsed.Clock
	held       map[int]approvalplan.Held
	released   bool
	aborted    bool
	attempted  map[int]bool
	lastSigned int
	budget     *captureBudget
}

// NewRunner takes the raw body bytes already retained by a recovered job (zero
// for a new run), so a restart cannot reset the job output budget.
func NewRunner(draft approvalplan.ApprovalDraft, ssh PhasedRunner, registry CurrentRegistry, clock elapsed.Clock, retainedOutputBytes int64) (*Runner, error) {
	if err := draft.Validate(); err != nil {
		return nil, err
	}
	if draft.CommandJob == nil || ssh == nil || registry == nil || clock == nil || retainedOutputBytes < 0 || retainedOutputBytes > approvalplan.MaxJobOutputBytes {
		return nil, errors.New("jobplan: invalid runner configuration")
	}
	job := *draft.CommandJob
	job.Steps = slices.Clone(job.Steps)
	for i := range job.Steps {
		if d := job.Steps[i].TrustedDisplay; d != nil {
			copy := *d
			job.Steps[i].TrustedDisplay = &copy
		}
	}
	draft.CommandJob = &job
	r := &Runner{draft: draft, ssh: ssh, registry: registry, clock: clock, held: make(map[int]approvalplan.Held), attempted: make(map[int]bool)}
	for _, s := range job.Steps {
		if s.Route.Signed() {
			r.lastSigned = s.Ordinal
		}
	}
	if draft.Coordinator == approvalplan.CoordinatorExecutor {
		r.budget = &captureBudget{remaining: approvalplan.MaxJobOutputBytes - retainedOutputBytes}
	}
	return r, nil
}

func (r *Runner) HoldWindows(sentAt approvalplan.Now, windows []time.Time) error {
	if r.released {
		return errors.New("jobplan: signature set released")
	}
	if len(windows) != len(r.draft.CommandJob.Steps) {
		return errors.New("jobplan: invalid signature windows")
	}
	for i, s := range r.draft.CommandJob.Steps {
		if s.Route.Signed() == windows[i].IsZero() {
			return errors.New("jobplan: invalid signature windows")
		}
	}
	for i, s := range r.draft.CommandJob.Steps {
		if _, exists := r.held[i+1]; s.Route.Signed() && !exists {
			r.held[i+1] = approvalplan.Acquire(sentAt, windows[i], time.Duration(s.SignatureTTLSeconds)*time.Second)
		}
	}
	return nil
}

// Close drops all held authority. It is also called at the last signed Start,
// a K16 refusal, and the end of Run. A closed set cannot be reacquired.
func (r *Runner) Close() { clear(r.held); r.released = true }

func (r *Runner) guard(ordinal int) error {
	h, ok := r.held[ordinal]
	now := approvalplan.Now{Wall: r.clock.Wall(), Elapsed: r.clock.Elapsed()}
	if !ok || !h.PassesK16(now) {
		r.Close()
		return errors.New("jobplan: signature window closed")
	}
	return nil
}

// RunStep performs one dispatch; executor actors may call it after their Claim.
// Callers close the runner when their run ends. Journal failures are returned
// as fixed errors, with no invented durable result or automatic retry.
func (r *Runner) RunStep(ctx context.Context, ordinal int, dispatch Dispatch, earlierExecuted bool, journal StepJournal) (StepExecution, error) {
	if ordinal < 1 || ordinal > len(r.draft.CommandJob.Steps) || r.attempted[ordinal] || r.aborted {
		return StepExecution{}, errors.New("jobplan: invalid step dispatch")
	}
	r.attempted[ordinal] = true
	step := r.draft.CommandJob.Steps[ordinal-1]
	finish := func(out StepExecution) (StepExecution, error) {
		if out.Result.Status.Abort() {
			r.aborted = true
			r.Close()
		}
		if journal != nil && journal.AfterStep(ordinal, out.Result) != nil {
			r.Close()
			r.aborted = true
			return out, errors.New("jobplan: after-step journal failed")
		}
		return out, nil
	}
	refuse := func(status approvalplan.StepStatus, annotation string) (StepExecution, error) {
		return finish(StepExecution{Result: approvalplan.NoOutputResult(status, annotation), Outcome: Outcome{Status: status, Annotation: annotation, VerdictClass: string(status)}})
	}
	current, digest, err := r.registry.ReadCurrent(step.Target.ServerAlias)
	if err != nil || approvalplan.ValidateRouteSnapshot(current) != nil || digest != step.RegistryEntryDigest || current.Digest() != step.RegistryEntryDigest {
		detail := "target changed before dispatch"
		if err != nil && err.Error() == "registry unreadable" {
			detail = "registry unreadable"
		}
		r.Close()
		return refuse(approvalplan.StepStaleTarget, detail)
	}
	if step.Route.Signed() && r.guard(ordinal) != nil {
		return refuse(approvalplan.StepExpiredUnexecuted, "signature window closed before dispatch")
	}
	wire := step.ExactCommand
	var guard func() error
	if step.Route.Signed() {
		if !strings.HasPrefix(dispatch.WireCommand, "SSHGATE_SIG:") {
			r.Close()
			return refuse(approvalplan.StepFailedNotStarted, "missing signed command")
		}
		wire = dispatch.WireCommand
		guard = func() error {
			if err := r.guard(ordinal); err != nil {
				return err
			}
			if ordinal == r.lastSigned {
				r.Close()
			}
			return nil
		}
	}
	if journal != nil && journal.BeforeStep(ordinal) != nil {
		r.Close()
		r.aborted = true
		return StepExecution{}, errors.New("jobplan: before-step journal failed")
	}
	limit := int64(0)
	if r.budget != nil {
		limit = min(r.draft.CommandJob.MaxOutputBytes, approvalplan.MaxStreamOutputBytes)
	}
	stdout, stderr := newCapture(limit, r.budget), newCapture(limit, r.budget)
	exit, runErr := r.ssh.RunPhasedTo(ctx, current.ResolvedHost, current.ResolvedUser, current.ResolvedPort, wire, dispatch.Stdin, guard, stdout, stderr)
	outBytes, outTruncated := stdout.finish()
	errBytes, errTruncated := stderr.finish()
	kind := stepKind(step)
	outcomeStderr := errBytes
	if kind == UnsignedRead || kind == SignedWrite || kind == SignedReveal {
		outcomeStderr = stderr.outcomeBytes(errBytes)
	}
	outcome := StepOutcome(kind, earlierExecuted, PhasedResult{Stdout: outBytes, Stderr: outcomeStderr, ExitCode: exit, Err: runErr})
	result := approvalplan.StepResult{Status: outcome.Status, Annotation: outcome.Annotation,
		Stdout: outBytes, Stderr: errBytes, StdoutBytes: stdout.count, StderrBytes: stderr.count,
		StdoutSHA256: outputDigest(outBytes), StderrSHA256: outputDigest(errBytes), Truncated: outTruncated || errTruncated}
	if runErr == nil && exit >= 0 {
		result.ExitCode = &exit
	}
	return finish(StepExecution{Result: result, Outcome: outcome})
}

// Run executes an already-claimed batch. Stateful coordinators use RunStep
// when they need to Claim again between steps. JobView owns every stop rule.
func (r *Runner) Run(ctx context.Context, dispatches []Dispatch, journal StepJournal) (RunResult, error) {
	defer r.Close()
	if len(dispatches) != len(r.draft.CommandJob.Steps) {
		return RunResult{}, errors.New("jobplan: invalid dispatch count")
	}
	job := approvalplan.R2{RequestID: r.draft.RequestID, Draft: r.draft, Steps: make([]approvalplan.JobStep, len(dispatches))}
	out := RunResult{Steps: make([]StepExecution, len(dispatches))}
	for i, dispatch := range dispatches {
		view := approvalplan.JobView(job, "")
		if view.State == approvalplan.JobFinal {
			break
		}
		execution, err := r.RunStep(ctx, i+1, dispatch, len(view.ExecutedOrdinals) != 0, journal)
		out.Steps[i] = execution
		if err != nil {
			out.Summary = approvalplan.JobView(job, "")
			return out, err
		}
		job.Steps[i] = approvalplan.JobStep{Ordinal: i + 1, Result: &out.Steps[i].Result}
	}
	out.Summary = approvalplan.JobView(job, "")
	return out, nil
}

func stepKind(step approvalplan.Step) StepKind {
	if step.Route == approvalplan.RouteSignedAdmin {
		if step.ExactCommand == "SSHGATE_REVOKE" {
			return AdminRevoke
		}
		return AdminUpdate
	}
	return StepKind(step.Route)
}
