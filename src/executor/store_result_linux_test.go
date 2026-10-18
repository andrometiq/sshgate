//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/mcp/jobplan"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

func TestJobStoreResultConsistency(t *testing.T) {
	zero, one, refusal, negative := 0, 1, 77, -1
	for _, spec := range []st.StepSpec{st.Read("cat /tmp/job"), st.Write("touch /tmp/job", 60), st.Reveal("cat /tmp/secret")} {
		for _, status := range []ap.StepStatus{
			ap.StepSucceeded, ap.StepFailed, ap.StepFailedNotStarted,
			ap.StepIndeterminate, ap.StepExpiredUnexecuted, ap.StepStaleTarget,
		} {
			for _, exit := range []*int{nil, &zero, &one, &refusal, &negative} {
				label := "absent"
				if exit != nil {
					label = fmt.Sprint(*exit)
				}
				t.Run(string(spec.Route)+"/"+string(status)+"/"+label, func(t *testing.T) {
					valid := false
					switch status {
					case ap.StepSucceeded:
						valid = exit == &zero
					case ap.StepFailed:
						valid = exit == &one || exit == &refusal
					case ap.StepFailedNotStarted:
						valid = exit == nil || spec.Route == ap.RouteUnsignedRead && exit == &refusal
					default:
						valid = exit == nil
					}
					local, store, dir := jobStore(t)
					job := storeJob(t, 1, false)
					specs := []st.StepSpec{spec}
					if spec.Route == ap.RouteUnsignedRead {
						specs = append(specs, st.Write("touch /tmp/tail", 60))
						job.Steps = append(job.Steps, ap.JobStep{Ordinal: 2})
					}
					job.Draft = st.JobDraft(job.RequestID, ap.CoordinatorExecutor, st.T0, specs...)
					job.Draft.CommandJob.StopPolicy = ap.StopAnyNonzero
					job.DraftHash, _ = ap.DraftHash(job.Draft)
					job.InputHash = job.DraftHash
					job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
					job = dispatchFixture(t, job, 1)
					if err := store.Commit(job); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(dir, ap.JobKey(job.RequestID))
					original, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					result := ap.NoOutputResult(status, "")
					result.ExitCode = exit
					job.Steps[0].Result = &result
					at := st.T0
					if spec.Route.Signed() || status != ap.StepSucceeded {
						job.FinalAt = &at
					}
					body, err := ap.EncodeR2(job)
					if err != nil {
						t.Fatal("fixture must pass frozen schema", err)
					}
					err = store.Commit(job)
					if valid && err != nil || !valid && !errors.Is(err, ErrReportAuthLost) {
						t.Fatalf("commit: %v (valid=%t)", err, valid)
					}
					if !valid {
						after, err := os.ReadFile(path)
						if err != nil || !bytes.Equal(original, after) {
							t.Fatal("rejected commit changed disk", err)
						}
						loaded, err := store.Load(job.RequestID)
						if err != nil || loaded.Steps[0].Result != nil {
							t.Fatal("rejected commit changed snapshot", err)
						}
					}
					store.Close()
					if err := os.WriteFile(path, body, 0600); err != nil {
						t.Fatal(err)
					}
					reopened, err := local.OpenJobStore()
					if err != nil {
						t.Fatal(err)
					}
					defer reopened.Close()
					_, err = reopened.Load(job.RequestID)
					if valid && err != nil || !valid && !errors.Is(err, ErrReportAuthLost) {
						t.Fatalf("restart: %v (valid=%t)", err, valid)
					}
					files, err := reopened.List()
					if err != nil || len(files) != 1 || files[0].Quarantined == valid {
						t.Fatal("quarantine metadata", files, err)
					}
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(body, after) {
						t.Fatal("reopen changed evidence", err)
					}
				})
			}
		}
	}
	for _, status := range []ap.StepStatus{ap.StepSkipped, ap.StepNotRun, "unknown"} {
		if !errors.Is(validateStepResult(ap.NoOutputResult(status, ""), ap.RouteSignedWrite), ErrReportAuthLost) {
			t.Fatalf("accepted status %q", status)
		}
	}
}

type resultTransport struct {
	phased jobplan.PhasedResult
	called bool
}

func (r *resultTransport) RunPhasedTo(_ context.Context, _, _ string, _ int, _ string, _ io.Reader, guard func() error, stdout, stderr io.Writer) (int, error) {
	r.called = true
	if guard != nil {
		if err := guard(); err != nil {
			return 0, err
		}
	}
	_, _ = stdout.Write(r.phased.Stdout)
	_, _ = stderr.Write(r.phased.Stderr)
	return r.phased.ExitCode, r.phased.Err
}

type resultRegistry struct{ target ap.RouteSnapshot }

func (r resultRegistry) ReadCurrent(string) (ap.RouteSnapshot, string, error) {
	return r.target, r.target.Digest(), nil
}

// Exercise the real runner construction, not a test copy of its exit-code logic.
func TestStoredResultProducerDrift(t *testing.T) {
	rows := []struct {
		name   string
		phased jobplan.PhasedResult
	}{
		{"success", jobplan.PhasedResult{ExitCode: 0}},
		{"failed", jobplan.PhasedResult{ExitCode: 3}},
		{"jail_refusal", jobplan.PhasedResult{ExitCode: 77, Stderr: []byte("gate: read jail unavailable")}},
		{"jail_after_start", jobplan.PhasedResult{ExitCode: 77, Stderr: []byte("gate: read jail unavailable: the jail failed after the read may have started")}},
		{"negative_exit", jobplan.PhasedResult{ExitCode: -1}},
		{"not_started", jobplan.PhasedResult{Err: &gatessh.PhasedError{Class: "failed_not_started"}}},
		{"guard_refused", jobplan.PhasedResult{Err: &gatessh.PhasedError{Class: "guard_refused"}}},
		{"indeterminate", jobplan.PhasedResult{Err: &gatessh.PhasedError{Class: "indeterminate"}}},
		{"unknown_class", jobplan.PhasedResult{Err: &gatessh.PhasedError{Class: "unknown"}}},
		{"unknown_error", jobplan.PhasedResult{Err: errors.New("transport failure")}},
	}
	for _, spec := range []st.StepSpec{st.Read("cat /tmp/job"), st.Write("touch /tmp/job", 60), st.Reveal("cat /tmp/secret")} {
		for _, row := range rows {
			t.Run(string(spec.Route)+"/"+row.name, func(t *testing.T) {
				job := storeJob(t, 1, false)
				specs := []st.StepSpec{spec}
				if !spec.Route.Signed() {
					specs = append(specs, st.Write("touch /tmp/tail", 60))
					job.Steps = append(job.Steps, ap.JobStep{Ordinal: 2})
				}
				job.Draft = st.JobDraft(job.RequestID, ap.CoordinatorExecutor, st.T0, specs...)
				job.Draft.CommandJob.StopPolicy = ap.StopAnyNonzero
				job.DraftHash, _ = ap.DraftHash(job.Draft)
				job.InputHash = job.DraftHash
				job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
				job = dispatchFixture(t, job, 1)
				transport := &resultTransport{phased: row.phased}
				runner, err := jobplan.NewRunner(job.Draft, transport, resultRegistry{st.Route(spec.Alias)}, elapsedtest.NewFake(st.T0), 0)
				if err != nil {
					t.Fatal(err)
				}
				defer runner.Close()
				windows := make([]time.Time, len(specs))
				for i, step := range specs {
					if step.Route.Signed() {
						windows[i] = st.T0.Add(time.Minute)
					}
				}
				dispatch := jobplan.Dispatch{}
				if spec.Route.Signed() {
					dispatch.WireCommand = "SSHGATE_SIG:test"
				}
				if err := runner.HoldWindows(ap.Now{Wall: st.T0}, windows); err != nil {
					t.Fatal(err)
				}
				produced, err := runner.RunStep(context.Background(), 1, dispatch, false, nil)
				if err != nil || !transport.called {
					t.Fatal("runner did not reach transport", err)
				}
				kind := jobplan.UnsignedRead
				if spec.Route.Signed() {
					kind = jobplan.SignedWrite
				}
				if spec.Route == ap.RouteSignedReveal {
					kind = jobplan.SignedReveal
				}
				if produced.Result.Status != jobplan.StepOutcome(kind, false, row.phased).Status {
					t.Fatal("runner and outcome disagree")
				}
				job.Steps[0].Result = &produced.Result
				if spec.Route.Signed() || produced.Result.Status != ap.StepSucceeded {
					at := st.T0
					job.FinalAt = &at
				}
				_, store, _ := jobStore(t)
				if err := store.Commit(job); err != nil {
					t.Fatalf("producer result rejected: %+v: %v", produced.Result, err)
				}
			})
		}
	}
	for _, status := range []ap.StepStatus{ap.StepIndeterminate, ap.StepFailedNotStarted, ap.StepExpiredUnexecuted, ap.StepStaleTarget} {
		t.Run("no_output/"+string(status), func(t *testing.T) {
			job := dispatchFixture(t, storeJob(t, 1, false), 1)
			result := ap.NoOutputResult(status, "recovered or refused")
			job.Steps[0].Result = &result
			at := st.T0
			job.FinalAt = &at
			_, store, _ := jobStore(t)
			if err := store.Commit(job); err != nil {
				t.Fatal("NoOutputResult rejected", err)
			}
		})
	}
}
