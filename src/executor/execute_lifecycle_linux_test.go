//go:build linux

package executor

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

type commandLifecycleAdapter struct{ engine *lifecycle.Engine }

func (a commandLifecycleAdapter) Submit(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
	return a.engine.Submit(c, st.PrincipalA, d)
}
func (a commandLifecycleAdapter) Get(c context.Context, id string) (ap.Summary, error) {
	return a.engine.Get(st.PrincipalA, id)
}
func (a commandLifecycleAdapter) Claim(c context.Context, id, h string, token [32]byte) (approvalwire.ClaimAnswer, error) {
	answer, err := a.engine.Claim(c, st.PrincipalA, id, ap.Claim{Token: token, PlanHash: h})
	result := approvalwire.ClaimAnswer{Status: answer.Claim, Class: answer.Class, Signatures: answer.Signatures}
	if !answer.DecidedAt.IsZero() {
		result.DecidedAt = &answer.DecidedAt
	}
	return result, lifecycleWireError(err)
}
func (a commandLifecycleAdapter) Report(c context.Context, id, h string, token [32]byte, r approvalwire.Report) error {
	_, err := a.engine.Report(st.PrincipalA, id, ap.Report{Token: token, PlanHash: h, Body: ap.FinalReport{Steps: r.Steps, Class: r.Class, ExecutedOrdinals: r.ExecutedOrdinals, Partial: r.Partial, ResultDigest: r.ResultDigest}})
	return lifecycleWireError(err)
}

type commandFreezer struct{}

func (commandFreezer) Freeze(c context.Context, d ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	return st.Freeze(d, principal, now, time.Hour), nil
}
func (commandFreezer) BuildSnapshot(c context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	return []byte(`{"segments":[]}`), p.Rationale, nil
}

type commandMinter struct {
	t   *testing.T
	job ap.R2
}

func (m commandMinter) Mint(c context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	return commandClaim(m.t, m.job).Signatures, nil
}

func TestCommandJobRealLifecycleReports(t *testing.T) {
	cases := []struct {
		mode       string
		dispatches int
		statuses   []ap.StepStatus
		class      ap.JobClass
		executed   []int
		partial    bool
	}{
		{"success", 3, []ap.StepStatus{ap.StepSucceeded, ap.StepSucceeded, ap.StepSucceeded}, ap.ClassSucceeded, []int{1, 2, 3}, false},
		{"mixed_indeterminate", 2, []ap.StepStatus{ap.StepFailed, ap.StepIndeterminate, ap.StepNotRun}, ap.ClassIndeterminate, []int{1, 2}, true},
		{"stop_on_error", 2, []ap.StepStatus{ap.StepSucceeded, ap.StepFailed, ap.StepSkipped}, ap.ClassFailed, []int{1, 2}, true},
		{"expired", 0, []ap.StepStatus{ap.StepExpiredUnexecuted, ap.StepNotRun, ap.StepNotRun}, ap.ClassExpiredUnexecuted, nil, false},
		{"jail_read", 1, []ap.StepStatus{ap.StepFailedNotStarted, ap.StepNotRun, ap.StepNotRun}, ap.ClassFailedNotStarted, nil, false},
		{"jail_signed", 1, []ap.StepStatus{ap.StepFailed}, ap.ClassFailed, []int{1}, false},
	}
	for _, want := range cases {
		t.Run(want.mode, func(t *testing.T) {
			mode := want.mode
			commands := []string{"cat /tmp/a", "touch /tmp/a", "touch /tmp/b"}
			if mode == "jail_signed" {
				commands = nil
			}
			s, store, _, request := commandFixture(t, commands...)
			job := store.jobs[request.Input.RequestID]
			if mode == "stop_on_error" {
				job.Draft.CommandJob.StopPolicy = ap.StopAnyNonzero
			}
			if mode == "jail_signed" {
				job.Draft.CommandJob.Steps[0].Route = ap.RouteSignedReveal
				job.Draft.CommandJob.Steps[0].SignatureTTLSeconds = 60
			}
			job.DraftHash, _ = ap.DraftHash(job.Draft)
			job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
			store.jobs[job.RequestID] = job
			model := st.NewSigner(&st.Clock{Wall: st.T0}, 42)
			key := ap.RecordKey(st.PrincipalA, job.RequestID)
			model.Submit(st.PrincipalA, job.Draft)
			model.AssistArrives(key, true)
			model.Reconcile(key)
			model.Tap(key, ap.VoteApprove, st.Operator, true)
			model.FlushPass()
			if model.Store[key].Header.Decision == nil || model.Store[key].Header.Decision.Status != ap.ApprovalApproved {
				t.Fatal("fixture not approved")
			}
			if model.Err != nil {
				t.Fatal(model.Err)
			}
			mem := &lifecycle.MemStore{}
			if err := mem.Commit(key, model.Store[key]); err != nil {
				t.Fatal(err)
			}
			engine, err := lifecycle.New(lifecycle.Config{Store: mem, Clock: s.clock, Freezer: commandFreezer{}, SnapshotBuilder: commandFreezer{}, Minter: commandMinter{t, job}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { engine.Close() })
			if mode == "expired" {
				s.clock.(interface{ Advance(time.Duration) }).Advance(5 * time.Minute)
			}
			calls := 0
			ssh := commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
				if e := g(); e != nil {
					return -1, &gatessh.PhasedError{Class: "guard_refused"}
				}
				calls++
				switch mode {
				case "mixed_indeterminate":
					if calls == 1 {
						return 1, nil
					}
					return -1, &gatessh.PhasedError{Class: "indeterminate"}
				case "stop_on_error":
					if calls == 2 {
						return 1, nil
					}
				case "jail_read", "jail_signed":
					io.WriteString(stderr, "gate: read jail unavailable: test")
					return 77, nil
				}
				return 0, nil
			})
			if err = s.StartCommandJobs(commandLifecycleAdapter{engine}, ssh); err != nil {
				t.Fatal(err)
			}
			final := waitCommand(t, s, job.RequestID, commandFinal)
			s.Close()
			if calls != want.dispatches {
				t.Errorf("dispatches = %d; want %d", calls, want.dispatches)
			}
			view := ap.JobView(final, s.epoch)
			if !slices.Equal(view.Steps, want.statuses) || view.Class != want.class || !slices.Equal(view.ExecutedOrdinals, want.executed) || view.Partial != want.partial {
				t.Errorf("executor outcome: steps=%v class=%s executed=%v partial=%t; want steps=%v class=%s executed=%v partial=%t", view.Steps, view.Class, view.ExecutedOrdinals, view.Partial, want.statuses, want.class, want.executed, want.partial)
			}
			if final.ReportResult == nil || final.ReportResult.State != ap.ReportAcked {
				t.Fatalf("real lifecycle refused: %+v", final)
			}
			record, err := mem.Load(key)
			if err != nil {
				t.Fatal(err)
			}
			report := record.Header.FinalReport
			if report == nil {
				t.Fatal("report missing from real lifecycle")
			}
			statuses := make([]ap.StepStatus, len(report.Steps))
			for i, step := range report.Steps {
				statuses[i] = step.Status
				if step.Ordinal != i+1 {
					t.Errorf("report step %d has ordinal %d", i+1, step.Ordinal)
				}
			}
			if !slices.Equal(statuses, want.statuses) || report.Class != want.class || !slices.Equal(report.ExecutedOrdinals, want.executed) || report.Partial != want.partial {
				t.Errorf("signer report: steps=%v class=%s executed=%v partial=%t; want steps=%v class=%s executed=%v partial=%t", statuses, report.Class, report.ExecutedOrdinals, report.Partial, want.statuses, want.class, want.executed, want.partial)
			}
		})
	}
}

func lifecycleWireError(err error) error {
	var code *ap.CodeError
	if errors.As(err, &code) {
		return &approvalwire.WireError{Code: code.Code}
	}
	return err
}

func TestCommandJobRealLifecycleTerminalClaims(t *testing.T) {
	for _, mode := range []string{"grant_not_live", "execution_reported"} {
		t.Run(mode, func(t *testing.T) {
			s, store, _, request := commandFixture(t)
			job := store.jobs[request.Input.RequestID]
			model := st.NewSigner(&st.Clock{Wall: st.T0}, 43)
			approve := func(id string) {
				key := ap.RecordKey(st.PrincipalA, id)
				model.AssistArrives(key, true)
				model.Reconcile(key)
				model.Tap(key, ap.VoteApprove, st.Operator, true)
				model.FlushPass()
			}
			if mode == "grant_not_live" {
				target := job.Draft.CommandJob.Steps[0].Target
				grant := st.GrantDraft(st.ID(2), target.ServerAlias, time.Hour, st.T0)
				grant.StandingGrant.TrustedHostFingerprint = target.TrustedHostFingerprint
				grant.StandingGrant.RegistryEntryDigest = target.Digest()
				model.Submit(st.PrincipalA, grant)
				approve(grant.RequestID)
			}
			key := ap.RecordKey(st.PrincipalA, job.RequestID)
			model.Submit(st.PrincipalA, job.Draft)
			if mode == "grant_not_live" {
				if decision := model.Store[key].Header.Decision; decision == nil || !strings.HasPrefix(decision.DecidedBy, ap.GrantDecidedPrefix) {
					t.Fatal("fixture did not use grant")
				}
				model.RevokeAlias(job.Draft.CommandJob.Steps[0].Target.ServerAlias)
			} else {
				approve(job.RequestID)
				raw, err := hex.DecodeString(job.ClaimToken)
				if err != nil {
					t.Fatal(err)
				}
				var token [32]byte
				copy(token[:], raw)
				if answer := model.Claim(key, token); answer.Claim != ap.ClaimSignatures {
					t.Fatal(answer)
				}
				reported := job
				reported.Steps = append([]ap.JobStep(nil), job.Steps...)
				result := ap.NoOutputResult(ap.StepSucceeded, "")
				zero := 0
				result.ExitCode = &zero
				reported.Steps[0].Result = &result
				if answer := model.Report(key, token, ap.JobReport(reported)); answer.Code != "" {
					t.Fatal(answer)
				}
			}
			model.FlushPass()
			if model.Err != nil {
				t.Fatal(model.Err)
			}
			mem := &lifecycle.MemStore{}
			for key, record := range model.Store {
				if err := mem.Commit(key, record); err != nil {
					t.Fatal(err)
				}
			}
			engine, err := lifecycle.New(lifecycle.Config{Store: mem, Clock: s.clock, Freezer: commandFreezer{}, SnapshotBuilder: commandFreezer{}, Minter: commandMinter{t, job}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { engine.Close() })
			if err = s.StartCommandJobs(commandLifecycleAdapter{engine}, commandSSHFunc(func(context.Context, string, func() error, io.Writer, io.Writer) (int, error) {
				t.Error("terminal Claim dispatched")
				return 0, nil
			})); err != nil {
				t.Fatal(err)
			}
			final := waitCommand(t, s, job.RequestID, commandFinal)
			s.Close()
			expected := ap.OutcomeJobError
			if mode == "execution_reported" {
				expected = ap.OutcomeAdopted
			}
			if final.Outcome == nil || final.Outcome.Kind != expected || final.ReportResult != nil {
				t.Fatalf("terminal Claim: %+v", final)
			}
		})
	}
}
