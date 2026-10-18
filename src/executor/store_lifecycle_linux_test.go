//go:build linux

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func dispatchFixture(t *testing.T, job ap.R2, ordinal int) ap.R2 {
	t.Helper()
	if job.SignerAck == "" {
		job, _ = ap.ApplyJob(job, ap.SignerAck{PlanHash: job.DraftHash}, ap.Now{Wall: st.T0}, st.Epoch(1))
	}
	next, answer := ap.ApplyJob(job, ap.MarkStep{Ordinal: ordinal}, ap.Now{Wall: st.T0}, st.Epoch(1))
	if !answer.Changed {
		t.Fatal(answer)
	}
	return next
}

// Every fixture is canonical under the frozen schema. Both entry paths must
// enforce lifecycle relationships without modifying quarantined evidence.
func TestJobStoreLifecycle(t *testing.T) {
	cases := []string{
		"live_report", "live_delivery", "live_removal", "result_gap", "marker_gap",
		"marker_after_abort", "result_after_abort", "marker_after_stop", "result_after_stop",
		"outcome_after_terminal", "outcome_report", "derived_not_run", "derived_skipped",
		"result_without_marker", "indeterminate_without_marker", "evidence_without_ack",
		"removal_without_bodies", "removal_unknown_cause", "pressure_without_delivery", "removed_bodies_present",
		"approval_lost_after_ack", "denied_without_ack", "outcome_inflight", "valid_live", "valid_inflight", "valid_abort", "valid_continue",
		"valid_outcome_prefix", "valid_error_inflight", "valid_removed", "valid_pressure", "valid_unstorable",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			local, store, dir := jobStore(t)
			job := storeJob(t, 1, true)
			if err := store.Commit(job); err != nil {
				t.Fatal(err)
			}
			original, err := ap.EncodeR2(job)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ap.JobKey(job.RequestID))
			job.SignerAck = job.DraftHash
			marker := func(i int) { job.Steps[i].Marker = &ap.Marker{Epoch: st.Epoch(1), At: st.T0} }
			result := func(i int, status ap.StepStatus) {
				r := ap.NoOutputResult(status, "")
				if status == ap.StepSucceeded || status == ap.StepFailed {
					exit := 0
					if status == ap.StepFailed {
						exit = 1
					}
					r.ExitCode = &exit
				}
				job.Steps[i].Result = &r
			}
			finish := func() { at := st.T0; job.FinalAt = &at }
			outcome := func() { job.Outcome = &ap.JobOutcome{Kind: ap.OutcomeJobError}; finish() }
			report := func() { job.ReportResult = &ap.ReportResult{State: ap.ReportAcked} }
			removed := func() {
				marker(0)
				result(0, ap.StepFailed)
				digest := sha256.Sum256([]byte("x"))
				job.Steps[0].Result.StdoutSHA256 = hex.EncodeToString(digest[:])
				job.Steps[0].Result.StdoutBytes = 1
				job.BodiesRemoved = &ap.BodiesRemoved{Cause: ap.BodiesRemovedAge}
				finish()
			}
			switch name {
			case "live_report":
				report()
			case "live_delivery":
				at := st.T0
				job.FirstDeliveredAt = &at
			case "live_removal":
				job.BodiesRemoved = &ap.BodiesRemoved{Cause: ap.BodiesRemovedAge}
			case "result_gap":
				marker(1)
				result(1, ap.StepIndeterminate)
			case "marker_gap":
				marker(1)
			case "marker_after_abort", "result_after_abort":
				result(0, ap.StepExpiredUnexecuted)
				finish()
				marker(1)
				if name == "result_after_abort" {
					result(1, ap.StepSucceeded)
				}
			case "marker_after_stop", "result_after_stop":
				marker(0)
				result(0, ap.StepFailed)
				finish()
				marker(1)
				if name == "result_after_stop" {
					result(1, ap.StepSucceeded)
				}
			case "outcome_after_terminal":
				result(0, ap.StepExpiredUnexecuted)
				outcome()
			case "outcome_report":
				outcome()
				report()
			case "derived_not_run":
				result(0, ap.StepNotRun)
			case "derived_skipped":
				result(0, ap.StepSkipped)
			case "result_without_marker":
				result(0, ap.StepSucceeded)
			case "indeterminate_without_marker":
				result(0, ap.StepIndeterminate)
				finish()
			case "evidence_without_ack":
				marker(0)
				job.SignerAck = ""
			case "removal_without_bodies":
				removed()
				job.Steps[0].Result.StdoutBytes = 0
			case "removal_unknown_cause":
				removed()
				job.BodiesRemoved.Cause = "unknown"
			case "pressure_without_delivery":
				removed()
				job.BodiesRemoved.Cause = ap.BodiesRemovedBudget
			case "removed_bodies_present":
				removed()
				job.Steps[0].Result.Stdout = []byte("x")
			case "approval_lost_after_ack":
				outcome()
				job.Outcome.Kind = ap.OutcomeApprovalLost
			case "denied_without_ack":
				outcome()
				job.Outcome.Kind = ap.OutcomeDenied
				job.SignerAck = ""
			case "outcome_inflight":
				marker(0)
				outcome()
				job.Outcome.Kind = ap.OutcomeDenied
			case "valid_inflight":
				marker(0)
			case "valid_abort":
				result(0, ap.StepStaleTarget)
				finish()
			case "valid_continue":
				job.Draft.CommandJob.StopPolicy = ap.StopNever
				marker(0)
				result(0, ap.StepFailed)
				marker(1)
			case "valid_outcome_prefix":
				marker(0)
				result(0, ap.StepSucceeded)
				outcome()
			case "valid_error_inflight":
				marker(0)
				outcome()
			case "valid_removed", "valid_pressure":
				removed()
				if name == "valid_pressure" {
					job.BodiesRemoved.Cause = ap.BodiesRemovedBudget
					at := st.T0
					job.FirstDeliveredAt = &at
				}
			case "valid_unstorable":
				marker(0)
				result(0, ap.StepSucceeded)
				job.Steps[0].Result.BodiesUnstorable = true
				job.Steps[0].Result.StdoutBytes = 1
			}
			job.DraftHash, _ = ap.DraftHash(job.Draft)
			job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
			valid := strings.HasPrefix(name, "valid_")
			// Retained bodies with a removal flag fail the schema too; the boundary
			// must still return the same authority failure.
			body, err := ap.EncodeR2(job)
			if name == "removed_bodies_present" {
				if err == nil {
					t.Fatal("schema accepted retained removed body")
				}
				if !errors.Is(store.Commit(job), ErrReportAuthLost) {
					t.Fatal("commit accepted removed body")
				}
				return
			}
			if err != nil {
				t.Fatal("fixture schema", err)
			}
			err = store.Commit(job)
			if valid && err != nil || !valid && !errors.Is(err, ErrReportAuthLost) {
				t.Fatalf("commit: %v", err)
			}
			if !valid {
				unchanged, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(original, unchanged) {
					t.Fatal("refused commit changed disk", err)
				}
				loaded, err := store.Load(job.RequestID)
				if err != nil || loaded.SignerAck != "" {
					t.Fatal("refused commit changed snapshot", err)
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
				t.Fatalf("restart: %v", err)
			}
			files, err := reopened.List()
			if err != nil || len(files) != 1 || files[0].Quarantined == valid || files[0].EncodedBytes != int64(len(body)) {
				t.Fatal("restart metadata", files, err)
			}
			if !valid {
				if !errors.Is(reopened.Commit(job), ErrReportAuthLost) || !errors.Is(reopened.Remove(job.RequestID), ErrReportAuthLost) {
					t.Fatal("quarantine not protected")
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatal("evidence changed", err)
			}
		})
	}
}
