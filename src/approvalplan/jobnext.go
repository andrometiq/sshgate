package approvalplan

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"
)

// Executor retention (SA-9, E75), counted from final_at.
const (
	BodyRetention       = 7 * 24 * time.Hour
	BodyPressureMinAge  = 24 * time.Hour
	JobFileRetention    = 30 * 24 * time.Hour
	BodiesRemovedAge    = "age"
	BodiesRemovedBudget = "pressure"
)

// JobActionKind names what JobNext asks the job's actor to do next.
type JobActionKind string

const (
	JobActNone JobActionKind = "none"
	// JobActSubmit resubmits the stored draft (idempotent).
	JobActSubmit JobActionKind = "submit"
	// JobActObserve reads the signer's view (Get or Wait).
	JobActObserve JobActionKind = "observe"
	// JobActClaim claims before Step: a signed step, or the first dispatch.
	JobActClaim JobActionKind = "claim"
	// JobActCheck runs a fresh registry.ReadCurrent for Step; report it
	// with JobOnCheck.
	JobActCheck JobActionKind = "check"
	// JobActDispatch commits Step's marker and, unless it answers
	// already_marked, runs the step under JobMemory.Guard and commits its
	// result.
	JobActDispatch JobActionKind = "dispatch"
	// JobActCommit applies Commit.
	JobActCommit JobActionKind = "commit"
	// JobActReport sends the one final report.
	JobActReport JobActionKind = "report"
)

// JobAction is JobNext's answer.
type JobAction struct {
	Kind   JobActionKind
	Step   int
	Signed bool
	Commit JobCommand
	Report FinalReport
}

// JobMemory is what a job's actor holds in memory in this process: never
// journaled, all lost at exit.
type JobMemory struct {
	// Approved: the signer's view was seen approved in this process.
	Approved bool
	// Claimed is the step the latest successful Claim was made for.
	Claimed int
	// Checked is the step whose ReadCurrent check passed.
	Checked int
	// Held are the step windows, each acquired once per process at the
	// first Claim answer that carried it (SA-1 rule 3.4).
	Held map[int]Held
	// Delivered: an await response delivered the final result.
	Delivered bool
}

// JobNext is the executor's reconciler (SA-5), the same function live and in
// recovery, run single-flight per job. Its order guarantees that no step is
// chosen for dispatch while evidence says otherwise.
func JobNext(job R2, now Now, epoch string, mem JobMemory) JobAction {
	now = now.norm()
	if jobFinal(job) {
		switch {
		case owesReport(job):
			return JobAction{Kind: JobActReport, Report: JobReport(job)}
		case mem.Delivered && job.FirstDeliveredAt == nil:
			return JobAction{Kind: JobActCommit, Commit: MarkDelivered{}}
		}
		return JobAction{Kind: JobActNone}
	}
	k := firstOpen(job)
	if m := job.Steps[k-1].Marker; m != nil {
		if m.Epoch == epoch {
			return JobAction{Kind: JobActNone}
		}
		return JobAction{Kind: JobActCommit, Commit: RecordResult{Ordinal: k, Result: NoOutputResult(StepIndeterminate, "")}}
	}
	if job.SignerAck == "" {
		return JobAction{Kind: JobActSubmit}
	}
	if !mem.Approved && !dispatched(job) {
		return JobAction{Kind: JobActObserve}
	}
	signed := stepSigned(job, k)
	if (signed || !dispatched(job)) && mem.Claimed != k {
		return JobAction{Kind: JobActClaim, Step: k, Signed: signed}
	}
	if mem.Checked != k {
		return JobAction{Kind: JobActCheck, Step: k, Signed: signed}
	}
	if !mem.Guard(job, k, now) {
		return JobAction{Kind: JobActCommit, Commit: RecordResult{Ordinal: k, Result: NoOutputResult(StepExpiredUnexecuted, "")}}
	}
	return JobAction{Kind: JobActDispatch, Step: k, Signed: signed}
}

// Guard is K16 for step k (E10): an unsigned step always passes; a signed
// step passes only on its held window. The actor calls it before the marker
// (through JobNext) and again as RunPhased's pre-start guard.
func (m JobMemory) Guard(job R2, k int, now Now) bool {
	if !stepSigned(job, k) {
		return true
	}
	h, ok := m.Held[k]
	return ok && h.PassesK16(now.norm())
}

// SignerAnswer is a signer call's answer, as the executor's client saw it.
type SignerAnswer struct {
	// Lost is a dial or transport failure, or a written request whose
	// response was lost: transient.
	Lost bool
	// Code is the refusal code, "" on success.
	Code Code
	// Decision is the record's approval status from Submit, Get or Wait.
	Decision ApprovalStatus
	// PlanHash is Submit's answer.
	PlanHash string
	// Claim, Class, DecidedAt and Windows are a Claim's answer.
	Claim     ClaimStatus
	Class     JobClass
	DecidedAt time.Time
	Windows   []time.Time
	// SentAt is both clocks read just before the call was sent: a Claim
	// answer's windows are acquired at it.
	SentAt Now
}

// JobOnAnswer classifies a signer answer to act with SA-5's one
// definitive/transient split: a transient answer changes nothing and is
// retried; a definitive one ends the job. It returns the command to commit
// (nil for none) and the actor's updated memory.
func JobOnAnswer(job R2, mem JobMemory, act JobAction, ans SignerAnswer) (JobCommand, JobMemory) {
	if ans.Lost || ans.Code.Retryable() {
		return nil, mem
	}
	switch act.Kind {
	case JobActSubmit:
		switch {
		case ans.Code == CodeSubmitWindowClosed:
			return SetOutcome{Outcome: JobOutcome{Kind: OutcomeApprovalLost}}, mem
		case ans.Code != "":
			return SetOutcome{Outcome: JobOutcome{Kind: OutcomeJobError, Code: ans.Code}}, mem
		case !ValidSHA256Hex(ans.PlanHash):
			return nil, mem
		}
		mem.Approved = mem.Approved || ans.Decision == ApprovalApproved
		return SignerAck{PlanHash: ans.PlanHash}, mem
	case JobActObserve:
		if ans.Code != "" {
			return SetOutcome{Outcome: JobOutcome{Kind: OutcomeJobError, Code: ans.Code}}, mem
		}
		if ans.Decision == ApprovalApproved {
			mem.Approved = true
			return nil, mem
		}
		return adoptDecision(ans.Decision), mem
	case JobActClaim:
		return claimAnswer(job, mem, act.Step, ans)
	case JobActReport:
		if ans.Code != "" {
			return SettleReport{Result: ReportResult{State: ReportRefused, Code: ans.Code}}, mem
		}
		return SettleReport{Result: ReportResult{State: ReportAcked}}, mem
	}
	return nil, mem
}

func adoptDecision(d ApprovalStatus) JobCommand {
	switch d {
	case ApprovalDenied:
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeDenied}}
	case ApprovalCanceled:
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeCanceled}}
	case ApprovalExpired:
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeExpired}}
	case ApprovalError:
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeJobError}}
	}
	return nil
}

// claimAnswer maps a Claim answer (SA-5 step 6). The coordinator Claims only
// after seeing approved, so expired is always the window's close.
func claimAnswer(job R2, mem JobMemory, k int, ans SignerAnswer) (JobCommand, JobMemory) {
	if ans.Code != "" {
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeJobError, Code: ans.Code}}, mem
	}
	switch ans.Claim {
	case ClaimSignatures:
		mem.Approved, mem.Claimed = true, k
		mem.Held = maps(mem.Held)
		for i, end := range ans.Windows {
			if _, held := mem.Held[i+1]; !held && !end.IsZero() && i < len(job.Steps) {
				mem.Held[i+1] = Acquire(ans.SentAt.norm(), end, time.Duration(stepTTL(job, i+1))*time.Second)
			}
		}
		return nil, mem
	case ClaimNotReady:
		return nil, mem
	case ClaimExpired:
		return RecordResult{Ordinal: k, Result: NoOutputResult(StepExpiredUnexecuted, "")}, mem
	case ClaimMaterializationError:
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeJobError}}, mem
	case ClaimExecutionReported:
		return SetOutcome{Outcome: JobOutcome{Kind: OutcomeAdopted, Class: ans.Class}}, mem
	}
	return adoptDecision(ApprovalStatus(ans.Claim)), mem
}

func maps(m map[int]Held) map[int]Held {
	out := make(map[int]Held, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// JobOnCheck records step k's ReadCurrent check: a failure commits
// stale_target with no marker; a pass is memory only.
func JobOnCheck(mem JobMemory, k int, passed bool) (JobCommand, JobMemory) {
	if !passed {
		return RecordResult{Ordinal: k, Result: NoOutputResult(StepStaleTarget, "")}, mem
	}
	mem.Checked = k
	return nil, mem
}

var emptySHA256 = func() string { s := sha256.Sum256(nil); return hex.EncodeToString(s[:]) }()

// NoOutputResult is a step result with no output: a check failure, a K16
// failure, an orphan marker's indeterminate.
func NoOutputResult(status StepStatus, annotation string) StepResult {
	return StepResult{Status: status, StdoutSHA256: emptySHA256, StderrSHA256: emptySHA256, Annotation: annotation}
}

// owesReport: the job is final through its step results (so an approval was
// seen), no outcome ended it, and no answer has settled the report.
func owesReport(job R2) bool {
	return jobFinal(job) && job.Outcome == nil && job.ReportResult == nil
}

// JobReport is the one final report, a canonical function of the job record
// (E38), so a resend is an exact duplicate: every ordinal, a derived status
// with no other field for a step without a result, and a result digest from
// the stored per-step digests, never the bodies.
func JobReport(job R2) FinalReport {
	statuses := jobStatuses(job)
	r := FinalReport{
		Class: AggregateJobClass(statuses), ExecutedOrdinals: ExecutedOrdinals(statuses), Partial: Partial(statuses),
	}
	type digestStep struct {
		StepReport
		StdoutSHA256 string `json:"stdout_sha256,omitempty"`
		StderrSHA256 string `json:"stderr_sha256,omitempty"`
	}
	digested := make([]digestStep, len(statuses))
	for i, st := range statuses {
		sr := StepReport{Ordinal: i + 1, Status: st}
		if res := job.Steps[i].Result; res != nil {
			out, errBytes, truncated := res.StdoutBytes, res.StderrBytes, res.Truncated
			sr.ExitCode, sr.StdoutBytes, sr.StderrBytes, sr.Truncated = res.ExitCode, &out, &errBytes, &truncated
			digested[i] = digestStep{sr, res.StdoutSHA256, res.StderrSHA256}
		} else {
			digested[i] = digestStep{StepReport: sr}
		}
		r.Steps = append(r.Steps, sr)
	}
	r.ResultDigest = hashHex("sshgate-job-result-v1\x00", mustCanonical(digested))
	r.BodyDigest = ReportDigest(r)
	return r
}

// ExecSubmitAdmit is exec_submit's check of a new ID before admission (SA-5):
// the caller-fixed window (submit_window_closed once passed; invalid_request
// more than 3600 s + 5 s ahead, the MCP having fixed it moments before), then
// the job's reservation against R2Max. "" admits it to the caps.
func ExecSubmitAdmit(now time.Time, d ApprovalDraft, maxOutputBytes int64) Code {
	switch {
	case now.After(d.SubmitNotAfter):
		return CodeSubmitWindowClosed
	case d.SubmitNotAfter.After(now.Add(SubmitWindowMax + LocalSkew)):
		return CodeInvalidRequest
	case R2Reservation(d, maxOutputBytes) > R2Max:
		return CodeRequestTooLarge
	}
	return ""
}

func hasBodies(job R2) bool {
	return slices.ContainsFunc(job.Steps, func(s JobStep) bool {
		return s.Result != nil && (len(s.Result.Stdout) > 0 || len(s.Result.Stderr) > 0)
	})
}

func reportSettled(job R2) bool { return !owesReport(job) }

// JobRetention is the executor's retention planner for one final job (SA-9):
// remove bodies at final_at + 7 d, or under budget pressure once delivered at
// least 24 h ago (never while undelivered); drop the raw token once the
// report is settled or never owed and the bodies are gone. nil: nothing due.
func JobRetention(job R2, now Now, bodyPressure bool) JobCommand {
	now = now.norm()
	if !jobFinal(job) || job.FinalAt == nil {
		return nil
	}
	if hasBodies(job) && job.BodiesRemoved == nil {
		switch {
		case !now.Wall.Before(job.FinalAt.Add(BodyRetention)):
			return RemoveBodies{Cause: BodiesRemovedAge}
		case bodyPressure && job.FirstDeliveredAt != nil && !now.Wall.Before(job.FirstDeliveredAt.Add(BodyPressureMinAge)):
			return RemoveBodies{Cause: BodiesRemovedBudget}
		}
		return nil
	}
	if job.ClaimToken != "" && reportSettled(job) {
		return DropToken{}
	}
	return nil
}

// JobDeletable is SA-9's one job-file deletion predicate, for the age path
// and the count path alike: final; bodies removed or never had any; report
// settled or never owed; past submit_not_after + 24 h; and then 30 d after
// final_at, or earlier under count pressure.
func JobDeletable(job R2, now Now, countPressure bool) bool {
	now = now.norm()
	if !jobFinal(job) || job.FinalAt == nil || (hasBodies(job) && job.BodiesRemoved == nil) || !reportSettled(job) ||
		now.Wall.Before(job.Draft.SubmitNotAfter.Add(DeleteFloor)) {
		return false
	}
	return countPressure || !now.Wall.Before(job.FinalAt.Add(JobFileRetention))
}
