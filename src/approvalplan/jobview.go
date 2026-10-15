package approvalplan

import "slices"

// JobState is the executor job's state, a pure view of its R2 record (E29).
// The record cannot tell a pending signer decision from an approved one, so
// an acknowledged job's approval status comes from the signer.
type JobState string

const (
	JobSubmitted    JobState = "submitted"
	JobAcknowledged JobState = "acknowledged"
	JobApproved     JobState = "approved"
	JobExecuting    JobState = "executing"
	JobFinal        JobState = "final"
)

// JobSummary is what exec_get, exec_await and exec_list read.
type JobSummary struct {
	RequestID string   `json:"request_id"`
	State     JobState `json:"state"`
	// Executing is the ordinal in flight in this epoch.
	Executing int `json:"executing,omitempty"`
	// Steps holds the stored results' statuses, and for a final job every
	// step: not_run after an abort or an outcome, skipped after a
	// stop-policy stop (E29).
	Steps            []StepStatus `json:"steps"`
	Class            JobClass     `json:"class,omitempty"`
	ExecutedOrdinals []int        `json:"executed_ordinals"`
	Partial          bool         `json:"partial,omitempty"`
	Outcome          *JobOutcome  `json:"outcome,omitempty"`
}

// JobView derives the job's state from its slots (E29). It judges no
// deadline and never writes.
func JobView(job R2, epoch string) JobSummary {
	sum := JobSummary{RequestID: job.RequestID, State: JobSubmitted}
	if job.Outcome != nil {
		o := *job.Outcome
		sum.Outcome = &o
	}
	sum.Steps = jobStatuses(job)
	sum.ExecutedOrdinals = ExecutedOrdinals(sum.Steps)
	switch {
	case jobFinal(job):
		sum.State = JobFinal
		sum.Partial = Partial(sum.Steps)
		switch {
		case job.Outcome == nil:
			sum.Class = AggregateJobClass(sum.Steps)
		case job.Outcome.Kind == OutcomeAdopted:
			sum.Class = job.Outcome.Class
		}
	case inFlight(job, epoch) > 0:
		sum.State, sum.Executing = JobExecuting, inFlight(job, epoch)
	case dispatched(job):
		sum.State = JobApproved
	case job.SignerAck != "":
		sum.State = JobAcknowledged
	}
	return sum
}

// resultEnd reports whether the stored results end the job (E29): an abort
// status, a stop-policy stop, or the last step's result. tail is the derived
// status of every later step.
func resultEnd(job R2) (ended bool, tail StepStatus) {
	for i, s := range job.Steps {
		r := s.Result
		switch {
		case r == nil:
			return false, ""
		case r.Status.Abort():
			return true, StepNotRun
		case r.Status == StepFailed && stopsAfter(job, i+1):
			return true, StepSkipped
		case i == len(job.Steps)-1:
			return true, ""
		}
	}
	return false, ""
}

func jobFinal(job R2) bool {
	ended, _ := resultEnd(job)
	return ended || job.Outcome != nil
}

// stopsAfter applies the job's stop policy (E30) to a failed step k: the
// class default stops only after a failed signed step.
func stopsAfter(job R2, k int) bool {
	j := job.Draft.CommandJob
	if j == nil {
		return true
	}
	switch j.StopPolicy {
	case StopAnyNonzero:
		return true
	case StopNever:
		return false
	}
	return j.Steps[k-1].Route.Signed()
}

// jobStatuses is the stored results' statuses, completed for a final job.
func jobStatuses(job R2) []StepStatus {
	out := []StepStatus{}
	for _, s := range job.Steps {
		if s.Result == nil {
			break
		}
		out = append(out, s.Result.Status)
	}
	ended, tail := resultEnd(job)
	if !ended && job.Outcome == nil {
		return out
	}
	if job.Outcome != nil {
		tail = StepNotRun
	}
	for len(out) < len(job.Steps) {
		out = append(out, tail)
	}
	return out
}

// firstOpen is the ordinal of the first step with no result, or 0.
func firstOpen(job R2) int {
	for i, s := range job.Steps {
		if s.Result == nil {
			return i + 1
		}
	}
	return 0
}

// inFlight is the ordinal whose marker is from epoch and has no result.
func inFlight(job R2, epoch string) int {
	k := firstOpen(job)
	if k > 0 && job.Steps[k-1].Marker != nil && job.Steps[k-1].Marker.Epoch == epoch {
		return k
	}
	return 0
}

// dispatched reports whether any step has a marker or a result: a first
// dispatch needed a successful Claim, so this proves approval.
func dispatched(job R2) bool {
	for _, s := range job.Steps {
		if s.Marker != nil || s.Result != nil {
			return true
		}
	}
	return false
}

// stepSigned reports whether job step k carries a signature (a transfer's one
// step carries two).
func stepSigned(job R2, k int) bool {
	if j := job.Draft.CommandJob; j != nil {
		return j.Steps[k-1].Route.Signed()
	}
	return true
}

func stepTTL(job R2, k int) int {
	if j := job.Draft.CommandJob; j != nil {
		return j.Steps[k-1].SignatureTTLSeconds
	}
	return job.Draft.Transfer.SignatureTTLSeconds
}

// JobCommand is one commit on an executor job record (SA-3 R2). ApplyJob is
// the executor's one commit function, as Apply is the signer's.
type JobCommand interface{ isJobCommand() }

// SignerAck records the plan_hash the signer's Submit answered.
type SignerAck struct{ PlanHash string }

// SetOutcome ends a job without a step result ending it.
type SetOutcome struct{ Outcome JobOutcome }

// MarkStep commits step k's dispatch marker before Start (invariant 7).
type MarkStep struct{ Ordinal int }

// RecordResult commits step k's result together with its bodies.
type RecordResult struct {
	Ordinal int
	Result  StepResult
}

// SettleReport commits the report's settlement: acked, or refused on a
// definitive answer.
type SettleReport struct{ Result ReportResult }

// MarkDelivered commits first_delivered_at after an await delivered the
// final result.
type MarkDelivered struct{}

// RemoveBodies drops every step's bodies, keeping sizes and digests.
type RemoveBodies struct{ Cause string }

// DropToken removes the raw claim token.
type DropToken struct{}

func (SignerAck) isJobCommand()     {}
func (SetOutcome) isJobCommand()    {}
func (MarkStep) isJobCommand()      {}
func (RecordResult) isJobCommand()  {}
func (SettleReport) isJobCommand()  {}
func (MarkDelivered) isJobCommand() {}
func (RemoveBodies) isJobCommand()  {}
func (DropToken) isJobCommand()     {}

// JobAnswer is a job commit's answer. Changed says the store must commit the
// returned record. Refused names why a command did not apply.
type JobAnswer struct {
	Changed       bool
	AlreadyMarked bool
	Refused       string
}

// ApplyJob applies one command to a job record at now. The commit that first
// makes the job final also sets final_at = now, and no other commit touches
// it (SA-3 R2). A command whose guard fails changes nothing.
func ApplyJob(job R2, cmd JobCommand, now Now, epoch string) (R2, JobAnswer) {
	now = now.norm()
	wasFinal := jobFinal(job)
	next := job
	next.Steps = slices.Clone(job.Steps)
	at := now.Wall
	refuse := func(why string) (R2, JobAnswer) { return job, JobAnswer{Refused: why} }
	switch cmd := cmd.(type) {
	case SignerAck:
		if job.SignerAck == cmd.PlanHash {
			return job, JobAnswer{}
		}
		if job.SignerAck != "" {
			return refuse("signer_ack: already holds another plan_hash")
		}
		next.SignerAck = cmd.PlanHash
	case SetOutcome:
		if wasFinal {
			return refuse("final")
		}
		o := cmd.Outcome
		next.Outcome = &o
	case MarkStep:
		if wasFinal || cmd.Ordinal != firstOpen(job) {
			return refuse("not_next")
		}
		if job.Steps[cmd.Ordinal-1].Marker != nil {
			return job, JobAnswer{AlreadyMarked: true}
		}
		next.Steps[cmd.Ordinal-1].Marker = &Marker{Epoch: epoch, At: at}
	case RecordResult:
		if wasFinal || cmd.Ordinal != firstOpen(job) {
			return refuse("not_next")
		}
		r := cmd.Result
		next.Steps[cmd.Ordinal-1].Result = &r
	case SettleReport:
		if !owesReport(job) {
			return refuse("not_owed")
		}
		r := cmd.Result
		next.ReportResult = &r
	case MarkDelivered:
		if !wasFinal || job.FirstDeliveredAt != nil {
			return refuse("not_due")
		}
		next.FirstDeliveredAt = &at
	case RemoveBodies:
		if !wasFinal || job.FinalAt == nil || job.BodiesRemoved != nil || !hasBodies(job) {
			return refuse("not_due")
		}
		switch cmd.Cause {
		case BodiesRemovedAge:
			if now.Wall.Before(job.FinalAt.Add(BodyRetention)) {
				return refuse("not_due")
			}
		case BodiesRemovedBudget:
			if job.FirstDeliveredAt == nil || now.Wall.Before(job.FirstDeliveredAt.Add(BodyPressureMinAge)) {
				return refuse("not_due")
			}
		default:
			return refuse("unsupported cause")
		}
		for i, s := range next.Steps {
			if s.Result != nil {
				r := *s.Result
				r.Stdout, r.Stderr = nil, nil
				next.Steps[i].Result = &r
			}
		}
		next.BodiesRemoved = &BodiesRemoved{Cause: cmd.Cause}
	case DropToken:
		if job.ClaimToken == "" || !wasFinal || !reportSettled(job) || hasBodies(job) {
			return refuse("not_due")
		}
		next.ClaimToken = ""
	default:
		return refuse("unknown command")
	}
	if !wasFinal && jobFinal(next) {
		next.FinalAt = &at
	}
	if err := next.validate(); err != nil {
		return refuse(err.Error())
	}
	return next, JobAnswer{Changed: true}
}
