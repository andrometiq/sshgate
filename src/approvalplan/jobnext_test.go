package approvalplan_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

var (
	epoch1 = st.Epoch(1)
	epoch2 = st.Epoch(2)
)

// jobRig is one job record, committed through ApplyJob and checked by
// statetest's job invariants.
type jobRig struct {
	t   *testing.T
	job ap.R2
	now ap.Now
	mem ap.JobMemory
	ep  string
}

func newJob(t *testing.T, policy ap.StopPolicy, specs ...st.StepSpec) *jobRig {
	t.Helper()
	d := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, specs...)
	d.CommandJob.StopPolicy = policy
	hash, err := ap.DraftHash(d)
	if err != nil {
		t.Fatal(err)
	}
	tok := st.Token(st.ID(1))
	job := ap.R2{
		Version: ap.R2Version, RequestID: d.RequestID, InputHash: hash, Draft: d, DraftHash: hash, CreatedAt: st.T0,
		Reservation: int64(ap.R2Reservation(d, ap.MaxJobOutputBytes)), ClaimToken: hex.EncodeToString(tok[:]),
		Steps: make([]ap.JobStep, len(specs)),
	}
	for i := range job.Steps {
		job.Steps[i].Ordinal = i + 1
	}
	return &jobRig{t: t, job: job, now: ap.Now{Wall: st.T0, Elapsed: time.Hour}, ep: epoch1}
}

func (j *jobRig) do(cmd ap.JobCommand) ap.JobAnswer {
	j.t.Helper()
	after, ans := ap.ApplyJob(j.job, cmd, j.now, j.ep)
	if ans.Changed {
		if err := st.CheckJobTransition(&j.job, after, j.now, j.ep); err != nil {
			j.t.Fatalf("%T: %v", cmd, err)
		}
		j.job = after
	} else if ans.Refused != "" && ans.Refused != "not_due" && ans.Refused != "not_next" && ans.Refused != "final" && ans.Refused != "not_owed" {
		j.t.Fatalf("%T refused: %s", cmd, ans.Refused)
	}
	return ans
}

func (j *jobRig) next() ap.JobAction { return ap.JobNext(j.job, j.now, j.ep, j.mem) }

// answer feeds a signer answer for act through JobOnAnswer and commits it.
func (j *jobRig) answer(act ap.JobAction, ans ap.SignerAnswer) {
	j.t.Helper()
	var cmd ap.JobCommand
	cmd, j.mem = ap.JobOnAnswer(j.job, j.mem, act, ans)
	if cmd != nil {
		j.do(cmd)
	}
}

func result(status ap.StepStatus) ap.StepResult {
	r := ap.NoOutputResult(status, "")
	if status == ap.StepSucceeded || status == ap.StepFailed {
		exit := 0
		if status == ap.StepFailed {
			exit = 1
		}
		r.ExitCode = &exit
	}
	return r
}

// windows is a Claim answer's per-step windows for a decision at decided.
func (j *jobRig) windows(decided time.Time) []time.Time {
	out := make([]time.Time, len(j.job.Steps))
	for i, s := range j.job.Draft.CommandJob.Steps {
		if s.Route.Signed() {
			out[i] = time.Unix(decided.Unix()+int64(s.SignatureTTLSeconds), 0).UTC()
		}
	}
	return out
}

func (j *jobRig) signatures(decided time.Time) ap.SignerAnswer {
	return ap.SignerAnswer{Claim: ap.ClaimSignatures, DecidedAt: decided, Windows: j.windows(decided), SentAt: j.now}
}

// approve walks the job to approved in memory: ack, then an observed approval.
func (j *jobRig) approve() {
	j.t.Helper()
	j.answer(ap.JobAction{Kind: ap.JobActSubmit}, ap.SignerAnswer{PlanHash: fmt.Sprintf("%064x", 1), Decision: ap.ApprovalApproved})
}

// runStep drives JobNext through claim, check and dispatch of the next step
// with the given claim answer, and commits the step's result; it returns the
// actions JobNext yielded.
func (j *jobRig) runStep(claim ap.SignerAnswer, status ap.StepStatus, runFor time.Duration) []ap.JobActionKind {
	j.t.Helper()
	var kinds []ap.JobActionKind
	for range 6 {
		act := j.next()
		kinds = append(kinds, act.Kind)
		switch act.Kind {
		case ap.JobActClaim:
			j.answer(act, claim)
		case ap.JobActCheck:
			var cmd ap.JobCommand
			cmd, j.mem = ap.JobOnCheck(j.mem, act.Step, true)
			if cmd != nil {
				j.do(cmd)
			}
		case ap.JobActCommit:
			j.do(act.Commit)
			return kinds
		case ap.JobActDispatch:
			if ans := j.do(ap.MarkStep{Ordinal: act.Step}); ans.AlreadyMarked {
				return kinds
			}
			j.now.Wall, j.now.Elapsed = j.now.Wall.Add(runFor), j.now.Elapsed+runFor
			j.do(ap.RecordResult{Ordinal: act.Step, Result: result(status)})
			return kinds
		default:
			return kinds
		}
	}
	return kinds
}

var abortStatuses = []ap.StepStatus{ap.StepFailedNotStarted, ap.StepExpiredUnexecuted, ap.StepStaleTarget, ap.StepIndeterminate}

// JobNext precedence: final evidence is never followed by a dispatch.
func TestJobNextPrecedence(t *testing.T) {
	for _, status := range abortStatuses {
		for _, policy := range []ap.StopPolicy{ap.StopClassDefaultWritesOnly, ap.StopAnyNonzero, ap.StopNever} {
			for _, last := range []bool{true, false} {
				for _, orphan := range []bool{false, true} {
					specs := []st.StepSpec{st.Write("a", 60)}
					if !last {
						specs = append(specs, st.Write("b", 60))
					}
					j := newJob(t, policy, specs...)
					j.approve()
					j.do(ap.RecordResult{Ordinal: 1, Result: result(status)})
					if orphan && !last {
						j.job.Steps[1].Marker = &ap.Marker{Epoch: epoch2, At: st.T0}
					}
					j.ep = epoch2
					act := j.next()
					v := ap.JobView(j.job, j.ep)
					if act.Kind != ap.JobActReport || v.State != ap.JobFinal || v.Class != ap.JobClass(status) {
						t.Fatalf("%s/%s/last=%v/orphan=%v: %s, view %+v", status, policy, last, orphan, act.Kind, v)
					}
					if !last && v.Steps[1] != ap.StepNotRun {
						t.Fatalf("tail %v", v.Steps)
					}
				}
			}
		}
	}
	// A check failure written without a marker ends the job: no dispatch.
	j := newJob(t, ap.StopNever, st.Write("a", 60), st.Read("r"))
	j.approve()
	cmd, _ := ap.JobOnCheck(j.mem, 1, false)
	j.do(cmd)
	if act := j.next(); act.Kind != ap.JobActReport {
		t.Fatalf("after a check failure: %s", act.Kind)
	}
	// An orphan marker from another epoch becomes indeterminate first.
	j = newJob(t, ap.StopNever, st.Write("a", 60), st.Read("r"))
	j.approve()
	j.do(ap.MarkStep{Ordinal: 1})
	j.ep = epoch2
	act := j.next()
	if c, ok := act.Commit.(ap.RecordResult); act.Kind != ap.JobActCommit || !ok || c.Result.Status != ap.StepIndeterminate {
		t.Fatalf("orphan marker: %+v", act)
	}
	j.do(act.Commit)
	if v := ap.JobView(j.job, j.ep); v.State != ap.JobFinal || !slices.Equal(v.Steps, []ap.StepStatus{ap.StepIndeterminate, ap.StepNotRun}) {
		t.Fatalf("view %+v", v)
	}
}

// Single flight (r5.1): a current-epoch marker with no result is in flight,
// and a second Marker answers already_marked.
func TestJobSingleFlight(t *testing.T) {
	j := newJob(t, ap.StopNever, st.Write("a", 60))
	j.approve()
	j.do(ap.MarkStep{Ordinal: 1})
	if act := j.next(); act.Kind != ap.JobActNone {
		t.Fatalf("in flight: %s", act.Kind)
	}
	if v := ap.JobView(j.job, j.ep); v.State != ap.JobExecuting || v.Executing != 1 {
		t.Fatalf("view %+v", v)
	}
	if ans := j.do(ap.MarkStep{Ordinal: 1}); !ans.AlreadyMarked || ans.Changed {
		t.Fatalf("second marker %+v", ans)
	}
}

// Unsigned steps (r5.2): no Claim and no K16 after the first dispatch.
func TestJobUnsignedSteps(t *testing.T) {
	decided := st.T0
	for _, restart := range []bool{false, true} {
		j := newJob(t, ap.StopNever, st.Write("w", 60), st.Read("r"))
		j.approve()
		j.runStep(j.signatures(decided), ap.StepSucceeded, 90*time.Second)
		if restart {
			j.ep, j.mem = epoch2, ap.JobMemory{}
		}
		kinds := j.runStep(ap.SignerAnswer{}, ap.StepSucceeded, time.Second)
		if !slices.Equal(kinds, []ap.JobActionKind{ap.JobActCheck, ap.JobActDispatch}) {
			t.Fatalf("restart=%v: the read after the window took %v", restart, kinds)
		}
	}
	// [read, write]: the first dispatch still needs a Claim, and its
	// materialization_error ends the job with no dispatch.
	j := newJob(t, ap.StopNever, st.Read("r"), st.Write("w", 60))
	j.approve()
	if act := j.next(); act.Kind != ap.JobActClaim || act.Signed {
		t.Fatalf("first dispatch: %+v", act)
	}
	j.answer(j.next(), ap.SignerAnswer{Claim: ap.ClaimMaterializationError})
	if v := ap.JobView(j.job, j.ep); v.State != ap.JobFinal || v.Outcome.Kind != ap.OutcomeJobError || len(v.ExecutedOrdinals) != 0 {
		t.Fatalf("view %+v", v)
	}
	// [write, read, write] with the windows ended: the read runs, the second
	// write gets expired_unexecuted.
	j = newJob(t, ap.StopNever, st.Write("a", 60), st.Read("r"), st.Write("b", 60))
	j.approve()
	j.runStep(j.signatures(decided), ap.StepSucceeded, 2*time.Minute)
	j.runStep(ap.SignerAnswer{}, ap.StepSucceeded, time.Second)
	j.runStep(ap.SignerAnswer{Claim: ap.ClaimExpired}, ap.StepSucceeded, 0)
	v := ap.JobView(j.job, j.ep)
	if !slices.Equal(v.Steps, []ap.StepStatus{ap.StepSucceeded, ap.StepSucceeded, ap.StepExpiredUnexecuted}) || v.Class != ap.ClassExpiredUnexecuted || !v.Partial {
		t.Fatalf("view %+v", v)
	}
}

// K16 on two clocks (S4, S5): the held pair, acquired once per process, ends
// the next signed step whichever clock moved.
func TestJobK16TwoClocks(t *testing.T) {
	decided := st.T0
	for _, c := range []struct {
		name  string
		runW1 time.Duration
		step  time.Duration
	}{
		{"7 min step back", 90 * time.Second, -7 * time.Minute},
		{"7 min forward step", 10 * time.Second, 7 * time.Minute},
	} {
		j := newJob(t, ap.StopNever, st.Write("w1", 60), st.Write("w2", 60))
		j.approve()
		j.runStep(j.signatures(decided), ap.StepSucceeded, c.runW1)
		j.now.Wall = j.now.Wall.Add(c.step)
		held := j.mem.Held[2]
		// The signer fake keeps returning the held set, so the pair decides.
		kinds := j.runStep(j.signatures(decided), ap.StepSucceeded, 0)
		if j.mem.Held[2] != held {
			t.Fatalf("%s: a repeat Claim re-acquired the window", c.name)
		}
		if st := j.job.Steps[1].Result; st == nil || st.Status != ap.StepExpiredUnexecuted || j.job.Steps[1].Marker != nil || slices.Contains(kinds, ap.JobActDispatch) {
			t.Fatalf("%s: %v %+v", c.name, kinds, j.job.Steps[1])
		}
	}
	// S5: a read between two signed steps runs; the last write meets K16.
	j := newJob(t, ap.StopNever, st.Write("w1", 60), st.Read("r"), st.Write("w3", 60))
	j.approve()
	j.runStep(j.signatures(decided), ap.StepSucceeded, 30*time.Second)
	j.runStep(ap.SignerAnswer{}, ap.StepSucceeded, 40*time.Second)
	j.runStep(j.signatures(decided), ap.StepSucceeded, 0)
	if v := ap.JobView(j.job, j.ep); !slices.Equal(v.Steps, []ap.StepStatus{ap.StepSucceeded, ap.StepSucceeded, ap.StepExpiredUnexecuted}) {
		t.Fatalf("S5 view %+v", v)
	}
	// The pre-start guard: a slow handshake after the marker spends the margin.
	j = newJob(t, ap.StopNever, st.Write("w1", 60))
	j.approve()
	j.answer(j.next(), j.signatures(j.now.Wall))
	j.runStep(ap.SignerAnswer{}, ap.StepSucceeded, 0)
	if j.job.Steps[0].Result == nil {
		t.Fatal("the step did not run")
	}
	j = newJob(t, ap.StopNever, st.Write("w1", 60))
	j.approve()
	j.answer(j.next(), j.signatures(j.now.Wall))
	ans, mem := ap.JobOnCheck(j.mem, 1, true)
	j.mem = mem
	if ans != nil || j.next().Kind != ap.JobActDispatch {
		t.Fatal("not ready to dispatch")
	}
	j.do(ap.MarkStep{Ordinal: 1})
	j.now.Elapsed += 59 * time.Second
	if j.mem.Guard(j.job, 1, j.now) {
		t.Fatal("the pre-start guard passed with the elapsed half spent")
	}
}

// OD-3: every definitive answer ends the job with error{code}; every
// transient answer leaves it unchanged.
func TestJobDefinitiveTransient(t *testing.T) {
	definitive := map[ap.JobActionKind][]ap.Code{
		ap.JobActSubmit:  {ap.CodeConflict, ap.CodeInvalidRequest, ap.CodeRequestTooLarge, ap.CodeRecordCorrupt},
		ap.JobActObserve: {ap.CodeNotFound, ap.CodeRecordCorrupt},
		ap.JobActClaim:   {ap.CodeInvalidClaim, ap.CodeNotFound, ap.CodeRecordCorrupt},
	}
	for kind, codes := range definitive {
		for _, code := range codes {
			j := newJob(t, ap.StopNever, st.Write("a", 60))
			if kind != ap.JobActSubmit {
				j.approve()
			}
			j.answer(ap.JobAction{Kind: kind, Step: 1}, ap.SignerAnswer{Code: code})
			v := ap.JobView(j.job, j.ep)
			if v.State != ap.JobFinal || v.Outcome == nil || v.Outcome.Code != code || j.next().Kind != ap.JobActNone {
				t.Fatalf("%s %s: %+v", kind, code, v)
			}
			if !ap.JobDeletable(j.job, ap.Now{Wall: st.T0.Add(31 * 24 * time.Hour)}, false) {
				t.Fatalf("%s %s: a final error job with no bodies is not deletable", kind, code)
			}
		}
	}
	for _, ans := range []ap.SignerAnswer{
		{Code: ap.CodeStorageUncertain}, {Code: ap.CodeBusy}, {Code: ap.CodeLifecycleUnavailable},
		{Code: ap.CodeQueueFull}, {Code: ap.CodeSubmitWindowAhead}, {Lost: true},
	} {
		for _, kind := range []ap.JobActionKind{ap.JobActSubmit, ap.JobActObserve, ap.JobActClaim} {
			j := newJob(t, ap.StopNever, st.Write("a", 60))
			before := fmt.Sprint(j.job)
			if cmd, _ := ap.JobOnAnswer(j.job, j.mem, ap.JobAction{Kind: kind, Step: 1}, ans); cmd != nil || fmt.Sprint(j.job) != before {
				t.Fatalf("%s %+v ended or changed the job: %+v", kind, ans, cmd)
			}
		}
	}
	// A definitive Claim answer after an executed step keeps it and partial.
	j := newJob(t, ap.StopNever, st.Write("a", 60), st.Write("b", 60), st.Write("c", 60))
	j.approve()
	j.runStep(j.signatures(j.now.Wall), ap.StepSucceeded, time.Second)
	j.answer(ap.JobAction{Kind: ap.JobActClaim, Step: 2}, ap.SignerAnswer{Code: ap.CodeRecordCorrupt})
	v := ap.JobView(j.job, j.ep)
	if !slices.Equal(v.Steps, []ap.StepStatus{ap.StepSucceeded, ap.StepNotRun, ap.StepNotRun}) || !slices.Equal(v.ExecutedOrdinals, []int{1}) || !v.Partial {
		t.Fatalf("view %+v", v)
	}
	// Outcomes before any step ran: all not_run, not partial.
	for _, o := range []ap.JobOutcome{{Kind: ap.OutcomeAdopted, Class: ap.ClassFailed}, {Kind: ap.OutcomeApprovalLost}} {
		j := newJob(t, ap.StopNever, st.Write("a", 60), st.Read("r"))
		j.do(ap.SetOutcome{Outcome: o})
		if v := ap.JobView(j.job, j.ep); !slices.Equal(v.Steps, []ap.StepStatus{ap.StepNotRun, ap.StepNotRun}) || v.Partial || len(v.ExecutedOrdinals) != 0 {
			t.Fatalf("%s: %+v", o.Kind, v)
		}
	}
	// A stop-policy stop derives a skipped tail.
	j = newJob(t, ap.StopClassDefaultWritesOnly, st.Write("a", 60), st.Write("b", 60), st.Read("r"))
	j.approve()
	j.runStep(j.signatures(j.now.Wall), ap.StepSucceeded, time.Second)
	j.runStep(j.signatures(j.now.Wall.Add(-time.Second)), ap.StepFailed, time.Second)
	if v := ap.JobView(j.job, j.ep); !slices.Equal(v.Steps, []ap.StepStatus{ap.StepSucceeded, ap.StepFailed, ap.StepSkipped}) || !v.Partial {
		t.Fatalf("stop policy: %+v", v)
	}
}

// final_at is set by exactly the commit that makes the job final, and the
// report, delivery, token and body commits never touch it.
func TestJobFinalAt(t *testing.T) {
	j := newJob(t, ap.StopNever, st.Write("a", 60))
	j.approve()
	j.runStep(j.signatures(j.now.Wall), ap.StepSucceeded, 8*24*time.Hour)
	final := *j.job.FinalAt
	if !final.Equal(j.now.Wall) {
		t.Fatalf("final_at %s, the result commit was at %s", final, j.now.Wall)
	}
	act := j.next()
	if act.Kind != ap.JobActReport {
		t.Fatalf("after the last result: %s", act.Kind)
	}
	if again := ap.JobReport(j.job); mustJSON(t, again) != mustJSON(t, act.Report) {
		t.Fatal("the report body is not a canonical function of the record")
	}
	j.now.Wall = j.now.Wall.Add(time.Hour)
	j.answer(act, ap.SignerAnswer{})
	j.mem.Delivered = true
	j.do(j.next().Commit)
	j.now.Wall = final.Add(ap.BodyRetention)
	j.do(ap.DropToken{})
	if again := ap.JobReport(j.job); mustJSON(t, again) != mustJSON(t, act.Report) {
		t.Fatal("the report body changed after the token was dropped")
	}
	if !j.job.FinalAt.Equal(final) || j.job.ClaimToken != "" || j.job.ReportResult.State != ap.ReportAcked {
		t.Fatalf("final_at moved or a later commit failed: %+v", j.job)
	}
	j = newJob(t, ap.StopNever, st.Write("a", 60))
	j.now.Wall = j.now.Wall.Add(time.Minute)
	j.answer(ap.JobAction{Kind: ap.JobActSubmit}, ap.SignerAnswer{Code: ap.CodeSubmitWindowClosed})
	if j.job.FinalAt == nil || !j.job.FinalAt.Equal(j.now.Wall) || j.job.Outcome.Kind != ap.OutcomeApprovalLost {
		t.Fatalf("outcome commit: %+v", j.job)
	}
}

// SA-9's one job-file deletion predicate (r5.2).
func TestJobDeletionPredicate(t *testing.T) {
	withBody := func() *jobRig {
		j := newJob(t, ap.StopNever, st.Write("a", 60))
		j.approve()
		j.answer(j.next(), j.signatures(j.now.Wall))
		_, j.mem = ap.JobOnCheck(j.mem, 1, true)
		j.do(ap.MarkStep{Ordinal: 1})
		r := result(ap.StepSucceeded)
		r.Stdout, r.StdoutBytes = []byte("ok\n"), 3
		digest := sha256.Sum256(r.Stdout)
		r.StdoutSHA256 = hex.EncodeToString(digest[:])
		j.do(ap.RecordResult{Ordinal: 1, Result: r})
		return j
	}
	at := func(j *jobRig, d time.Duration) ap.Now { return ap.Now{Wall: j.job.FinalAt.Add(d)} }
	j := withBody()
	j.answer(j.next(), ap.SignerAnswer{})
	for _, pressure := range []bool{false, true} {
		if ap.JobDeletable(j.job, at(j, 6*24*time.Hour), pressure) {
			t.Fatalf("pressure=%v: an undelivered body under 7 d does not protect its job", pressure)
		}
	}
	if cmd := ap.JobRetention(j.job, at(j, 6*24*time.Hour), true); cmd != nil {
		t.Fatalf("budget pressure removed an undelivered body: %+v", cmd)
	}
	j = withBody()
	j.now = at(j, 8*24*time.Hour)
	j.do(ap.JobRetention(j.job, j.now, false))
	if ap.JobDeletable(j.job, at(j, 31*24*time.Hour), true) || ap.JobRetention(j.job, j.now, false) != nil {
		t.Fatal("a job whose report is owed is deletable, or its token droppable")
	}
	j.answer(j.next(), ap.SignerAnswer{Code: ap.CodeInvalidReport})
	if j.job.ReportResult.State != ap.ReportRefused {
		t.Fatalf("report result %+v", j.job.ReportResult)
	}
	if _, ok := ap.JobRetention(j.job, j.now, false).(ap.DropToken); !ok {
		t.Fatal("the token is not dropped once final, settled and body-less")
	}
	if ap.JobDeletable(j.job, at(j, 29*24*time.Hour), false) || !ap.JobDeletable(j.job, at(j, 30*24*time.Hour), false) ||
		!ap.JobDeletable(j.job, at(j, 9*24*time.Hour), true) {
		t.Fatal("the age and count paths disagree with the predicate")
	}
	early := ap.Now{Wall: j.job.Draft.SubmitNotAfter.Add(23 * time.Hour)}
	if ap.JobDeletable(j.job, early, true) {
		t.Fatal("deletable inside submit_not_after + 24 h")
	}
}

// exec_submit's window (r5.2): closed after submit_not_after, invalid more
// than 3605 s ahead.
func TestExecSubmitAdmit(t *testing.T) {
	d := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("a", 60))
	cases := []struct {
		snA  time.Duration
		want ap.Code
	}{{-time.Second, ap.CodeSubmitWindowClosed}, {3606 * time.Second, ap.CodeInvalidRequest}, {3602 * time.Second, ""}, {0, ""}}
	for _, c := range cases {
		d.SubmitNotAfter = st.T0.Add(c.snA)
		if got := ap.ExecSubmitAdmit(st.T0, d, ap.MaxJobOutputBytes); got != c.want {
			t.Errorf("submit_not_after %+v: %q, want %q", c.snA, got, c.want)
		}
	}
}

// The report split (SA-5 step 7): a definitive refusal settles the report,
// a transient answer leaves it owed and resent with the same bytes.
func TestJobReportSplit(t *testing.T) {
	for _, c := range []struct {
		ans     ap.SignerAnswer
		settled bool
	}{
		{ap.SignerAnswer{Code: ap.CodeSignerIncompatible}, true}, {ap.SignerAnswer{Code: ap.CodeInvalidRequest}, true},
		{ap.SignerAnswer{Code: ap.CodeStorageUncertain}, false}, {ap.SignerAnswer{Lost: true}, false},
	} {
		j := newJob(t, ap.StopNever, st.Write("a", 60))
		j.approve()
		j.runStep(j.signatures(j.now.Wall), ap.StepSucceeded, time.Second)
		act := j.next()
		j.answer(act, c.ans)
		if settled := j.job.ReportResult != nil; settled != c.settled {
			t.Fatalf("%+v: settled=%v", c.ans, settled)
		}
		if !c.settled && mustJSON(t, j.next().Report) != mustJSON(t, act.Report) {
			t.Fatal("the resent report differs")
		}
	}
}

func TestRemoveBodiesRechecksCommitAge(t *testing.T) {
	j := newJob(t, ap.StopNever, st.Write("w", 60))
	j.approve()
	j.answer(j.next(), j.signatures(j.now.Wall))
	_, j.mem = ap.JobOnCheck(j.mem, 1, true)
	j.do(ap.MarkStep{Ordinal: 1})
	r := result(ap.StepSucceeded)
	r.Stdout = []byte("ok\n")
	r.StdoutBytes = 3
	digest := sha256.Sum256(r.Stdout)
	r.StdoutSHA256 = hex.EncodeToString(digest[:])
	j.do(ap.RecordResult{Ordinal: 1, Result: r})
	final := *j.job.FinalAt
	planned := ap.JobRetention(j.job, ap.Now{Wall: final.Add(ap.BodyRetention)}, false)
	for _, tc := range []struct {
		name      string
		cmd       ap.JobCommand
		age       time.Duration
		delivered bool
		want      bool
	}{
		{"clock back", planned, ap.BodyRetention - time.Hour, false, false},
		{"at age", planned, ap.BodyRetention, false, true},
		{"unknown", ap.RemoveBodies{Cause: "bogus"}, ap.BodyRetention, false, false},
		{"undelivered", ap.RemoveBodies{Cause: ap.BodiesRemovedBudget}, ap.BodyRetention, false, false},
		{"delivery too new", ap.RemoveBodies{Cause: ap.BodiesRemovedBudget}, ap.BodyPressureMinAge - time.Second, true, false},
		{"delivery old", ap.RemoveBodies{Cause: ap.BodiesRemovedBudget}, ap.BodyPressureMinAge, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := j.job
			if tc.delivered {
				job.FirstDeliveredAt = &final
			}
			after, a := ap.ApplyJob(job, tc.cmd, ap.Now{Wall: final.Add(tc.age)}, j.ep)
			if a.Changed != tc.want || (len(after.Steps[0].Result.Stdout) == 0) != tc.want {
				t.Fatalf("%+v", a)
			}
		})
	}
}

func TestMalformedSignerAnswersAreDefinitive(t *testing.T) {
	j := newJob(t, ap.StopNever, st.Write("w", 60))
	for _, kind := range []ap.JobActionKind{ap.JobActSubmit, ap.JobActObserve, ap.JobActClaim, ap.JobActReport} {
		job := j.job
		if kind == ap.JobActReport {
			final := newJob(t, ap.StopNever, st.Write("w", 60))
			final.approve()
			final.runStep(final.signatures(final.now.Wall), ap.StepSucceeded, 0)
			job = final.job
		}
		cmd, _ := ap.JobOnAnswer(job, j.mem, ap.JobAction{Kind: kind, Step: 1}, ap.SignerAnswer{Code: "unknown"})
		after, a := ap.ApplyJob(job, cmd, j.now, j.ep)
		if kind == ap.JobActReport {
			if !a.Changed || after.ReportResult == nil || after.ReportResult.State != ap.ReportRefused || after.ReportResult.Code != ap.CodeSignerIncompatible || ap.JobNext(after, j.now, j.ep, ap.JobMemory{}).Kind != ap.JobActNone {
				t.Fatalf("report did not settle: %+v %+v", after.ReportResult, a)
			}
			continue
		}
		if !a.Changed || after.Outcome == nil || after.Outcome.Code != ap.CodeSignerIncompatible {
			t.Fatalf("%s: %+v %+v", kind, cmd, a)
		}
	}
	for _, tc := range []struct {
		kind ap.JobActionKind
		ans  ap.SignerAnswer
	}{
		{ap.JobActSubmit, ap.SignerAnswer{Decision: ap.ApprovalPending}},
		{ap.JobActSubmit, ap.SignerAnswer{PlanHash: "bad", Decision: ap.ApprovalPending}},
		{ap.JobActObserve, ap.SignerAnswer{Decision: "unknown"}},
		{ap.JobActClaim, ap.SignerAnswer{Claim: "unknown"}},
		{ap.JobActClaim, ap.SignerAnswer{Claim: ap.ClaimExecutionReported}},
		{ap.JobActClaim, ap.SignerAnswer{Claim: ap.ClaimExecutionReported, Class: "unknown"}},
		{ap.JobActClaim, ap.SignerAnswer{Claim: ap.ClaimSignatures}},
	} {
		cmd, _ := ap.JobOnAnswer(j.job, j.mem, ap.JobAction{Kind: tc.kind, Step: 1}, tc.ans)
		after, a := ap.ApplyJob(j.job, cmd, j.now, j.ep)
		if !a.Changed || after.Outcome == nil || after.Outcome.Code != ap.CodeSignerIncompatible || ap.JobNext(after, j.now, j.ep, ap.JobMemory{}).Kind != ap.JobActNone {
			t.Fatalf("%+v did not end job: %+v %+v", tc, after.Outcome, a)
		}
	}
}
