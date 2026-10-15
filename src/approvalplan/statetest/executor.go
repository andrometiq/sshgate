package statetest

import (
	"encoding/hex"
	"fmt"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Gate is the fake target gate. Its clock is the true time (the start plus
// elapsed), so a wall step on the signer or executor never moves it; it
// refuses a signed dispatch at or after the signature's Exp, as the real
// gate does.
type Gate struct {
	Start      time.Time
	Dispatches map[string]int
	Refused    int
}

// Executor is the model executor: a durable store of R2 jobs, each job's
// in-memory JobMemory, and the JobNext driver, talking to a Signer. Its
// commits are checked with CheckJobTransition and can be crash points.
type Executor struct {
	Signer    *Signer
	Principal string
	Clock     *Clock
	Gate      *Gate
	Jobs      map[string]ap.R2
	Epoch     string
	// StepTime is how long each dispatched step runs; StepFails makes
	// every step exit non-zero.
	StepTime  time.Duration
	StepFails bool
	// StaleTarget makes every ReadCurrent check fail.
	StaleTarget bool
	CrashAt     int
	CrashLanded bool
	Commits     int
	epochs      int
	mem         map[string]ap.JobMemory
	// BeforeStart runs between the marker commit and the pre-start guard,
	// standing in for a slow dial and handshake.
	BeforeStart func()
}

// NewExecutor starts a model executor for principal.
func NewExecutor(s *Signer, principal string) *Executor {
	e := &Executor{
		Signer: s, Principal: principal, Clock: s.Clock, Jobs: map[string]ap.R2{},
		Gate: &Gate{Start: s.Clock.Wall.Add(-s.Clock.Elapsed), Dispatches: map[string]int{}},
	}
	e.Restart()
	return e
}

// Restart discards all memory and starts a new epoch.
func (e *Executor) Restart() {
	e.epochs++
	e.Epoch = Epoch(1000 + e.epochs)
	e.mem = map[string]ap.JobMemory{}
}

// Submit is exec_submit: the window check, then the job commit. An existing
// ID is returned whatever the time.
func (e *Executor) Submit(d ap.ApprovalDraft) ap.Code {
	key := ap.JobKey(d.RequestID)
	if _, ok := e.Jobs[key]; ok {
		return ""
	}
	now := e.Clock.Now()
	if code := ap.ExecSubmitAdmit(now.Wall, d, d.CommandJob.MaxOutputBytes*int64(len(d.CommandJob.Steps))); code != "" {
		return code
	}
	hash, _ := ap.DraftHash(d)
	tok := Token(d.RequestID)
	job := ap.R2{
		Version: ap.R2Version, RequestID: d.RequestID, InputHash: hash, Draft: d, DraftHash: hash,
		CreatedAt: now.Wall, Reservation: int64(ap.R2Reservation(d, ap.MaxJobOutputBytes)),
		ClaimToken: hex.EncodeToString(tok[:]), Steps: make([]ap.JobStep, len(d.CommandJob.Steps)),
	}
	for i := range job.Steps {
		job.Steps[i].Ordinal = i + 1
	}
	e.commit(key, nil, job, now)
	return ""
}

func (e *Executor) commit(key string, before *ap.R2, after ap.R2, now ap.Now) {
	if err := CheckJobTransition(before, after, now, e.Epoch); err != nil {
		e.Signer.fail(fmt.Errorf("job commit %d on %s: %w", e.Commits+1, key, err))
	}
	e.Commits++
	crashing := e.Commits == e.CrashAt
	if !crashing || e.CrashLanded {
		e.Jobs[key] = after
	}
	if crashing {
		panic(crash{owner: "executor"})
	}
}

func (e *Executor) applyJob(key string, cmd ap.JobCommand) ap.JobAnswer {
	now := e.Clock.Now()
	before := e.Jobs[key]
	after, ans := ap.ApplyJob(before, cmd, now, e.Epoch)
	if ans.Changed {
		e.commit(key, &before, after, now)
	}
	return ans
}

// Drive runs JobNext for one job until it has nothing to do, at most n
// actions.
func (e *Executor) Drive(key string, n int) {
	for range n {
		job, ok := e.Jobs[key]
		if !ok {
			return
		}
		mem := e.mem[key]
		act := ap.JobNext(job, e.Clock.Now(), e.Epoch, mem)
		if act.Kind == ap.JobActNone {
			return
		}
		if act.Kind == ap.JobActClaim && !act.Signed && anyDispatched(job) {
			e.Signer.fail(fmt.Errorf("JobNext claimed for unsigned step %d of %s after the first dispatch", act.Step, key))
		}
		if !e.step(key, job, mem, act) {
			return
		}
	}
}

func anyDispatched(job ap.R2) bool {
	for _, s := range job.Steps {
		if s.Marker != nil || s.Result != nil {
			return true
		}
	}
	return false
}

func (e *Executor) step(key string, job ap.R2, mem ap.JobMemory, act ap.JobAction) bool {
	var cmd ap.JobCommand
	switch act.Kind {
	case ap.JobActCommit:
		cmd = act.Commit
	case ap.JobActCheck:
		cmd, mem = ap.JobOnCheck(mem, act.Step, !e.StaleTarget)
	case ap.JobActDispatch:
		e.dispatch(key, mem, act)
		return true
	default:
		ans := e.call(ap.RecordKey(e.Principal, job.RequestID), job, act, Token(job.RequestID))
		cmd, mem = ap.JobOnAnswer(job, mem, act, ans)
	}
	progressed := cmd != nil || enc(mem) != enc(e.mem[key])
	e.mem[key] = mem
	if cmd != nil {
		e.applyJob(key, cmd)
	}
	return progressed
}

// call performs one signer call as the executor's client sees it.
func (e *Executor) call(skey string, job ap.R2, act ap.JobAction, tok [32]byte) ap.SignerAnswer {
	ans := ap.SignerAnswer{SentAt: e.Clock.Now()}
	s := e.Signer
	switch act.Kind {
	case ap.JobActSubmit:
		a := s.Submit(e.Principal, job.Draft)
		ans.Code = a.Code
		if sum, ok := s.Get(skey); ok && a.Code == "" {
			ans.Decision, ans.PlanHash = sum.ApprovalStatus, sum.PlanHash
		}
	case ap.JobActObserve:
		sum, ok := s.Get(skey)
		if !ok {
			ans.Code = ap.CodeNotFound
		}
		ans.Decision = sum.ApprovalStatus
	case ap.JobActClaim:
		a := s.Claim(skey, tok)
		ans.Code, ans.Claim, ans.Class, ans.DecidedAt, ans.Windows = a.Code, a.Claim, a.Class, a.DecidedAt, a.Windows
	case ap.JobActReport:
		ans.Code = s.Report(skey, tok, act.Report).Code
	}
	return ans
}

// dispatch is the actor's dispatch: the marker, the pre-start guard (K16 on
// the held pair), the gate, the run, and the result.
func (e *Executor) dispatch(key string, mem ap.JobMemory, act ap.JobAction) {
	if ans := e.applyJob(key, ap.MarkStep{Ordinal: act.Step}); ans.AlreadyMarked || !ans.Changed {
		return
	}
	if e.BeforeStart != nil {
		e.BeforeStart()
	}
	job := e.Jobs[key]
	if !mem.Guard(job, act.Step, e.Clock.Now()) {
		e.applyJob(key, ap.RecordResult{Ordinal: act.Step, Result: ap.NoOutputResult(ap.StepExpiredUnexecuted, "")})
		return
	}
	e.Gate.Dispatches[fmt.Sprintf("%s/%d", key, act.Step)]++
	status, exit := ap.StepSucceeded, 0
	if act.Signed {
		gateNow := e.Gate.Start.Add(e.Clock.Elapsed)
		if exp := mem.Held[act.Step].WallEnd; !gateNow.Before(exp) {
			e.Gate.Refused++
			status, exit = ap.StepFailed, 65
		}
	}
	e.Clock.Advance(e.StepTime)
	if e.StepFails {
		status, exit = ap.StepFailed, 1
	}
	res := ap.NoOutputResult(status, "")
	res.ExitCode = &exit
	e.applyJob(key, ap.RecordResult{Ordinal: act.Step, Result: res})
}
