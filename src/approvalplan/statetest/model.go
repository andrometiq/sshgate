package statetest

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// ModelSettings shortens the retention ages so a schedule reaches Shed and
// Delete.
var ModelSettings = ap.Settings{ReportHorizon: time.Hour, Retention: 2 * time.Hour, MaxAge: 3 * time.Hour}

// Model is one random schedule over a signer, an executor, the Telegram,
// sink and gate fakes, and the two-reading clock, with crash injection at
// any commit, landed or not. Run returns the first property violation.
type Model struct {
	Clock        *Clock
	Signer       *Signer
	Exec         *Executor
	rnd          *rand.Rand
	ids          int
	noWallSteps  bool
	dispatchCuts int
	trace        []string
}

// NewModel builds a model from a seed.
func NewModel(seed uint64) *Model {
	clock := &Clock{Wall: T0, Elapsed: time.Hour}
	s := NewSigner(clock, seed)
	s.Settings = ModelSettings
	s.Oracle = true
	m := &Model{Clock: clock, Signer: s, Exec: NewExecutor(s, PrincipalA), rnd: rand.New(rand.NewPCG(seed, 2))}
	m.noWallSteps = seed%2 == 0
	m.Exec.StepTime = time.Second
	return m
}

// Run performs n random operations, quiesces the system, and checks that
// every write-ahead state was completed by its driver.
func (m *Model) Run(n int) error {
	m.witnesses()
	for i := 0; i < n && m.Signer.Err == nil; i++ {
		m.guard(m.op)
	}
	if m.Signer.Err == nil {
		m.quiesce()
	}
	if err := m.Signer.Err; err != nil {
		return m.wrap(err)
	}
	if err := m.checkDrivers(); err != nil {
		return m.wrap(err)
	}
	if len(m.Signer.Released) < 4 || len(m.Exec.Gate.Dispatches) < 3 || m.dispatchCuts < 1 || m.Exec.Gate.Checked < 3 {
		return m.wrap(fmt.Errorf("coverage collapsed: releases=%d dispatches=%d cuts=%d gate=%d", len(m.Signer.Released), len(m.Exec.Gate.Dispatches), m.dispatchCuts, m.Exec.Gate.Checked))
	}
	m.Clock.Advance(30 * time.Hour)
	m.Signer.Tick()
	m.Signer.Tick()
	return m.wrap(m.Signer.Err)
}

func (m *Model) wrap(err error) error {
	if err == nil {
		return nil
	}
	tail := m.trace
	if len(tail) > 40 {
		tail = tail[len(tail)-40:]
	}
	return fmt.Errorf("%w\nlast operations:\n  %s", err, strings.Join(tail, "\n  "))
}

func (m *Model) log(format string, args ...any) {
	m.trace = append(m.trace, fmt.Sprintf(format, args...))
}

// guard runs f and turns an injected crash into its owner's restart.
func (m *Model) guard(f func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		c, ok := r.(crash)
		if !ok {
			panic(r)
		}
		m.log("CRASH %s", c.owner)
		if c.owner == "signer" {
			m.Signer.CrashAt = 0
			m.guard(m.Signer.Restart)
		} else {
			m.Exec.CrashAt = 0
			m.Exec.Restart()
		}
	}()
	f()
}

func (m *Model) recordKey() (string, bool) {
	keys := m.Signer.keys()
	if len(keys) == 0 {
		return "", false
	}
	return keys[m.rnd.IntN(len(keys))], true
}

func (m *Model) newJob() {
	m.ids++
	id := ID(m.ids)
	specs := []StepSpec{Write("systemctl restart app", 60)}
	for range m.rnd.IntN(3) {
		switch m.rnd.IntN(3) {
		case 0:
			specs = append(specs, Read("df -h"))
		case 1:
			specs = append(specs, Write("logrotate -f /etc/logrotate.conf", 30+m.rnd.IntN(31)))
		default:
			specs = append(specs, Reveal("cat /etc/app.env"))
		}
	}
	m.rnd.Shuffle(len(specs), func(i, j int) { specs[i], specs[j] = specs[j], specs[i] })
	m.log("job %s %v", id, specs)
	if code := m.Exec.Submit(JobDraft(id, ap.CoordinatorExecutor, m.Clock.Wall, specs...)); code != "" {
		m.Signer.fail(fmt.Errorf("generated admission: %s", code))
	}
	m.Exec.Drive(ap.JobKey(id), 1)
	if m.rnd.IntN(2) == 0 {
		key := ap.RecordKey(PrincipalA, id)
		m.approve(key)
		m.Exec.Drive(ap.JobKey(id), 40)
	}
}

func (m *Model) op() {
	s, e := m.Signer, m.Exec
	s.Sink.Fail, s.TG.Fail = false, false
	key, haveKey := m.recordKey()
	switch n := m.rnd.IntN(112); {
	case n >= 100 && haveKey && n < 106:
		m.log("approve %s", key[:8])
		s.AssistArrives(key, false)
		s.Reconcile(key)
		s.Tap(key, ap.VoteApprove, Operator, true)
		s.FlushPass()
		if rec, ok := s.Store[key]; ok {
			e.Drive(ap.JobKey(rec.Header.RequestID), 40)
		}
	case n >= 106 && haveKey:
		rec := s.Store[key]
		m.log("claim %s", key[:8])
		s.Claim(key, Token(rec.Header.RequestID))
	case n < 12:
		m.newJob()
	case n < 16:
		m.ids++
		principal := []string{PrincipalA, PrincipalB}[m.rnd.IntN(2)]
		m.log("grant %s by %s", ID(m.ids), principal)
		s.Submit(principal, GrantDraft(ID(m.ids), "web-1", time.Duration(1+m.rnd.IntN(60))*time.Minute, m.Clock.Wall))
	case n < 30 && haveKey:
		decision := []string{ap.VoteApprove, ap.VoteDeny}[m.rnd.IntN(4)/3]
		valid := m.rnd.IntN(5) > 0
		m.log("tap %s %s valid=%v", key[:8], decision, valid)
		s.Tap(key, decision, Operator, valid)
	case n < 33 && haveKey:
		m.log("cancel %s", key[:8])
		s.Cancel(key)
	case n < 36 && haveKey:
		m.log("renotify %s", key[:8])
		s.Renotify(key)
	case n < 38:
		m.log("revoke web-1")
		s.RevokeAlias("web-1")
	case n < 44 && haveKey:
		m.log("assist %s", key[:8])
		s.AssistArrives(key, m.rnd.IntN(3) == 0)
	case n < 58:
		m.log("tick")
		s.Tick()
	case n < 70:
		d := time.Duration(1+m.rnd.IntN(3)) * time.Second
		m.log("advance %s", d)
		m.Clock.Advance(d)
	case n < 74:
		if m.noWallSteps {
			m.driveAll(40)
			return
		}
		d := time.Duration(m.rnd.IntN(7201)-3600) * time.Second
		m.log("step wall %s", d)
		m.Clock.StepWall(d)
	case n < 78:
		s.Sink.Fail = !s.Sink.Fail
		m.log("sink fail=%v", s.Sink.Fail)
		s.FlushPass()
	case n < 80:
		s.TG.Fail = !s.TG.Fail
		m.log("telegram fail=%v", s.TG.Fail)
		if haveKey {
			s.Reconcile(key)
		}
	case n < 84:
		s.CrashAt, s.CrashLanded = s.Commits+1+m.rnd.IntN(4), m.rnd.IntN(2) == 0
		m.log("signer crash at commit %d landed=%v", s.CrashAt, s.CrashLanded)
	case n < 87:
		e.CrashAt, e.CrashLanded = e.Commits+1+m.rnd.IntN(4), m.rnd.IntN(2) == 0
		m.log("executor crash at commit %d landed=%v", e.CrashAt, e.CrashLanded)
	default:
		m.log("drive")
		m.driveAll(6)
	}
}

func (m *Model) driveAll(n int) {
	for _, key := range sortedJobs(m.Exec.Jobs) {
		m.Exec.Drive(key, n)
	}
}

func sortedJobs(jobs map[string]ap.R2) []string {
	keys := make([]string, 0, len(jobs))
	for k := range jobs {
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

// quiesce completes drivers before retention. A deadline may still be far
// ahead after a wall step back, so advance to actual pending deadlines.
func (m *Model) quiesce() {
	s := m.Signer
	s.Sink.Fail, s.TG.Fail, s.CrashAt, m.Exec.CrashAt = false, false, 0, 0
	m.log("quiesce")
	s.Tick()
	m.driveAll(40)
	end := m.Clock.Wall
	// A submit_window_ahead job can otherwise create a fresh pending
	// record after this pass selected all existing record deadlines.
	for _, job := range m.Exec.Jobs {
		if job.SignerAck == "" && job.FinalAt == nil && job.Draft.SubmitNotAfter.After(end) {
			end = job.Draft.SubmitNotAfter
		}
	}
	for _, rec := range s.Store {
		if rec.Header.Decision == nil && rec.Header.RequestExpiresAt.After(end) {
			end = rec.Header.RequestExpiresAt
		}
		if claimEnd, ok := ap.ClaimEnd(rec); ok && claimEnd.After(end) {
			end = claimEnd
		}
	}
	m.Clock.Advance(end.Sub(m.Clock.Wall) + time.Second)
	for range 4 {
		s.Tick()
		m.driveAll(40)
	}
}

// checkDrivers: after quiescence no record or job is left in a write-ahead
// state without its driver having completed it, no send or dispatch was
// repeated, and no grant crossed principals.
func (m *Model) checkDrivers() error {
	s, now := m.Signer, m.Clock.Now()
	if len(s.Store) == 0 {
		return errors.New("driver checks have an empty store")
	}
	for _, key := range s.keys() {
		rec := s.Store[key]
		w := ap.Next(rec, now, s.Epoch, s.Settings, s.grantLive(key))
		if !rec.Header.Shed && ap.R1Reservation(rec) != s.Reserved[key] {
			return fmt.Errorf("record %s: R1Reservation moved from its value at freeze", key)
		}
		if w.Clock || w.Notify.Kind != ap.NotifyNone || ap.Unflushed(rec) || rec.Header.Decision == nil {
			return fmt.Errorf("record %s left with work: %+v unflushed=%v", key, w, ap.Unflushed(rec))
		}
		if d := rec.Header.Decision; strings.HasPrefix(d.DecidedBy, ap.GrantDecidedPrefix) {
			id := strings.TrimPrefix(d.DecidedBy, ap.GrantDecidedPrefix)
			for _, g := range s.Store {
				if g.Header.RequestID == id && g.Header.Principal != rec.Header.Principal {
					return fmt.Errorf("record %s was decided by another principal's grant", key)
				}
			}
		}
	}
	for k, n := range s.TG.BurstSends {
		if n > 1 {
			return fmt.Errorf("burst %s was sent %d times", k, n)
		}
	}
	for k, n := range s.TG.CardSends {
		if n > 1 {
			return fmt.Errorf("card %s was sent %d times", k, n)
		}
	}
	for k, n := range m.Exec.Gate.Dispatches {
		if n > 1 {
			return fmt.Errorf("step %s was dispatched %d times", k, n)
		}
	}
	// R-4 (acquisition offset) and R-5 (wrong source clock) are excluded
	// only in runs whose wall clock always equals the gate's true clock.
	if m.Exec.Gate.Refused > 0 && m.noWallSteps {
		return errors.New("the gate refused a signature K16 passed, with no wall step back")
	}
	for _, key := range sortedJobs(m.Exec.Jobs) {
		job := m.Exec.Jobs[key]
		// Independent of JobNext/owesReport: completed step jobs owe a report.
		if job.FinalAt != nil && job.Outcome == nil {
			if job.ReportResult == nil {
				return fmt.Errorf("job %s suppressed its owed report", key)
			}
			rec, ok := s.Store[ap.RecordKey(m.Exec.Principal, job.RequestID)]
			if job.ReportResult.State == ap.ReportAcked && (!ok || rec.Header.FinalReport == nil) {
				return fmt.Errorf("job %s acked an absent report", key)
			}
		}
		if v := ap.JobView(job, m.Exec.Epoch); v.State != ap.JobFinal || ap.JobNext(job, now, m.Exec.Epoch, ap.JobMemory{}).Kind != ap.JobActNone {
			return fmt.Errorf("job %s left unfinished: %+v", key, v)
		}
	}
	return nil
}
