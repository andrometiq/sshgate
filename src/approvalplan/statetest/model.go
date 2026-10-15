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
	Clock    *Clock
	Signer   *Signer
	Exec     *Executor
	rnd      *rand.Rand
	ids      int
	stepBack bool
	trace    []string
}

// NewModel builds a model from a seed.
func NewModel(seed uint64) *Model {
	clock := &Clock{Wall: T0, Elapsed: time.Hour}
	s := NewSigner(clock, seed)
	s.Settings = ModelSettings
	m := &Model{Clock: clock, Signer: s, Exec: NewExecutor(s, PrincipalA), rnd: rand.New(rand.NewPCG(seed, 2))}
	m.Exec.StepTime = 5 * time.Second
	return m
}

// Run performs n random operations, quiesces the system, and checks that
// every write-ahead state was completed by its driver.
func (m *Model) Run(n int) error {
	for i := 0; i < n && m.Signer.Err == nil; i++ {
		m.guard(m.op)
	}
	if m.Signer.Err == nil {
		m.quiesce()
	}
	if err := m.Signer.Err; err != nil {
		return m.wrap(err)
	}
	return m.wrap(m.checkDrivers())
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
	m.Exec.Submit(JobDraft(id, ap.CoordinatorExecutor, m.Clock.Wall, specs...))
}

func (m *Model) op() {
	s, e := m.Signer, m.Exec
	key, haveKey := m.recordKey()
	switch n := m.rnd.IntN(112); {
	case n >= 100 && haveKey && n < 106:
		m.log("approve %s", key[:8])
		s.AssistArrives(key, false)
		s.Reconcile(key)
		s.Tap(key, ap.VoteApprove, Operator, true)
		s.FlushPass()
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
		d := time.Duration(1+m.rnd.IntN(90)) * time.Second
		m.log("advance %s", d)
		m.Clock.Advance(d)
	case n < 74:
		d := time.Duration(m.rnd.IntN(7201)-3600) * time.Second
		m.stepBack = m.stepBack || d < 0
		m.log("step wall %s", d)
		m.Clock.StepWall(d)
	case n < 78:
		s.Sink.Fail = !s.Sink.Fail
		m.log("sink fail=%v", s.Sink.Fail)
	case n < 80:
		s.TG.Fail = !s.TG.Fail
		m.log("telegram fail=%v", s.TG.Fail)
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

// quiesce lets every driver finish with working fakes and no crash: ticks,
// flushes, the executor, and enough time for every deadline and age.
func (m *Model) quiesce() {
	s := m.Signer
	s.Sink.Fail, s.TG.Fail, s.CrashAt, m.Exec.CrashAt = false, false, 0, 0
	m.log("quiesce")
	for i := range 60 {
		m.guard(func() {
			s.Tick()
			m.driveAll(40)
		})
		if i == 30 {
			m.Clock.Advance(30 * time.Hour)
		}
		m.Clock.Advance(time.Minute)
	}
}

// checkDrivers: after quiescence no record or job is left in a write-ahead
// state without its driver having completed it, no send or dispatch was
// repeated, and no grant crossed principals.
func (m *Model) checkDrivers() error {
	s, now := m.Signer, m.Clock.Now()
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
			grant := ap.RecordKey(rec.Header.Principal, strings.TrimPrefix(d.DecidedBy, ap.GrantDecidedPrefix))
			if g, ok := s.Store[grant]; ok && g.Header.Principal != rec.Header.Principal {
				return fmt.Errorf("record %s was decided by another principal's grant", key)
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
	if m.Exec.Gate.Refused > 0 && !m.stepBack {
		return errors.New("the gate refused a signature K16 passed, with no wall step back")
	}
	for _, key := range sortedJobs(m.Exec.Jobs) {
		job := m.Exec.Jobs[key]
		if v := ap.JobView(job, m.Exec.Epoch); v.State != ap.JobFinal || ap.JobNext(job, now, m.Exec.Epoch, ap.JobMemory{}).Kind != ap.JobActNone {
			return fmt.Errorf("job %s left unfinished: %+v", key, v)
		}
	}
	return nil
}
