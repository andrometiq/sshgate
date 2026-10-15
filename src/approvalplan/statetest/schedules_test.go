package statetest

import (
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func TestAdmissionClockPass(t *testing.T) {
	m := NewModel(0)
	s := m.Signer
	s.LiveCap = 1
	d := JobDraft(ID(1), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))
	if a := s.Submit(PrincipalA, d); a.Code != "" {
		t.Fatal(a)
	}
	key := ap.RecordKey(PrincipalA, d.RequestID)
	m.approve(key)
	// Tick is paused: the expired window still occupies the one live slot.
	m.Clock.Advance(60 * time.Second)
	if ap.Class(s.Store[key], m.Clock.Now(), s.Settings, false) != ap.ClassLive {
		t.Fatal("fixture not live before Clock")
	}
	if a := s.Submit(PrincipalA, JobDraft(ID(2), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))); a.Code != "" {
		t.Fatal(a)
	}
	if h := s.Store[key].Header; h.Mint == nil || h.Mint.Reason != ap.MintReasonWindowClosed {
		t.Fatal("admission did not commit window closure")
	}
	if a := s.Submit(PrincipalA, JobDraft(ID(3), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))); a.Code != ap.CodeQueueFull {
		t.Fatal("live cap not enforced", a)
	}
	if s.Err != nil {
		t.Fatal(s.Err)
	}
}

func TestFlushBatchDeadlineOrder(t *testing.T) {
	m := NewModel(0)
	s := m.Signer
	s.Sink.Fail = true
	for i := 1; i <= 600; i++ {
		// Reverse deadline order against record keys; each pending record has
		// only its submitted event, so one flush cannot create another event.
		s.Validity = ap.ValidityMin + time.Duration(601-i)*time.Second
		d := JobDraft(ID(i), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))
		cmd := SubmitOf(d, PrincipalA, m.Clock.Wall, s.Validity)
		cmd.AssistDeadline = m.Clock.Wall.Add(time.Duration(601-i) * time.Millisecond)
		if a := s.apply(ap.RecordKey(PrincipalA, d.RequestID), cmd, s.inputs("")); a.Code != "" {
			t.Fatal(a)
		}
	}
	s.FlushPass()
	if len(s.FlushOrder) != 0 {
		t.Fatal("failed sink flushed")
	}
	s.Sink.Fail = false
	for pass := 0; pass < 4; pass++ {
		before := len(s.FlushOrder)
		s.FlushPass()
		if len(s.FlushOrder)-before > ap.FlushBatch {
			t.Fatal("batch limit exceeded")
		}
	}
	if len(s.FlushOrder) != 600 {
		t.Fatalf("drained %d", len(s.FlushOrder))
	}
	var previous time.Time
	for _, key := range s.FlushOrder {
		due := ap.NextDueAt(s.Store[key], m.Clock.Now(), s.Settings)
		if !previous.IsZero() && due.Before(previous) {
			t.Fatal("not nearest deadline first")
		}
		previous = due
		if ap.Unflushed(s.Store[key]) {
			t.Fatal("undrained", key)
		}
	}
	if s.Err != nil {
		t.Fatal(s.Err)
	}
}

func TestGrantDeletionDoesNotReviveOlder(t *testing.T) {
	m := NewModel(0)
	s := m.Signer
	for i := 1; i <= 2; i++ {
		id := ID(i)
		s.Submit(PrincipalA, GrantDraft(id, "web-1", 24*time.Hour, m.Clock.Wall))
		m.approve(ap.RecordKey(PrincipalA, id))
	}
	newest := ap.RecordKey(PrincipalA, ID(2))
	s.RevokeAlias("web-1")
	s.FlushPass()
	m.Clock.StepWall(26 * time.Hour)
	if a := s.Do(newest, ap.Delete{Pressure: true}); !a.Removed {
		t.Fatal(a)
	}
	// R-2 permits a new ID after wall rollback, but never revives a grant.
	m.Clock.StepWall(-26 * time.Hour)
	d := JobDraft(ID(3), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))
	s.Submit(PrincipalA, d)
	if s.Store[ap.RecordKey(PrincipalA, d.RequestID)].Header.Decision != nil {
		t.Fatal("deleted newest grant revived older grant")
	}
	if s.Err != nil {
		t.Fatal(s.Err)
	}
}

func TestModelDeferredAdmission(t *testing.T) {
	m := NewModel(0)
	m.Signer.Submit(PrincipalA, JobDraft(ID(1), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60)))
	m.Exec.Submit(JobDraft(ID(2), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60)))
	m.Clock.StepWall(-10 * time.Second)
	m.Exec.Drive(ap.JobKey(ID(2)), 1)
	if job := m.Exec.Jobs[ap.JobKey(ID(2))]; job.SignerAck != "" || job.Outcome != nil {
		t.Fatal("fixture was not deferred by submit_window_ahead")
	}
	m.quiesce()
	if m.Signer.Err != nil {
		t.Fatal(m.Signer.Err)
	}
	if err := m.checkDrivers(); err != nil {
		t.Fatal(err)
	}
	job := m.Exec.Jobs[ap.JobKey(ID(2))]
	if job.Outcome == nil || job.Outcome.Kind != ap.OutcomeApprovalLost {
		t.Fatalf("deferred admission did not close: %+v", job.Outcome)
	}
}

func TestLateReportFailedSinkSchedule(t *testing.T) {
	m := NewModel(0)
	s, e := m.Signer, m.Exec
	gid, id := ID(1), ID(2)
	if a := s.Submit(PrincipalA, GrantDraft(gid, "web-1", time.Hour, m.Clock.Wall)); a.Code != "" {
		t.Fatal(a)
	}
	m.approve(ap.RecordKey(PrincipalA, gid))
	if code := e.Submit(JobDraft(id, ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 1))); code != "" {
		t.Fatal(code)
	}
	jk, key := ap.JobKey(id), ap.RecordKey(PrincipalA, id)
	e.Drive(jk, 1)
	if h := s.Store[key].Header; h.Decision == nil || h.Decision.DecidedBy != ap.GrantDecidedPrefix+gid || h.AssistDeadline != m.Clock.Wall.Add(5*time.Second) {
		t.Fatal("invalid grant/assist fixture")
	}
	m.Clock.Advance(time.Second)
	if a := s.Claim(key, Token(id)); a.Claim != ap.ClaimExpired {
		t.Fatal(a)
	}
	s.FlushPass()
	s.Do(key, ap.ShedRecord{Pressure: true})
	s.Sink.Fail = true
	m.Clock.Advance(4 * time.Second)
	s.Do(key, ap.Tick{})
	if a := s.Claim(key, Token("invalid")); a.Code != ap.CodeInvalidClaim {
		t.Fatal(a)
	}
	e.Drive(jk, 40)
	if h := s.Store[key].Header; h.FinalReport == nil {
		t.Fatal("valid late report not recorded")
	}
	job := e.Jobs[jk]
	if job.ReportResult == nil || job.ReportResult.State != ap.ReportAcked {
		t.Fatalf("report not settled as acknowledged: %+v", job.ReportResult)
	}
	if len(e.Gate.Dispatches) != 0 {
		t.Fatal("expired job dispatched")
	}
	if ap.Class(s.Store[key], m.Clock.Now(), s.Settings, false) != ap.ClassSettled {
		t.Fatal("signer record not settled")
	}
	if s.Err != nil {
		t.Fatal(s.Err)
	}
}
