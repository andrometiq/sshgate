package statetest

import (
	"fmt"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func (m *Model) approve(key string) {
	s := m.Signer
	s.AssistArrives(key, false)
	s.Reconcile(key)
	s.Tap(key, ap.VoteApprove, Operator, true)
	s.FlushPass()
}

// witnesses guarantees useful execution and a crash between marker and
// result in every run; random schedules then explore other prefixes.
func (m *Model) witnesses() {
	s, e := m.Signer, m.Exec
	for i := 0; i < 3; i++ {
		m.ids++
		id := ID(m.ids)
		key := ap.RecordKey(PrincipalA, id)
		jk := ap.JobKey(id)
		if code := e.Submit(JobDraft(id, ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))); code != "" {
			s.fail(fmt.Errorf("witness admission: %s", code))
			return
		}
		e.Drive(jk, 1)
		if _, ok := s.Store[key]; !ok {
			s.fail(fmt.Errorf("witness signer admission failed"))
			return
		}
		// A pending request, and then an approved but unflushed request, must
		// release nothing. This also exercises audit bypass mutants directly.
		if a := s.Claim(key, Token(id)); len(a.Signatures) > 0 {
			s.fail(fmt.Errorf("pending witness released signatures"))
		}
		s.Sink.Fail = true
		m.approve(key)
		if a := s.Claim(key, Token(id)); len(a.Signatures) > 0 {
			s.fail(fmt.Errorf("unflushed witness released signatures"))
		}
		s.Sink.Fail = false
		s.FlushPass()
		if i == 2 {
			e.BeforeStart = func() { m.dispatchCuts++; e.BeforeStart = nil; panic(crash{owner: "executor"}) }
		}
		m.guard(func() { e.Drive(jk, 40) })
		e.Drive(jk, 40)
	}
	// A human-approved grant is tried against hostile principal and host
	// bindings before its valid use. The oracle does not call GrantCovers.
	m.ids++
	gid := ID(m.ids)
	gkey := ap.RecordKey(PrincipalA, gid)
	s.Submit(PrincipalA, GrantDraft(gid, "web-1", time.Hour, m.Clock.Wall))
	m.approve(gkey)
	for _, foreign := range []bool{true, false} {
		m.ids++
		d := JobDraft(ID(m.ids), ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60))
		principal := PrincipalA
		if foreign {
			principal = PrincipalB
		} else {
			d.CommandJob.Steps[0].Target.TrustedHostFingerprint = Fingerprint("other")
			d.CommandJob.Steps[0].RegistryEntryDigest = d.CommandJob.Steps[0].Target.Digest()
		}
		a := s.Submit(principal, d)
		key := ap.RecordKey(principal, d.RequestID)
		if a.Code != "" {
			s.fail(fmt.Errorf("binding witness admission: %s", a.Code))
			continue
		}
		if s.Store[key].Header.Decision != nil {
			s.fail(fmt.Errorf("grant crossed principal/host binding"))
		}
	}
	m.ids++
	id := ID(m.ids)
	e.Submit(JobDraft(id, ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60)))
	e.Drive(ap.JobKey(id), 1)
	if d := s.Store[ap.RecordKey(PrincipalA, id)].Header.Decision; d == nil || d.DecidedBy != ap.GrantDecidedPrefix+gid {
		s.fail(fmt.Errorf("live grant witness was not approved by its grant"))
		return
	}
	s.FlushPass()
	e.Drive(ap.JobKey(id), 40)
	// Revoke and pressure-shed the newest grant: it must never cover again.
	s.RevokeAlias("web-1")
	s.FlushPass()
	s.Do(gkey, ap.ShedRecord{Pressure: true})
	m.ids++
	id = ID(m.ids)
	s.Submit(PrincipalA, JobDraft(id, ap.CoordinatorExecutor, m.Clock.Wall, Write("w", 60)))
	if s.Store[ap.RecordKey(PrincipalA, id)].Header.Decision != nil {
		s.fail(fmt.Errorf("shed grant revived"))
	}
}
