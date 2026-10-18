package lifecycletest

import (
	"context"
	"reflect"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func grants(t *testing.T, factory StoreFactory) {
	for _, end := range []string{"revoke", "wall", "elapsed", "suspend", "restart"} {
		t.Run(end, func(t *testing.T) {
			f := newFixture(t, factory)
			n := &notifier{}
			f.config.Notifier = n
			f.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return nil })
			f.open()
			if _, err := f.engine.Submit(context.Background(), st.PrincipalA, st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0)); err != nil {
				t.Fatal(err)
			}
			f.clock.Advance(5 * time.Second)
			if err := f.engine.Reconcile(); err != nil {
				t.Fatal(err)
			}
			f.run()
			eventually(t, func() bool {
				r := f.record()
				return len(r.Payload.CardEntries) == 1 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
			})
			card := n.latest()
			answer, err := f.engine.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: card.Handle, Challenge: card.Challenge, MsgID: 4}})
			if err != nil || answer.Noise {
				t.Fatalf("grant vote: %+v %v", answer, err)
			}
			probe := func(id int, principal string) ap.Summary {
				t.Helper()
				d := st.JobDraft(st.ID(id), ap.CoordinatorExecutor, f.clock.Wall(), st.Write("true", 60))
				s, err := f.engine.Submit(context.Background(), principal, d)
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			if probe(2, st.PrincipalA).ApprovalStatus != ap.ApprovalApproved {
				t.Fatal("positive control: grant not live")
			}
			if probe(3, st.PrincipalB).ApprovalStatus != ap.ApprovalPending {
				t.Fatal("foreign principal spent grant")
			}
			switch end {
			case "revoke":
				if err := f.engine.Revoke("web-1"); err != nil {
					t.Fatal(err)
				}
				eventually(t, func() bool {
					r := f.record()
					return r.Header.AuditedThrough == r.Header.OutboxSeq && ap.NotifyNext(r, ap.Now{Wall: f.clock.Wall()}, st.Epoch(99), ap.LocalSettings).Kind == ap.NotifyNone
				})
				before := f.record()
				if err := f.engine.Revoke("web-1"); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, f.record()) {
					t.Fatal("Revoke replay changed record")
				}
			case "wall":
				f.clock.StepWall(time.Hour)
			case "elapsed":
				f.clock.Advance(time.Hour)
				f.clock.StepWall(-time.Hour)
			case "suspend":
				f.clock.Suspend(8 * time.Hour)
			case "restart":
				f.engine.Close()
				f.open()
				f.run()
			}
			if err := f.engine.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if probe(4, st.PrincipalA).ApprovalStatus != ap.ApprovalPending {
				t.Fatal("ended grant authorized Submit")
			}
			f.clock.StepWall(-time.Hour)
			if probe(5, st.PrincipalA).ApprovalStatus != ap.ApprovalPending {
				t.Fatal("wall rollback revived grant")
			}
		})
	}
}
