package lifecycletest

import (
	"context"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func replay(t *testing.T, factory StoreFactory) {
	f := newFixture(t, factory)
	n := &notifier{}
	var mints atomic.Int32
	f.config.Notifier = n
	f.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return nil })
	f.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
		if !at.Equal(f.record().Header.Decision.DecidedAt) {
			t.Error("mint did not use persisted decision")
		}
		return []string{st.Sig(p.RequestID, 1, int(mints.Add(1)))}, nil
	})
	f.open()
	summary := f.submit()
	before, count := f.record(), f.store.count()
	repeated := f.submit()
	if !reflect.DeepEqual(summary, repeated) || !reflect.DeepEqual(before, f.record()) || count != f.store.count() {
		t.Fatal("Submit replay changed record or answer")
	}
	_, foreign := f.engine.Get(st.PrincipalB, st.ID(1))
	_, absent := f.engine.Get(st.PrincipalB, st.ID(999))
	if foreign == nil || absent == nil || foreign.Error() != absent.Error() {
		t.Fatal("foreign ID disclosed existence")
	}
	f.clock.Advance(5 * time.Second)
	f.engine.Get(st.PrincipalA, st.ID(1))
	f.engine.List(st.PrincipalA)
	if !reflect.DeepEqual(before, f.record()) || count != f.store.count() {
		t.Fatal("views wrote time facts")
	}
	if err := f.engine.Reconcile(); err != nil {
		t.Fatal(err)
	}
	f.run()
	eventually(t, func() bool {
		r := f.record()
		return len(r.Payload.CardEntries) == 1 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
	})
	card := n.latest()
	vote := ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: card.Handle, Challenge: card.Challenge, MsgID: 4}}
	if answer, err := f.engine.Vote(vote); err != nil || answer.Noise {
		t.Fatalf("vote: %+v %v", answer, err)
	}
	claim := ap.Claim{Token: st.Token(st.ID(1)), PlanHash: summary.PlanHash}
	first, err := f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
	if err != nil || first.Claim != ap.ClaimSignatures {
		t.Fatalf("Claim: %+v %v", first, err)
	}
	eventually(t, func() bool {
		r := f.record()
		return r.Header.AuditedThrough == r.Header.OutboxSeq && len(r.Payload.StatusEdits) > 0 && ap.NotifyNext(r, ap.Now{Wall: f.clock.Wall()}, st.Epoch(99), ap.LocalSettings).Kind == ap.NotifyNone
	})
	// Compare after the flusher and status driver reach their fixed point.
	before = f.record()
	second, err := f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
	if err != nil || !reflect.DeepEqual(first.Signatures, second.Signatures) || mints.Load() != 1 {
		t.Fatal("Claim reminted or changed released bytes")
	}
	after := f.record()
	if after.Header.ClaimCount != before.Header.ClaimCount+1 {
		t.Fatal("repeat Claim did not increment exactly once")
	}
	after.Header.ClaimCount = before.Header.ClaimCount
	if !reflect.DeepEqual(before, after) {
		t.Fatal("repeat Claim changed more than claim_count")
	}
	if err := st.CheckRecordAnswer(f.record(), second, ap.Now{Wall: f.clock.Wall(), Elapsed: f.clock.Elapsed()}); err != nil {
		t.Fatal(err)
	}
	view, err := f.engine.Get(st.PrincipalA, st.ID(1))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := f.engine.List(st.PrincipalA)
	if err != nil {
		t.Fatal(err)
	}
	waited, err := f.engine.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{view, listed, waited} {
		encoded, err := ap.Canonical(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), first.Signatures[0]) {
			t.Fatal("non-Claim view released signatures")
		}
	}

	for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
		vote.Decision = decision
		before = f.record()
		answer, err := f.engine.Vote(vote)
		after = f.record()
		if err != nil || !answer.Noise || after.Header.OutboxSeq != before.Header.OutboxSeq+1 || !reflect.DeepEqual(after.Header.Decision, before.Header.Decision) || len(after.Header.Votes) != len(before.Header.Votes) {
			t.Fatal("vote replay was not one inert noise event")
		}
	}
	states := []ap.StepStatus{ap.StepSucceeded}
	report := ap.Report{Token: st.Token(st.ID(1)), PlanHash: summary.PlanHash, Body: ap.FinalReport{Class: ap.AggregateJobClass(states), ExecutedOrdinals: ap.ExecutedOrdinals(states), Partial: ap.Partial(states), Steps: []ap.StepReport{{Ordinal: 1, Status: states[0]}}, ResultDigest: strings.Repeat("a", 64)}}
	if _, err := f.engine.Report(st.PrincipalA, st.ID(1), report); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		r := f.record()
		return r.Header.AuditedThrough == r.Header.OutboxSeq && len(r.Payload.StatusEdits) >= 2 && ap.NotifyNext(r, ap.Now{Wall: f.clock.Wall()}, st.Epoch(99), ap.LocalSettings).Kind == ap.NotifyNone
	})
	before = f.record()
	if _, err := f.engine.Report(st.PrincipalA, st.ID(1), report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.record()) {
		t.Fatal("duplicate report changed record")
	}
	if _, err := f.engine.Shed(st.PrincipalA, st.ID(1), true); err != nil {
		t.Fatal(err)
	}
	before = f.record()
	if !before.Header.Shed {
		t.Fatal("settled record not shed")
	}
	if _, err := f.engine.Shed(st.PrincipalA, st.ID(1), true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.record()) {
		t.Fatal("Shed replay changed header")
	}

}

func clockFacts(t *testing.T, factory StoreFactory) {
	for _, step := range []time.Duration{-10 * time.Second, -time.Hour, 8 * time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			f := newFixture(t, factory)
			f.open()
			summary := f.submit()
			f.clock.Advance(2 * time.Hour)
			if got, err := f.engine.Get(st.PrincipalA, st.ID(1)); err != nil || got.ApprovalStatus != ap.ApprovalPending {
				t.Fatal("read invented expiry")
			}
			if err := f.engine.Reconcile(); err != nil {
				t.Fatal(err)
			}
			before, count := f.record(), f.store.count()
			if before.Header.Assist == nil || before.Header.Decision == nil || before.Header.Decision.Status != ap.ApprovalExpired {
				t.Fatal("Clock omitted due slots")
			}
			f.clock.StepWall(step)
			if err := f.engine.Reconcile(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, f.record()) || count != f.store.count() {
				t.Fatal("Clock replay changed committed closure")
			}
			f.engine.Close()
			f.open()
			if got, err := f.engine.Get(st.PrincipalA, st.ID(1)); err != nil || got.ApprovalStatus != ap.ApprovalExpired {
				t.Fatal("Startup contradicted expiry")
			}
			answer, err := f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{Token: st.Token(st.ID(1)), PlanHash: summary.PlanHash})
			if err != nil || len(answer.Signatures) != 0 {
				t.Fatal("expired record released signatures")
			}
		})
	}
}

func releaseSkew(t *testing.T, factory StoreFactory) {
	for _, minted := range []bool{false, true} {
		name := "first_claim"
		if minted {
			name = "repeat_claim"
		}
		t.Run(name, func(t *testing.T) {
			trace := recoveryTrace(t)
			rec := trace[len(trace)-1]
			in := ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings, Minted: []string{st.Sig(st.ID(1), 1, 1)}}
			rec, _ = ap.Apply(&rec, ap.Flush{Through: rec.Header.OutboxSeq}, ap.Now{Wall: st.T0}, in)
			claim := ap.Claim{Token: st.Token(st.ID(1)), PlanHash: rec.Header.PlanHash}
			if minted {
				rec, _ = ap.Apply(&rec, claim, ap.Now{Wall: st.T0}, in)
			}
			f := newFixture(t, factory)
			if err := f.store.Store.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), rec); err != nil {
				t.Fatal(err)
			}
			f.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				t.Error("mint despite clock skew")
				return nil, nil
			})
			f.clock.StepWall(-time.Hour)
			f.open()
			answer, err := f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
			if err != nil || len(answer.Signatures) != 0 {
				t.Fatal("clock-skew Claim released bytes")
			}
			after := f.record()
			if minted {
				if answer.Claim != ap.ClaimExpired || len(after.Payload.Signatures) != 0 {
					t.Fatal("repeat Claim did not erase on clock skew")
				}
			} else if answer.Claim != ap.ClaimMaterializationError || after.Header.Mint == nil || after.Header.Mint.Reason != ap.MintReasonClockSkew {
				t.Fatal("first Claim did not commit clock-skew refusal")
			}
			f.clock.StepWall(time.Hour)
			f.engine.Close()
			f.open()
			answer, err = f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
			if err != nil || len(answer.Signatures) != 0 {
				t.Fatal("restart reversed clock-skew closure")
			}
		})
	}
}
