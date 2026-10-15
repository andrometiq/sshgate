package approvalplan_test

import (
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// rig is a model signer whose every commit is checked by statetest's
// transition invariants; a violation fails the test at cleanup.
type rig struct {
	t     *testing.T
	clock *st.Clock
	s     *st.Signer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	clock := &st.Clock{Wall: st.T0, Elapsed: time.Hour}
	s := st.NewSigner(clock, 1)
	s.Validity = ap.ValidityDefault
	t.Cleanup(func() {
		if s.Err != nil {
			t.Errorf("invariant violated: %v", s.Err)
		}
	})
	return &rig{t: t, clock: clock, s: s}
}

func (r *rig) now() ap.Now { return r.clock.Now() }

func (r *rig) rec(key string) ap.R1 {
	r.t.Helper()
	rec, ok := r.s.Store[key]
	if !ok {
		r.t.Fatalf("no record %s", key)
	}
	return rec
}

func (r *rig) view(key string) ap.Summary {
	r.t.Helper()
	sum, ok := r.s.Get(key)
	if !ok {
		r.t.Fatalf("no record %s", key)
	}
	return sum
}

// submit submits a command_job for PrincipalA and returns its record key.
func (r *rig) submit(id string, coord ap.Coordinator, specs ...st.StepSpec) string {
	r.t.Helper()
	if ans := r.s.Submit(st.PrincipalA, st.JobDraft(id, coord, r.clock.Wall, specs...)); ans.Code != "" {
		r.t.Fatalf("submit %s: %+v", id, ans)
	}
	return ap.RecordKey(st.PrincipalA, id)
}

// approve delivers the card, fills assist, confirms the edit and taps
// Approve, then flushes: the record is approved at the returned decided_at.
func (r *rig) approve(key string) time.Time {
	r.t.Helper()
	r.s.AssistArrives(key, false)
	r.s.Reconcile(key)
	if ans := r.s.Tap(key, ap.VoteApprove, st.Operator, true); ans.Code != "" || ans.Noise {
		r.t.Fatalf("approve %s: %+v", key, ans)
	}
	r.s.FlushPass()
	d := r.rec(key).Header.Decision
	if d == nil || d.Status != ap.ApprovalApproved {
		r.t.Fatalf("approve %s: decision %+v", key, d)
	}
	return d.DecidedAt
}

func (r *rig) claim(key, id string) ap.Answer {
	r.t.Helper()
	return r.s.Claim(key, st.Token(id))
}

// apply runs one command directly through Apply and commits it into the rig.
func (r *rig) apply(key string, cmd ap.Command) ap.Answer {
	r.t.Helper()
	rec := r.rec(key)
	after, ans := ap.Apply(&rec, cmd, r.now(), ap.Inputs{Epoch: r.s.Epoch, Settings: r.s.Settings})
	if ans.Changed {
		if err := st.CheckTransition(&rec, after, r.now()); err != nil {
			r.t.Fatalf("%T: %v", cmd, err)
		}
		r.s.Store[key] = after
	}
	return ans
}

func eventKinds(rec ap.R1, afterSeq uint64) []string {
	var kinds []string
	for _, e := range rec.Header.Outbox {
		if e.Seq > afterSeq {
			kinds = append(kinds, e.Kind)
		}
	}
	return kinds
}

type replayRow int

const (
	// exact: the second application changes nothing.
	exact replayRow = iota
	// noiseOnly: the second changes the record by exactly one noise event.
	noiseOnly
	// counterOnly: the second adds exactly 1 to claim_count, nothing else.
	counterOnly
)

// SA-11's replay rows (r5.4): every command applied twice, right after
// itself at the same instant, meets exactly its row.
func TestReplayRows(t *testing.T) {
	type setup func(r *rig) (string, ap.Command)
	pending := func(r *rig) string { return r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60)) }
	approved := func(r *rig) string { k := pending(r); r.approve(k); return k }
	rows := []struct {
		name  string
		setup setup
		row   replayRow
	}{
		{"submit same draft", func(r *rig) (string, ap.Command) {
			k := pending(r)
			return k, st.SubmitOf(st.JobDraft(st.ID(1), ap.CoordinatorExecutor, r.rec(k).Header.CreatedAt, st.Write("w", 60)), st.PrincipalA, r.clock.Wall, r.s.Validity)
		}, exact},
		{"assist result", func(r *rig) (string, ap.Command) {
			res := st.Assist(r.clock.Wall)
			return pending(r), ap.AssistDone{Result: &res}
		}, exact},
		{"tick", func(r *rig) (string, ap.Command) { return pending(r), ap.Tick{} }, exact},
		{"flush", func(r *rig) (string, ap.Command) {
			k := pending(r)
			return k, ap.Flush{Through: r.rec(k).Header.OutboxSeq}
		}, exact},
		{"burst start", func(r *rig) (string, ap.Command) { return pending(r), ap.BurstStart{} }, exact},
		{"card start", func(r *rig) (string, ap.Command) {
			k := pending(r)
			r.s.Do(k, ap.BurstStart{})
			r.s.Do(k, ap.BurstDone{PartMsgIDs: []int64{1}})
			h, c := r.s.NewCard()
			return k, ap.CardStart{Handle: h, ChalHash: c}
		}, exact},
		{"renotify, resend due", func(r *rig) (string, ap.Command) { return pending(r), ap.Renotify{} }, exact},
		{"renotify, none due", func(r *rig) (string, ap.Command) {
			k := pending(r)
			r.s.Reconcile(k)
			return k, ap.Renotify{}
		}, exact},
		{"admin cancel", func(r *rig) (string, ap.Command) {
			k := pending(r)
			return k, ap.AdminCancel{PlanHash: r.rec(k).Header.PlanHash, Admin: st.Admin}
		}, exact},
		{"revoke", func(r *rig) (string, ap.Command) { return r.grant(st.ID(5), st.PrincipalA, 3600e9), ap.Revoke{} }, exact},
		{"shed", func(r *rig) (string, ap.Command) {
			k := pending(r)
			r.s.Cancel(k)
			r.s.FlushPass()
			return k, ap.ShedRecord{Pressure: true}
		}, exact},
		{"report duplicate", func(r *rig) (string, ap.Command) {
			k := approved(r)
			return k, ap.Report{Token: st.Token(st.ID(1)), PlanHash: r.rec(k).Header.PlanHash, Body: negativeReport(1)}
		}, exact},
		{"vote", func(r *rig) (string, ap.Command) {
			k := pending(r)
			r.s.Reconcile(k)
			e := r.entries(k)[0]
			return k, ap.CastVote{Operator: st.Operator, Decision: ap.VoteDeny, Authn: "telegram", Flags: ap.LocalVoteFlags,
				Card: &ap.CardTap{Handle: e.Handle, Challenge: "0000000000000000", MsgID: *e.MsgID}}
		}, noiseOnly},
		{"invalid claim", func(r *rig) (string, ap.Command) { return approved(r), ap.Claim{Token: st.Token("x")} }, noiseOnly},
		{"invalid report", func(r *rig) (string, ap.Command) { return approved(r), ap.Report{Token: st.Token("x")} }, noiseOnly},
		{"claim", func(r *rig) (string, ap.Command) {
			k := approved(r)
			r.claim(k, st.ID(1))
			return k, ap.Claim{Token: st.Token(st.ID(1)), PlanHash: r.rec(k).Header.PlanHash}
		}, counterOnly},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t)
			key, cmd := row.setup(r)
			in := ap.Inputs{Epoch: r.s.Epoch, Settings: r.s.Settings}
			rec := r.rec(key)
			first, ans1 := ap.Apply(&rec, cmd, r.now(), in)
			if !ans1.Changed {
				first = rec
			}
			second, ans2 := ap.Apply(&first, cmd, r.now(), in)
			switch row.row {
			case exact:
				if ans2.Changed || ans2.Code != "" && ans2.Code != ans1.Code {
					t.Fatalf("second application %+v after %+v", ans2, ans1)
				}
			case noiseOnly:
				f, s := first.Header, second.Header
				if !ans2.Noise || s.OutboxSeq != f.OutboxSeq+1 || !s.Outbox[len(s.Outbox)-1].Replay || len(s.Votes) != len(f.Votes) || ans2.Reason != ans1.Reason {
					t.Fatalf("second application %+v", ans2)
				}
				s.Outbox, s.OutboxSeq, f.Outbox, f.OutboxSeq = nil, 0, nil, 0
				if mustJSON(t, s) != mustJSON(t, f) {
					t.Fatal("a noise replay changed more than the outbox")
				}
			case counterOnly:
				if ans2.Claim != ap.ClaimSignatures || mustJSON(t, ans2.Signatures) != mustJSON(t, ans1.Signatures) {
					t.Fatalf("repeat claim %+v", ans2)
				}
				first.Header.ClaimCount++
				if mustJSON(t, first) != mustJSON(t, second) {
					t.Fatal("a repeat claim changed more than claim_count")
				}
			}
		})
	}
}
