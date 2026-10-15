package approvalplan_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// Claim totality: every reachable combination of decision, mint slot, final
// report, claim_count, window position and flush gets exactly the answer
// SA-4 lists, in its precedence.
func TestClaimTotality(t *testing.T) {
	type state struct {
		name  string
		build func(r *rig, key string)
		want  ap.ClaimStatus
		// wantAfter is the answer once claim_end has passed.
		wantAfter ap.ClaimStatus
	}
	approved := func(r *rig, key string) { r.approve(key) }
	states := []state{
		{"pending", func(*rig, string) {}, ap.ClaimNotReady, ap.ClaimNotReady},
		{"approved unflushed", func(r *rig, key string) { r.s.Sink.Fail = true; r.approve(key) }, ap.ClaimNotReady, ap.ClaimExpired},
		{"approved", approved, ap.ClaimSignatures, ap.ClaimExpired},
		{"claimed", func(r *rig, key string) { approved(r, key); r.claim(key, idOf(key, r)) }, ap.ClaimSignatures, ap.ClaimExpired},
		{"denied", func(r *rig, key string) {
			r.s.Reconcile(key)
			r.s.Tap(key, ap.VoteDeny, st.Operator, true)
			r.s.FlushPass()
		}, ap.ClaimDenied, ap.ClaimDenied},
		{"canceled", func(r *rig, key string) { r.s.Cancel(key); r.s.FlushPass() }, ap.ClaimCanceled, ap.ClaimCanceled},
		{"error", func(r *rig, key string) { r.s.TG.Fail = true; r.s.Reconcile(key); r.s.FlushPass() }, ap.ClaimError, ap.ClaimError},
		{"reported unclaimed", func(r *rig, key string) {
			approved(r, key)
			r.s.Report(key, st.Token(idOf(key, r)), negativeReport(1))
			r.s.FlushPass()
		}, ap.ClaimExecutionReported, ap.ClaimExpired},
		{"reported claimed", func(r *rig, key string) {
			approved(r, key)
			r.claim(key, idOf(key, r))
			r.s.Report(key, st.Token(idOf(key, r)), reportOf(ap.StepSucceeded))
			r.s.FlushPass()
		}, ap.ClaimExpired, ap.ClaimExpired},
	}
	for _, s := range states {
		for _, past := range []bool{false, true} {
			for _, goodToken := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/past=%v/token=%v", s.name, past, goodToken), func(t *testing.T) {
					r := newRig(t)
					key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
					s.build(r, key)
					if past {
						r.clock.Advance(25 * time.Hour)
					}
					token := st.Token(st.ID(1))
					if !goodToken {
						token = st.Token("other")
					}
					ans := r.s.Claim(key, token)
					want := s.want
					if past {
						want = s.wantAfter
					}
					if !goodToken {
						if ans.Code != ap.CodeInvalidClaim || !ans.Noise {
							t.Fatalf("bad token: %+v", ans)
						}
						return
					}
					if ans.Code != "" || ans.Claim != want || !ans.Claim.Valid() {
						t.Fatalf("answer %+v, want %s", ans, want)
					}
				})
			}
		}
	}
}

func idOf(key string, r *rig) string { return r.rec(key).Header.RequestID }

func negativeReport(steps int) ap.FinalReport {
	statuses := make([]ap.StepStatus, steps)
	statuses[0] = ap.StepExpiredUnexecuted
	for i := 1; i < steps; i++ {
		statuses[i] = ap.StepNotRun
	}
	return reportOf(statuses...)
}

// reportOf is a report whose derived fields are computed from its steps.
func reportOf(statuses ...ap.StepStatus) ap.FinalReport {
	r := ap.FinalReport{Class: ap.AggregateJobClass(statuses), ExecutedOrdinals: ap.ExecutedOrdinals(statuses), Partial: ap.Partial(statuses)}
	r.ResultDigest = fmt.Sprintf("%064x", 7)
	for i, s := range statuses {
		r.Steps = append(r.Steps, ap.StepReport{Ordinal: i + 1, Status: s})
	}
	return r
}

// Report acceptance (SA-4 Report, E25, E29, E38).
func TestReportAcceptance(t *testing.T) {
	F, I, S, N, K, X := ap.StepFailed, ap.StepIndeterminate, ap.StepSucceeded, ap.StepNotRun, ap.StepSkipped, ap.StepExpiredUnexecuted
	bad := func(edit func(*ap.FinalReport), statuses ...ap.StepStatus) ap.FinalReport {
		r := reportOf(statuses...)
		edit(&r)
		return r
	}
	cases := []struct {
		name    string
		steps   int
		claimed bool
		report  ap.FinalReport
		ok      bool
	}{
		{"negative report, no claim", 1, false, reportOf(X), true},
		{"executed report without a claim", 1, false, reportOf(S), false},
		{"class disagrees", 1, true, bad(func(r *ap.FinalReport) { r.Class = ap.ClassFailed }, S), false},
		{"[failed, indeterminate] claiming partial", 2, true, bad(func(r *ap.FinalReport) { r.Partial = true }, F, I), false},
		{"[failed, indeterminate] omitting ordinal 2", 2, true, bad(func(r *ap.FinalReport) { r.ExecutedOrdinals = []int{1} }, F, I), false},
		{"[failed, indeterminate] exact", 2, true, reportOf(F, I), true},
		{"3 steps listing 2", 3, true, reportOf(F, I), false},
		{"3 steps listing 1", 3, true, reportOf(F), false},
		{"ordinals out of order", 3, true, bad(func(r *ap.FinalReport) { r.Steps[1].Ordinal, r.Steps[2].Ordinal = 3, 2 }, F, I, N), false},
		{"duplicate ordinal", 3, true, bad(func(r *ap.FinalReport) { r.Steps[2].Ordinal = 2 }, F, I, N), false},
		{"[not_run, succeeded, succeeded]", 3, true, reportOf(N, S, S), false},
		{"[indeterminate, succeeded, not_run]", 3, true, reportOf(I, S, N), false},
		{"[succeeded, skipped, failed]", 3, true, reportOf(S, K, F), false},
		{"[failed, indeterminate, not_run]", 3, true, reportOf(F, I, N), true},
		{"stop-policy [succeeded, failed, skipped]", 3, true, reportOf(S, F, K), true},
		{"negative [expired_unexecuted, not_run, not_run]", 3, false, reportOf(X, N, N), true},
		{"[stale_target, not_run, not_run]", 3, false, reportOf(ap.StepStaleTarget, N, N), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			specs := []st.StepSpec{st.Write("w", 60), st.Read("df"), st.Read("du")}[:c.steps]
			key := r.submit(st.ID(1), ap.CoordinatorExecutor, specs...)
			r.approve(key)
			if c.claimed {
				r.claim(key, st.ID(1))
			}
			ans := r.s.Report(key, st.Token(st.ID(1)), c.report)
			if got := ans.Code == ""; got != c.ok {
				t.Fatalf("accepted=%v, want %v: %+v", got, c.ok, ans)
			}
			if !c.ok && (ans.Code != ap.CodeInvalidReport || !ans.Noise) {
				t.Fatalf("refusal %+v", ans)
			}
			if c.ok && r.view(key).ExecutionStatus != ap.ExecutionFinal {
				t.Fatal("accepted report not final in the view")
			}
		})
	}
}

// An exact duplicate is acked, a different body refused; a report after the
// horizon and after a shed is accepted and replaces unreported.
func TestReportDuplicatesHorizonShed(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key)
	r.claim(key, st.ID(1))
	body := reportOf(ap.StepSucceeded)
	if ans := r.s.Report(key, st.Token(st.ID(1)), body); ans.Code != "" || r.rec(key).Payload.Signatures != nil {
		t.Fatalf("report %+v (accepting erases the bytes)", ans)
	}
	if ans := r.s.Report(key, st.Token(st.ID(1)), body); ans.Code != "" || ans.Changed {
		t.Fatalf("duplicate %+v", ans)
	}
	if ans := r.s.Report(key, st.Token(st.ID(1)), reportOf(ap.StepFailed)); ans.Code != ap.CodeInvalidReport {
		t.Fatalf("different body %+v", ans)
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key2)
	r.claim(key2, st.ID(2))
	r.clock.Advance(r.s.Settings.ReportHorizon + 2*time.Minute)
	r.s.Tick()
	if v := r.view(key2).ExecutionStatus; v != ap.ExecutionUnreported {
		t.Fatalf("view %s", v)
	}
	if ans := r.apply(key2, ap.ShedRecord{Pressure: true}); !ans.Changed {
		t.Fatalf("shed %+v", ans)
	}
	if ans := r.s.Report(key2, st.Token(st.ID(2)), body); ans.Code != "" {
		t.Fatalf("late report on a shed record %+v", ans)
	}
	if sum := r.view(key2); sum.ExecutionStatus != ap.ExecutionFinal || !sum.Pruned || sum.ExecutionClass != ap.ClassSucceeded {
		t.Fatalf("view after late report %+v", sum)
	}
}

// A repeat Claim returns byte-identical signatures, calls the minter no more
// and adds exactly 1 to claim_count; a stored plan corrupted to carry an XFER
// step never reaches the minter.
func TestRepeatClaimAndMintRecheck(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key)
	first := r.claim(key, st.ID(1))
	rec := r.rec(key)
	second, ans := ap.Apply(&rec, ap.Claim{Token: st.Token(st.ID(1)), PlanHash: rec.Header.PlanHash}, r.now(), ap.Inputs{Epoch: r.s.Epoch})
	if ans.Claim != ap.ClaimSignatures || ans.MintRequired || fmt.Sprint(ans.Signatures) != fmt.Sprint(first.Signatures) {
		t.Fatalf("repeat claim %+v", ans)
	}
	rec.Header.ClaimCount++
	if a, b := mustJSON(t, rec), mustJSON(t, second); a != b {
		t.Fatal("a repeat claim changed more than claim_count")
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key2)
	bad := r.rec(key2)
	bad.Payload.Plan.CommandJob.Steps[0].ExactCommand = "SSHGATE_XFER_SEND x"
	if _, err := ap.EncodeR1(bad); err == nil {
		t.Fatal("a record whose plan carries an XFER step encoded")
	}
	_, ans = ap.Apply(&bad, ap.Claim{Token: st.Token(st.ID(2)), PlanHash: bad.Header.PlanHash}, r.now(),
		ap.Inputs{Epoch: r.s.Epoch, Minted: []string{"SSHGATE_SIG:x"}})
	if ans.Code != ap.CodeRecordCorrupt || ans.Changed || ans.MintRequired || len(ans.Signatures) != 0 {
		t.Fatalf("corrupted plan claim %+v", ans)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Owner scope: with no record under the caller's key, every command answers
// the same not_found and writes nothing, so a foreign ID and an absent ID
// are indistinguishable.
func TestAbsentRecordAnswersIdentically(t *testing.T) {
	cmds := []ap.Command{
		ap.AssistDone{Unavailable: "x"}, ap.CastVote{}, ap.AdminCancel{}, ap.Revoke{}, ap.Tick{}, ap.Flush{},
		ap.ShedRecord{}, ap.Delete{}, ap.Claim{}, ap.Report{}, ap.Renotify{}, ap.BurstStart{}, ap.BurstDone{},
		ap.CardStart{}, ap.CardDone{}, ap.EditStart{}, ap.EditDone{}, ap.StatusEdited{},
	}
	for _, cmd := range cmds {
		rec, ans := ap.Apply(nil, cmd, ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1)})
		if mustJSON(t, ans) != mustJSON(t, ap.Answer{Code: ap.CodeNotFound}) || mustJSON(t, rec) != mustJSON(t, ap.R1{}) {
			t.Errorf("%T: %+v", cmd, ans)
		}
	}
}
