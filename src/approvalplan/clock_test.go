package approvalplan_test

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func TestStaticTimeReads(t *testing.T) {
	var files []string
	for _, pattern := range []string{"*.go", "statetest/*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if filepath.Ext(m) == ".go" && !slices.Contains([]string{"_test.go"}, m[max(0, len(m)-8):]) {
				files = append(files, m)
			}
		}
	}
	if len(files) < 20 {
		t.Fatalf("found only %d files", len(files))
	}
	elapsedtest.AssertNoDirectTimeReads(t, files)
}

// Clock order after downtime: one pass writes assist unavailable, then the
// expiry, whose assist_bound is that unavailable slot.
func TestClockOrderAfterDowntime(t *testing.T) {
	r := newRig(t)
	r.s.Validity = ap.ValidityMin
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	seq := r.rec(key).Header.OutboxSeq
	r.clock.Advance(ap.ValidityMin + time.Second)
	r.s.Reconcile(key)
	rec := r.rec(key)
	if got := eventKinds(rec, seq); !slices.Equal(got[:2], []string{ap.EventAssist, ap.EventDecision}) {
		t.Fatalf("events %v", got)
	}
	d, a := rec.Header.Decision, rec.Header.Assist
	if d.Status != ap.ApprovalExpired || !d.DecidedAt.Equal(rec.Header.RequestExpiresAt) || d.DecidedBy != ap.DecidedByClock {
		t.Fatalf("decision %+v", d)
	}
	if want := (ap.AssistBound{State: ap.AssistUnavailable, Revision: 1, Digest: a.Digest}); d.AssistBound != want {
		t.Fatalf("assist_bound %+v, want %+v", d.AssistBound, want)
	}
}

// Clock is idempotent, never overwrites a slot, and its unavailable snapshot
// is a pure function of the header: two passes at different instants write
// byte-identical slots.
func TestClockIdempotentPure(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	rec := r.rec(key)
	at := func(d time.Duration) ap.Now { return ap.Now{Wall: rec.Header.AssistDeadline.Add(d)} }
	a, ev := ap.Clock(rec, at(time.Second), r.s.Epoch)
	b, _ := ap.Clock(rec, at(time.Hour), r.s.Epoch)
	if len(ev) != 1 || *a.Header.Assist != *b.Header.Assist {
		t.Fatalf("snapshots differ: %+v vs %+v", a.Header.Assist, b.Header.Assist)
	}
	if again, ev := ap.Clock(a, at(2*time.Second), r.s.Epoch); len(ev) != 0 || *again.Header.Assist != *a.Header.Assist {
		t.Fatal("Clock is not idempotent")
	}
	if early, ev := ap.Clock(rec, at(-time.Second), r.s.Epoch); len(ev) != 0 || early.Header.Assist != nil {
		t.Fatal("Clock wrote a deadline after now")
	}
	r.s.AssistArrives(key, false)
	ready := r.rec(key)
	if after, ev := ap.Clock(ready, at(time.Hour), r.s.Epoch); len(ev) != 0 || *after.Header.Assist != *ready.Header.Assist {
		t.Fatal("Clock overwrote a filled assist slot")
	}
}

// A vote at request_expires_at + 1 s with the tick paused commits expired and
// vote_refused in one commit and is refused.
func TestVoteAfterExpiryTickPaused(t *testing.T) {
	r := newRig(t)
	r.s.Validity = ap.ValidityMin
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	r.clock.Advance(ap.ValidityMin + time.Second)
	before := r.s.Commits
	seq := r.rec(key).Header.OutboxSeq
	ans := r.s.Tap(key, ap.VoteApprove, st.Operator, true)
	rec := r.rec(key)
	if !ans.Noise || ans.Reason != "expired" || r.s.Commits != before+1 || len(rec.Header.Votes) != 0 {
		t.Fatalf("answer %+v commits %d", ans, r.s.Commits-before)
	}
	if got := eventKinds(rec, seq); !slices.Contains(got, ap.EventDecision) || !slices.Contains(got, ap.EventVoteRefused) {
		t.Fatalf("events %v", got)
	}
}

// X3: an idempotent re-Submit and a not_ready Claim each commit a due Clock
// fact exactly once, and nothing when nothing is due.
func TestDueClockCommitsOnce(t *testing.T) {
	r := newRig(t)
	id := st.ID(1)
	d := st.JobDraft(id, ap.CoordinatorExecutor, r.clock.Wall, st.Write("w", 60))
	key := r.submit(id, ap.CoordinatorExecutor, st.Write("w", 60))
	r.clock.Advance(10 * time.Second)
	for i, want := range []bool{true, false} {
		if ans := r.s.Submit(st.PrincipalA, d); ans.Code != "" || ans.Changed != want {
			t.Fatalf("resubmit %d: %+v", i, ans)
		}
	}
	if r.rec(key).Header.Assist == nil {
		t.Fatal("resubmit did not commit Clock's assist slot")
	}
	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.clock.Advance(10 * time.Second)
	for i, want := range []bool{true, false} {
		if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimNotReady || ans.Changed != want {
			t.Fatalf("claim %d: %+v", i, ans)
		}
	}
}

// The first window: an unclaimed record's window closes at the first signed
// step's end; once claimed, the Erase comes at the last.
func TestFirstWindow(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("a", 30), st.Write("b", 60))
	decided := r.approve(key)
	first := time.Unix(decided.Unix()+30, 0).UTC()
	r.clock.Wall = first.Add(-time.Second)
	if c := r.view(key).Class; c != ap.ClassLive {
		t.Fatalf("class before first_end %s", c)
	}
	r.clock.Wall = first
	r.s.Tick()
	sum := r.view(key)
	if sum.Class != ap.ClassSettled || sum.ExecutionStatus != ap.ExecutionExpiredUnclaimed {
		t.Fatalf("after first_end: %+v", sum)
	}
	if ans := r.claim(key, st.ID(1)); ans.Claim != ap.ClaimExpired {
		t.Fatalf("claim %+v", ans)
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("a", 30), st.Write("b", 60))
	decided = r.approve(key2)
	if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimSignatures {
		t.Fatalf("claim %+v", ans)
	}
	r.clock.Wall = time.Unix(decided.Unix()+59, 0).UTC()
	r.s.Tick()
	if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimSignatures {
		t.Fatalf("repeat claim before last_end: %+v", ans)
	}
	r.clock.Wall = time.Unix(decided.Unix()+60, 0).UTC()
	r.s.Tick()
	if rec := r.rec(key2); rec.Payload.Signatures != nil || rec.Header.Mint.State != ap.MintSignatures {
		t.Fatal("no Erase at last_end")
	}
	if sum := r.view(key2); sum.Class != ap.ClassAwaitingReport || sum.ExecutionStatus != ap.ExecutionExecuting {
		t.Fatalf("after Erase: %+v", sum)
	}
}

// Windows exist only for signed steps, end at whole seconds, and the claim
// answer carries every step's window.
func TestWindowsSignedStepsWholeSeconds(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Read("df"), st.Write("w", 60))
	decided := r.approve(key)
	end, _ := ap.ClaimEnd(r.rec(key))
	if want := time.Unix(decided.Unix()+60, 0).UTC(); !end.Equal(want) {
		t.Fatalf("claim_end %s, want %s", end, want)
	}
	r.clock.Advance(time.Second)
	ans := r.claim(key, st.ID(1))
	if ans.Claim != ap.ClaimSignatures || len(ans.Windows) != 2 || !ans.Windows[0].IsZero() || !ans.Windows[1].Equal(end) {
		t.Fatalf("claim %+v", ans)
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60), st.Read("df"))
	r.s.AssistArrives(key2, false)
	r.s.Reconcile(key2)
	r.clock.Wall = r.clock.Wall.Truncate(time.Second).Add(time.Second + 900*time.Millisecond)
	r.s.Tap(key2, ap.VoteApprove, st.Operator, true)
	r.s.FlushPass()
	d := r.rec(key2).Header.Decision.DecidedAt
	if d.Nanosecond() != 900_000_000 {
		t.Fatalf("decided_at %s", d)
	}
	end, _ = ap.ClaimEnd(r.rec(key2))
	if want := time.Unix(d.Unix()+60, 0).UTC(); !end.Equal(want) {
		t.Fatalf("claim_end %s, want %s", end, want)
	}
	r.clock.Wall = end.Add(200 * time.Millisecond)
	if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimExpired {
		t.Fatalf("claim past the whole-second end: %+v", ans)
	}
}

// next_due_at walks a claimed, unreported record: claim_end (the Erase),
// then the report horizon, then the Shed age; the tick alone moves it out
// of live at claim_end.
func TestNextDueAt(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	decided := r.approve(key)
	r.claim(key, st.ID(1))
	r.s.FlushPass()
	end, _ := ap.ClaimEnd(r.rec(key))
	s := r.s.Settings
	if due := ap.NextDueAt(r.rec(key), r.now(), s); !due.Equal(end) {
		t.Fatalf("due %s, want claim_end %s", due, end)
	}
	r.clock.Wall = end
	r.s.Tick()
	if c := r.view(key).Class; c != ap.ClassAwaitingReport {
		t.Fatalf("class at claim_end %s", c)
	}
	horizon := end.Add(s.ReportHorizon)
	if due := ap.NextDueAt(r.rec(key), r.now(), s); !due.Equal(horizon) {
		t.Fatalf("due %s, want horizon %s", due, horizon)
	}
	r.clock.Wall = horizon
	if due := ap.NextDueAt(r.rec(key), r.now(), s); !due.Equal(decided.Add(s.Retention)) {
		t.Fatalf("due %s, want shed age", due)
	}
	if sum := r.view(key); sum.ExecutionStatus != ap.ExecutionUnreported || sum.Class != ap.ClassSettled {
		t.Fatalf("after horizon: %+v", sum)
	}
}

// With the flusher stopped, a Claim past claim_end answers expired (and
// commits window_closed), never not_ready.
func TestClaimPrecedenceFlusherStopped(t *testing.T) {
	r := newRig(t)
	r.s.Sink.Fail = true
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	decided := r.approve(key)
	if ans := r.claim(key, st.ID(1)); ans.Claim != ap.ClaimNotReady {
		t.Fatalf("claim before flush: %+v", ans)
	}
	r.clock.Wall = time.Unix(decided.Unix()+60, 0).UTC()
	if ans := r.claim(key, st.ID(1)); ans.Claim != ap.ClaimExpired || !ans.Changed {
		t.Fatalf("claim past claim_end: %+v", ans)
	}
	if m := r.rec(key).Header.Mint; m == nil || m.Reason != ap.MintReasonWindowClosed {
		t.Fatalf("mint %+v", m)
	}
}

// An in_process_sync record is claimable only until created_at + 310 s.
func TestSyncClaimDeadline(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorInProcessSync, st.Write("w", 60))
	created := r.rec(key).Header.CreatedAt
	r.clock.Wall = created.Add(300 * time.Second)
	r.approve(key)
	r.clock.Wall = created.Add(ap.SyncClaimWindow)
	ans := r.claim(key, st.ID(1))
	if ans.Claim != ap.ClaimExpired || r.rec(key).Header.Mint.Reason != ap.MintReasonWindowClosed {
		t.Fatalf("late sync claim: %+v", ans)
	}
	if v := r.view(key).ExecutionStatus; v != ap.ExecutionExpiredUnclaimed {
		t.Fatalf("view %s", v)
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorInProcessSync, st.Write("w", 60))
	created = r.rec(key2).Header.CreatedAt
	r.clock.Wall = created.Add(290 * time.Second)
	r.approve(key2)
	if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimSignatures {
		t.Fatalf("claim %+v", ans)
	}
	r.clock.Wall = created.Add(ap.SyncClaimWindow)
	r.s.Tick()
	if r.rec(key2).Payload.Signatures != nil {
		t.Fatal("a claimed sync record kept its bytes past the sync deadline")
	}
}

// SA-1 rule 3.2: no future-dated signature leaves the signer.
func TestReleaseCheck(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key)
	r.clock.Advance(time.Second)
	r.clock.StepWall(-10 * time.Second)
	r.clock.Advance(time.Second)
	if ans := r.claim(key, st.ID(1)); ans.Claim != ap.ClaimMaterializationError || ans.Reason != ap.MintReasonClockSkew {
		t.Fatalf("first claim 2 s after a 10 s step back: %+v", ans)
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key2)
	r.clock.Advance(time.Second)
	r.clock.StepWall(-10 * time.Second)
	r.clock.Advance(5 * time.Second)
	if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimSignatures {
		t.Fatalf("first claim 6 s after a 10 s step back: %+v", ans)
	}
	r.clock.StepWall(-time.Hour)
	if ans := r.claim(key2, st.ID(2)); ans.Claim != ap.ClaimExpired || r.rec(key2).Payload.Signatures != nil {
		t.Fatalf("repeat claim after a 1 h step back: %+v", ans)
	}
}

// Steps back of 10 s and of 1 h change no epoch and refuse no
// de-escalation, and a record decided after the step claims normally.
func TestStepBackRefusesNoDeescalation(t *testing.T) {
	for _, back := range []time.Duration{10 * time.Second, time.Hour} {
		r := newRig(t)
		epoch := r.s.Epoch
		cancel := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
		r.s.Submit(st.PrincipalA, st.GrantDraft(st.ID(2), "web-1", time.Hour, r.clock.Wall))
		grant := ap.RecordKey(st.PrincipalA, st.ID(2))
		r.approve(grant)
		r.clock.StepWall(-back)
		if ans := r.s.Cancel(cancel); ans.Code != "" || r.rec(cancel).Header.Decision.Status != ap.ApprovalCanceled {
			t.Fatalf("cancel after %s step back: %+v", back, ans)
		}
		r.s.RevokeAlias("web-1")
		if r.rec(grant).Header.RevokedAt == nil || r.s.Epoch != epoch {
			t.Fatalf("revoke after %s step back", back)
		}
		key := r.submit(st.ID(3), ap.CoordinatorExecutor, st.Write("w", 60))
		r.approve(key)
		if ans := r.claim(key, st.ID(3)); ans.Claim != ap.ClaimSignatures {
			t.Fatalf("claim after %s step back: %+v", back, ans)
		}
	}
}

// R-2 pinned: once both stores have deleted an ID, a step back of more than
// a day lets its exact bytes in as a new request, which still needs a vote.
func TestDeletedIDReplayNeedsAVote(t *testing.T) {
	r := newRig(t)
	r.s.Settings.MaxAge = time.Hour
	id := st.ID(1)
	d := st.JobDraft(id, ap.CoordinatorExecutor, r.clock.Wall, st.Write("w", 60))
	key := r.submit(id, ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	r.s.Tap(key, ap.VoteDeny, st.Operator, true)
	r.s.FlushPass()
	r.clock.Advance(ap.SubmitWindowMax + ap.DeleteFloor + time.Minute)
	r.s.Tick()
	r.s.Tick()
	if _, ok := r.s.Store[key]; ok {
		t.Fatal("the denied record was not deleted at its age")
	}
	r.clock.StepWall(-25 * time.Hour)
	if ans := r.s.Submit(st.PrincipalA, d); ans.Code != "" {
		t.Fatalf("replay: %+v", ans)
	}
	if sum := r.view(key); sum.ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("replayed request is %s", sum.ApprovalStatus)
	}
}

// S1 (D1): a record created on a fast clock that is then corrected is
// judged only by its own decided_at, at the wall clock of each evaluation:
// a restart writes no window_closed and no Erase, and the Claim succeeds.
func TestFastClockCorrected(t *testing.T) {
	r := newRig(t)
	r.clock.Wall = st.T0.Add(2 * time.Hour)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.clock.StepWall(-time.Hour)
	r.clock.Advance(10 * time.Minute)
	r.approve(key)
	r.clock.Advance(30 * time.Second)
	r.s.Restart()
	if m := r.rec(key).Header.Mint; m != nil {
		t.Fatalf("Startup wrote %+v", m)
	}
	r.clock.Advance(10 * time.Second)
	if ans := r.claim(key, st.ID(1)); ans.Claim != ap.ClaimSignatures {
		t.Fatalf("claim %+v", ans)
	}
}

// Flush retry (r5.5): an approved record whose flush failed is unflushed and
// due at claim_end only; once the sink recovers a retry pass releases the
// Claim before claim_end, and a sink dead for good ends it expired.
func TestFlushRetry(t *testing.T) {
	for _, recoverAfter := range []time.Duration{time.Second, 50 * time.Second, 0} {
		r := newRig(t)
		r.s.Sink.Fail = true
		key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
		decided := r.approve(key)
		end, _ := ap.ClaimEnd(r.rec(key))
		if !ap.Unflushed(r.rec(key)) || !ap.NextDueAt(r.rec(key), r.now(), r.s.Settings).Equal(end) {
			t.Fatal("a failed flush is not on the retry list, or moved next_due_at")
		}
		var got ap.Answer
		for wait := 250 * time.Millisecond; r.clock.Wall.Before(end.Add(time.Second)); wait = min(2*wait, 2*time.Second) {
			r.clock.Advance(wait)
			if recoverAfter > 0 && !r.clock.Wall.Before(decided.Add(recoverAfter)) {
				r.s.Sink.Fail = false
			}
			r.s.Tick()
			if got = r.claim(key, st.ID(1)); got.Claim != ap.ClaimNotReady {
				break
			}
		}
		want := ap.ClaimSignatures
		if recoverAfter == 0 {
			want = ap.ClaimExpired
		}
		if got.Claim != want {
			t.Fatalf("sink recovering after %s: claim %+v", recoverAfter, got)
		}
	}
}
