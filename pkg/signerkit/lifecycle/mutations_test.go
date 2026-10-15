package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

type mintFunc func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error)

func (f mintFunc) Mint(ctx context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	return f(ctx, p, at)
}

func submitJob(t *testing.T, e *Engine, id int) ap.Summary {
	t.Helper()
	sum, err := e.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(id), ap.CoordinatorExecutor, e.config.Clock.Wall(), st.Write("touch /tmp/example", 60)))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}
func readyCard(t *testing.T, e *Engine, id int, assist bool) ap.CastVote {
	t.Helper()
	if assist {
		command(t, e, id, ap.AssistDone{Unavailable: "test unavailable"})
	}
	command(t, e, id, ap.BurstStart{})
	command(t, e, id, ap.BurstDone{PartMsgIDs: []int64{1}})
	handle := strings.Repeat(string(rune('a'+id)), 12)
	command(t, e, id, ap.CardStart{Handle: handle, ChalHash: ap.ChallengeHash("0123456789abcdef")})
	command(t, e, id, ap.CardDone{Handle: handle, MsgID: 2})
	return ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: handle, Challenge: "0123456789abcdef", MsgID: 2}}
}
func voteApprove(t *testing.T, e *Engine, id int) {
	t.Helper()
	ans, err := e.Vote(readyCard(t, e, id, true))
	if err != nil || ans.Noise {
		t.Fatalf("approve: %+v %v", ans, err)
	}
}
func flushRecord(t *testing.T, e *Engine, id int) {
	t.Helper()
	r, err := e.config.Store.Load(ap.RecordKey(st.PrincipalA, st.ID(id)))
	if err != nil {
		t.Fatal(err)
	}
	command(t, e, id, ap.Flush{Through: r.Header.OutboxSeq})
}
func claimOf(id int, sum ap.Summary) ap.Claim {
	return ap.Claim{Token: st.Token(st.ID(id)), PlanHash: sum.PlanHash}
}
func checkCode(t *testing.T, err error, code ap.Code) {
	t.Helper()
	var ce *ap.CodeError
	if !errors.As(err, &ce) || ce.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func finalBody(status ap.StepStatus) ap.FinalReport {
	states := []ap.StepStatus{status}
	return ap.FinalReport{Class: ap.AggregateJobClass(states), ExecutedOrdinals: ap.ExecutedOrdinals(states), Partial: ap.Partial(states), Steps: []ap.StepReport{{Ordinal: 1, Status: status}}, ResultDigest: strings.Repeat("a", 64)}
}

func TestVoteGuardsReplayAndClock(t *testing.T) {
	for _, which := range []string{"preparing", "stale", "expired", "replay", "deny"} {
		t.Run(which, func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			sum := submitJob(t, e, 1)
			vote := readyCard(t, e, 1, which != "preparing" && which != "stale")
			switch which {
			case "stale":
				clock.Advance(6 * time.Second)
			case "expired":
				clock.Advance(2 * time.Hour)
			case "deny":
				vote.Decision = ap.VoteDeny
			}
			start := store.commits
			ans, err := e.Vote(vote)
			if err != nil {
				t.Fatal(err)
			}
			if store.commits != start+1 {
				t.Fatal("vote was not one commit")
			}
			rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			switch which {
			case "preparing", "stale":
				if !ans.Noise || rec.Header.Decision != nil {
					t.Fatal("unreviewed approval accepted")
				}
			case "expired":
				if !ans.Noise || ans.Reason != "expired" || rec.Header.Decision.Status != ap.ApprovalExpired || !rec.Header.Decision.DecidedAt.Equal(rec.Header.RequestExpiresAt) {
					t.Fatalf("expiry: %+v", ans)
				}
			case "deny":
				if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalDenied {
					t.Fatal("local deny veto not enforced")
				}
			case "replay":
				for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
					vote.Decision = decision
					ans, err = e.Vote(vote)
					if err != nil || !ans.Noise {
						t.Fatal("replay accepted")
					}
				}
				after, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				if len(after.Header.Votes) != 1 || !reflect.DeepEqual(after.Header.Decision, rec.Header.Decision) || after.Header.OutboxSeq != rec.Header.OutboxSeq+2 {
					t.Fatal("replay changed resolution or lost audit")
				}
			}
			if _, err = e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClaimConcurrentMintAndCommitBarrier(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	e, _, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	vote := readyCard(t, e, 1, true)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Vote(vote); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	calls := 0
	e.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
		calls++
		if e.mu.TryLock() {
			e.mu.Unlock()
			t.Error("mint outside critical section")
		}
		if !at.Equal(st.T0) || p.RequestID != st.ID(1) {
			t.Error("wrong mint input")
		}
		return []string{st.Sig(p.RequestID, 1, calls)}, nil
	})
	claim := claimOf(1, sum)
	ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
	if err != nil || ans.Claim != ap.ClaimNotReady || calls != 0 {
		t.Fatal("audit gate bypass")
	}
	flushRecord(t, e, 1)
	store.fail = true
	ans, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
	if err == nil || len(ans.Signatures) != 0 {
		t.Fatal("failed commit released signatures")
	}
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Header.Mint != nil || rec.Header.ClaimCount != 0 {
		t.Fatal("failed mint published")
	}
	store.fail = false
	answers := make(chan ap.Answer, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
			if err != nil {
				t.Error(err)
			}
			answers <- a
		}()
	}
	wg.Wait()
	close(answers)
	var signatures []string
	for a := range answers {
		if a.Claim != ap.ClaimSignatures {
			t.Fatalf("claim: %+v", a)
		}
		if signatures == nil {
			signatures = a.Signatures
		}
		if !reflect.DeepEqual(a.Signatures, signatures) {
			t.Fatal("multiple sets released")
		}
	}
	if calls != 2 {
		t.Fatalf("mint calls %d", calls)
	}
	rec, _ = store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Header.ClaimCount != 20 {
		t.Fatal("lost claim count")
	}
}

func TestClaimAndReportOwnerIsolation(t *testing.T) {
	for _, shed := range []bool{false, true} {
		t.Run(fmt.Sprint(shed), func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			sum := submitJob(t, e, 1)
			if shed {
				_, err := e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin})
				if err != nil {
					t.Fatal(err)
				}
				flushRecord(t, e, 1)
				command(t, e, 1, ap.ShedRecord{Pressure: true})
			}
			before := store.commits
			_, foreign := e.Claim(context.Background(), st.PrincipalB, st.ID(1), claimOf(1, sum))
			_, absent := e.Claim(context.Background(), st.PrincipalB, st.ID(999), claimOf(1, sum))
			if foreign == nil || absent == nil || foreign.Error() != absent.Error() {
				t.Fatal("claim existence leak")
			}
			_, foreign = e.Report(st.PrincipalB, st.ID(1), ap.Report{})
			_, absent = e.Report(st.PrincipalB, st.ID(999), ap.Report{})
			if foreign == nil || absent == nil || foreign.Error() != absent.Error() || store.commits != before {
				t.Fatal("report existence leak or foreign audit")
			}
			_, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{})
			checkCode(t, err, ap.CodeInvalidClaim)
			_, err = e.Report(st.PrincipalA, st.ID(1), ap.Report{})
			checkCode(t, err, ap.CodeInvalidReport)
			if store.commits != before+2 {
				t.Fatal("invalid owner commands not audited")
			}
		})
	}
}

func TestClaimExpirySkewAndSigningFailure(t *testing.T) {
	for _, which := range []string{"expiry", "skew", "signing", "repeat_expiry"} {
		t.Run(which, func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			sum := submitJob(t, e, 1)
			voteApprove(t, e, 1)
			flushRecord(t, e, 1)
			calls := 0
			e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				calls++
				if which == "signing" {
					return nil, errors.New("private signing failure")
				}
				return []string{"signature"}, nil
			})
			cl := claimOf(1, sum)
			if which == "repeat_expiry" {
				if _, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), cl); err != nil {
					t.Fatal(err)
				}
			}
			switch which {
			case "expiry", "repeat_expiry":
				clock.Advance(time.Minute)
			case "skew":
				clock.StepWall(-10 * time.Second)
			}
			a, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), cl)
			if err != nil {
				t.Fatal(err)
			}
			switch which {
			case "expiry", "repeat_expiry":
				if a.Claim != ap.ClaimExpired {
					t.Fatal(a)
				}
			case "skew":
				if a.Reason != ap.MintReasonClockSkew || calls != 0 {
					t.Fatal(a)
				}
			case "signing":
				if a.Reason != ap.MintReasonSigningFailed || calls != 1 {
					t.Fatal(a)
				}
			}
			rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if len(rec.Payload.Signatures) != 0 {
				t.Fatal("expired or failed bytes retained")
			}
			if which == "expiry" && rec.Header.ClaimCount != 0 {
				t.Fatal("expired first claim minted")
			}
		})
	}
}

func TestReportCommitErasureAndDuplicates(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	flushRecord(t, e, 1)
	e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{"signature"}, nil
	})
	report := ap.Report{Token: st.Token(st.ID(1)), PlanHash: sum.PlanHash, Body: finalBody(ap.StepSucceeded)}
	_, err := e.Report(st.PrincipalA, st.ID(1), report)
	checkCode(t, err, ap.CodeInvalidReport)
	if _, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum)); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	if _, err = e.Report(st.PrincipalA, st.ID(1), report); err == nil {
		t.Fatal("report acked before commit")
	}
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Header.FinalReport != nil || len(rec.Payload.Signatures) != 1 {
		t.Fatal("failed report published")
	}
	store.fail = false
	if _, err = e.Report(st.PrincipalA, st.ID(1), report); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Header.FinalReport == nil || len(rec.Payload.Signatures) != 0 {
		t.Fatal("report failed to erase")
	}
	flushRecord(t, e, 1)
	command(t, e, 1, ap.ShedRecord{Pressure: true})
	clock.Advance(48 * time.Hour)
	before := store.commits
	if _, err = e.Report(st.PrincipalA, st.ID(1), report); err != nil || store.commits != before {
		t.Fatal("duplicate report not inert")
	}
	report.Body.ResultDigest = strings.Repeat("b", 64)
	_, err = e.Report(st.PrincipalA, st.ID(1), report)
	checkCode(t, err, ap.CodeInvalidReport)
	ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
	if err != nil || ans.Claim != ap.ClaimExecutionReported || len(ans.Signatures) != 0 {
		t.Fatal("reported claim", ans, err)
	}
}

func TestFirstClaimCorruptStoredPlan(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	flushRecord(t, e, 1)
	e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		t.Fatal("corrupt plan reached minter")
		return nil, nil
	})
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	var raw map[string]any
	if err := json.Unmarshal(store.records[key], &raw); err != nil {
		t.Fatal(err)
	}
	plan := raw["payload"].(map[string]any)["plan"].(map[string]any)
	step := plan["command_job"].(map[string]any)["steps"].([]any)[0].(map[string]any)
	step["exact_command"] = "SSHGATE_XFER_SEND forbidden"
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	store.records[key] = data
	before := store.commits
	ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
	checkCode(t, err, ap.CodeRecordCorrupt)
	if store.commits != before || len(ans.Signatures) != 0 || !reflect.DeepEqual(store.records[key], data) {
		t.Fatal("corrupt record changed or released bytes")
	}
}

func TestGrantClaimUsesDecidingGrantAndExpiryLatch(t *testing.T) {
	for _, which := range []string{"revoked", "superseded", "elapsed", "live"} {
		t.Run(which, func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			submitGrant(t, e, 1, st.PrincipalA)
			voteApprove(t, e, 1)
			sum := submitJob(t, e, 2)
			if sum.ApprovalStatus != ap.ApprovalApproved {
				t.Fatal("grant did not cover job")
			}
			flushRecord(t, e, 2)
			switch which {
			case "revoked":
				if err := e.Revoke("web-1"); err != nil {
					t.Fatal(err)
				}
			case "superseded":
				submitGrant(t, e, 3, st.PrincipalA)
				voteApprove(t, e, 3)
			case "elapsed":
				clock.Advance(time.Hour)
				clock.StepWall(-time.Hour)
			}
			calls := 0
			e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				calls++
				return []string{"signature"}, nil
			})
			ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(2), claimOf(2, sum))
			if err != nil {
				t.Fatal(err)
			}
			if which == "live" {
				if ans.Claim != ap.ClaimSignatures || calls != 1 {
					t.Fatal(ans)
				}
				return
			}
			if ans.Claim != ap.ClaimMaterializationError || ans.Reason != ap.MintReasonGrantNotLive || calls != 0 {
				t.Fatalf("dead deciding grant signed: %+v", ans)
			}
			if which == "elapsed" {
				r, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				command(t, e, 1, ap.Flush{Through: r.Header.OutboxSeq})
				if len(e.projections.grants) != 0 {
					t.Fatal("expired grant revived")
				}
			}
		})
	}
}

func TestRevokeAliasGlobalAndCancelCommitFailure(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	first := submitGrant(t, e, 1, st.PrincipalA)
	voteApprove(t, e, 1)
	// A distinct principal uses the same request ID. Give it a distinct card.
	submitGrant(t, e, 1, st.PrincipalB)
	key := ap.RecordKey(st.PrincipalB, st.ID(1))
	e.mu.Lock()
	before, _ := e.load(key)
	now := e.now()
	for _, cmd := range []ap.Command{ap.AssistDone{Unavailable: "test unavailable"}, ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{3}}, ap.CardStart{Handle: "zzzzzzzzzzzz", ChalHash: ap.ChallengeHash("0123456789abcdef")}, ap.CardDone{Handle: "zzzzzzzzzzzz", MsgID: 4}} {
		after, ans, err := e.commitLocked(key, before, cmd, now, ap.Inputs{})
		if err != nil || ans.Code != "" {
			t.Fatalf("fixture: %+v %v", ans, err)
		}
		before = &after
	}
	e.mu.Unlock()
	_, err := e.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: "zzzzzzzzzzzz", Challenge: "0123456789abcdef", MsgID: 4}})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.projections.grants) != 2 {
		t.Fatal("fixture missing grants")
	}
	clock.StepWall(-time.Hour)
	store.fail = true
	if err = e.Revoke("web-1"); err == nil || len(e.projections.grants) != 2 {
		t.Fatal("failed revoke published")
	}
	store.fail = false
	if err = e.Revoke("web-1"); err != nil || len(e.projections.grants) != 0 {
		t.Fatal("alias revoke incomplete")
	}
	count := store.commits
	if err = e.Revoke("web-1"); err != nil || store.commits != count {
		t.Fatal("revoke not idempotent")
	}
	if _, err = e.AdminCancel(st.ID(1), ap.AdminCancel{PlanHash: first.PlanHash, Admin: st.Admin}); err == nil {
		t.Fatal("bare request ID accepted")
	}
	sum := submitJob(t, e, 2)
	_, err = e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: "wrong", Admin: st.Admin})
	checkCode(t, err, ap.CodeConflict)
	store.fail = true
	if _, err = e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin}); err == nil {
		t.Fatal("failed cancel acked")
	}
	got, _ := e.Get(st.PrincipalA, st.ID(2))
	if got.ApprovalStatus != ap.ApprovalPending {
		t.Fatal("failed cancel published")
	}
	store.fail = false
	if _, err = e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin}); err != nil {
		t.Fatal(err)
	}
	got, _ = e.Get(st.PrincipalA, st.ID(2))
	if got.ApprovalStatus != ap.ApprovalCanceled {
		t.Fatal("cancel failed after clock step")
	}
}

func TestVoteResolutionAndFailedCommit(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	vote := readyCard(t, e, 1, true)
	original := *vote.Card
	vote.Card.Challenge = "wrong"
	ans, err := e.Vote(vote)
	if err != nil || !ans.Noise || ans.Reason != "stale_challenge" {
		t.Fatal("forged challenge accepted", ans, err)
	}
	*vote.Card = original
	store.fail = true
	if _, err = e.Vote(vote); err == nil {
		t.Fatal("failed vote acked")
	}
	got, _ := e.Get(st.PrincipalA, st.ID(1))
	if got.ApprovalStatus != ap.ApprovalPending {
		t.Fatal("failed vote published")
	}
	store.fail = false
	submitJob(t, e, 2)
	command(t, e, 2, ap.AssistDone{Unavailable: "test unavailable"})
	command(t, e, 2, ap.BurstStart{})
	command(t, e, 2, ap.BurstDone{PartMsgIDs: []int64{5}})
	command(t, e, 2, ap.CardStart{Handle: original.Handle, ChalHash: ap.ChallengeHash(original.Challenge)})
	command(t, e, 2, ap.CardDone{Handle: original.Handle, MsgID: 6})
	before := store.commits
	if _, err = e.Vote(vote); err == nil || store.commits != before {
		t.Fatal("ambiguous card selected record")
	}
	e.projections.handles.add(sum.RecordHandle, ap.RecordKey(st.PrincipalA, st.ID(2)))
	if _, err = e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin}); err == nil || store.commits != before {
		t.Fatal("ambiguous handle canceled record")
	}
}

func TestLateNegativeReportAfterShed(t *testing.T) {
	e, clock, _, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	clock.Advance(time.Minute)
	ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
	if err != nil || ans.Claim != ap.ClaimExpired {
		t.Fatal(ans, err)
	}
	flushRecord(t, e, 1)
	command(t, e, 1, ap.ShedRecord{Pressure: true})
	clock.Advance(48 * time.Hour)
	report := ap.Report{Token: st.Token(st.ID(1)), PlanHash: sum.PlanHash, Body: finalBody(ap.StepExpiredUnexecuted)}
	if _, err = e.Report(st.PrincipalA, st.ID(1), report); err != nil {
		t.Fatal(err)
	}
	ans, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
	if err != nil || ans.Claim != ap.ClaimExecutionReported {
		t.Fatal(ans, err)
	}
}

func TestClaimMissingMinterAndInvalidSignatureCount(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	voteApprove(t, e, 1)
	flushRecord(t, e, 1)
	before := store.commits
	_, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
	checkCode(t, err, ap.CodeLifecycleUnavailable)
	if store.commits != before {
		t.Fatal("missing adapter wrote mint slot")
	}
	e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) { return nil, nil })
	_, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
	checkCode(t, err, ap.CodeInvalidRequest)
	if store.commits != before {
		t.Fatal("wrong signature count committed")
	}
}
