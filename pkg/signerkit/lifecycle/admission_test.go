package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func admissionSubmit(e *Engine, id int, principal string) (ap.Summary, error) {
	return e.Submit(context.Background(), principal, st.JobDraft(st.ID(id), ap.CoordinatorExecutor, e.config.Clock.Wall(), st.Write("touch /tmp/example", 60)))
}

func TestAdmissionLiveCapsAndClockPass(t *testing.T) {
	for _, limit := range []string{"principal", "total"} {
		t.Run(limit, func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			if limit == "principal" {
				e.config.Caps.LivePerPrincipal = 1
			} else {
				e.config.Caps.LiveTotal = 1
			}
			submitJob(t, e, 1)
			voteApprove(t, e, 1)
			before := store.commits
			_, err := admissionSubmit(e, 2, st.PrincipalA)
			checkCode(t, err, ap.CodeQueueFull)
			if store.commits != before || len(e.projections.records) != 1 {
				t.Fatal("refusal stored new work")
			}
			clock.Advance(time.Minute + time.Millisecond)
			// No Reconcile: admission must close the expired signature window itself.
			if _, err := admissionSubmit(e, 2, st.PrincipalA); err != nil {
				t.Fatal(err)
			}
			rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if rec.Header.Mint == nil || rec.Header.Mint.Reason != ap.MintReasonWindowClosed || e.projections.total.live != 1 {
				t.Fatal("admission did not commit Clock before reusing live slot")
			}
		})
	}
	t.Run("principal isolation", func(t *testing.T) {
		e, _, _, _ := engineFixture(t)
		e.config.Caps.LivePerPrincipal = 1
		submitJob(t, e, 1)
		if _, err := admissionSubmit(e, 2, st.PrincipalB); err != nil {
			t.Fatal(err)
		}
		_, err := admissionSubmit(e, 3, st.PrincipalA)
		checkCode(t, err, ap.CodeQueueFull)
	})
	t.Run("failed clock commit", func(t *testing.T) {
		e, clock, store, _ := engineFixture(t)
		e.config.Caps.LiveTotal = 1
		submitJob(t, e, 1)
		clock.Advance(2 * time.Hour)
		store.fail = true
		if _, err := admissionSubmit(e, 2, st.PrincipalA); err == nil {
			t.Fatal("admitted after failed Clock")
		}
		if len(e.projections.records) != 1 || e.projections.total.live != 1 {
			t.Fatal("failed Clock changed counters")
		}
	})
}

func cancelAdmissionRecord(t *testing.T, e *Engine, id int) {
	t.Helper()
	rec, err := e.config.Store.Load(ap.RecordKey(st.PrincipalA, st.ID(id)))
	if err != nil {
		t.Fatal(err)
	}
	command(t, e, id, ap.AssistDone{Unavailable: "test unavailable"})
	command(t, e, id, ap.AdminCancel{PlanHash: rec.Header.PlanHash, Admin: st.Admin})
	flushRecord(t, e, id)
}

func TestAdmissionHistoryReclaimsByDecisionAge(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	e.config.Caps.FullRecords = 2
	submitJob(t, e, 1)
	submitJob(t, e, 2)
	cancelAdmissionRecord(t, e, 2)
	clock.Advance(time.Second)
	cancelAdmissionRecord(t, e, 1)
	submitJob(t, e, 3)
	old, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(2)))
	newer, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if old.Payload != nil || newer.Payload == nil || e.projections.total.full != 2 {
		t.Fatal("did not shed oldest decision first")
	}
	// Count pressure cannot delete even settled headers before the replay floor.
	e.config.Caps.RecordsTotal = 3
	_, err := admissionSubmit(e, 4, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	clock.Advance(25 * time.Hour)
	submitJob(t, e, 4)
	if _, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(2))); !errors.Is(err, ErrNotFound) {
		t.Fatal("count pressure did not delete oldest eligible header", err)
	}
}

func TestAdmissionReplaysAndUnauditedProtection(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	e.config.Caps.FullRecords = 1
	d := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, e.config.Clock.Wall(), st.Write("touch /tmp/example", 60))
	sum, err := e.Submit(context.Background(), st.PrincipalA, d)
	if err != nil {
		t.Fatal(err)
	}
	command(t, e, 1, ap.AssistDone{Unavailable: "test unavailable"})
	command(t, e, 1, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin})
	_, err = admissionSubmit(e, 2, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Payload == nil {
		t.Fatal("unaudited payload shed")
	}
	flushRecord(t, e, 1)
	submitJob(t, e, 2)
	got, err := e.Submit(context.Background(), st.PrincipalA, d)
	if err != nil || !got.Pruned || got.ApprovalStatus != ap.ApprovalCanceled {
		t.Fatal("shed replay did not bypass admission", got, err)
	}
	d.Rationale = "changed reason"
	_, err = e.Submit(context.Background(), st.PrincipalA, d)
	checkCode(t, err, ap.CodeConflict)
}

func TestAdmissionConcurrentBudget(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	reservation := e.projections.total.reserved
	e.config.Caps.PayloadBytes = 8*reservation + reservation/2
	var wg sync.WaitGroup
	accepted := make(chan bool, 16)
	for id := 2; id <= 17; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := admissionSubmit(e, id, st.PrincipalA)
			if err != nil {
				var ce *ap.CodeError
				if !errors.As(err, &ce) || ce.Code != ap.CodeQueueFull {
					t.Error(err)
				}
			}
			accepted <- err == nil
		}(id)
	}
	wg.Wait()
	close(accepted)
	count := 1
	for ok := range accepted {
		if ok {
			count++
		}
	}
	if count != 8 || e.projections.total.reserved != 8*reservation {
		t.Fatal("concurrent admission overbooked budget", count, e.projections.total)
	}
	entries, _ := store.List()
	if len(entries) != 8 {
		t.Fatal("refused request persisted")
	}
	restarted, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.projections.total.reserved != 8*reservation {
		t.Fatal("restart lost reservations")
	}
}

func TestReservationSurvivesGrowthAndReleasesOnlyOnShed(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	sums := make([]ap.Summary, 8)
	for i := 1; i <= 8; i++ {
		sums[i-1] = submitJob(t, e, i)
	}
	budget := e.projections.total.reserved
	e.config.Caps.PayloadBytes = budget
	_, err := admissionSubmit(e, 9, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{"signature"}, nil
	})
	for i := 1; i <= 8; i++ {
		tap := readyCard(t, e, i, false)
		command(t, e, i, ap.AssistDone{Unavailable: "test unavailable"})
		tap.Card.Handle = strings.Repeat(string(rune('j'+i)), 12)
		command(t, e, i, ap.EditStart{Handle: tap.Card.Handle, ChalHash: ap.ChallengeHash(tap.Card.Challenge)})
		command(t, e, i, ap.EditDone{Handle: tap.Card.Handle})
		if answer, err := e.Vote(tap); err != nil || answer.Noise {
			t.Fatal(answer, err)
		}
		flushRecord(t, e, i)
		ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(i), claimOf(i, sums[i-1]))
		if err != nil || len(ans.Signatures) != 1 {
			t.Fatal(ans, err)
		}
		rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(i)))
		step := ap.NotifyNext(rec, e.now(), e.epoch, e.config.Settings)
		if step.Kind != ap.NotifyStatus {
			t.Fatal("missing status edit")
		}
		command(t, e, i, ap.StatusEdited{State: step.State})
		// The sink stays unavailable: mandatory transitions and noise still fit.
		for range ap.NoiseFold + 4 {
			command(t, e, i, ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: "unknowncardx", Challenge: "0123456789abcdef", MsgID: 2}})
		}
	}
	var encoded int64
	for key, charge := range e.projections.records {
		rec, _ := store.Load(key)
		b, _ := json.Marshal(rec)
		encoded += int64(len(b))
		if int64(len(b)) > charge.reserved {
			t.Fatal("record exceeded reservation")
		}
	}
	if encoded > budget || e.projections.total.reserved != budget {
		t.Fatal("growth escaped reserved budget")
	}
	restarted, err := New(e.config)
	if err != nil || restarted.projections.total.reserved != budget {
		t.Fatal("restart lost grown-record reservation", err)
	}
	clock.Advance(20 * time.Minute)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	flushRecord(t, e, 1)
	ans, err := e.Shed(st.PrincipalA, st.ID(1), true)
	if err != nil || !ans.Changed {
		t.Fatal("running record not shed", ans, err)
	}
	if ans, err = e.Delete(st.PrincipalA, st.ID(1), true); err != nil || ans.Removed {
		t.Fatal("running record deleted", ans, err)
	}
	clock.Advance(5 * time.Minute)
	_, err = e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: st.Token(st.ID(1)), PlanHash: sums[0].PlanHash, Body: finalBody(ap.StepIndeterminate)})
	if err != nil {
		t.Fatal("late report rejected", err)
	}
	got, err := e.Get(st.PrincipalA, st.ID(1))
	if err != nil || !got.Pruned {
		t.Fatal(got, err)
	}
	if e.projections.total.reserved >= budget {
		t.Fatal("Shed did not release reservation")
	}
	submitJob(t, e, 9)
}

func TestRetentionReconcileAndFailedShed(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	e.config.Settings.Retention = time.Hour
	e.config.Settings.MaxAge = 2 * 24 * time.Hour
	submitJob(t, e, 1)
	cancelAdmissionRecord(t, e, 1)
	clock.Advance(time.Hour)
	before := e.projections.total
	store.fail = true
	if err := e.Reconcile(); err == nil {
		t.Fatal("Shed failure hidden")
	}
	if e.projections.total != before {
		t.Fatal("failed Shed released charge")
	}
	store.fail = false
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if rec.Payload != nil || e.projections.total.reserved != 0 {
		t.Fatal("age Shed not performed")
	}
	clock.Advance(48 * time.Hour)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if e.projections.total.records != 0 {
		t.Fatal("age Delete not performed")
	}
}

func TestAdmissionCapsDefaultsAndValidation(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	if e.config.Caps.PayloadBytes != ap.LocalPayloadBudget || e.config.Caps.FullRecords != ap.LocalFullRecords {
		t.Fatal("wrong defaults")
	}
	for _, caps := range []Caps{{LivePerPrincipal: -1}, {LiveTotal: -1}, {FullRecords: -1}, {RecordsTotal: -1}, {PayloadBytes: -1}} {
		c := e.config
		c.Caps = caps
		if _, err := New(c); err == nil {
			t.Fatal("negative cap accepted", caps)
		}
	}
}

func TestReclamationOwnerScopeAndGrantMark(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	submitGrant(t, e, 1, st.PrincipalA)
	approve(t, e, 1)
	submitGrant(t, e, 2, st.PrincipalA)
	approve(t, e, 2)
	if err := e.Revoke("web-1"); err != nil {
		t.Fatal(err)
	}
	flushRecord(t, e, 2)
	for _, op := range []func(string, string, bool) (ap.Answer, error){e.Shed, e.Delete} {
		before := store.commits
		_, foreign := op(st.PrincipalB, st.ID(2), true)
		_, absent := op(st.PrincipalB, st.ID(999), true)
		if foreign == nil || absent == nil || foreign.Error() != absent.Error() || store.commits != before {
			t.Fatal("reclamation owner leak")
		}
	}
	mark := e.projections.newest[grantOwner{st.PrincipalA, "web-1"}]
	if ans, err := e.Shed(st.PrincipalA, st.ID(2), true); err != nil || !ans.Changed {
		t.Fatal(ans, err)
	}
	clock.Advance(25 * time.Hour)
	if ans, err := e.Delete(st.PrincipalA, st.ID(2), true); err != nil || !ans.Removed {
		t.Fatal(ans, err)
	}
	if e.projections.newest[grantOwner{st.PrincipalA, "web-1"}] != mark {
		t.Fatal("Delete lowered newest grant mark")
	}
	if sum := submitJob(t, e, 3); sum.ApprovalStatus != ap.ApprovalPending {
		t.Fatal("deleted grant revived authority")
	}
	if !reflect.DeepEqual(e.projections.grants, map[string]*grantProjection{}) {
		t.Fatal("superseded grant revived")
	}
}

func TestAdmissionSettledHistoryDoesNotConsumeLiveCaps(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	for id := 1; id <= 600; id++ {
		submitJob(t, e, id)
		cancelAdmissionRecord(t, e, id)
	}
	submitJob(t, e, 601)
	if e.projections.total.live != 1 || e.projections.total.records != 601 || e.projections.total.full > ap.LocalFullRecords {
		t.Fatal("settled history blocked live work", e.projections.total)
	}
}

func TestAdmissionQuarantineChargesCannotBeReclaimed(t *testing.T) {
	for _, cap := range []string{"live", "full", "total", "bytes"} {
		t.Run(cap, func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			c := e.config
			c.Store = startupStore{Store: store, entries: []StoreEntry{{Key: ap.RecordKey(st.PrincipalA, st.ID(999)), Quarantined: true, EncodedSize: 400 << 10}}}
			switch cap {
			case "live":
				c.Caps.LiveTotal = 1
			case "full":
				c.Caps.FullRecords = 1
			case "total":
				c.Caps.RecordsTotal = 1
			case "bytes":
				c.Caps.PayloadBytes = 400 << 10
			}
			recovered, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			_, err = admissionSubmit(recovered, 1, st.PrincipalA)
			checkCode(t, err, ap.CodeQueueFull)
			if store.commits != 0 || len(recovered.projections.quarantined) != 1 {
				t.Fatal("quarantine reclaimed")
			}
		})
	}
}

type removeFailureStore struct {
	Store
	fail bool
}

func (s *removeFailureStore) Remove(key string) error {
	if s.fail {
		return errors.New("remove failed")
	}
	return s.Store.Remove(key)
}

func TestDeleteFailureKeepsProjections(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	cancelAdmissionRecord(t, e, 1)
	clock.Advance(25 * time.Hour)
	failing := &removeFailureStore{Store: store, fail: true}
	e.config.Store = failing
	before := e.projections.total
	if _, err := e.Delete(st.PrincipalA, st.ID(1), true); err == nil {
		t.Fatal("Delete failure hidden")
	}
	if e.projections.total != before {
		t.Fatal("failed Delete released charge")
	}
	if _, err := e.projections.handles.resolve(sum.RecordHandle); err != nil {
		t.Fatal("failed Delete removed handle")
	}
	failing.fail = false
	if ans, err := e.Delete(st.PrincipalA, st.ID(1), true); err != nil || !ans.Removed {
		t.Fatal(ans, err)
	}
	if e.projections.total.records != 0 || e.projections.total.reserved != 0 {
		t.Fatal("Delete failed to release charge")
	}
	if _, err := e.projections.handles.resolve(sum.RecordHandle); err == nil {
		t.Fatal("Delete retained handle")
	}
}

func TestReclamationDuringNotifierStatus(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "shed", true: "delete"}[remove], func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			submitJob(t, e, 1)
			voteApprove(t, e, 1)
			clock.Advance(25 * time.Hour)
			command(t, e, 1, ap.Tick{})
			flushRecord(t, e, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			n := &testNotifier{status: func(string) { close(entered); <-release }}
			e.config.Notifier = n
			actor := &notifyActor{engine: e, key: ap.RecordKey(st.PrincipalA, st.ID(1)), nudge: make(chan struct{}, 1)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- actor.run(ctx) }()
			receiveNotify(t, entered)
			if remove {
				if ans, err := e.Delete(st.PrincipalA, st.ID(1), true); err != nil || !ans.Removed {
					t.Fatal(ans, err)
				}
			} else {
				if ans, err := e.Shed(st.PrincipalA, st.ID(1), true); err != nil || !ans.Changed {
					t.Fatal(ans, err)
				}
			}
			close(release)
			// A late transport completion must not recreate or fail a reclaimed record.
			select {
			case err := <-done:
				t.Fatal("actor failed after reclamation", err)
			case <-time.After(20 * time.Millisecond):
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			rec, err := store.Load(actor.key)
			if remove {
				if !errors.Is(err, ErrNotFound) {
					t.Fatal("deleted record recreated")
				}
			} else if err != nil || rec.Payload != nil {
				t.Fatal("shed payload recreated")
			}
		})
	}
}

func TestAdmissionRefusalNeverNotifies(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	e.config.Caps.PayloadBytes = 1
	n := &testNotifier{}
	runNotifier(t, e, n)
	_, err := admissionSubmit(e, 1, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	actors := len(e.notifyActors)
	e.mu.Unlock()
	n.mu.Lock()
	bursts := n.bursts
	n.mu.Unlock()
	if actors != 0 || bursts != 0 || store.commits != 0 {
		t.Fatal("refused admission dispatched a notification")
	}
}

func TestDeleteClocksBeforeFlushGate(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	sum := submitJob(t, e, 1)
	// Resolve and audit before assist is due, then leave the tick paused.
	command(t, e, 1, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin})
	flushRecord(t, e, 1)
	clock.Advance(25 * time.Hour)
	answer, err := e.Delete(st.PrincipalA, st.ID(1), true)
	if err != nil || answer.Removed {
		t.Fatal("Delete skipped due Clock audit", answer, err)
	}
	rec, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if err != nil || rec.Header.Assist == nil || !ap.Unflushed(rec) {
		t.Fatal("Delete did not commit Clock before testing its flush gate", err)
	}
	flushRecord(t, e, 1)
	answer, err = e.Delete(st.PrincipalA, st.ID(1), true)
	if err != nil || !answer.Removed {
		t.Fatal(answer, err)
	}
}

type reclaimOnLoadStore struct {
	Store
	loads   int
	reclaim func()
}

func (s *reclaimOnLoadStore) Load(key string) (ap.R1, error) {
	s.loads++
	if s.loads == 3 {
		s.reclaim()
	}
	return s.Store.Load(key)
}

func TestNotifierRechecksDeletionBeforeSend(t *testing.T) {
	for _, card := range []bool{false, true} {
		t.Run(map[bool]string{false: "parts", true: "card"}[card], func(t *testing.T) {
			e, clock, store, _ := engineFixture(t)
			submitJob(t, e, 1)
			if card {
				command(t, e, 1, ap.BurstStart{})
				command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
			}
			key := ap.RecordKey(st.PrincipalA, st.ID(1))
			wrapper := &reclaimOnLoadStore{Store: store}
			wrapper.reclaim = func() {
				// Actor Load holds the engine lock. Inject the committed reclamation at
				// the read between the write-ahead commit and its transport call.
				clock.Advance(25 * time.Hour)
				rec, err := store.Load(key)
				if err != nil {
					t.Fatal(err)
				}
				rec, _, err = e.commitLocked(key, &rec, ap.Tick{}, e.now(), ap.Inputs{})
				if err != nil {
					t.Fatal(err)
				}
				rec, _, err = e.commitLocked(key, &rec, ap.Flush{Through: rec.Header.OutboxSeq}, e.now(), ap.Inputs{})
				if err != nil {
					t.Fatal(err)
				}
				_, answer, err := e.commitLocked(key, &rec, ap.Delete{Pressure: true}, e.now(), ap.Inputs{})
				if err != nil || !answer.Removed {
					t.Fatal(answer, err)
				}
			}
			e.config.Store = wrapper
			actor := &notifyActor{engine: e, key: key}
			n := &testNotifier{parts: func(Notification) ([]int64, error) { t.Fatal("sent parts after Delete"); return nil, nil }, card: func(Notification) (int64, error) { t.Fatal("sent card after Delete"); return 0, nil }}
			if err := actor.burst(context.Background(), n); err != nil {
				t.Fatal(err)
			}
			if wrapper.loads != 3 {
				t.Fatal("did not reach pre-send read", wrapper.loads)
			}
		})
	}
}
