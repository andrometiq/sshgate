package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type freezer struct {
	calls      int
	wrongOwner bool
}

func (f *freezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	f.calls++
	if f.wrongOwner {
		principal = st.PrincipalB
	}
	return st.Freeze(d, principal, now, time.Hour), nil
}

type snapshotter struct{}

func (snapshotter) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	return []byte(`{"segments":[]}`), p.Rationale, nil
}

type failingStore struct {
	MemStore
	fail    bool
	commits int
}

func (s *failingStore) Commit(key string, r ap.R1) error {
	s.commits++
	if s.fail {
		return errors.New("injected commit failure")
	}
	return s.MemStore.Commit(key, r)
}
func engineFixture(t *testing.T) (*Engine, *elapsedtest.Fake, *failingStore, *freezer) {
	t.Helper()
	clock, store, f := elapsedtest.NewFake(st.T0), &failingStore{}, &freezer{}
	e, err := New(Config{Store: store, Clock: clock, Freezer: f, SnapshotBuilder: snapshotter{}})
	if err != nil {
		t.Fatal(err)
	}
	return e, clock, store, f
}
func submitGrant(t *testing.T, e *Engine, id int, principal string) ap.Summary {
	t.Helper()
	sum, err := e.Submit(context.Background(), principal, st.GrantDraft(st.ID(id), "web-1", time.Hour, e.config.Clock.Wall()))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}
func command(t *testing.T, e *Engine, id int, cmd ap.Command) ap.R1 {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	key := ap.RecordKey(st.PrincipalA, st.ID(id))
	before, err := e.load(key)
	if err != nil {
		t.Fatal(err)
	}
	rec, ans, err := e.commitLocked(key, before, cmd, e.now(), ap.Inputs{})
	if err != nil || ans.Code != "" {
		t.Fatalf("%T: %+v %v", cmd, ans, err)
	}
	return rec
}
func approve(t *testing.T, e *Engine, id int) ap.R1 {
	t.Helper()
	command(t, e, id, ap.AssistDone{Unavailable: "test unavailable"})
	command(t, e, id, ap.BurstStart{})
	command(t, e, id, ap.BurstDone{PartMsgIDs: []int64{1}})
	handle := "abcdefghijkl"
	challenge := "0123456789abcdef"
	command(t, e, id, ap.CardStart{Handle: handle, ChalHash: ap.ChallengeHash(challenge)})
	command(t, e, id, ap.CardDone{Handle: handle, MsgID: 2})
	rec := command(t, e, id, ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: handle, Challenge: challenge, MsgID: 2}})
	if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalApproved {
		t.Fatalf("not approved: %+v", rec.Header)
	}
	return rec
}
func TestSubmitSerializationReplayAndOwnerReads(t *testing.T) {
	e, clock, store, f := engineFixture(t)
	d := st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Submit(context.Background(), st.PrincipalA, d); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if store.commits != 1 || f.calls != 1 || e.projections.total.records != 1 {
		t.Fatal("duplicate submit froze or committed twice")
	}
	clock.Advance(2 * time.Hour)
	commits := store.commits
	got, err := e.Get(st.PrincipalA, d.RequestID)
	if err != nil || got.ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("read derived closure: %+v %v", got, err)
	}
	list, err := e.List(st.PrincipalB)
	if err != nil || len(list) != 0 {
		t.Fatal("foreign list")
	}
	_, foreign := e.Get(st.PrincipalB, d.RequestID)
	_, absent := e.Get(st.PrincipalB, st.ID(999))
	if foreign == nil || absent == nil || foreign.Error() != absent.Error() || store.commits != commits {
		t.Fatal("owner read changed state or leaked existence")
	}
	got, err = e.Submit(context.Background(), st.PrincipalA, d)
	if err != nil || got.ApprovalStatus != ap.ApprovalExpired || f.calls != 1 {
		t.Fatalf("replay failed: %+v %v", got, err)
	}
	d.Rationale = "different reason"
	if _, err = e.Submit(context.Background(), st.PrincipalA, d); err == nil {
		t.Fatal("changed draft accepted")
	}
}
func TestFailedCommitPublishesNothing(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	store.fail = true
	_, err := e.Submit(context.Background(), st.PrincipalA, st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0))
	if err == nil {
		t.Fatal("commit failure hidden")
	}
	if !reflect.DeepEqual(e.projections, newProjections()) {
		t.Fatal("failed commit published projections")
	}
	store.fail = false
	submitGrant(t, e, 1, st.PrincipalA)
	before, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	store.fail = true
	e.mu.Lock()
	_, _, err = e.commitLocked(ap.RecordKey(st.PrincipalA, st.ID(1)), &before, ap.AdminCancel{PlanHash: before.Header.PlanHash, Admin: st.Admin}, e.now(), ap.Inputs{})
	e.mu.Unlock()
	got, _ := e.Get(st.PrincipalA, st.ID(1))
	if err == nil || got.ApprovalStatus != ap.ApprovalPending || e.projections.total.live != 1 {
		t.Fatal("failed transition became visible")
	}
}
func TestFreezerCannotChangeOwner(t *testing.T) {
	e, _, store, f := engineFixture(t)
	f.wrongOwner = true
	_, err := e.Submit(context.Background(), st.PrincipalA, st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0))
	if err == nil || store.commits != 0 {
		t.Fatal("freezer changed owner")
	}
}
func TestProjectionIndexesCountersAndDue(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	sum := submitGrant(t, e, 1, st.PrincipalA)
	submitGrant(t, e, 1, st.PrincipalB)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	if k, err := e.projections.handles.resolve(sum.RecordHandle); err != nil || k != key {
		t.Fatal("record handle missing")
	}
	if _, err := e.projections.requestIDs.resolve(st.ID(1)); err == nil {
		t.Fatal("ambiguous id resolved")
	}
	if e.projections.total.records != 2 || e.projections.total.full != 2 || e.projections.total.live != 2 || e.projections.total.reserved <= 0 || !e.projections.due[key].Equal(st.T0.Add(5*time.Second)) {
		t.Fatalf("bad projections: %+v", e.projections)
	}
	approve(t, e, 1)
	if k, err := e.projections.cards.resolve("abcdefghijkl"); err != nil || k != key {
		t.Fatal("card index missing")
	}
	rec := command(t, e, 1, ap.Revoke{})
	command(t, e, 1, ap.Flush{Through: rec.Header.OutboxSeq})
	reserved := e.projections.total.reserved
	command(t, e, 1, ap.ShedRecord{Pressure: true})
	if e.projections.total.full != 1 || e.projections.total.reserved >= reserved || e.projections.total.records != 2 {
		t.Fatal("shed did not release reservation")
	}
	if _, err := e.projections.cards.resolve("abcdefghijkl"); err == nil {
		t.Fatal("shed card retained")
	}
	if _, err := e.projections.handles.resolve(sum.RecordHandle); err != nil {
		t.Fatal("shed lost handle")
	}
}
func TestGrantSupersessionDeletionAndExpiryLatch(t *testing.T) {
	for _, elapsedExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "wall", true: "elapsed"}[elapsedExpiry], func(t *testing.T) {
			e, clock, _, _ := engineFixture(t)
			submitGrant(t, e, 1, st.PrincipalA)
			approve(t, e, 1)
			submitGrant(t, e, 2, st.PrincipalA)
			approve(t, e, 2)
			owner := grantOwner{st.PrincipalA, "web-1"}
			first, second := ap.RecordKey(st.PrincipalA, st.ID(1)), ap.RecordKey(st.PrincipalA, st.ID(2))
			if e.projections.grants[first] != nil || e.projections.newest[owner] != second {
				t.Fatal("superseded grant live")
			}
			d := st.JobDraft(st.ID(3), ap.CoordinatorInProcessSync, clock.Wall(), st.Write("touch /tmp/example", 60))
			sum, err := e.Submit(context.Background(), st.PrincipalA, d)
			if err != nil || sum.ApprovalStatus != ap.ApprovalApproved {
				t.Fatalf("grant not spent: %+v %v", sum, err)
			}
			d.RequestID = st.ID(4)
			d.ExecutorClaimTokenHash = ap.ClaimTokenHash(st.Token(d.RequestID))
			sum, err = e.Submit(context.Background(), st.PrincipalB, d)
			if err != nil || sum.ApprovalStatus != ap.ApprovalPending {
				t.Fatal("foreign grant spent")
			}
			if elapsedExpiry {
				clock.Advance(time.Hour)
				clock.StepWall(-time.Hour)
			} else {
				clock.StepWall(time.Hour)
			}
			// Reads trail the writer even when either end has passed.
			if sum, err := e.Get(st.PrincipalA, st.ID(2)); err != nil || sum.Class != ap.ClassLive {
				t.Fatal("read expired grant")
			}
			expiredDraft := st.JobDraft(st.ID(5), ap.CoordinatorInProcessSync, clock.Wall(), st.Write("touch /tmp/example", 60))
			expired, err := e.Submit(context.Background(), st.PrincipalA, expiredDraft)
			if err != nil || expired.ApprovalStatus != ap.ApprovalPending {
				t.Fatal("expired grant revived")
			}
			clock.StepWall(-time.Hour)
			grantRecord, err := e.config.Store.Load(second)
			if err != nil {
				t.Fatal(err)
			}
			command(t, e, 2, ap.Flush{Through: grantRecord.Header.OutboxSeq})
			if e.projections.grants[second] != nil {
				t.Fatal("expired grant revived")
			}
			// Exercise the actual Delete path, after flushing and the deletion floor.
			clock.Advance(8 * 24 * time.Hour)
			rec := command(t, e, 2, ap.Tick{})
			command(t, e, 2, ap.Flush{Through: rec.Header.OutboxSeq})
			command(t, e, 2, ap.Delete{})
			if _, err := e.Get(st.PrincipalA, st.ID(2)); err == nil {
				t.Fatal("delete did not remove grant")
			}
			if e.projections.newest[owner] != second || e.projections.grants[first] != nil {
				t.Fatal("delete revived superseded grant")
			}
		})
	}
}

func TestNewIDWindowAndRecovery(t *testing.T) {
	e, clock, store, f := engineFixture(t)
	d := st.GrantDraft(st.ID(1), "web-1", time.Hour, clock.Wall())
	clock.Advance(2 * time.Hour)
	if _, err := e.Submit(context.Background(), st.PrincipalA, d); err == nil || store.commits != 0 || f.calls != 0 {
		t.Fatal("expired new ID reached freeze or commit")
	}
	submitGrant(t, e, 2, st.PrincipalA)
	if _, err := New(e.config); err != nil {
		t.Fatal(err)
	}
}

func TestIndexCollisionsAndRemoval(t *testing.T) {
	for _, name := range []string{"card", "record", "request"} {
		t.Run(name, func(t *testing.T) {
			i := index{}
			i.add("collision", "first")
			i.add("collision", "second")
			if _, err := i.resolve("collision"); err == nil {
				t.Fatal("ambiguous index resolved")
			}
			i.remove("collision", "first")
			if key, err := i.resolve("collision"); err != nil || key != "second" {
				t.Fatal("remaining entry lost")
			}
			i.remove("collision", "second")
			if _, err := i.resolve("collision"); err == nil {
				t.Fatal("removed index resolved")
			}
		})
	}
}
