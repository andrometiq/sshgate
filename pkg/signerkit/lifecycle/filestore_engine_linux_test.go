//go:build linux

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func fileEngineFixture(t *testing.T) (*Engine, *elapsedtest.Fake, *FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approvals")
	store, err := OpenFileStore(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	clock := elapsedtest.NewFake(st.T0)
	e, err := New(Config{Store: store, Clock: clock, Freezer: &freezer{}, SnapshotBuilder: snapshotter{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, clock, store, path
}

func restartFileEngine(t *testing.T, e *Engine, s *FileStore) *Engine {
	t.Helper()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	next, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Close() })
	if next.epoch == e.epoch {
		t.Fatal("epoch reused")
	}
	return next
}

func TestFileStoreStartupRebuildsIndexes(t *testing.T) {
	e, _, s, _ := fileEngineFixture(t)
	submitJob(t, e, 1)
	readyCard(t, e, 1, true)
	submitGrant(t, e, 2, st.PrincipalA)
	approve(t, e, 2)
	submitJob(t, e, 3)
	cancelAdmissionRecord(t, e, 3)
	command(t, e, 3, ap.ShedRecord{Pressure: true})
	before := e.projections
	next := restartFileEngine(t, e, s)
	got := next.projections
	if len(got.grants) != 0 || len(got.newest) != 0 {
		t.Fatal("grant authority survived restart")
	}
	if !reflect.DeepEqual(got.cards, before.cards) || !reflect.DeepEqual(got.handles, before.handles) || !reflect.DeepEqual(got.requestIDs, before.requestIDs) || !reflect.DeepEqual(got.unflushed, before.unflushed) || !reflect.DeepEqual(got.due, before.due) {
		t.Fatal("indexes changed on restart")
	}
	if got.total.records != before.total.records || got.total.full != before.total.full || got.total.reserved != before.total.reserved || got.total.live != before.total.live-1 {
		t.Fatal("counters not reconstructed", got.total, before.total)
	}
	for key := range got.records {
		rec, err := s.Load(key)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.work[key], ap.Next(rec, next.now(), next.epoch, next.config.Settings, false)) {
			t.Fatal("Startup omitted Next")
		}
	}
}

func TestFileStoreReservationAndLateReportAfterRestart(t *testing.T) {
	e, clock, s, path := fileEngineFixture(t)
	sums := make([]ap.Summary, 8)
	for i := 1; i <= 8; i++ {
		sums[i-1] = submitJob(t, e, i)
		voteApprove(t, e, i)
		flushRecord(t, e, i)
	}
	budget := e.projections.total.reserved
	e.config.Caps.PayloadBytes = budget
	_, err := admissionSubmit(e, 9, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	e = restartFileEngine(t, e, s)
	if e.projections.total.reserved != budget {
		t.Fatal("reservation changed before Claim")
	}
	e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{"signature"}, nil
	})
	for i := 1; i <= 8; i++ {
		ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(i), claimOf(i, sums[i-1]))
		if err != nil || len(ans.Signatures) != 1 {
			t.Fatal(ans, err)
		}
	}
	var size int64
	for key, charge := range e.projections.records {
		info, err := os.Stat(filepath.Join(path, key))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > charge.reserved {
			t.Fatal("file exceeded reservation")
		}
		size += info.Size()
	}
	if size > budget {
		t.Fatal("files exceeded budget")
	}
	clock.Advance(20 * time.Minute)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	flushRecord(t, e, 1)
	ans, err := e.Shed(st.PrincipalA, st.ID(1), true)
	if err != nil || !ans.Changed {
		t.Fatal(ans, err)
	}
	if ans, err = e.Delete(st.PrincipalA, st.ID(1), true); err != nil || ans.Removed {
		t.Fatal("awaiting_report deleted", ans, err)
	}
	e = restartFileEngine(t, e, s)
	for range 40 {
		_, _ = e.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{Token: st.Token(st.ID(99)), PlanHash: sums[0].PlanHash})
		_, _ = e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: st.Token(st.ID(99)), PlanHash: sums[0].PlanHash, Body: finalBody(ap.StepIndeterminate)})
	}
	if _, err := e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: st.Token(st.ID(1)), PlanHash: sums[0].PlanHash, Body: finalBody(ap.StepIndeterminate)}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if err != nil || rec.Payload != nil || rec.Header.FinalReport == nil {
		t.Fatal("late report lost", err)
	}
	info, err := os.Stat(filepath.Join(path, ap.RecordKey(st.PrincipalA, st.ID(1))))
	if err != nil || info.Size() > ap.ShedMax {
		t.Fatal("shed record exceeded bound", err)
	}
}

func TestFileStoreDefaultLiveCaps(t *testing.T) {
	e, _, _, _ := fileEngineFixture(t)
	for id := 1; id <= 256; id++ {
		principal := []string{st.PrincipalA, st.PrincipalB, "local-uid:1002"}[(id-1)/100]
		if _, err := admissionSubmit(e, id, principal); err != nil {
			t.Fatalf("admission %d: %v", id, err)
		}
	}
	if e.projections.total.reserved >= ap.LocalPayloadBudget {
		t.Fatal("one-step live cap consumed entire payload budget")
	}
	_, err := admissionSubmit(e, 257, "local-uid:1002")
	checkCode(t, err, ap.CodeQueueFull)
}

func TestFileStoreQuarantineBudgetRestart(t *testing.T) {
	e, _, s, path := fileEngineFixture(t)
	key := ap.RecordKey(st.PrincipalA, st.ID(999))
	if err := os.WriteFile(filepath.Join(path, key), make([]byte, 400<<10), 0600); err != nil {
		t.Fatal(err)
	}
	e = restartFileEngine(t, e, s)
	if e.projections.total.reserved != 400<<10 || len(e.projections.quarantined) != 1 {
		t.Fatal("quarantine not charged")
	}
	e.config.Caps.PayloadBytes = 400 << 10
	_, err := admissionSubmit(e, 1, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	e = restartFileEngine(t, e, s)
	if e.projections.total.reserved != 400<<10 {
		t.Fatal("restart lost quarantine charge")
	}
	if err := os.Remove(filepath.Join(path, key)); err != nil {
		t.Fatal(err)
	}
	e = restartFileEngine(t, e, s)
	submitJob(t, e, 1)
}

func TestFileStoreRetentionAndDeletedReplay(t *testing.T) {
	e, clock, s, _ := fileEngineFixture(t)
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, clock.Wall(), st.Write("touch /tmp/example", 60))
	if _, err := e.Submit(context.Background(), st.PrincipalA, draft); err != nil {
		t.Fatal(err)
	}
	cancelAdmissionRecord(t, e, 1)
	clock.Advance(8 * 24 * time.Hour)
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	e = restartFileEngine(t, e, s)
	if e.projections.total.records != 0 {
		t.Fatal("retention did not delete record")
	}
	_, err := e.Submit(context.Background(), st.PrincipalA, draft)
	checkCode(t, err, ap.CodeSubmitWindowClosed)
}
