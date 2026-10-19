//go:build linux

package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	e, clock, store, path := fileEngineFixture(t)
	budget := int64(ap.LocalPayloadBudget)
	store.afterStoreUpdate = func() error { checkFileReservations(t, path, budget); return nil }
	sums := make([]ap.Summary, 8)
	for i := 1; i <= 8; i++ {
		sums[i-1] = submitJob(t, e, i)
	}
	budget = e.projections.total.reserved
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
	}
	unflushed := e.projections.unflushed
	e = restartFileEngine(t, e, store)
	if e.projections.total.reserved != budget || !reflect.DeepEqual(unflushed, e.projections.unflushed) {
		t.Fatal("restart lost budget or unflushed work")
	}
	for i := 1; i <= 8; i++ {
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
		beforeNoise := command(t, e, i, ap.StatusEdited{State: step.State})
		// The sink stays unavailable: mandatory transitions and noise still fit.
		for range ap.NoiseFold + 4 {
			command(t, e, i, ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: "unknowncardx", Challenge: "0123456789abcdef", MsgID: 2}})
		}
		afterNoise, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(i)))
		if err != nil {
			t.Fatal(err)
		}
		prefix := len(beforeNoise.Header.Outbox)
		if len(afterNoise.Header.Outbox) != prefix+ap.NoiseFold || afterNoise.Header.OutboxSeq != beforeNoise.Header.OutboxSeq+ap.NoiseFold || afterNoise.Header.NoiseDropped != beforeNoise.Header.NoiseDropped+4 || !reflect.DeepEqual(afterNoise.Header.Outbox[:prefix], beforeNoise.Header.Outbox) {
			t.Fatal("full outbox lost events or noise accounting")
		}
		for _, event := range afterNoise.Header.Outbox[prefix:] {
			if event.Kind != ap.EventVoteReplay || !event.Replay {
				t.Fatal("wrong retained noise", event)
			}
		}
	}
	if e.projections.total.reserved != budget {
		t.Fatal("growth escaped reservation")
	}
	unflushed = e.projections.unflushed
	e = restartFileEngine(t, e, store)
	if e.projections.total.reserved != budget || !reflect.DeepEqual(unflushed, e.projections.unflushed) {
		t.Fatal("restart lost grown work")
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
	e = restartFileEngine(t, e, store)
	e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return errors.New("sink unavailable") })
	if failed, err := e.flushPass(context.Background()); err != nil || !failed {
		t.Fatal("failing writer acknowledged events")
	}
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	before, err := store.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	for range 40 {
		_, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), ap.Claim{Token: st.Token(st.ID(99)), PlanHash: sums[0].PlanHash})
		checkCode(t, err, ap.CodeInvalidClaim)
		_, err = e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: st.Token(st.ID(99)), PlanHash: sums[0].PlanHash, Body: finalBody(ap.StepIndeterminate)})
		checkCode(t, err, ap.CodeInvalidReport)
	}
	clock.Advance(5 * time.Minute)
	_, err = e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: st.Token(st.ID(1)), PlanHash: sums[0].PlanHash, Body: finalBody(ap.StepIndeterminate)})
	if err != nil {
		t.Fatal("late report rejected", err)
	}
	rec, err := store.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Header.Outbox) != 2 || rec.Header.Outbox[0].Kind != ap.EventInvalidClaim || rec.Header.Outbox[1].Kind != ap.EventFinalReport || rec.Header.NoiseDropped-before.Header.NoiseDropped != 79 {
		t.Fatalf("late report/noise accounting: %+v", rec.Header)
	}
	if rec.Header.OutboxSeq-before.Header.OutboxSeq != 2 {
		t.Fatal("unexpected outbox sequence")
	}
	unflushed = e.projections.unflushed
	e = restartFileEngine(t, e, store)
	recovered, err := store.Load(key)
	if err != nil || !reflect.DeepEqual(rec, recovered) || !reflect.DeepEqual(unflushed, e.projections.unflushed) {
		t.Fatal("restart lost unflushed late report", err)
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

// Runs after each durable update, before the FileStore publishes its cache.
func checkFileReservations(t *testing.T, path string, budget int64) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, entry := range entries {
		if !validKey(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		rec, err := ap.DecodeR1(data)
		if err != nil {
			t.Fatal(err)
		}
		bound := ap.ShedMax
		if rec.Payload != nil {
			bound = ap.R1Reservation(rec)
			total += int64(len(data))
		}
		if len(data) > bound {
			t.Fatalf("%s size %d exceeds %d", entry.Name(), len(data), bound)
		}
	}
	if total > budget {
		t.Fatalf("full files %d exceed budget %d", total, budget)
	}
}
