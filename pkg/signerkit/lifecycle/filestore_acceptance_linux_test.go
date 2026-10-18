//go:build linux

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func TestFileStoreGrantBurst(t *testing.T) {
	for _, report := range []bool{true, false} {
		t.Run(map[bool]string{true: "claimed-reported", false: "unclaimed"}[report], func(t *testing.T) {
			e, clock, _, _ := fileEngineFixture(t)
			submitGrant(t, e, 1000, st.PrincipalA)
			approve(t, e, 1000)
			flushRecord(t, e, 1000)
			e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				return []string{"signature"}, nil
			})
			for id := 1; id <= 150; id++ {
				sum, err := admissionSubmit(e, id, st.PrincipalA)
				// The live grant occupies one of the principal's live slots (SA-6.5).
				if !report && id >= ap.LocalLivePerPrincipal {
					checkCode(t, err, ap.CodeQueueFull)
					continue
				}
				if err != nil {
					t.Fatalf("submit %d: %v", id, err)
				}
				if sum.ApprovalStatus != ap.ApprovalApproved {
					t.Fatal("grant did not cover job")
				}
				if report {
					fileClaimReport(t, e, id, sum)
				}
				clock.Advance(300 * time.Millisecond)
			}
			if !report {
				if len(e.notifyActors) != 0 || e.projections.total.live != 100 {
					t.Fatal("refused burst created work", e.projections.total)
				}
				clock.Advance(2 * time.Minute)
				if _, err := admissionSubmit(e, 151, st.PrincipalA); err != nil {
					t.Fatal("admission did not clock expired windows", err)
				}
			}
		})
	}
}

func fileClaimReport(t *testing.T, e *Engine, id int, sum ap.Summary) {
	t.Helper()
	flushRecord(t, e, id)
	ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(id), claimOf(id, sum))
	if err != nil || len(ans.Signatures) != 1 {
		t.Fatal("claim", ans, err)
	}
	if _, err := e.Report(st.PrincipalA, st.ID(id), ap.Report{Token: st.Token(st.ID(id)), PlanHash: sum.PlanHash, Body: finalBody(ap.StepSucceeded)}); err != nil {
		t.Fatal(err)
	}
	flushRecord(t, e, id)
}

// BenchmarkFileStoreStartupMeasurement is the disk acceptance run; use -benchtime=1x.
func BenchmarkFileStoreStartupMeasurement(b *testing.B) {
	t := b
	if testing.Short() {
		t.Skip("65,536-record disk measurement")
	}
	// Use the workspace filesystem: the system temporary directory may be tmpfs.
	root, err := os.MkdirTemp(".", "filestore-startup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	path := filepath.Join(root, "approvals")
	s, err := AcquireFileStore(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := ap.Now{Wall: st.T0}
	inputs := ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings}
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))
	full, answer := ap.Apply(nil, st.SubmitOf(draft, st.PrincipalA, st.T0, time.Hour), now, inputs)
	if answer.Code != "" {
		t.Fatal(answer)
	}
	for _, cmd := range []ap.Command{ap.AssistDone{Unavailable: "measurement"}, ap.AdminCancel{PlanHash: full.Header.PlanHash, Admin: st.Admin}} {
		full, answer = ap.Apply(&full, cmd, now, inputs)
		if answer.Code != "" {
			t.Fatal(answer)
		}
	}
	full, answer = ap.Apply(&full, ap.Flush{Through: full.Header.OutboxSeq}, now, inputs)
	if answer.Code != "" {
		t.Fatal(answer)
	}
	shed, answer := ap.Apply(&full, ap.ShedRecord{Pressure: true}, now, inputs)
	if answer.Code != "" || shed.Payload != nil {
		t.Fatal("shed fixture", answer)
	}
	// Reuse settled shapes, recomputing every identity-bound field for each file.
	for id := 1; id <= ap.LocalRecordsTotal; id++ {
		draft := st.JobDraft(st.ID(id), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))
		plan := st.Freeze(draft, st.PrincipalA, st.T0, time.Hour)
		rec := shed
		if id <= ap.LocalFullRecords {
			rec = full
			payload := *full.Payload
			payload.Plan = plan
			rec.Payload = &payload
		}
		rec.Header.RequestID = draft.RequestID
		rec.Header.ClaimTokenHash = draft.ExecutorClaimTokenHash
		rec.Header.DraftHash, err = ap.DraftHash(draft)
		if err != nil {
			t.Fatal(err)
		}
		rec.Header.PlanHash, err = ap.PlanHash(plan)
		if err != nil {
			t.Fatal(err)
		}
		data, err := ap.EncodeR1(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, ap.RecordKey(st.PrincipalA, st.ID(id))), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	b.ResetTimer()
	for range b.N {
		start := time.Now()
		if err := s.Reopen(); err != nil {
			t.Fatal(err)
		}
		loaded := time.Since(start)
		t.Logf("warm reload: 65536 files in %s", loaded)
		e, err := New(Config{Store: s, Clock: elapsedtest.NewFake(st.T0), Freezer: &freezer{}, SnapshotBuilder: snapshotter{}})
		if err != nil {
			t.Fatal(err)
		}
		total := time.Since(start)
		if e.projections.total.records != 65536 || e.projections.total.full != 512 || len(e.projections.quarantined) != 0 {
			t.Fatal("wrong startup population", e.projections.total)
		}
		t.Logf("warm: records=65536 full=512 shed=65024 reload=%s startup_total=%s (10s reference SSD gate applies without -race)", loaded, total)
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
	}
	b.StopTimer()
}

type timedFileStore struct {
	*FileStore
	latencies []time.Duration
}

func (s *timedFileStore) Commit(key string, rec ap.R1) error {
	start := time.Now()
	err := s.FileStore.Commit(key, rec)
	s.latencies = append(s.latencies, time.Since(start))
	return err
}

func TestFileStoreGrantStress(t *testing.T) {
	if testing.Short() {
		t.Skip("one simulated hour on disk and tmpfs")
	}
	if raceEnabled {
		t.Skip("the E54 latency gate does not hold under race instrumentation")
	}
	for _, base := range []string{".", "/dev/shm"} {
		t.Run(filepath.Base(base), func(t *testing.T) {
			root, err := os.MkdirTemp(base, "filestore-stress-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			s, err := OpenFileStore(filepath.Join(root, "approvals"), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			clock := elapsedtest.NewFake(st.T0)
			e, err := New(Config{Store: s, Clock: clock, Freezer: &freezer{}, SnapshotBuilder: snapshotter{}})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			// Cover the entire simulated hour, including its last request.
			draft := st.GrantDraft(st.ID(10000), "web-1", 2*time.Hour, clock.Wall())
			if _, err := e.Submit(context.Background(), st.PrincipalA, draft); err != nil {
				t.Fatal(err)
			}
			approve(t, e, 10000)
			flushRecord(t, e, 10000)
			e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				return []string{"signature"}, nil
			})
			timed := &timedFileStore{FileStore: s}
			e.config.Store = timed
			e.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return nil })
			for id := 1; id <= 3600; id++ {
				sum := submitJob(t, e, id)
				if sum.ApprovalStatus != ap.ApprovalApproved {
					t.Fatalf("grant not applied at %d", id)
				}
				fileClaimReport(t, e, id, sum)
				totals := e.projections.total
				if totals.live > ap.LocalLiveTotal || totals.full > ap.LocalFullRecords || totals.records > ap.LocalRecordsTotal || totals.reserved > ap.LocalPayloadBudget {
					t.Fatal("cap exceeded", totals)
				}
				clock.Advance(time.Second)
				if err := e.Reconcile(); err != nil {
					t.Fatal(err)
				}
				for len(e.projections.unflushed) > 0 {
					if _, err := e.flushPass(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				if id%600 == 0 {
					t.Logf("completed %d/3600 writes; full=%d records=%d", id, e.projections.total.full, e.projections.total.records)
				}
			}
			slices.Sort(timed.latencies)
			p99 := timed.latencies[(len(timed.latencies)-1)*99/100]
			t.Logf("3600 writes, %d durable updates, p99=%s (gate 250ms)", len(timed.latencies), p99)
			if p99 > 250*time.Millisecond {
				t.Errorf("commit p99 exceeds E54: %s", p99)
			}
		})
	}
}
