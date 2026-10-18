//go:build linux

package lifecycle

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
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

	// The race suite launches an uninstrumented production startup harness: race
	// instrumentation is not part of the SSD latency contract.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "startup.go")
	if err := os.WriteFile(source, []byte(fileStartupMeasurementProgram), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := filepath.Abs(filepath.Join(root, "startup"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("measurement build: %v %s", err, output)
	}
	cold := filepath.Join(root, "cold")
	if err := os.Mkdir(cold, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !validKey(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(cold, entry.Name()), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	b.ResetTimer()
	for range b.N {
		for _, measurement := range []struct{ name, path string }{{"warm", path}, {"cold-fresh-copy", cold}} {
			output, err := exec.Command(binary, measurement.path).CombinedOutput()
			if err != nil {
				t.Fatalf("startup: %v %s", err, output)
			}
			var result struct {
				Reload, Total time.Duration
				Records, Full int
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err, string(output))
			}
			if result.Records != 65536 || result.Full != 512 {
				t.Fatal("wrong startup population", result)
			}
			t.Logf("%s: records=%d full=%d reload=%s startup_total=%s (uninstrumented production harness)", measurement.name, result.Records, result.Full, result.Reload, result.Total)
			if measurement.name == "warm" && result.Total > 10*time.Second {
				t.Errorf("warm SSD startup exceeded 10s: %s", result.Total)
			}
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

const fileStartupMeasurementProgram = `package main
import (
 "context"
 "encoding/json"
 "os"
 "time"
 lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
 ap "github.com/karthikeyan5/sshgate/src/approvalplan"
 st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)
type adapters struct{}
func(adapters)Wall()time.Time{return st.T0}
func(adapters)Elapsed()time.Duration{return 0}
func(adapters)Freeze(context.Context,ap.ApprovalDraft,string,string,time.Time)(ap.ApprovalPlanV1,error){panic("unexpected freeze")}
func(adapters)BuildSnapshot(context.Context,ap.ApprovalPlanV1)([]byte,string,error){panic("unexpected snapshot")}
func main(){
 start:=time.Now()
 store,err:=lc.OpenFileStore(os.Args[1],uint32(os.Getuid()));if err!=nil{panic(err)}
 defer store.Close()
 reload:=time.Since(start)
 engine,err:=lc.New(lc.Config{Store:store,Clock:adapters{},Freezer:adapters{},SnapshotBuilder:adapters{}});if err!=nil{panic(err)}
 total:=time.Since(start)
 defer engine.Close()
 entries,err:=store.List();if err!=nil{panic(err)}
 full:=0
 for _,entry:=range entries{if entry.Quarantined{panic("quarantined record")};rec,err:=store.Load(entry.Key);if err!=nil{panic(err)};if rec.Payload!=nil{full++}}
 if err:=json.NewEncoder(os.Stdout).Encode(struct{Reload,Total time.Duration;Records,Full int}{reload,total,len(entries),full});err!=nil{panic(err)}
}
`
