package sqlitestore

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type v2Snapshot struct {
	record   ap.R1
	now      ap.Now
	settings ap.Settings
}

// Model.Run has no observer and deletes its store before returning. Drive its
// signer with seeded schedules instead, saving immutable transition snapshots.
func generatedV2Snapshots(t *testing.T) []v2Snapshot {
	t.Helper()
	var snapshots []v2Snapshot
	coverage := map[string]int{}
	for seed := uint64(1); seed <= 12; seed++ {
		random := rand.New(rand.NewPCG(seed, 2))
		clock := &statetest.Clock{Wall: statetest.T0, Elapsed: time.Hour}
		signer := statetest.NewSigner(clock, seed)
		signer.Settings = ap.Settings{ReportHorizon: time.Duration(1+random.IntN(10)) * time.Minute, Retention: 2 * time.Hour, MaxAge: 3 * time.Hour}
		start := len(snapshots)
		// Randomize the ordering while requiring all six lifecycle paths per seed.
		for _, path := range random.Perm(6) {
			id := statetest.ID(int(seed)*10 + path)
			key := ap.RecordKey(statetest.PrincipalA, id)
			capture := func() ap.R1 {
				t.Helper()
				if signer.Err != nil {
					t.Fatal(signer.Err)
				}
				rec, ok := signer.Store[key]
				if !ok {
					t.Fatalf("seed %d path %d: missing record", seed, path)
				}
				data, err := ap.EncodeR1(rec)
				if err != nil {
					t.Fatal(err)
				}
				rec, err = ap.DecodeR1(data)
				if err != nil {
					t.Fatal(err)
				}
				snapshots = append(snapshots, v2Snapshot{rec, clock.Now(), signer.Settings})
				mint := "none"
				if rec.Header.Mint != nil {
					mint = "error"
					if rec.Header.Mint.State == ap.MintSignatures {
						mint = "erased"
						if rec.Payload != nil && len(rec.Payload.Signatures) > 0 {
							mint = "bytes"
						}
					}
				}
				coverage["mint/"+mint]++
				if rec.Header.FinalReport != nil {
					coverage["final"]++
				}
				if rec.Header.Shed {
					coverage["shed"]++
				}
				if ap.Unflushed(rec) {
					coverage["unflushed"]++
				} else {
					coverage["flushed"]++
				}
				return rec
			}
			// Capture just before, at (before Clock), and after each deadline.
			deadline := func(name string, at time.Time, changed func(ap.R1, ap.R1) bool) {
				t.Helper()
				clock.Advance(at.Add(-time.Second).Sub(clock.Wall))
				before := capture()
				clock.Advance(time.Second)
				capture()
				signer.Do(key, ap.Tick{})
				after := capture()
				if !changed(before, after) {
					t.Fatalf("seed %d path %d: %s transition missing", seed, path, name)
				}
				coverage[name]++
			}
			signer.Submit(statetest.PrincipalA, statetest.JobDraft(id, ap.CoordinatorExecutor, clock.Wall, statetest.Write("true", 30+random.IntN(31))))
			rec := capture()
			deadline("assist", rec.Header.AssistDeadline, func(a, b ap.R1) bool { return a.Header.Assist == nil && b.Header.Assist != nil })
			signer.Reconcile(key)
			capture()
			if path == 0 {
				deadline("expiry", rec.Header.RequestExpiresAt, func(a, b ap.R1) bool {
					return a.Header.Decision == nil && b.Header.Decision != nil && b.Header.Decision.Status == ap.ApprovalExpired
				})
			} else if path == 1 {
				signer.Tap(key, ap.VoteDeny, statetest.Operator, true)
				capture()
			} else {
				signer.Tap(key, ap.VoteApprove, statetest.Operator, true)
				capture()
				signer.FlushPass()
				capture()
				if path >= 3 {
					signer.Claim(key, statetest.Token(id))
					capture()
					signer.FlushPass()
					capture()
					if path == 4 {
						status := []ap.StepStatus{ap.StepSucceeded, ap.StepFailed}[random.IntN(2)]
						report := ap.FinalReport{Class: ap.AggregateJobClass([]ap.StepStatus{status}), ExecutedOrdinals: []int{1}, ResultDigest: fmt.Sprintf("%064x", seed), Steps: []ap.StepReport{{Ordinal: 1, Status: status}}}
						signer.Report(key, statetest.Token(id), report)
						capture()
					}
				}
				end, ok := ap.ClaimEnd(signer.Store[key])
				if !ok {
					t.Fatal("missing claim deadline")
				}
				name := "erase"
				if path == 2 {
					name = "window_closed"
				}
				if path != 4 {
					deadline(name, end, func(a, b ap.R1) bool {
						if path == 2 {
							return a.Header.Mint == nil && b.Header.Mint != nil && b.Header.Mint.State == ap.MintError
						}
						return a.Payload != nil && len(a.Payload.Signatures) > 0 && b.Payload != nil && len(b.Payload.Signatures) == 0
					})
				}
				if path == 3 || path == 5 {
					last, _ := ap.LastEnd(signer.Store[key])
					deadline("horizon", last.Add(signer.Settings.ReportHorizon), func(a, b ap.R1) bool {
						before := ap.View(a, ap.Now{Wall: clock.Wall.Add(-time.Second)}, signer.Epoch, signer.Settings, false)
						after := ap.View(b, clock.Now(), signer.Epoch, signer.Settings, false)
						return before.ExecutionStatus == ap.ExecutionExecuting && after.ExecutionStatus == ap.ExecutionUnreported
					})
				}
			}
			signer.FlushPass()
			rec = capture()
			if rec.Header.Decision == nil {
				t.Fatal("missing decision")
			}
			clock.Advance(rec.Header.Decision.DecidedAt.Add(signer.Settings.Retention).Sub(clock.Wall))
			capture()
			signer.Do(key, ap.ShedRecord{})
			rec = capture()
			if !rec.Header.Shed {
				t.Fatal("retention did not shed")
			}
			signer.FlushPass()
			capture()
			clock.Advance(30 * time.Hour)
			capture()
			if !signer.Do(key, ap.Delete{}).Removed {
				t.Fatal("retention did not delete")
			}
			coverage["delete"]++
		}
		if len(snapshots) == start {
			t.Fatalf("seed %d produced no samples", seed)
		}
	}
	for _, name := range []string{"mint/none", "mint/bytes", "mint/erased", "mint/error", "final", "shed", "unflushed", "flushed", "assist", "expiry", "window_closed", "erase", "horizon", "delete"} {
		if coverage[name] == 0 {
			t.Fatalf("missing generated coverage: %s", name)
		}
	}
	t.Logf("checked %d generated snapshots; coverage: %v", len(snapshots), coverage)
	return snapshots
}
