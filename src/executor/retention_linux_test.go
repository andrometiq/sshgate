//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

// Retention only needs the locked directory, not a listening socket.
func retentionStore(t *testing.T) (*Local, *JobStore) {
	t.Helper()
	dir, err := openPrivateDirectory(t.TempDir(), "executor")
	if err != nil {
		t.Fatal(err)
	}
	if err := lock(int(dir.Fd()), "executor"); err != nil {
		t.Fatal(err)
	}
	local := &Local{directory: dir}
	t.Cleanup(func() { local.Close() })
	store, err := local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return local, store
}

func retentionJob(t *testing.T, id int, body, settled bool) ap.R2 {
	t.Helper()
	job := storeJob(t, id, false)
	job.SignerAck = job.DraftHash
	apply := func(cmd ap.JobCommand) {
		next, answer := ap.ApplyJob(job, cmd, ap.Now{Wall: st.T0}, st.Epoch(1))
		if !answer.Changed || answer.Refused != "" {
			t.Fatal(answer)
		}
		job = next
	}
	apply(ap.MarkStep{Ordinal: 1})
	result := ap.NoOutputResult(ap.StepSucceeded, "")
	zero := 0
	result.ExitCode = &zero
	if body {
		result.Stdout = []byte("retained")
		result.StdoutBytes = int64(len(result.Stdout))
		hash := sha256.Sum256(result.Stdout)
		result.StdoutSHA256 = hex.EncodeToString(hash[:])
	}
	apply(ap.RecordResult{Ordinal: 1, Result: result})
	if settled {
		apply(ap.SettleReport{Result: ap.ReportResult{State: ap.ReportAcked}})
	}
	return job
}

func retentionPass(t *testing.T, s *Service, reservation int64) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.retainLocked(reservation); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionAgeRestartAndDeliveryRace(t *testing.T) {
	local, store := retentionStore(t)
	s, _ := waiterService(t, 0)
	s.store = store
	job := retentionJob(t, 1, true, true)
	if err := store.Commit(job); err != nil {
		t.Fatal(err)
	}
	clock := s.clock.(*elapsedtest.Fake)
	clock.Advance(7*24*time.Hour - time.Second)
	retentionPass(t, s, 0)
	got, _ := store.Load(job.RequestID)
	if got.BodiesRemoved != nil {
		t.Fatal("premature removal")
	}
	clock.Advance(time.Second)
	retentionPass(t, s, 0)
	got, _ = store.Load(job.RequestID)
	if got.BodiesRemoved == nil || got.BodiesRemoved.Cause != ap.BodiesRemovedAge || got.ClaimToken != "" || !got.FinalAt.Equal(*job.FinalAt) {
		t.Fatal("retention slots", got)
	}
	store.Close()
	reopened, err := local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s.store = reopened
	response, _, err := s.awaitSnapshot([]string{job.RequestID})
	if err != nil || response.Items[0].Job.ResultStatus != "result_expired" {
		t.Fatal(response, err)
	}
	clock.Advance(23 * 24 * time.Hour)
	retentionPass(t, s, 0)
	if _, err := s.Get(executorwire.GetRequest{ProtoVersion: executorwire.Proto, Kind: executorwire.KindGet, RequestID: job.RequestID}); err == nil {
		t.Fatal("deleted job returned")
	}
	if _, err := os.Stat(filepath.Join(local.directory.Name(), ap.JobKey(job.RequestID))); !os.IsNotExist(err) {
		t.Fatal("file survived", err)
	}
	s.commandSigner = &commandSignerFake{}
	s.delivered([]string{job.RequestID})
	select {
	case err := <-s.fatal:
		t.Fatal("late delivery fatal", err)
	default:
	}
	if len(s.deliveries) != 0 {
		t.Fatal("late delivery resurrected job")
	}
}

func TestRetentionProtectionAndPressure(t *testing.T) {
	for _, mode := range []string{"undelivered", "recent_delivery", "owed", "settled", "actor", "submission", "reader", "floor"} {
		t.Run(mode, func(t *testing.T) {
			_, store := retentionStore(t)
			s, _ := waiterService(t, 0)
			s.store = store
			body := mode == "undelivered" || mode == "recent_delivery"
			job := retentionJob(t, 1, body, mode != "owed")
			clock := s.clock.(*elapsedtest.Fake)
			clock.Advance(2 * 24 * time.Hour)
			if mode == "recent_delivery" {
				at := clock.Wall()
				job.FirstDeliveredAt = &at
			}
			if mode == "floor" {
				job.Draft.SubmitNotAfter = clock.Wall()
				job.DraftHash, _ = ap.DraftHash(job.Draft)
			}
			if err := store.Commit(job); err != nil {
				t.Fatal(err)
			}
			if mode == "reader" {
				s.submitReaders[job.RequestID] = 1
			}
			if mode == "actor" {
				s.actors[job.RequestID] = &commandActor{}
			}
			if mode == "submission" {
				s.submissions[job.RequestID] = &submitAttempt{}
				defer delete(s.submissions, job.RequestID)
			}
			s.jobFileLimit = 1
			s.budgetLimit = 1
			retentionPass(t, s, 1)
			got, err := store.Load(job.RequestID)
			if mode == "settled" {
				if !errors.Is(err, securestate.ErrNotFound) {
					t.Fatal("count pressure did not delete", err)
				}
				return
			}
			if err != nil {
				t.Fatal("protected job deleted", err)
			}
			if body && got.BodiesRemoved != nil {
				t.Fatal("protected body removed")
			}
			if mode == "owed" && got.ClaimToken == "" {
				t.Fatal("owed token removed")
			}
		})
	}
}

func TestRetentionBudgetOldestAndStop(t *testing.T) {
	_, store := retentionStore(t)
	s, _ := waiterService(t, 0)
	s.store = store
	first := retentionJob(t, 1, true, true)
	second := retentionJob(t, 2, true, true)
	at := st.T0
	first.FirstDeliveredAt = &at
	second.FirstDeliveredAt = &at
	later := st.T0.Add(time.Hour)
	second.FinalAt = &later
	for _, job := range []ap.R2{first, second} {
		if err := store.Commit(job); err != nil {
			t.Fatal(err)
		}
	}
	one, _ := R2FinalCharge(first)
	two, _ := R2FinalCharge(second)
	s.budgetLimit = one + two
	s.clock.(*elapsedtest.Fake).Advance(2 * 24 * time.Hour)
	retentionPass(t, s, 1)
	a, _ := store.Load(first.RequestID)
	b, _ := store.Load(second.RequestID)
	if a.BodiesRemoved == nil || a.BodiesRemoved.Cause != ap.BodiesRemovedBudget || b.BodiesRemoved != nil {
		t.Fatal("pressure did not reclaim oldest only")
	}
	s.Close()
	s.mu.Lock()
	err := s.retainLocked(0)
	s.mu.Unlock()
	if err == nil {
		t.Fatal("retention ignored stop")
	}
}

func TestRetentionKeepsLiveAndOwedAcrossAge(t *testing.T) {
	_, store := retentionStore(t)
	s, _ := waiterService(t, 0)
	s.store = store
	live := storeJob(t, 1, false)
	owed := retentionJob(t, 2, true, false)
	for _, job := range []ap.R2{live, owed} {
		if err := store.Commit(job); err != nil {
			t.Fatal(err)
		}
	}
	s.clock.(*elapsedtest.Fake).Advance(31 * 24 * time.Hour)
	retentionPass(t, s, 0)
	got, err := store.Load(live.RequestID)
	if err != nil || got.FinalAt != nil || got.ClaimToken == "" {
		t.Fatal("live job changed", got, err)
	}
	got, err = store.Load(owed.RequestID)
	if err != nil || got.ClaimToken == "" || got.BodiesRemoved == nil {
		t.Fatal("owed report lost", got, err)
	}
	if got.Steps[0].Result.StdoutSHA256 != owed.Steps[0].Result.StdoutSHA256 {
		t.Fatal("report digest changed")
	}
	got, answer := ap.ApplyJob(got, ap.SettleReport{Result: ap.ReportResult{State: ap.ReportRefused, Code: ap.CodeNotFound}}, ap.Now{Wall: s.clock.Wall()}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	if err := store.Commit(got); err != nil {
		t.Fatal(err)
	}
	retentionPass(t, s, 0)
	if _, err := store.Load(owed.RequestID); !errors.Is(err, securestate.ErrNotFound) {
		t.Fatal("settled old report survived", err)
	}
}

func TestRetentionDuePassSkipsUnchangedBodies(t *testing.T) {
	s, store := waiterService(t, 0)
	job := retentionJob(t, 1, true, true)
	store.jobs[job.RequestID] = job
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projectRetentionLocked(job)
	loads := store.loads
	for range 3 {
		if err := s.retainDueLocked(); err != nil {
			t.Fatal(err)
		}
	}
	if store.loads != loads {
		t.Fatal("timer decoded bodies before retention was due")
	}
	s.clock.(*elapsedtest.Fake).Advance(7 * 24 * time.Hour)
	if err := s.retainDueLocked(); err != nil {
		t.Fatal(err)
	}
	if store.jobs[job.RequestID].BodiesRemoved == nil {
		t.Fatal("due bodies retained")
	}
}

func TestRetentionPinsSubmissionThroughSnapshot(t *testing.T) {
	s, store := waiterService(t, 0)
	request := submitRequest(t, 1)
	if _, err := s.Submit(request); err != nil {
		t.Fatal(err)
	}
	job := store.jobs[request.Input.RequestID]
	job.SignerAck = job.DraftHash
	job, _ = ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: ap.NoOutputResult(ap.StepStaleTarget, "")}, ap.Now{Wall: st.T0}, s.epoch)
	job, _ = ap.ApplyJob(job, ap.SettleReport{Result: ap.ReportResult{State: ap.ReportAcked}}, ap.Now{Wall: st.T0}, s.epoch)
	store.jobs[job.RequestID] = job
	s.clock.(*elapsedtest.Fake).Advance(31 * 24 * time.Hour)
	s.signer = submitSignerFake{get: func(context.Context, string) (ap.Summary, error) {
		return notificationSummary(job.Draft, ap.NotificationSent), nil
	}}
	checked := false
	loads := 0
	store.beforeLoad = func(id string) {
		loads++
		if loads == 1 || s.submissions[id] != nil || checked {
			return
		}
		checked = true
		if _, removed, err := s.retainJobLocked(store.jobs[id], false, false); err != nil || removed {
			t.Errorf("snapshot lost pin: removed=%v err=%v", removed, err)
		}
	}
	response, err := s.SubmitAndNotify(context.Background(), request)
	if err != nil || response.Job == nil || !checked {
		t.Fatal("submission snapshot not protected", response, err, checked)
	}
	store.beforeLoad = nil
	if s.submitReaders[job.RequestID] != 0 {
		t.Fatal("handler pin leaked")
	}
	retentionPass(t, s, 0)
	if _, err := store.Load(job.RequestID); !errors.Is(err, securestate.ErrNotFound) {
		t.Fatal("completed handler still pins file", err)
	}
}

func TestRetentionAdmissionReclaimsOrRefuses(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprint(body), func(t *testing.T) {
			_, store := retentionStore(t)
			s, _ := waiterService(t, 0)
			s.store = store
			s.commandSigner = &commandSignerFake{}
			job := retentionJob(t, 1, body, true)
			if err := store.Commit(job); err != nil {
				t.Fatal(err)
			}
			s.clock.(*elapsedtest.Fake).Advance(2 * 24 * time.Hour)
			s.jobFileLimit = 1
			s.mu.Lock()
			err := s.admit(4096)
			s.mu.Unlock()
			if body {
				requireCode(t, err, "executor_full")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetentionStartupAppliesAge(t *testing.T) {
	_, store := retentionStore(t)
	s, _ := waiterService(t, 0)
	s.store = store
	job := retentionJob(t, 1, true, true)
	if err := store.Commit(job); err != nil {
		t.Fatal(err)
	}
	s.clock.(*elapsedtest.Fake).Advance(31 * 24 * time.Hour)
	if err := s.StartCommandJobs(&commandSignerFake{}, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(job.RequestID); !errors.Is(err, securestate.ErrNotFound) {
		t.Fatal("startup retained old finished file", err)
	}
}

func TestRetentionLongRunningStepUsesFinalTime(t *testing.T) {
	s, mem, signer, request := commandFixture(t)
	_, store := retentionStore(t)
	if err := store.Commit(mem.jobs[request.Input.RequestID]); err != nil {
		t.Fatal(err)
	}
	s.store = store
	entered := make(chan struct{})
	release := make(chan struct{})
	clock := s.clock.(*elapsedtest.Fake)
	if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
		if err := g(); err != nil {
			return -1, err
		}
		clock.Advance(8 * 24 * time.Hour)
		close(entered)
		select {
		case <-release:
		case <-c.Done():
			return -1, c.Err()
		}
		io.WriteString(out, "result")
		return 0, nil
	})); err != nil {
		t.Fatal(err)
	}
	receiveWait(t, entered)
	retentionPass(t, s, 0)
	live := commandJob(t, s, request.Input.RequestID)
	if live.FinalAt != nil || live.Steps[0].Marker == nil {
		t.Fatal("running step changed")
	}
	close(release)
	final := waitCommand(t, s, request.Input.RequestID, commandFinal)
	if !final.FinalAt.Equal(clock.Wall()) {
		t.Fatal("finality did not use completion time")
	}
	retentionPass(t, s, 0)
	if commandJob(t, s, request.Input.RequestID).BodiesRemoved != nil {
		t.Fatal("creation age removed fresh result")
	}
	clock.Advance(7 * 24 * time.Hour)
	retentionPass(t, s, 0)
	if commandJob(t, s, request.Input.RequestID).BodiesRemoved == nil {
		t.Fatal("completion age did not remove body")
	}
}

func TestRetentionTimerRemovesDueBodies(t *testing.T) {
	_, store := retentionStore(t)
	s, _ := waiterService(t, 0)
	s.store = store
	job := retentionJob(t, 1, true, true)
	if err := store.Commit(job); err != nil {
		t.Fatal(err)
	}
	if err := s.StartCommandJobs(&commandSignerFake{}, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	s.clock.(*elapsedtest.Fake).Advance(7 * 24 * time.Hour)
	got := waitCommand(t, s, job.RequestID, func(job ap.R2) bool { return job.BodiesRemoved != nil })
	if got.BodiesRemoved.Cause != ap.BodiesRemovedAge {
		t.Fatal("wrong removal cause")
	}
	s.clock.(*elapsedtest.Fake).Advance(23 * 24 * time.Hour)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		_, err := store.Load(job.RequestID)
		s.mu.Unlock()
		if errors.Is(err, securestate.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-deadline.C:
			t.Fatal("timer retained old job file")
		case <-tick.C:
		}
	}
}

type retentionCommitHook struct {
	Store
	afterCommit func(ap.R2)
}

func (s retentionCommitHook) Commit(job ap.R2) error {
	if err := s.Store.Commit(job); err != nil {
		return err
	}
	s.afterCommit(job)
	return nil
}

func TestRetentionRechecksTimeAfterRemovingCommit(t *testing.T) {
	for _, phase := range []string{"bodies", "token"} {
		t.Run(phase, func(t *testing.T) {
			_, disk := retentionStore(t)
			s, _ := waiterService(t, 0)
			job := retentionJob(t, 1, true, true)
			if err := disk.Commit(job); err != nil {
				t.Fatal(err)
			}
			clock := s.clock.(*elapsedtest.Fake)
			clock.Advance(30 * 24 * time.Hour)
			rolledBack := false
			s.store = retentionCommitHook{Store: disk, afterCommit: func(next ap.R2) {
				if !rolledBack && next.BodiesRemoved != nil && (phase == "bodies" || next.ClaimToken == "") {
					clock.StepWall(-24 * time.Hour)
					rolledBack = true
				}
			}}
			retentionPass(t, s, 0)
			got, err := disk.Load(job.RequestID)
			if err != nil {
				t.Fatalf("rollback during %s commit deleted the file: %v", phase, err)
			}
			if !rolledBack || got.BodiesRemoved == nil || got.ClaimToken != "" {
				t.Fatal("removing commits did not complete before deletion eligibility was rechecked")
			}
			clock.Advance(24 * time.Hour)
			retentionPass(t, s, 0)
			if _, err := disk.Load(job.RequestID); !errors.Is(err, securestate.ErrNotFound) {
				t.Fatal("file was not deleted once the age was reached again", err)
			}
		})
	}
}
