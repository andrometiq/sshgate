//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/mcp/jobplan"
)

func TestCommandJobMaximumCaptureAndReportAfterBodyRemoval(t *testing.T) {
	s, store, signer, request := commandFixture(t, "touch /tmp/a", "touch /tmp/b", "touch /tmp/c", "touch /tmp/d", "touch /tmp/e", "touch /tmp/f")
	job := store.jobs[request.Input.RequestID]
	for i := range job.Draft.CommandJob.Steps {
		job.Draft.CommandJob.Steps[i].ExactCommand = strings.Repeat("<", ap.MaxTotalBytes/6)
		hash := sha256.Sum256([]byte(job.Draft.CommandJob.Steps[i].ExactCommand))
		job.Draft.CommandJob.Steps[i].CommandSHA256 = hex.EncodeToString(hash[:])
	}
	job.Draft.Rationale = strings.Repeat("<", ap.MaxRationaleBytes)
	job.Draft.CommandJob.MaxOutputBytes = ap.MaxStreamOutputBytes
	var hashErr error
	job.DraftHash, hashErr = ap.DraftHash(job.Draft)
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
	if _, err := ap.EncodeR2(job); err != nil {
		t.Fatal(err)
	}
	store.jobs[job.RequestID] = job
	// Validate every record's actual encoded size, including all retained bodies.
	store.beforeCommit = func(j ap.R2) error { _, err := ap.EncodeR2(j); return err }
	signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) {
		return commandClaim(t, job), nil
	}
	firstReport := make(chan []byte, 1)
	signer.report = func(c context.Context, id, h string, tok [32]byte, r approvalwire.Report) error {
		body, _ := json.Marshal(r)
		firstReport <- body
		<-c.Done()
		return c.Err()
	}
	flood := bytes.Repeat([]byte{0xff}, ap.MaxStreamOutputBytes+100)
	ssh := commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
		if err := g(); err != nil {
			return -1, err
		}
		out.Write(flood)
		stderr.Write(flood)
		return 0, nil
	})
	if err := s.StartCommandJobs(signer, ssh); err != nil {
		t.Fatal(err)
	}
	var report []byte
	select {
	case report = <-firstReport:
	case err := <-s.fatal:
		t.Fatal(err)
	case <-time.After(30 * time.Second):
		t.Fatal("maximum capture did not complete")
	}
	s.Close()
	final := store.jobs[job.RequestID]
	retained := 0
	for _, step := range final.Steps {
		if step.Result == nil || step.Result.BodiesUnstorable || !step.Result.Truncated {
			t.Fatal("maximum output was lost", step)
		}
		retained += len(step.Result.Stdout) + len(step.Result.Stderr)
	}
	if retained != ap.MaxJobOutputBytes {
		t.Fatal("wrong bounded output size", retained)
	}
	clock := s.clock.(*elapsedtest.Fake)
	clock.Advance(7 * 24 * time.Hour)
	final, answer := ap.ApplyJob(final, ap.RemoveBodies{Cause: ap.BodiesRemovedAge}, ap.Now{Wall: clock.Wall(), Elapsed: clock.Elapsed()}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	store.jobs[job.RequestID] = final
	next, err := NewService(Config{Store: store, Servers: s.servers, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	signer.report = func(c context.Context, id, h string, tok [32]byte, r approvalwire.Report) error {
		body, _ := json.Marshal(r)
		if !bytes.Equal(body, report) {
			t.Error("report changed after body removal")
		}
		return nil
	}
	if err = next.StartCommandJobs(signer, commandSSHFunc(func(context.Context, string, func() error, io.Writer, io.Writer) (int, error) {
		t.Error("final job redispatched")
		return 0, nil
	})); err != nil {
		t.Fatal(err)
	}
	waitCommand(t, next, job.RequestID, commandFinal)
}

func TestCommandJobTinyCaptureRetainsJailRemediationAfterRestart(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	job := store.jobs[request.Input.RequestID]
	job.Draft.CommandJob.MaxOutputBytes = 1
	job.Draft.CommandJob.Steps[0].Route = ap.RouteSignedReveal
	var hashErr error
	job.DraftHash, hashErr = ap.DraftHash(job.Draft)
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
	store.jobs[job.RequestID] = job
	signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) {
		return commandClaim(t, job), nil
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
		if err := g(); err != nil {
			return -1, err
		}
		io.WriteString(stderr, "gate: read jail unavailable: test")
		return 77, nil
	})); err != nil {
		t.Fatal(err)
	}
	final := waitCommand(t, s, job.RequestID, commandFinal)
	s.Close()
	next, err := NewService(Config{Store: store, Servers: s.servers, Clock: s.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	response, _, err := next.awaitSnapshot([]string{job.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	result := response.Items[0].Job.Results[0]
	message, ok := jobplan.ReadJailRemediation(result.Annotation)
	if len(result.Stderr) != 1 || result.Status != ap.StepFailed || !ok || message == "" || len(ap.JobView(final, next.epoch).ExecutedOrdinals) != 1 {
		t.Fatal("restart lost execution evidence", result)
	}
	if final.FinalAt == nil || !final.FinalAt.Equal(st.T0) {
		t.Fatal("final time missing")
	}
}

func TestCommandJobsStartGuard(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	delete(store.jobs, request.Input.RequestID)
	if err := s.StartCommandJobs(nil, commandSSHFunc(successfulSSH)); err == nil {
		t.Fatal("nil signer accepted")
	}
	if err := s.StartCommandJobs(signer, nil); err == nil {
		t.Fatal("nil runner accepted")
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err == nil {
		t.Fatal("second worker owner accepted")
	}
	s.Close()
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err == nil {
		t.Fatal("stopped owner restarted")
	}
}

func TestCommandJobChecksRouteBeforeRunner(t *testing.T) {
	s, store, _, request := commandFixture(t)
	job := store.jobs[request.Input.RequestID]
	job.SignerAck = job.DraftHash
	store.jobs[job.RequestID] = job
	if err := s.servers.Remove("server"); err != nil {
		t.Fatal(err)
	}
	actor := commandActor{service: s, id: job.RequestID, memory: ap.JobMemory{Approved: true, Claimed: 1}}
	if _, _, err := actor.next(); err != nil {
		t.Fatal(err)
	}
	final := commandJob(t, s, job.RequestID)
	if final.Steps[0].Result == nil || final.Steps[0].Result.Status != ap.StepStaleTarget || final.Steps[0].Marker != nil || actor.runner != nil {
		t.Fatal("route was not rejected before runner construction")
	}
}

func TestCommandJobRestartRunsUnsignedTailWithoutClaim(t *testing.T) {
	s, store, signer, request := commandFixture(t, "touch /tmp/a", "cat /tmp/a")
	job := store.jobs[request.Input.RequestID]
	job.SignerAck = job.DraftHash
	job, answer := ap.ApplyJob(job, ap.MarkStep{Ordinal: 1}, ap.Now{Wall: st.T0}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	result := ap.NoOutputResult(ap.StepSucceeded, "")
	zero := 0
	result.ExitCode = &zero
	job, answer = ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: result}, ap.Now{Wall: st.T0}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	store.jobs[job.RequestID] = job
	s.clock.(*elapsedtest.Fake).Advance(90 * time.Second)
	signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) {
		t.Error("unsigned tail reacquired authority")
		return approvalwire.ClaimAnswer{Status: ap.ClaimExpired}, nil
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
		if w != "cat /tmp/a" {
			t.Error("repeated signed write")
		}
		return successfulSSH(c, w, g, out, stderr)
	})); err != nil {
		t.Fatal(err)
	}
	final := waitCommand(t, s, job.RequestID, commandFinal)
	if ap.JobView(final, s.epoch).Class != ap.ClassSucceeded {
		t.Fatal(final)
	}
}

func TestCommandJobClaimTerminalStatuses(t *testing.T) {
	for _, status := range []ap.ClaimStatus{ap.ClaimExpired, ap.ClaimMaterializationError, ap.ClaimExecutionReported} {
		t.Run(string(status), func(t *testing.T) {
			s, _, signer, request := commandFixture(t)
			signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) {
				return approvalwire.ClaimAnswer{Status: status, Class: ap.ClassSucceeded}, nil
			}
			if err := s.StartCommandJobs(signer, commandSSHFunc(func(context.Context, string, func() error, io.Writer, io.Writer) (int, error) {
				t.Error("terminal Claim dispatched")
				return 0, nil
			})); err != nil {
				t.Fatal(err)
			}
			job := waitCommand(t, s, request.Input.RequestID, commandFinal)
			if status == ap.ClaimExpired {
				if job.ReportResult == nil || job.Steps[0].Result.Status != ap.StepExpiredUnexecuted {
					t.Fatal(job)
				}
			} else {
				kind := ap.OutcomeJobError
				if status == ap.ClaimExecutionReported {
					kind = ap.OutcomeAdopted
				}
				if job.Outcome == nil || job.Outcome.Kind != kind || job.ReportResult != nil {
					t.Fatal(job)
				}
			}
		})
	}
}

func TestCommandJobClaimNotReadyRetries(t *testing.T) {
	s, _, signer, request := commandFixture(t)
	original := signer.claim
	tries := 0
	signer.claim = func(c context.Context, id, h string, token [32]byte) (approvalwire.ClaimAnswer, error) {
		tries++
		if job := commandJob(t, s, id); job.Steps[0].Marker != nil {
			t.Error("marker written before Claim")
		}
		if tries < 3 {
			return approvalwire.ClaimAnswer{Status: ap.ClaimNotReady}, nil
		}
		return original(c, id, h, token)
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	waitCommand(t, s, request.Input.RequestID, commandFinal)
	s.Close()
	if tries != 3 {
		t.Fatal("not_ready was not retried", tries)
	}
}

func TestCommandJobDeliveryRequiresSuccessfulResponse(t *testing.T) {
	s, _, signer, request := commandFixture(t)
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	waitCommand(t, s, request.Input.RequestID, commandFinal)
	frame, err := executorwire.MarshalRequest(executorwire.AwaitRequest{ProtoVersion: executorwire.Proto, Kind: executorwire.KindAwait, RequestIDs: []string{request.Input.RequestID}})
	if err != nil {
		t.Fatal(err)
	}
	for _, success := range []bool{false, true} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.ServeConn(context.Background(), server) }()
		if _, err := client.Write(frame); err != nil {
			t.Fatal(err)
		}
		if success {
			if _, err := io.ReadAll(client); err != nil {
				t.Fatal(err)
			}
		}
		client.Close()
		err := receiveWait(t, done)
		if success {
			if err != nil {
				t.Fatal(err)
			}
			waitCommand(t, s, request.Input.RequestID, func(j ap.R2) bool { return j.FirstDeliveredAt != nil })
		} else {
			if err == nil {
				t.Fatal("failed write was accepted")
			}
			s.mu.Lock()
			j, loadErr := s.store.Load(request.Input.RequestID)
			delivered := s.deliveries[request.Input.RequestID] || j.FirstDeliveredAt != nil
			s.mu.Unlock()
			if loadErr != nil || delivered {
				t.Fatal("failed response recorded delivery", loadErr)
			}
		}
	}
}
