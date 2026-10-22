//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

type commandSignerFake struct {
	submitSignerFake
	claim  func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error)
	report func(context.Context, string, string, [32]byte, approvalwire.Report) error
}

func (f *commandSignerFake) Claim(c context.Context, id, h string, t [32]byte) (approvalwire.ClaimAnswer, error) {
	return f.claim(c, id, h, t)
}
func (f *commandSignerFake) Report(c context.Context, id, h string, t [32]byte, r approvalwire.Report) error {
	return f.report(c, id, h, t, r)
}

type commandSSHFunc func(context.Context, string, func() error, io.Writer, io.Writer) (int, error)

func (f commandSSHFunc) RunPhasedTo(c context.Context, h, u string, p int, w string, in io.Reader, g func() error, out, err io.Writer) (int, error) {
	return f(c, w, g, out, err)
}
func successfulSSH(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
	if e := g(); e != nil {
		return -1, &gatessh.PhasedError{Class: "guard_refused"}
	}
	io.WriteString(out, "output")
	return 0, nil
}
func commandFixture(t *testing.T, commands ...string) (*Service, *waiterStore, *commandSignerFake, executorwire.SubmitRequest) {
	t.Helper()
	s, store := waiterService(t, 0)
	request := submitRequest(t, 1)
	if len(commands) > 0 {
		in := request.Input
		in.Tool = "run_batch"
		in.Command = ""
		in.Commands = commands
		request = requestWith(t, in)
	}
	view, err := s.Submit(request)
	if err != nil {
		t.Fatal(err)
	}
	job := store.jobs[view.RequestID]
	signer := &commandSignerFake{}
	summary := notificationSummary(job.Draft, ap.NotificationSent)
	summary.ApprovalStatus = ap.ApprovalApproved
	signer.submit = func(context.Context, ap.ApprovalDraft) (ap.Summary, error) { return summary, nil }
	signer.get = func(context.Context, string) (ap.Summary, error) { return summary, nil }
	signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) {
		return commandClaim(t, job), nil
	}
	signer.report = func(context.Context, string, string, [32]byte, approvalwire.Report) error { return nil }
	s.signer = signer
	return s, store, signer, request
}
func commandClaim(t *testing.T, job ap.R2) approvalwire.ClaimAnswer {
	t.Helper()
	at := st.T0
	answer := approvalwire.ClaimAnswer{Status: ap.ClaimSignatures, DecidedAt: &at}
	for _, step := range job.Draft.CommandJob.Steps {
		if !step.Route.Signed() {
			continue
		}
		wire, err := sigwire.EncodeSigned(make([]byte, 64), sigwire.SigPayload{Cmd: step.ExactCommand, Host: step.Target.TrustedHostFingerprint, Reveal: step.Route == ap.RouteSignedReveal, TS: at.Unix(), Exp: at.Add(time.Duration(step.SignatureTTLSeconds) * time.Second).Unix(), Nonce: "test-nonce"})
		if err != nil {
			t.Fatal(err)
		}
		answer.Signatures = append(answer.Signatures, wire)
	}
	return answer
}
func commandJob(t *testing.T, s *Service, id string) ap.R2 {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	j, e := s.store.Load(id)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func waitCommand(t *testing.T, s *Service, id string, predicate func(ap.R2) bool) ap.R2 {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		j := commandJob(t, s, id)
		if predicate(j) {
			return j
		}
		select {
		case e := <-s.fatal:
			t.Fatal(e)
		case <-timer.C:
			t.Fatalf("job did not progress: %+v", ap.JobView(j, s.epoch))
		case <-tick.C:
		}
	}
}
func commandFinal(j ap.R2) bool { return j.ReportResult != nil || j.Outcome != nil }

func TestCommandJobSingleFlightAndDelivery(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var dispatches, claims atomic.Int32
	original := signer.claim
	signer.claim = func(c context.Context, id, h string, tok [32]byte) (approvalwire.ClaimAnswer, error) {
		claims.Add(1)
		return original(c, id, h, tok)
	}
	ssh := commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
		if e := g(); e != nil {
			return -1, e
		}
		dispatches.Add(1)
		committed := commandJob(t, s, request.Input.RequestID)
		if committed.Steps[0].Marker == nil || committed.Steps[0].Marker.Epoch != s.epoch {
			t.Error("Start preceded its durable marker")
		}
		close(entered)
		select {
		case <-release:
		case <-c.Done():
			return -1, c.Err()
		}
		io.WriteString(out, "retained")
		return 0, nil
	})
	if err := s.StartCommandJobs(signer, ssh); err != nil {
		t.Fatal(err)
	}
	receiveWait(t, entered)
	for range 100 {
		s.mu.Lock()
		s.nudgeLocked(request.Input.RequestID)
		s.mu.Unlock()
		if _, e := s.Submit(request); e != nil {
			t.Fatal(e)
		}
	}
	close(release)
	j := waitCommand(t, s, request.Input.RequestID, commandFinal)
	if dispatches.Load() != 1 || claims.Load() != 1 || j.FinalAt == nil || string(j.Steps[0].Result.Stdout) != "retained" {
		t.Fatalf("dispatches=%d claims=%d job=%+v", dispatches.Load(), claims.Load(), j)
	}
	response, _, err := s.awaitSnapshot([]string{j.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Items[0].Job.Results) != 1 || j.FirstDeliveredAt != nil {
		t.Fatal("await changed delivery or omitted output")
	}
	s.delivered([]string{j.RequestID})
	waitCommand(t, s, j.RequestID, func(j ap.R2) bool { return j.FirstDeliveredAt != nil })
	s.Close()
	body, _ := json.Marshal(store.jobs[j.RequestID])
	if bytes.Contains(body, []byte("SSHGATE_SIG:")) {
		t.Fatal("signature persisted")
	}
}

func TestCommandJobResubmitBeyondBoundAndRestart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "bound", true: "restart"}[restart], func(t *testing.T) {
			s, store, signer, request := commandFixture(t)
			var submits atomic.Int32
			original := signer.submit
			release := make(chan struct{})
			signer.submit = func(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
				submits.Add(1)
				select {
				case <-release:
					return original(c, d)
				default:
					return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
				}
			}
			signer.get = func(context.Context, string) (ap.Summary, error) {
				return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeNotFound}
			}
			s.submitTimeout = 20 * time.Millisecond
			if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
				t.Fatal(err)
			}
			response, err := s.SubmitAndNotify(context.Background(), request)
			if err != nil || response.Job == nil || response.NotificationStatus != "" {
				t.Fatalf("bounded response: %+v %v", response, err)
			}
			if restart {
				s.Close()
				next, err := NewService(Config{Store: store, Servers: s.servers, Clock: s.clock})
				if err != nil {
					t.Fatal(err)
				}
				s = next
				t.Cleanup(s.Close)
				if err = s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			j := waitCommand(t, s, request.Input.RequestID, commandFinal)
			if j.ReportResult == nil || submits.Load() < 2 {
				t.Fatal("job did not resubmit and execute", j.Outcome, submits.Load())
			}
		})
	}
}

func TestCommandJobRecoveryAndAbort(t *testing.T) {
	for _, status := range []ap.StepStatus{"", ap.StepStaleTarget, ap.StepExpiredUnexecuted, ap.StepFailedNotStarted, ap.StepIndeterminate} {
		t.Run(string(status), func(t *testing.T) {
			s, store, signer, request := commandFixture(t, "touch /tmp/a", "touch /tmp/b")
			j := store.jobs[request.Input.RequestID]
			j.SignerAck = j.DraftHash
			j, _ = ap.ApplyJob(j, ap.MarkStep{Ordinal: 1}, ap.Now{Wall: st.T0}, "11111111111111111111111111111111")
			if status != "" {
				j, _ = ap.ApplyJob(j, ap.RecordResult{Ordinal: 1, Result: ap.NoOutputResult(status, "")}, ap.Now{Wall: st.T0}, "11111111111111111111111111111111")
			}
			store.jobs[j.RequestID] = j
			var calls atomic.Int32
			if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
				calls.Add(1)
				return successfulSSH(c, w, g, out, err)
			})); err != nil {
				t.Fatal(err)
			}
			j = waitCommand(t, s, j.RequestID, commandFinal)
			expected := status
			if expected == "" {
				expected = ap.StepIndeterminate
			}
			if calls.Load() != 0 || j.Steps[0].Result.Status != expected || j.Steps[1].Result != nil {
				t.Fatal("recovery redispatched or changed abort", j)
			}
		})
	}
}

func TestCommandJobUnsignedTailAndTwoClocks(t *testing.T) {
	for _, mode := range []string{"tail", "expired_write", "wall_back", "wall_forward", "suspend"} {
		t.Run(mode, func(t *testing.T) {
			commands := []string{"touch /tmp/a", "cat /tmp/a"}
			if mode != "tail" {
				commands = append(commands, "touch /tmp/b")
			}
			s, _, signer, request := commandFixture(t, commands...)
			clock := s.clock.(*elapsedtest.Fake)
			var calls, claims atomic.Int32
			claim := signer.claim
			signer.claim = func(c context.Context, id, h string, tok [32]byte) (approvalwire.ClaimAnswer, error) {
				claims.Add(1)
				return claim(c, id, h, tok)
			}
			ssh := commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
				n := calls.Add(1)
				exit, e := successfulSSH(c, w, g, out, err)
				if n == 1 {
					switch mode {
					case "wall_forward":
						clock.Advance(10 * time.Second)
						clock.StepWall(7 * time.Minute)
					case "wall_back":
						clock.Advance(90 * time.Second)
						clock.StepWall(-7 * time.Minute)
					case "suspend":
						clock.Suspend(8 * time.Hour)
						clock.StepWall(-8 * time.Hour)
					default:
						clock.Advance(90 * time.Second)
					}
				}
				return exit, e
			})
			if err := s.StartCommandJobs(signer, ssh); err != nil {
				t.Fatal(err)
			}
			j := waitCommand(t, s, request.Input.RequestID, commandFinal)
			view := ap.JobView(j, s.epoch)
			if calls.Load() != 2 || j.Steps[1].Result.Status != ap.StepSucceeded {
				t.Fatalf("unsigned tail did not run: %+v", view)
			}
			if mode == "tail" {
				if claims.Load() != 1 || view.Class != ap.ClassSucceeded {
					t.Fatal(view, claims.Load())
				}
			} else if claims.Load() != 2 || j.Steps[2].Result.Status != ap.StepExpiredUnexecuted {
				t.Fatal(view, claims.Load())
			}
		})
	}
}

func TestCommandJobPreStartAndRegistryGuards(t *testing.T) {
	for _, mode := range []string{"marker_delay", "handshake_wall", "handshake_elapsed", "registry"} {
		t.Run(mode, func(t *testing.T) {
			s, store, signer, request := commandFixture(t)
			clock := s.clock.(*elapsedtest.Fake)
			if mode == "marker_delay" {
				store.beforeCommit = func(j ap.R2) error {
					if j.Steps[0].Marker != nil && j.Steps[0].Result == nil {
						clock.Advance(59 * time.Second)
					}
					return nil
				}
			}
			if mode == "registry" {
				if err := s.servers.Remove("server"); err != nil {
					t.Fatal(err)
				}
			}
			var starts atomic.Int32
			ssh := commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
				if mode == "handshake_wall" {
					clock.StepWall(time.Minute)
				}
				if mode == "handshake_elapsed" {
					clock.Suspend(time.Minute)
					clock.StepWall(-time.Minute)
				}
				if e := g(); e != nil {
					return -1, &gatessh.PhasedError{Class: "guard_refused"}
				}
				starts.Add(1)
				return 0, nil
			})
			if err := s.StartCommandJobs(signer, ssh); err != nil {
				t.Fatal(err)
			}
			j := waitCommand(t, s, request.Input.RequestID, commandFinal)
			want := ap.StepExpiredUnexecuted
			if mode == "registry" {
				want = ap.StepStaleTarget
			}
			if starts.Load() != 0 || j.Steps[0].Result.Status != want {
				t.Fatal("guard did not prevent Start", j)
			}
		})
	}
}

func TestCommandJobDefinitiveAndTransientAnswers(t *testing.T) {
	for _, phase := range []string{"submit", "get", "claim", "report"} {
		for _, code := range []ap.Code{ap.CodeBusy, ap.CodeStorageUncertain, ap.CodeRecordCorrupt} {
			t.Run(phase+"/"+string(code), func(t *testing.T) {
				s, _, signer, request := commandFixture(t)
				var tries atomic.Int32
				refuse := func() error {
					if tries.Add(1) == 1 {
						return &approvalwire.WireError{Code: code}
					}
					return nil
				}
				switch phase {
				case "submit":
					original := signer.submit
					signer.submit = func(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
						if e := refuse(); e != nil {
							return ap.Summary{}, e
						}
						return original(c, d)
					}
				case "get":
					originalSubmit := signer.submit
					signer.submit = func(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
						sum, e := originalSubmit(c, d)
						sum.ApprovalStatus = ap.ApprovalPending
						return sum, e
					}
					original := signer.get
					signer.get = func(c context.Context, id string) (ap.Summary, error) {
						if e := refuse(); e != nil {
							return ap.Summary{}, e
						}
						return original(c, id)
					}
				case "claim":
					original := signer.claim
					signer.claim = func(c context.Context, id, h string, tok [32]byte) (approvalwire.ClaimAnswer, error) {
						if e := refuse(); e != nil {
							return approvalwire.ClaimAnswer{}, e
						}
						return original(c, id, h, tok)
					}
				case "report":
					signer.report = func(context.Context, string, string, [32]byte, approvalwire.Report) error { return refuse() }
				}
				if e := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); e != nil {
					t.Fatal(e)
				}
				j := waitCommand(t, s, request.Input.RequestID, commandFinal)
				if code.Retryable() {
					if tries.Load() != 2 || j.ReportResult == nil || j.ReportResult.State != ap.ReportAcked {
						t.Fatal("transient ended job", j)
					}
				} else if phase == "report" {
					if j.ReportResult == nil || j.ReportResult.State != ap.ReportRefused {
						t.Fatal(j)
					}
				} else if j.Outcome == nil || j.Outcome.Code != code || j.ReportResult != nil {
					t.Fatal(j)
				}
			})
		}
	}
}

func TestCommandJobStopAndReportReplay(t *testing.T) {
	for _, phase := range []string{"before_start", "running", "claim", "report"} {
		t.Run(phase, func(t *testing.T) {
			s, store, signer, request := commandFixture(t)
			entered := make(chan struct{})
			var reportBytes []byte
			originalClaim := signer.claim
			if phase == "claim" {
				signer.claim = func(c context.Context, id, h string, tok [32]byte) (approvalwire.ClaimAnswer, error) {
					close(entered)
					<-c.Done()
					return approvalwire.ClaimAnswer{}, c.Err()
				}
			}
			if phase == "report" {
				signer.report = func(c context.Context, id, h string, tok [32]byte, r approvalwire.Report) error {
					reportBytes, _ = json.Marshal(r)
					close(entered)
					<-c.Done()
					return c.Err()
				}
			}
			ssh := commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
				if phase == "running" {
					if e := g(); e != nil {
						return -1, e
					}
				}
				if phase == "before_start" || phase == "running" {
					close(entered)
					<-c.Done()
					return -1, c.Err()
				}
				return successfulSSH(c, w, g, out, err)
			})
			if e := s.StartCommandJobs(signer, ssh); e != nil {
				t.Fatal(e)
			}
			receiveWait(t, entered)
			before := commandJob(t, s, request.Input.RequestID)
			s.Close()
			after := commandJob(t, s, request.Input.RequestID)
			b, _ := json.Marshal(before)
			a, _ := json.Marshal(after)
			if !bytes.Equal(b, a) {
				t.Fatal("stop committed effect result")
			}
			next, e := NewService(Config{Store: store, Servers: s.servers, Clock: s.clock})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(next.Close)
			signer.claim = originalClaim
			signer.report = func(c context.Context, id, h string, tok [32]byte, r approvalwire.Report) error {
				if phase == "report" {
					body, _ := json.Marshal(r)
					if !bytes.Equal(body, reportBytes) {
						t.Error("report changed on restart")
					}
				}
				return nil
			}
			var runs atomic.Int32
			if e = next.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
				runs.Add(1)
				return successfulSSH(c, w, g, out, err)
			})); e != nil {
				t.Fatal(e)
			}
			j := waitCommand(t, next, request.Input.RequestID, commandFinal)
			expected := int32(0)
			if phase == "claim" {
				expected = 1
			}
			if runs.Load() != expected {
				t.Fatal("incorrect restart dispatch count", runs.Load())
			}
			if (phase == "before_start" || phase == "running") && j.Steps[0].Result.Status != ap.StepIndeterminate {
				t.Fatal(j)
			}
		})
	}
}

func TestCommandJobResultCommitRefusal(t *testing.T) {
	for _, fault := range []error{securestate.ErrTooLarge, securestate.ErrCommitUncertain} {
		t.Run(fault.Error(), func(t *testing.T) {
			s, store, signer, request := commandFixture(t)
			var attempts int
			store.beforeCommit = func(j ap.R2) error {
				if j.Steps[0].Result != nil {
					attempts++
					if attempts == 1 {
						return fault
					}
				}
				return nil
			}
			if e := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); e != nil {
				t.Fatal(e)
			}
			if errors.Is(fault, securestate.ErrCommitUncertain) {
				if e := receiveWait(t, s.fatal); !errors.Is(e, fault) {
					t.Fatal(e)
				}
				s.Close()
				j := commandJob(t, s, request.Input.RequestID)
				if attempts != 1 || j.Steps[0].Result != nil {
					t.Fatal("uncertain commit retried")
				}
				return
			}
			j := waitCommand(t, s, request.Input.RequestID, commandFinal)
			r := j.Steps[0].Result
			if !r.BodiesUnstorable || len(r.Stdout) != 0 || r.ExitCode == nil || *r.ExitCode != 0 || r.StdoutBytes != 6 {
				t.Fatal(r)
			}
		})
	}
}

func TestCommandJobRejectsMalformedSignatureSet(t *testing.T) {
	for _, mode := range []string{"missing", "extra", "wrong_command", "wrong_host", "wrong_window", "wrong_reveal", "wrong_net"} {
		t.Run(mode, func(t *testing.T) {
			s, store, signer, request := commandFixture(t)
			claim := commandClaim(t, store.jobs[request.Input.RequestID])
			switch mode {
			case "missing":
				claim.Signatures = nil
			case "extra":
				claim.Signatures = append(claim.Signatures, claim.Signatures[0])
			default:
				sig, p, _ := sigwire.DecodeSigned(claim.Signatures[0])
				switch mode {
				case "wrong_command":
					p.Cmd = "touch /tmp/other"
				case "wrong_host":
					p.Host = "SHA256:other"
				case "wrong_window":
					p.Exp++
				case "wrong_reveal":
					p.Reveal = true
				case "wrong_net":
					p.Net = true
				}
				claim.Signatures[0], _ = sigwire.EncodeSigned(sig, p)
			}
			signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) { return claim, nil }
			var runs atomic.Int32
			if e := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
				runs.Add(1)
				return successfulSSH(c, w, g, out, err)
			})); e != nil {
				t.Fatal(e)
			}
			j := waitCommand(t, s, request.Input.RequestID, commandFinal)
			if runs.Load() != 0 || j.Outcome == nil || j.Outcome.Code != ap.CodeSignerIncompatible {
				t.Fatal("malformed authority dispatched", j)
			}
		})
	}
}

func TestCommandJobsIgnoreAdminAndTransfer(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	j := store.jobs[request.Input.RequestID]
	j.Draft.CommandJob.Steps[0].Route = ap.RouteSignedAdmin
	store.jobs[j.RequestID] = j
	if commandExecutable(j) {
		t.Fatal("admin draft admitted to command worker")
	}
	var calls atomic.Int32
	signer.submit = func(context.Context, ap.ApprovalDraft) (ap.Summary, error) { calls.Add(1); return ap.Summary{}, nil }
	if e := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if calls.Load() != 0 || commandExecutable(ap.R2{Draft: ap.ApprovalDraft{Transfer: &ap.Transfer{}}}) {
		t.Fatal("non-command job executed")
	}
}

func TestCommandJobAlreadyMarkedNeverStarts(t *testing.T) {
	s, store, _, request := commandFixture(t)
	job := store.jobs[request.Input.RequestID]
	job.SignerAck = job.DraftHash
	job, _ = ap.ApplyJob(job, ap.MarkStep{Ordinal: 1}, ap.Now{Wall: st.T0}, s.epoch)
	store.jobs[job.RequestID] = job
	actor := commandActor{service: s, id: job.RequestID}
	if err := actor.BeforeStep(1); err == nil {
		t.Fatal("already_marked accepted")
	}
}

func TestCommandJobStaticClockReads(t *testing.T) {
	elapsedtest.AssertNoDirectTimeReads(t, []string{"execute_linux.go", "notify_linux.go", "retention_linux.go"}, "execute_linux.go:commandWake", "execute_linux.go:commandCallContext", "notify_linux.go:Service.SubmitAndNotify", "notify_linux.go:Service.submitNotification", "notify_linux.go:Service.observeNotification", "retention_linux.go:Service.retentionLoop")
}

func TestCommandJobFractionalDecisionWindow(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	job := store.jobs[request.Input.RequestID]
	claim := commandClaim(t, job)
	fractional := claim.DecidedAt.Add(900 * time.Millisecond)
	claim.DecidedAt = &fractional
	signer.claim = func(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error) { return claim, nil }
	s.clock.(*elapsedtest.Fake).Advance(58500 * time.Millisecond)
	var starts atomic.Int32
	if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
		starts.Add(1)
		return successfulSSH(c, w, g, out, stderr)
	})); err != nil {
		t.Fatal(err)
	}
	j := waitCommand(t, s, job.RequestID, commandFinal)
	if starts.Load() != 0 || j.Steps[0].Result.Status != ap.StepExpiredUnexecuted {
		t.Fatal("fractional decision extended the signature window")
	}
}

func TestCommandJobSubmitDecisionAndReconciliation(t *testing.T) {
	for _, mode := range []string{"denied_submit", "lost_denied", "lost_absent"} {
		t.Run(mode, func(t *testing.T) {
			s, _, signer, request := commandFixture(t)
			var submits, gets atomic.Int32
			original := signer.submit
			signer.submit = func(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
				n := submits.Add(1)
				sum, _ := original(c, d)
				if mode == "denied_submit" {
					sum.ApprovalStatus = ap.ApprovalDenied
					return sum, nil
				}
				if n == 1 {
					return ap.Summary{}, approvalwire.ErrResponseLost
				}
				return sum, nil
			}
			signer.get = func(c context.Context, id string) (ap.Summary, error) {
				gets.Add(1)
				if mode == "lost_absent" {
					return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeNotFound}
				}
				if mode == "denied_submit" {
					return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
				}
				return ap.Summary{RequestID: id, PlanHash: strings.Repeat("a", 64), ApprovalStatus: ap.ApprovalDenied, NotificationStatus: ap.NotificationSent}, nil
			}
			var runs atomic.Int32
			if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, stderr io.Writer) (int, error) {
				runs.Add(1)
				return successfulSSH(c, w, g, out, stderr)
			})); err != nil {
				t.Fatal(err)
			}
			job := waitCommand(t, s, request.Input.RequestID, commandFinal)
			switch mode {
			case "denied_submit":
				if submits.Load() != 1 || gets.Load() != 0 || runs.Load() != 0 || job.Outcome == nil || job.Outcome.Kind != ap.OutcomeDenied {
					t.Fatal("terminal Submit was not adopted", job)
				}
			case "lost_denied":
				if submits.Load() != 1 || gets.Load() != 1 || runs.Load() != 0 || job.Outcome == nil || job.Outcome.Kind != ap.OutcomeDenied {
					t.Fatal("lost Submit was not reconciled", job)
				}
			case "lost_absent":
				if submits.Load() != 2 || gets.Load() != 1 || runs.Load() != 1 || job.ReportResult == nil {
					t.Fatal("absent Submit was not resent", job)
				}
			}
		})
	}
}

func TestCommandJobSubmitNotificationEvidence(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	delete(store.jobs, request.Input.RequestID)
	s.submitTimeout = 2 * time.Second
	signer.get = func(c context.Context, id string) (ap.Summary, error) { <-c.Done(); return ap.Summary{}, c.Err() }
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := s.SubmitAndNotify(context.Background(), request)
	if err != nil || response.NotificationStatus != ap.NotificationSent || response.Job == nil || response.Job.ExecutionStatus == ap.JobSubmitted {
		t.Fatalf("Submit evidence lost: %+v %v", response, err)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("fresh sent evidence waited for stalled Get")
	}
}

func TestCommandJobNonCommandAdmissionWithoutLegacySigner(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	delete(store.jobs, request.Input.RequestID)
	s.signer = nil
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	input := request.Input
	input.Tool = "revoke_server"
	input.Command = ""
	response, err := s.SubmitAndNotify(context.Background(), requestWith(t, input))
	if err != nil || response.Job == nil || response.Job.ExecutionStatus != ap.JobSubmitted {
		t.Fatalf("non-command admission changed: %+v %v", response, err)
	}
	if commandJob(t, s, input.RequestID).SignerAck != "" {
		t.Fatal("non-command worker ran")
	}
}

func TestCommandJobFinalityDropsAuthorityBeforeReport(t *testing.T) {
	s, store, signer, request := commandFixture(t, "touch /tmp/a", "touch /tmp/b")
	job := store.jobs[request.Input.RequestID]
	job.SignerAck = job.DraftHash
	job, answer := ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: ap.NoOutputResult(ap.StepStaleTarget, "")}, ap.Now{Wall: st.T0}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	store.jobs[job.RequestID] = job
	s.commandSigner = signer
	s.commandSSH = commandSSHFunc(successfulSSH)
	actor := commandActor{service: s, id: job.RequestID, signatures: map[int]string{1: "secret"}, memory: ap.JobMemory{Held: map[int]ap.Held{1: {}}}}
	if err := actor.ensureRunner(job); err != nil {
		t.Fatal(err)
	}
	signer.report = func(context.Context, string, string, [32]byte, approvalwire.Report) error {
		if len(actor.signatures) != 0 || len(actor.memory.Held) != 0 {
			t.Error("authority held during final report")
		}
		if err := actor.runner.HoldWindows(ap.Now{Wall: st.T0}, []time.Time{st.T0.Add(time.Minute), st.T0.Add(time.Minute)}); err == nil {
			t.Error("runner authority was not released")
		}
		return &approvalwire.WireError{Code: ap.CodeBusy}
	}
	if _, _, err := actor.next(); err != nil {
		t.Fatal(err)
	}
}

func TestCommandJobNotificationCompletionSurvivesStaleGet(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	delete(store.jobs, request.Input.RequestID)
	s.submitTimeout = 800 * time.Millisecond
	entered, release, reported := make(chan struct{}), make(chan struct{}), make(chan struct{})
	original := signer.submit
	signer.submit = func(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
		select {
		case <-entered:
		case <-c.Done():
			return ap.Summary{}, c.Err()
		}
		return original(c, d)
	}
	var gets atomic.Int32
	signer.get = func(c context.Context, id string) (ap.Summary, error) {
		if gets.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-c.Done():
				return ap.Summary{}, c.Err()
			}
			return ap.Summary{RequestID: id, NotificationStatus: ap.NotificationNotStarted}, nil
		}
		<-c.Done()
		return ap.Summary{}, c.Err()
	}
	signer.report = func(context.Context, string, string, [32]byte, approvalwire.Report) error {
		close(reported)
		return nil
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	answers := make(chan executorwire.Response, 1)
	go func() {
		r, e := s.SubmitAndNotify(context.Background(), request)
		if e != nil {
			t.Error(e)
		}
		answers <- r
	}()
	receiveWait(t, reported)
	close(release)
	if got := receiveWait(t, answers); got.NotificationStatus != ap.NotificationSent {
		t.Fatalf("stale Get erased sent evidence: %+v", got)
	}
	// The reverse ordering uses the same lock-protected observation operation.
	attempt := submitAttempt{notification: ap.NotificationSent}
	attempt.observe(ap.NotificationSending)
	if attempt.notification != ap.NotificationSent {
		t.Fatal("delayed Submit erased completion")
	}
}
