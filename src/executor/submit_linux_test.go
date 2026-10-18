//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

type countingStore struct {
	*JobStore
	commits int
	local   *Local
}

func (s *countingStore) Commit(job ap.R2) error { s.commits++; return s.JobStore.Commit(job) }

func submitService(t *testing.T) (*Service, *countingStore, *elapsedtest.Fake, string) {
	t.Helper()
	local, store, _ := jobStore(t)
	path := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	target := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/a", 60)).CommandJob.Steps[0].Target
	if err := servers.Add("server", registry.Entry{Host: target.ResolvedHost, Port: target.ResolvedPort, User: target.ResolvedUser, Fingerprint: target.TrustedHostFingerprint, AddedAt: target.AddedAt}); err != nil {
		t.Fatal(err)
	}
	clock := elapsedtest.NewFake(st.T0)
	counted := &countingStore{JobStore: store, local: local}
	service, err := NewService(Config{Store: counted, Servers: servers, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return service, counted, clock, path
}
func submitRequest(t *testing.T, id int) executorwire.SubmitRequest {
	t.Helper()
	return requestWith(t, executorwire.Input{RequestID: st.ID(id), SubmitNotAfter: st.T0.Add(time.Hour), Tool: "run", Server: "server", Command: "touch /tmp/job", Reason: "Create the requested file", MaxOutputBytes: 1024})
}
func requestWith(t *testing.T, in executorwire.Input) executorwire.SubmitRequest {
	t.Helper()
	hash, err := in.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return executorwire.SubmitRequest{ProtoVersion: executorwire.Proto, Kind: executorwire.KindSubmit, Input: in, InputHash: hash}
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var wire *executorwire.WireError
	var plan *ap.CodeError
	if errors.As(err, &wire) && wire.Code == code || errors.As(err, &plan) && string(plan.Code) == code {
		return
	}
	t.Fatalf("want %s, got %v", code, err)
}

func TestSubmitIdempotentConcurrentAndRestart(t *testing.T) {
	s, store, clock, path := submitService(t)
	request := submitRequest(t, 1)
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			job, err := s.Submit(request)
			if err != nil || job.ExecutionStatus != ap.JobSubmitted {
				t.Errorf("submit: %+v %v", job, err)
			}
		}()
	}
	group.Wait()
	if store.commits != 1 {
		t.Fatalf("commits = %d", store.commits)
	}
	files, _ := store.List()
	if len(files) != 1 {
		t.Fatalf("files = %d", len(files))
	}
	stored, _ := store.Load(request.Input.RequestID)
	tokenBytes, err := hex.DecodeString(stored.ClaimToken)
	if err != nil || len(tokenBytes) != 32 {
		t.Fatal("claim token")
	}
	var token [32]byte
	copy(token[:], tokenBytes)
	if stored.Draft.ExecutorClaimTokenHash != ap.ClaimTokenHash(token) || stored.Draft.Coordinator != ap.CoordinatorExecutor || !stored.Draft.SubmitNotAfter.Equal(request.Input.SubmitNotAfter) {
		t.Fatal("draft envelope changed")
	}
	clock.Advance(2 * time.Hour)
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	// A new service and re-opened store reconstruct idempotency solely from disk.
	if err := store.JobStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := NewService(Config{Store: reopened, Servers: s.servers, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.epoch == s.epoch {
		t.Fatal("epoch reused")
	}
	job, err := restarted.Submit(request)
	if err != nil || job.ExecutionStatus != ap.JobSubmitted {
		t.Fatalf("replay: %+v %v", job, err)
	}
	changed := request.Input
	changed.SubmitNotAfter = changed.SubmitNotAfter.Add(time.Second)
	_, err = restarted.Submit(requestWith(t, changed))
	requireCode(t, err, "conflict")
}

func TestSubmitWindowAndReservation(t *testing.T) {
	for _, test := range []struct {
		name  string
		delta time.Duration
		code  string
	}{
		{"past", -time.Nanosecond, "submit_window_closed"}, {"equal", 0, ""}, {"allowance", 3602 * time.Second, ""}, {"boundary", 3605 * time.Second, ""}, {"ahead", 3606 * time.Second, "invalid_request"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, store, _, _ := submitService(t)
			in := submitRequest(t, 1).Input
			in.SubmitNotAfter = st.T0.Add(test.delta)
			_, err := s.Submit(requestWith(t, in))
			if test.code != "" {
				requireCode(t, err, test.code)
				if store.commits != 0 {
					t.Fatal("refusal committed")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	s, store, _, _ := submitService(t)
	s.reservationLimit = 1
	_, err := s.Submit(submitRequest(t, 1))
	requireCode(t, err, "request_too_large")
	if store.commits != 0 {
		t.Fatal("oversize committed")
	}
}

func TestSubmitFreshRegistryAndValidation(t *testing.T) {
	for _, failure := range []string{"missing", "malformed", "permissions", "read_only", "changed"} {
		t.Run(failure, func(t *testing.T) {
			s, store, _, path := submitService(t)
			body, _ := os.ReadFile(path)
			var entries map[string]registry.Entry
			if err := json.Unmarshal(body, &entries); err != nil {
				t.Fatal(err)
			}
			entry := entries["server"]
			switch failure {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			default:
				if failure == "changed" {
					entry.Host = "replacement.example"
				} else {
					entry.ReadOnly = true
				}
				entries["server"] = entry
				body, _ = json.Marshal(entries)
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			request := submitRequest(t, 1)
			_, err := s.Submit(request)
			if failure == "changed" {
				if err != nil {
					t.Fatal(err)
				}
				job, _ := store.Load(request.Input.RequestID)
				if job.Draft.CommandJob.Steps[0].Target.ResolvedHost != entry.Host {
					t.Fatal("cached route used")
				}
			} else {
				requireCode(t, err, "invalid_request")
				if store.commits != 0 {
					t.Fatal("invalid route committed")
				}
			}
		})
	}
	s, store, _, _ := submitService(t)
	for _, command := range []string{"SSHGATE_REVOKE", "cat /etc/hostname"} {
		request := submitRequest(t, 1)
		request.Input.Command = command
		// Hash the deliberately invalid envelope without the wire helper.
		request.InputHash, _ = ap.InputHash(request.Input)
		if _, err := s.Submit(request); err == nil {
			t.Fatalf("accepted %q", command)
		}
	}
	request := submitRequest(t, 1)
	request.InputHash = strings.Repeat("0", 64)
	_, err := s.Submit(request)
	requireCode(t, err, "invalid_request")
	if store.commits != 0 {
		t.Fatal("invalid request committed")
	}
}

func TestSubmitBuilders(t *testing.T) {
	for _, tool := range []string{"run", "run_batch", "revoke_server", "update_gate", "transfer"} {
		t.Run(tool, func(t *testing.T) {
			s, store, _, _ := submitService(t)
			in := submitRequest(t, 1).Input
			in.Tool = tool
			switch tool {
			case "run":
				in.Reveal = true
				in.Command = "cat /etc/hostname"
			case "run_batch":
				in.Command = ""
				in.Commands = []string{"cat /etc/hostname", "touch /tmp/a"}
				stop := false
				in.StopOnError = &stop
			case "revoke_server":
				in.Command = ""
			case "update_gate":
				in.Command = ""
				s.stagedGatePath = filepath.Join(t.TempDir(), "gate")
				if err := os.WriteFile(s.stagedGatePath, []byte("staged gate bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "transfer":
				in.Command = ""
				in.Server = ""
				in.Transfer = &executorwire.TransferInput{SourceAlias: "server", DestinationAlias: "server", SourcePath: "/a", DestinationPath: "/b", Mode: ap.TransferMode}
			}
			request := requestWith(t, in)
			if _, err := s.Submit(request); err != nil {
				t.Fatal(err)
			}
			job, err := store.Load(in.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			if job.Reservation != int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft))) {
				t.Fatal("wrong reservation")
			}
			if tool == "update_gate" {
				sum := sha256.Sum256([]byte("staged gate bytes"))
				if job.Draft.CommandJob.Steps[0].ExactCommand != "SSHGATE_UPDATE "+hex.EncodeToString(sum[:]) {
					t.Fatal("wrong staged hash")
				}
			}
			if tool == "transfer" && len(job.Steps) != 1 {
				t.Fatal("transfer job step count")
			}
		})
	}
}

func TestSubmitLiveAndByteCaps(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "bytes"}[large], func(t *testing.T) {
			s, store, _, _ := submitService(t)
			var used int64
			for n := 1; n <= 101; n++ {
				in := submitRequest(t, n).Input
				if large {
					in.MaxOutputBytes = ap.MaxStreamOutputBytes
					in.Tool = "run_batch"
					in.Commands = []string{in.Command, in.Command, in.Command, in.Command}
					in.Command = ""
				}
				_, err := s.Submit(requestWith(t, in))
				if err != nil {
					requireCode(t, err, "executor_full")
					if !large && n != 101 {
						t.Fatalf("live limit at %d", n)
					}
					if large && n >= 100 {
						t.Fatal("budget not enforced")
					}
					return
				}
				job, _ := store.Load(in.RequestID)
				used += job.Reservation
				if used > ap.ExecutorBudget {
					t.Fatal("overcommitted")
				}
			}
			t.Fatal("limit not reached")
		})
	}
}

func TestSubmitQuarantineAndCommitFailure(t *testing.T) {
	s, store, _, _ := submitService(t)
	request := submitRequest(t, 1)
	key := ap.JobKey(request.Input.RequestID)
	store.files[key] = storedJob{JobFile: JobFile{Key: key, Quarantined: true, EncodedBytes: 123}}
	_, err := s.Submit(request)
	if !errors.Is(err, ErrReportAuthLost) {
		t.Fatal(err)
	}
	if store.commits != 0 {
		t.Fatal("quarantine overwritten")
	}
	delete(store.files, key)
	store.update = func(func(*securestate.Transaction) error) error { return securestate.ErrCommitUncertain }
	_, err = s.Submit(request)
	if !errors.Is(err, securestate.ErrCommitUncertain) {
		t.Fatal(err)
	}
	_, err = s.Submit(request)
	if !errors.Is(err, securestate.ErrCommitUncertain) {
		t.Fatal("uncertain store reused", err)
	}
}

func TestSubmitProtocolTwoConnections(t *testing.T) {
	s, store, _, _ := submitService(t)
	request := submitRequest(t, 1)
	for i := 0; i < 2; i++ {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.ServeSubmit(server) }()
		frame, err := executorwire.MarshalRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Write(frame); err != nil {
			t.Fatal(err)
		}
		reply, err := bufio.NewReader(client).ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		client.Close()
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		response, err := executorwire.DecodeResponse(executorwire.KindSubmit, reply)
		if err != nil || !response.OK || response.Job.ExecutionStatus != ap.JobSubmitted {
			t.Fatalf("%s: %v", reply, err)
		}
		job, loadErr := store.Load(request.Input.RequestID)
		if loadErr != nil {
			t.Fatal("reply preceded durable job", loadErr)
		}
		if bytes.Contains(reply, []byte(job.ClaimToken)) || bytes.Contains(reply, []byte(request.Input.Command)) {
			t.Fatal("private job fields in reply")
		}
	}
	if store.commits != 1 {
		t.Fatalf("commits=%d", store.commits)
	}
}

func TestSubmitAccountingFinalAndRemovedBodies(t *testing.T) {
	s, store, _, _ := submitService(t)
	request := submitRequest(t, 1)
	if _, err := s.Submit(request); err != nil {
		t.Fatal(err)
	}
	job, _ := store.Load(request.Input.RequestID)
	if err := s.admit(ap.ExecutorBudget - job.Reservation); err != nil {
		t.Fatal(err)
	}
	requireCode(t, s.admit(ap.ExecutorBudget-job.Reservation+1), "executor_full")
	body := bytes.Repeat([]byte{0xff, '<', '>', '&'}, 128)
	sum := sha256.Sum256(body)
	empty := sha256.Sum256(nil)
	exit := 0
	job = dispatchFixture(t, job, 1)
	job, answer := ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: ap.StepResult{Status: ap.StepSucceeded, ExitCode: &exit, StdoutBytes: int64(len(body)), Stdout: body, StdoutSHA256: hex.EncodeToString(sum[:]), StderrSHA256: hex.EncodeToString(empty[:])}}, ap.Now{Wall: st.T0}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	if err := store.Commit(job); err != nil {
		t.Fatal(err)
	}
	encoded, err := ap.EncodeR2(job)
	if err != nil {
		t.Fatal(err)
	}
	charge, err := R2FinalCharge(job)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.admit(ap.ExecutorBudget - charge); err != nil {
		t.Fatal("final reservation not released", err)
	}
	requireCode(t, s.admit(ap.ExecutorBudget-charge+1), "executor_full")
	// Put the budget one byte short of admitting an identical new job.
	fillerKey := ap.JobKey(st.ID(90))
	store.files[fillerKey] = storedJob{JobFile: JobFile{Key: fillerKey, Quarantined: true,
		EncodedBytes: ap.ExecutorBudget - charge - job.Reservation + 1}}
	_, err = s.Submit(submitRequest(t, 2))
	requireCode(t, err, "executor_full")
	delete(store.files, fillerKey)
	job, answer = ap.ApplyJob(job, ap.RemoveBodies{Cause: ap.BodiesRemovedAge}, ap.Now{Wall: st.T0.Add(ap.BodyRetention)}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	if err = store.Commit(job); err != nil {
		t.Fatal(err)
	}
	removed, _ := ap.EncodeR2(job)
	removedCharge, err := R2FinalCharge(job)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) >= len(encoded) {
		t.Fatal("body not removed")
	}
	if err = s.admit(ap.ExecutorBudget - removedCharge); err != nil {
		t.Fatal("body share not released", err)
	}
	requireCode(t, s.admit(ap.ExecutorBudget-removedCharge+1), "executor_full")
	store.files[fillerKey] = storedJob{JobFile: JobFile{Key: fillerKey, Quarantined: true,
		EncodedBytes: ap.ExecutorBudget - charge - job.Reservation + 1}}
	if _, err = s.Submit(submitRequest(t, 2)); err != nil {
		t.Fatal("removed bodies did not admit job", err)
	}
	delete(store.files, fillerKey)
	if err = store.Remove(st.ID(2)); err != nil {
		t.Fatal(err)
	}
	// A quarantined file consumes both its bytes and one live slot.
	key := ap.JobKey(st.ID(2))
	store.files[key] = storedJob{JobFile: JobFile{Key: key, Quarantined: true, EncodedBytes: 100}}
	requireCode(t, s.admit(ap.ExecutorBudget-removedCharge), "executor_full")
}

func TestSubmitClockReads(t *testing.T) {
	elapsedtest.AssertNoDirectTimeReads(t, []string{"submit_linux.go", "draft_linux.go", "submit_wire_linux.go"})
}

func TestSubmitProtocolRefusals(t *testing.T) {
	for _, kind := range []string{"malformed", "conflict", "quarantine", "uncertain"} {
		t.Run(kind, func(t *testing.T) {
			s, store, _, _ := submitService(t)
			request := submitRequest(t, 1)
			frame, err := executorwire.MarshalRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			want := kind
			switch kind {
			case "malformed":
				frame = []byte("{\n")
				want = "invalid_request"
			case "conflict":
				if _, err = s.Submit(request); err != nil {
					t.Fatal(err)
				}
				request.Input.Command = "touch /tmp/other"
				request = requestWith(t, request.Input)
				frame, err = executorwire.MarshalRequest(request)
				if err != nil {
					t.Fatal(err)
				}
			case "quarantine":
				key := ap.JobKey(request.Input.RequestID)
				store.files[key] = storedJob{JobFile: JobFile{Key: key, Quarantined: true, EncodedBytes: 10}}
				want = "report_auth_lost"
			case "uncertain":
				store.update = func(func(*securestate.Transaction) error) error { return securestate.ErrCommitUncertain }
			}
			client, server := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- s.ServeSubmit(server) }()
			if _, err = client.Write(frame); err != nil {
				t.Fatal(err)
			}
			reply, readErr := bufio.NewReader(client).ReadBytes('\n')
			client.Close()
			serveErr := <-done
			if kind == "uncertain" {
				if !errors.Is(serveErr, securestate.ErrCommitUncertain) || len(reply) != 0 || readErr == nil {
					t.Fatalf("uncertain reply: %s %v %v", reply, readErr, serveErr)
				}
				return
			}
			if readErr != nil || serveErr != nil {
				t.Fatalf("%v %v", readErr, serveErr)
			}
			response, err := executorwire.DecodeResponse(executorwire.KindSubmit, reply)
			requireCode(t, err, want)
			if response.OK || response.Error == nil || response.Error.Code != want {
				t.Fatalf("%s", reply)
			}
		})
	}
}

func TestSubmitFileCap(t *testing.T) {
	s, store, _, _ := submitService(t)
	// Populate the committed snapshot with valid final records, which consume
	// no live slots and together remain below the byte budget.
	for i := 1; i <= ap.ExecutorJobFiles; i++ {
		job := storeJob(t, i, false)
		job.SignerAck = job.DraftHash
		job, answer := ap.ApplyJob(job, ap.SetOutcome{Outcome: ap.JobOutcome{Kind: ap.OutcomeDenied}}, ap.Now{Wall: st.T0}, s.epoch)
		if !answer.Changed {
			t.Fatal(answer)
		}
		body, err := ap.EncodeR2(job)
		if err != nil {
			t.Fatal(err)
		}
		key := ap.JobKey(job.RequestID)
		store.files[key] = storedJob{JobFile: JobFile{Key: key, RequestID: job.RequestID, EncodedBytes: int64(len(body))}, body: body}
	}
	_, err := s.Submit(submitRequest(t, ap.ExecutorJobFiles+1))
	requireCode(t, err, "executor_full")
	if store.commits != 0 {
		t.Fatal("file cap admitted a new job")
	}
}

type admissionScanStore struct {
	Store
	scan func()
}

func (s *admissionScanStore) List() ([]JobFile, error) {
	if s.scan != nil {
		scan := s.scan
		s.scan = nil
		scan()
	}
	return s.Store.List()
}

func TestSubmitRouteAfterAdmission(t *testing.T) {
	for _, mode := range []string{"changed", "capacity", "reservation", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			service, store, _, path := submitService(t)
			request := submitRequest(t, 1)
			draft, err := service.buildDraft(request.Input, strings.Repeat("0", 64))
			if err != nil {
				t.Fatal(err)
			}
			preliminary := int64(ap.R2Reservation(draft, ap.PermittedOutputBytes(draft)))
			if mode == "capacity" {
				key := ap.JobKey(st.ID(90))
				store.files[key] = storedJob{JobFile: JobFile{Key: key, Quarantined: true, EncodedBytes: ap.ExecutorBudget - preliminary}}
			}
			if mode == "reservation" {
				service.reservationLimit = preliminary
			}
			service.store = &admissionScanStore{Store: store, scan: func() {
				if mode == "invalid" {
					if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
					return
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var entries map[string]registry.Entry
				if err := json.Unmarshal(body, &entries); err != nil {
					t.Fatal(err)
				}
				entry := entries["server"]
				entry.Host = "longer-replacement-host.example"
				entries["server"] = entry
				body, err = json.Marshal(entries)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}}
			_, err = service.Submit(request)
			switch mode {
			case "capacity":
				requireCode(t, err, "executor_full")
			case "reservation":
				requireCode(t, err, "request_too_large")
			case "invalid":
				requireCode(t, err, "invalid_request")
			default:
				if err != nil {
					t.Fatal(err)
				}
				job, err := store.Load(request.Input.RequestID)
				if err != nil {
					t.Fatal(err)
				}
				if job.Draft.CommandJob.Steps[0].Target.ResolvedHost != "longer-replacement-host.example" {
					t.Fatal("froze pre-admission route")
				}
				if job.Reservation <= preliminary {
					t.Fatal("did not resize reservation")
				}
				return
			}
			if store.commits != 0 {
				t.Fatal("refused admission committed a job")
			}
		})
	}
}

func TestFinalChargeBudgetBoundary(t *testing.T) {
	reports := []ap.ReportResult{{State: ap.ReportAcked}}
	for _, code := range ap.AllCodes {
		if !code.Retryable() {
			reports = append(reports, ap.ReportResult{State: ap.ReportRefused, Code: code})
		}
	}
	for _, report := range reports {
		t.Run(report.State+string(report.Code), func(t *testing.T) {
			service, store, _, _ := submitService(t)
			request := submitRequest(t, 1)
			if _, err := service.Submit(request); err != nil {
				t.Fatal(err)
			}
			job, err := store.Load(request.Input.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("output")
			digest := sha256.Sum256(body)
			empty := sha256.Sum256(nil)
			exit := 0
			job = dispatchFixture(t, job, 1)
			job, answer := ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: ap.StepResult{Status: ap.StepSucceeded, ExitCode: &exit, Stdout: body, StdoutBytes: int64(len(body)), StdoutSHA256: hex.EncodeToString(digest[:]), StderrSHA256: hex.EncodeToString(empty[:])}}, ap.Now{Wall: st.T0}, service.epoch)
			if !answer.Changed {
				t.Fatal(answer)
			}
			if err := store.Commit(job); err != nil {
				t.Fatal(err)
			}
			charge, err := R2FinalCharge(job)
			if err != nil {
				t.Fatal(err)
			}
			if charge > job.Reservation {
				t.Fatal("charge exceeds reservation")
			}
			encoded, _ := ap.EncodeR2(job)
			// Encoded size alone would admit this new job with no room for delivery.
			key := ap.JobKey(st.ID(90))
			store.files[key] = storedJob{JobFile: JobFile{Key: key, Quarantined: true, EncodedBytes: ap.ExecutorBudget - int64(len(encoded)) - job.Reservation}}
			_, err = service.Submit(submitRequest(t, 2))
			requireCode(t, err, "executor_full")
			store.files[key] = storedJob{JobFile: JobFile{Key: key, Quarantined: true, EncodedBytes: ap.ExecutorBudget - charge - job.Reservation}}
			if _, err = service.Submit(submitRequest(t, 2)); err != nil {
				t.Fatal(err)
			}
			for _, command := range []ap.JobCommand{ap.MarkDelivered{}, ap.SettleReport{Result: report}, ap.RemoveBodies{Cause: ap.BodiesRemovedAge}, ap.DropToken{}} {
				job, answer = ap.ApplyJob(job, command, ap.Now{Wall: st.T0.Add(ap.BodyRetention)}, service.epoch)
				if !answer.Changed {
					t.Fatal(answer)
				}
				if err := store.Commit(job); err != nil {
					t.Fatal(err)
				}
				next, err := R2FinalCharge(job)
				if err != nil {
					t.Fatal(err)
				}
				if next > charge {
					t.Fatalf("%T raised charge: %d > %d", command, next, charge)
				}
				charge = next
				if err := service.admit(0); err != nil {
					t.Fatalf("%T exceeded budget: %v", command, err)
				}
			}
		})
	}
}
