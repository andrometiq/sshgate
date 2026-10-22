//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

func TestCommandJobGetNotFoundAfterAck(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	job := store.jobs[request.Input.RequestID]
	job.SignerAck = job.DraftHash
	store.jobs[job.RequestID] = job
	signer.get = func(context.Context, string) (ap.Summary, error) {
		return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeNotFound}
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(func(context.Context, string, func() error, io.Writer, io.Writer) (int, error) {
		t.Error("dispatch after lost approval")
		return 0, nil
	})); err != nil {
		t.Fatal(err)
	}
	got := waitCommand(t, s, job.RequestID, commandFinal)
	if got.Outcome == nil || got.Outcome.Code != ap.CodeNotFound || got.ReportResult != nil {
		t.Fatal(got)
	}
}

func TestCommandJobResubmitWindowAnswers(t *testing.T) {
	for _, mode := range []string{"closed", "ahead"} {
		t.Run(mode, func(t *testing.T) {
			s, _, signer, request := commandFixture(t)
			var calls atomic.Int32
			original := signer.submit
			signer.submit = func(c context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
				if calls.Add(1) == 1 {
					if mode == "closed" {
						s.clock.(*elapsedtest.Fake).Advance(2 * time.Hour)
						return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
					}
					return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeSubmitWindowAhead}
				}
				if mode == "closed" {
					return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeSubmitWindowClosed}
				}
				return original(c, d)
			}
			if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
				t.Fatal(err)
			}
			got := waitCommand(t, s, request.Input.RequestID, commandFinal)
			if mode == "closed" {
				if got.Outcome == nil || got.Outcome.Kind != ap.OutcomeApprovalLost || calls.Load() != 2 {
					t.Fatal(got, calls.Load())
				}
			} else if got.ReportResult == nil || calls.Load() != 2 {
				t.Fatal(got, calls.Load())
			}
		})
	}
}

func TestCommandJobClaimCorruptBeforeSecondStep(t *testing.T) {
	s, _, signer, request := commandFixture(t, "touch /tmp/a", "touch /tmp/b")
	var calls atomic.Int32
	original := signer.claim
	signer.claim = func(c context.Context, id, h string, tok [32]byte) (approvalwire.ClaimAnswer, error) {
		if calls.Add(1) == 2 {
			return approvalwire.ClaimAnswer{}, &approvalwire.WireError{Code: ap.CodeRecordCorrupt}
		}
		return original(c, id, h, tok)
	}
	var starts atomic.Int32
	if err := s.StartCommandJobs(signer, commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
		starts.Add(1)
		return successfulSSH(c, w, g, out, err)
	})); err != nil {
		t.Fatal(err)
	}
	got := waitCommand(t, s, request.Input.RequestID, commandFinal)
	if starts.Load() != 1 || got.Outcome == nil || got.Outcome.Code != ap.CodeRecordCorrupt || got.Steps[0].Result == nil || got.Steps[1].Result != nil {
		t.Fatal(got, starts.Load())
	}
	s.Close()
	next, err := NewService(Config{Store: s.store, Servers: s.servers, Clock: s.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	response, _, err := next.awaitSnapshot([]string{got.RequestID})
	if err != nil || !response.Items[0].Job.Partial {
		t.Fatal(response, err)
	}
}

func TestCommandJobRegistryFailures(t *testing.T) {
	for _, mode := range []string{"malformed", "unreadable", "insecure", "changed"} {
		t.Run(mode, func(t *testing.T) {
			s, _, signer, request := commandFixture(t)
			path := filepath.Join(t.TempDir(), "servers.json")
			servers, err := registry.New(path)
			if err != nil {
				t.Fatal(err)
			}
			job := commandJob(t, s, request.Input.RequestID)
			target := job.Draft.CommandJob.Steps[0].Target
			entry := registry.Entry{Host: target.ResolvedHost, Port: target.ResolvedPort, User: target.ResolvedUser, Fingerprint: target.TrustedHostFingerprint, AddedAt: target.AddedAt}
			if mode == "changed" {
				entry.Host = "changed.example.invalid"
			}
			if err = servers.Add("server", entry); err != nil {
				t.Fatal(err)
			}
			s.servers = servers
			switch mode {
			case "malformed":
				err = os.WriteFile(path, []byte("{"), 0600)
			case "insecure":
				err = os.Chmod(path, 0620)
			case "unreadable":
				if os.Getuid() == 0 {
					t.Skip("root bypasses read permissions")
				}
				err = os.Chmod(path, 0000)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.StartCommandJobs(signer, commandSSHFunc(func(context.Context, string, func() error, io.Writer, io.Writer) (int, error) {
				t.Error("stale registry dispatched")
				return 0, nil
			})); err != nil {
				t.Fatal(err)
			}
			got := waitCommand(t, s, job.RequestID, commandFinal)
			if got.Steps[0].Result == nil || got.Steps[0].Result.Status != ap.StepStaleTarget {
				t.Fatal(got)
			}
		})
	}
}

func TestCommandJobLastSignedStartDropsAuthority(t *testing.T) {
	s, store, _, request := commandFixture(t)
	job := store.jobs[request.Input.RequestID]
	actor := commandActor{service: s, id: job.RequestID, ordinal: 1, lastSigned: 1, signatures: map[int]string{1: "secret"}, memory: ap.JobMemory{Held: map[int]ap.Held{1: {}}}}
	s.commandSSH = commandSSHFunc(func(c context.Context, w string, g func() error, out, err io.Writer) (int, error) {
		if err := g(); err != nil {
			t.Fatal(err)
		}
		if len(actor.signatures) != 0 || len(actor.memory.Held) != 0 {
			t.Fatal("authority survives last Start")
		}
		return 0, nil
	})
	if _, err := actor.RunPhasedTo(context.Background(), "", "", 0, "", nil, func() error { return nil }, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestWaiterNonPolledTick(t *testing.T) {
	entered := make(chan struct{}, 1)
	client := &waitSignerFake{wait: func(c context.Context, _ []string, _ time.Duration) ([]ap.Summary, error) {
		entered <- struct{}{}
		<-c.Done()
		return nil, c.Err()
	}}
	s, store := waiterService(t, 1, client)
	job := storeJob(t, 2, false)
	store.jobs[job.RequestID] = job
	s.startWaiter()
	receiveWait(t, entered)
	drainNudge(s, job.RequestID)
	s.mu.Lock()
	flag := s.jobNudges[job.RequestID]
	s.mu.Unlock()
	receiveWait(t, flag)
}

func TestWaiterAckCommitWake(t *testing.T) {
	entered := make(chan struct{}, 1)
	client := &waitSignerFake{wait: func(c context.Context, _ []string, _ time.Duration) ([]ap.Summary, error) {
		entered <- struct{}{}
		<-c.Done()
		return nil, c.Err()
	}}
	s, store := waiterService(t, 0, client)
	s.startWaiter()
	// Synchronize with the idle waiter's initial pass before adding membership.
	for {
		s.mu.Lock()
		ready := s.waiterInitialized
		s.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	job := storeJob(t, 1, false)
	job.SignerAck = job.DraftHash
	s.mu.Lock()
	store.jobs[job.RequestID] = job
	s.jobCommittedLocked(job)
	s.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("ack commit did not wake waiter")
	}
}

func TestWaiterBackoffReset(t *testing.T) {
	entered := make(chan int, 8)
	release := make(chan error)
	client := &waitSignerFake{wait: func(c context.Context, _ []string, _ time.Duration) ([]ap.Summary, error) {
		entered <- 1
		select {
		case err := <-release:
			return nil, err
		case <-c.Done():
			return nil, c.Err()
		}
	}}
	s, _ := waiterService(t, 1, client)
	s.startWaiter()
	for range 3 {
		receiveWait(t, entered)
		release <- errors.New("transient")
	}
	receiveWait(t, entered)
	release <- nil
	select {
	case <-entered:
	case <-time.After(600 * time.Millisecond):
		t.Fatal("successful poll did not reset backoff")
	}
}

func TestCommandJobWorkerCachesRecordAndWakes(t *testing.T) {
	s, store, signer, request := commandFixture(t)
	observed := make(chan struct{}, 8)
	signer.submit = func(context.Context, ap.ApprovalDraft) (ap.Summary, error) {
		return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
	}
	s.commandSigner = signer
	actor := commandActor{service: s, id: request.Input.RequestID}
	for range 4 {
		if _, _, err := actor.next(); err != nil {
			t.Fatal(err)
		}
	}
	loads := store.loads
	for range 4 {
		if _, _, err := actor.next(); err != nil {
			t.Fatal(err)
		}
	}
	if store.loads != loads {
		t.Fatal("idle actor redecoded job")
	}
	flag := make(chan struct{}, 1)
	go func() {
		if commandWake(s.effects, flag, time.Hour) {
			observed <- struct{}{}
		}
	}()
	flag <- struct{}{}
	receiveWait(t, observed)
}

func TestCommandJobArtifactsContainNoAuthority(t *testing.T) {
	commandArtifacts(t, nil)
}

func commandArtifacts(t *testing.T, transport commandSSHFunc) {
	t.Helper()
	s, mem, signer, request := commandFixture(t)
	local, disk := retentionStore(t)
	job := mem.jobs[request.Input.RequestID]
	if err := disk.Commit(job); err != nil {
		t.Fatal(err)
	}
	s.store = disk
	var report []byte
	signer.report = func(_ context.Context, _ string, _ string, _ [32]byte, r approvalwire.Report) error {
		report, _ = json.Marshal(r)
		return nil
	}
	claim := commandClaim(t, job)
	if transport == nil {
		transport = commandSSHFunc(func(_ context.Context, w string, g func() error, _ io.Writer, _ io.Writer) (int, error) {
			if err := g(); err != nil {
				return -1, err
			}
			return -1, &gatessh.PhasedError{Class: "failed_not_started", Detail: w}
		})
	}
	if err := s.StartCommandJobs(signer, transport); err != nil {
		t.Fatal(err)
	}
	waitCommand(t, s, job.RequestID, commandFinal)
	s.Close()
	response, _, err := s.awaitSnapshot([]string{job.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(response)
	artifacts := [][]byte{encoded, report}
	// JSON encodes []byte bodies as base64; inspect their decoded contents too.
	persisted, err := disk.Load(job.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range persisted.Steps {
		if step.Result != nil {
			artifacts = append(artifacts, step.Result.Stdout, step.Result.Stderr, []byte(step.Result.Annotation))
		}
	}
	for _, item := range response.Items {
		if item.Job != nil {
			for _, result := range item.Job.Results {
				artifacts = append(artifacts, result.Stdout, result.Stderr, []byte(result.Annotation))
			}
		}
	}
	entries, err := os.ReadDir(local.directory.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(local.directory.Name(), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, body)
	}
	needles := []string{"SSHGATE_SIG:"}
	for _, wire := range claim.Signatures {
		needles = append(needles, wire)
		for _, part := range strings.FieldsFunc(wire, func(r rune) bool { return r == ':' || r == ' ' }) {
			if len(part) > 20 {
				needles = append(needles, part)
			}
		}
	}
	for _, body := range artifacts {
		for _, needle := range needles {
			if bytes.Contains(body, []byte(needle)) {
				t.Fatal("artifact retained authority")
			}
		}
	}
	for _, body := range [][]byte{encoded, report} {
		if bytes.Contains(body, []byte(job.Draft.CommandJob.Steps[0].ExactCommand)) {
			t.Fatal("diagnostic retained command")
		}
	}
}

func TestCommandJobsResolveOutOfOrder(t *testing.T) {
	s, store, signer, _ := commandFixture(t)
	const count = 4
	ids := make([]string, count)
	releases := make(map[string]chan struct{})
	for i := range count {
		request := submitRequest(t, i+1)
		if _, err := s.Submit(request); err != nil {
			t.Fatal(err)
		}
		ids[i] = request.Input.RequestID
		releases[ids[i]] = make(chan struct{})
	}
	entered := make(chan string, count)
	signer.submit = func(ctx context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
		entered <- d.RequestID
		select {
		case <-ctx.Done():
			return ap.Summary{}, ctx.Err()
		case <-releases[d.RequestID]:
		}
		summary := notificationSummary(d, ap.NotificationSent)
		summary.ApprovalStatus = ap.ApprovalApproved
		return summary, nil
	}
	signer.claim = func(_ context.Context, id, _ string, _ [32]byte) (approvalwire.ClaimAnswer, error) {
		s.mu.Lock()
		job := store.jobs[id]
		s.mu.Unlock()
		return commandClaim(t, job), nil
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	for range count {
		receiveWait(t, entered)
	}
	for i := count - 1; i >= 0; i-- {
		close(releases[ids[i]])
		got := waitCommand(t, s, ids[i], commandFinal)
		if got.ReportResult == nil {
			t.Fatal(got)
		}
		for j := 0; j < i; j++ {
			if commandJob(t, s, ids[j]).FinalAt != nil {
				t.Fatal("unreleased job finalized")
			}
		}
	}
}

func TestCommandJobWorkerNudgeInterruptsBackoff(t *testing.T) {
	s, _, signer, request := commandFixture(t)
	calls := make(chan context.Context, 8)
	release := make(chan struct{})
	var count atomic.Int32
	signer.submit = func(ctx context.Context, _ ap.ApprovalDraft) (ap.Summary, error) {
		calls <- ctx
		if count.Add(1) == 4 {
			select {
			case <-release:
			case <-ctx.Done():
				return ap.Summary{}, ctx.Err()
			}
		}
		return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
	}
	if err := s.StartCommandJobs(signer, commandSSHFunc(successfulSSH)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		receiveWait(t, calls)
	}
	fourth := receiveWait(t, calls)
	close(release)
	// The call context is cancelled when the actor has handled the transient
	// answer. Its next retry now has the maximum two-second backoff.
	receiveWait(t, fourth.Done())
	s.mu.Lock()
	s.nudgeLocked(request.Input.RequestID)
	s.mu.Unlock()
	select {
	case <-calls:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("worker nudge did not interrupt signer retry backoff")
	}
}
