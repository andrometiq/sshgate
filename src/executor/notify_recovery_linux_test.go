//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

func TestSubmitCancellationStillReportsUncertainAck(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unlanded", true: "landed"}[landed], func(t *testing.T) {
			service, store, _, _ := submitService(t)
			ownerContext, cancelOwner := context.WithCancel(context.Background())
			ownerDone := make(chan error, 1)
			ownerFinished := make(chan struct{})
			go func() { defer close(ownerFinished); ownerDone <- service.Serve(ownerContext, store.local) }()
			originalUpdate := store.update
			writes := 0
			store.update = func(fn func(*securestate.Transaction) error) error {
				writes++
				if writes == 1 {
					return originalUpdate(fn)
				}
				if landed {
					if err := originalUpdate(fn); err != nil {
						return err
					}
				}
				return securestate.ErrCommitUncertain
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseSigner := func() { releaseOnce.Do(func() { close(release) }) }
			service.signer = submitSignerFake{submit: func(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
				close(entered)
				select {
				case <-release:
					return notificationSummary(draft, ap.NotificationSent), nil
				case <-ctx.Done():
					return ap.Summary{}, ctx.Err()
				}
			}}
			callerContext, cancelCaller := context.WithCancel(context.Background())
			callerDone := make(chan executorwire.Response, 1)
			callerFinished := make(chan struct{})
			defer func() {
				cancelCaller()
				releaseSigner()
				cancelOwner()
				service.Close()
				<-callerFinished
				<-ownerFinished
			}()
			request := submitRequest(t, 1)
			go func() {
				defer close(callerFinished)
				response, err := service.SubmitAndNotify(callerContext, request)
				if err != nil {
					t.Error(err)
				}
				callerDone <- response
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("signer Submit did not enter")
			}
			cancelCaller()
			select {
			case response := <-callerDone:
				if response.Job == nil || response.Job.ExecutionStatus != ap.JobSubmitted {
					t.Fatalf("canceled caller: %+v", response)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("caller did not stop waiting")
			}
			releaseSigner()
			select {
			case err := <-ownerDone:
				if !errors.Is(err, securestate.ErrCommitUncertain) {
					t.Fatalf("owner lost uncertainty: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("owner did not receive actor storage failure")
			}
			if _, err := store.Load(request.Input.RequestID); !errors.Is(err, securestate.ErrCommitUncertain) {
				t.Fatalf("store was not poisoned: %v", err)
			}
		})
	}
}

// The signer outlives both executor instances and accepts exact duplicates only.
type restartSigner struct {
	mu        sync.Mutex
	records   map[string][]byte
	submitted [][]byte
}

func (s *restartSigner) Submit(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
	body, err := json.Marshal(draft)
	if err != nil {
		return ap.Summary{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submitted = append(s.submitted, body)
	if previous, ok := s.records[draft.RequestID]; ok && !bytes.Equal(previous, body) {
		return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeConflict}
	}
	s.records[draft.RequestID] = body
	return notificationSummary(draft, ap.NotificationSent), nil
}

func (s *restartSigner) Get(_ context.Context, id string) (ap.Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, ok := s.records[id]
	if !ok {
		return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeNotFound}
	}
	var draft ap.ApprovalDraft
	if err := json.Unmarshal(body, &draft); err != nil {
		return ap.Summary{}, err
	}
	return notificationSummary(draft, ap.NotificationSent), nil
}

func TestSubmitNotificationDiskRestartCuts(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "local_commit", true: "signer_accepted"}[accepted], func(t *testing.T) {
			service, store, clock, _ := submitService(t)
			defer service.Close()
			signer := &restartSigner{records: make(map[string][]byte)}
			service.signer = signer
			request := submitRequest(t, 1)
			if _, err := service.Submit(request); err != nil {
				t.Fatal(err)
			}
			original, err := store.Load(request.Input.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			draftBytes, err := json.Marshal(original.Draft)
			if err != nil {
				t.Fatal(err)
			}
			if accepted {
				store.update = func(func(*securestate.Transaction) error) error { return securestate.ErrCommitUncertain }
				if _, err = service.SubmitAndNotify(context.Background(), request); !errors.Is(err, securestate.ErrCommitUncertain) {
					t.Fatalf("ack cut: %v", err)
				}
			}
			service.Close()
			clock.Advance(time.Minute)
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := store.local.OpenJobStore()
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restored, err := reopened.Load(request.Input.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			if restored.SignerAck != "" {
				t.Fatal("cut persisted a signer acknowledgement")
			}
			restoredBytes, err := json.Marshal(restored.Draft)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restoredBytes, draftBytes) || restored.ClaimToken != original.ClaimToken || restored.DraftHash != original.DraftHash || !restored.Draft.SubmitNotAfter.Equal(request.Input.SubmitNotAfter) {
				t.Fatal("disk reopen changed draft, token, hash or submit window")
			}
			signer.mu.Lock()
			beforeRecords := len(signer.records)
			beforeCalls := len(signer.submitted)
			signer.mu.Unlock()
			if accepted && (beforeRecords != 1 || beforeCalls != 1) || !accepted && (beforeRecords != 0 || beforeCalls != 0) {
				t.Fatalf("wrong signer cut: records=%d calls=%d", beforeRecords, beforeCalls)
			}
			restarted, err := NewService(Config{Store: reopened, Servers: service.servers, Clock: clock, Signer: signer})
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			response, err := restarted.SubmitAndNotify(context.Background(), request)
			if err != nil || response.Job == nil || response.Job.ExecutionStatus != ap.JobAcknowledged || response.NotificationStatus != ap.NotificationSent {
				t.Fatalf("recovery: %+v %v", response, err)
			}
			recovered, err := reopened.Load(request.Input.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			recoveredBytes, err := json.Marshal(recovered.Draft)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recoveredBytes, draftBytes) || recovered.ClaimToken != original.ClaimToken || recovered.DraftHash != original.DraftHash || !recovered.Draft.SubmitNotAfter.Equal(original.Draft.SubmitNotAfter) || recovered.SignerAck == "" {
				t.Fatal("recovery changed durable identity or failed to acknowledge")
			}
			signer.mu.Lock()
			defer signer.mu.Unlock()
			wantCalls := 1
			if accepted {
				wantCalls = 2
			}
			if len(signer.records) != 1 || len(signer.submitted) != wantCalls {
				t.Fatalf("signer records=%d calls=%d", len(signer.records), len(signer.submitted))
			}
			for _, body := range signer.submitted {
				if !bytes.Equal(body, draftBytes) {
					t.Fatal("signer received a changed draft")
				}
			}
		})
	}
}
