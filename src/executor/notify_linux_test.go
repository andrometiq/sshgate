//go:build linux

package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

type submitSignerFake struct {
	submit func(context.Context, ap.ApprovalDraft) (ap.Summary, error)
	get    func(context.Context, string) (ap.Summary, error)
}

func (f submitSignerFake) Submit(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
	return f.submit(ctx, draft)
}
func (f submitSignerFake) Get(ctx context.Context, id string) (ap.Summary, error) {
	return f.get(ctx, id)
}
func notificationSummary(draft ap.ApprovalDraft, status ap.NotificationStatus) ap.Summary {
	hash, _ := ap.DraftHash(draft)
	return ap.Summary{RequestID: draft.RequestID, PlanHash: hash, ApprovalStatus: ap.ApprovalPending, NotificationStatus: status}
}

// Done observes the actual wait select, after the caller binds its attempt.
type waitEntryContext struct {
	context.Context
	service   *Service
	requestID string
	entered   chan *submitAttempt
	once      sync.Once
}

func (c *waitEntryContext) Done() <-chan struct{} {
	c.once.Do(func() {
		c.service.mu.Lock()
		attempt := c.service.submissions[c.requestID]
		c.service.mu.Unlock()
		c.entered <- attempt
	})
	return c.Context.Done()
}

func TestSubmitNotificationCommittedAndSingleFlight(t *testing.T) {
	service, store, _, _ := submitService(t)
	defer service.Close()
	if service.submitTimeout != 65*time.Second {
		t.Fatal("production return bound changed")
	}
	request := submitRequest(t, 1)
	var mu sync.Mutex
	calls := 0
	var summary ap.Summary
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	releaseSigner := func() { releaseOnce.Do(func() { close(release) }) }
	var group sync.WaitGroup
	defer func() { releaseSigner(); group.Wait() }()
	service.signer = submitSignerFake{
		submit: func(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
			stored, err := store.Load(draft.RequestID)
			if err != nil || stored.DraftHash == "" {
				t.Error("signer called before commit", err)
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 65*time.Second {
				t.Error("unbounded signer call")
			}
			mu.Lock()
			calls++
			summary = notificationSummary(draft, ap.NotificationSent)
			answer := summary
			mu.Unlock()
			enteredOnce.Do(func() { close(entered) })
			<-release
			return answer, nil
		},
		get: func(context.Context, string) (ap.Summary, error) { mu.Lock(); defer mu.Unlock(); return summary, nil },
	}
	responses := make(chan executorwire.Response, 2)
	startCaller := func() <-chan *submitAttempt {
		waiting := make(chan *submitAttempt, 1)
		ctx := &waitEntryContext{Context: context.Background(), service: service, requestID: request.Input.RequestID, entered: waiting}
		group.Add(1)
		go func() {
			defer group.Done()
			response, err := service.SubmitAndNotify(ctx, request)
			if err != nil {
				t.Error(err)
			}
			responses <- response
		}()
		return waiting
	}
	waitForAttempt := func(waiting <-chan *submitAttempt) *submitAttempt {
		select {
		case attempt := <-waiting:
			return attempt
		case <-time.After(5 * time.Second):
			t.Fatal("caller did not enter the attempt wait")
			return nil
		}
	}
	first := waitForAttempt(startCaller())
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first signer call did not enter")
	}
	second := waitForAttempt(startCaller())
	if first == nil || second != first {
		t.Error("second caller joined a different attempt")
	}
	releaseSigner()
	group.Wait()
	close(responses)
	for response := range responses {
		if response.Job == nil || response.Job.ExecutionStatus != ap.JobAcknowledged || response.NotificationStatus != ap.NotificationSent {
			t.Fatalf("reply: %+v", response)
		}
		if _, err := executorwire.MarshalResponse(response); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || store.commits != 2 {
		t.Fatalf("submits=%d commits=%d", calls, store.commits)
	}
}

func TestSubmitNotificationBounds(t *testing.T) {
	for _, mode := range []string{"slow_submit", "busy", "not_started", "sending"} {
		t.Run(mode, func(t *testing.T) {
			service, store, _, _ := submitService(t)
			defer service.Close()
			service.submitTimeout = 250 * time.Millisecond
			var summary ap.Summary
			service.signer = submitSignerFake{
				submit: func(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
					switch mode {
					case "slow_submit":
						<-ctx.Done()
						return ap.Summary{}, ctx.Err()
					case "busy":
						return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
					}
					summary = notificationSummary(draft, ap.NotificationStatus(mode))
					return summary, nil
				},
				get: func(context.Context, string) (ap.Summary, error) { return summary, nil },
			}
			response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
			if err != nil {
				t.Fatal(err)
			}
			service.Close()
			wantNotification, wantState := ap.NotificationStatus(""), ap.JobSubmitted
			if mode == "not_started" || mode == "sending" {
				wantNotification, wantState = ap.NotificationSending, ap.JobAcknowledged
			}
			if response.NotificationStatus != wantNotification || response.Job.ExecutionStatus != wantState {
				t.Fatalf("reply: %+v", response)
			}
			job, err := store.Load(response.Job.RequestID)
			if err != nil || job.Outcome != nil {
				t.Fatal("bound terminalized a durable job", job.Outcome, err)
			}
		})
	}
}

func TestSubmitNotificationRetriesAndReconciliation(t *testing.T) {
	for _, mode := range []string{"busy", "storage_uncertain", "lost_denied", "lost_absent", "incompatible"} {
		t.Run(mode, func(t *testing.T) {
			service, _, _, _ := submitService(t)
			defer service.Close()
			calls, gets := 0, 0
			var first []byte
			var summary ap.Summary
			service.signer = submitSignerFake{
				submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
					calls++
					body, _ := json.Marshal(draft)
					if calls == 1 {
						first = body
					} else if string(first) != string(body) {
						t.Error("retry changed draft bytes")
					}
					summary = notificationSummary(draft, ap.NotificationSent)
					if calls == 1 {
						switch mode {
						case "busy", "storage_uncertain":
							return ap.Summary{}, &approvalwire.WireError{Code: ap.Code(mode)}
						case "lost_denied", "lost_absent":
							return ap.Summary{}, approvalwire.ErrResponseLost
						case "incompatible":
							return ap.Summary{}, approvalwire.ErrSignerIncompatible
						}
					}
					return summary, nil
				},
				get: func(context.Context, string) (ap.Summary, error) {
					gets++
					if mode == "lost_absent" && gets == 1 {
						return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeNotFound}
					}
					answer := summary
					if mode == "lost_denied" {
						answer.ApprovalStatus = ap.ApprovalDenied
					}
					return answer, nil
				},
			}
			response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "lost_denied":
				if calls != 1 || gets != 1 || response.Job.Outcome == nil || response.Job.Outcome.Kind != ap.OutcomeDenied {
					t.Fatalf("lost denial: %+v calls=%d gets=%d", response, calls, gets)
				}
			case "incompatible":
				if calls != 1 || response.Job.Outcome == nil || response.Job.Outcome.Code != ap.CodeSignerIncompatible {
					t.Fatalf("incompatible: %+v", response)
				}
			default:
				if calls != 2 || response.Job.ExecutionStatus != ap.JobAcknowledged || response.NotificationStatus != ap.NotificationSent {
					t.Fatalf("retry: %+v calls=%d", response, calls)
				}
			}
		})
	}
}

func TestSubmitNotificationStopReturnsCommittedJob(t *testing.T) {
	service, store, _, _ := submitService(t)
	defer service.Close()
	waiting := make(chan struct{})
	service.signer = submitSignerFake{
		submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
			return notificationSummary(draft, ap.NotificationSending), nil
		},
		get: func(ctx context.Context, _ string) (ap.Summary, error) {
			close(waiting)
			<-ctx.Done()
			return ap.Summary{}, ctx.Err()
		},
	}
	done := make(chan executorwire.Response, 1)
	go func() {
		response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
		if err != nil {
			t.Error(err)
		}
		done <- response
	}()
	<-waiting
	service.Close()
	response := <-done
	if response.Job == nil || response.Job.ExecutionStatus != ap.JobAcknowledged || store.commits != 2 {
		t.Fatalf("stop response: %+v commits=%d", response, store.commits)
	}
	_, err := service.Submit(submitRequest(t, 2))
	requireCode(t, err, "executor_unavailable")
}

func TestSubmitNotificationRefusalMakesNoSignerCall(t *testing.T) {
	for _, mode := range []string{"window", "oversize", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			service, store, _, _ := submitService(t)
			defer service.Close()
			service.signer = submitSignerFake{submit: func(context.Context, ap.ApprovalDraft) (ap.Summary, error) {
				t.Error("refused admission called signer")
				return ap.Summary{}, errors.New("unexpected call")
			}}
			request := submitRequest(t, 1)
			switch mode {
			case "window":
				request.Input.SubmitNotAfter = request.Input.SubmitNotAfter.Add(-2 * time.Hour)
			case "oversize":
				service.reservationLimit = 1
			case "uncertain":
				store.update = func(func(*securestate.Transaction) error) error { return securestate.ErrCommitUncertain }
			}
			request = requestWith(t, request.Input)
			if _, err := service.SubmitAndNotify(context.Background(), request); err == nil {
				t.Fatal("admission should fail")
			}
		})
	}
}

func TestSubmitNotificationSentAfterPoll(t *testing.T) {
	service, _, _, _ := submitService(t)
	defer service.Close()
	var summary ap.Summary
	gets := 0
	service.signer = submitSignerFake{
		submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
			summary = notificationSummary(draft, ap.NotificationNotStarted)
			return summary, nil
		},
		get: func(_ context.Context, id string) (ap.Summary, error) {
			gets++
			if id != summary.RequestID {
				t.Error("wrong Get id")
			}
			answer := summary
			answer.NotificationStatus = ap.NotificationSent
			return answer, nil
		},
	}
	response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
	if err != nil || response.NotificationStatus != ap.NotificationSent || gets != 1 {
		t.Fatalf("poll: %+v gets=%d err=%v", response, gets, err)
	}
}

func TestSubmitNotificationWireGolden(t *testing.T) {
	for _, status := range []ap.NotificationStatus{ap.NotificationSent, ap.NotificationSending, ""} {
		t.Run(string(status), func(t *testing.T) {
			service, _, _, _ := submitService(t)
			defer service.Close()
			service.submitTimeout = 250 * time.Millisecond
			service.signer = submitSignerFake{
				submit: func(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
					if status == "" {
						<-ctx.Done()
						return ap.Summary{}, ctx.Err()
					}
					return notificationSummary(draft, status), nil
				},
				get: func(context.Context, string) (ap.Summary, error) {
					t.Error("unexpected poll before short bound")
					return ap.Summary{}, errors.New("unexpected Get")
				},
			}
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan error, 1)
			go func() { done <- service.ServeSubmit(server) }()
			frame, err := executorwire.MarshalRequest(submitRequest(t, 1))
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
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			state := "acknowledged"
			notification := `,"notification_status":"` + string(status) + `"`
			if status == "" {
				state, notification = "submitted", ""
			}
			want := `{"proto_version":1,"kind":"exec_submit","ok":true,"job":{"request_id":"a2_0000000000000000000001","execution_status":"` + state + `","steps":[],"executed_ordinals":[]}` + notification + "}\n"
			if string(reply) != want {
				t.Fatalf("response golden\ngot  %s\nwant %s", reply, want)
			}
		})
	}
}

func TestSubmitNotificationCallerCancellationKeepsAttempt(t *testing.T) {
	service, store, _, _ := submitService(t)
	defer service.Close()
	request := submitRequest(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var summary ap.Summary
	calls := 0
	service.signer = submitSignerFake{
		submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
			calls++
			if calls == 1 {
				close(entered)
				<-release
			}
			summary = notificationSummary(draft, ap.NotificationSent)
			return summary, nil
		},
		get: func(context.Context, string) (ap.Summary, error) { return summary, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan executorwire.Response, 1)
	go func() {
		response, err := service.SubmitAndNotify(ctx, request)
		if err != nil {
			t.Error(err)
		}
		done <- response
	}()
	<-entered
	service.mu.Lock()
	attempt := service.submissions[request.Input.RequestID]
	service.mu.Unlock()
	cancel()
	response := <-done
	if response.Job == nil || response.Job.ExecutionStatus != ap.JobSubmitted {
		t.Fatalf("canceled caller: %+v", response)
	}
	close(release)
	<-attempt.done
	job, err := store.Load(request.Input.RequestID)
	if err != nil || job.SignerAck == "" {
		t.Fatal("caller cancellation killed durable submission", err)
	}
	response, err = service.SubmitAndNotify(context.Background(), request)
	if err != nil || calls != 1 || response.Job.ExecutionStatus != ap.JobAcknowledged {
		t.Fatalf("replay: %+v calls=%d err=%v", response, calls, err)
	}
}

func TestSubmitNotificationStopDiscardsLateAnswer(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "error"}[success], func(t *testing.T) {
			service, store, _, _ := submitService(t)
			defer service.Close()
			entered := make(chan struct{})
			service.signer = submitSignerFake{submit: func(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
				close(entered)
				<-ctx.Done()
				if success {
					return notificationSummary(draft, ap.NotificationSent), nil
				}
				return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeInvalidRequest}
			}}
			done := make(chan executorwire.Response, 1)
			go func() {
				response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
				if err != nil {
					t.Error(err)
				}
				done <- response
			}()
			<-entered
			service.Close()
			response := <-done
			if response.Job == nil || response.Job.ExecutionStatus != ap.JobSubmitted || store.commits != 1 {
				t.Fatalf("late answer committed: %+v commits=%d", response, store.commits)
			}
		})
	}
}

func TestSubmitStopDrainsStalledConsumer(t *testing.T) {
	service, store, _, _ := submitService(t)
	peerUID := store.local.peerUID
	store.local.peerUID = func(conn *net.UnixConn) (uint32, error) {
		if err := conn.SetWriteBuffer(4096); err != nil {
			return 0, err
		}
		return peerUID(conn)
	}
	job, _ := maximumJob(t, 1)
	if err := store.Commit(job); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, store.local) }()
	conn, err := net.Dial("unix", store.local.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	frame, err := executorwire.MarshalRequest(executorwire.AwaitRequest{ProtoVersion: executorwire.Proto, Kind: executorwire.KindAwait, RequestIDs: []string{job.RequestID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	// The first response byte proves the handler has entered the large write.
	if _, err = conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited for a stalled result consumer")
	}
}

func TestSubmitNotificationPollAdoptsDecisionOnce(t *testing.T) {
	service, store, _, _ := submitService(t)
	defer service.Close()
	var summary ap.Summary
	service.signer = submitSignerFake{
		submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
			summary = notificationSummary(draft, ap.NotificationNotStarted)
			return summary, nil
		},
		get: func(context.Context, string) (ap.Summary, error) {
			answer := summary
			answer.ApprovalStatus = ap.ApprovalDenied
			answer.NotificationStatus = ap.NotificationNotApplicable
			return answer, nil
		},
	}
	response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if response.Job.Outcome == nil || response.Job.Outcome.Kind != ap.OutcomeDenied || store.commits != 3 {
		t.Fatalf("decision: %+v commits=%d", response, store.commits)
	}
}

func TestSubmitNotificationReplayEvidence(t *testing.T) {
	for _, mode := range []string{"busy", "lost", "not_started", "sending", "sent"} {
		t.Run(mode, func(t *testing.T) {
			service, store, clock, _ := submitService(t)
			defer service.Close()
			request := submitRequest(t, 1)
			service.signer = submitSignerFake{submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
				return notificationSummary(draft, ap.NotificationSent), nil
			}}
			initial, err := service.SubmitAndNotify(context.Background(), request)
			if err != nil || initial.NotificationStatus != ap.NotificationSent {
				t.Fatalf("initial: %+v %v", initial, err)
			}
			service.Close()
			replay, err := NewService(Config{Store: store, Servers: service.servers, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			defer replay.Close()
			replay.submitTimeout = 250 * time.Millisecond
			calls := 0
			job, err := store.Load(request.Input.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			replay.signer = submitSignerFake{
				submit: func(context.Context, ap.ApprovalDraft) (ap.Summary, error) {
					t.Error("acknowledged replay resubmitted")
					return ap.Summary{}, errors.New("unexpected Submit")
				},
				get: func(context.Context, string) (ap.Summary, error) {
					calls++
					switch mode {
					case "busy":
						return ap.Summary{}, &approvalwire.WireError{Code: ap.CodeBusy}
					case "lost":
						return ap.Summary{}, approvalwire.ErrResponseLost
					default:
						return notificationSummary(job.Draft, ap.NotificationStatus(mode)), nil
					}
				},
			}
			response, err := replay.SubmitAndNotify(context.Background(), request)
			replay.Close()
			if err != nil {
				t.Fatal(err)
			}
			want := ap.NotificationStatus("")
			if mode == "not_started" || mode == "sending" {
				want = ap.NotificationSending
			}
			if mode == "sent" {
				want = ap.NotificationSent
			}
			if calls == 0 || response.NotificationStatus != want || response.Job.ExecutionStatus != ap.JobAcknowledged || store.commits != 2 {
				t.Fatalf("replay: %+v gets=%d commits=%d", response, calls, store.commits)
			}
		})
	}
}

func TestSubmitNotificationTerminalDecisionStillPolls(t *testing.T) {
	for _, deniedAtSubmit := range []bool{false, true} {
		t.Run(map[bool]string{false: "get", true: "submit"}[deniedAtSubmit], func(t *testing.T) {
			service, store, _, _ := submitService(t)
			defer service.Close()
			var summary ap.Summary
			gets := 0
			service.signer = submitSignerFake{
				submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
					summary = notificationSummary(draft, ap.NotificationSending)
					if deniedAtSubmit {
						summary.ApprovalStatus = ap.ApprovalDenied
					}
					return summary, nil
				},
				get: func(context.Context, string) (ap.Summary, error) {
					gets++
					answer := summary
					answer.ApprovalStatus = ap.ApprovalDenied
					if deniedAtSubmit || gets == 2 {
						answer.NotificationStatus = ap.NotificationSent
					}
					return answer, nil
				},
			}
			response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
			wantGets := 2
			if deniedAtSubmit {
				wantGets = 1
			}
			if err != nil || response.Job == nil || response.Job.Outcome == nil || response.Job.Outcome.Kind != ap.OutcomeDenied || response.NotificationStatus != ap.NotificationSent || gets != wantGets || store.commits != 3 {
				t.Fatalf("terminal notification: %+v gets=%d commits=%d err=%v", response, gets, store.commits, err)
			}
		})
	}
}

func TestSubmitNotificationEarlyStopPreservesNotStarted(t *testing.T) {
	service, _, _, _ := submitService(t)
	defer service.Close()
	waiting := make(chan struct{})
	service.signer = submitSignerFake{
		submit: func(_ context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
			return notificationSummary(draft, ap.NotificationNotStarted), nil
		},
		get: func(ctx context.Context, _ string) (ap.Summary, error) {
			close(waiting)
			<-ctx.Done()
			return ap.Summary{}, ctx.Err()
		},
	}
	done := make(chan executorwire.Response, 1)
	go func() {
		response, err := service.SubmitAndNotify(context.Background(), submitRequest(t, 1))
		if err != nil {
			t.Error(err)
		}
		done <- response
	}()
	<-waiting
	service.Close()
	response := <-done
	if response.Job == nil || response.Job.ExecutionStatus != ap.JobAcknowledged || response.NotificationStatus != ap.NotificationNotStarted {
		t.Fatalf("early stop: %+v", response)
	}
}
