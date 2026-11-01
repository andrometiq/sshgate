//go:build linux

package executor

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

func TestWaiterConfiguredClientIsIndependentOfSubmissionSeam(t *testing.T) {
	calls := make(chan struct{}, 1)
	configured := &waitSignerFake{wait: func(ctx context.Context, _ []string, _ time.Duration) ([]ap.Summary, error) {
		calls <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	s, _ := waiterService(t, 1, configured)
	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for range 10000 {
			s.signer = submitSignerFake{}
			runtime.Gosched()
		}
	}()
	close(start)
	for range 10000 {
		s.startWaiter()
		runtime.Gosched()
	}
	receiveWait(t, done)
	receiveWait(t, calls)
	s.Close()
}

func TestWaiterCommitPaths(t *testing.T) {
	for _, phase := range []string{"before_registration", "during_registration", "after_registration"} {
		for _, failed := range []string{"none", "admission", "ack"} {
			t.Run(phase+"/"+failed, func(t *testing.T) {
				signerEntered, releaseSigner := make(chan struct{}), make(chan struct{})
				signerReturned := make(chan struct{})
				waits := make(chan []string, 4)
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(releaseSigner) }) }
				client := &waitSignerFake{submitSignerFake: submitSignerFake{submit: func(ctx context.Context, draft ap.ApprovalDraft) (ap.Summary, error) {
					defer close(signerReturned)
					close(signerEntered)
					select {
					case <-releaseSigner:
						return notificationSummary(draft, ap.NotificationSent), nil
					case <-ctx.Done():
						return ap.Summary{}, ctx.Err()
					}
				}}, wait: func(ctx context.Context, ids []string, _ time.Duration) ([]ap.Summary, error) {
					waits <- append([]string(nil), ids...)
					<-ctx.Done()
					return nil, ctx.Err()
				}}
				s, store := waiterService(t, 0, client)
				defer release()
				fault := errors.New("commit refused")
				admissionEntered, releaseAdmission := make(chan struct{}), make(chan struct{})
				store.beforeCommit = func(job ap.R2) error {
					if job.SignerAck == "" {
						close(admissionEntered)
						<-releaseAdmission
						if failed == "admission" {
							return fault
						}
					} else if failed == "ack" {
						return fault
					}
					return nil
				}
				if phase == "after_registration" {
					if _, err := s.refreshWaiter(); err != nil {
						t.Fatal(err)
					}
					s.startWaiter()
				}
				type answer struct {
					response executorwire.Response
					err      error
				}
				submitted := make(chan answer, 1)
				go func() {
					response, err := s.SubmitAndNotify(context.Background(), submitRequest(t, 1))
					submitted <- answer{response, err}
				}()
				receiveWait(t, admissionEntered)
				close(releaseAdmission)
				if failed == "admission" {
					got := receiveWait(t, submitted)
					if !errors.Is(got.err, fault) {
						t.Fatal(got.err)
					}
					s.startWaiter()
					s.Close()
					if len(store.jobs) != 0 || len(s.jobNudges) != 0 || len(s.waitJobs) != 0 || len(waits) != 0 {
						t.Fatal("failed admission changed membership")
					}
					return
				}
				receiveWait(t, signerEntered)
				// The admission hook must publish the flag before the signer can ack.
				s.mu.Lock()
				flag := s.jobNudges[st.ID(1)]
				watching := s.waitJobs[st.ID(1)]
				s.mu.Unlock()
				if flag == nil || len(flag) != 1 || watching {
					t.Fatal("admission did not publish exactly a job nudge")
				}
				if phase == "during_registration" {
					registrationEntered, releaseRegistration := make(chan struct{}), make(chan struct{})
					var registrationOnce sync.Once
					s.mu.Lock()
					store.beforeList = func() { registrationOnce.Do(func() { close(registrationEntered); <-releaseRegistration }) }
					s.mu.Unlock()
					s.startWaiter()
					receiveWait(t, registrationEntered)
					release()
					receiveWait(t, signerReturned)
					// The ack answer exists while startup holds the commit lock.
					// The snapshot must finish before the ack commit can publish.
					close(releaseRegistration)
				} else {
					release()
				}
				got := receiveWait(t, submitted)
				if failed == "ack" && !errors.Is(got.err, fault) {
					t.Fatal(got.err)
				}
				if failed == "none" && got.err != nil {
					t.Fatal(got.err)
				}
				if phase == "before_registration" {
					s.startWaiter()
				}

				if failed == "none" {
					ids := receiveWait(t, waits)
					if len(ids) != 1 || ids[0] != st.ID(1) {
						t.Fatal("committed ack not watched", ids)
					}
				}
				s.Close()
				if failed == "ack" && (s.waitJobs[st.ID(1)] || len(waits) != 0 || store.jobs[st.ID(1)].SignerAck != "") {
					t.Fatal("failed ack changed membership")
				}
			})
		}
	}
}

func TestWaiterMembershipDoesNotCancelInFlightPoll(t *testing.T) {
	var mu sync.Mutex
	starts, cancellations := 0, 0
	entered := make(chan []string, 32)
	release := make(chan struct{})
	client := &waitSignerFake{submitSignerFake: submitSignerFake{submit: func(_ context.Context, d ap.ApprovalDraft) (ap.Summary, error) {
		return notificationSummary(d, ap.NotificationSent), nil
	}}, wait: func(ctx context.Context, ids []string, _ time.Duration) ([]ap.Summary, error) {
		mu.Lock()
		starts++
		mu.Unlock()
		entered <- append([]string(nil), ids...)
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			mu.Lock()
			cancellations++
			mu.Unlock()
			return nil, ctx.Err()
		}
	}}
	s, _ := waiterService(t, 1, client)
	s.startWaiter()
	receiveWait(t, entered)
	for id := 2; id <= 21; id++ {
		if _, err := s.SubmitAndNotify(context.Background(), submitRequest(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	drainNudge(s, st.ID(21))
	s.mu.Lock()
	flag := s.jobNudges[st.ID(21)]
	s.mu.Unlock()
	receiveWait(t, flag)
	mu.Lock()
	observedStarts, observedCancels := starts, cancellations
	mu.Unlock()
	if observedStarts != 1 || observedCancels != 0 {
		t.Fatalf("membership replaced pending poll: starts=%d cancellations=%d", observedStarts, observedCancels)
	}
	release <- struct{}{}
	ids := receiveWait(t, entered)
	if len(ids) != 21 {
		t.Fatal("next poll omitted committed jobs", ids)
	}
	s.Close()
}
