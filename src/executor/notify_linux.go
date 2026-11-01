//go:build linux

package executor

import (
	"context"
	"errors"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

const SubmitNotificationTimeout = 65 * time.Second

// SubmitSigner is the approval plane needed before execution starts.
type SubmitSigner interface {
	Submit(context.Context, ap.ApprovalDraft) (ap.Summary, error)
	Get(context.Context, string) (ap.Summary, error)
}

type submitAttempt struct {
	done         chan struct{}
	notification ap.NotificationStatus
	bounded      bool
	err          error
}

// SubmitAndNotify bounds all signer work after the local admission commit.
// A disconnected caller does not cancel the service-owned submission.
// Notification evidence belongs to this attempt: an older acknowledgement
// cannot supply a notification status when every fresh Get fails.
func (s *Service) SubmitAndNotify(ctx context.Context, request executorwire.SubmitRequest) (executorwire.Response, error) {
	var attempt *submitAttempt
	var bound context.Context
	var cancel context.CancelFunc
	ownsAttempt := false
	var pinned string
	defer func() {
		if pinned != "" {
			s.mu.Lock()
			s.submitReaders[pinned]--
			if s.submitReaders[pinned] == 0 {
				delete(s.submitReaders, pinned)
			}
			s.mu.Unlock()
		}
	}()
	job, err := s.submit(request, func(id string) {
		pinned = id
		s.submitReaders[id]++
		bound, cancel = context.WithTimeout(s.effects, s.submitTimeout)
		if s.signer == nil && s.commandSigner == nil {
			return
		}
		attempt = s.submissions[id]
		if attempt == nil && !s.stopping {
			attempt = &submitAttempt{done: make(chan struct{})}
			s.submissions[id] = attempt
			ownsAttempt = true
			go func() {
				defer cancel()
				s.submitNotification(bound, id, attempt)
				s.mu.Lock()
				if attempt.err != nil {
					s.reportFatal(attempt.err)
				}
				attempt.bounded = errors.Is(bound.Err(), context.DeadlineExceeded)
				delete(s.submissions, id)
				close(attempt.done)
				s.mu.Unlock()
			}()
		}
	})
	if err != nil {
		return executorwire.Response{}, err
	}
	if !ownsAttempt {
		defer cancel()
	}
	response := executorwire.Response{ProtoVersion: executorwire.Proto, Kind: executorwire.KindSubmit, OK: true, Job: &job}
	if attempt != nil {
		ticker := time.NewTicker(500 * time.Millisecond)
	wait:
		for {
			select {
			case <-attempt.done:
				break wait
			case <-bound.Done():
				break wait
			case <-ctx.Done():
				break wait
			case <-ticker.C:
				s.mu.Lock()
				notified := notificationComplete(attempt.notification)
				s.mu.Unlock()
				if notified {
					break wait
				}
			}
		}
		ticker.Stop()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if attempt != nil {
		if attempt.err != nil {
			return executorwire.Response{}, attempt.err
		}
		response.NotificationStatus = attempt.notification
		if response.NotificationStatus == ap.NotificationNotStarted && (attempt.bounded || errors.Is(bound.Err(), context.DeadlineExceeded)) {
			response.NotificationStatus = ap.NotificationSending
		}
	}
	committed, err := s.store.Load(job.RequestID)
	if err != nil {
		return executorwire.Response{}, err
	}
	view := executorwire.FromSummary(ap.JobView(committed, s.epoch))
	response.Job = &view
	return response, nil
}

// Close refuses new commits before cancelling and joining signer effects.
func (s *Service) Close() {
	s.mu.Lock()
	s.stopping = true
	s.cancelEffects()
	attempts := make([]*submitAttempt, 0, len(s.submissions))
	for _, attempt := range s.submissions {
		attempts = append(attempts, attempt)
	}
	waiterStarted := s.waiterStarted
	s.mu.Unlock()
	if waiterStarted {
		<-s.waiterDone
	}
	for _, attempt := range attempts {
		<-attempt.done
	}
	s.actorGroup.Wait()
}

func (s *Service) submitNotification(ctx context.Context, id string, attempt *submitAttempt) {
	s.mu.Lock()
	job, loadErr := s.store.Load(id)
	commands := s.commandSigner != nil && loadErr == nil && commandExecutable(job)
	s.mu.Unlock()
	if commands {
		s.observeNotification(ctx, id, attempt)
		return
	}
	if s.signer == nil {
		return
	}
	reconcile := false
	backoff := 250 * time.Millisecond
	for ctx.Err() == nil {
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return
		}
		job, err := s.store.Load(id)
		if err != nil {
			attempt.err = err
			s.mu.Unlock()
			return
		}
		if ap.JobView(job, s.epoch).State == ap.JobFinal && job.SignerAck == "" {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		action := ap.JobAction{Kind: ap.JobActSubmit}
		var summary ap.Summary
		if job.SignerAck != "" || reconcile {
			action.Kind = ap.JobActObserve
			summary, err = s.signer.Get(ctx, id)
		} else {
			summary, err = s.signer.Submit(ctx, job.Draft)
		}
		if ctx.Err() != nil {
			return
		}
		answer := ap.SignerAnswer{Decision: summary.ApprovalStatus, PlanHash: summary.PlanHash}
		if err != nil {
			var wire *approvalwire.WireError
			if errors.Is(err, approvalwire.ErrSignerIncompatible) {
				answer.Code = ap.CodeSignerIncompatible
			} else if errors.As(err, &wire) {
				answer.Code = wire.Code
			} else {
				answer.Lost = true
			}
		} else if summary.RequestID != id || !summary.NotificationStatus.Valid() {
			answer.Code = ap.CodeSignerIncompatible
		}
		// A lost Submit is reconciled before an idempotent resend. Before the ack,
		// not_found means there is no observed record yet, not a lost approval.
		if action.Kind == ap.JobActObserve && job.SignerAck == "" && answer.Code == ap.CodeNotFound {
			reconcile = false
		} else {
			s.mu.Lock()
			if s.stopping || ctx.Err() != nil {
				s.mu.Unlock()
				return
			}
			current, loadErr := s.store.Load(id)
			if loadErr != nil {
				attempt.err = loadErr
				s.mu.Unlock()
				return
			}
			job = current
			if err == nil && answer.Code == "" {
				attempt.observe(summary.NotificationStatus)
				if job.SignerAck == "" {
					action.Kind = ap.JobActSubmit
				}
			}
			if ap.JobView(job, s.epoch).State != ap.JobFinal {
				command, memory := ap.JobOnAnswer(job, ap.JobMemory{}, action, answer)
				if command != nil {
					job, err = s.commitSubmission(job, command)
					if err != nil {
						attempt.err = err
						s.mu.Unlock()
						return
					}
				}
				if action.Kind == ap.JobActSubmit && answer.Code == "" && !answer.Lost && job.SignerAck != "" {
					command, _ = ap.JobOnAnswer(job, memory, ap.JobAction{Kind: ap.JobActObserve}, answer)
					if command != nil {
						job, err = s.commitSubmission(job, command)
						if err != nil {
							attempt.err = err
							s.mu.Unlock()
							return
						}
					}
				}
			}
			final := ap.JobView(job, s.epoch).State == ap.JobFinal
			notified := attempt.notification != "" && attempt.notification != ap.NotificationNotStarted && attempt.notification != ap.NotificationSending
			s.mu.Unlock()
			if final && job.SignerAck == "" || notified {
				return
			}
			if answer.Lost {
				reconcile = true
			}
		}
		delay := backoff
		if err == nil && answer.Code == "" {
			delay = 500 * time.Millisecond
			backoff = 250 * time.Millisecond
		} else if backoff < 2*time.Second {
			backoff *= 2
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Caller holds the same lock used by admission and the owner stop latch.
func (s *Service) commitSubmission(job ap.R2, command ap.JobCommand) (ap.R2, error) {
	next, answer := ap.ApplyJob(job, command, ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}, s.epoch)
	if answer.Refused != "" {
		return job, errors.New("executor: submission transition refused")
	}
	if answer.Changed {
		if err := s.store.Commit(next); err != nil {
			return job, err
		}
		s.jobCommittedLocked(next)
	}
	return next, nil
}

// The command actor alone owns signer transitions once execution is enabled.
func (s *Service) observeNotification(ctx context.Context, id string, attempt *submitAttempt) {
	for ctx.Err() == nil {
		s.mu.Lock()
		status := attempt.notification
		s.mu.Unlock()
		if status != "" && status != ap.NotificationNotStarted && status != ap.NotificationSending {
			return
		}
		summary, err := s.commandSigner.Get(ctx, id)
		s.mu.Lock()
		if s.stopping || ctx.Err() != nil {
			s.mu.Unlock()
			return
		}
		if err == nil && summary.RequestID == id && summary.NotificationStatus.Valid() {
			attempt.observe(summary.NotificationStatus)
		}
		job, loadErr := s.store.Load(id)
		if loadErr != nil {
			attempt.err = loadErr
			s.mu.Unlock()
			return
		}
		done := ap.JobView(job, s.epoch).State == ap.JobFinal && job.SignerAck == "" || attempt.notification != "" && attempt.notification != ap.NotificationNotStarted && attempt.notification != ap.NotificationSending
		s.mu.Unlock()
		if done {
			return
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func notificationComplete(status ap.NotificationStatus) bool {
	return status != "" && status != ap.NotificationNotStarted && status != ap.NotificationSending
}

// E63 ends at the first complete observation. An older in-flight response
// cannot erase that evidence after another call has observed completion.
func (a *submitAttempt) observe(status ap.NotificationStatus) {
	if !notificationComplete(a.notification) {
		a.notification = status
	}
}
