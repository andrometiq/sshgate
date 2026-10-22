//go:build linux

package executor

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/mcp/jobplan"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// CommandSigner is the command actor's approval plane. Signature bytes are
// held only by the actor and are never passed to the job store.
type CommandSigner interface {
	SubmitSigner
	Claim(context.Context, string, string, [32]byte) (approvalwire.ClaimAnswer, error)
	Report(context.Context, string, string, [32]byte, approvalwire.Report) error
}

// StartCommandJobs enables recovery and execution of run/run_batch drafts.
// Production wiring remains gated on the executor intake scope decision.
func (s *Service) StartCommandJobs(signer CommandSigner, ssh jobplan.PhasedRunner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if signer == nil || ssh == nil || s.stopping || s.commandSigner != nil || len(s.submissions) != 0 {
		return errors.New("executor: cannot start command workers")
	}
	files, err := s.store.List()
	if err != nil {
		return err
	}
	var jobs []ap.R2
	for _, file := range files {
		if file.Quarantined {
			continue
		}
		job, err := s.store.Load(file.RequestID)
		if err != nil {
			return err
		}
		jobs = append(jobs, job)
	}
	s.commandSigner, s.commandSSH = signer, ssh
	for _, job := range jobs {
		s.projectJobLocked(job)
	}
	return nil
}

func commandExecutable(job ap.R2) bool {
	if job.Draft.CommandJob == nil {
		return false
	}
	for _, step := range job.Draft.CommandJob.Steps {
		switch step.Route {
		case ap.RouteUnsignedRead, ap.RouteSignedWrite, ap.RouteSignedReveal:
		default:
			return false
		}
	}
	return true
}

type commandActor struct {
	service    *Service
	id         string
	memory     ap.JobMemory
	runner     *jobplan.Runner
	signatures map[int]string
	ordinal    int
	lastSigned int
	journalErr error
	reconcile  bool
}

// Caller holds mu. Actor lifetime is separate from the coalesced nudge flag.
func (s *Service) startCommandActorLocked(id string, flag chan struct{}) {
	if s.commandSigner == nil || s.actors[id] {
		return
	}
	s.actors[id] = true
	s.actorGroup.Add(1)
	go func() {
		defer s.actorGroup.Done()
		actor := commandActor{service: s, id: id}
		defer func() {
			if actor.runner != nil {
				actor.runner.Close()
			}
			clear(actor.signatures)
		}()
		backoff := 250 * time.Millisecond
		for {
			select {
			case <-s.effects.Done():
				return
			case <-flag:
			}
			for {
				progress, done, err := actor.next()
				if err != nil {
					if s.effects.Err() == nil {
						s.reportFatal(err)
					}
					return
				}
				if done {
					s.mu.Lock()
					delete(s.actors, id)
					if s.deliveries[id] {
						s.nudgeLocked(id)
					}
					s.mu.Unlock()
					return
				}
				if progress {
					backoff = 250 * time.Millisecond
					continue
				}
				// Nudges never bypass a transient-answer backoff.
				if !commandBackoff(s.effects, backoff) {
					return
				}
				backoff = min(2*time.Second, backoff*2)
			}
		}
	}()
}

func (a *commandActor) next() (bool, bool, error) {
	s := a.service
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return false, true, nil
	}
	job, err := s.store.Load(a.id)
	a.memory.Delivered = s.deliveries[a.id]
	s.mu.Unlock()
	if err != nil {
		return false, false, err
	}
	if !commandExecutable(job) {
		return false, true, nil
	}
	if ap.JobView(job, s.epoch).State == ap.JobFinal {
		clear(a.signatures)
		clear(a.memory.Held)
		if a.runner != nil {
			a.runner.Close()
		}
	}
	action := ap.JobNext(job, ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}, s.epoch, a.memory)
	if action.Kind == ap.JobActSubmit && a.reconcile {
		action.Kind = ap.JobActObserve
	}
	switch action.Kind {
	case ap.JobActNone:
		return false, ap.JobView(job, s.epoch).State == ap.JobFinal, nil
	case ap.JobActCommit:
		err = a.commit(action.Commit)
	case ap.JobActCheck:
		step := job.Draft.CommandJob.Steps[action.Step-1]
		target, digest, readErr := s.servers.ReadCurrent(step.Target.ServerAlias)
		var cmd ap.JobCommand
		cmd, a.memory = ap.JobOnCheck(a.memory, action.Step, readErr == nil && ap.ValidateRouteSnapshot(target) == nil && digest == step.RegistryEntryDigest && target.Digest() == digest)
		if cmd != nil {
			err = a.commit(cmd)
		}
	case ap.JobActDispatch:
		err = a.dispatch(job, action)
	default:
		return a.call(job, action)
	}
	return true, false, err
}

func (a *commandActor) call(job ap.R2, action ap.JobAction) (bool, bool, error) {
	s := a.service
	ctx, cancel := commandCallContext(s.effects)
	defer cancel()
	answer := ap.SignerAnswer{SentAt: ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}}
	var err error
	var claim approvalwire.ClaimAnswer
	var notification ap.NotificationStatus
	switch action.Kind {
	case ap.JobActSubmit, ap.JobActObserve:
		var summary ap.Summary
		if action.Kind == ap.JobActSubmit {
			summary, err = s.commandSigner.Submit(ctx, job.Draft)
		} else {
			summary, err = s.commandSigner.Get(ctx, job.RequestID)
		}
		answer.Decision, answer.PlanHash = summary.ApprovalStatus, summary.PlanHash
		if err == nil && summary.RequestID == job.RequestID && summary.NotificationStatus.Valid() {
			notification = summary.NotificationStatus
		}
		if err == nil && summary.RequestID != job.RequestID {
			answer.Code = ap.CodeSignerIncompatible
		}
	case ap.JobActClaim, ap.JobActReport:
		raw, decodeErr := hex.DecodeString(job.ClaimToken)
		if decodeErr != nil || len(raw) != 32 {
			return false, false, ErrReportAuthLost
		}
		var token [32]byte
		copy(token[:], raw)
		if action.Kind == ap.JobActClaim {
			claim, err = s.commandSigner.Claim(ctx, job.RequestID, job.SignerAck, token)
			answer.Claim, answer.Class = claim.Status, claim.Class
			if err == nil && claim.Status == ap.ClaimSignatures {
				if !a.acceptSignatures(job, claim, &answer) {
					answer.Code = ap.CodeSignerIncompatible
				}
			}
		} else {
			r := action.Report
			err = s.commandSigner.Report(ctx, job.RequestID, job.SignerAck, token, approvalwire.Report{ReportSequence: approvalwire.ReportSequence, Steps: r.Steps, Class: r.Class, ExecutedOrdinals: r.ExecutedOrdinals, Partial: r.Partial, ResultDigest: r.ResultDigest})
		}
	}
	if s.effects.Err() != nil {
		return false, true, nil
	}
	if err != nil {
		var wire *approvalwire.WireError
		if errors.Is(err, approvalwire.ErrSignerIncompatible) {
			answer.Code = ap.CodeSignerIncompatible
		} else if errors.As(err, &wire) {
			answer.Code = wire.Code
		} else {
			answer.Lost = true
		}
	}
	reconciled := action.Kind == ap.JobActObserve && job.SignerAck == ""
	if reconciled && answer.Code == ap.CodeNotFound && !answer.Lost {
		a.reconcile = false
		return false, false, nil
	}
	if action.Kind == ap.JobActSubmit && answer.Lost {
		a.reconcile = true
	}
	if reconciled && answer.Code == "" && !answer.Lost {
		action.Kind = ap.JobActSubmit
		a.reconcile = false
	}
	command, mem := ap.JobOnAnswer(job, a.memory, action, answer)
	a.memory = mem
	if command != nil {
		if err := a.commit(command); err != nil {
			return false, false, err
		}
		if action.Kind == ap.JobActSubmit && answer.Code == "" && !answer.Lost {
			job.SignerAck = answer.PlanHash
			observation, memory := ap.JobOnAnswer(job, a.memory, ap.JobAction{Kind: ap.JobActObserve}, answer)
			a.memory = memory
			if observation != nil {
				if err := a.commit(observation); err != nil {
					return false, false, err
				}
			}
		}
		a.publishNotification(notification)
		return true, false, nil
	}
	a.publishNotification(notification)
	if action.Kind == ap.JobActClaim && answer.Code == "" && !answer.Lost && answer.Claim == ap.ClaimSignatures {
		if err := a.ensureRunner(job); err != nil {
			return false, false, err
		}
		if err := a.runner.HoldWindows(answer.SentAt, answer.Windows); err != nil {
			return false, false, err
		}
		return true, false, nil
	}
	return action.Kind == ap.JobActObserve && answer.Code == "" && !answer.Lost && answer.Decision == ap.ApprovalApproved, false, nil
}

// Match every envelope to its frozen step, including its authority window.
// The remote gate owns cryptographic verification.
func (a *commandActor) acceptSignatures(job ap.R2, claim approvalwire.ClaimAnswer, answer *ap.SignerAnswer) bool {
	if claim.DecidedAt == nil {
		return false
	}
	answer.DecidedAt = *claim.DecidedAt
	answer.Windows = make([]time.Time, len(job.Steps))
	signatures := make(map[int]string)
	i := 0
	for _, step := range job.Draft.CommandJob.Steps {
		if !step.Route.Signed() {
			continue
		}
		if i >= len(claim.Signatures) {
			return false
		}
		wire := claim.Signatures[i]
		signature, payload, err := sigwire.DecodeSigned(wire)
		end := time.Unix(claim.DecidedAt.Unix()+int64(step.SignatureTTLSeconds), 0).UTC()
		if err != nil || len(signature) != 64 || payload.Net || payload.Cmd != step.ExactCommand || payload.Host != step.Target.TrustedHostFingerprint || payload.Reveal != (step.Route == ap.RouteSignedReveal) || payload.TS != claim.DecidedAt.Unix() || payload.Exp != end.Unix() {
			return false
		}
		signatures[step.Ordinal] = wire
		answer.Windows[step.Ordinal-1] = end
		i++
	}
	if i != len(claim.Signatures) {
		return false
	}
	clear(a.signatures)
	a.signatures = signatures
	return true
}

func (a *commandActor) ensureRunner(job ap.R2) error {
	if a.runner != nil {
		return nil
	}
	var retained int64
	for _, step := range job.Steps {
		if step.Result != nil {
			retained += int64(len(step.Result.Stdout) + len(step.Result.Stderr))
		}
	}
	var err error
	for _, step := range job.Draft.CommandJob.Steps {
		if step.Route.Signed() {
			a.lastSigned = step.Ordinal
		}
	}
	a.runner, err = jobplan.NewRunner(job.Draft, a, a.service.servers, a.service.clock, retained)
	return err
}

func (a *commandActor) dispatch(job ap.R2, action ap.JobAction) error {
	if err := a.ensureRunner(job); err != nil {
		return err
	}
	a.ordinal = action.Step
	dispatch := jobplan.Dispatch{WireCommand: a.signatures[action.Step]}
	_, err := a.runner.RunStep(a.service.effects, action.Step, dispatch, len(ap.JobView(job, a.service.epoch).ExecutedOrdinals) > 0, a)
	// Runner drops its held windows at the last signed Start. Do not retain the
	// corresponding wire authority across an unsigned tail or a failed dispatch.
	lastSigned := 0
	for _, step := range job.Draft.CommandJob.Steps {
		if step.Route.Signed() {
			lastSigned = step.Ordinal
		}
	}
	if action.Step >= lastSigned || err != nil {
		clear(a.signatures)
		clear(a.memory.Held)
	}
	if a.journalErr != nil {
		return a.journalErr
	}
	return err
}

func (a *commandActor) BeforeStep(ordinal int) error {
	a.journalErr = a.commit(ap.MarkStep{Ordinal: ordinal})
	return a.journalErr
}
func (a *commandActor) AfterStep(ordinal int, result ap.StepResult) error {
	err := a.commit(ap.RecordResult{Ordinal: ordinal, Result: result})
	if errors.Is(err, securestate.ErrTooLarge) {
		result.Stdout, result.Stderr = nil, nil
		result.BodiesUnstorable = true
		err = a.commit(ap.RecordResult{Ordinal: ordinal, Result: result})
	}
	a.journalErr = err
	return err
}

func (a *commandActor) commit(command ap.JobCommand) error {
	s := a.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return refusal("executor_unavailable")
	}
	job, err := s.store.Load(a.id)
	if err != nil {
		return err
	}
	next, answer := ap.ApplyJob(job, command, ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}, s.epoch)
	if answer.Refused != "" || answer.AlreadyMarked {
		return errors.New("executor: job transition refused")
	}
	if !answer.Changed {
		return nil
	}
	if err := s.store.Commit(next); err != nil {
		return err
	}
	if _, ok := command.(ap.MarkDelivered); ok {
		delete(s.deliveries, a.id)
	}
	s.jobCommittedLocked(next)
	return nil
}

// RunPhasedTo releases the envelope set at the same pre-Start point as the
// runner's held windows, rather than keeping it through a long final command.
func (a *commandActor) RunPhasedTo(ctx context.Context, host, user string, port int, wire string, stdin io.Reader, guard func() error, stdout, stderr io.Writer) (int, error) {
	preStart := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if guard != nil {
			if err := guard(); err != nil {
				clear(a.signatures)
				clear(a.memory.Held)
				return err
			}
		}
		if a.ordinal == a.lastSigned {
			clear(a.signatures)
			clear(a.memory.Held)
		}
		return nil
	}
	return a.service.commandSSH.RunPhasedTo(ctx, host, user, port, wire, stdin, preStart, stdout, stderr)
}

// Delivery is queued only after the response write succeeds; Await itself
// remains a read. JobNext commits the timestamp independently of the caller.
func (s *Service) delivered(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping || s.commandSigner == nil {
		return
	}
	for _, id := range ids {
		job, err := s.store.Load(id)
		if err != nil {
			s.reportFatal(err)
			continue
		}
		if !commandExecutable(job) || job.FirstDeliveredAt != nil {
			continue
		}
		s.deliveries[id] = true
		s.nudgeLocked(id)
	}
}

// Timers schedule effects; they never judge an authority window.
func commandBackoff(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func commandCallContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, SubmitNotificationTimeout)
}

func (a *commandActor) publishNotification(status ap.NotificationStatus) {
	if !status.Valid() {
		return
	}
	s := a.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if attempt := s.submissions[a.id]; attempt != nil && !s.stopping {
		attempt.observe(status)
	}
}
