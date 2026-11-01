//go:build linux

package executor

import (
	"context"
	"sort"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// WaitSigner is the client's WaitMany operation (called Wait on the wire client).
// Replies are wakeups only; the job actor owns observation and transitions.
type WaitSigner interface {
	Wait(context.Context, []string, time.Duration) ([]ap.Summary, error)
}

// Caller holds mu. A buffered channel is the actor's coalescing pending flag;
// nudging never runs JobNext or starts a second actor.
func (s *Service) nudgeLocked(id string) {
	if s.stopping {
		return
	}
	flag := s.jobNudges[id]
	if flag == nil {
		flag = make(chan struct{}, 1)
		s.jobNudges[id] = flag
	}
	s.startCommandActorLocked(id, flag)
	select {
	case flag <- struct{}{}:
	default:
	}
}

func (s *Service) jobCommittedLocked(job ap.R2) {
	if actor := s.actors[job.RequestID]; actor != nil {
		actor.job = &job
	}
	s.projectJobLocked(job)
	select {
	case s.waiterWake <- struct{}{}:
	default:
	}
}

func (s *Service) startWaiter() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waitSigner == nil || s.stopping || s.waiterStarted {
		return
	}
	s.waiterStarted = true
	go s.waiter(s.waitSigner)
}

// projectJobLocked is updated only from committed records. Final jobs with a
// report outstanding still need nudges, but no longer need approval watches.
func (s *Service) projectJobLocked(job ap.R2) {
	id := job.RequestID
	s.projectRetentionLocked(job)
	delete(s.waitJobs, id)
	if !commandExecutable(job) {
		delete(s.jobNudges, id)
		return
	}
	final := ap.JobView(job, s.epoch).State == ap.JobFinal
	if final && ap.JobNext(job, ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}, s.epoch, ap.JobMemory{}).Kind == ap.JobActNone {
		delete(s.jobNudges, id)
		return
	}
	s.nudgeLocked(id)
	if !final && job.SignerAck != "" {
		s.waitJobs[id] = true
	}
}

// Decode retained output once at startup, never on ticks or commit wakeups.
// All later commit paths must call jobCommittedLocked with the committed R2.
func (s *Service) refreshWaiter() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return nil, nil
	}
	if !s.waiterInitialized {
		files, err := s.store.List()
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if file.Quarantined {
				continue
			}
			job, err := s.store.Load(file.RequestID)
			if err != nil {
				return nil, err
			}
			s.projectJobLocked(job)
		}
		s.waiterInitialized = true
	}
	for id := range s.jobNudges {
		s.nudgeLocked(id)
	}
	ids := make([]string, 0, len(s.waitJobs))
	for id := range s.waitJobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// A peer disconnect does not cancel the signer's WaitMany. Keep one poll
// until it answers; membership changes apply to the next poll. Ticks still
// nudge every active job, including newly admitted jobs not in that poll.
func (s *Service) waiter(signer WaitSigner) {
	defer close(s.waiterDone)
	ctx, cancel := context.WithCancel(s.effects)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(0)
	defer timer.Stop()
	answers := make(chan error, 1)
	inFlight := false
	defer func() {
		cancel()
		if inFlight {
			<-answers
		}
	}()
	ready := false
	lastID := ""
	backoff := 250 * time.Millisecond
	for {
		ids, err := s.refreshWaiter()
		if err != nil {
			s.reportFatal(err)
			return
		}
		if !inFlight && ready && len(ids) != 0 {
			// Rotate if a recovered store contains more than one batch.
			start := 0
			if len(ids) > ap.AwaitMaxIDs {
				start = sort.SearchStrings(ids, lastID)
				if start < len(ids) && ids[start] == lastID {
					start++
				}
				if start == len(ids) {
					start = 0
				}
			}
			batch := ids[start:min(start+ap.AwaitMaxIDs, len(ids))]
			lastID = batch[len(batch)-1]
			inFlight = true
			go func() { answers <- s.waitBatch(ctx, signer, batch) }()
		}
		select {
		case <-s.effects.Done():
			return
		case <-s.waiterWake:
		case <-ticker.C:
		case <-timer.C:
			ready = true
		case err := <-answers:
			inFlight = false
			ready = false
			if err == nil {
				backoff = 250 * time.Millisecond
			}
			timer.Reset(backoff)
			if err != nil {
				backoff = min(2*time.Second, backoff*2)
			}
		}
	}
}

func (s *Service) waitBatch(ctx context.Context, signer WaitSigner, ids []string) error {
	// Leave the client's response grace after the server-side poll expires.
	call, cancel := context.WithTimeout(ctx, ap.AwaitMaxWait+sign.ApprovalWaitGrace)
	defer cancel()
	_, err := signer.Wait(call, ids, ap.AwaitMaxWait)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Replies only wake existing actors. Get remains the authoritative observation.
	for _, id := range ids {
		if s.jobNudges[id] != nil {
			s.nudgeLocked(id)
		}
	}
	return err
}
