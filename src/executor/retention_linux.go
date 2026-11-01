//go:build linux

package executor

import (
	"sort"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// retainLocked shares admission's lock with Get and every transition. An actor
// or submission pins its file until its in-flight effects have returned.
func (s *Service) retainLocked(reservation int64) error {
	if s.stopping {
		return refusal("executor_unavailable")
	}
	files, err := s.store.List()
	if err != nil {
		return err
	}
	jobs := make([]ap.R2, 0, len(files))
	var used int64
	for _, file := range files {
		if file.Quarantined {
			used += file.EncodedBytes
			continue
		}
		job, err := s.store.Load(file.RequestID)
		if err != nil {
			return err
		}
		charge := job.Reservation
		if job.FinalAt != nil {
			charge, err = R2FinalCharge(job)
			if err != nil {
				return err
			}
			jobs = append(jobs, job)
		}
		used += charge
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].FinalAt.Equal(*jobs[j].FinalAt) {
			return jobs[i].RequestID < jobs[j].RequestID
		}
		return jobs[i].FinalAt.Before(*jobs[j].FinalAt)
	})
	count := len(files)
	for _, job := range jobs {
		before, err := R2FinalCharge(job)
		if err != nil {
			return err
		}
		job, removed, err := s.retainJobLocked(job, reservation > 0 && used+reservation > s.budgetLimit, reservation > 0 && count >= s.jobFileLimit)
		if err != nil {
			return err
		}
		if removed {
			count--
			used -= before
			continue
		}
		after, err := R2FinalCharge(job)
		if err != nil {
			return err
		}
		used += after - before
	}
	return nil
}

func (s *Service) retentionLoop() {
	defer s.actorGroup.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.effects.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.stopping {
				s.mu.Unlock()
				return
			}
			var err error
			now := s.clock.Wall()
			for _, due := range s.retentionDue {
				if !now.Before(due) {
					err = s.retainDueLocked()
					break
				}
			}
			s.mu.Unlock()
			if err != nil {
				s.reportFatal(err)
				return
			}
		}
	}
}

// This projection schedules age work; the pure predicates are checked again
// against the committed record before any mutation.
func (s *Service) projectRetentionLocked(job ap.R2) {
	delete(s.retentionDue, job.RequestID)
	if job.FinalAt == nil {
		return
	}
	now := ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}
	if ap.JobRetention(job, now, false) != nil {
		s.retentionDue[job.RequestID] = now.Wall
		return
	}
	for _, step := range job.Steps {
		if step.Result != nil && len(step.Result.Stdout)+len(step.Result.Stderr) > 0 {
			s.retentionDue[job.RequestID] = job.FinalAt.Add(ap.BodyRetention)
			return
		}
	}
	if job.ReportResult == nil && job.Outcome == nil {
		return
	}
	due := job.FinalAt.Add(ap.JobFileRetention)
	if floor := job.Draft.SubmitNotAfter.Add(ap.DeleteFloor); floor.After(due) {
		due = floor
	}
	s.retentionDue[job.RequestID] = due
}

func (s *Service) retainDueLocked() error {
	now := s.clock.Wall()
	for id, due := range s.retentionDue {
		if now.Before(due) {
			continue
		}
		job, err := s.store.Load(id)
		if err != nil {
			return err
		}
		if _, _, err = s.retainJobLocked(job, false, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) retainJobLocked(job ap.R2, bodyPressure, countPressure bool) (ap.R2, bool, error) {
	for {
		now := ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}
		command := ap.JobRetention(job, now, bodyPressure)
		if command == nil {
			break
		}
		next, answer := ap.ApplyJob(job, command, now, s.epoch)
		if answer.Refused != "" || !answer.Changed {
			return job, false, ErrReportAuthLost
		}
		if err := s.store.Commit(next); err != nil {
			return job, false, err
		}
		job = next
		s.jobCommittedLocked(job)
	}
	s.projectRetentionLocked(job)
	if s.actors[job.RequestID] != nil || s.submissions[job.RequestID] != nil || s.submitReaders[job.RequestID] > 0 {
		return job, false, nil
	}
	now := ap.Now{Wall: s.clock.Wall(), Elapsed: s.clock.Elapsed()}
	if !ap.JobDeletable(job, now, countPressure) {
		return job, false, nil
	}
	if err := s.store.Remove(job.RequestID); err != nil {
		return job, false, err
	}
	delete(s.retentionDue, job.RequestID)
	delete(s.deliveries, job.RequestID)
	delete(s.jobNudges, job.RequestID)
	delete(s.waitJobs, job.RequestID)
	return job, true, nil
}
