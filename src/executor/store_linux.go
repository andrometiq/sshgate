//go:build linux

package executor

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"golang.org/x/sys/unix"
)

var ErrReportAuthLost = errors.New("report_auth_lost")

// JobFile describes a committed file, including a quarantined file whose
// request ID cannot be trusted. Quarantine never changes the file on disk.
type JobFile struct {
	Key          string
	RequestID    string // Empty for quarantined files.
	EncodedBytes int64
	Quarantined  bool
}

type storedJob struct {
	JobFile
	body []byte
}

// JobStore owns the write-through snapshot of the locked job directory.
// Callers serialize read/transition/commit operations at the executor level.
// Close it before Local. An uncertain mutation poisons it until process exit.
type JobStore struct {
	mu       sync.RWMutex
	disk     *securestate.Store
	files    map[string]storedJob
	poisoned bool
	closed   bool
	// update is a failure-injection seam; production uses disk.Update.
	update func(func(*securestate.Transaction) error) error
}

// OpenJobStore removes orphan temps, then validates all files in one View.
// Only content failures are quarantined; unsafe objects refuse startup.
func (l *Local) OpenJobStore() (*JobStore, error) {
	disk, err := l.OpenStore()
	if err != nil {
		return nil, err
	}
	s := &JobStore{disk: disk, files: make(map[string]storedJob), update: disk.Update}
	err = disk.Update(func(tx *securestate.Transaction) error {
		_, err := tx.RemoveOrphanTemps()
		return err
	})
	if err == nil {
		err = disk.View(func(tx *securestate.Transaction) error {
			names, err := tx.ListNames(approvalplan.ExecutorJobFiles)
			if err != nil {
				return err
			}
			for _, name := range names {
				if !validJobKey(name) {
					return fmt.Errorf("executor: unexpected job entry %q", name)
				}
				var stat unix.Stat_t
				if err := unix.Fstatat(int(l.directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				body, err := tx.ReadFile(name, approvalplan.R2Max)
				if err != nil && !errors.Is(err, securestate.ErrTooLarge) {
					return err
				}
				entry := storedJob{JobFile: JobFile{Key: name, EncodedBytes: stat.Size}}
				if err == nil {
					job, decodeErr := approvalplan.DecodeR2(body)
					if decodeErr == nil && validateStoredJob(job) == nil && approvalplan.JobKey(job.RequestID) == name {
						entry.body = body
						entry.RequestID = job.RequestID
						entry.EncodedBytes = int64(len(body))
					}
				}
				entry.Quarantined = entry.body == nil
				s.files[name] = entry
			}
			return nil
		})
	}
	if err != nil {
		disk.Close()
		return nil, err
	}
	return s, nil
}

func validJobKey(key string) bool {
	if !strings.HasPrefix(key, "j-") {
		return false
	}
	encoding := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	digest, err := encoding.DecodeString(key[2:])
	return err == nil && len(digest) == 32 && encoding.EncodeToString(digest) == key[2:]
}

func (s *JobStore) available() error {
	if s.poisoned {
		return securestate.ErrCommitUncertain
	}
	if s.closed {
		return securestate.ErrClosed
	}
	return nil
}

// Load returns an independent record. Missing and quarantined keys remain
// distinct, so callers cannot submit over a damaged job.
func (s *JobStore) Load(requestID string) (approvalplan.R2, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return approvalplan.R2{}, err
	}
	entry, ok := s.files[approvalplan.JobKey(requestID)]
	if !ok {
		return approvalplan.R2{}, securestate.ErrNotFound
	}
	if entry.Quarantined {
		return approvalplan.R2{}, ErrReportAuthLost
	}
	return approvalplan.DecodeR2(entry.body)
}

// List returns metadata sorted by storage key, without disk reads or writes.
func (s *JobStore) List() ([]JobFile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	files := make([]JobFile, 0, len(s.files))
	for _, entry := range s.files {
		files = append(files, entry.JobFile)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Key < files[j].Key })
	return files, nil
}

// Commit validates schema, authority, lifecycle and result consistency before replacing
// one R2. The caller owns admission and applies approvalplan transitions first.
func (s *JobStore) Commit(job approvalplan.R2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	key := approvalplan.JobKey(job.RequestID)
	if s.files[key].Quarantined {
		return ErrReportAuthLost
	}
	if err := validateStoredJob(job); err != nil {
		return err
	}
	body, err := approvalplan.EncodeR2(job)
	if err != nil {
		return err
	}
	err = s.update(func(tx *securestate.Transaction) error { return tx.WriteFile(key, body, approvalplan.R2Max) })
	if err != nil {
		return s.mutationError(err)
	}
	s.files[key] = storedJob{JobFile: JobFile{Key: key, RequestID: job.RequestID, EncodedBytes: int64(len(body))}, body: body}
	return nil
}

// Remove deletes a job only after the caller has checked retention eligibility.
func (s *JobStore) Remove(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	key := approvalplan.JobKey(requestID)
	entry, ok := s.files[key]
	if !ok {
		return securestate.ErrNotFound
	}
	if entry.Quarantined {
		return ErrReportAuthLost
	}
	if err := s.update(func(tx *securestate.Transaction) error { return tx.Remove(key) }); err != nil {
		return s.mutationError(err)
	}
	delete(s.files, key)
	return nil
}

func (s *JobStore) mutationError(err error) error {
	if errors.Is(err, securestate.ErrCommitUncertain) {
		s.poisoned = true
		s.files = nil
	}
	return err
}

func (s *JobStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.files = nil
	return s.disk.Close()
}

func validateStoredJob(job approvalplan.R2) error {
	// SA-3/SA-5: results form one prefix, followed by at most one
	// in-flight marker. A terminal result forbids all later evidence.
	closed, ended, hadBodies, hasBodies := false, false, false, false
	for i, step := range job.Steps {
		if closed && (step.Marker != nil || step.Result != nil) {
			return ErrReportAuthLost
		}
		if (step.Marker != nil || step.Result != nil) && job.SignerAck == "" {
			return ErrReportAuthLost
		}
		r := step.Result
		if r == nil {
			closed = true
			if step.Marker != nil && job.Outcome != nil && job.Outcome.Kind != approvalplan.OutcomeJobError {
				return ErrReportAuthLost
			}
			continue
		}
		route := approvalplan.Route("")
		if command := job.Draft.CommandJob; command != nil && i < len(command.Steps) {
			route = command.Steps[i].Route
		}
		if err := validateStepResult(*r, route); err != nil {
			return err
		}
		switch r.Status {
		case approvalplan.StepSucceeded, approvalplan.StepFailed, approvalplan.StepIndeterminate:
			if step.Marker == nil {
				return ErrReportAuthLost
			}
		case approvalplan.StepFailedNotStarted, approvalplan.StepExpiredUnexecuted, approvalplan.StepStaleTarget:
		default: // skipped and not_run are derived, never stored results.
			return ErrReportAuthLost
		}
		hasBodies = hasBodies || len(r.Stdout)+len(r.Stderr) > 0
		hadBodies = hadBodies || !r.BodiesUnstorable && (r.StdoutBytes > 0 || r.StderrBytes > 0)
		stop := true
		if command := job.Draft.CommandJob; command != nil && i < len(command.Steps) {
			stopSigned := command.StopPolicy != approvalplan.StopNever && command.Steps[i].Route.Signed()
			stop = command.StopPolicy == approvalplan.StopAnyNonzero || stopSigned
		}
		failedStop := r.Status == approvalplan.StepFailed && stop
		ended = r.Status.Abort() || failedStop || i == len(job.Steps)-1
		closed = ended
	}
	if outcome := job.Outcome; outcome != nil {
		lostAfterAck := outcome.Kind == approvalplan.OutcomeApprovalLost && job.SignerAck != ""
		missingAck := outcome.Kind != approvalplan.OutcomeApprovalLost && outcome.Kind != approvalplan.OutcomeJobError && job.SignerAck == ""
		if ended || lostAfterAck || missingAck {
			return ErrReportAuthLost
		}
	}
	final := ended || job.Outcome != nil
	hasFinalEvidence := job.ReportResult != nil || job.FirstDeliveredAt != nil || job.BodiesRemoved != nil
	hasOutcomeReport := job.Outcome != nil && job.ReportResult != nil
	if !final && hasFinalEvidence || hasOutcomeReport {
		return ErrReportAuthLost
	}
	if removed := job.BodiesRemoved; removed != nil {
		unknownCause := removed.Cause != approvalplan.BodiesRemovedAge && removed.Cause != approvalplan.BodiesRemovedBudget
		pressureBeforeDelivery := removed.Cause == approvalplan.BodiesRemovedBudget && job.FirstDeliveredAt == nil
		if hasBodies || !hadBodies || unknownCause || pressureBeforeDelivery {
			return ErrReportAuthLost
		}
	}
	if final != (job.FinalAt != nil) {
		return ErrReportAuthLost
	}
	if job.ClaimToken == "" {
		if !final || job.Outcome == nil && job.ReportResult == nil {
			return ErrReportAuthLost
		}
		if hasBodies {
			return ErrReportAuthLost
		}
		return nil
	}
	raw, err := hex.DecodeString(job.ClaimToken)
	if err != nil || len(raw) != 32 {
		return ErrReportAuthLost
	}
	var token [32]byte
	copy(token[:], raw)
	if approvalplan.ClaimTokenHash(token) != job.Draft.ExecutorClaimTokenHash {
		return ErrReportAuthLost
	}
	return nil
}

// validateStepResult accepts only exit-code shapes produced by jobplan's runner
// or approvalplan.NoOutputResult during recovery and pre-dispatch refusal.
func validateStepResult(result approvalplan.StepResult, route approvalplan.Route) error {
	exit := result.ExitCode
	allowed := map[approvalplan.StepStatus]bool{
		approvalplan.StepSucceeded:         exit != nil && *exit == 0,
		approvalplan.StepFailed:            exit != nil && *exit > 0,
		approvalplan.StepFailedNotStarted:  exit == nil || route == approvalplan.RouteUnsignedRead && *exit == 77,
		approvalplan.StepIndeterminate:     exit == nil,
		approvalplan.StepExpiredUnexecuted: exit == nil,
		approvalplan.StepStaleTarget:       exit == nil,
	}
	if !allowed[result.Status] {
		return ErrReportAuthLost
	}
	return nil
}
