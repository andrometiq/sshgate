//go:build linux

package executor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

// Store is the committed job state. All mutations must share Service's lock.
type Store interface {
	Load(string) (ap.R2, error)
	List() ([]JobFile, error)
	Commit(ap.R2) error
}

type Config struct {
	Store          Store
	Servers        *registry.Servers
	Clock          elapsed.Clock
	StagedGatePath string
}

// Service serializes admission with job commits. C2's job transitions must use
// this same critical section so released reservations cannot race admission.
type Service struct {
	mu               sync.Mutex
	store            Store
	servers          *registry.Servers
	clock            elapsed.Clock
	stagedGatePath   string
	epoch            string
	reservationLimit int64 // Test seam; production uses R2Max.
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || config.Servers == nil {
		return nil, errors.New("executor: store and registry are required")
	}
	if config.Clock == nil {
		config.Clock = elapsed.Real()
	}
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, err
	}
	return &Service{store: config.Store, servers: config.Servers, clock: config.Clock,
		stagedGatePath: config.StagedGatePath, epoch: hex.EncodeToString(epoch[:]), reservationLimit: ap.R2Max}, nil
}

// Submit returns only public job facts, and only after the durable commit.
// Commit errors, particularly ErrCommitUncertain, remain errors for the owner
// to handle; they must never be turned into an ordinary retryable refusal.
func (s *Service) Submit(request executorwire.SubmitRequest) (executorwire.Job, error) {
	if _, err := executorwire.MarshalRequest(request); err != nil {
		return executorwire.Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in := request.Input
	job, err := s.store.Load(in.RequestID)
	if err == nil {
		if job.InputHash != request.InputHash {
			return executorwire.Job{}, refusal("conflict")
		}
		return executorwire.FromSummary(ap.JobView(job, s.epoch)), nil
	}
	if !errors.Is(err, securestate.ErrNotFound) {
		return executorwire.Job{}, err
	}
	now := s.clock.Wall()
	// Check the caller's window before registry I/O or capacity admission.
	window := ap.ApprovalDraft{SubmitNotAfter: in.SubmitNotAfter}
	if code := ap.ExecSubmitAdmit(now, window, 0); code != "" {
		return executorwire.Job{}, refusal(string(code))
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return executorwire.Job{}, err
	}
	// The exact encoded reservation includes the current registry snapshot.
	draft, err := s.buildDraft(in, ap.ClaimTokenHash(token))
	if err != nil {
		return executorwire.Job{}, err
	}
	reservation := int64(ap.R2Reservation(draft, ap.PermittedOutputBytes(draft)))
	if reservation > s.reservationLimit {
		return executorwire.Job{}, refusal("request_too_large")
	}
	if err := s.admit(reservation); err != nil {
		return executorwire.Job{}, err
	}
	// Freeze the route only after admission, then account for its actual size.
	draft, err = s.buildDraft(in, ap.ClaimTokenHash(token))
	if err != nil {
		return executorwire.Job{}, err
	}
	reservation = int64(ap.R2Reservation(draft, ap.PermittedOutputBytes(draft)))
	if reservation > s.reservationLimit {
		return executorwire.Job{}, refusal("request_too_large")
	}
	if err := s.admit(reservation); err != nil {
		return executorwire.Job{}, err
	}
	hash, err := ap.DraftHash(draft)
	if err != nil {
		return executorwire.Job{}, err
	}
	job = ap.R2{Version: ap.R2Version, RequestID: in.RequestID, InputHash: request.InputHash,
		Draft: draft, DraftHash: hash, CreatedAt: now, Reservation: reservation, ClaimToken: hex.EncodeToString(token[:])}
	count := 1
	if draft.CommandJob != nil {
		count = len(draft.CommandJob.Steps)
	}
	for i := 0; i < count; i++ {
		job.Steps = append(job.Steps, ap.JobStep{Ordinal: i + 1})
	}
	if err := s.store.Commit(job); err != nil {
		return executorwire.Job{}, err
	}
	return executorwire.FromSummary(ap.JobView(job, s.epoch)), nil
}

func refusal(code string) error { return &executorwire.WireError{Code: code, Message: code} }

func (s *Service) admit(reservation int64) error {
	files, err := s.store.List()
	if err != nil {
		return err
	}
	if len(files) >= ap.ExecutorJobFiles {
		return refusal("executor_full")
	}
	var used int64
	live := 0
	for _, file := range files {
		charge := file.EncodedBytes
		if file.Quarantined {
			live++
		} else {
			job, err := s.store.Load(file.RequestID)
			if err != nil {
				return err
			}
			if ap.JobView(job, s.epoch).State != ap.JobFinal {
				live++
				charge = job.Reservation
			} else {
				charge, err = R2FinalCharge(job)
				if err != nil {
					return err
				}
			}
		}
		if charge < 0 || charge > ap.ExecutorBudget-used {
			return refusal("executor_full")
		}
		used += charge
	}
	if live >= ap.ExecutorLiveJobs || reservation > ap.ExecutorBudget-used {
		return refusal("executor_full")
	}
	return nil
}
