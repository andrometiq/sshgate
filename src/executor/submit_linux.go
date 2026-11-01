//go:build linux

package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/mcp/jobplan"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

// Store is the committed job state. All mutations must share Service's lock.
type Store interface {
	Load(string) (ap.R2, error)
	List() ([]JobFile, error)
	Commit(ap.R2) error
	Remove(string) error
}

type Config struct {
	Store          Store
	Servers        *registry.Servers
	Clock          elapsed.Clock
	StagedGatePath string
	Signer         SubmitSigner
}

// Service serializes admission with job commits. C2's job transitions must use
// this same critical section so released reservations cannot race admission.
type Service struct {
	mu                sync.Mutex
	commandSigner     CommandSigner
	commandSSH        jobplan.PhasedRunner
	actors            map[string]*commandActor
	deliveries        map[string]bool
	retentionDue      map[string]time.Time
	submitReaders     map[string]int
	actorGroup        sync.WaitGroup
	signer            SubmitSigner
	submissions       map[string]*submitAttempt
	fatal             chan error
	effects           context.Context
	cancelEffects     context.CancelFunc
	stopping          bool
	waitSigner        WaitSigner // Immutable constructor dependency, separate from submission test seams.
	waiterStarted     bool
	waiterDone        chan struct{}
	waiterWake        chan struct{}
	waiterInitialized bool
	waitJobs          map[string]bool
	jobNudges         map[string]chan struct{}
	submitTimeout     time.Duration
	store             Store
	servers           *registry.Servers
	clock             elapsed.Clock
	stagedGatePath    string
	epoch             string
	jobFileLimit      int
	budgetLimit       int64
	reservationLimit  int64 // Test seam; production uses R2Max.
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
	waitSigner, _ := config.Signer.(WaitSigner)
	effects, cancelEffects := context.WithCancel(context.Background())
	return &Service{
		actors: make(map[string]*commandActor), deliveries: make(map[string]bool), retentionDue: make(map[string]time.Time), submitReaders: make(map[string]int), store: config.Store, servers: config.Servers, clock: config.Clock,
		signer: config.Signer, waitSigner: waitSigner, submissions: make(map[string]*submitAttempt), fatal: make(chan error, 1),
		effects: effects, cancelEffects: cancelEffects, submitTimeout: SubmitNotificationTimeout,
		waiterDone: make(chan struct{}), waiterWake: make(chan struct{}, 1), jobNudges: make(map[string]chan struct{}), waitJobs: make(map[string]bool),
		stagedGatePath: config.StagedGatePath, epoch: hex.EncodeToString(epoch[:]), reservationLimit: ap.R2Max, jobFileLimit: ap.ExecutorJobFiles, budgetLimit: ap.ExecutorBudget,
	}, nil
}

// Submit returns only public job facts, and only after the durable commit.
// Commit errors, particularly ErrCommitUncertain, remain errors for the owner
// to handle; they must never be turned into an ordinary retryable refusal.
func (s *Service) Submit(request executorwire.SubmitRequest) (executorwire.Job, error) {
	return s.submit(request, nil)
}

// admitted runs under mu after a confirmed commit (or an idempotent lookup),
// before any worker can observe this admission.
func (s *Service) submit(request executorwire.SubmitRequest, admitted func(string)) (executorwire.Job, error) {
	if _, err := executorwire.MarshalRequest(request); err != nil {
		return executorwire.Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return executorwire.Job{}, refusal("executor_unavailable")
	}
	in := request.Input
	job, err := s.store.Load(in.RequestID)
	if err == nil {
		if job.InputHash != request.InputHash {
			return executorwire.Job{}, refusal("conflict")
		}
		if admitted != nil {
			admitted(job.RequestID)
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
	if admitted != nil {
		admitted(job.RequestID)
	}
	s.jobCommittedLocked(job)
	return executorwire.FromSummary(ap.JobView(job, s.epoch)), nil
}

func refusal(code string) error { return &executorwire.WireError{Code: code, Message: code} }

func (s *Service) admit(reservation int64) error {
	if s.commandSigner != nil {
		if err := s.retainLocked(reservation); err != nil {
			return err
		}
	}
	files, err := s.store.List()
	if err != nil {
		return err
	}
	if len(files) >= s.jobFileLimit {
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
		if charge < 0 || charge > s.budgetLimit-used {
			return refusal("executor_full")
		}
		used += charge
	}
	if live >= ap.ExecutorLiveJobs || reservation > s.budgetLimit-used {
		return refusal("executor_full")
	}
	return nil
}
