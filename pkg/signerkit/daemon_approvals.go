package signerkit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// RecoverableStore retains exclusive ownership across failed reloads.
type RecoverableStore interface {
	lifecycle.Store
	Reopen() error
	Close() error
}

// ApprovalRuntimeConfig transfers store and legacy ownership to the runtime.
// NewEngine must construct fresh generation-owned dependencies and clean them
// up on failure. It must use the supplied store and persistent Legacy service.
type ApprovalRuntimeConfig struct {
	Store     RecoverableStore
	Legacy    *lifecycle.LegacyService
	NewEngine func(lifecycle.Store) (*lifecycle.Engine, error)
}

// ApprovalRuntime owns replaceable v2 generations and the persistent v1 owner.
// Call Run once to supervise recovery, and Close before releasing dependencies.
type ApprovalRuntime struct {
	mu              sync.Mutex
	config          ApprovalRuntimeConfig
	engine          *lifecycle.Engine
	cause           error
	ctx             context.Context
	cancel          context.CancelFunc
	started, closed bool
	done            chan struct{}
	closeOnce       sync.Once
	closeErr        error
	wait            func(context.Context, time.Duration) bool
}

// NewApprovalRuntime retains ownership even when initial loading fails. Status
// diagnoses that state while Run retries. Acquire storage ownership beforehand.
func NewApprovalRuntime(c ApprovalRuntimeConfig) (*ApprovalRuntime, error) {
	if c.Store == nil || c.Legacy == nil || c.NewEngine == nil {
		return nil, errors.New("signer: approval store, legacy service and engine factory are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &ApprovalRuntime{config: c, ctx: ctx, cancel: cancel, done: make(chan struct{}), wait: waitApprovalRecovery}
	if err := r.rebuild(); err != nil {
		r.cause = approvalRecoveryCause(err)
	}
	return r, nil
}

func approvalRecoveryCause(err error) error {
	var coded *ap.CodeError
	if errors.As(err, &coded) && coded.Code == ap.CodeStorageUncertain {
		return err
	}
	cause := &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
	if err != nil {
		cause.Msg = err.Error()
	}
	return cause
}

func waitApprovalRecovery(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (r *ApprovalRuntime) rebuild() error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if err := r.config.Store.Reopen(); err != nil {
		return err
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	engine, err := r.config.NewEngine(r.config.Store)
	if err != nil {
		return err
	}
	if engine == nil {
		return errors.New("signer: engine factory returned nil")
	}
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		engine.Close()
		return context.Canceled
	}
	r.engine, r.cause = engine, nil
	r.mu.Unlock()
	return nil
}

// Current resolves a generation for one operation. Never cache it across calls.
// A previously returned engine permanently refuses work after its stop latch.
func (r *ApprovalRuntime) Current() (*lifecycle.Engine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cause != nil {
		return nil, r.cause
	}
	if r.engine != nil {
		if err := r.engine.Availability(); err != nil {
			return nil, err
		}
	}
	if r.closed || r.engine == nil {
		return nil, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
	}
	return r.engine, nil
}

// Status includes the latched recovery cause until a replacement is published.
func (r *ApprovalRuntime) Status() error { _, err := r.Current(); return err }

// Legacy is the persistent callback and request owner across v2 recoveries.
func (r *ApprovalRuntime) Legacy() *lifecycle.LegacyService { return r.config.Legacy }

// Run joins each failed generation before reopening storage. Cancellation stops
// recovery; Close also joins legacy work and releases the ownership descriptor.
func (r *ApprovalRuntime) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.started || r.closed {
		r.mu.Unlock()
		return errors.New("signer: approval runtime already run or closed")
	}
	r.started = true
	r.mu.Unlock()
	defer close(r.done)
	defer func() {
		r.mu.Lock()
		engine := r.engine
		r.mu.Unlock()
		if engine != nil {
			engine.Close()
		}
	}()
	stop := context.AfterFunc(ctx, r.cancel)
	defer stop()
	delay := time.Second
	for r.ctx.Err() == nil {
		r.mu.Lock()
		engine := r.engine
		r.mu.Unlock()
		if engine != nil {
			err := engine.Run(r.ctx) // returns only after generation-owned work joins
			r.mu.Lock()
			r.engine = nil
			r.cause = approvalRecoveryCause(err)
			r.mu.Unlock()
			delay = time.Second
		}
		if !r.wait(r.ctx, delay) {
			break
		}
		if err := r.rebuild(); err != nil {
			r.mu.Lock()
			var coded *ap.CodeError
			if !errors.As(r.cause, &coded) || coded.Code != ap.CodeStorageUncertain {
				r.cause = approvalRecoveryCause(err)
			}
			r.mu.Unlock()
			delay = min(delay*2, 30*time.Second)
		}
	}
	return r.ctx.Err()
}

// Close establishes the stop cut before joining, then releases storage last.
func (r *ApprovalRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		engine, started := r.engine, r.started
		r.mu.Unlock()
		if engine != nil {
			r.closeErr = engine.Close()
		}
		r.closeErr = errors.Join(r.closeErr, r.config.Legacy.Close())
		if started {
			<-r.done
		}
		r.closeErr = errors.Join(r.closeErr, r.config.Store.Close())
	})
	return r.closeErr
}

// ApprovalMinter binds lifecycle signing to this service's custody boundary.
func (s *Service) ApprovalMinter() lifecycle.Minter { return approvalMinter{s.daemon} }

type approvalMinter struct{ daemon *Daemon }

func (m approvalMinter) Mint(ctx context.Context, plan ap.ApprovalPlanV1, at time.Time) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if plan.Transfer != nil {
		transfer := plan.Transfer
		send, recv, err := m.daemon.signTransferLegsAt(transfer.SendCommand, transfer.Source.Target.TrustedHostFingerprint,
			transfer.RecvCommand, transfer.Destination.Target.TrustedHostFingerprint, int64(transfer.SignatureTTLSeconds), at.Unix())
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []string{send.Sig, recv.Sig}, nil
	}
	if plan.CommandJob == nil {
		return nil, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	commands := make([]signRequestCmd, 0, len(plan.CommandJob.Steps))
	for _, step := range plan.CommandJob.Steps {
		if step.Route.Signed() {
			commands = append(commands, signRequestCmd{Server: step.Target.ServerAlias, Cmd: step.ExactCommand,
				TTLSec: int64(step.SignatureTTLSeconds), Host: step.Target.TrustedHostFingerprint, Reveal: step.Route == ap.RouteSignedReveal})
		}
	}
	signatures, err := m.daemon.signAt(commands, at.Unix())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]string, len(signatures))
	for i, signature := range signatures {
		out[i] = signature.Sig
	}
	return out, nil
}
