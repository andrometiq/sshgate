package signerkit

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
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
	// Recheck the stored plan, including E71, before any custody call.
	if err := plan.Validate(); err != nil {
		return nil, &ap.CodeError{Code: ap.CodeRecordCorrupt}
	}
	if plan.Transfer != nil {
		transfer := plan.Transfer
		registry := m.daemon.XferRegistry
		if registry == nil {
			return nil, &lifecycle.StaleEnrollmentError{}
		}
		registry.mu.RLock()
		defer registry.mu.RUnlock()
		source, sourceErr := registry.snapshotLocked(transfer.Source.Target.TrustedHostFingerprint)
		destination, destinationErr := registry.snapshotLocked(transfer.Destination.Target.TrustedHostFingerprint)
		if sourceErr != nil || destinationErr != nil || source.EntryDigest != transfer.Source.KeyEntryDigest || destination.EntryDigest != transfer.Destination.KeyEntryDigest {
			return nil, &lifecycle.StaleEnrollmentError{Digests: ap.XferDigests{Source: source.EntryDigest, Destination: destination.EntryDigest}}
		}
		if !validFrozenTransferLegs(*transfer, source, destination) {
			return nil, &ap.CodeError{Code: ap.CodeRecordCorrupt}
		}
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

// Validate both legs before custody; signing still uses the original frozen bytes.
func validFrozenTransferLegs(transfer ap.Transfer, source, destination XferKeySnapshot) bool {
	send, err := xferwire.ParseSend(transfer.SendCommand)
	if err != nil {
		return false
	}
	recv, err := xferwire.ParseRecv(transfer.RecvCommand)
	if err != nil {
		return false
	}
	return xfer.BoxPublicText(send.BoxPub) == destination.BoxPub &&
		transfer.Destination.PublicKey == destination.BoxPub &&
		xfer.IDPublicText(recv.IDPub) == source.IDPub &&
		transfer.Source.PublicKey == source.IDPub &&
		send.XferID == transfer.TransferID && recv.XferID == transfer.TransferID &&
		send.DestID == transfer.Destination.Target.TrustedHostFingerprint &&
		recv.DestID == transfer.Destination.Target.TrustedHostFingerprint &&
		recv.SrcID == transfer.Source.Target.TrustedHostFingerprint &&
		send.SrcPath == transfer.Source.Path && recv.DestPath == transfer.Destination.Path &&
		recv.Mode == transfer.Mode
}

// ApprovalAuditWriter projects outbox metadata through the configured audit sink.
// A sink failure is returned to the lifecycle so audited_through cannot advance.
func (s *Service) ApprovalAuditWriter() lifecycle.AuditWriter { return approvalAuditWriter{s} }

type approvalAuditWriter struct{ service *Service }

func (w approvalAuditWriter) WriteApproval(ctx context.Context, metadata ap.AuditMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.service.audit == nil {
		return ErrNoAudit
	}
	return w.service.audit.Call(ctx, AuditCall{Time: w.service.daemon.now(), RequestID: metadata.RequestID, Lifecycle: "approval-" + metadata.Transition, Approval: &metadata})
}

// ApprovalXferDigests reads both enrollments from the same registry generation.
func (s *Service) ApprovalXferDigests() lifecycle.XferDigests {
	return approvalXferDigests{s.daemon.XferRegistry}
}

type approvalXferDigests struct{ registry *XferRegistry }

func (d approvalXferDigests) Current(ctx context.Context, transfer ap.Transfer) (ap.XferDigests, error) {
	if err := ctx.Err(); err != nil {
		return ap.XferDigests{}, err
	}
	if d.registry == nil {
		return ap.XferDigests{}, errors.New("transfer registry unavailable")
	}
	d.registry.mu.RLock()
	defer d.registry.mu.RUnlock()
	return transferDigestsLocked(d.registry, transfer)
}
func transferDigestsLocked(registry *XferRegistry, transfer ap.Transfer) (ap.XferDigests, error) {
	source, err := registry.snapshotLocked(transfer.Source.Target.TrustedHostFingerprint)
	if err != nil {
		return ap.XferDigests{}, err
	}
	destination, err := registry.snapshotLocked(transfer.Destination.Target.TrustedHostFingerprint)
	if err != nil {
		return ap.XferDigests{}, err
	}
	return ap.XferDigests{Source: source.EntryDigest, Destination: destination.EntryDigest}, nil
}

// ApprovalFreezer binds authenticated ownership and configured validity. Route
// snapshots remain requester-supplied; transfer keys come only from the signer.
func (s *Service) ApprovalFreezer(validity time.Duration) lifecycle.Freezer {
	return approvalFreezer{s.daemon.XferRegistry, validity}
}

type approvalFreezer struct {
	registry *XferRegistry
	validity time.Duration
}

func (f approvalFreezer) Freeze(ctx context.Context, draft ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	if err := ctx.Err(); err != nil {
		return ap.ApprovalPlanV1{}, err
	}
	if err := draft.Validate(); err != nil {
		return ap.ApprovalPlanV1{}, err
	}
	inputs := ap.FreezeInputs{RequesterPrincipal: principal, RequesterSub: sub, Now: now, Validity: f.validity}
	if draft.Transfer != nil {
		transfer, err := f.freezeTransfer(*draft.Transfer)
		if err != nil {
			return ap.ApprovalPlanV1{}, err
		}
		inputs.Transfer = transfer
	}
	return ap.FreezeDraft(draft, inputs)
}
func (f approvalFreezer) freezeTransfer(transfer ap.Transfer) (*ap.TransferFreezeInputs, error) {
	if f.registry == nil {
		return nil, errors.New("transfer registry unavailable")
	}
	f.registry.mu.RLock()
	source, err := f.registry.snapshotLocked(transfer.Source.Target.TrustedHostFingerprint)
	if err != nil {
		f.registry.mu.RUnlock()
		return nil, err
	}
	destination, err := f.registry.snapshotLocked(transfer.Destination.Target.TrustedHostFingerprint)
	f.registry.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	id, err := newXferID()
	if err != nil {
		return nil, err
	}
	box, err := xfer.ParseBoxPublicText(destination.BoxPub)
	if err != nil {
		return nil, err
	}
	identity, err := xfer.ParseIDPublicText(source.IDPub)
	if err != nil {
		return nil, err
	}
	send, err := xferwire.EncodeSend(box, id, transfer.Destination.Target.TrustedHostFingerprint, transfer.Source.Path)
	if err != nil {
		return nil, err
	}
	recv, err := xferwire.EncodeRecv(identity, id, transfer.Source.Target.TrustedHostFingerprint, transfer.Destination.Target.TrustedHostFingerprint, transfer.Mode, transfer.Destination.Path)
	if err != nil {
		return nil, err
	}
	return &ap.TransferFreezeInputs{
		Source:      ap.TransferKeySnapshot{HostFingerprint: transfer.Source.Target.TrustedHostFingerprint, Label: source.Label, PublicKey: source.IDPub, EntryDigest: source.EntryDigest},
		Destination: ap.TransferKeySnapshot{HostFingerprint: transfer.Destination.Target.TrustedHostFingerprint, Label: destination.Label, PublicKey: destination.BoxPub, EntryDigest: destination.EntryDigest},
		TransferID:  id, SendCommand: send, RecvCommand: recv,
	}, nil
}

// ApprovalSnapshotBuilder uses the shared renderer with a fresh per-request salt.
func (s *Service) ApprovalSnapshotBuilder() lifecycle.SnapshotBuilder {
	return approvalSnapshotBuilder{s.daemon}
}

type approvalSnapshotBuilder struct{ daemon *Daemon }

func (b approvalSnapshotBuilder) BuildSnapshot(ctx context.Context, plan ap.ApprovalPlanV1) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, "", err
	}
	snapshot, err := approvalreview.BuildSnapshot(plan, &salt, b.daemon.RedactRules)
	if err != nil {
		return nil, "", err
	}
	view, err := approvalreview.BuildView(snapshot, approvalreview.Assist{State: ap.AssistPreparing})
	if err != nil {
		return nil, "", err
	}
	encoded, err := snapshot.Encode()
	return encoded, view.Reason, err
}
