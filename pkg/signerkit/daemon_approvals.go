package signerkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/sigwire"
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
	// AllowedUIDs restricts local v2 calls when nonempty.
	AllowedUIDs []uint32
	Store       RecoverableStore
	Legacy      *lifecycle.LegacyService
	// PrepareLegacy installs the artifact in the same notifier configured on Legacy.
	// Nil keeps the frozen Backend path; a configured adapter must never send here.
	PrepareLegacy func(*lifecycle.PreparedLegacyApproval) error
	NewEngine     func(lifecycle.Store) (*lifecycle.Engine, error)
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
	c.AllowedUIDs = slices.Clone(c.AllowedUIDs)
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

type approvalCallerKey struct{}
type approvalCaller struct {
	runtime   *ApprovalRuntime
	principal string
	uid       uint32
	hasPeer   bool
}

// HandleSignRequestWithPeer binds v2 ownership to the kernel's connection identity.
func (s *Service) HandleSignRequestWithPeer(ctx context.Context, conn io.ReadWriter, peer *PeerCredentials) error {
	s.approvalsMu.Lock()
	caller := approvalCaller{runtime: s.approvals}
	s.approvalsMu.Unlock()
	if peer != nil {
		caller.uid, caller.hasPeer = peer.UID, true
		caller.principal = fmt.Sprintf("local-uid:%d", peer.UID)
	}
	return s.daemon.HandleSignRequest(context.WithValue(ctx, approvalCallerKey{}, caller), conn)
}

func (d *Daemon) handleApproval(ctx context.Context, conn io.ReadWriter, line []byte) error {
	caller, _ := ctx.Value(approvalCallerKey{}).(approvalCaller)
	// Refusal metadata is derived only from the caller's frame, never a record.
	var meta struct {
		Kind      string `json:"kind"`
		RequestID string `json:"request_id"`
		Draft     struct {
			RequestID string `json:"request_id"`
		} `json:"draft"`
	}
	_ = json.Unmarshal(line, &meta)
	if meta.Kind == aw.KindSubmit {
		meta.RequestID = meta.Draft.RequestID
	}
	request, err := aw.DecodeLocalRequest(line)
	var response aw.Response
	var recorded bool
	if err == nil {
		switch {
		case caller.runtime == nil:
			err = &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
		case !caller.hasPeer:
			err = &ap.CodeError{Code: ap.CodeInvalidRequest}
		case len(caller.runtime.config.AllowedUIDs) > 0 && !slices.Contains(caller.runtime.config.AllowedUIDs, caller.uid):
			err = &ap.CodeError{Code: ap.CodeNotFound}
		default:
			var engine *lifecycle.Engine
			engine, err = caller.runtime.Current()
			if err == nil {
				response, recorded, err = dispatchApproval(ctx, engine, caller.principal, request)
			}
		}
	}
	if err != nil {
		code := ap.CodeLifecycleUnavailable
		var coded *ap.CodeError
		if errors.As(err, &coded) && coded.Code.Valid() {
			code = coded.Code
		}
		// Never reflect internal errors or requester-controlled parser text.
		response = aw.ErrorResponse(code, string(code))
	}
	frame, marshalErr := aw.MarshalLocalResponse(meta.Kind, response)
	if marshalErr != nil {
		return marshalErr
	}
	setWriteGrace(conn)
	n, writeErr := conn.Write(frame)
	if writeErr == nil && n != len(frame) {
		writeErr = io.ErrShortWrite
	}
	if err != nil && !recorded {
		metadata := ap.AuditMetadata{Kind: ap.Kind(meta.Kind), RequestID: meta.RequestID, Principal: caller.principal, Transition: "refused{" + string(response.Error.Code) + "}"}
		if auditErr := d.Audit.Write(AuditEvent{TS: d.now(), RequestID: meta.RequestID, Status: "error", Approval: &metadata}); auditErr != nil {
			fmt.Fprintf(os.Stderr, "signer: audit write failed: %v\n", auditErr)
		}
	}
	return writeErr
}

// The boolean reports a committed noise event; those refusals use the outbox.
func dispatchApproval(ctx context.Context, engine *lifecycle.Engine, principal string, request any) (aw.Response, bool, error) {
	response := aw.Response{ApprovalProto: aw.Proto, OK: true}
	var err error
	var answer ap.Answer
	switch request := request.(type) {
	case aw.SubmitRequest:
		var summary ap.Summary
		summary, err = engine.Submit(ctx, principal, request.Draft)
		response.Summary = &summary
	case aw.GetRequest:
		var summary ap.Summary
		summary, err = engine.Get(principal, request.RequestID)
		response.Summary = &summary
	case aw.ListRequest:
		response.Summaries, response.NextCursor, err = approvalPage(engine, principal, request)
	case aw.WaitRequest:
		var result lifecycle.WaitResult
		result, err = engine.WaitMany(ctx, principal, request.RequestIDs, time.Duration(request.WaitSeconds)*time.Second)
		response.Summaries = result.Summaries
	case aw.ClaimRequest:
		token, _ := hex.DecodeString(request.ClaimToken) // Strict wire validation checked length and alphabet.
		answer, err = engine.Claim(ctx, principal, request.RequestID, ap.Claim{Token: [32]byte(token), PlanHash: request.PlanHash})
		response.Claim = &aw.ClaimAnswer{Status: answer.Claim, Reason: answer.Reason, Class: answer.Class, Signatures: answer.Signatures}
		if answer.Claim == ap.ClaimSignatures {
			response.Claim.DecidedAt = &answer.DecidedAt
		}
	case aw.ReportRequest:
		token, _ := hex.DecodeString(request.ClaimToken)
		body := request.Report
		answer, err = engine.Report(principal, request.RequestID, ap.Report{Token: [32]byte(token), PlanHash: request.PlanHash, Body: ap.FinalReport{
			Class: body.Class, Steps: body.Steps, ExecutedOrdinals: body.ExecutedOrdinals, Partial: body.Partial, ResultDigest: body.ResultDigest,
		}})
	}
	return response, answer.Noise, err
}

func approvalPage(engine *lifecycle.Engine, principal string, request aw.ListRequest) ([]ap.Summary, string, error) {
	var after string
	if request.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(request.Cursor)
		if err != nil || !ap.ValidRequestID(string(decoded)) {
			return nil, "", &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		after = string(decoded)
	}
	summaries, err := engine.List(principal)
	if err != nil {
		return nil, "", err
	}
	slices.SortFunc(summaries, func(a, b ap.Summary) int { return strings.Compare(a.RequestID, b.RequestID) })
	start := 0
	for start < len(summaries) && summaries[start].RequestID <= after {
		start++
	}
	page := summaries[start:]
	next := ""
	if len(page) > request.Limit {
		page = page[:request.Limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(page[len(page)-1].RequestID))
	}
	return page, next, nil
}

// legacyApprove preserves the direct backend path unless a local legacy notifier
// is attached. Synthesized plans exist only inside legacyAssistInput.
func (d *Daemon) legacyApprove(ctx context.Context, request any, transferCommands []string) (<-chan Result, *lifecycle.PreparedLegacyApproval, error) {
	caller, _ := ctx.Value(approvalCallerKey{}).(approvalCaller)
	if caller.runtime == nil || caller.runtime.config.PrepareLegacy == nil {
		var ch <-chan Result
		var err error
		switch req := request.(type) {
		case ApprovalRequest:
			ch, err = d.Backend.Request(ctx, req)
		case GrantApprovalRequest:
			ch, err = d.Backend.RequestGrant(ctx, req)
		case TransferApprovalRequest:
			ch, err = d.Backend.RequestTransfer(ctx, req)
		case RegisterApprovalRequest:
			ch, err = d.Backend.RequestRegisterKey(ctx, req)
		default:
			err = errors.New("unsupported legacy approval")
		}
		return ch, nil, err
	}
	if !caller.hasPeer {
		return nil, nil, errors.New("legacy approval requires peer credentials")
	}
	submitted := d.now()
	if req, ok := request.(ApprovalRequest); ok {
		submitted = req.Submitted
	}
	ctx, cancel := context.WithTimeout(ctx, submitted.Add(sigwire.ApprovalWindow).Sub(d.now()))
	defer cancel()
	artifact, reservation, err := d.prepareLegacy(ctx, caller, request, transferCommands)
	if err != nil {
		return legacyPreparationFailure(ctx, err)
	}
	legacy := caller.runtime.Legacy()
	defer legacy.CancelLegacy(reservation)
	if err := caller.runtime.config.PrepareLegacy(artifact); err != nil {
		return nil, nil, legacyRenderError(artifact.Data().Inputs)
	}
	if err := legacy.DeliverLegacy(reservation, artifact); err != nil {
		switch err.Error() {
		case "legacy approval render does not match the request":
			err = legacyRenderError(artifact.Data().Inputs)
		case "backend: legacy card delivery failed":
			err = errors.New("legacy card delivery failed")
		}
		return legacyPreparationFailure(ctx, err)
	}
	resolved := reservation.Request().Wait()
	result := Result{Status: StatusTimeout, ApprovedBy: resolved.ResolvedBy}
	switch resolved.Status {
	case "approved":
		result.Status = StatusApproved
	case "denied":
		result.Status = StatusDenied
	}
	ch := make(chan Result, 1)
	ch <- result
	close(ch)
	return ch, artifact, nil
}

func legacyPreparationFailure(ctx context.Context, err error) (<-chan Result, *lifecycle.PreparedLegacyApproval, error) {
	if ctx.Err() == nil {
		return nil, nil, err
	}
	ch := make(chan Result, 1)
	ch <- Result{Status: StatusTimeout}
	close(ch)
	return ch, nil, nil
}

func legacyRenderError(inputs []ap.LegacySignInput) error {
	for _, input := range inputs {
		if input.Net {
			return errors.New("net_unsupported: network reads need a card that shows them")
		}
	}
	return errors.New("legacy approval render does not match the request")
}

func legacySignInputs(commands []CommandReq) []ap.LegacySignInput {
	inputs := make([]ap.LegacySignInput, len(commands))
	for i, c := range commands {
		sum := sha256.Sum256([]byte(c.Cmd))
		inputs[i] = ap.LegacySignInput{Server: c.Server, HostFingerprint: c.HostKeyFP, Command: c.Cmd, CommandSHA256: hex.EncodeToString(sum[:]), TTLSeconds: c.TTLSec, Reveal: c.Reveal, Net: c.Net, Reason: c.Reason}
	}
	return inputs
}

func (d *Daemon) prepareLegacy(ctx context.Context, caller approvalCaller, request any, transferCommands []string) (*lifecycle.PreparedLegacyApproval, *lifecycle.LegacyReservation, error) {
	var instanceBytes [16]byte
	if _, err := rand.Read(instanceBytes[:]); err != nil {
		return nil, nil, err
	}
	instance := hex.EncodeToString(instanceBytes[:])
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, nil, err
	}
	defer clear(salt[:])
	submitted := d.now()
	req := approvalreview.LegacyRequest{Requester: caller.principal, SubmittedAt: submitted, ExpiresAt: submitted.Add(sigwire.ApprovalWindow)}
	var inputs []ap.LegacySignInput
	switch r := request.(type) {
	case ApprovalRequest:
		req.RequestID = r.RequestID
		req.SubmittedAt, req.ExpiresAt = r.Submitted, r.Submitted.Add(sigwire.ApprovalWindow)
		inputs = legacySignInputs(r.Commands)
	case GrantApprovalRequest:
		req.RequestID = r.RequestID
		req.Grant = &approvalreview.LegacyGrant{Alias: r.Alias, Scope: r.Scope, Commands: slices.Clone(r.Commands), Duration: r.Duration}
	case TransferApprovalRequest:
		req.RequestID = r.RequestID
		req.Transfer = &approvalreview.LegacyTransfer{TransferID: r.XferID, SourceLabel: r.SrcLabel, SourceFingerprint: r.SrcFP, SourcePath: r.SrcPath, DestLabel: r.DestLabel, DestFingerprint: r.DestFP, DestPath: r.DestPath, Mode: r.Mode}
	case RegisterApprovalRequest:
		req.RequestID = r.RequestID
		req.Register = &ap.RegisterTransferKey{HostFingerprint: r.HostFP, Label: r.Label, BoxPub: r.BoxPub, IDPub: r.IDPub}
	default:
		return nil, nil, errors.New("unsupported legacy approval")
	}
	var snapshot approvalreview.ReviewSnapshot
	var err error
	snapshotSalt := salt
	if len(inputs) > 0 {
		snapshot, err = approvalreview.BuildPreparedSignSnapshot(instance, inputs, approvalreview.LegacyMeta{RequestID: req.RequestID, Requester: req.Requester, SubmittedAt: req.SubmittedAt, ExpiresAt: req.ExpiresAt}, &snapshotSalt, d.RedactRules)
	} else {
		snapshot, err = approvalreview.BuildLegacySnapshot(req, &snapshotSalt, d.RedactRules)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(inputs) > 0 && !legacySnapshotMatches(instance, inputs, snapshot) {
		return nil, nil, legacyRenderError(inputs)
	}
	encoded, err := snapshot.Encode()
	if err != nil {
		return nil, nil, err
	}
	input, err := d.legacyAssistInput(req, inputs, transferCommands, salt)
	redactionFailed := errors.Is(err, assist.ErrNoPolicy) || errors.Is(err, assist.ErrRedactFailed)
	if err != nil && !redactionFailed {
		return nil, nil, err
	}
	legacy := caller.runtime.Legacy()
	reservation, err := legacy.ReserveLegacy(ctx, lifecycle.LegacyInstance{ID: instance, UID: caller.uid, RequestID: req.RequestID, RedactionFailed: redactionFailed}, encoded, input)
	if err != nil {
		return nil, nil, err
	}
	artifact, err := renderLegacy(instance, inputs, snapshot, reservation)
	if err != nil {
		legacy.CancelLegacy(reservation)
		return nil, nil, err
	}
	return artifact, reservation, nil
}

func legacySnapshotMatches(instance string, inputs []ap.LegacySignInput, snapshot approvalreview.ReviewSnapshot) bool {
	digest, ok := ap.LegacySignDigest(instance, inputs)
	if !ok || snapshot.SignDigest != digest || len(snapshot.Steps) != len(inputs) {
		return false
	}
	for i, input := range inputs {
		step := snapshot.Steps[i]
		route := ap.RouteSignedWrite
		if isAdminVerb(input.Command) {
			route = ap.RouteSignedAdmin
		} else if input.Reveal {
			route = ap.RouteSignedReveal
		}
		alias := strings.ReplaceAll(approvalreview.NeutralizeText(input.Server), " ", `\x20`)
		if step.Ordinal != i+1 || step.Target.Alias != alias || step.Target.Fingerprint != input.HostFingerprint || step.TTLSeconds != int(input.TTLSeconds) || step.Route != route || step.Reveal != input.Reveal || step.Net != input.Net || step.Command.SHA256 != input.CommandSHA256 {
			return false
		}
	}
	return true
}

// The invalid-for-v2 plan is advisory input only: never return it to a caller,
// validate it, persist it, or pass it to a freezer, authorizer or minter.
func (d *Daemon) legacyAssistInput(req approvalreview.LegacyRequest, inputs []ap.LegacySignInput, transferCommands []string, salt [32]byte) (assist.Input, error) {
	plan := ap.ApprovalPlanV1{RationaleOrigin: ap.OriginSynthesizedLegacyV1, Rationale: ap.LegacyRationaleText}
	switch {
	case len(inputs) > 0:
		plan.Kind = ap.KindCommandJob
		plan.CommandJob = &ap.CommandJob{}
		for _, input := range inputs {
			plan.CommandJob.Steps = append(plan.CommandJob.Steps, ap.Step{ExactCommand: input.Command})
		}
	case req.Grant != nil:
		plan.Kind = ap.KindStandingGrant
		plan.StandingGrant = &ap.StandingGrant{Scope: ap.GrantScope(req.Grant.Scope), DurationSeconds: int(req.Grant.Duration / time.Second), Commands: slices.Clone(req.Grant.Commands)}
	case req.Transfer != nil:
		if len(transferCommands) != 2 {
			return assist.Input{}, errors.New("legacy transfer needs both signer-built legs")
		}
		plan.Kind = ap.KindTransfer
		plan.Transfer = &ap.Transfer{SendCommand: transferCommands[0], RecvCommand: transferCommands[1]}
	case req.Register != nil:
		plan.Kind, plan.RegisterTransferKey = ap.KindRegisterTransferKey, req.Register
	}
	return assist.RedactForProvider(plan, salt, d.RedactRules)
}

func renderLegacy(instance string, inputs []ap.LegacySignInput, snapshot approvalreview.ReviewSnapshot, reservation *lifecycle.LegacyReservation) (*lifecycle.PreparedLegacyApproval, error) {
	render := reservation.RenderContext()
	metadata, err := json.Marshal(approvalreview.LegacyMeta{RequestID: snapshot.RequestID, Requester: snapshot.Requester, SubmittedAt: snapshot.SubmittedAt, ExpiresAt: snapshot.ExpiresAt})
	if err != nil {
		return nil, err
	}
	render.Metadata = metadata
	view, err := approvalreview.BuildView(snapshot, approvalreview.Assist{State: render.Assist.State, Result: render.Assist.Result, Reason: render.Assist.Reason})
	if err != nil {
		return nil, err
	}
	parts, err := approvalreview.PackParts(view, render.Handle)
	if err != nil {
		return nil, err
	}
	card, err := approvalreview.DecisionCard(view, render.Handle, len(parts))
	if err != nil {
		return nil, err
	}
	payload := make([]lifecycle.LegacyMessage, 0, len(parts)+1)
	for _, part := range parts {
		payload = append(payload, lifecycle.LegacyMessage{Bytes: []byte(part)})
	}
	payload = append(payload, lifecycle.LegacyMessage{Bytes: []byte(card), ApproveLabel: view.ApproveLabel, DenyLabel: view.DenyLabel})
	return lifecycle.NewPreparedLegacyApproval(lifecycle.LegacyPreparedData{Instance: instance, Inputs: inputs, SignDigest: snapshot.SignDigest, Snapshot: reservation.Snapshot(), Context: render, Payload: payload})
}

func (d *Daemon) respondLegacy(conn io.Writer, req signRequest, result Result, artifact *lifecycle.PreparedLegacyApproval) error {
	if artifact != nil && result.Status == StatusApproved {
		data := artifact.Data()
		commands := make([]signRequestCmd, len(data.Inputs))
		for i, input := range data.Inputs {
			commands[i] = signRequestCmd{Server: input.Server, Host: input.HostFingerprint, Cmd: input.Command, TTLSec: input.TTLSeconds, Reveal: input.Reveal, Net: input.Net, Reason: input.Reason}
		}
		if !reflect.DeepEqual(commands, req.Commands) || result.Signatures != nil {
			return d.respondError(conn, req.RequestID, legacyRenderError(data.Inputs).Error())
		}
		req.Commands = commands
	}
	return d.respond(conn, req, result)
}
