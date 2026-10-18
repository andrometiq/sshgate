package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"reflect"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// LegacyInstance is minted by the trusted adapter; ID is a random 128-bit hex
// instance, independent of the caller's request ID. UID comes from peer credentials.
type LegacyInstance struct {
	ID        string
	UID       uint32
	RequestID string
}

// LegacyReservation is a preparation capability bound to one legacy service/request.
// It returns only copies of the frozen rendering inputs. ReserveLegacy has
// completed the one assist attempt before returning it.
type LegacyReservation struct {
	service  *LegacyService
	request  *LegacyRequest
	instance string
	snapshot []byte
	render   LegacyRenderContext
}

func (r *LegacyReservation) Request() *LegacyRequest            { return r.request }
func (r *LegacyReservation) Snapshot() []byte                   { return bytes.Clone(r.snapshot) }
func (r *LegacyReservation) RenderContext() LegacyRenderContext { return cloneLegacyContext(r.render) }

// ReserveLegacy admits an untappable request, freezes destination and snapshot,
// and waits for terminal assist. The raw challenge stays only in preparation
// material; the request table and tombstone use its hash.
func (e *LegacyService) ReserveLegacy(ctx context.Context, instance LegacyInstance, snapshot []byte, input assist.Input) (*LegacyReservation, error) {
	if !ap.ValidEpoch(instance.ID) || len(snapshot) == 0 {
		return nil, errors.New("lifecycle: invalid legacy instance or snapshot")
	}
	e.mu.Lock()
	if e.closed || e.config.LegacyNotifier == nil {
		e.mu.Unlock()
		return nil, unavailable()
	}
	for _, r := range e.requests {
		if r.instance == instance.ID {
			e.mu.Unlock()
			return nil, errors.New("lifecycle: duplicate legacy instance")
		}
	}
	handle, err := ap.NewCardHandle(rand.Reader)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	challenge, err := ap.NewChallenge(rand.Reader)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	r, err := e.reserveLegacyLocked(ctx, instance.UID, instance.RequestID, handle, challenge)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	r.instance = instance.ID
	reservation := &LegacyReservation{service: e, request: r, instance: instance.ID, snapshot: bytes.Clone(snapshot), render: LegacyRenderContext{Handle: handle, Challenge: challenge}}
	deadline := e.config.Clock.Wall().Add(e.config.AssistTimeout)
	e.joined.Add(1)
	e.mu.Unlock()
	defer e.joined.Done()
	reservation.render.Destination = e.config.LegacyNotifier.Destination()
	if reservation.render.Destination.ChatID == 0 || reservation.render.Destination.TopicID < 0 {
		e.CancelLegacy(reservation)
		return nil, errors.New("lifecycle: invalid legacy destination")
	}
	workCtx := r.ctx
	completed := make(chan assist.Snapshot, 1)
	outcome := e.assistPool.TrySubmit(workCtx, e.config.Assessor, input, deadline, func(s assist.Snapshot) { completed <- s })
	switch outcome {
	case assist.Closed:
		e.CancelLegacy(reservation)
		return nil, unavailable()
	case assist.Full:
		reservation.render.Assist = assist.Snapshot{State: ap.AssistUnavailable, Reason: assist.ReasonBusy}
	case assist.Accepted:
		select {
		case reservation.render.Assist = <-completed:
		case <-r.done:
			return nil, unavailable()
		case <-workCtx.Done():
			e.mu.Lock()
			e.resolveLegacyLocked(r, LegacyResult{Status: "timeout"})
			e.mu.Unlock()
			return nil, unavailable()
		}
	}
	// Run enforces legacy alignment for synthesized inputs. Reject any input that
	// did not cross that redaction boundary instead of rendering agent alignment.
	if !terminalLegacyAssist(reservation.render.Assist) {
		reservation.render.Assist = assist.Snapshot{State: ap.AssistUnavailable, Reason: assist.ReasonFailed}
	}
	reservation.render = cloneLegacyContext(reservation.render)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLegacyLocked(e.now())
	if e.closed || r.result.Status != "" {
		return nil, unavailable()
	}
	return reservation, nil
}

// CancelLegacy drops an abandoned preparation (for example a render mismatch).
// It cancels preparation and delivery; a live approval is already committed.
func (e *LegacyService) CancelLegacy(reservation *LegacyReservation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if reservation != nil && reservation.service == e && !reservation.request.live {
		e.resolveLegacyLocked(reservation.request, LegacyResult{Status: "error"})
	}
}

// DeliverLegacy compares the notifier's complete frozen copy before I/O. No
// caller can activate separately: only a successful all-delivered report does.
// A reservation is single-use even if delivery fails; errors never include data.
func (e *LegacyService) DeliverLegacy(reservation *LegacyReservation, artifact *PreparedLegacyApproval) error {
	e.mu.Lock()
	if e.closed || reservation == nil || reservation.service != e {
		e.mu.Unlock()
		return unavailable()
	}
	r := reservation.request
	e.expireLegacyLocked(e.now())
	if r.result.Status != "" || r.live || r.delivering {
		e.mu.Unlock()
		return unavailable()
	}
	if artifact == nil || artifact.data.Instance != reservation.instance || !bytes.Equal(artifact.data.Snapshot, reservation.snapshot) || !sameReservedContext(artifact.data.Context, reservation.render) {
		e.resolveLegacyLocked(r, LegacyResult{Status: "error"})
		e.mu.Unlock()
		return errors.New("legacy approval render does not match the request")
	}
	artifact = &PreparedLegacyApproval{data: artifact.Data()}
	r.artifact = artifact
	r.delivering = true
	e.joined.Add(1)
	e.mu.Unlock()
	defer e.joined.Done()
	prepared, err := e.config.LegacyNotifier.Prepared(reservation.instance)
	if err != nil || !sameLegacyPrepared(artifact, prepared) {
		e.mu.Lock()
		e.resolveLegacyLocked(r, LegacyResult{Status: "error"})
		e.mu.Unlock()
		return errors.New("legacy approval render does not match the request")
	}
	e.mu.Lock()
	e.expireLegacyLocked(e.now())
	if e.closed || r.result.Status != "" {
		e.mu.Unlock()
		return unavailable()
	}
	e.mu.Unlock()
	report, err := e.config.LegacyNotifier.Deliver(r.ctx, &PreparedLegacyApproval{data: artifact.Data()})
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLegacyLocked(e.now())
	if e.closed || r.result.Status != "" {
		return unavailable()
	}
	if err != nil || !report.AllDelivered {
		e.resolveLegacyLocked(r, LegacyResult{Status: "error"})
		return errors.New("backend: legacy card delivery failed")
	}
	r.live = true
	return nil
}

func sameReservedContext(a, b LegacyRenderContext) bool {
	// A7 freezes metadata from its authoritative snapshot, after reservation.
	a.Metadata = nil
	b.Metadata = nil
	return reflect.DeepEqual(a, b)
}
