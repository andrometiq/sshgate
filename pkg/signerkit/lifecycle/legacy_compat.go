package lifecycle

import (
	"context"
	"errors"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// ReserveLegacy delegates to the persistent legacy owner.
func (e *Engine) ReserveLegacy(ctx context.Context, instance LegacyInstance, snapshot []byte, input assist.Input) (*LegacyReservation, error) {
	if e.legacy == nil {
		return nil, unavailable()
	}
	return e.legacy.ReserveLegacy(ctx, instance, snapshot, input)
}
func (e *Engine) CancelLegacy(r *LegacyReservation) {
	if e.legacy != nil {
		e.legacy.CancelLegacy(r)
	}
}
func (e *Engine) DeliverLegacy(r *LegacyReservation, a *PreparedLegacyApproval) error {
	if e.legacy == nil {
		return unavailable()
	}
	if r != nil {
		e.mu.Lock()
		collision := len(e.projections.cards[r.render.Handle]) != 0
		e.mu.Unlock()
		if collision {
			e.legacy.CancelLegacy(r)
			return errors.New("lifecycle: legacy handle collision")
		}
	}
	return e.legacy.DeliverLegacy(r, a)
}

// VoteLegacy preserves routing for callers using an engine directly. Runtime
// adapters should route against the persistent owner and the current generation.
func (e *Engine) VoteLegacy(v ap.CastVote, answer func(LegacyTapResult)) (LegacyTapResult, error) {
	if e.legacy == nil {
		return LegacyTapResult{}, unavailable()
	}
	e.mu.Lock()
	knownV2 := v.Card != nil && len(e.projections.cards[v.Card.Handle]) != 0
	e.mu.Unlock()
	if knownV2 {
		if e.legacy.HasHandle(v.Card.Handle) {
			return LegacyTapResult{}, errors.New("lifecycle: legacy handle collision")
		}
		return LegacyTapResult{}, nil
	}
	return e.legacy.VoteLegacy(v, answer)
}
