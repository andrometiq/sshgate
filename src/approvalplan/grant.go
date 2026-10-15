package approvalplan

import (
	"slices"
	"strings"
	"time"
)

// GrantLive is the record half of SA-6.4's liveness: an approved grant
// decided in the current epoch, not revoked, newest for its (principal,
// alias) by the caller's newest-grant mark, and before its wall end. The
// caller also requires projection membership, whose held pair (AcquireGrant)
// ends it at the first finding on either clock and never re-adds it.
func GrantLive(rec R1, now Now, epoch string, newestForAlias bool) bool {
	h := rec.Header
	d := h.Decision
	return h.Kind == KindStandingGrant && d != nil && d.Status == ApprovalApproved && d.Epoch == epoch &&
		h.RevokedAt == nil && newestForAlias && now.norm().Wall.Before(GrantExpiresAt(h))
}

// AcquireGrant is the grant's held deadline, acquired when the commit that
// approved it in this epoch is confirmed (SA-1 rule 3.4).
func AcquireGrant(rec R1, now Now) Held {
	return Acquire(now.norm(), GrantExpiresAt(rec.Header), time.Duration(rec.Header.DurationSeconds)*time.Second)
}

// GrantCovers reports whether grant covers every signed step of rec, a
// command_job of the grant's own principal (E9, E24). The byte refusal is
// outermost: an SSHGATE_ command, a reveal or an admin step is never covered.
// Coverage needs the grant's payload; a shed grant covers nothing.
func GrantCovers(grant, rec R1) bool {
	g, h := grant.Header, rec.Header
	if g.Kind != KindStandingGrant || grant.Payload == nil || grant.Payload.Plan.StandingGrant == nil ||
		h.Kind != KindCommandJob || rec.Payload == nil || rec.Payload.Plan.CommandJob == nil ||
		g.Principal != h.Principal || g.SubPrincipal != h.SubPrincipal {
		return false
	}
	scope := grant.Payload.Plan.StandingGrant
	for _, s := range rec.Payload.Plan.CommandJob.Steps {
		if strings.HasPrefix(s.ExactCommand, AdminVerbPrefix) || s.Route == RouteSignedReveal || s.Route == RouteSignedAdmin {
			return false
		}
		if !s.Route.Signed() {
			continue
		}
		if s.Target.ServerAlias != g.GrantAlias || s.Target.TrustedHostFingerprint != g.GrantHostFP {
			return false
		}
		if scope.Scope != GrantScopeAll && !slices.Contains(scope.Commands, s.ExactCommand) {
			return false
		}
	}
	return true
}
