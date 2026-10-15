package statetest

import (
	"fmt"
	"slices"
	"strings"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// authorization is evidence captured at the deciding commit, independently
// of Decide and GrantCovers. It survives record shedding and deletion.
type authorization struct {
	decisionSeq uint64
	planHash    string
	decision    string
}

func (s *Signer) checkAuthorization(key string, before *ap.R1, after ap.R1, cmd ap.Command, in ap.Inputs) {
	if !s.Oracle {
		return
	}
	d := after.Header.Decision
	if d == nil || d.Status != ap.ApprovalApproved || before != nil && before.Header.Decision != nil {
		return
	}
	authorized := false
	if v, ok := cmd.(ap.CastVote); ok && before != nil && v.Card != nil && v.Operator == Operator && v.Decision == ap.VoteApprove && s.Clock.Wall.Before(after.Header.RequestExpiresAt) {
		if before.Payload != nil && before.Header.Assist != nil {
			for i := len(before.Payload.CardEntries) - 1; i >= 0; i-- {
				c := before.Payload.CardEntries[i]
				if c.Retired {
					continue
				}
				challenge, known := s.challenge[c.Handle]
				delivered := c.Kind == ap.CardEdit && c.Confirmed || c.Kind != ap.CardEdit && c.Outcome == ap.OutcomeSent
				authorized = known && delivered && c.Handle == v.Card.Handle && c.MsgID != nil && *c.MsgID == v.Card.MsgID && challenge == v.Card.Challenge && slices.Contains(c.Actions, ap.ActionApprove) && c.Rev == 1
				break
			}
		}
	}
	if g := in.Grant; g != nil && strings.HasPrefix(d.DecidedBy, ap.GrantDecidedPrefix) {
		gkey := ap.RecordKey(g.Record.Header.Principal, g.Record.Header.RequestID)
		a, human := s.authorized[gkey]
		human = human && a.planHash == g.Record.Header.PlanHash && a.decision == enc(g.Record.Header.Decision)
		authorized = human && g.Live && s.independentGrantLive(gkey, g.Record) && independentCoverage(g.Record, after) && d.DecidedBy == ap.GrantDecidedPrefix+g.Record.Header.RequestID
	}
	if !authorized {
		s.fail(fmt.Errorf("approval %s has no independent human/live-grant authorization", key))
		return
	}
	for _, event := range after.Header.Outbox {
		if event.Kind == ap.EventDecision {
			s.authorized[key] = authorization{decisionSeq: event.Seq, planHash: after.Header.PlanHash, decision: enc(d)}
			return
		}
	}
	s.fail(fmt.Errorf("approval %s has no decision audit event", key))
}

func independentCoverage(grant, rec ap.R1) bool {
	if grant.Payload == nil || rec.Payload == nil || grant.Payload.Plan.StandingGrant == nil || rec.Payload.Plan.CommandJob == nil || grant.Header.Principal != rec.Header.Principal || grant.Header.SubPrincipal != rec.Header.SubPrincipal {
		return false
	}
	g := grant.Payload.Plan.StandingGrant
	for _, step := range rec.Payload.Plan.CommandJob.Steps {
		if strings.HasPrefix(step.ExactCommand, "SSHGATE_") || step.Route == ap.RouteSignedReveal || step.Route == ap.RouteSignedAdmin {
			return false
		}
		if step.Route == ap.RouteUnsignedRead {
			continue
		}
		if step.Target.ServerAlias != g.Alias || step.Target.TrustedHostFingerprint != g.TrustedHostFingerprint || g.Scope != ap.GrantScopeAll && !slices.Contains(g.Commands, step.ExactCommand) {
			return false
		}
	}
	return true
}

func (s *Signer) checkReleaseAuthority(key string) {
	if !s.Oracle {
		return
	}
	a, ok := s.authorized[key]
	rec, present := s.Store[key]
	if !ok || !present || a.planHash != rec.Header.PlanHash || a.decision != enc(rec.Header.Decision) || a.decisionSeq == 0 || s.Sink.Keys[ap.EventKey(key, a.decisionSeq)] == 0 {
		s.fail(fmt.Errorf("release/dispatch %s lacks authorized, flushed decision", key))
	}
}

func (s *Signer) independentGrantLive(key string, rec ap.R1) bool {
	h := rec.Header
	hold := s.grants[key]
	now := s.Clock.Now()
	return hold != nil && !hold.dead && h.Decision != nil && h.Decision.Status == ap.ApprovalApproved && h.Decision.Epoch == s.Epoch && h.RevokedAt == nil && s.newest[h.Principal+"\x00"+h.GrantAlias] == key && now.Wall.Before(hold.held.WallEnd) && now.Elapsed < hold.held.ElapsedEnd
}
