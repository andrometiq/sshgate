package lifecycle

import (
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"time"
)

type grantOwner struct{ principal, alias string }
type grantProjection struct {
	held ap.Held
}
type recordCharge struct {
	principal, requestID, handle string
	cards                        []string
	full, live                   bool
	reserved                     int64
}
type counters struct {
	records, full, live int
	reserved            int64
}

// Every index retains all matches so collisions fail closed at resolution.
type index map[string]map[string]struct{}

func (i index) add(value, key string) {
	if i[value] == nil {
		i[value] = make(map[string]struct{})
	}
	i[value][key] = struct{}{}
}
func (i index) remove(value, key string) {
	delete(i[value], key)
	if len(i[value]) == 0 {
		delete(i, value)
	}
}
func (i index) resolve(value string) (string, error) {
	matches := i[value]
	if len(matches) == 0 {
		return "", &ap.CodeError{Code: ap.CodeNotFound}
	}
	if len(matches) != 1 {
		return "", &ap.CodeError{Code: ap.CodeInvalidRequest, Msg: "ambiguous id — use the handle from /pending"}
	}
	for key := range matches {
		return key, nil
	}
	panic("unreachable")
}

type projections struct {
	records                    map[string]recordCharge
	grants                     map[string]*grantProjection
	newest                     map[grantOwner]string
	cards, handles, requestIDs index
	total                      counters
	principals                 map[string]counters
	due                        map[string]time.Time
}

func newProjections() projections {
	return projections{records: map[string]recordCharge{}, grants: map[string]*grantProjection{}, newest: map[grantOwner]string{}, cards: index{}, handles: index{}, requestIDs: index{}, principals: map[string]counters{}, due: map[string]time.Time{}}
}
func (p *projections) count(c recordCharge, delta int) {
	apply := func(n *counters) {
		n.records += delta
		if c.full {
			n.full += delta
		}
		if c.live {
			n.live += delta
		}
		n.reserved += int64(delta) * c.reserved
	}
	apply(&p.total)
	n := p.principals[c.principal]
	apply(&n)
	if n.records == 0 {
		delete(p.principals, c.principal)
	} else {
		p.principals[c.principal] = n
	}
}
func (p *projections) removeRecord(key string) {
	if c, ok := p.records[key]; ok {
		p.count(c, -1)
		p.handles.remove(c.handle, key)
		p.requestIDs.remove(c.requestID, key)
		for _, card := range c.cards {
			p.cards.remove(card, key)
		}
		delete(p.records, key)
	}
	delete(p.due, key)
}
func (p *projections) remove(key string) {
	p.removeRecord(key)
	delete(p.grants, key)
	// The newest mark survives deletion of the superseder.
}
func (p *projections) dropGrant(key string) {
	delete(p.grants, key)
	if c, ok := p.records[key]; ok && c.live {
		p.count(c, -1)
		c.live = false
		p.records[key] = c
		p.count(c, 1)
	}
}
func (p *projections) expireGrants(now ap.Now) {
	for key, grant := range p.grants {
		if grant.held.Passed(now) {
			p.dropGrant(key)
		}
	}
}
func (p *projections) update(key string, before *ap.R1, after ap.R1, now ap.Now, epoch string, settings ap.Settings) {
	p.removeRecord(key)
	h := after.Header
	if h.Kind == ap.KindStandingGrant {
		owner := grantOwner{h.Principal, h.GrantAlias}
		if (before == nil || before.Header.Decision == nil) && h.Decision != nil && h.Decision.Status == ap.ApprovalApproved && h.Decision.Epoch == epoch {
			if previous := p.newest[owner]; previous != "" {
				p.dropGrant(previous)
			}
			p.newest[owner] = key
			if ap.GrantLive(after, now, epoch, true) {
				p.grants[key] = &grantProjection{held: ap.AcquireGrant(after, now)}
			}
		}
		if h.RevokedAt != nil {
			p.dropGrant(key)
		}
	}
	charge := recordCharge{principal: h.Principal, requestID: h.RequestID, handle: ap.RecordHandle(key), full: after.Payload != nil, live: ap.Class(after, now, settings, p.grants[key] != nil) == ap.ClassLive}
	if charge.full {
		charge.reserved = int64(ap.R1Reservation(after))
		for _, card := range after.Payload.CardEntries {
			charge.cards = append(charge.cards, card.Handle)
			p.cards.add(card.Handle, key)
		}
	}
	p.records[key] = charge
	p.count(charge, 1)
	p.handles.add(charge.handle, key)
	p.requestIDs.add(charge.requestID, key)
	if due := ap.NextDueAt(after, now, settings); !due.IsZero() {
		p.due[key] = due
	}
}
