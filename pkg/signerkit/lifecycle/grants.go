package lifecycle

import (
	"slices"
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Grant is an owned view of a live grant, without claim capabilities.
type Grant struct {
	RequestID              string
	Alias                  string
	Scope                  ap.GrantScope
	Commands               []string
	TrustedHostFingerprint string
	RegistryEntryDigest    string
	ExpiresAt              time.Time
}

// ListGrants reads the principal's published live grants without taking Engine.mu.
func (e *Engine) ListGrants(principal string) ([]Grant, error) {
	p := &e.published
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.availabilityLocked(); err != nil {
		return nil, err
	}
	// Membership in p.grants is the writer's published liveness; reads never
	// apply their own clock, so they cannot lead or contradict the writer.
	out := make([]Grant, 0)
	for key := range p.grants {
		record := p.records[key]
		if record == nil {
			return nil, keyError()
		}
		if record.Header.Principal != principal {
			continue
		}
		if record.Payload == nil || record.Payload.Plan.StandingGrant == nil {
			return nil, keyError()
		}
		grant := record.Payload.Plan.StandingGrant
		out = append(out, Grant{
			RequestID: record.Header.RequestID, Alias: grant.Alias, Scope: grant.Scope,
			Commands: slices.Clone(grant.Commands), TrustedHostFingerprint: grant.TrustedHostFingerprint,
			RegistryEntryDigest: grant.RegistryEntryDigest, ExpiresAt: ap.GrantExpiresAt(record.Header),
		})
	}
	slices.SortFunc(out, func(a, b Grant) int {
		if order := strings.Compare(a.Alias, b.Alias); order != 0 {
			return order
		}
		return strings.Compare(a.RequestID, b.RequestID)
	})
	return out, nil
}
