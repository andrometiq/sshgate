// Package policyreview owns the transport-neutral, bounded semantic review of
// base-manifest changes. It deliberately knows nothing about signerkit,
// Telegram, hosted HTTP, or persistence.
package policyreview

import (
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/karthikeyan5/sshgate/src/policy"
)

const (
	MaxBootstrapEntries      = 32
	MaxReviewedLiteralBytes  = 24 << 10
	MaxBootstrapLiteralBytes = 4 << 10
	MaxRevisionChanges       = 32
)

// ChangeSet is the deterministic semantic delta used by every human review
// surface. Slices are sorted by ID.
type ChangeSet struct {
	AxesChanged    bool
	AddedEntries   []policy.BaseEntry
	RemovedIDs     []string
	NewRevokedIDs  []string
	LogicalChanges int
}

// ValidateBootstrap enforces the hard bounds and out-of-band identity rule for
// a first manifest.
func ValidateBootstrap(candidate policy.BaseManifest) error {
	if len(candidate.Entries) > MaxBootstrapEntries {
		return errors.New("policy review: bootstrap entry review bound exceeded")
	}
	total := 0
	for _, entry := range candidate.Entries {
		if !ValidOutOfBandID(entry.ID) {
			return errors.New("policy review: newly reviewed entry is not a random out-of-band policy id")
		}
		if len(entry.Identity.Literal) > MaxBootstrapLiteralBytes {
			return errors.New("policy review: command literal exceeds per-entry review bound")
		}
		total += len(entry.Identity.Literal)
	}
	if total > MaxReviewedLiteralBytes {
		return errors.New("policy review: newly reviewed literals exceed aggregate bound")
	}
	// The persisted v2 document has one axes item plus every added entry and
	// explicit revocation. Keep classification aligned with the renderer so an
	// accepted bootstrap can never become permanently unrenderable.
	if 1+len(candidate.Entries)+len(candidate.RevokedPermitIDs) > MaxDocumentItems {
		return errors.New("policy review: bootstrap logical-part bound exceeded")
	}
	return nil
}

// ValidateSuccessor enforces append-only identity/tombstone lineage and the
// bounded review delta for one successor.
func ValidateSuccessor(head, candidate policy.BaseManifest) error {
	_, err := Changes(&head, candidate)
	return err
}

// Changes returns a deterministic semantic delta after validating all review
// invariants. A nil head denotes bootstrap.
func Changes(head *policy.BaseManifest, candidate policy.BaseManifest) (ChangeSet, error) {
	if head == nil {
		if err := ValidateBootstrap(candidate); err != nil {
			return ChangeSet{}, err
		}
		changes := ChangeSet{AxesChanged: true, LogicalChanges: 1}
		changes.AddedEntries = append(changes.AddedEntries, candidate.Entries...)
		changes.NewRevokedIDs = append(changes.NewRevokedIDs, candidate.RevokedPermitIDs...)
		sort.Slice(changes.AddedEntries, func(i, j int) bool { return changes.AddedEntries[i].ID < changes.AddedEntries[j].ID })
		sort.Strings(changes.NewRevokedIDs)
		changes.LogicalChanges += len(changes.AddedEntries) + len(changes.NewRevokedIDs)
		return changes, nil
	}

	headEntries := make(map[string]policy.BaseEntry, len(head.Entries))
	headRevoked := make(map[string]struct{}, len(head.RevokedPermitIDs))
	for _, entry := range head.Entries {
		headEntries[entry.ID] = entry
	}
	for _, id := range head.RevokedPermitIDs {
		headRevoked[id] = struct{}{}
	}
	candidateEntries := make(map[string]policy.BaseEntry, len(candidate.Entries))
	candidateRevoked := make(map[string]struct{}, len(candidate.RevokedPermitIDs))
	for _, entry := range candidate.Entries {
		candidateEntries[entry.ID] = entry
	}
	for _, id := range candidate.RevokedPermitIDs {
		candidateRevoked[id] = struct{}{}
	}
	for id := range headRevoked {
		if _, ok := candidateRevoked[id]; !ok {
			return ChangeSet{}, errors.New("policy review: tombstone deletion")
		}
		if _, resurrected := candidateEntries[id]; resurrected {
			return ChangeSet{}, errors.New("policy review: revoked id resurrection")
		}
	}

	changes := ChangeSet{AxesChanged: head.MissAction != candidate.MissAction || head.Growth != candidate.Growth}
	if changes.AxesChanged {
		changes.LogicalChanges++
	}
	removed := make(map[string]struct{})
	for id, oldEntry := range headEntries {
		newEntry, retained := candidateEntries[id]
		if retained {
			if !reflect.DeepEqual(oldEntry, newEntry) {
				return ChangeSet{}, errors.New("policy review: retained entry changed under immutable id")
			}
			continue
		}
		if _, revoked := candidateRevoked[id]; !revoked {
			return ChangeSet{}, errors.New("policy review: entry removed without tombstone")
		}
		removed[id] = struct{}{}
		changes.RemovedIDs = append(changes.RemovedIDs, id)
		changes.LogicalChanges++
	}
	newLiteralBytes := 0
	for id, entry := range candidateEntries {
		if _, retained := headEntries[id]; retained {
			continue
		}
		if !ValidOutOfBandID(id) {
			return ChangeSet{}, errors.New("policy review: newly reviewed entry is not a random out-of-band policy id")
		}
		if _, used := headRevoked[id]; used {
			return ChangeSet{}, errors.New("policy review: revoked id resurrection")
		}
		newLiteralBytes += len(entry.Identity.Literal)
		changes.AddedEntries = append(changes.AddedEntries, entry)
		changes.LogicalChanges++
	}
	for id := range candidateRevoked {
		if _, old := headRevoked[id]; old {
			continue
		}
		if _, pairedRemoval := removed[id]; pairedRemoval {
			continue
		}
		changes.NewRevokedIDs = append(changes.NewRevokedIDs, id)
		changes.LogicalChanges++
	}
	if changes.LogicalChanges == 0 || changes.LogicalChanges > MaxRevisionChanges {
		return ChangeSet{}, errors.New("policy review: revision logical-change bound violated")
	}
	if newLiteralBytes > MaxReviewedLiteralBytes {
		return ChangeSet{}, errors.New("policy review: newly reviewed literals exceed aggregate bound")
	}
	sort.Strings(changes.RemovedIDs)
	sort.Slice(changes.AddedEntries, func(i, j int) bool { return changes.AddedEntries[i].ID < changes.AddedEntries[j].ID })
	sort.Strings(changes.NewRevokedIDs)
	return changes, nil
}

func ValidOutOfBandID(id string) bool {
	const prefix = "pa_oob_"
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) {
		return false
	}
	for _, c := range id[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
