package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// SchemaV1 is the only policy payload schema accepted by this package.
	SchemaV1 uint64 = 1

	// Fixed collection and aggregate bounds. The payload decoder applies its
	// byte bound before JSON/base64 allocation; validation applies the more
	// specific entry and decoded-literal bounds below.
	MaxBaseEntries         = 256
	MaxRevokedPermitIDs    = 4096
	MaxTotalLiteralBytes   = 1 << 20
	MaxPolicyPayloadBytes  = 2 << 20
	MaxPolicyEnvelopeBytes = 3 << 20

	MaxPermitIDBytes  = 128
	MaxRequestIDBytes = 128
)

// Decision is the policy engine's codec-neutral result.
type Decision string

const (
	DecisionDirect   Decision = "direct"
	DecisionApproval Decision = "approval"
	DecisionDeny     Decision = "deny"
)

// MissAction selects the authoritative action for an ordinary permit miss.
type MissAction string

const (
	MissActionClassifier MissAction = "classifier"
	MissActionAsk        MissAction = "ask"
	MissActionDeny       MissAction = "deny"
)

// Growth selects how permanent policy authority may grow.
type Growth string

const (
	GrowthNone      Growth = "none"
	GrowthSignToAdd Growth = "sign-to-add"
	GrowthOutOfBand Growth = "out-of-band"
)

// EntrySource records which purpose produced a base-manifest entry.
type EntrySource string

const (
	EntrySourceOutOfBand EntrySource = "out-of-band"
)

// PermitPurpose is carried inside a permit certificate as defense in depth in
// addition to its distinct signing domain.
type PermitPurpose string

const (
	PermitPurposeAllowCommand PermitPurpose = "allow-command"
)

var (
	// ErrInvalidManifest marks an invalid base-manifest payload.
	ErrInvalidManifest = errors.New("policy: invalid base manifest")
	// ErrInvalidCertificate marks an invalid permit-certificate payload.
	ErrInvalidCertificate = errors.New("policy: invalid permit certificate")
)

// BaseEntry is a permanent exact command installed through the separate
// out-of-band administrative plane.
type BaseEntry struct {
	ID       string
	Identity CommandIdentity
	Source   EntrySource
}

// BaseManifest is the protected, host-bound policy base. Revision is ordered
// within an Epoch; rollback protection is a loader concern outside this
// package.
type BaseManifest struct {
	Schema           uint64
	Host             string
	Epoch            uint64
	MissAction       MissAction
	Growth           Growth
	Revision         uint64
	RevokedPermitIDs []string
	Entries          []BaseEntry
}

// Validate checks all schema, enum, collection, identity, and uniqueness
// invariants. It does not check filesystem ownership or a protected epoch
// anchor.
func (m BaseManifest) Validate() error {
	if m.Schema != SchemaV1 {
		return fmt.Errorf("%w: unsupported schema %d", ErrInvalidManifest, m.Schema)
	}
	if err := validateHostFingerprint(m.Host); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if m.Epoch == 0 {
		return fmt.Errorf("%w: epoch must be greater than zero", ErrInvalidManifest)
	}
	if m.Revision == 0 {
		return fmt.Errorf("%w: revision must be greater than zero", ErrInvalidManifest)
	}
	switch m.MissAction {
	case MissActionClassifier, MissActionAsk, MissActionDeny:
	default:
		return fmt.Errorf("%w: unknown miss_action %q", ErrInvalidManifest, m.MissAction)
	}
	switch m.Growth {
	case GrowthNone, GrowthSignToAdd, GrowthOutOfBand:
	default:
		return fmt.Errorf("%w: unknown growth %q", ErrInvalidManifest, m.Growth)
	}
	if m.MissAction == MissActionClassifier && m.Growth != GrowthNone {
		return fmt.Errorf("%w: classifier miss_action requires growth=none", ErrInvalidManifest)
	}
	if m.Growth == GrowthSignToAdd && m.MissAction != MissActionAsk {
		return fmt.Errorf("%w: sign-to-add growth requires miss_action=ask", ErrInvalidManifest)
	}
	if len(m.Entries) > MaxBaseEntries {
		return fmt.Errorf("%w: %d entries; maximum is %d", ErrTooLarge, len(m.Entries), MaxBaseEntries)
	}
	if len(m.RevokedPermitIDs) > MaxRevokedPermitIDs {
		return fmt.Errorf("%w: %d revoked permit ids; maximum is %d", ErrTooLarge, len(m.RevokedPermitIDs), MaxRevokedPermitIDs)
	}

	revoked := make(map[string]struct{}, len(m.RevokedPermitIDs))
	for n, id := range m.RevokedPermitIDs {
		if err := validatePermitID(id); err != nil {
			return fmt.Errorf("%w: revoked_permit_ids[%d]: %v", ErrInvalidManifest, n, err)
		}
		if _, exists := revoked[id]; exists {
			return fmt.Errorf("%w: duplicate revoked permit id %q", ErrInvalidManifest, id)
		}
		revoked[id] = struct{}{}
	}

	entries := make(map[string]struct{}, len(m.Entries))
	totalLiteral := 0
	for n, entry := range m.Entries {
		if err := validatePermitID(entry.ID); err != nil {
			return fmt.Errorf("%w: entries[%d].id: %v", ErrInvalidManifest, n, err)
		}
		if _, exists := entries[entry.ID]; exists {
			return fmt.Errorf("%w: duplicate entry id %q", ErrInvalidManifest, entry.ID)
		}
		if _, isRevoked := revoked[entry.ID]; isRevoked {
			return fmt.Errorf("%w: entry id %q is also revoked", ErrInvalidManifest, entry.ID)
		}
		entries[entry.ID] = struct{}{}
		if entry.Source != EntrySourceOutOfBand {
			return fmt.Errorf("%w: entries[%d] has unknown source %q", ErrInvalidManifest, n, entry.Source)
		}
		if err := entry.Identity.Validate(); err != nil {
			return fmt.Errorf("%w: entries[%d]: %v", ErrInvalidManifest, n, err)
		}
		totalLiteral += len(entry.Identity.Literal)
		if totalLiteral > MaxTotalLiteralBytes {
			return fmt.Errorf("%w: decoded entry literals exceed %d bytes", ErrTooLarge, MaxTotalLiteralBytes)
		}
	}
	return nil
}

// PermitCertificate is the dedicated sign-to-add capability for one exact
// command under one host and base epoch/digest. It is not an ordinary command
// signature and cannot be used across signing domains.
type PermitCertificate struct {
	Schema     uint64
	Purpose    PermitPurpose
	PermitID   string
	RequestID  string
	Host       string
	BaseEpoch  uint64
	BaseDigest [sha256.Size]byte
	Identity   CommandIdentity
}

// Validate checks all certificate invariants.
func (c PermitCertificate) Validate() error {
	if c.Schema != SchemaV1 {
		return fmt.Errorf("%w: unsupported schema %d", ErrInvalidCertificate, c.Schema)
	}
	if c.Purpose != PermitPurposeAllowCommand {
		return fmt.Errorf("%w: unknown purpose %q", ErrInvalidCertificate, c.Purpose)
	}
	if err := validatePermitID(c.PermitID); err != nil {
		return fmt.Errorf("%w: permit_id: %v", ErrInvalidCertificate, err)
	}
	if err := validateOpaqueID("request_id", c.RequestID, MaxRequestIDBytes, false); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	if err := validateHostFingerprint(c.Host); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	if c.BaseEpoch == 0 {
		return fmt.Errorf("%w: base_epoch must be greater than zero", ErrInvalidCertificate)
	}
	if bytes.Equal(c.BaseDigest[:], make([]byte, sha256.Size)) {
		return fmt.Errorf("%w: base_digest must not be all zero", ErrInvalidCertificate)
	}
	if err := c.Identity.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	return nil
}

func validatePermitID(id string) error {
	return validateOpaqueID("permit id", id, MaxPermitIDBytes, true)
}

func validateOpaqueID(field, id string, max int, requirePermitPrefix bool) error {
	if id == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(id) > max {
		return fmt.Errorf("%s is %d bytes; maximum is %d", field, len(id), max)
	}
	if requirePermitPrefix && (len(id) < 4 || id[:3] != "pa_") {
		return fmt.Errorf("%s must start with pa_", field)
	}
	for _, b := range []byte(id) {
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == '-' || b == '_') {
			return fmt.Errorf("%s contains non-canonical byte 0x%02x", field, b)
		}
	}
	return nil
}

func validateHostFingerprint(host string) error {
	const prefix = "SHA256:"
	if len(host) != len(prefix)+43 || host[:len(prefix)] != prefix {
		return errors.New("host must be a canonical OpenSSH SHA256 fingerprint")
	}
	raw, err := base64.RawStdEncoding.DecodeString(host[len(prefix):])
	if err != nil || len(raw) != sha256.Size || base64.RawStdEncoding.EncodeToString(raw) != host[len(prefix):] {
		return errors.New("host must be a canonical OpenSSH SHA256 fingerprint")
	}
	return nil
}
