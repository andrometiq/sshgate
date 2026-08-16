package policystore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

const (
	ConfigDigestDomain            = "sshgate-policy-config-digest-v1"
	AccountingVersion             = "sshgate-policy-logical-bytes-v3"
	ArchiveRecordVersion          = "sshgate-policy-archive-record-v3"
	ArchiveBindingVersion         = "sshgate-policy-archive-binding-v1"
	DurableAuditVersion           = "sshgate-policy-durable-audit-v2"
	AuditEventVersion             = "sshgate-policy-audit-event-v2"
	VoterEligibilityVersion       = "sshgate-policy-voter-eligibility-v1"
	RejectionWindowLimit          = 16
	RejectionWindowSeconds        = 600
	RejectionRetainedRowLimit     = 64
	MaxRejectionReservedBytes     = 8 << 20
	DefaultRejectionReservedBytes = MaxRejectionReservedBytes
	RecoveryLeaseMaxTTLSeconds    = 120
	RosterSweepSeconds            = 30
	MaxHeads                      = 256
	MaxFullRequests               = 1024
	MaxLogicalBytes               = 256 << 20
	MaxActiveGlobal               = 256
	MaxActivePerPrincipal         = 64
	MaxVotesPerRequest            = 256
)

var ErrInvalidConfig = errors.New("policy store: invalid configuration")

type ConfigDigestInput struct {
	RequesterOperatorID                   string
	RequiredApprovals                     uint64
	DenyVeto                              bool
	AllowSelfApprove                      bool
	PolicyVoterRole                       string
	VoterEligibilityVersion               string
	VoteStepUpRequired                    bool
	VoteAuthMethodsJSON                   []byte
	MaxHeads                              uint64
	MaxRequests                           uint64
	MaxLogicalBytes                       uint64
	MaxActiveGlobal                       uint64
	MaxActivePerPrincipal                 uint64
	MaxVotesPerRequest                    uint64
	MaxRejectionReservedBytesPerPrincipal uint64
	ArchiveID                             string
	ReviewRendererVersion                 string
	ReviewRulesDigest                     string
}

func DefaultConfigDigestInput() ConfigDigestInput {
	return ConfigDigestInput{
		MaxHeads: MaxHeads, MaxRequests: MaxFullRequests,
		MaxLogicalBytes: MaxLogicalBytes, MaxActiveGlobal: MaxActiveGlobal,
		MaxActivePerPrincipal:                 MaxActivePerPrincipal,
		MaxVotesPerRequest:                    MaxVotesPerRequest,
		MaxRejectionReservedBytesPerPrincipal: DefaultRejectionReservedBytes,
	}
}

func (input ConfigDigestInput) Validate() error {
	if err := ValidateIdentity(input.RequesterOperatorID); err != nil {
		return fmt.Errorf("%w: requester_operator_id: %v", ErrInvalidConfig, err)
	}
	if input.RequiredApprovals == 0 || input.RequiredApprovals > MaxVotesPerRequest {
		return fmt.Errorf("%w: required_approvals %d", ErrInvalidConfig, input.RequiredApprovals)
	}
	if input.PolicyVoterRole != "operator" || input.ReviewRendererVersion != "sshgate-policy-review-v2" ||
		!validVoterEligibilityVersion(input.VoterEligibilityVersion) || len(input.VoteAuthMethodsJSON) == 0 {
		return fmt.Errorf("%w: invalid policy value", ErrInvalidConfig)
	}
	wantMethods := `["session"]`
	if input.VoteStepUpRequired {
		wantMethods = `["totp"]`
	}
	if string(input.VoteAuthMethodsJSON) != wantMethods {
		return fmt.Errorf("%w: vote auth methods are not the canonical initial-release set", ErrInvalidConfig)
	}
	if !validLowerHex(input.ReviewRulesDigest, 64) {
		return fmt.Errorf("%w: invalid review rules digest", ErrInvalidConfig)
	}
	if !ValidArchiveID(input.ArchiveID) {
		return fmt.Errorf("%w: invalid archive ID", ErrInvalidConfig)
	}
	if input.MaxHeads != MaxHeads || input.MaxRequests != MaxFullRequests ||
		input.MaxLogicalBytes != MaxLogicalBytes || input.MaxActiveGlobal != MaxActiveGlobal ||
		input.MaxActivePerPrincipal != MaxActivePerPrincipal || input.MaxVotesPerRequest != MaxVotesPerRequest {
		return fmt.Errorf("%w: fixed quota mismatch", ErrInvalidConfig)
	}
	if input.MaxRejectionReservedBytesPerPrincipal == 0 || input.MaxRejectionReservedBytesPerPrincipal > MaxRejectionReservedBytes {
		return fmt.Errorf("%w: rejection byte cap %d", ErrInvalidConfig, input.MaxRejectionReservedBytesPerPrincipal)
	}
	return nil
}

func validVoterEligibilityVersion(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return value == VoterEligibilityVersion
}

// ConfigDigest applies the frozen R47 framing and field order. It intentionally
// hashes the supplied persisted image without semantic validation so a safety
// scan can reproduce and compare even a mismatching row. Trust boundaries call
// ConfigDigestInput.Validate separately before accepting the configuration.
func ConfigDigest(input ConfigDigestInput) (string, error) {
	boolean := func(value bool) []byte {
		if value {
			return []byte{'1'}
		}
		return []byte{'0'}
	}
	integer := func(value uint64) []byte { return []byte(strconv.FormatUint(value, 10)) }
	fields := [][]byte{
		[]byte(input.RequesterOperatorID), integer(input.RequiredApprovals),
		boolean(input.DenyVeto), boolean(input.AllowSelfApprove),
		[]byte(input.PolicyVoterRole), []byte(input.VoterEligibilityVersion),
		boolean(input.VoteStepUpRequired), input.VoteAuthMethodsJSON,
		integer(input.MaxHeads), integer(input.MaxRequests), integer(input.MaxLogicalBytes),
		integer(input.MaxActiveGlobal), integer(input.MaxActivePerPrincipal), integer(input.MaxVotesPerRequest),
		integer(RejectionWindowLimit), integer(RejectionWindowSeconds), integer(RejectionRetainedRowLimit),
		integer(input.MaxRejectionReservedBytesPerPrincipal), integer(RecoveryLeaseMaxTTLSeconds),
		integer(RosterSweepSeconds), []byte(DurableAuditVersion), []byte(AccountingVersion),
		[]byte(ArchiveRecordVersion), []byte(AuditEventVersion), []byte(input.ArchiveID),
		[]byte(input.ReviewRendererVersion), []byte(input.ReviewRulesDigest),
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(ConfigDigestDomain))
	_, _ = hash.Write([]byte{0})
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(fields)))
	_, _ = hash.Write(count[:])
	for _, field := range fields {
		if err := writeLengthPrefixed(hash, field); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeLengthPrefixed(writer byteWriter, value []byte) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return errors.New("policy store: field exceeds uint32 framing")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	if _, err := writer.Write(size[:]); err != nil {
		return err
	}
	_, err := writer.Write(value)
	return err
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := range value {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func ValidArchiveID(value string) bool {
	return len(value) == 38 && value[:6] == "parch_" && validLowerHex(value[6:], 32)
}
