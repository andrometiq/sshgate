package policystore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxIdentityBytes = 128

var ErrInvalidIdentity = errors.New("policy store: invalid policy identity")

// ValidateIdentity applies the one grammar shared by principals, requesters,
// operators, eligible-voter IDs, and policy-enabled machine client IDs.
func ValidateIdentity(identity string) error {
	switch {
	case identity == "":
		return fmt.Errorf("%w: empty", ErrInvalidIdentity)
	case len(identity) > MaxIdentityBytes:
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrInvalidIdentity, len(identity), MaxIdentityBytes)
	case strings.IndexByte(identity, 0) >= 0:
		return fmt.Errorf("%w: contains NUL", ErrInvalidIdentity)
	case !utf8.ValidString(identity):
		return fmt.Errorf("%w: invalid UTF-8", ErrInvalidIdentity)
	default:
		return nil
	}
}

// FreezeIdentities validates, sorts by raw UTF-8 bytes, rejects duplicates,
// and returns the one canonical roster JSON plus its lowercase SHA-256.
func FreezeIdentities(identities []string) ([]byte, string, error) {
	if len(identities) > MaxVotesPerRequest {
		return nil, "", fmt.Errorf("%w: %d voters exceeds %d", ErrInvalidIdentity, len(identities), MaxVotesPerRequest)
	}
	frozen := append([]string(nil), identities...)
	if err := ValidateIdentities(frozen); err != nil {
		return nil, "", err
	}
	sort.Strings(frozen)
	for index := 1; index < len(frozen); index++ {
		if frozen[index] == frozen[index-1] {
			return nil, "", fmt.Errorf("%w: duplicate %q", ErrInvalidIdentity, frozen[index])
		}
	}
	if frozen == nil {
		frozen = []string{}
	}
	encoded, err := json.Marshal(frozen)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(digest[:]), nil
}

func DecodeFrozenIdentities(encoded []byte) ([]string, error) {
	var identities []string
	if err := json.Unmarshal(encoded, &identities); err != nil {
		return nil, fmt.Errorf("policy store: frozen identities: %w", err)
	}
	canonical, _, err := FreezeIdentities(identities)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, errors.New("policy store: frozen identities are not canonical sorted JSON")
	}
	return identities, nil
}

func ValidateIdentities(identities []string) error {
	for index, identity := range identities {
		if err := ValidateIdentity(identity); err != nil {
			return fmt.Errorf("identity %d: %w", index, err)
		}
	}
	return nil
}
