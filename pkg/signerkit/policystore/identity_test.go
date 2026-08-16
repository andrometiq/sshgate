package policystore

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateIdentity(t *testing.T) {
	t.Parallel()
	validMultibyte := strings.Repeat("é", 64)
	for _, identity := range []string{"operator", strings.Repeat("x", 128), validMultibyte} {
		if err := ValidateIdentity(identity); err != nil {
			t.Fatalf("ValidateIdentity(%q): %v", identity, err)
		}
	}
	invalid := []string{"", strings.Repeat("x", 129), "a\x00b", string([]byte{0xff})}
	for _, identity := range invalid {
		if err := ValidateIdentity(identity); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("ValidateIdentity(%q) error = %v", identity, err)
		}
	}
}

func TestFreezeIdentitiesCanonicalSortedUnique(t *testing.T) {
	t.Parallel()
	encoded, digest, err := FreezeIdentities([]string{"zeta", "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `["alpha","zeta"]` || !validLowerHex(digest, 64) {
		t.Fatalf("frozen = %s %s", encoded, digest)
	}
	decoded, err := DecodeFrozenIdentities(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0] != "alpha" || decoded[1] != "zeta" {
		t.Fatalf("decoded = %#v", decoded)
	}
	if _, _, err := FreezeIdentities([]string{"same", "same"}); err == nil {
		t.Fatal("duplicate voter accepted")
	}
	if _, err := DecodeFrozenIdentities([]byte(`["zeta","alpha"]`)); err == nil {
		t.Fatal("unsorted voter JSON accepted")
	}
}
