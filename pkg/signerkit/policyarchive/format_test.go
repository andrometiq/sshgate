package policyarchive

import (
	"bytes"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
)

const (
	testArchiveID   = "parch_0123456789abcdef0123456789abcdef"
	testAuthorityID = "pauth_fedcba9876543210fedcba9876543210"
)

func TestEncodeBindingGolden(t *testing.T) {
	want := append([]byte("sshgate-policy-archive-binding-v1\x00\x00\x00\x00\x02\x01\x00\x00\x00\x26"), testArchiveID...)
	want = append(want, []byte("\x01\x00\x00\x00\x26")...)
	want = append(want, testAuthorityID...)

	got, err := EncodeBinding(testArchiveID, testAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("binding bytes = %x\nwant          = %x", got, want)
	}
}

func TestBindingCodecMatchesPolicyStoreABI(t *testing.T) {
	want, err := (policystore.ArchiveBinding{
		ArchiveID:   testArchiveID,
		AuthorityID: testAuthorityID,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeBinding(testArchiveID, testAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("archive binding codec diverged from policy-store ABI:\narchive = %x\nstore   = %x", got, want)
	}
}

func TestEncodeBindingRejectsNonCanonicalIdentifiers(t *testing.T) {
	tests := []struct {
		name        string
		archiveID   string
		authorityID string
	}{
		{name: "archive uppercase", archiveID: "parch_0123456789abcdef0123456789abcdeF", authorityID: testAuthorityID},
		{name: "archive whitespace", archiveID: testArchiveID + " ", authorityID: testAuthorityID},
		{name: "archive wrong prefix", archiveID: "pauth_0123456789abcdef0123456789abcdef", authorityID: testAuthorityID},
		{name: "authority uppercase", archiveID: testArchiveID, authorityID: "pauth_fedcba9876543210fedcba987654321A"},
		{name: "authority whitespace", archiveID: testArchiveID, authorityID: testAuthorityID + "\n"},
		{name: "authority wrong prefix", archiveID: testArchiveID, authorityID: "parch_fedcba9876543210fedcba9876543210"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := EncodeBinding(test.archiveID, test.authorityID); err == nil {
				t.Fatal("EncodeBinding accepted a non-canonical identifier")
			}
		})
	}
}

func TestTemporaryObjectNameGrammar(t *testing.T) {
	valid := ".pja-tmp-0123456789abcdef0123456789abcdef"
	if !validTemporaryObjectName(valid) {
		t.Fatalf("valid name %q was rejected", valid)
	}
	for _, invalid := range []string{
		"pja-tmp-0123456789abcdef0123456789abcdef",
		".pja-tmp-0123456789abcdef0123456789abcde",
		".pja-tmp-0123456789abcdef0123456789abcdef0",
		".pja-tmp-0123456789abcdef0123456789abcdeF",
		".pja-tmp-0123456789abcdef0123456789abcdef.pja",
	} {
		if validTemporaryObjectName(invalid) {
			t.Fatalf("invalid name %q was accepted", invalid)
		}
	}
}
