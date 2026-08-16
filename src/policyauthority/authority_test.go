package policyauthority

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func TestAuditEventIDV2GoldenAndAuthoritySeparation(t *testing.T) {
	event := AuditEvent{
		Purpose: policywire.Purpose, Principal: "ab", RequestID: "c",
		TupleDigest: "d", Phase: "submission", StateVersion: 1,
	}
	const emptyAuthorityGolden = "cf3c788236c0d934e37ab3c3cd85b2676a1799437dc957c718a577f946e1c2cb"
	if got := AuditEventID(event); got != emptyAuthorityGolden {
		t.Fatalf("empty-authority v2 golden = %q; want %q", got, emptyAuthorityGolden)
	}
	event.AuthorityID = "pauth_0123456789abcdef0123456789abcdef"
	if got := AuditEventID(event); got == emptyAuthorityGolden || got != AuditEventID(event) {
		t.Fatalf("authority-bound event ID = %q", got)
	}
}

func TestTupleDigestSeparatesLengthBoundaries(t *testing.T) {
	first := RequestTuple{RequestID: "ab", Purpose: "c", HostKeyFP: "d", ExpectedSignerKeyID: "e", PayloadSHA256: "f"}
	second := first
	second.RequestID, second.Purpose = "a", "bc"
	if TupleDigest(first) == TupleDigest(second) {
		t.Fatal("length-framed tuples collided")
	}
}

func TestClassifyRevalidatesHeadKeyDigestAndLineage(t *testing.T) {
	seed := bytes.Repeat([]byte{0x31}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	host := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	headManifest := policy.BaseManifest{Schema: 1, Host: host, Epoch: 1, Revision: 1, MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone}
	headEnvelope, err := policy.SignBaseManifest(private, headManifest)
	if err != nil {
		t.Fatal(err)
	}
	headPayload, _, _ := policy.DecodeBaseManifestEnvelope(headEnvelope)
	_, headDigest, _ := policywire.PayloadDigests(headPayload)
	candidate := headManifest
	candidate.Revision = 2
	candidate.MissAction = policy.MissActionAsk
	candidate.Growth = policy.GrowthOutOfBand
	payload, err := policy.MarshalBaseManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	request, err := policywire.NewRequest("pm_0123456789abcdef0123456789abcdef", host, keyID, payload, headDigest, false)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeRequest(mustRequestBytes(t, request))
	if err != nil {
		t.Fatal(err)
	}
	head := &Head{ManifestEnvelope: headEnvelope, BaseDigest: headDigest, SignerKeyID: keyID, SignerPublicKey: public}
	if got := Classify(decoded, head, public); got.ErrorCode != "" || got.NoOp {
		t.Fatalf("valid successor classification = %#v", got)
	}
	badDigest := *head
	badDigest.BaseDigest = strings.Repeat("f", 64)
	if got := Classify(decoded, &badDigest, public); got.ErrorCode == "" {
		t.Fatal("unverified head digest accepted")
	}
	badKey := *head
	badKey.SignerPublicKey = bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)
	if got := Classify(decoded, &badKey, public); got.ErrorCode != policywire.ErrorPolicyKeyTransitionRequired {
		t.Fatalf("raw key mismatch classification = %#v", got)
	}
}

func mustRequestBytes(t testing.TB, request policywire.Request) []byte {
	t.Helper()
	body, err := policywire.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
