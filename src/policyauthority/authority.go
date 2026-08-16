// Package policyauthority owns policy-authority tuple, event, and lineage
// semantics without depending on signerkit, a store, HTTP, or Telegram.
package policyauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const (
	RequestTupleDomain = "sshgate-policy-request-tuple-v1\x00"
	AuditEventDomain   = "sshgate-policy-audit-event-v2\x00"
)

type RequestTuple struct {
	RequestID           string
	Purpose             string
	HostKeyFP           string
	ExpectedSignerKeyID string
	PayloadSHA256       string
	ExpectedHeadDigest  string
	Bootstrap           bool
}

func TupleDigest(tuple RequestTuple) string {
	h := sha256.New()
	_, _ = h.Write([]byte(RequestTupleDomain))
	for _, field := range []string{tuple.RequestID, tuple.Purpose, tuple.HostKeyFP, tuple.ExpectedSignerKeyID, tuple.PayloadSHA256, tuple.ExpectedHeadDigest} {
		writeLengthField(h, []byte(field))
	}
	if tuple.Bootstrap {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type AuditEvent struct {
	AuthorityID  string
	Purpose      string
	Principal    string
	RequestID    string
	TupleDigest  string
	Phase        string
	StateVersion uint64
}

func AuditEventID(event AuditEvent) string {
	h := sha256.New()
	_, _ = h.Write([]byte(AuditEventDomain))
	for _, field := range []string{event.AuthorityID, event.Purpose, event.Principal, event.RequestID, event.TupleDigest, event.Phase} {
		writeLengthField(h, []byte(field))
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], event.StateVersion)
	_, _ = h.Write(version[:])
	return hex.EncodeToString(h.Sum(nil))
}

func ValidAuthorityID(authorityID string) bool {
	const prefix = "pauth_"
	if len(authorityID) != len(prefix)+32 || !strings.HasPrefix(authorityID, prefix) {
		return false
	}
	for _, c := range authorityID[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type Head struct {
	ManifestEnvelope []byte
	BaseDigest       string
	SignerKeyID      string
	SignerPublicKey  ed25519.PublicKey
}

type Classification struct {
	NoOp      bool
	ErrorCode policywire.ErrorCode
}

// Classify validates bootstrap/successor lineage and hard review bounds. The
// caller supplies only an already-decoded request, an optional verified-store
// head representation, and the frozen public key.
func Classify(decoded policywire.DecodedRequest, head *Head, publicKey ed25519.PublicKey) Classification {
	candidate := decoded.Manifest
	if head == nil {
		if !decoded.Wire.Bootstrap || decoded.Wire.ExpectedHeadDigest != "" || candidate.Epoch != 1 || candidate.Revision != 1 {
			return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
		}
		if err := policyreview.ValidateBootstrap(candidate); err != nil {
			return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
		}
		return Classification{}
	}
	if decoded.Wire.Bootstrap {
		return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
	}
	if decoded.Wire.ExpectedHeadDigest != head.BaseDigest {
		return Classification{ErrorCode: policywire.ErrorStalePolicyHead}
	}
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil || keyID != head.SignerKeyID || keyID != decoded.Wire.ExpectedSignerKeyID || !bytes.Equal(publicKey, head.SignerPublicKey) {
		return Classification{ErrorCode: policywire.ErrorPolicyKeyTransitionRequired}
	}
	headManifest, err := policy.VerifyBaseManifest(head.ManifestEnvelope, publicKey)
	if err != nil {
		return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
	}
	headPayload, _, err := policy.DecodeBaseManifestEnvelope(head.ManifestEnvelope)
	if err != nil {
		return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
	}
	_, headDigest, err := policywire.PayloadDigests(headPayload)
	if err != nil || headDigest != head.BaseDigest {
		return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
	}
	if bytes.Equal(headPayload, decoded.Payload) {
		return Classification{NoOp: true}
	}
	if candidate.Host != headManifest.Host || candidate.Epoch != headManifest.Epoch {
		return Classification{ErrorCode: policywire.ErrorPolicyKeyTransitionRequired}
	}
	if headManifest.Revision == ^uint64(0) || candidate.Revision != headManifest.Revision+1 {
		return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
	}
	if err := policyreview.ValidateSuccessor(headManifest, candidate); err != nil {
		return Classification{ErrorCode: policywire.ErrorInvalidPolicyRequest}
	}
	return Classification{}
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeLengthField(writer hashWriter, field []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(field)
}
