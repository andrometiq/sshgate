package policywire

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/karthikeyan5/sshgate/src/policy"
)

// VerifyResponseForRequest verifies that response belongs to the exact policy
// request and frozen policy-authority key supplied by the caller. It performs
// tuple correlation for every status. For an approved response it also
// verifies the Ed25519 envelope and requires its payload to be byte-for-byte
// identical to the canonical payload carried by request.
//
// This function is pure: it does not perform I/O, retry, consult current key
// configuration, or generate a replacement request ID. Callers recovering an
// older request must pass the key frozen for that request.
func VerifyResponseForRequest(request Request, response DecodedResponse, frozenPublicKey ed25519.PublicKey) error {
	requestPayload, requestManifest, err := validateRequest(request)
	if err != nil {
		return fmt.Errorf("policy wire correlation: request: %w", err)
	}

	validatedEnvelope, err := validateResponse(response.Wire)
	if err != nil {
		return fmt.Errorf("policy wire correlation: response: %w", err)
	}
	if !bytes.Equal(validatedEnvelope, response.ManifestEnvelope) {
		return fmt.Errorf("policy wire correlation: decoded response envelope does not match response wire")
	}

	keyID, err := policy.SignerKeyID(frozenPublicKey)
	if err != nil {
		return fmt.Errorf("policy wire correlation: frozen authority key: %w", err)
	}
	if request.ExpectedSignerKeyID != keyID {
		return fmt.Errorf("policy wire correlation: request signer key %q does not match frozen key %q", request.ExpectedSignerKeyID, keyID)
	}

	payloadSHA256, baseDigest, err := PayloadDigests(requestPayload)
	if err != nil {
		return fmt.Errorf("policy wire correlation: request payload: %w", err)
	}
	if response.Wire.RequestID != request.RequestID {
		return fmt.Errorf("policy wire correlation: response request_id %q does not match request %q", response.Wire.RequestID, request.RequestID)
	}
	if response.Wire.Purpose != Purpose {
		return fmt.Errorf("policy wire correlation: response purpose %q does not match %q", response.Wire.Purpose, Purpose)
	}
	if response.Wire.PayloadSHA256 != payloadSHA256 {
		return fmt.Errorf("policy wire correlation: response payload_sha256 does not match request payload")
	}
	if response.Wire.BaseDigest != baseDigest {
		return fmt.Errorf("policy wire correlation: response base_digest does not match request payload")
	}
	if response.Wire.SignerKeyID != keyID {
		return fmt.Errorf("policy wire correlation: response signer_key_id %q does not match frozen key %q", response.Wire.SignerKeyID, keyID)
	}

	if response.Wire.Status != StatusApproved {
		return nil
	}
	verifiedManifest, err := policy.VerifyBaseManifest(response.ManifestEnvelope, frozenPublicKey)
	if err != nil {
		return fmt.Errorf("policy wire correlation: approved envelope signature: %w", err)
	}
	approvedPayload, _, err := policy.DecodeBaseManifestEnvelope(response.ManifestEnvelope)
	if err != nil {
		return fmt.Errorf("policy wire correlation: approved envelope: %w", err)
	}
	if !bytes.Equal(approvedPayload, requestPayload) {
		return fmt.Errorf("policy wire correlation: approved envelope payload does not byte-match request payload")
	}
	if requestManifest.Host != request.HostKeyFP || verifiedManifest.Host != request.HostKeyFP {
		return fmt.Errorf("policy wire correlation: approved envelope host does not match request host %q", request.HostKeyFP)
	}
	return nil
}
