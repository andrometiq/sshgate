package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

var (
	// ErrNotCanonical marks otherwise-decodable JSON or base64 that is not in
	// the one frozen canonical representation emitted by this package.
	ErrNotCanonical = errors.New("policy: non-canonical encoding")
	// ErrInvalidEnvelope marks an invalid signed-envelope container.
	ErrInvalidEnvelope = errors.New("policy: invalid signed envelope")
)

type identityWire struct {
	Codec      string `json:"codec"`
	LiteralB64 string `json:"literal_b64"`
	SHA256     string `json:"sha256"`
}

type baseEntryWire struct {
	ID         string      `json:"id"`
	Codec      string      `json:"codec"`
	LiteralB64 string      `json:"literal_b64"`
	SHA256     string      `json:"sha256"`
	Source     EntrySource `json:"source"`
}

// Every payload wire field is explicit: its declaration order freezes JSON
// field order and prevents accidental shape drift during model refactors.
type baseManifestWire struct {
	Schema           uint64          `json:"schema"`
	Host             string          `json:"host"`
	Epoch            uint64          `json:"epoch"`
	MissAction       MissAction      `json:"miss_action"`
	Growth           Growth          `json:"growth"`
	Revision         uint64          `json:"revision"`
	RevokedPermitIDs []string        `json:"revoked_permit_ids"`
	Entries          []baseEntryWire `json:"entries"`
}

type permitCertificateWire struct {
	Schema     uint64        `json:"schema"`
	Purpose    PermitPurpose `json:"purpose"`
	PermitID   string        `json:"permit_id"`
	RequestID  string        `json:"request_id"`
	Host       string        `json:"host"`
	BaseEpoch  uint64        `json:"base_epoch"`
	BaseDigest string        `json:"base_digest"`
	Codec      string        `json:"codec"`
	LiteralB64 string        `json:"literal_b64"`
	SHA256     string        `json:"sha256"`
}

type signedEnvelopeWire struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// MarshalBaseManifest validates m and returns its one canonical JSON payload.
func MarshalBaseManifest(m BaseManifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	w := baseManifestWire{
		Schema:           m.Schema,
		Host:             m.Host,
		Epoch:            m.Epoch,
		MissAction:       m.MissAction,
		Growth:           m.Growth,
		Revision:         m.Revision,
		RevokedPermitIDs: append([]string(nil), m.RevokedPermitIDs...),
		Entries:          make([]baseEntryWire, len(m.Entries)),
	}
	if w.RevokedPermitIDs == nil {
		w.RevokedPermitIDs = []string{}
	}
	sort.Strings(w.RevokedPermitIDs)
	entries := append([]BaseEntry(nil), m.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for n, entry := range entries {
		identity := encodeIdentity(entry.Identity)
		w.Entries[n] = baseEntryWire{
			ID:         entry.ID,
			Codec:      identity.Codec,
			LiteralB64: identity.LiteralB64,
			SHA256:     identity.SHA256,
			Source:     entry.Source,
		}
	}
	if w.Entries == nil {
		w.Entries = []baseEntryWire{}
	}
	out, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("marshal base manifest: %w", err)
	}
	if len(out) > MaxPolicyPayloadBytes {
		return nil, fmt.Errorf("%w: base manifest payload is %d bytes; maximum is %d", ErrTooLarge, len(out), MaxPolicyPayloadBytes)
	}
	return out, nil
}

// ParseBaseManifest accepts only the exact canonical JSON emitted by
// MarshalBaseManifest. It rejects duplicate/unknown keys, trailing values,
// non-canonical base64 or hex, and all semantic invariant violations.
func ParseBaseManifest(payload []byte) (BaseManifest, error) {
	if err := checkPayloadSize(payload); err != nil {
		return BaseManifest{}, err
	}
	var w baseManifestWire
	if err := decodeCanonicalJSON(payload, &w); err != nil {
		return BaseManifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	m := BaseManifest{
		Schema:           w.Schema,
		Host:             w.Host,
		Epoch:            w.Epoch,
		MissAction:       w.MissAction,
		Growth:           w.Growth,
		Revision:         w.Revision,
		RevokedPermitIDs: append([]string(nil), w.RevokedPermitIDs...),
		Entries:          make([]BaseEntry, len(w.Entries)),
	}
	for n, entry := range w.Entries {
		identity, err := decodeIdentity(identityWire{
			Codec: entry.Codec, LiteralB64: entry.LiteralB64, SHA256: entry.SHA256,
		})
		if err != nil {
			return BaseManifest{}, fmt.Errorf("%w: entries[%d]: %v", ErrInvalidManifest, n, err)
		}
		m.Entries[n] = BaseEntry{ID: entry.ID, Identity: identity, Source: entry.Source}
	}
	if err := m.Validate(); err != nil {
		return BaseManifest{}, err
	}
	canonical, err := MarshalBaseManifest(m)
	if err != nil {
		return BaseManifest{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return BaseManifest{}, fmt.Errorf("%w: base manifest payload", ErrNotCanonical)
	}
	return m, nil
}

// MarshalPermitCertificate validates c and returns its one canonical JSON
// payload.
func MarshalPermitCertificate(c PermitCertificate) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	w := permitCertificateWire{
		Schema:     c.Schema,
		Purpose:    c.Purpose,
		PermitID:   c.PermitID,
		RequestID:  c.RequestID,
		Host:       c.Host,
		BaseEpoch:  c.BaseEpoch,
		BaseDigest: encodeDigest(c.BaseDigest),
		Codec:      c.Identity.Codec,
		LiteralB64: base64.StdEncoding.EncodeToString(c.Identity.Literal),
		SHA256:     encodeDigest(c.Identity.Digest),
	}
	out, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("marshal permit certificate: %w", err)
	}
	if len(out) > MaxPolicyPayloadBytes {
		return nil, fmt.Errorf("%w: permit certificate payload is %d bytes; maximum is %d", ErrTooLarge, len(out), MaxPolicyPayloadBytes)
	}
	return out, nil
}

// ParsePermitCertificate accepts only the exact canonical JSON emitted by
// MarshalPermitCertificate.
func ParsePermitCertificate(payload []byte) (PermitCertificate, error) {
	if err := checkPayloadSize(payload); err != nil {
		return PermitCertificate{}, err
	}
	var w permitCertificateWire
	if err := decodeCanonicalJSON(payload, &w); err != nil {
		return PermitCertificate{}, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	baseDigest, err := decodeDigest(w.BaseDigest)
	if err != nil {
		return PermitCertificate{}, fmt.Errorf("%w: base_digest: %v", ErrInvalidCertificate, err)
	}
	identity, err := decodeIdentity(identityWire{Codec: w.Codec, LiteralB64: w.LiteralB64, SHA256: w.SHA256})
	if err != nil {
		return PermitCertificate{}, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	c := PermitCertificate{
		Schema:     w.Schema,
		Purpose:    w.Purpose,
		PermitID:   w.PermitID,
		RequestID:  w.RequestID,
		Host:       w.Host,
		BaseEpoch:  w.BaseEpoch,
		BaseDigest: baseDigest,
		Identity:   identity,
	}
	if err := c.Validate(); err != nil {
		return PermitCertificate{}, err
	}
	canonical, err := MarshalPermitCertificate(c)
	if err != nil {
		return PermitCertificate{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return PermitCertificate{}, fmt.Errorf("%w: permit certificate payload", ErrNotCanonical)
	}
	return c, nil
}

func encodeIdentity(identity CommandIdentity) identityWire {
	return identityWire{
		Codec:      identity.Codec,
		LiteralB64: base64.StdEncoding.EncodeToString(identity.Literal),
		SHA256:     encodeDigest(identity.Digest),
	}
}

func decodeIdentity(w identityWire) (CommandIdentity, error) {
	if w.Codec != CodecShellExactV1 {
		return CommandIdentity{}, fmt.Errorf("%w: unsupported codec %q", ErrInvalidIdentity, w.Codec)
	}
	if w.LiteralB64 == "" {
		return CommandIdentity{}, fmt.Errorf("%w: literal_b64 is empty", ErrInvalidIdentity)
	}
	if base64.StdEncoding.DecodedLen(len(w.LiteralB64)) > MaxLiteralBytes {
		return CommandIdentity{}, fmt.Errorf("%w: encoded literal exceeds %d decoded bytes", ErrTooLarge, MaxLiteralBytes)
	}
	literal, err := base64.StdEncoding.DecodeString(w.LiteralB64)
	if err != nil || base64.StdEncoding.EncodeToString(literal) != w.LiteralB64 {
		return CommandIdentity{}, fmt.Errorf("%w: literal_b64 is not canonical standard base64", ErrInvalidIdentity)
	}
	digest, err := decodeDigest(w.SHA256)
	if err != nil {
		return CommandIdentity{}, fmt.Errorf("%w: sha256: %v", ErrInvalidIdentity, err)
	}
	identity := CommandIdentity{Codec: w.Codec, Literal: literal, Digest: digest}
	if err := identity.Validate(); err != nil {
		return CommandIdentity{}, err
	}
	return identity, nil
}

func encodeDigest(digest [sha256.Size]byte) string {
	return hex.EncodeToString(digest[:])
}

func decodeDigest(s string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	if len(s) != hex.EncodedLen(sha256.Size) {
		return out, errors.New("must be 64 lowercase hexadecimal characters")
	}
	decoded, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(decoded) != s {
		return out, errors.New("must be 64 lowercase hexadecimal characters")
	}
	copy(out[:], decoded)
	return out, nil
}

func checkPayloadSize(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("policy: empty payload")
	}
	if len(payload) > MaxPolicyPayloadBytes {
		return fmt.Errorf("%w: payload is %d bytes; maximum is %d", ErrTooLarge, len(payload), MaxPolicyPayloadBytes)
	}
	return nil
}

func decodeCanonicalJSON(data []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return err
	}
	return nil
}

// rejectDuplicateJSONKeys scans every object, including nested future shapes.
// encoding/json otherwise accepts duplicate known fields with last-one-wins
// semantics, which is not suitable for signed policy payloads.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONValue(dec); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return err
	}
	return nil
}

func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	return nil
}

func requireEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}
