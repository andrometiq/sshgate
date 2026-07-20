package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sampleManifest(t testing.TB) BaseManifest {
	t.Helper()
	return BaseManifest{
		Schema:           SchemaV1,
		Host:             validHost(),
		Epoch:            3,
		MissAction:       MissActionAsk,
		Growth:           GrowthSignToAdd,
		Revision:         7,
		RevokedPermitIDs: []string{"pa_retired_01"},
		Entries: []BaseEntry{{
			ID:       "pa_status_nginx",
			Identity: mustIdentity(t, "systemctl status nginx"),
			Source:   EntrySourceOutOfBand,
		}},
	}
}

func sampleCertificate(t testing.TB) PermitCertificate {
	t.Helper()
	manifest := sampleManifest(t)
	digest, err := BaseManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return PermitCertificate{
		Schema:     SchemaV1,
		Purpose:    PermitPurposeAllowCommand,
		PermitID:   "pa_restart_nginx",
		RequestID:  "req_01HZY8YQ5K",
		Host:       validHost(),
		BaseEpoch:  manifest.Epoch,
		BaseDigest: digest,
		Identity:   mustIdentity(t, "systemctl restart nginx"),
	}
}

func TestBaseManifestPayload_Golden(t *testing.T) {
	payload, err := MarshalBaseManifest(sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"schema":1,"host":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","epoch":3,"miss_action":"ask","growth":"sign-to-add","revision":7,"revoked_permit_ids":["pa_retired_01"],"entries":[{"id":"pa_status_nginx","codec":"shell-exact-v1","literal_b64":"c3lzdGVtY3RsIHN0YXR1cyBuZ2lueA==","sha256":"06617dbf00a554f63e04fa6d53eac01606adde27e0e6e68c5ca1b7eefff47499","source":"out-of-band"}]}`
	if got := string(payload); got != want {
		t.Fatalf("canonical base payload drifted:\n got  %s\n want %s", got, want)
	}
	parsed, err := ParseBaseManifest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, sampleManifest(t)) {
		t.Fatalf("round trip drift:\n got  %#v\n want %#v", parsed, sampleManifest(t))
	}
}

func TestSignerKeyIDDomainAndShape(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	got, err := SignerKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	material := append([]byte("sshgate-policy-key-id-v1\x00"), publicKey...)
	wantDigest := sha256.Sum256(material)
	want := hex.EncodeToString(wantDigest[:])
	if got != want || len(got) != 64 || got != strings.ToLower(got) {
		t.Fatalf("SignerKeyID = %q; want %q", got, want)
	}
	if _, err := SignerKeyID(publicKey[:31]); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("short key error = %v; want ErrBadSignature", err)
	}
}

func TestPermitCertificatePayload_Golden(t *testing.T) {
	payload, err := MarshalPermitCertificate(sampleCertificate(t))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"schema":1,"purpose":"allow-command","permit_id":"pa_restart_nginx","request_id":"req_01HZY8YQ5K","host":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base_epoch":3,"base_digest":"9b088ebec0daf90362dd6d99a6adc5e25b1cf834a22edbdb55a55e92bcfcfea8","codec":"shell-exact-v1","literal_b64":"c3lzdGVtY3RsIHJlc3RhcnQgbmdpbng=","sha256":"28cdb4658b398dfdd8aa35d2be5b96a88f615ccd646afb0a9b1235bf5f3ca852"}`
	if got := string(payload); got != want {
		t.Fatalf("canonical certificate payload drifted:\n got  %s\n want %s", got, want)
	}
	parsed, err := ParsePermitCertificate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, sampleCertificate(t)) {
		t.Fatalf("round trip drift:\n got  %#v\n want %#v", parsed, sampleCertificate(t))
	}
}

func TestBaseManifestParser_StrictCanonicalJSON(t *testing.T) {
	payload := mustManifestPayload(t)
	entry := mustEntryJSON(t, sampleManifest(t).Entries[0])
	cases := map[string][]byte{
		"leading whitespace":   append([]byte(" "), payload...),
		"trailing whitespace":  append(append([]byte(nil), payload...), '\n'),
		"trailing value":       append(append([]byte(nil), payload...), []byte(`{}`)...),
		"duplicate key":        []byte(strings.Replace(string(payload), `{"schema":1,`, `{"schema":1,"schema":1,`, 1)),
		"unknown key":          []byte(strings.Replace(string(payload), `{"schema":1,`, `{"unknown":true,"schema":1,`, 1)),
		"different key order":  []byte(strings.Replace(string(payload), `{"schema":1,"host":"`+validHost()+`"`, `{"host":"`+validHost()+`","schema":1`, 1)),
		"null entries":         []byte(strings.Replace(string(payload), `"entries":[`+entry+`]`, `"entries":null`, 1)),
		"duplicate nested key": []byte(strings.Replace(string(payload), `"codec":"shell-exact-v1"`, `"codec":"shell-exact-v1","codec":"shell-exact-v1"`, 1)),
		"unknown nested key":   []byte(strings.Replace(string(payload), `"source":"out-of-band"`, `"surprise":1,"source":"out-of-band"`, 1)),
	}
	for name, malformed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBaseManifest(malformed); err == nil {
				t.Fatalf("accepted %s: %s", name, malformed)
			}
		})
	}
}

func TestBaseManifestParser_RejectsMalformedIdentityEncodings(t *testing.T) {
	payload := string(mustManifestPayload(t))
	identity := sampleManifest(t).Entries[0].Identity
	literalB64 := base64.StdEncoding.EncodeToString(identity.Literal)
	digestHex := hex.EncodeToString(identity.Digest[:])
	cases := map[string]string{
		"unpadded literal base64": strings.Replace(payload, literalB64, strings.TrimRight(literalB64, "="), 1),
		"uppercase digest hex":    strings.Replace(payload, digestHex, strings.ToUpper(digestHex), 1),
		"wrong digest":            strings.Replace(payload, digestHex, strings.Repeat("0", 64), 1),
		"unknown codec":           strings.Replace(payload, CodecShellExactV1, "source-plan-v1", 1),
	}
	for name, malformed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBaseManifest([]byte(malformed)); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestDecodeIdentityLiteralBoundExactAndPlusOne(t *testing.T) {
	wireFor := func(size int) identityWire {
		literal := bytes.Repeat([]byte{'x'}, size)
		digest := ShellExactDigest(literal)
		return identityWire{
			Codec:      CodecShellExactV1,
			LiteralB64: base64.StdEncoding.EncodeToString(literal),
			SHA256:     hex.EncodeToString(digest[:]),
		}
	}

	identity, err := decodeIdentity(wireFor(MaxLiteralBytes))
	if err != nil {
		t.Fatalf("exact %d-byte literal rejected: %v", MaxLiteralBytes, err)
	}
	if len(identity.Literal) != MaxLiteralBytes {
		t.Fatalf("decoded literal length = %d, want %d", len(identity.Literal), MaxLiteralBytes)
	}
	if _, err := decodeIdentity(wireFor(MaxLiteralBytes + 1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%d-byte literal error = %v, want ErrTooLarge", MaxLiteralBytes+1, err)
	}
}

func TestBaseManifestPayload_CanonicalizesSetOrdering(t *testing.T) {
	m := sampleManifest(t)
	m.RevokedPermitIDs = []string{"pa_z", "pa_b"}
	second := BaseEntry{ID: "pa_a", Identity: mustIdentity(t, "echo a"), Source: EntrySourceOutOfBand}
	m.Entries = append([]BaseEntry{m.Entries[0]}, second)
	payload, err := MarshalBaseManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"revoked_permit_ids":["pa_b","pa_z"]`) {
		t.Fatalf("revocations not canonicalized: %s", payload)
	}
	if strings.Index(string(payload), `"id":"pa_a"`) > strings.Index(string(payload), `"id":"pa_status_nginx"`) {
		t.Fatalf("entries not canonicalized: %s", payload)
	}
	parsed, err := ParseBaseManifest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Entries[0].ID != "pa_a" || parsed.RevokedPermitIDs[0] != "pa_b" {
		t.Fatalf("parsed order is not canonical: %#v", parsed)
	}

	// The same valid fields in a non-canonical set order must not be accepted
	// as a signed payload, even though MarshalBaseManifest can canonicalize a
	// model supplied by a caller.
	unsorted := strings.Replace(string(payload), `"revoked_permit_ids":["pa_b","pa_z"]`, `"revoked_permit_ids":["pa_z","pa_b"]`, 1)
	if _, err := ParseBaseManifest([]byte(unsorted)); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("unsorted payload error = %v; want ErrNotCanonical", err)
	}
}

func TestBaseManifestValidate_ExhaustiveInvariants(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BaseManifest)
		want   error
	}{
		{"schema", func(m *BaseManifest) { m.Schema = 2 }, ErrInvalidManifest},
		{"host", func(m *BaseManifest) { m.Host = "SHA256:nope" }, ErrInvalidManifest},
		{"epoch", func(m *BaseManifest) { m.Epoch = 0 }, ErrInvalidManifest},
		{"revision", func(m *BaseManifest) { m.Revision = 0 }, ErrInvalidManifest},
		{"miss action", func(m *BaseManifest) { m.MissAction = "maybe" }, ErrInvalidManifest},
		{"growth", func(m *BaseManifest) { m.Growth = "wildcard" }, ErrInvalidManifest},
		{"classifier growth", func(m *BaseManifest) { m.MissAction = MissActionClassifier }, ErrInvalidManifest},
		{"sign-to-add deny", func(m *BaseManifest) { m.MissAction = MissActionDeny }, ErrInvalidManifest},
		{"duplicate revoked", func(m *BaseManifest) { m.RevokedPermitIDs = []string{"pa_x", "pa_x"} }, ErrInvalidManifest},
		{"bad revoked id", func(m *BaseManifest) { m.RevokedPermitIDs = []string{"not_permit"} }, ErrInvalidManifest},
		{"duplicate entry", func(m *BaseManifest) { m.Entries = append(m.Entries, m.Entries[0]) }, ErrInvalidManifest},
		{"active revoked", func(m *BaseManifest) { m.RevokedPermitIDs = []string{m.Entries[0].ID} }, ErrInvalidManifest},
		{"bad entry id", func(m *BaseManifest) { m.Entries[0].ID = "pa_bad/id" }, ErrInvalidManifest},
		{"bad source", func(m *BaseManifest) { m.Entries[0].Source = "sign-to-add" }, ErrInvalidManifest},
		{"bad identity", func(m *BaseManifest) { m.Entries[0].Identity.Digest[0] ^= 1 }, ErrInvalidManifest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := sampleManifest(t)
			tc.mutate(&m)
			if err := m.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestBaseManifestValidate_BoundsBeforeMarshal(t *testing.T) {
	m := sampleManifest(t)
	m.Entries = make([]BaseEntry, MaxBaseEntries+1)
	if !errors.Is(m.Validate(), ErrTooLarge) {
		t.Fatalf("entry count error = %v", m.Validate())
	}
	m = sampleManifest(t)
	m.RevokedPermitIDs = make([]string, MaxRevokedPermitIDs+1)
	if !errors.Is(m.Validate(), ErrTooLarge) {
		t.Fatalf("revoked count error = %v", m.Validate())
	}
	m = sampleManifest(t)
	m.Entries = nil
	for n, total := 0, 0; total <= MaxTotalLiteralBytes; n++ {
		identity, err := NewShellExactIdentity(bytes.Repeat([]byte{'x'}, MaxLiteralBytes))
		if err != nil {
			t.Fatal(err)
		}
		m.Entries = append(m.Entries, BaseEntry{ID: "pa_bound_" + base64.RawURLEncoding.EncodeToString([]byte{byte(n >> 8), byte(n)}), Identity: identity, Source: EntrySourceOutOfBand})
		total += MaxLiteralBytes
	}
	if !errors.Is(m.Validate(), ErrTooLarge) {
		t.Fatalf("total literal error = %v", m.Validate())
	}
	oversized := bytes.Repeat([]byte{' '}, MaxPolicyPayloadBytes+1)
	if _, err := ParseBaseManifest(oversized); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("payload bound error = %v", err)
	}
}

func TestPermitCertificateValidate_ExhaustiveInvariants(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PermitCertificate)
	}{
		{"schema", func(c *PermitCertificate) { c.Schema = 2 }},
		{"purpose", func(c *PermitCertificate) { c.Purpose = "ordinary-sign" }},
		{"permit id", func(c *PermitCertificate) { c.PermitID = "grant_1" }},
		{"request id", func(c *PermitCertificate) { c.RequestID = "bad id" }},
		{"host", func(c *PermitCertificate) { c.Host = "" }},
		{"base epoch", func(c *PermitCertificate) { c.BaseEpoch = 0 }},
		{"base digest", func(c *PermitCertificate) { c.BaseDigest = [sha256.Size]byte{} }},
		{"identity", func(c *PermitCertificate) { c.Identity.Literal = []byte("different") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := sampleCertificate(t)
			tc.mutate(&c)
			if err := c.Validate(); !errors.Is(err, ErrInvalidCertificate) {
				t.Fatalf("error = %v; want ErrInvalidCertificate", err)
			}
		})
	}
}

func TestPermitCertificateParser_StrictCanonicalJSON(t *testing.T) {
	payload := mustCertificatePayload(t)
	cases := [][]byte{
		append([]byte(" "), payload...),
		append(append([]byte(nil), payload...), '\n'),
		[]byte(strings.Replace(string(payload), `{"schema":1,`, `{"schema":1,"schema":1,`, 1)),
		[]byte(strings.Replace(string(payload), `{"schema":1,`, `{"extra":0,"schema":1,`, 1)),
		[]byte(strings.Replace(string(payload), `"purpose":"allow-command"`, `"purpose":"ordinary-sign"`, 1)),
		[]byte(strings.Replace(string(payload), `"base_epoch":3`, `"base_epoch":0`, 1)),
	}
	for n, malformed := range cases {
		if _, err := ParsePermitCertificate(malformed); err == nil {
			t.Fatalf("case %d accepted: %s", n, malformed)
		}
	}
}

func TestSignedEnvelopes_GoldenDomainSeparationAndVerification(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for n := range seed {
		seed[n] = byte(n)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	manifestEnvelope, err := SignBaseManifest(privateKey, sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	manifestPayload, manifestSig, err := DecodeBaseManifestEnvelope(manifestEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	const wantManifestSig = "1f57e4409c3445e93fc9ec6dfd6f91a2f6a58088ecf1b26aa7d884365aed4078c88f4523968af9a2f250cc7f8f999a4f6cf84157ebd910fff882254f154db803"
	if got := hex.EncodeToString(manifestSig); got != wantManifestSig {
		t.Fatalf("manifest signature drifted:\n got  %s\n want %s", got, wantManifestSig)
	}
	if _, err := VerifyBaseManifest(manifestEnvelope, publicKey); err != nil {
		t.Fatalf("verify manifest: %v", err)
	}

	certificateEnvelope, err := SignPermitCertificate(privateKey, sampleCertificate(t))
	if err != nil {
		t.Fatal(err)
	}
	certificatePayload, certificateSig, err := DecodePermitCertificateEnvelope(certificateEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	const wantCertificateSig = "ddfb97e1acb04ab0f046cd1227c25592ff1b2edffaaf4eb0b4779bac3523ef0a9334c3193d16fb3e09b00a231e4ad753bd4ce57294914a7e2848e2e891a51d0a"
	if got := hex.EncodeToString(certificateSig); got != wantCertificateSig {
		t.Fatalf("certificate signature drifted:\n got  %s\n want %s", got, wantCertificateSig)
	}
	if _, err := VerifyPermitCertificate(certificateEnvelope, publicKey); err != nil {
		t.Fatalf("verify certificate: %v", err)
	}

	if bytes.Equal(manifestSig, certificateSig) {
		t.Fatal("distinct policy purposes produced identical signatures")
	}
	if ed25519.Verify(publicKey, signingBytes(permitCertificateDomain, SchemaV1, manifestPayload), manifestSig) {
		t.Fatal("manifest signature verified in permit-certificate domain")
	}
	if ed25519.Verify(publicKey, signingBytes(baseManifestDomain, SchemaV1, certificatePayload), certificateSig) {
		t.Fatal("certificate signature verified in base-manifest domain")
	}
	if _, err := VerifyPermitCertificate(manifestEnvelope, publicKey); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("manifest-as-certificate error = %v; want ErrBadSignature", err)
	}
	if _, err := VerifyBaseManifest(certificateEnvelope, publicKey); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("certificate-as-manifest error = %v; want ErrBadSignature", err)
	}

	message, err := BaseManifestSigningBytes(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(message, []byte(baseManifestDomain)) {
		t.Fatal("signing bytes missing domain prefix")
	}
	offset := len(baseManifestDomain)
	if got := binary.BigEndian.Uint64(message[offset : offset+8]); got != SchemaV1 {
		t.Fatalf("signed schema = %d; want %d", got, SchemaV1)
	}
	if got := binary.BigEndian.Uint64(message[offset+8 : offset+16]); got != uint64(len(manifestPayload)) {
		t.Fatalf("signed payload length = %d; want %d", got, len(manifestPayload))
	}
}

func TestSignedEnvelope_StrictAndTamperResistant(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err := SignBaseManifest(privateKey, sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}

	otherPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	otherPublic := otherPrivate.Public().(ed25519.PublicKey)
	if _, err := VerifyBaseManifest(envelope, otherPublic); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key error = %v", err)
	}

	payload, signature, err := DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	tamperedSig, err := EncodeBaseManifestEnvelope(payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBaseManifest(tamperedSig, publicKey); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered signature error = %v", err)
	}

	var outer signedEnvelopeWire
	if err := json.Unmarshal(envelope, &outer); err != nil {
		t.Fatal(err)
	}
	outer.PayloadB64 = base64.StdEncoding.EncodeToString(append(payload, ' '))
	tamperedPayload, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBaseManifest(tamperedPayload, publicKey); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload error = %v", err)
	}

	outerCases := [][]byte{
		append([]byte(" "), envelope...),
		append(append([]byte(nil), envelope...), '\n'),
		[]byte(strings.Replace(string(envelope), `{"payload_b64":`, `{"extra":1,"payload_b64":`, 1)),
		[]byte(strings.Replace(string(envelope), `{"payload_b64":`, `{"payload_b64":"eA==","payload_b64":`, 1)),
	}
	for n, malformed := range outerCases {
		if _, _, err := DecodeBaseManifestEnvelope(malformed); err == nil {
			t.Fatalf("outer case %d accepted", n)
		}
	}
}

func TestSigningAndEnvelopeKeyLengthChecks(t *testing.T) {
	if _, err := SignBaseManifest(ed25519.PrivateKey{1}, sampleManifest(t)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("private key error = %v", err)
	}
	payload := mustManifestPayload(t)
	if _, err := EncodeBaseManifestEnvelope(payload, []byte{1}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("signature length error = %v", err)
	}
	envelope, err := EncodeBaseManifestEnvelope(payload, make([]byte, ed25519.SignatureSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBaseManifest(envelope, ed25519.PublicKey{1}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("public key error = %v", err)
	}
}

func TestBaseManifestDigest_IsCanonicalAndDomainSeparated(t *testing.T) {
	m := sampleManifest(t)
	payload := mustManifestPayload(t)
	fromModel, err := BaseManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	fromPayload, err := BaseManifestPayloadDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if fromModel != fromPayload {
		t.Fatalf("model digest %x != payload digest %x", fromModel, fromPayload)
	}
	plain := sha256.Sum256(payload)
	if fromModel == plain {
		t.Fatal("base digest is not domain separated from raw SHA-256")
	}
	if _, err := BaseManifestPayloadDigest(append(payload, '\n')); err == nil {
		t.Fatal("digest accepted non-canonical payload")
	}
}

func mustManifestPayload(t testing.TB) []byte {
	t.Helper()
	payload, err := MarshalBaseManifest(sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mustCertificatePayload(t testing.TB) []byte {
	t.Helper()
	payload, err := MarshalPermitCertificate(sampleCertificate(t))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mustEntryJSON(t testing.TB, entry BaseEntry) string {
	t.Helper()
	identity := encodeIdentity(entry.Identity)
	w := baseEntryWire{
		ID: entry.ID, Codec: identity.Codec, LiteralB64: identity.LiteralB64,
		SHA256: identity.SHA256, Source: entry.Source,
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
