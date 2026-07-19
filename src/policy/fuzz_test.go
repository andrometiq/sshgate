package policy

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
)

func FuzzParseBaseManifest(f *testing.F) {
	payload, err := MarshalBaseManifest(sampleManifest(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := ParseBaseManifest(data)
		if err != nil {
			return
		}
		reencoded, err := MarshalBaseManifest(manifest)
		if err != nil {
			t.Fatalf("accepted manifest cannot re-marshal: %v", err)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatalf("accepted non-canonical manifest:\n input %q\n output %q", data, reencoded)
		}
		reparsed, err := ParseBaseManifest(reencoded)
		if err != nil || !reflect.DeepEqual(manifest, reparsed) {
			t.Fatalf("round-trip = (%#v, %v); want %#v", reparsed, err, manifest)
		}
	})
}

func FuzzParsePermitCertificate(f *testing.F) {
	payload, err := MarshalPermitCertificate(sampleCertificate(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Add([]byte(`{"schema":1}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		certificate, err := ParsePermitCertificate(data)
		if err != nil {
			return
		}
		reencoded, err := MarshalPermitCertificate(certificate)
		if err != nil {
			t.Fatalf("accepted certificate cannot re-marshal: %v", err)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatalf("accepted non-canonical certificate:\n input %q\n output %q", data, reencoded)
		}
	})
}

func FuzzVerifyBaseManifest(f *testing.F) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x80}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err := SignBaseManifest(privateKey, sampleManifest(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(envelope)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := VerifyBaseManifest(data, publicKey)
		if err != nil {
			return
		}
		if err := manifest.Validate(); err != nil {
			t.Fatalf("verified invalid manifest: %v", err)
		}
	})
}

func FuzzShellExactIdentity(f *testing.F) {
	f.Add([]byte("systemctl status nginx"), []byte("systemctl status nginx"))
	f.Add([]byte("echo x"), []byte("echo  x"))
	f.Fuzz(func(t *testing.T, literal, candidate []byte) {
		identity, err := NewShellExactIdentity(literal)
		if err != nil {
			return
		}
		got := identity.MatchesShellExact(candidate)
		want := bytes.Equal(literal, candidate) && len(candidate) > 0 && len(candidate) <= MaxLiteralBytes && bytes.IndexByte(candidate, 0) < 0
		if got != want {
			t.Fatalf("match = %v; want %v for literal %x candidate %x", got, want, literal, candidate)
		}
	})
}
