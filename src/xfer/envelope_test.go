package xfer_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

const (
	testXfer = "xfer-abc123"
	testDest = "dest-server-B"
	testMax  = 1 << 20 // 1 MiB
)

// recipient bundles a box keypair for a test recipient.
type recipient struct {
	pub  *[32]byte
	priv *[32]byte
}

func newRecipient(t *testing.T) recipient {
	t.Helper()
	k, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("GenerateBoxKey: %v", err)
	}
	return recipient{pub: k.Public(), priv: k.Private()}
}

func newSender(t *testing.T) *xfer.IDKey {
	t.Helper()
	k, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("GenerateIDKey: %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)

	sizes := []int{0, 1, 16, 32, 100, 1024, 4096, 65536}
	for _, n := range sizes {
		pt := make([]byte, n)
		if _, err := rand.Read(pt); err != nil {
			t.Fatalf("rand: %v", err)
		}
		env, err := xfer.Seal(pt, rcpt.pub, sender.Private(), testXfer, testDest)
		if err != nil {
			t.Fatalf("Seal(size=%d): %v", n, err)
		}
		got, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax)
		if err != nil {
			t.Fatalf("Open(size=%d): %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size=%d: plaintext mismatch", n)
		}
	}
}

func TestOpenWrongRecipientKey(t *testing.T) {
	rcpt := newRecipient(t)
	other := newRecipient(t)
	sender := newSender(t)

	env, err := xfer.Seal([]byte("secret"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := xfer.Open(env, other.pub, other.priv, sender.Public(), testXfer, testDest, testMax); err == nil {
		t.Fatal("Open with wrong recipient key succeeded; want failure")
	}
}

func TestOpenFlippedByteFails(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)

	env, err := xfer.Seal([]byte("secret payload"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a bit in the middle of the sealed ciphertext.
	env.Sealed[len(env.Sealed)/2] ^= 0x01
	if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax); err == nil {
		t.Fatal("Open with flipped ciphertext byte succeeded; want failure (Poly1305)")
	}
}

func TestOpenWrongSenderIDFails(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)
	impostor := newSender(t)

	env, err := xfer.Seal([]byte("secret"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Verifying against a DIFFERENT identity public key must fail.
	if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, impostor.Public(), testXfer, testDest, testMax); err == nil {
		t.Fatal("Open with wrong expected sender id succeeded; want failure (provenance)")
	}
}

func TestOpenAttestSignedByDifferentKeyFails(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)
	impostor := newSender(t)

	env, err := xfer.Seal([]byte("secret"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Re-seal the SAME transfer with the impostor's identity, then verify
	// against the honest sender — attestation must not validate.
	forged, err := xfer.Seal([]byte("secret"), rcpt.pub, impostor.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal(forged): %v", err)
	}
	env.Attest = forged.Attest
	if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax); err == nil {
		t.Fatal("Open with attestation signed by another id key succeeded; want failure")
	}
}

func TestOpenRebindFails(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)

	env, err := xfer.Seal([]byte("secret"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	t.Run("wrong xferID expected", func(t *testing.T) {
		if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), "other-xfer", testDest, testMax); err == nil {
			t.Fatal("Open with wrong expected xferID succeeded; want failure")
		}
	})
	t.Run("wrong destID expected", func(t *testing.T) {
		if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, "other-dest", testMax); err == nil {
			t.Fatal("Open with wrong expected destID succeeded; want failure")
		}
	})
	t.Run("tampered envelope xferID", func(t *testing.T) {
		tampered := env
		tampered.XferID = "hijacked"
		// Caller still expects the real transfer; binding check rejects.
		if _, err := xfer.Open(tampered, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax); err == nil {
			t.Fatal("Open with tampered envelope xferID succeeded; want failure")
		}
	})
	t.Run("attacker rebinds both envelope and expectation", func(t *testing.T) {
		// Even if the attacker rewrites the envelope's XferID AND the caller
		// is fooled into expecting it, the attestation was signed over the
		// ORIGINAL xferID, so provenance fails closed.
		tampered := env
		tampered.XferID = "hijacked"
		if _, err := xfer.Open(tampered, rcpt.pub, rcpt.priv, sender.Public(), "hijacked", testDest, testMax); err == nil {
			t.Fatal("Open with fully-rebound xferID succeeded; want failure (attest binds xferID)")
		}
	})
}

// TestReverseMITMContentSubstitution is the explicit reverse-MITM test.
// A hostile agent CAN encrypt to B's real box key (box.SealAnonymous is
// anonymous), but it CANNOT forge A's attestation. So a substituted
// plaintext, sealed to the right recipient but without a valid attestation
// from A, must fail closed at Open.
func TestReverseMITMContentSubstitution(t *testing.T) {
	rcpt := newRecipient(t)
	honestSender := newSender(t)

	// Honest transfer of P from A.
	honest, err := xfer.Seal([]byte("the-real-secret-P"), rcpt.pub, honestSender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal(honest): %v", err)
	}

	// Hostile agent seals a DIFFERENT plaintext P2 to B's real key. It does
	// not hold A's identity key, so it cannot produce a valid Attest for P2.
	// Simulate the best it can do: seal P2 anonymously and reuse A's Attest
	// (which is over P, not P2).
	hostileSealed, err := box.SealAnonymous(nil, []byte("attacker-injected-P2"), rcpt.pub, rand.Reader)
	if err != nil {
		t.Fatalf("SealAnonymous(hostile): %v", err)
	}
	forged := xfer.Envelope{
		Version: honest.Version,
		XferID:  honest.XferID,
		DestID:  honest.DestID,
		Sealed:  hostileSealed,
		Attest:  honest.Attest, // A's attestation, but over the WRONG content
	}
	if _, err := xfer.Open(forged, rcpt.pub, rcpt.priv, honestSender.Public(), testXfer, testDest, testMax); err == nil {
		t.Fatal("reverse-MITM: content substitution opened; want failure (attest binds sha256(plaintext))")
	}
}

func TestOpenMaxPlaintextCap(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)

	pt := make([]byte, 4096)
	if _, err := rand.Read(pt); err != nil {
		t.Fatalf("rand: %v", err)
	}
	env, err := xfer.Seal(pt, rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	t.Run("exact cap opens", func(t *testing.T) {
		if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, 4096); err != nil {
			t.Fatalf("Open at exact cap: %v", err)
		}
	})
	t.Run("below cap rejects", func(t *testing.T) {
		// 4095 < 4096: post-open plaintext-length check must reject.
		if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, 4095); err == nil {
			t.Fatal("Open with maxPlaintext below plaintext size succeeded; want failure")
		}
	})
	t.Run("pre-open ciphertext cap rejects", func(t *testing.T) {
		// A tiny cap makes the sealed blob exceed cap+overhead before the
		// AEAD is even invoked.
		if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, 8); err == nil {
			t.Fatal("Open with tiny maxPlaintext succeeded; want failure")
		}
	})
	t.Run("negative cap rejects", func(t *testing.T) {
		if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, -1); err == nil {
			t.Fatal("Open with negative maxPlaintext succeeded; want failure")
		}
	})
}

func TestOpenUnsupportedVersion(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)
	env, err := xfer.Seal([]byte("x"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env.Version = 999
	if _, err := xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax); err == nil {
		t.Fatal("Open with unsupported version succeeded; want failure")
	}
}

func TestSealInvalidArgs(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)

	if _, err := xfer.Seal([]byte("x"), nil, sender.Private(), testXfer, testDest); err == nil {
		t.Fatal("Seal with nil recipient succeeded; want failure")
	}
	if _, err := xfer.Seal([]byte("x"), rcpt.pub, ed25519.PrivateKey(nil), testXfer, testDest); err == nil {
		t.Fatal("Seal with nil sender key succeeded; want failure")
	}
	if _, err := xfer.Seal([]byte("x"), rcpt.pub, ed25519.PrivateKey("short"), testXfer, testDest); err == nil {
		t.Fatal("Seal with short sender key succeeded; want failure")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)

	env, err := xfer.Seal([]byte("round-trip-me"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	blob, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := xfer.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Version != env.Version || got.XferID != env.XferID || got.DestID != env.DestID ||
		!bytes.Equal(got.Sealed, env.Sealed) || !bytes.Equal(got.Attest, env.Attest) {
		t.Fatal("marshal/unmarshal did not round-trip")
	}
	// The decoded envelope must still open.
	pt, err := xfer.Open(got, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax)
	if err != nil {
		t.Fatalf("Open after round-trip: %v", err)
	}
	if string(pt) != "round-trip-me" {
		t.Fatalf("round-trip plaintext = %q", pt)
	}
}

func TestUnmarshalRejectsBadInput(t *testing.T) {
	rcpt := newRecipient(t)
	sender := newSender(t)
	env, err := xfer.Seal([]byte("x"), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	good, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	cases := map[string][]byte{
		"empty":             {},
		"garbage":           []byte("not json at all"),
		"truncated":         good[:len(good)/2],
		"empty json object": []byte(`{}`),
		"unknown field":     []byte(`{"v":1,"xfer_id":"a","dest_id":"b","sealed":"AAAA","attest":"AAAA","evil":1}`),
		"missing sealed":    []byte(`{"v":1,"xfer_id":"a","dest_id":"b","attest":"` + b64Sig() + `"}`),
		"short attest":      []byte(`{"v":1,"xfer_id":"a","dest_id":"b","sealed":"AAAA","attest":"AAAA"}`),
		"trailing data":     append(append([]byte{}, good...), []byte("garbage")...),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := xfer.Unmarshal(in); err == nil {
				t.Fatalf("Unmarshal(%s) succeeded; want failure", name)
			}
		})
	}
}

// b64Sig returns a base64 std-encoded all-zero ed25519-signature-length
// blob for building a wire object that is missing only the sealed field.
func b64Sig() string {
	sig := make([]byte, ed25519.SignatureSize)
	return base64.StdEncoding.EncodeToString(sig)
}

// TestNoSecretInErrors seals a recognizable plaintext, then drives every
// reject path and asserts no returned error string contains the plaintext
// bytes (or an obvious substring of them).
func TestNoSecretInErrors(t *testing.T) {
	rcpt := newRecipient(t)
	other := newRecipient(t)
	sender := newSender(t)
	impostor := newSender(t)

	const secret = "TOP-SECRET-CANARY-STRING-do-not-leak-0xDEADBEEF"

	env, err := xfer.Seal([]byte(secret), rcpt.pub, sender.Private(), testXfer, testDest)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Collect errors from every reject path.
	var errs []error
	collect := func(_ []byte, e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}

	collect(xfer.Open(env, other.pub, other.priv, sender.Public(), testXfer, testDest, testMax)) // wrong recipient
	collect(xfer.Open(env, rcpt.pub, rcpt.priv, impostor.Public(), testXfer, testDest, testMax)) // wrong sender
	collect(xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), "nope", testDest, testMax))     // rebind
	collect(xfer.Open(env, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, 4))         // cap

	flipped := env
	flipped.Sealed = append([]byte{}, env.Sealed...)
	flipped.Sealed[0] ^= 0xFF
	collect(xfer.Open(flipped, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax)) // tamper

	badVer := env
	badVer.Version = 42
	collect(xfer.Open(badVer, rcpt.pub, rcpt.priv, sender.Public(), testXfer, testDest, testMax)) // version

	// Seal error path.
	if _, e := xfer.Seal([]byte(secret), nil, sender.Private(), testXfer, testDest); e != nil {
		errs = append(errs, e)
	}

	if len(errs) < 6 {
		t.Fatalf("expected at least 6 reject-path errors, got %d", len(errs))
	}
	for _, e := range errs {
		if strings.Contains(e.Error(), secret) {
			t.Fatalf("error string leaked the plaintext secret: %q", e.Error())
		}
		// Also guard against a distinctive fragment leaking.
		if strings.Contains(e.Error(), "CANARY") || strings.Contains(e.Error(), "DEADBEEF") {
			t.Fatalf("error string leaked a plaintext fragment: %q", e.Error())
		}
	}
}
