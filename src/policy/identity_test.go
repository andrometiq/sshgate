package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand"
	"strings"
	"testing"
)

func TestShellExactIdentity_GoldenAndExactness(t *testing.T) {
	literal := []byte("systemctl status nginx")
	identity, err := NewShellExactIdentity(literal)
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "06617dbf00a554f63e04fa6d53eac01606adde27e0e6e68c5ca1b7eefff47499"
	if got := hex.EncodeToString(identity.Digest[:]); got != wantDigest {
		t.Fatalf("digest = %s; want %s", got, wantDigest)
	}
	if !identity.MatchesShellExact(literal) {
		t.Fatal("identity does not match its exact source")
	}

	variants := [][]byte{
		[]byte(" systemctl status nginx"),
		[]byte("systemctl  status nginx"),
		[]byte("systemctl status nginx "),
		[]byte("systemctl status nginx\n"),
		[]byte("SYSTEMCTL status nginx"),
		[]byte("systemctl status 'nginx'"),
		[]byte("systemctl status $UNIT"),
	}
	for _, variant := range variants {
		if identity.MatchesShellExact(variant) {
			t.Errorf("unexpected match for byte-distinct source %q", variant)
		}
	}
}

func TestShellExactIdentity_UnicodeIsNotNormalized(t *testing.T) {
	composed, err := NewShellExactIdentity([]byte("printf é"))
	if err != nil {
		t.Fatal(err)
	}
	decomposed := []byte("printf e\u0301")
	if composed.MatchesShellExact(decomposed) {
		t.Fatal("NFC and NFD spellings must remain distinct")
	}
	if ShellExactDigest(composed.Literal) == ShellExactDigest(decomposed) {
		t.Fatal("byte-distinct Unicode spellings unexpectedly share digest")
	}
}

func TestShellExactIdentity_ByteSafeAndCopiesInput(t *testing.T) {
	literal := []byte{'e', 'c', 'h', 'o', ' ', 0xff}
	identity, err := NewShellExactIdentity(literal)
	if err != nil {
		t.Fatalf("invalid UTF-8 must remain representable in the remote identity: %v", err)
	}
	literal[0] = 'X'
	if got := string(identity.Literal[:4]); got != "echo" {
		t.Fatalf("identity aliases caller input: %q", got)
	}
	if !identity.MatchesShellExact([]byte{'e', 'c', 'h', 'o', ' ', 0xff}) {
		t.Fatal("byte-safe identity did not round-trip")
	}
}

func TestShellExactIdentity_RejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		literal []byte
		wantErr error
	}{
		{name: "empty", literal: nil, wantErr: ErrInvalidIdentity},
		{name: "NUL", literal: []byte("echo\x00oops"), wantErr: ErrInvalidIdentity},
		{name: "too large", literal: bytes.Repeat([]byte{'x'}, MaxLiteralBytes+1), wantErr: ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewShellExactIdentity(tc.literal)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v; want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCommandIdentityValidate_RejectsCodecAndDigestDrift(t *testing.T) {
	identity := mustIdentity(t, "echo ok")
	identity.Codec = "source-plan-v1"
	if !errors.Is(identity.Validate(), ErrInvalidIdentity) {
		t.Fatalf("unknown codec error = %v", identity.Validate())
	}
	identity = mustIdentity(t, "echo ok")
	identity.Digest[0] ^= 0xff
	if !errors.Is(identity.Validate(), ErrInvalidIdentity) {
		t.Fatalf("digest drift error = %v", identity.Validate())
	}
}

func TestShellExactIdentity_PropertyDifferentBytesDoNotMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(80))
	for n := 0; n < 1_000; n++ {
		length := 1 + rng.Intn(256)
		literal := make([]byte, length)
		for i := range literal {
			literal[i] = byte(1 + rng.Intn(255)) // never generate NUL
		}
		identity, err := NewShellExactIdentity(literal)
		if err != nil {
			t.Fatalf("case %d: %v", n, err)
		}
		if !identity.MatchesShellExact(append([]byte(nil), literal...)) {
			t.Fatalf("case %d: exact copy did not match", n)
		}
		different := append([]byte(nil), literal...)
		different[rng.Intn(len(different))] ^= 0x80
		if bytes.Equal(different, literal) {
			different = append(different, '!')
		}
		if identity.MatchesShellExact(different) {
			t.Fatalf("case %d: different literal matched", n)
		}
	}
}

func mustIdentity(t testing.TB, literal string) CommandIdentity {
	t.Helper()
	identity, err := NewShellExactIdentity([]byte(literal))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func validHost() string {
	return "SHA256:" + strings.Repeat("A", 43)
}
