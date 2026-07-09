package redact_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

// pemKey generates a real RSA-2048 PEM block — 1.7-1.9 KB depending
// on the exact key. We use it for the small-chunk write tests so
// the fixture is structurally identical to what we'd see in the wild.
func pemKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestPEMFullBlockRedactedAsOneSpan(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	key := pemKey(t)
	input := []byte("prefix-line\n")
	input = append(input, key...)
	input = append(input, []byte("suffix-line\n")...)

	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil) // no rules — PEM accumulator owns this
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := out.String()
	if strings.Contains(s, "BEGIN PRIVATE KEY") {
		t.Errorf("output still contains the PEM block:\n%s", s)
	}
	if !strings.HasPrefix(s, "prefix-line\n") {
		t.Errorf("prefix line missing or altered: %q", s[:min(len(s), 30)])
	}
	if !strings.Contains(s, "suffix-line") {
		t.Errorf("suffix line missing")
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("no inline marker present: %q", s)
	}
}

func TestPEMSpanningSmallChunkWrites(t *testing.T) {
	var salt [32]byte
	key := pemKey(t)
	input := []byte("warmup\n")
	input = append(input, key...)
	input = append(input, []byte("tail\n")...)

	for _, chunk := range []int{8, 32, 256, 1024} {
		chunk := chunk
		t.Run("chunk-"+itoa(chunk), func(t *testing.T) {
			var out bytes.Buffer
			w := redact.NewWriter(&out, salt, nil)
			for i := 0; i < len(input); i += chunk {
				end := i + chunk
				if end > len(input) {
					end = len(input)
				}
				if _, err := w.Write(input[i:end]); err != nil {
					t.Fatalf("Write at %d: %v", i, err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			s := out.String()
			if strings.Contains(s, "BEGIN PRIVATE KEY") {
				t.Errorf("chunk=%d: PEM block leaked through", chunk)
			}
			if !strings.Contains(s, redact.MarkerPrefix) {
				t.Errorf("chunk=%d: no marker emitted; out=%q", chunk, s)
			}
			if !strings.HasPrefix(s, "warmup\n") {
				t.Errorf("chunk=%d: warmup line lost; out prefix=%q", chunk, s[:min(len(s), 40)])
			}
			if !strings.Contains(s, "tail\n") {
				t.Errorf("chunk=%d: tail line lost", chunk)
			}
		})
	}
}

// --- W4-8: completed non-private PEM blocks pass through --------------------
//
// A completed BEGIN…END block is type-checked (writer.go feedPEM Complete
// branch). Only PRIVATE KEY variants — and any UNKNOWN label (fail closed) —
// redact wholesale; CERTIFICATE / PUBLIC KEY / CSR / parameter blocks pass
// through with only NAMED secret rules scanned over them, so `cat server.crt`,
// public keys, and CSRs survive while an embedded credential is still caught.

// selfSignedCertPEM builds a real ed25519 self-signed certificate PEM
// (Type "CERTIFICATE"). The redactor treats the block textually, but using a
// real cert gives a realistic 64-char base64 body — one the generic
// high-entropy net WOULD redact if it (wrongly) ran on this path.
func selfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sshgate-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func publicKeyPEM(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func csrPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "sshgate-test"}}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// synthPEM builds a well-formed BEGIN…END block of the given type around
// body (used where cryptographic validity is irrelevant — the redactor
// matches the block textually).
func synthPEM(typ, body string) string {
	return "-----BEGIN " + typ + "-----\n" + body + "\n-----END " + typ + "-----\n"
}

func TestPEMCertificatePassesThrough(t *testing.T) {
	cert := string(selfSignedCertPEM(t))
	out := redactString(t, "prefix-line\n"+cert+"suffix-line\n")

	if !strings.Contains(out, cert) {
		t.Errorf("certificate block did not pass through verbatim.\n got: %q\nwant substr: %q", out, cert)
	}
	if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") || !strings.Contains(out, "-----END CERTIFICATE-----") {
		t.Errorf("certificate armour lost; out=%q", out)
	}
	if strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("certificate should NOT be redacted; got marker in out=%q", out)
	}
	if !strings.HasPrefix(out, "prefix-line\n") || !strings.Contains(out, "suffix-line") {
		t.Errorf("surrounding lines mangled; out=%q", out)
	}
}

func TestPEMPublicKeyPassesThrough(t *testing.T) {
	pub := string(publicKeyPEM(t))
	out := redactString(t, pub)
	if !strings.Contains(out, pub) {
		t.Errorf("PUBLIC KEY block did not pass through; out=%q", out)
	}
	if strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("PUBLIC KEY should not be redacted; out=%q", out)
	}
}

func TestPEMCertificateRequestPassesThrough(t *testing.T) {
	csr := string(csrPEM(t))
	out := redactString(t, csr)
	if !strings.Contains(out, csr) {
		t.Errorf("CSR block did not pass through; out=%q", out)
	}
	if strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("CSR should not be redacted; out=%q", out)
	}
}

// TestPEMPublicParamTypesPassThrough covers the remaining public/param types
// (RSA PUBLIC KEY, DH PARAMETERS, EC PARAMETERS). A generic-net-catchable
// 3-class body survives, proving the named-only path skips the generic net.
func TestPEMPublicParamTypesPassThrough(t *testing.T) {
	for _, typ := range []string{"RSA PUBLIC KEY", "DH PARAMETERS", "EC PARAMETERS"} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			body := run3class(120) // >= genericMinLen, 3-class, high entropy
			block := synthPEM(typ, body)
			out := redactString(t, block)
			if !strings.Contains(out, body) {
				t.Errorf("%s body was redacted (generic net leaked onto the named path?); out=%q", typ, out)
			}
			if strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("%s should not be redacted; out=%q", typ, out)
			}
		})
	}
}

// TestPEMCertificateEmbeddedSecretRedacted proves the non-private path runs
// the NAMED ruleset (not a blind verbatim pass): an AWS key hidden in a cert
// header comment is redacted while the cert body survives.
func TestPEMCertificateEmbeddedSecretRedacted(t *testing.T) {
	cert := string(selfSignedCertPEM(t))
	akia := "AKIA" + strings.Repeat("Q", 16) // assembled at runtime (no token literal in source)
	// Inject the secret as a header line right after the BEGIN line.
	withSecret := strings.Replace(cert, "-----\n", "-----\nX-Secret: "+akia+"\n", 1)

	out := redactString(t, withSecret)
	if strings.Contains(out, akia) {
		t.Errorf("embedded AWS key leaked; out=%q", out)
	}
	if !strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("embedded secret should produce a marker; out=%q", out)
	}
	if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") || !strings.Contains(out, "-----END CERTIFICATE-----") {
		t.Errorf("certificate armour lost while redacting embedded secret; out=%q", out)
	}
}

// TestPEMCertificateSmallChunkWrites pins the boundary handling for a cert
// arriving in small chunks (mirrors TestPEMSpanningSmallChunkWrites).
func TestPEMCertificateSmallChunkWrites(t *testing.T) {
	var salt [32]byte
	cert := selfSignedCertPEM(t)
	input := []byte("warmup\n")
	input = append(input, cert...)
	input = append(input, []byte("tail\n")...)

	for _, chunk := range []int{8, 32, 256} {
		chunk := chunk
		t.Run("chunk-"+itoa(chunk), func(t *testing.T) {
			var out bytes.Buffer
			w := redact.NewWriter(&out, salt, rules.Combined())
			for i := 0; i < len(input); i += chunk {
				end := i + chunk
				if end > len(input) {
					end = len(input)
				}
				if _, err := w.Write(input[i:end]); err != nil {
					t.Fatalf("Write at %d: %v", i, err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			s := out.String()
			if !strings.Contains(s, string(cert)) {
				t.Errorf("chunk=%d: certificate did not survive verbatim; out=%q", chunk, s)
			}
			if strings.Contains(s, redact.MarkerPrefix) {
				t.Errorf("chunk=%d: certificate should not be redacted; out=%q", chunk, s)
			}
			if !strings.HasPrefix(s, "warmup\n") || !strings.Contains(s, "tail\n") {
				t.Errorf("chunk=%d: framing lost; out=%q", chunk, s)
			}
		})
	}
}

// TestPEMPrivateKeyVariantsRedactWholesale is the adversarial still-redacts
// proof: EVERY private-key label variant still hard-redacts the whole span.
func TestPEMPrivateKeyVariantsRedactWholesale(t *testing.T) {
	variants := []string{
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"DSA PRIVATE KEY",
		"OPENSSH PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY",
		"PGP PRIVATE KEY BLOCK",
		"PRIVATE KEY", // PKCS#8, no algorithm prefix
	}
	for _, typ := range variants {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			body := run3class(120)
			block := synthPEM(typ, body)
			out := redactString(t, "before\n"+block+"after\n")
			if strings.Contains(out, body) {
				t.Errorf("%s body LEAKED — private key not redacted; out=%q", typ, out)
			}
			if strings.Contains(out, "-----BEGIN "+typ+"-----") {
				t.Errorf("%s BEGIN armour survived — not a wholesale redaction; out=%q", typ, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("%s produced no marker; out=%q", typ, out)
			}
			if !strings.HasPrefix(out, "before\n") || !strings.Contains(out, "after\n") {
				t.Errorf("%s: surrounding framing mangled; out=%q", typ, out)
			}
		})
	}
}

// TestPEMUnknownLabelRedactsWholesale pins the fail-closed default: an
// UNRECOGNISED BEGIN label (neither a known public type nor "PRIVATE KEY") is
// treated as secret and redacted wholesale.
func TestPEMUnknownLabelRedactsWholesale(t *testing.T) {
	for _, typ := range []string{"WEIRD SECRET BLOB", "PROPRIETARY KEY MATERIAL", "MYSTERY"} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			body := run3class(120)
			block := synthPEM(typ, body)
			out := redactString(t, block)
			if strings.Contains(out, body) {
				t.Errorf("unknown-label %q body LEAKED (should fail closed); out=%q", typ, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("unknown-label %q produced no marker; out=%q", typ, out)
			}
		})
	}
}

func TestPEMAbortedFalseBeginPassesThrough(t *testing.T) {
	var salt [32]byte

	// 9 KiB of bytes after a -----BEGIN line, with NO matching END.
	// Should hit the 8 KiB abort threshold and flush untouched.
	junk := bytes.Repeat([]byte("Z"), 9*1024)
	input := []byte("noise\n-----BEGIN FAKE STUFF-----\n")
	input = append(input, junk...)
	input = append(input, []byte("\nstill-no-end-marker\n")...)

	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil)
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := out.String()
	// The false BEGIN bytes must appear verbatim.
	if !strings.Contains(s, "-----BEGIN FAKE STUFF-----") {
		t.Errorf("false BEGIN bytes should pass through, got %q (truncated)", s[:min(len(s), 80)])
	}
	if !strings.Contains(s, "still-no-end-marker") {
		t.Errorf("post-aborted tail lost")
	}
	if strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("false BEGIN should not produce a redaction marker; got %q", s)
	}
}

func TestPEMEndWithoutBeginIsPassthrough(t *testing.T) {
	var salt [32]byte
	input := []byte("orphan -----END PRIVATE KEY----- in the middle of logs\n")
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil)
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if string(out.Bytes()) != string(input) {
		t.Errorf("out = %q, want verbatim %q", out.String(), input)
	}
}

// itoa avoids strconv import bloat in this single use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
