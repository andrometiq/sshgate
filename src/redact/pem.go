package redact

import "bytes"

// PEM-armoured private keys are the longest plausible single secret
// in command output (RSA-2048 ≈ 1.6 KB, RSA-4096 ≈ 3.4 KB). The
// sliding-window scanner's safe-prefix (4 KiB) is enough for most
// PEM blocks, but a multi-key blob or a particularly large key can
// exceed the safe prefix. The PEM accumulator special-cases this:
// when the scanner sees `-----BEGIN ` it switches into accumulate
// mode and buffers verbatim until `-----END ...-----` (the matching
// END line) appears, then redacts the entire span.
//
// If END does not appear within pemMaxBuffer bytes (8 KiB), the
// accumulator aborts: the buffered bytes flush through unchanged,
// and the scanner resumes normal Layer 1 sliding-window mode at
// the byte after the BEGIN. This is "false BEGIN" recovery — e.g.
// a log line that happens to contain the literal `-----BEGIN ` is
// not a leak, and we must not hold its bytes forever.

const (
	pemBegin     = "-----BEGIN "
	pemEndPrefix = "-----END "
	pemEndSuffix = "-----"

	// pemMaxBuffer is the abort threshold. RSA-8192 PEM is ~6.5 KB;
	// 8 KiB covers it with room for a header comment. Beyond that
	// we declare false-BEGIN and flush.
	pemMaxBuffer = 8 * 1024
)

// pemAccumulator is the state machine the writer uses while inside
// a PEM block. The writer constructs it inline (see processBuffer in
// writer.go, which seeds buf by feed-ing the BEGIN-and-after bytes)
// and drives it one chunk at a time via feed.
type pemAccumulator struct {
	buf []byte
}

// pemFeedResult describes what the writer should do after feeding
// bytes into the accumulator.
type pemFeedResult struct {
	// Complete is true when the accumulator found a matching END line
	// and the entire PEM span (Buffered) should be redacted as one
	// secret. The Tail is the unconsumed bytes after the END line —
	// the writer continues scanning Tail in normal mode.
	Complete bool
	// Aborted is true when the buffer hit pemMaxBuffer without ever
	// finding END. The Buffered bytes must pass through unchanged;
	// Tail is the unconsumed bytes the writer should re-feed to the
	// scanner.
	Aborted bool
	// Buffered is the full span the accumulator owned. On Complete
	// this is what gets replaced with a marker. On Aborted this is
	// what passes through.
	Buffered []byte
	// Tail is bytes from the input chunk that lie past the closing
	// END line (Complete) or past pemMaxBuffer (Aborted). The writer
	// resumes scanning these in normal mode.
	Tail []byte
}

// feed appends chunk into the accumulator and reports whether the
// PEM span is complete, aborted, or still in progress. While in
// progress all three Buffered/Tail/Complete/Aborted fields are zero.
func (a *pemAccumulator) feed(chunk []byte) pemFeedResult {
	// Append, then look for the END marker in the freshly-merged
	// buffer. We must scan the join because END could straddle the
	// previous chunk boundary.
	a.buf = append(a.buf, chunk...)

	if idx := findPEMEnd(a.buf); idx >= 0 {
		// Find the newline that terminates the END line; the span
		// includes the trailing newline so the wire stays clean.
		lineEnd := idx
		for lineEnd < len(a.buf) && a.buf[lineEnd] != '\n' {
			lineEnd++
		}
		if lineEnd < len(a.buf) {
			lineEnd++ // include the '\n'
		}
		span := make([]byte, lineEnd)
		copy(span, a.buf[:lineEnd])
		tail := append([]byte(nil), a.buf[lineEnd:]...)
		return pemFeedResult{Complete: true, Buffered: span, Tail: tail}
	}

	if len(a.buf) >= pemMaxBuffer {
		// False BEGIN: flush. Treat the BEGIN line itself as already
		// emitted-by-the-fact-of-buffering; the writer passes Buffered
		// through unchanged.
		buffered := append([]byte(nil), a.buf...)
		return pemFeedResult{Aborted: true, Buffered: buffered}
	}

	return pemFeedResult{}
}

// findPEMEnd locates the start of the first `-----END ...-----`
// marker in buf, or -1 if none is present. The match requires the
// `-----` suffix on the same line, so a stray `-----END ` inside an
// unrelated stream does not falsely trigger.
func findPEMEnd(buf []byte) int {
	off := 0
	for {
		idx := bytes.Index(buf[off:], []byte(pemEndPrefix))
		if idx < 0 {
			return -1
		}
		start := off + idx
		// Find the end of this line.
		lineEnd := start
		for lineEnd < len(buf) && buf[lineEnd] != '\n' {
			lineEnd++
		}
		line := buf[start:lineEnd]
		// Require the closing `-----` suffix (possibly with trailing
		// whitespace before the newline).
		trimmed := bytes.TrimRight(line, " \t\r")
		if bytes.HasSuffix(trimmed, []byte(pemEndSuffix)) {
			return start
		}
		off = lineEnd
		if off >= len(buf) {
			return -1
		}
	}
}

// findPEMBegin locates the first `-----BEGIN ` substring in buf, or
// -1 if absent. It is the writer's signal to enter accumulate mode.
func findPEMBegin(buf []byte) int {
	return bytes.Index(buf, []byte(pemBegin))
}

// isPrivateKeyBegin reports whether buf opens with a high-confidence
// private-key BEGIN line — i.e. a `-----BEGIN ...PRIVATE KEY-----`
// header. It is used at the abort / EOF boundaries to decide whether an
// unterminated `BEGIN` span is a real (leaking) private key that must
// be redacted wholesale, versus a benign false-BEGIN that should be
// re-scanned byte-by-byte through Layer 1.
//
// The check is anchored to the first line of buf so a `-----BEGIN `
// that begins the accumulator span (which is how the writer seeds it)
// is classified by its own header, not by some later line.
func isPrivateKeyBegin(buf []byte) bool {
	idx := bytes.Index(buf, []byte(pemBegin))
	if idx < 0 {
		return false
	}
	lineEnd := idx
	for lineEnd < len(buf) && buf[lineEnd] != '\n' {
		lineEnd++
	}
	line := buf[idx:lineEnd]
	// Require the closing `-----` so a log line that merely contains the
	// literal `-----BEGIN PRIVATE KEY` substring without proper armour
	// does not get force-redacted at EOF.
	trimmed := bytes.TrimRight(line, " \t\r")
	if !bytes.HasSuffix(trimmed, []byte(pemEndSuffix)) {
		return false
	}
	return bytes.Contains(line, []byte("PRIVATE KEY"))
}

// pemPublicTypes is the allowlist of PEM block types that carry NO secret
// material — certificates, public keys, CSRs, and public parameters. A
// COMPLETED block (verified `-----END-----`) whose BEGIN label names one of
// these is passed through with only the NAMED secret rules scanned over it,
// so its base64 body survives (`cat server.crt`, `ssh-keygen -y`,
// `openssl req`) while an embedded credential is still caught.
//
// Everything NOT in this set is redacted wholesale on the completed-block
// path: every `…PRIVATE KEY…` variant (covered by isPrivateKeyBegin too:
// RSA/EC/DSA/OPENSSH/ENCRYPTED/PGP PRIVATE KEY BLOCK, plain PKCS8) AND every
// UNRECOGNISED label. That is the fail-closed bias — if we cannot prove a
// label is a public/cert type, we treat the whole span as secret. Labels
// are the uppercase text between `-----BEGIN ` and `-----`; matched
// case-sensitively per RFC 7468.
var pemPublicTypes = map[string]bool{
	"CERTIFICATE":             true,
	"TRUSTED CERTIFICATE":     true,
	"X509 CRL":                true,
	"CERTIFICATE REQUEST":     true, // PKCS#10 CSR
	"NEW CERTIFICATE REQUEST": true, // legacy CSR label
	"PUBLIC KEY":              true, // SubjectPublicKeyInfo
	"RSA PUBLIC KEY":          true, // PKCS#1 public
	"DSA PUBLIC KEY":          true,
	"DH PARAMETERS":           true,
	"EC PARAMETERS":           true, // curve identifier only — public
	"DSA PARAMETERS":          true,
	"PKCS7":                   true,
	"CMS":                     true,
	"ATTRIBUTE CERTIFICATE":   true,
	"PGP PUBLIC KEY BLOCK":    true,
	"PGP SIGNATURE":           true,
	"SSH2 PUBLIC KEY":         true, // RFC 4716
}

// pemBlockType returns the type label of the first `-----BEGIN <TYPE>-----`
// line in buf (the text between `-----BEGIN ` and the closing `-----`), or
// "" when buf does not open with a well-formed BEGIN line. The accumulator
// seeds its span at the BEGIN, so this reads the block's own header.
func pemBlockType(buf []byte) string {
	idx := bytes.Index(buf, []byte(pemBegin))
	if idx < 0 {
		return ""
	}
	start := idx + len(pemBegin)
	lineEnd := start
	for lineEnd < len(buf) && buf[lineEnd] != '\n' {
		lineEnd++
	}
	line := buf[start:lineEnd]
	trimmed := bytes.TrimRight(line, " \t\r")
	if !bytes.HasSuffix(trimmed, []byte(pemEndSuffix)) {
		return ""
	}
	typ := bytes.TrimSuffix(trimmed, []byte(pemEndSuffix))
	return string(bytes.TrimSpace(typ))
}

// isPublicPEMBegin reports whether buf opens with a well-formed BEGIN line
// whose type is a known public (non-secret) PEM type — see pemPublicTypes.
// It is the completed-block discriminator: true -> pass the block through
// (named-only scan); false -> redact wholesale (private key OR unknown
// label, fail closed).
func isPublicPEMBegin(buf []byte) bool {
	t := pemBlockType(buf)
	return t != "" && pemPublicTypes[t]
}
