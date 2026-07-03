// Package gatever locates the build-injected gate version marker.
//
// The marker is baked into the gate binary at link time via
//
//	-ldflags "-X main.versionMarker=SSHGATE_GATE_VERSION{<VERSION>}"
//
// (Makefile `release-gate`/`sshgate-gate-linux`). It exists so the operator's
// approval banner and the gate's SSHGATE_VERSION probe can report a
// human-readable build version WITHOUT debug/buildinfo vcs stamping — which the
// verified-release recipe turns OFF via -buildvcs=false (spec §11.1/§11.2). A
// dev build with no -X carries the default marker SSHGATE_GATE_VERSION{dev}.
//
// # Safe scan (spec §11.2 "Scanning the marker safely", HIGH-1)
//
// Two paths scan gate-binary bytes for this marker: the gate's binaryRevision
// (over incoming SSHGATE_UPDATE bytes) and the MCP's staged-bytes scan. Both
// ship INSIDE a gate binary that itself carries the marker prefix, so a naive
// first-match scan could lock onto the scanner's own copy and read adjacent
// .rodata as the "version", silently defeating the downgrade cue. Two rules
// close this and BOTH are load-bearing:
//
//  1. The search prefix is built at RUNTIME from non-constant bytes
//     (prefixBytes), so the folded literal "SSHGATE_GATE_VERSION{" never lands
//     in this package's .rodata. A source-level split alone is insufficient —
//     Go constant-folds compile-time string concatenation.
//  2. Scan is ALL-OCCURRENCES with an acceptance rule, never first-match: a
//     candidate is valid iff it is the prefix followed by 1..64 chars of
//     [A-Za-z0-9._+-] then a closing '}'. Exactly one distinct valid value →
//     that version; zero, or two-or-more CONFLICTING distinct valid values →
//     "unknown". Repeat occurrences of the SAME value collapse to one.
//
// # The lingering-default carve-out (empirically confirmed on go1.26.4)
//
// `-X main.versionMarker=...` does NOT remove the source default literal
// `SSHGATE_GATE_VERSION{dev}` from the linked binary's .rodata: a release binary
// contains BOTH {dev} (the lingering default) and {<VERSION>} (the injected
// value). Under rule 2 alone those are two distinct valid values → "unknown",
// which would blank the version display for EVERY release binary. The spec's
// abstract model did not account for this. Scan therefore treats the exact
// sentinel token "dev" as the build-time placeholder and skips it: it can never
// be a real VERSION (which must match ^v[0-9A-Za-z._+-]+$), so ignoring it lets
// a release binary resolve to its injected version instead of a spurious
// dev/release conflict. Version (single-marker, used by the running gate to
// report its OWN compiled-in marker) does NOT skip "dev", so a genuine dev build
// still reports "dev".
//
// This whole mechanism is UX-only. The security property rides on the SHA-256
// alone (R4): a forged or stripped marker changes only what the banner
// DISPLAYS, never what the gate ENFORCES.
package gatever

import "bytes"

// Unknown is returned when no valid, non-sentinel version marker can be
// resolved from the scanned bytes.
const Unknown = "unknown"

// devSentinel is the version token of the compiled-in default marker
// (SSHGATE_GATE_VERSION{dev}). Scan skips it because -X does not strip the
// default literal from .rodata (see the package doc); it must stay in lockstep
// with the default value of the gate's versionMarker var. It can never collide
// with a real VERSION, which must start with 'v'.
const devSentinel = "dev"

// maxVersionLen bounds the version token between the marker delimiters: 1..64
// chars of the version charset. A stray byte (CR, space, comment) outside the
// charset — or a token longer than this — makes the occurrence invalid.
const maxVersionLen = 64

const (
	openDelim  = '{'
	closeDelim = '}'
)

// prefixBytes builds the marker search prefix "SSHGATE_GATE_VERSION{" at RUNTIME
// (safe-scan rule 1). It MUST assemble the token from separate pieces joined
// through a mutable slice so the Go linker never places the whole contiguous
// literal in this package's read-only data — otherwise a scanner could match its
// own constant. The connective '_' and '{' are byte values (not string
// literals), so the contiguous prefix exists only in the returned slice, never
// in .rodata.
func prefixBytes() []byte {
	b := make([]byte, 0, 21)
	b = append(b, "SSHGATE"...)
	b = append(b, '_')
	b = append(b, "GATE"...)
	b = append(b, '_')
	b = append(b, "VERSION"...)
	b = append(b, openDelim)
	return b
}

// isVersionChar reports whether c is in the version token charset
// [A-Za-z0-9._+-] (spec §11.2). This is the same charset the VERSION-file
// validator enforces, so any legal VERSION is a legal marker token.
func isVersionChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '+' || c == '-':
		return true
	default:
		return false
	}
}

// acceptAt applies the acceptance rule at body[start] (immediately after a
// prefix): read 1..64 version chars then a closing '}'. Returns the token and
// true on success; ("", false) on any violation (non-version byte before '}',
// no closing '}', empty token, or a token longer than maxVersionLen).
func acceptAt(body []byte, start int) (string, bool) {
	k := start
	for k < len(body) {
		c := body[k]
		if c == closeDelim {
			break
		}
		if !isVersionChar(c) {
			return "", false
		}
		if k-start >= maxVersionLen {
			return "", false // > maxVersionLen version chars before '}'
		}
		k++
	}
	if k >= len(body) || body[k] != closeDelim {
		return "", false // ran off the end with no closing '}'
	}
	n := k - start
	if n < 1 || n > maxVersionLen {
		return "", false
	}
	return string(body[start:k]), true
}

// Scan resolves the injected gate version from arbitrary binary bytes using the
// all-occurrences acceptance rule (rule 2) with the "dev" sentinel carve-out.
// It returns Unknown when there is no valid non-sentinel marker, or when two or
// more CONFLICTING distinct valid versions are present. Repeats of the same
// value collapse to one.
func Scan(body []byte) string {
	prefix := prefixBytes()
	found := ""
	haveOne := false
	off := 0
	for {
		rel := bytes.Index(body[off:], prefix)
		if rel < 0 {
			break
		}
		vstart := off + rel + len(prefix)
		// Advance past THIS prefix occurrence so the next iteration continues
		// scanning even when the current candidate is rejected.
		off = vstart
		ver, ok := acceptAt(body, vstart)
		if !ok || ver == devSentinel {
			continue
		}
		if !haveOne {
			found, haveOne = ver, true
			continue
		}
		if ver != found {
			return Unknown // conflicting distinct valid versions
		}
	}
	if !haveOne {
		return Unknown
	}
	return found
}

// Version extracts the version from a SINGLE known marker string (the gate's
// compiled-in versionMarker var), used by the running gate to report its OWN
// build version. Unlike Scan it does NOT skip the "dev" sentinel — a genuine dev
// build must report "dev" — and it takes the first valid marker (a single clean
// marker has exactly one). It returns Unknown for an empty or malformed marker.
func Version(marker string) string {
	body := []byte(marker)
	prefix := prefixBytes()
	rel := bytes.Index(body, prefix)
	if rel < 0 {
		return Unknown
	}
	ver, ok := acceptAt(body, rel+len(prefix))
	if !ok {
		return Unknown
	}
	return ver
}
