package tools

import (
	"fmt"
	"unicode/utf8"
)

// DefaultOutputCapBytes is the safe-by-default per-command output cap
// (256 KiB) that main wires into the Runner. It is large enough for
// ordinary diagnostics yet bounds a single multi-megabyte read (a deep
// directory walk, a huge log dump) from flooding the agent's context
// window (W5-11 / ROADMAP "reads safe-by-default against multi-megabyte
// output"). A per-call max_output_bytes overrides it (0 = unlimited).
const DefaultOutputCapBytes = 256 * 1024 // 262144

// capOutput truncates s to at most maxBytes bytes of ORIGINAL content,
// appending a truncation marker that reports how many bytes were dropped
// of the total. It returns the (possibly truncated) string and whether a
// truncation happened.
//
//   - maxBytes <= 0 disables the cap entirely (s is returned unchanged).
//   - When len(s) <= maxBytes, s is returned byte-identical (no marker).
//   - The marker is NOT counted against the budget, so it always survives:
//     the returned string may exceed maxBytes by the marker's length. This
//     guarantees a downstream reader always sees the truncation notice.
//   - The cut is moved back to a UTF-8 rune boundary so a multi-byte rune
//     is never split across the truncation point.
//
// This lives in the TOOLS layer and is applied only to the structured
// run/run_batch stdout/stderr. It is deliberately never applied in
// ssh.Client, whose shared run() also carries the update_gate binary
// readback and the box→box transfer ciphertext envelope — capping either
// would corrupt them.
func capOutput(s string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s, false
	}
	cut := maxBytes
	// Trim back off any UTF-8 continuation byte so we never split a rune.
	// s[cut] is the first byte that would be excluded; it must start a rune.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	marker := fmt.Sprintf("\n[...truncated %d of %d bytes]", len(s)-cut, len(s))
	return s[:cut] + marker, true
}

// effectiveOutputCap resolves the byte cap for one run/run_batch call.
// An explicit per-call override (RunInput/RunBatchInput.MaxOutputBytes,
// non-nil) always wins — including 0, which disables the cap for that
// call. When absent (nil) the Runner's DefaultMaxOutputBytes applies (0 in
// tests that do not set it, i.e. uncapped; DefaultOutputCapBytes in
// production).
func (r *Runner) effectiveOutputCap(override *int) int {
	if override != nil {
		return *override
	}
	return r.DefaultMaxOutputBytes
}
