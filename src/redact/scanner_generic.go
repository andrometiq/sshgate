package redact

import "math"

// This file is the generic default-deny net: the O(n) linear pass that
// backs SSHGate's 2026-07 "redact anything secret-shaped" mandate, plus
// the shared candidate gate that the pass and any Entropy-bearing named
// rule both consult.
//
// Why engine code and NOT a regex rule: Go's regexp is NFA-only (no DFA,
// no literal-prefix skip). Measured on the repo's BenchmarkScannerNoMatch
// profile, the two zero-keyword regex formulations of this net cost +66%
// and +73% per MB; this linear pass does the same work in ~+2%. A
// keyword-scoped regex net was also rejected: it silently deactivates on
// keyword-free buffers, so an unknown-named secret that never says
// "key/token/secret" would leak — defeating the default-deny mandate. See
// docs/redaction-architecture.md and the package header in
// src/redact/rules/sshgate/rules.go.

const (
	// genericEntropyRuleID / telegramTokenRuleID name the two detectors
	// the linear pass emits, so markers, the audit `why`, and tests can
	// name the detector that fired.
	genericEntropyRuleID = "sshgate-generic-high-entropy"
	telegramTokenRuleID  = "sshgate-telegram-bot-token"

	// genericMinLen is the trimmed-length floor for a generic candidate.
	// 32 is the spec floor and the tuning knob for a future FP/miss
	// report: below it, benign identifiers (long var names, base32 UUIDs)
	// dominate; at/above it the run is secret-shaped often enough that
	// redact-on-doubt wins.
	genericMinLen = 32
	// genericEntropy is the Shannon bits/byte floor. 3.5 kills repetitive
	// three-class runs like "Test123Test123…" (which clear the 3-class
	// content check but carry little information) while real base62 keys
	// (~5-6 bits/byte) pass.
	genericEntropy = 3.5

	// Telegram bot tokens are exactly `<bot_id>:AA<33 base64url>`. The id
	// is a numeric account id (historically 8-10 digits; 6 as a safety
	// floor); the body is `AA` + 33 base64url chars = 35, with ±1 slack
	// for format drift.
	tgIDMin   = 6
	tgIDMax   = 10
	tgBodyMin = 34
	tgBodyMax = 36
)

// sshKeyMarkers are the key-type prefixes that precede an SSH / ECDSA
// public-key blob in authorized_keys, known_hosts, or `ssh-keygen -y`
// output. When one of these sits on the SAME line before a candidate we
// veto the generic net — a pubkey body is a benign high-entropy blob, not
// a secret. Lowercase so indexFoldASCII (ASCII case-fold, allocation-free)
// can substring-match without a ToLower copy.
//
// Note this veto keeps only the GENERIC net off pubkey lines; it does NOT
// make `cat authorized_keys` marker-free — the pre-existing
// gitleaks-twitter-bearer rule already redacts long `AAAA…` ed25519/rsa
// bodies. See docs/redaction-architecture.md.
var sshKeyMarkers = []string{
	"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-",
}

// passesSecretGate is the generic-candidate gate shared by Entropy-bearing
// named rules (via findMatches) and the generic linear pass. A candidate
// span buf[start:end] is dropped unless it
//
//	(a) contains upper+lower+digit — kills lowercase hex (git SHAs, docker
//	    digests, sha256sums, nix hashes) and caseless identifiers;
//	(b) is NOT on the same line as an SSH public-key type marker; and
//	(c) has Shannon entropy >= threshold bits/byte — kills repetitive
//	    three-class runs.
//
// Cheapest checks first: length is filtered by the caller, then 3-class
// (single pass, early exit), then the bounded ssh-line look-back, then the
// entropy histogram last. matchStart is the offset the ssh look-back scans
// back from (the full-match start for a named rule, the run start for the
// generic pass); start/end bound the secret span whose content is judged.
func passesSecretGate(buf []byte, matchStart, start, end int, threshold float64) bool {
	span := buf[start:end]
	if !has3Class(span) {
		return false
	}
	if sshLineContext(buf, matchStart) {
		return false
	}
	return shannonEntropy(span) >= threshold
}

// has3Class reports whether b contains at least one lowercase letter, one
// uppercase letter, and one digit. OR-mask loop with an early exit the
// moment all three bits are set, so the common "fails fast" case is cheap.
func has3Class(b []byte) bool {
	var m int
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			m |= 1
		case c >= 'A' && c <= 'Z':
			m |= 2
		case c >= '0' && c <= '9':
			m |= 4
		}
		if m == 7 {
			return true
		}
	}
	return false
}

// shannonEntropy returns the Shannon entropy of b in bits/byte. It uses a
// fixed 256-int histogram on the stack, so it allocates nothing regardless
// of span length.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// sshLineContext reports whether the line containing matchStart carries an
// SSH public-key type marker BEFORE matchStart. It scans back from
// matchStart to the previous '\n' (capped at 1024 bytes — an ssh-rsa
// authorized_keys line is ~560-750 bytes) and substring-matches the
// markers with indexFoldASCII, so it is allocation-free (no ToLower copy).
func sshLineContext(buf []byte, matchStart int) bool {
	lo := matchStart - 1024
	if lo < 0 {
		lo = 0
	}
	for i := matchStart - 1; i >= lo; i-- {
		if buf[i] == '\n' {
			lo = i + 1
			break
		}
	}
	pre := buf[lo:matchStart]
	for _, m := range sshKeyMarkers {
		if indexFoldASCII(pre, m) >= 0 {
			return true
		}
	}
	return false
}

// isRunByte reports whether c can appear inside a maximal token run. The
// run alphabet is [A-Za-z0-9_-] — the union of base64url, hex, and common
// identifier/separator characters.
func isRunByte(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '_'
}

// scanGenericRuns is the single allocation-conscious pass. It segments
// maximal [A-Za-z0-9_-] runs and emits two kinds of match:
//
//	Telegram stitch — a bot token `<id>:AA<33 base64url>`. The id is the
//	  maximal TRAILING all-digit suffix (6-10 digits) of the previous run,
//	  the separator was exactly one ':', and the current run is the body
//	  (len 34-36, first byte 'A' — gitleaks upstream pins the 'A' too).
//	  Peeling the trailing digit suffix (rather than requiring the whole
//	  previous run to be digits) is what catches the glued URL form
//	  `api.telegram.org/bot<id>:<body>/…`: no word-boundary regex can match
//	  there (there is no \b inside "bot123…"). The span is id + ':' + body
//	  and MatchStart = id start, so the writer's straddler retention keeps
//	  the anchor together.
//
//	Generic net — a run NOT starting "_Z" (Itanium-mangled C++ symbols),
//	  edge-trimmed of '-'/'_', with trimmed length >= genericMinLen, that
//	  passes passesSecretGate at genericEntropy. MatchStart = Start = the
//	  TRIMMED run start; there is no anchor prefix. Getting this wrong
//	  (e.g. a zero default) would make the writer's ringMax tail path
//	  redact from offset 0 and swallow benign output wholesale.
//
// match.Secret is copied exactly as in the regex path. The result need not
// be pre-sorted; dedupMatches (called by findMatches) sorts and merges it
// with the regex matches.
func scanGenericRuns(buf []byte) []match {
	var out []match
	n := len(buf)
	i := 0
	// prevRunStart/prevRunEnd track the immediately preceding run when it
	// is separated from the current position by exactly one ':' (the only
	// separator a telegram stitch tolerates). Any other non-run byte
	// clears them.
	prevRunStart, prevRunEnd := -1, -1
	for i < n {
		if !isRunByte(buf[i]) {
			if buf[i] != ':' {
				prevRunStart, prevRunEnd = -1, -1
			}
			i++
			continue
		}
		start := i
		for i < n && isRunByte(buf[i]) {
			i++
		}
		end := i

		// (a) Telegram-bot-token stitch. Peel the maximal trailing
		// all-digit suffix of the previous run — this handles both the
		// bare form (whole run is digits) and the glued URL form
		// (`bot123…`, a non-digit prefix then the id).
		if prevRunStart >= 0 && buf[prevRunEnd] == ':' && prevRunEnd+1 == start {
			ds := prevRunEnd
			for ds > prevRunStart && buf[ds-1] >= '0' && buf[ds-1] <= '9' {
				ds--
			}
			idLen := prevRunEnd - ds
			bodyLen := end - start
			if idLen >= tgIDMin && idLen <= tgIDMax &&
				bodyLen >= tgBodyMin && bodyLen <= tgBodyMax &&
				buf[start] == 'A' {
				out = append(out, match{
					Start:      ds,
					End:        end,
					MatchStart: ds,
					RuleID:     telegramTokenRuleID,
					Secret:     append([]byte(nil), buf[ds:end]...),
				})
				// The body was consumed by the stitch; carry it as the new
				// prev run and skip the generic check on it.
				prevRunStart, prevRunEnd = start, end
				continue
			}
		}

		// (b) Generic high-entropy net. Veto Itanium-mangled `_Z…` symbols
		// on the RAW run (before edge-trim would strip the leading '_'),
		// then trim edge '-'/'_' and gate the trimmed span.
		if !(end-start >= 2 && buf[start] == '_' && buf[start+1] == 'Z') {
			ts, te := start, end
			for ts < te && (buf[ts] == '-' || buf[ts] == '_') {
				ts++
			}
			for te > ts && (buf[te-1] == '-' || buf[te-1] == '_') {
				te--
			}
			if te-ts >= genericMinLen && passesSecretGate(buf, ts, ts, te, genericEntropy) {
				out = append(out, match{
					Start:      ts,
					End:        te,
					MatchStart: ts,
					RuleID:     genericEntropyRuleID,
					Secret:     append([]byte(nil), buf[ts:te]...),
				})
			}
		}
		prevRunStart, prevRunEnd = start, end
	}
	return out
}
