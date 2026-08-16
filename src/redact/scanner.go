package redact

import (
	"sort"
	"sync/atomic"
)

// scanner runs the Layer 1 named-format ruleset against a byte
// buffer. It is the workhorse of the writer's hot path.
//
// Conflict-resolution order (locked spec §"Conflict resolution"):
//
//  1. Layer 1 named regex (built-in + sshgate-native + gitleaks).
//     Matches are sticky in v1.2.
//  2. Layer 2 file-mode heuristic. (R3 — not in R1.)
//  3. Layer 1 entropy. (thorough mode only — absent in v1.2.)
//  4. Recursive decode pass. (R4 — not in R1.)
//  5. Layer 3 redactlist. (R2 — not in R1.)
//  6. Emit remaining flagged spans as redactions.
//
// R1 implements step 1 only; the writer's chunk path is structured
// so steps 2-5 hook in at well-defined points without re-plumbing.

type scanner struct {
	rules []Rule
	salt  [32]byte

	// redactCount is a per-process counter of inline matches turned
	// into markers. Exposed via Stats(); a future redact.list /
	// redact.stats command (R5) reads it.
	redactCount atomic.Uint64

	// suppressedBytes counts bytes dropped by the ringMax suppression
	// continuation (a secret longer than ringMax whose anchor scrolled
	// out of the window). Bookkeeping only; observable via stats.
	suppressedBytes atomic.Uint64
}

func newScanner(salt [32]byte, rules []Rule) *scanner {
	return &scanner{rules: rules, salt: salt}
}

// match is a single rule hit on a buffer. Start/End are byte offsets
// into the buffer where the secret group lies (the bytes that get
// replaced with a marker); RuleID identifies which rule fired (used for
// audit logging in R2+).
//
// MatchStart is the offset of the FULL match (including any keyword/
// anchor prefix that sits before the secret group). It is used by the
// writer's straddler-retention logic: when a match crosses the
// prefix/tail boundary we must retain it starting from its anchor, not
// from the secret group — otherwise the anchor flushes out and the
// remaining secret can no longer be re-matched, leaking raw. MatchStart
// <= Start always.
type match struct {
	Start, End int
	MatchStart int
	RuleID     string
	Secret     []byte
}

// findMatches returns all rule matches inside buf, sorted by start
// offset and de-overlapped (earlier match wins). It is the full R1
// pipeline: the named regex ruleset PLUS the generic default-deny net.
// The result is a fresh slice — caller owns it.
func (s *scanner) findMatches(buf []byte) []match {
	if len(buf) == 0 || len(s.rules) == 0 {
		return nil
	}
	out := s.rawMatches(buf)
	return dedupMatches(out)
}

// rawMatches returns the complete, unresolved rule output. Callers that need
// to prove an exact source-byte mapping must reject overlaps before the
// writer's safe union/deduplication changes match cardinality.
func (s *scanner) rawMatches(buf []byte) []match {
	out := s.namedMatches(buf)
	// Step 3: the generic default-deny net (scanGenericRuns). It sits
	// AFTER the len(s.rules)==0 early return above, so the nil-rules
	// verbatim contract (scrub/pem nil-rules tests) is preserved — a real
	// Writer always carries the prepended marker-forgery rule, so the net
	// always runs inside a Writer. dedupMatches merges its output with the
	// regex matches (earliest-start-wins, tie -> longest).
	out = append(out, scanGenericRuns(buf)...)
	return out
}

// findNamedMatches returns matches from the named regex ruleset ONLY —
// it deliberately SKIPS the generic default-deny net (scanGenericRuns).
// It backs the completed non-private PEM path (writer.go): a certificate
// / public-key / CSR body is a benign high-entropy base64 blob — exactly
// like the SSH pubkey body the generic net already vetoes — so routing it
// through the generic net would re-redact it and defeat `cat server.crt`.
// The named rules still run so an embedded NAMED secret (an AWS key, a
// PAT, a `password=` line in a header comment) inside the block is caught.
func (s *scanner) findNamedMatches(buf []byte) []match {
	if len(buf) == 0 || len(s.rules) == 0 {
		return nil
	}
	return dedupMatches(s.namedMatches(buf))
}

// namedMatches runs the Layer-1 named regex ruleset over buf and returns
// the raw (un-deduped) matches. It is the shared core of findMatches (which
// adds the generic net) and findNamedMatches (which does not).
func (s *scanner) namedMatches(buf []byte) []match {
	var out []match
	for _, r := range s.rules {
		if !r.matchesKeyword(buf) {
			continue
		}
		idxs := r.Regex.FindAllSubmatchIndex(buf, -1)
		for _, ix := range idxs {
			matchStart := ix[0]
			start, end := ix[0], ix[1]
			if r.SecretGroup > 0 {
				// FindAllSubmatchIndex returns 2*N+2 ints per match:
				// [matchStart, matchEnd, g1Start, g1End, g2Start, g2End, ...]
				gi := 2 * r.SecretGroup
				if gi+1 < len(ix) && ix[gi] >= 0 {
					start, end = ix[gi], ix[gi+1]
				}
			}
			n := end - start
			if r.MinLen > 0 && n < r.MinLen {
				continue
			}
			// MaxLen trims runaway low-confidence matches. High-
			// confidence structural rules (JWT, PEM) are exempt: an
			// over-long match is still unmistakably the secret and must
			// be redacted, never dropped (MINOR 7).
			if r.MaxLen > 0 && n > r.MaxLen && !r.HighConfidence {
				continue
			}
			// Layer 1 entropy (the conflict-resolution slot reserved
			// above): a rule that opts in via Rule.Entropy > 0 is a broad
			// prefix rule (sk-<base62>) that must additionally clear the
			// entropy gate — 3-class content + Shannon entropy — so it does
			// not fire on lowercase key-type markers or prose slugs. NOTE:
			// this is passesEntropyGate, NOT passesSecretGate — a NAMED rule
			// must fire even on a line that also contains an ssh key-type
			// marker (the ssh-line veto belongs only to the generic net;
			// 3-class alone already rejects the lowercase FIDO markers the
			// veto was meant for, so applying it here only leaked keys).
			if r.Entropy > 0 && !passesEntropyGate(buf[start:end], r.Entropy) {
				continue
			}
			// Scoped SSH-pubkey veto (W4-9). ONE rule opts in via
			// WithSSHLineVeto: gitleaks-twitter-bearer, whose `AAAA…`
			// pattern also matches the base64 body of an ed25519/rsa
			// public key in authorized_keys / known_hosts. Drop the match
			// ONLY when BOTH hold: (a) an SSH key-type marker precedes it
			// on the same line (sshLineContext — the authorized_keys/
			// known_hosts context), AND (b) the matched body itself begins
			// with a recognised SSH-pubkey wire-format prefix (the base64
			// encoding of an `ssh-ed25519`/`ssh-rsa`/`ecdsa-sha2-…` key
			// type). Requiring (b) is the anti-spoof: a real Twitter bearer
			// (`AAAAAAAAAAAAAAAAAAAAAM…`) does NOT encode an SSH key type,
			// so prefixing it with a fake `ssh-rsa ` token cannot smuggle it
			// past redaction — it fails (b) and is still redacted. The veto
			// stays on this rule alone; a blanket named-path veto would let
			// a keyed secret escape by sharing a line with `ssh-rsa`.
			if r.VetoOnSSHLine &&
				sshLineContext(buf, matchStart) &&
				hasSSHPubkeyBodyPrefix(buf[start:end]) {
				continue
			}
			out = append(out, match{
				Start:      start,
				End:        end,
				MatchStart: matchStart,
				RuleID:     r.ID,
				Secret:     append([]byte(nil), buf[start:end]...),
			})
		}
	}
	return out
}

// dedupMatches sorts matches by start and merges overlaps. Same-start
// ties resolve to the longer match. When a later match overlaps an
// already-kept one BUT extends past its end, the kept match is extended to
// cover the UNION rather than the later match being dropped: dropping the
// remainder would leak the bytes beyond the kept end. That leak is real —
// a telegram-stitch match [id:body] whose id was peeled from the tail of a
// longer, earlier-starting generic run overlaps that run and reaches past
// it; a drop-the-remainder policy discarded the stitch and emitted the
// token body raw. Extending (union-merge) redacts the whole span and is
// always the safe direction for a default-deny redactor (never less
// redaction than before). The merged marker is re-keyed over the union
// bytes, reusing each match's own copied Secret (no buf needed).
func dedupMatches(in []match) []match {
	if len(in) <= 1 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start != in[j].Start {
			return in[i].Start < in[j].Start
		}
		// Tie-break: longer match first.
		return (in[i].End - in[i].Start) > (in[j].End - in[j].Start)
	})
	out := in[:0:len(in)]
	lastEnd := -1
	for _, m := range in {
		if m.Start < lastEnd {
			if m.End > lastEnd {
				// Union-merge: extend the kept match to m.End and append the
				// non-overlapping tail of m's secret (m.Secret is buf[m.Start:
				// m.End]; the tail past lastEnd starts at lastEnd-m.Start).
				k := &out[len(out)-1]
				k.Secret = append(append([]byte(nil), k.Secret...), m.Secret[lastEnd-m.Start:]...)
				k.End = m.End
				lastEnd = m.End
			}
			continue
		}
		out = append(out, m)
		lastEnd = m.End
	}
	return out
}

// redact emits a redacted copy of buf into dst, replacing every
// matched span with the appropriate inline marker. n is the number
// of matches applied; the writer reports it to the process-wide
// counter on Close.
func (s *scanner) redact(dst, buf []byte, matches []match) ([]byte, int) {
	if len(matches) == 0 {
		return append(dst, buf...), 0
	}
	prev := 0
	for _, m := range matches {
		dst = append(dst, buf[prev:m.Start]...)
		if m.RuleID == markerForgeryRuleID {
			// Child printed a literal MarkerPrefix — rewrite it to the
			// sanitized form instead of issuing a fresh marker, so the
			// forgery cannot masquerade as a gate redaction.
			dst = append(dst, NeutralizedMarkerPrefix...)
		} else {
			dst = append(dst, FormatMarker(s.salt, m.Secret)...)
		}
		prev = m.End
	}
	dst = append(dst, buf[prev:]...)
	return dst, len(matches)
}

// Stats reports the per-process redaction counter. Exposed so a
// future signed redact.stats command (R5) can return it; today only
// tests consume it.
func (s *scanner) Stats() uint64 {
	return s.redactCount.Load()
}
