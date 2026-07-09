package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Rule is a single named-format detection rule. As of the 2026-07
// default-deny widening, Entropy is a LIVE standard-scanner feature: a
// rule with Entropy > 0 is additionally gated by passesSecretGate
// (3-class content + ssh-line veto + Shannon entropy), so a broad prefix
// rule (sk-<base62>) does not fire on lowercase key-type markers or prose
// slugs. Set it via WithEntropy. `thorough` mode (docs/FUTURE.md) will add
// looser gates on top; the standard scanner already consults this field.
//
// Keywords is a cheap substring pre-filter: if a chunk does not
// contain at least one of the rule's keywords, the (much more
// expensive) regex match is skipped entirely. AND-of-any semantics —
// any single keyword present is enough to enable the regex. A rule
// with no keywords is always scanned (use sparingly; named-format
// rules almost always have a structural prefix that doubles as a
// keyword).
//
// SecretGroup names the regex capture group whose contents should be
// redacted. 0 means "the whole match". A rule whose secret is a
// substring of the match (e.g. `Authorization: Bearer <token>`) uses
// SecretGroup=1 so only the token is replaced, not the header.
//
// MinLen / MaxLen are post-match length filters applied to the
// secret group. Both zero means "no length filter". They exist to
// trim runaway matches (a 200KB blob of base64-shaped noise should
// not match the AWS access-key rule).
type Rule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	Keywords    []string
	SecretGroup int
	Entropy     float64
	MinLen      int
	MaxLen      int

	// HighConfidence marks a rule whose structural prefix is so
	// distinctive (e.g. a JWT's `eyJ.<b64>.<b64>.<b64>`, a PEM
	// `-----BEGIN`) that a match is a secret regardless of how long it
	// is. The scanner SKIPS the MaxLen filter for such rules (MINOR 7):
	// MaxLen exists to trim runaway low-confidence matches, but a
	// 5000-char JWT is still unmistakably a JWT and must be redacted —
	// dropping it because it is "too long" leaks a real secret. The
	// marker is keyed on a truncated prefix of the secret (see
	// markerKeyInputLimit), not the whole span, so an over-long secret
	// cannot blow up marker derivation.
	HighConfidence bool

	// VetoOnSSHLine, when set, drops a match that is genuinely an SSH
	// public-key body on an authorized_keys / known_hosts line. It exists
	// for the ONE rule (gitleaks-twitter-bearer) whose `AAAA…` pattern
	// also matches the base64 body of an ed25519/rsa public key. The veto
	// fires only when an SSH key-type marker precedes the match on the
	// same line AND the matched body itself begins with a recognised SSH
	// wire-format prefix (see scanner.go / hasSSHPubkeyBodyPrefix) — so a
	// real bearer token cannot be smuggled past redaction by prefixing it
	// with a fake `ssh-` token. Keep it on twitter-bearer alone; a blanket
	// named-path veto would leak keyed secrets that share a line with an
	// ssh marker. Set via WithSSHLineVeto.
	VetoOnSSHLine bool
}

// WithHighConfidence returns a copy of r marked high-confidence so the
// scanner exempts it from the MaxLen filter. See Rule.HighConfidence.
func (r Rule) WithHighConfidence() Rule {
	r.HighConfidence = true
	return r
}

// WithEntropy returns a copy of r whose match is additionally gated by the
// shared generic-secret gate at the given Shannon threshold (bits/byte):
// findMatches keeps the match only if the secret span also clears
// passesSecretGate (3-class content + ssh-line veto + entropy). Used by
// broad-prefix rules (e.g. sk-<base62>) that would otherwise fire on
// lowercase key-type markers (sk-ecdsa-sha2-…) and prose slugs. See
// scanner_generic.go. A threshold of 0 leaves the rule ungated.
func (r Rule) WithEntropy(bitsPerByte float64) Rule {
	r.Entropy = bitsPerByte
	return r
}

// WithSSHLineVeto returns a copy of r whose match is dropped when it is a
// genuine SSH public-key body on an authorized_keys / known_hosts line —
// an SSH key-type marker precedes it on the line AND the body carries an
// SSH wire-format prefix. See Rule.VetoOnSSHLine. Apply ONLY to the
// twitter-bearer rule (its `AAAA…` pattern collides with ed25519/rsa
// pubkey bodies); do not generalise it.
func (r Rule) WithSSHLineVeto() Rule {
	r.VetoOnSSHLine = true
	return r
}

// CompileRule builds a Rule from its plaintext regex source. Used by
// the per-source rule files in src/redact/rules/{gitleaks,sshgate}/
// so that the regex compile-error path is one place, not N.
//
// Panics on a bad regex: rules are compiled once at package
// initialisation and a broken built-in rule is a programmer bug we
// want surfaced at gate startup, not silently logged.
func CompileRule(id, desc, pattern string, keywords []string, secretGroup int, minLen, maxLen int) Rule {
	re := regexp.MustCompile(pattern)
	// Normalise keywords to lowercase for the case-insensitive
	// pre-filter. The regex itself decides case sensitivity.
	kw := make([]string, len(keywords))
	for i, k := range keywords {
		kw[i] = strings.ToLower(k)
	}
	return Rule{
		ID:          id,
		Description: desc,
		Regex:       re,
		Keywords:    kw,
		SecretGroup: secretGroup,
		MinLen:      minLen,
		MaxLen:      maxLen,
	}
}

// matchesKeyword reports whether buf contains any of the rule's
// keywords (case-insensitively). Rules with zero keywords always
// match — caller should weigh whether that rule is worth the regex
// cost on every chunk.
//
// The lowercase conversion uses a tight inline ASCII-only fold to
// avoid allocations in the hot path; non-ASCII bytes pass through
// unchanged (rule keywords are all ASCII).
func (r Rule) matchesKeyword(buf []byte) bool {
	if len(r.Keywords) == 0 {
		return true
	}
	for _, kw := range r.Keywords {
		if indexFoldASCII(buf, kw) >= 0 {
			return true
		}
	}
	return false
}

// indexFoldASCII returns the byte index of needle in haystack under
// ASCII case folding, or -1 if not found. needle must already be
// lowercase. Allocation-free.
func indexFoldASCII(haystack []byte, needle string) int {
	if needle == "" {
		return 0
	}
	n := len(needle)
	for i := 0; i+n <= len(haystack); i++ {
		match := true
		for j := 0; j < n; j++ {
			c := haystack[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// SortRules returns a copy of rules sorted by ID with duplicates by
// ID removed (last occurrence wins — used by the generated combined
// rule set so an SSHGate-native rule can override a gitleaks rule of
// the same ID).
func SortRules(rules []Rule) []Rule {
	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	out := make([]Rule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Validate reports any obviously-broken rule (empty ID, nil regex,
// SecretGroup out of range). Used by the generator and at package
// init time; surfaces bad rules at build time, not at runtime under
// load.
func Validate(rules []Rule) error {
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("rule %d: empty ID", i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("rule %s: duplicate ID", r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Regex == nil {
			return fmt.Errorf("rule %s: nil Regex", r.ID)
		}
		if r.SecretGroup < 0 || r.SecretGroup > r.Regex.NumSubexp() {
			return fmt.Errorf("rule %s: SecretGroup %d out of range (regex has %d subexpressions)", r.ID, r.SecretGroup, r.Regex.NumSubexp())
		}
	}
	return nil
}
