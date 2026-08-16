package redact

import (
	"bytes"
	"sort"
)

// RedactString runs the streaming Layer-1 redactor over s in one shot and
// returns the scrubbed result. It is the canonical way to scrub a string
// that is about to be LOGGED (a command string, an audit field) — the
// SAME ruleset that scrubs command OUTPUT, applied to text at rest, so the
// assignment/Authorization/PGPASSWORD/URL cases are caught identically to
// how they are caught in output today.
//
// It is pure: (salt, rules, s) in, scrubbed string out; no shared state,
// no goroutine concerns (each call builds its own Writer). Benign input
// (no rule matches) passes through byte-for-byte unchanged.
//
// Fail-OPEN: on any internal Write/Close error it returns s unchanged AND
// ok=false, so the caller can log the raw string rather than DROP the
// audit line. Observability of "what ran" must never be blocked by the
// redactor; a missing audit line is worse than a rare un-redacted one.
//
// SCOPE NOTE: RedactString does NOT close the password-as-CLI-flag ruleset
// gap (e.g. `mysql -p<secret>`) — it reuses the existing Combined()
// ruleset, which only covers the URL-userinfo form of those secrets. See
// scrub_test.go's pinned XFAIL.
func RedactString(s string, salt [32]byte, rules []Rule) (string, bool) {
	if s == "" || len(rules) == 0 {
		return s, true
	}
	var buf bytes.Buffer
	w := NewWriter(&buf, salt, rules)
	if _, err := w.Write([]byte(s)); err != nil {
		return s, false
	}
	if err := w.Close(); err != nil {
		return s, false
	}
	return buf.String(), true
}

// ExactRedactedBytes proves how many original bytes the canonical redactor
// replaced. It refuses ambiguous overlapping matches and any divergence from
// the supplied redacted output.
func ExactRedactedBytes(s string, salt [32]byte, rules []Rule, redacted string) (hidden int, ok bool) {
	defer func() {
		if recover() != nil {
			hidden = 0
			ok = false
		}
	}()
	full := make([]Rule, 0, len(rules)+1)
	full = append(full, markerForgeryRule())
	full = append(full, rules...)
	scanner := newScanner(salt, full)
	raw := scanner.rawMatches([]byte(s))
	if len(raw) == 0 {
		return 0, false
	}
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].Start != raw[j].Start {
			return raw[i].Start < raw[j].Start
		}
		return raw[i].End < raw[j].End
	})
	hidden = 0
	previousEnd := -1
	for _, match := range raw {
		if match.Start < 0 || match.End <= match.Start || match.End > len(s) || match.Start < previousEnd {
			return 0, false
		}
		hidden += match.End - match.Start
		previousEnd = match.End
	}
	reconstructed, count := scanner.redact(nil, []byte(s), raw)
	if count != len(raw) || string(reconstructed) != redacted {
		return 0, false
	}
	return hidden, true
}
