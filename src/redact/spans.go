package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sort"
	"strings"
)

// MaxSpanInput is the largest input RedactSpans accepts. It equals ringMax,
// so the single Write inside RedactString never reaches the Writer's
// suppression path.
const MaxSpanInput = 64 << 10

// pemBlockRuleID labels a PEM wholesale span that no named rule matched.
const pemBlockRuleID = "pem-block"

// spanAlignBudget bounds the alignment search, counted in positions tried,
// bytes compared, bytes hashed and 64 per key derivation.
const spanAlignBudget = 1 << 22

const markerKeyLength = 8

const markerLength = len(MarkerPrefix) + markerKeyLength + len(MarkerSuffix)

// Span is one hidden region of the original input.
type Span struct {
	Start, End int      // byte offsets into the original input; End > Start
	RuleIDs    []string // sorted, deduplicated; pemBlockRuleID for an unnamed PEM wholesale span
}

// SpanResult is RedactString's output together with where its markers came from.
type SpanResult struct {
	Redacted    string // equals RedactString(s, salt, rules)
	Spans       []Span // ascending, non-overlapping
	HiddenBytes int    // sum of span lengths
}

// RedactSpans returns RedactString's output and the input span behind each
// marker in it. The spans are derived from the canonical redactor's own
// output, not recomputed: each marker is aligned back to the input bytes
// whose MarkerKey it carries, and every other output byte must equal the
// input byte it stands for (a neutralized forgery prefix stands for a
// literal MarkerPrefix and is not a span). It returns false for input over
// MaxSpanInput, when RedactString fails, and whenever the alignment is not
// unique or cannot be proven within a fixed work budget.
func RedactSpans(s string, salt [32]byte, rules []Rule) (SpanResult, bool) {
	if len(rules) == 0 {
		return SpanResult{Redacted: s}, true
	}
	if len(s) > MaxSpanInput {
		return SpanResult{}, false
	}
	redacted, ok := RedactString(s, salt, rules)
	if !ok {
		return SpanResult{}, false
	}
	spans, ok := alignSpans(s, redacted, salt)
	if !ok {
		return SpanResult{}, false
	}
	attachRuleIDs(s, salt, rules, spans)
	hidden := 0
	for _, span := range spans {
		hidden += span.End - span.Start
	}
	return SpanResult{Redacted: redacted, Spans: spans, HiddenBytes: hidden}, true
}

// markerSegment is one marker of the redacted output and the literal text
// that follows it up to the next marker.
type markerSegment struct {
	key          string
	literalAfter string
}

// parseRedacted splits redacted into its leading literal and its markers.
// Every MarkerPrefix must open a complete marker.
func parseRedacted(redacted string) (head string, markers []markerSegment, ok bool) {
	next := strings.Index(redacted, MarkerPrefix)
	if next < 0 {
		return redacted, nil, true
	}
	head, rest := redacted[:next], redacted[next:]
	for rest != "" {
		if len(rest) < markerLength || !strings.HasPrefix(rest[len(MarkerPrefix)+markerKeyLength:], MarkerSuffix) {
			return "", nil, false
		}
		key := rest[len(MarkerPrefix) : len(MarkerPrefix)+markerKeyLength]
		if !isMarkerKey(key) {
			return "", nil, false
		}
		rest = rest[markerLength:]
		next = strings.Index(rest, MarkerPrefix)
		if next < 0 {
			next = len(rest)
		}
		markers = append(markers, markerSegment{key: key, literalAfter: rest[:next]})
		rest = rest[next:]
	}
	return head, markers, true
}

func isMarkerKey(key string) bool {
	for i := 0; i < len(key); i++ {
		if !('0' <= key[i] && key[i] <= '9' || 'a' <= key[i] && key[i] <= 'f') {
			return false
		}
	}
	return true
}

// alignSpans maps every marker of redacted to the input span it replaced.
// Literal text consumes exactly its own length of input (a neutralized
// prefix is as long as MarkerPrefix), so only the span ends are searched.
func alignSpans(s, redacted string, salt [32]byte) ([]Span, bool) {
	head, markers, ok := parseRedacted(redacted)
	if !ok {
		return nil, false
	}
	aligner := &spanAligner{s: s, salt: salt, markers: markers, memo: map[int]alignment{}}
	if !aligner.literalAt(0, head) {
		return nil, false
	}
	if len(markers) == 0 {
		return nil, len(head) == len(s)
	}
	aligner.need = make([]int, len(markers))
	for m := len(markers) - 1; m >= 0; m-- {
		aligner.need[m] = len(markers[m].literalAfter)
		if m+1 < len(markers) {
			aligner.need[m] += 1 + aligner.need[m+1]
		}
	}
	if aligner.solve(0, len(head)) != 1 || aligner.work > spanAlignBudget {
		return nil, false
	}
	spans := make([]Span, 0, len(markers))
	start := len(head)
	for m, marker := range markers {
		end := aligner.memo[aligner.memoKey(m, start)].end
		// The search derives keys incrementally; the accepted spans are
		// checked against the canonical MarkerKey.
		if MarkerKey(salt, []byte(s[start:end])) != marker.key {
			return nil, false
		}
		spans = append(spans, Span{Start: start, End: end})
		start = end + len(marker.literalAfter)
	}
	return spans, true
}

type spanAligner struct {
	s       string
	salt    [32]byte
	markers []markerSegment
	need    []int // need[m]: the fewest input bytes markers[m].literalAfter and everything after it consume
	memo    map[int]alignment
	work    int
}

// alignment is the search result for one (marker, span start) state.
type alignment struct {
	count int // complete alignments from this state, capped at 2
	end   int // the span end of the alignment when count is 1
}

func (a *spanAligner) memoKey(m, start int) int {
	return m*(len(a.s)+1) + start
}

func (a *spanAligner) solve(m, start int) int {
	key := a.memoKey(m, start)
	if result, ok := a.memo[key]; ok {
		return result.count
	}
	result := a.search(m, start)
	a.memo[key] = result
	return result.count
}

// search counts the alignments in which markers[m] hides s[start:end] for
// some end, stopping at two.
func (a *spanAligner) search(m, start int) alignment {
	marker := a.markers[m]
	isLast := m == len(a.markers)-1
	last := len(a.s) - a.need[m]
	first := start + 1
	if isLast {
		first = max(last, first)
	}
	keyLimit := start + markerKeyInputLimit
	keys := spanKeys{aligner: a, mac: hmac.New(sha256.New, a.salt[:]), start: start, pos: start}
	var result alignment
	for end := first; end <= last && result.count < 2; end++ {
		a.work++
		if a.work > spanAlignBudget {
			return alignment{}
		}
		// Past the key-input limit every end shares one key.
		if end > keyLimit && keys.at(end) != marker.key {
			break
		}
		searchEnd := last
		if end <= keyLimit {
			searchEnd = min(last, keyLimit)
		}
		next := a.nextLiteral(end, searchEnd, marker.literalAfter)
		if next < 0 {
			if searchEnd == last {
				break
			}
			end = keyLimit
			continue
		}
		end = next
		if !a.literalAt(end, marker.literalAfter) || keys.at(end) != marker.key {
			continue
		}
		count := 1
		if !isLast {
			count = a.solve(m+1, end+len(marker.literalAfter))
		}
		if count > 0 {
			result.count += count
			result.end = end
		}
	}
	result.count = min(result.count, 2)
	return result
}

// nextLiteral returns the first position in [from, through] where lit can
// start, judged by its text before any neutralized prefix, or -1. A lit that
// opens with a neutralized prefix can stand for either prefix, so every
// position is a candidate.
func (a *spanAligner) nextLiteral(from, through int, lit string) int {
	needle := lit
	if i := strings.Index(lit, NeutralizedMarkerPrefix); i >= 0 {
		needle = lit[:i]
	}
	if needle == "" {
		return from
	}
	window := a.s[from:min(through+len(needle), len(a.s))]
	i := strings.Index(window, needle)
	if i < 0 {
		return -1
	}
	return from + i
}

// literalAt reports whether literal output text lit stands for the input
// at pos. A neutralized prefix in the output stands for a MarkerPrefix.
func (a *spanAligner) literalAt(pos int, lit string) bool {
	if pos+len(lit) > len(a.s) {
		return false
	}
	input := a.s[pos : pos+len(lit)]
	for i := 0; i < len(lit); {
		a.work++
		if strings.HasPrefix(lit[i:], NeutralizedMarkerPrefix) && strings.HasPrefix(input[i:], MarkerPrefix) {
			i += len(MarkerPrefix)
			continue
		}
		if lit[i] != input[i] {
			return false
		}
		i++
	}
	return true
}

// spanKeys derives MarkerKey(salt, s[start:end]) for ascending ends from one
// running HMAC; Sum does not change the hash state.
type spanKeys struct {
	aligner   *spanAligner
	mac       hash.Hash
	start     int
	pos       int
	truncated string
}

func (k *spanKeys) at(end int) string {
	stop := min(end, k.start+markerKeyInputLimit)
	if stop == k.start+markerKeyInputLimit && k.truncated != "" {
		return k.truncated
	}
	k.mac.Write([]byte(k.aligner.s[k.pos:stop]))
	k.aligner.work += stop - k.pos + 64
	k.pos = stop
	key := hex.EncodeToString(k.mac.Sum(nil)[:4])
	if stop == k.start+markerKeyInputLimit {
		k.truncated = key
	}
	return key
}

// attachRuleIDs labels each span with every rule match that intersects it.
// A span no match explains still counts as hidden.
func attachRuleIDs(s string, salt [32]byte, rules []Rule, spans []Span) {
	matches := newScanner(salt, rules).rawMatches([]byte(s))
	for k := range spans {
		span := &spans[k]
		ids := map[string]bool{}
		hasNamedMatch := false
		for _, m := range matches {
			if m.Start >= span.End || m.End <= span.Start {
				continue
			}
			ids[m.RuleID] = true
			if m.RuleID != genericEntropyRuleID && m.RuleID != telegramTokenRuleID {
				hasNamedMatch = true
			}
		}
		if !hasNamedMatch && strings.HasPrefix(s[span.Start:span.End], pemBegin) {
			ids[pemBlockRuleID] = true
		}
		for id := range ids {
			span.RuleIDs = append(span.RuleIDs, id)
		}
		sort.Strings(span.RuleIDs)
	}
}
