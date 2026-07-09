package redact

import (
	"errors"
	"io"
)

// Writer sizing — the safe-prefix invariant.
//
// safePrefix is the number of trailing bytes we leave in the ring at
// the end of each Write so that a secret straddling chunk boundaries
// can still be matched on the next Write. 4 KiB covers every named
// rule in the v1.2 ruleset (the longest non-PEM regex still fits
// inside 4 KiB). PEM keys longer than safePrefix are handled by the
// PEM accumulator (see pem.go).
//
// ringInitial is the initial ring capacity; ringMax is the hard cap
// past which the writer flushes the head unconditionally. The cap
// exists so a single Write of 100 MB cannot make us hold all 100 MB
// in memory; the safe-prefix invariant only requires the *tail* to
// be retained.
const (
	safePrefix  = 4 * 1024
	ringInitial = 8 * 1024
	ringMax     = 64 * 1024
)

// ErrWriterClosed is returned by Write after Close has been called.
var ErrWriterClosed = errors.New("redact: write to closed writer")

// Writer is an io.WriteCloser that wraps an underlying writer and
// redacts any bytes matching its ruleset before forwarding them.
// Pipeline: Write → buffer → scan → emit-safe-prefix → forward.
//
// Concurrency: Writer is NOT goroutine-safe. The gate uses one
// writer per stream (stdout, stderr) and never shares them.
//
// Close flushes any remaining buffered bytes; it is safe to call
// multiple times.
type Writer struct {
	dst     io.Writer
	scanner *scanner

	buf    []byte
	closed bool

	// pem is non-nil while the writer is inside a PEM block.
	pem *pemAccumulator

	// suppressing is set when a ringMax forced-flush truncated a match
	// that still reached the buffer tail — i.e. a secret longer than
	// ringMax whose anchor has scrolled out of the window. The held
	// tail bytes are a continuation of that secret but no longer carry
	// the rule's anchor, so the regex can never re-match them. While
	// suppressing is true the writer drops (does not emit) all incoming
	// non-delimiter bytes as continuation of the redacted secret, and
	// clears the flag at the first whitespace/delimiter — the natural
	// end of a single token. This is the safe failure mode: it
	// over-redacts a pathological multi-megabyte single token rather
	// than ever leaking its raw bytes.
	suppressing bool
}

// isSecretDelimiter reports whether b terminates a contiguous secret
// token. Used by the ringMax suppression continuation to find where an
// anchor-less runaway secret ends.
func isSecretDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '"', '\'', '`', ';', '&', '|', '<', '>', '(', ')', '{', '}', ',':
		return true
	}
	return false
}

// NewWriter wraps dst. Every byte written through w passes Layer 1
// scanning using sessionSalt for HMAC marker keys; matched bytes are
// replaced with `[SSHGATE_REDACTED key=<8hex>]` before being forwarded
// to dst. rules is the compiled-in ruleset (see src/redact/rules/).
//
// A built-in marker-forgery rule is ALWAYS active in addition to the
// caller's ruleset (even when rules is nil): any literal MarkerPrefix
// the child prints is rewritten to NeutralizedMarkerPrefix so a
// surviving MarkerPrefix downstream provably came from the gate
// (MAJOR 6).
//
// The caller is responsible for closing the returned Writer.
// Close does NOT close dst.
func NewWriter(dst io.Writer, sessionSalt [32]byte, rules []Rule) *Writer {
	full := make([]Rule, 0, len(rules)+1)
	full = append(full, markerForgeryRule())
	full = append(full, rules...)
	return &Writer{
		dst:     dst,
		scanner: newScanner(sessionSalt, full),
		buf:     make([]byte, 0, ringInitial),
	}
}

// markerForgeryRule matches a literal MarkerPrefix in the byte stream.
// Its match is rewritten to NeutralizedMarkerPrefix by the scanner's
// redact step (keyed on markerForgeryRuleID) rather than replaced with
// a fresh marker — otherwise a forged marker would simply be reissued
// as a real-looking one. SecretGroup 0: the whole literal prefix is the
// span. The `[` is a regexp metachar, so it is escaped.
func markerForgeryRule() Rule {
	return CompileRule(
		markerForgeryRuleID,
		"literal SSHGATE marker prefix printed by the child (forgery guard)",
		regexpQuoteMarkerPrefix(),
		[]string{MarkerPrefix},
		0, 0, 0,
	)
}

// Write appends p to the internal ring buffer, scans for matches in
// the prefix that exceeds the safe-tail size, emits the scrubbed
// prefix to dst, and returns. The contract honours io.Writer: n is
// always len(p) on success (we always consume all input; the bytes
// may sit in the buffer until the next Write or Close).
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrWriterClosed
	}
	if len(p) == 0 {
		return 0, nil
	}

	// ringMax suppression continuation: we are mid-way through dropping a
	// secret longer than ringMax whose anchor scrolled out of the
	// window. Drop bytes until the token ends at a delimiter, then
	// resume normal processing on the remainder.
	if w.suppressing {
		i := 0
		for i < len(p) && !isSecretDelimiter(p[i]) {
			i++
		}
		w.scanner.suppressedBytes.Add(uint64(i))
		if i >= len(p) {
			// Entire chunk is continuation of the suppressed secret.
			return len(p), nil
		}
		// Token ended; the delimiter and everything after rejoin the
		// normal path.
		w.suppressing = false
		p = p[i:]
	}

	// PEM accumulator path: every byte goes into the accumulator
	// until it completes or aborts. The accumulator is responsible
	// for spilling unconsumed bytes back into the normal path.
	if w.pem != nil {
		if err := w.feedPEM(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	// Normal path: append, scan, emit.
	w.buf = append(w.buf, p...)
	if err := w.processBuffer(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes any buffered bytes (running them through one last
// scan with no safe-prefix held back) and marks the writer closed.
// Subsequent Writes return ErrWriterClosed. Close does not close
// the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.pem != nil {
		// Unterminated PEM at EOF. The accumulated bytes have NEVER
		// passed through the Layer-1 scanner, so flushing them raw leaks
		// secrets (BLOCKER 2). Two cases:
		//   1. The span opens with a real `...PRIVATE KEY-----` header —
		//      the stream ended mid-key. Redact the whole buffered span;
		//      an unterminated private key at EOF is still a private key.
		//   2. Otherwise it was a benign false BEGIN that simply never
		//      saw its END before the stream closed. Scan it through
		//      Layer 1 so any embedded named secret is caught while the
		//      surrounding bytes survive.
		buffered := w.pem.buf
		w.pem = nil
		if len(buffered) > 0 {
			if isPrivateKeyBegin(buffered) {
				marker := FormatMarker(w.scanner.salt, buffered)
				if _, err := w.dst.Write([]byte(marker)); err != nil {
					return err
				}
				w.scanner.redactCount.Add(1)
			} else if err := w.scanAndEmit(buffered); err != nil {
				return err
			}
		}
	}
	return w.processBuffer(true)
}

// feedPEM drives the accumulator. On completion the matched PEM
// span is replaced with a single marker (using HMAC of the secret
// bytes); on abort the buffered bytes pass through unchanged.
// Either way the unconsumed Tail is re-fed to the normal path so
// the next BEGIN inside the tail still triggers accumulator mode.
func (w *Writer) feedPEM(chunk []byte) error {
	res := w.pem.feed(chunk)
	switch {
	case res.Complete:
		w.pem = nil
		// Type-check the completed block. A verified `-----END-----`
		// means we hold a well-formed PEM span, so we can trust its
		// BEGIN label (W4-8).
		if isPublicPEMBegin(res.Buffered) {
			// Known public PEM — certificate / public key / CSR /
			// parameters. Pass the block through with ONLY the named
			// secret rules applied so its base64 body survives verbatim
			// (delivering `cat server.crt`, public keys, CSRs), while an
			// embedded credential in a header/comment is still caught. The
			// generic high-entropy net is deliberately skipped: a cert body
			// is a benign high-entropy blob, exactly like the SSH pubkey
			// body the generic net already vetoes.
			if err := w.scanNamedAndEmit(res.Buffered); err != nil {
				return err
			}
		} else {
			// A `…PRIVATE KEY…` block of any variant, OR an unrecognised
			// BEGIN label. Redact wholesale — fail closed: if we cannot
			// prove the type is public, treat the whole span as secret.
			marker := FormatMarker(w.scanner.salt, res.Buffered)
			if _, err := w.dst.Write([]byte(marker)); err != nil {
				return err
			}
			w.scanner.redactCount.Add(1)
		}
		// Re-feed tail through normal scan.
		if len(res.Tail) > 0 {
			w.buf = append(w.buf, res.Tail...)
			return w.processBuffer(false)
		}
		return nil
	case res.Aborted:
		w.pem = nil
		// The accumulator gave up looking for `-----END` after
		// pemMaxBuffer bytes. This span was NEVER seen by the Layer-1
		// scanner, so we must not flush it raw — a real AWS key / PAT /
		// password living in those bytes would leak verbatim (BLOCKER 1).
		//
		// Two recovery shapes:
		//   1. The span opens with a real `...PRIVATE KEY-----` header —
		//      treat it as a leaking key that simply lacks (so far) its
		//      END line and redact the whole span. Biasing toward
		//      redaction here is the safe call.
		//   2. Otherwise it is a benign false BEGIN (a log line that
		//      happened to contain `-----BEGIN `). Re-scan it (and the
		//      abort tail) through Layer 1 so any embedded named secret
		//      is still caught, while the surrounding noise passes
		//      through.
		if isPrivateKeyBegin(res.Buffered) {
			marker := FormatMarker(w.scanner.salt, res.Buffered)
			if _, err := w.dst.Write([]byte(marker)); err != nil {
				return err
			}
			w.scanner.redactCount.Add(1)
			if len(res.Tail) > 0 {
				w.buf = append(w.buf, res.Tail...)
				return w.processBuffer(false)
			}
			return nil
		}
		if err := w.scanAndEmit(res.Buffered); err != nil {
			return err
		}
		if len(res.Tail) > 0 {
			w.buf = append(w.buf, res.Tail...)
			return w.processBuffer(false)
		}
		return nil
	default:
		// Still in progress.
		return nil
	}
}

// processBuffer scans w.buf, splits it into a flushable prefix
// (everything past the safe-prefix tail) and a held tail, and emits
// the prefix. When flush=true (Close), the entire buffer is
// flushable.
func (w *Writer) processBuffer(flush bool) error {
	// If a BEGIN marker entered the buffer, transition to accumulate
	// mode for the BEGIN onward. We do this before length-based
	// flushing so the BEGIN never gets cut by the safe-prefix split.
	if idx := findPEMBegin(w.buf); idx >= 0 {
		// Emit any pre-BEGIN bytes that have already aged past the
		// safe prefix; the BEGIN-and-after move into the accumulator.
		head := w.buf[:idx]
		if len(head) > 0 {
			if err := w.scanAndEmit(head); err != nil {
				return err
			}
		}
		// Hand the BEGIN-and-after bytes to a fresh accumulator. The
		// accumulator might already see the matching END inside the
		// span we hand it; drive it once to handle that case (and to
		// uniformly handle the "input completes the PEM in one Write"
		// path).
		w.pem = &pemAccumulator{buf: make([]byte, 0, len(w.buf)-idx+512)}
		tail := append([]byte(nil), w.buf[idx:]...)
		w.buf = w.buf[:0]
		return w.feedPEM(tail)
	}

	// Decide how much of the buffer we can safely emit.
	var emitUpTo int
	switch {
	case flush:
		emitUpTo = len(w.buf)
	case len(w.buf) <= safePrefix:
		// Below safe-prefix: hold everything until the next Write or Close.
		return nil
	default:
		// Both the normal and "ring cap exceeded" paths emit
		// (len - safePrefix) so a secret straddling the prefix/tail
		// boundary still has the tail to match against next time.
		emitUpTo = len(w.buf) - safePrefix
	}

	if emitUpTo <= 0 {
		return nil
	}

	// Scan the entire buffer (prefix + tail) for matches. A match
	// whose start lies inside the prefix-to-emit is redacted on
	// emission. A match that straddles the prefix/tail boundary
	// (start at-or-before emitUpTo, end past emitUpTo) makes emitUpTo
	// retreat to the match's start — we retain the entire match in
	// the tail so it can complete or be matched again next round.
	//
	// The boundary test is `m.Start <= emitUpTo` (inclusive): a match
	// whose secret group begins exactly at emitUpTo and runs past it
	// would otherwise be split — the head bytes of the secret (its
	// anchor) emitted, the rest held with no anchor to re-match, so the
	// remainder leaks raw on the next round. Inclusive retention keeps
	// the whole match together.
	matches := w.scanner.findMatches(w.buf)
	for _, m := range matches {
		if m.Start <= emitUpTo && m.End > emitUpTo {
			// Straddler: hold the whole match — INCLUDING its anchor
			// (m.MatchStart, the keyword/prefix before the secret group)
			// — in the tail. Retreating only to m.Start (the secret
			// group) would flush the anchor, leaving the held remainder
			// un-re-matchable and so leaking raw next round.
			emitUpTo = m.MatchStart
			break
		}
	}

	// ringMax enforcement (the documented hard cap). The straddler
	// retreat above can drive emitUpTo back toward 0 round after round
	// for an adversarial open-ended match that never terminates — that
	// is the unbounded-growth bug ringMax exists to stop. Once the
	// buffer crosses ringMax we MUST flush rather than grow without
	// bound, and we must never flush a straddling secret raw.
	if !flush && len(w.buf) > ringMax {
		// Is there a match that reaches the very tail of the buffer
		// (m.End == len(buf))? That means an open secret whose anchor is
		// about to (or already did) scroll out of the window. Redact the
		// whole match from its anchor to the buffer end, drop the entire
		// buffer (retain nothing — a leftover anchor-less tail would leak
		// raw next round), and enter suppression so the secret's
		// continuation in the next Write is dropped until its delimiter.
		tailMatchStart := -1
		for _, m := range matches {
			if m.End != len(w.buf) {
				continue
			}
			if tailMatchStart < 0 || m.MatchStart < tailMatchStart {
				tailMatchStart = m.MatchStart
			}
		}
		if tailMatchStart >= 0 {
			// Emit any clean prefix before the open match, with its own
			// fully-contained matches redacted, then a single marker for
			// the open secret, then suppress its continuation.
			var headMatches []match
			for _, m := range matches {
				if m.End <= tailMatchStart {
					headMatches = append(headMatches, m)
				}
			}
			if err := w.emitWithMatches(w.buf[:tailMatchStart], headMatches); err != nil {
				return err
			}
			marker := FormatMarker(w.scanner.salt, w.buf[tailMatchStart:])
			if _, err := w.dst.Write([]byte(marker)); err != nil {
				return err
			}
			w.scanner.redactCount.Add(1)
			w.buf = w.buf[:0]
			w.suppressing = true
			return nil
		}
		// No tail-reaching match: a benign (or fully-contained-match)
		// buffer simply grew past the cap. Force-flush down to the safe
		// prefix, redacting any match that overlaps the flush boundary.
		forced := len(w.buf) - safePrefix
		if forced > emitUpTo {
			emitUpTo = forced
		}
		if err := w.emitRedactingOverlap(emitUpTo, matches); err != nil {
			return err
		}
		w.buf = append(w.buf[:0], w.buf[emitUpTo:]...)
		return nil
	}

	if emitUpTo <= 0 {
		// All matches straddle into the tail; hold the buffer for
		// next round. (Edge case only triggered by adversarial input
		// where a near-ring-max secret begins at offset 0 — bounded by
		// the ringMax flush above on the next Write.)
		return nil
	}

	// Keep only matches that fit fully within the prefix we're about
	// to emit; the writer's normal scan-on-next-Write picks up any
	// straddler we deferred above.
	var emitMatches []match
	for _, m := range matches {
		if m.End <= emitUpTo {
			emitMatches = append(emitMatches, m)
		}
	}

	if err := w.emitWithMatches(w.buf[:emitUpTo], emitMatches); err != nil {
		return err
	}
	// Compact: move the held tail to the start of the buffer.
	w.buf = append(w.buf[:0], w.buf[emitUpTo:]...)
	return nil
}

// emitRedactingOverlap flushes w.buf[:emitUpTo], redacting every match
// that overlaps the flushed region — including a match that straddles
// emitUpTo, whose tail past the boundary is dropped (truncated at the
// boundary). It is the ringMax safety valve: when the buffer is at the
// hard cap we cannot hold a never-terminating secret any longer, and we
// must never emit its bytes raw, so we redact the overlapping span up to
// the flush point. The redacted secret may be partial; that is fine — a
// partial marker is a redaction, not a leak.
func (w *Writer) emitRedactingOverlap(emitUpTo int, matches []match) error {
	var emitMatches []match
	for _, m := range matches {
		if m.Start >= emitUpTo {
			continue // entirely in the retained tail
		}
		mm := m
		if mm.End > emitUpTo {
			// Truncate the straddling match at the flush boundary so we
			// redact what we are about to emit; the remaining tail bytes
			// stay in the buffer and are re-scanned next round.
			mm.End = emitUpTo
			mm.Secret = append([]byte(nil), w.buf[mm.Start:emitUpTo]...)
		}
		emitMatches = append(emitMatches, mm)
	}
	return w.emitWithMatches(w.buf[:emitUpTo], emitMatches)
}

// emitWithMatches writes span to dst with the given pre-computed
// matches redacted. Counter is updated.
func (w *Writer) emitWithMatches(span []byte, matches []match) error {
	out := make([]byte, 0, len(span))
	out, n := w.scanner.redact(out, span, matches)
	if n > 0 {
		w.scanner.redactCount.Add(uint64(n))
	}
	if len(out) == 0 {
		return nil
	}
	_, err := w.dst.Write(out)
	return err
}

// scanAndEmit runs the scanner over span, writes the scrubbed bytes
// to dst, and updates the per-process counter. Used by the PEM
// pre-emit path where there's no need for straddler retention.
func (w *Writer) scanAndEmit(span []byte) error {
	matches := w.scanner.findMatches(span)
	return w.emitWithMatches(span, matches)
}

// scanNamedAndEmit runs ONLY the named ruleset (no generic default-deny
// net) over span and emits the scrubbed bytes. Used by the completed
// non-private PEM path (feedPEM) so a certificate / public-key / CSR base64
// body passes through verbatim while an embedded NAMED secret is redacted.
// See scanner.findNamedMatches for why the generic net must be skipped here.
func (w *Writer) scanNamedAndEmit(span []byte) error {
	matches := w.scanner.findNamedMatches(span)
	return w.emitWithMatches(span, matches)
}

// Redactions reports the total number of inline markers this writer
// has emitted. Cheap; safe to call from any goroutine.
func (w *Writer) Redactions() uint64 {
	return w.scanner.Stats()
}

// Buffered reports the number of bytes currently held in the writer's
// safe-prefix ring (plus any PEM accumulator). It exists so the
// ringMax invariant (the buffer is bounded regardless of input) is
// observable and testable. The returned figure is the live held-byte
// count, not a high-water mark.
func (w *Writer) Buffered() int {
	n := len(w.buf)
	if w.pem != nil {
		n += len(w.pem.buf)
	}
	return n
}

// RingMax returns the writer's hard ring-buffer cap in bytes. Exposed
// so tests can assert the documented bound without hard-coding the
// constant.
func RingMax() int { return ringMax }
