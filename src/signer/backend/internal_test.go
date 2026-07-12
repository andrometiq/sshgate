package backend

// In-package (white-box) tests for unexported helpers that the external
// backend_test package cannot reach: sanitiseExplainerErr, maskUserID,
// and runExplainer's panic-recovery. (The MockBackend double-resolve
// safety net moved to pkg/signerkit with mock.go.)

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
)

// panicExplainer is the panicking-Explainer fixture from the brief: it
// mimics the stubExplainer shape but blows up inside Explain. runExplainer
// must catch this, bump PanicsTotal, and signal the commands-only +
// footer fallback by returning a non-nil error.
type panicExplainer struct{}

func (panicExplainer) Explain(context.Context, []string) ([]string, error) {
	panic("explainer boom")
}

func TestSanitiseExplainerErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "unknown"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		// A wrapped deadline must still classify as timeout (errors.Is).
		{"wrapped_deadline", fmt.Errorf("explainer: http: %w", context.DeadlineExceeded), "timeout"},
		{"canceled", context.Canceled, "canceled"},
		{"wrapped_canceled", fmt.Errorf("explainer: %w", context.Canceled), "canceled"},
		// SECURITY: anything carrying a URL or bearer token must collapse
		// to a generic "upstream error" — never leak endpoints/creds to
		// the operator's Telegram DM.
		{"https_url", errors.New("dial https://api.openai.com/v1/chat failed"), "upstream error"},
		{"http_url", errors.New("connect http://10.0.0.1:8080 refused"), "upstream error"},
		{"bearer_token", errors.New("auth failed for Bearer sk-secret-xyz"), "upstream error"},
		// A plain short message passes through verbatim.
		{"plain", errors.New("model overloaded"), "model overloaded"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := sanitiseExplainerErr(c.err)
			if got != c.want {
				t.Errorf("sanitiseExplainerErr(%v) = %q; want %q", c.err, got, c.want)
			}
		})
	}
}

// TestSanitiseExplainerErr_TruncatesLongMessage checks the 80-char cap so
// a verbose upstream error can't blow up the Telegram footer. The result
// is truncated and ellipsised; crucially it must NOT contain the full
// original tail.
func TestSanitiseExplainerErr_TruncatesLongMessage(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 200)
	got := sanitiseExplainerErr(errors.New(long))
	if !strings.HasSuffix(got, "…") {
		t.Errorf("got = %q; want a trailing ellipsis on truncation", got)
	}
	// 80 runes + the ellipsis rune.
	if n := len([]rune(got)); n != 81 {
		t.Errorf("rune length = %d; want 81 (80 + ellipsis)", n)
	}
}

func TestMaskUserID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		id   int64
		want string
	}{
		// <= 4 digits → fully masked (can't reveal a short id meaningfully
		// without leaking most of it).
		{"one_digit", 5, "*"},
		{"three_digits", 123, "***"},
		{"four_digits", 1234, "****"},
		// > 4 digits → first 2 + middle stars + last 2.
		{"five_digits", 12345, "12*45"},
		{"seven_digits", 1234567, "12***67"},
		{"eight_digits", 77777777, "77****77"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := maskUserID(c.id)
			if got != c.want {
				t.Errorf("maskUserID(%d) = %q; want %q", c.id, got, c.want)
			}
			// The middle of a long id must never appear verbatim.
			if len(fmt.Sprintf("%d", c.id)) > 4 && strings.Contains(got, fmt.Sprintf("%d", c.id)) {
				t.Errorf("maskUserID(%d) = %q leaks the full id", c.id, got)
			}
		})
	}
}

// TestRunExplainerRecoversPanic asserts runExplainer catches a panicking
// Explainer: PanicsTotal increments, the returned error is non-nil (so
// the caller renders commands-only + footer), and lines is nil. This is
// the unit-level counterpart to the message-rendering fallback tests in
// telegram_test.go.
func TestRunExplainerRecoversPanic(t *testing.T) {
	t.Parallel()
	tb := &TelegramBackend{
		logger:    log.New(io.Discard, "", 0),
		Explainer: panicExplainer{},
	}
	before := tb.PanicsTotal()

	lines, err := tb.runExplainer(context.Background(), []CommandReq{{Server: "x", Cmd: "echo hi", TTLSec: 60}})
	if err == nil {
		t.Fatal("runExplainer returned nil err on a panicking Explainer; want a fallback-signalling error")
	}
	if lines != nil {
		t.Errorf("lines = %v; want nil after a panicking Explainer", lines)
	}
	if got := tb.PanicsTotal(); got != before+1 {
		t.Errorf("PanicsTotal = %d; want %d (incremented by the recovered panic)", got, before+1)
	}

	// And the sanitised reason for this error is a generic non-leaky
	// string suitable for the footer.
	if reason := sanitiseExplainerErr(err); reason == "" {
		t.Error("sanitiseExplainerErr returned empty for the panic error")
	}
}

// TestRunExplainerNoExplainerIsNoop verifies the early-return contract:
// a nil Explainer (or empty command list) yields (nil, nil) and never
// touches PanicsTotal.
func TestRunExplainerNoExplainerIsNoop(t *testing.T) {
	t.Parallel()
	tb := &TelegramBackend{logger: log.New(io.Discard, "", 0)}

	lines, err := tb.runExplainer(context.Background(), []CommandReq{{Cmd: "echo hi"}})
	if err != nil || lines != nil {
		t.Errorf("nil Explainer: got (%v, %v); want (nil, nil)", lines, err)
	}

	tb.Explainer = panicExplainer{}
	lines, err = tb.runExplainer(context.Background(), nil)
	if err != nil || lines != nil {
		t.Errorf("empty cmds: got (%v, %v); want (nil, nil)", lines, err)
	}
	if tb.PanicsTotal() != 0 {
		t.Errorf("PanicsTotal = %d; want 0 (no-op paths never invoke Explain)", tb.PanicsTotal())
	}
}
