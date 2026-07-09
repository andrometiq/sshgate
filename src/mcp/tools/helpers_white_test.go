package tools

import (
	"errors"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/classify"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// White-box unit tests for the small pure helpers in run.go / run_batch.go.
// These live in `package tools` (not tools_test) because the helpers are
// unexported. They take no I/O and assert the exact remediation/labelling
// contracts the run/run_batch paths depend on.

// TestGateDenyNote pins the remediation string for each well-known gate
// deny exit code and confirms every other exit yields "" (so the caller
// does NOT annotate a normal non-zero exit as a gate deny).
func TestGateDenyNote(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		exit      int
		wantEmpty bool
		// substrings that MUST appear in a non-empty note.
		wantContains []string
	}{
		{
			name:         "77 missing-sig / read-only",
			exit:         77,
			wantContains: []string{"exit 77", "read-only", "/sshgate:setup", "sshgate add"},
		},
		{
			name:         "65 bad / expired signature",
			exit:         65,
			wantContains: []string{"exit 65", "expired", "retry"},
		},
		{name: "0 clean exit -> no note", exit: 0, wantEmpty: true},
		{name: "1 ordinary failure -> no note", exit: 1, wantEmpty: true},
		{name: "2 ordinary failure -> no note", exit: 2, wantEmpty: true},
		{name: "127 not-found -> no note", exit: 127, wantEmpty: true},
		{name: "negative -> no note", exit: -1, wantEmpty: true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := gateDenyNote(c.exit)
			if c.wantEmpty {
				if got != "" {
					t.Errorf("gateDenyNote(%d) = %q; want empty", c.exit, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("gateDenyNote(%d) = empty; want a remediation note", c.exit)
			}
			for _, sub := range c.wantContains {
				if !strings.Contains(got, sub) {
					t.Errorf("gateDenyNote(%d) = %q; want substring %q", c.exit, got, sub)
				}
			}
		})
	}
}

// TestAppendNote covers the three branches of appendNote: empty stderr
// (note stands alone), newline-terminated stderr (no extra newline), and
// non-newline-terminated stderr (one separator newline inserted). The
// invariant is that the note always ends up on its own line and is never
// dropped.
func TestAppendNote(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		stderr string
		note   string
		want   string
	}{
		{
			name:   "empty stderr returns note verbatim",
			stderr: "",
			note:   "remediation",
			want:   "remediation",
		},
		{
			name:   "newline-terminated stderr: no double newline",
			stderr: "boom\n",
			note:   "remediation",
			want:   "boom\nremediation",
		},
		{
			name:   "non-terminated stderr: separator inserted",
			stderr: "boom",
			note:   "remediation",
			want:   "boom\nremediation",
		},
		{
			name:   "multi-line newline-terminated stderr",
			stderr: "line1\nline2\n",
			note:   "note",
			want:   "line1\nline2\nnote",
		},
		{
			name:   "empty stderr with empty note",
			stderr: "",
			note:   "",
			want:   "",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := appendNote(c.stderr, c.note); got != c.want {
				t.Errorf("appendNote(%q, %q) = %q; want %q", c.stderr, c.note, got, c.want)
			}
		})
	}
}

// TestNewRequestID asserts the "r_" prefix, that ids are non-empty, and
// that repeated calls produce distinct values (the entropy is real).
func TestNewRequestID(t *testing.T) {
	t.Parallel()
	const n = 256
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id, err := newRequestID()
		if err != nil {
			t.Fatalf("newRequestID: %v", err)
		}
		if !strings.HasPrefix(id, "r_") {
			t.Fatalf("newRequestID() = %q; want r_ prefix", id)
		}
		if len(id) <= len("r_") {
			t.Fatalf("newRequestID() = %q; want body after the prefix", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("newRequestID() produced a duplicate id %q within %d calls", id, n)
		}
		seen[id] = struct{}{}
	}
}

// TestKindLabel maps each classifier Kind to its JSON-side label. Unknown
// must render "unknown" (defensive — the batch path rejects blanks before
// this is reached) rather than panic.
func TestKindLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		k    classify.Kind
		want string
	}{
		{"read", classify.KindRead, "read"},
		{"write", classify.KindWrite, "write"},
		{"unknown", classify.KindUnknown, "unknown"},
		{"out-of-range falls through to unknown", classify.Kind(99), "unknown"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := kindLabel(c.k); got != c.want {
				t.Errorf("kindLabel(%v) = %q; want %q", c.k, got, c.want)
			}
		})
	}
}

// TestClassifySignErr maps each sign-layer sentinel to its short
// machine-readable token, and confirms an arbitrary error falls through
// to "error". errors.Is wrapping is honoured (a wrapped sentinel maps the
// same as the bare sentinel).
func TestClassifySignErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"denied", signpkg.ErrDenied, "denied"},
		{"timeout", signpkg.ErrTimeout, "timeout"},
		{"permission", signpkg.ErrSignerPermission, "permission"},
		{"unreachable", signpkg.ErrUnreachable, "unreachable"},
		{"verdict_unknown", signpkg.ErrVerdictUnknown, "verdict_unknown"},
		{"wrapped denied still maps", fmtWrap(signpkg.ErrDenied), "denied"},
		{"wrapped unreachable still maps", fmtWrap(signpkg.ErrUnreachable), "unreachable"},
		{"wrapped verdict_unknown still maps", fmtWrap(signpkg.ErrVerdictUnknown), "verdict_unknown"},
		{"arbitrary error falls through", errors.New("boom"), "error"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := classifySignErr(c.err); got != c.want {
				t.Errorf("classifySignErr(%v) = %q; want %q", c.err, got, c.want)
			}
		})
	}
}

// fmtWrap wraps err so errors.Is still finds the sentinel — used to prove
// classifySignErr unwraps rather than comparing pointers.
func fmtWrap(err error) error {
	return errWrap{err}
}

type errWrap struct{ inner error }

func (e errWrap) Error() string { return "wrapped: " + e.inner.Error() }
func (e errWrap) Unwrap() error { return e.inner }
