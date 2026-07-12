package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// White-box tests for the unexported format* helpers and
// isCleanShutdown. These live in package mcp (not mcp_test) so they can
// reach the unexported funcs directly — no production seam is added.

// TestFormatStatusSummary_Branches exercises the three mutually
// exclusive branches of formatStatusSummary's signer switch: reachable,
// not-configured (Tier 1), and configured-but-unreachable (Tier 2 down).
func TestFormatStatusSummary_Branches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		signer     tools.SignerStatus
		wantSubstr []string
		notSubstr  []string
	}{
		{
			name:       "healthy reachable",
			signer:     tools.SignerStatus{Path: "/run/s.sock", Reachable: true, Configured: true},
			wantSubstr: []string{"signer: reachable", "/run/s.sock"},
			notSubstr:  []string{"UNREACHABLE", "not configured"},
		},
		{
			name:       "tier1 not configured",
			signer:     tools.SignerStatus{Path: "/run/s.sock", Reachable: false, Configured: false},
			wantSubstr: []string{"not configured", "/run/s.sock", "read-only", "Tier 1"},
			notSubstr:  []string{"UNREACHABLE", "reachable ("},
		},
		{
			name:       "tier2 configured but unreachable",
			signer:     tools.SignerStatus{Path: "/run/s.sock", Reachable: false, Configured: true, Error: "dial: connection refused"},
			wantSubstr: []string{"UNREACHABLE", "/run/s.sock", "dial: connection refused"},
			notSubstr:  []string{"not configured", "signer: reachable"},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := tools.StatusOutput{SignerSocket: tc.signer}
			got := formatStatusSummary(out)
			for _, w := range tc.wantSubstr {
				if !strings.Contains(got, w) {
					t.Errorf("summary %q missing %q", got, w)
				}
			}
			for _, n := range tc.notSubstr {
				if strings.Contains(got, n) {
					t.Errorf("summary %q unexpectedly contains %q", got, n)
				}
			}
		})
	}
}

// TestFormatStatusSummary_ServerRows asserts the per-server up/down
// lines render alongside whichever signer branch is active.
func TestFormatStatusSummary_ServerRows(t *testing.T) {
	t.Parallel()
	out := tools.StatusOutput{
		SignerSocket: tools.SignerStatus{Path: "/run/s.sock", Reachable: true, Configured: true},
		Servers: []tools.ServerStatus{
			{Alias: "up", Reachable: true, PingMS: 12},
			{Alias: "down", Reachable: false, Error: "dial timeout"},
		},
	}
	got := formatStatusSummary(out)
	if !strings.Contains(got, "up: ok 12ms") {
		t.Errorf("missing up row: %q", got)
	}
	if !strings.Contains(got, "down: DOWN dial timeout") {
		t.Errorf("missing down row: %q", got)
	}
}

// TestGateDenyNoteFor covers the two well-known gate deny exit codes
// (77 / 65) on writes, plus the cases that must yield no note: reads,
// other exit codes, and a clean exit.
func TestGateDenyNoteFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		r          tools.CommandResult
		wantNote   bool
		wantSubstr string
	}{
		{
			name:       "write exit 77 -> read-only / missing-sig note",
			r:          tools.CommandResult{Kind: "write", ExitCode: 77},
			wantNote:   true,
			wantSubstr: "exit 77",
		},
		{
			name:       "write exit 65 -> bad/expired-sig note",
			r:          tools.CommandResult{Kind: "write", ExitCode: 65},
			wantNote:   true,
			wantSubstr: "exit 65",
		},
		{
			name:     "write exit 0 -> no note",
			r:        tools.CommandResult{Kind: "write", ExitCode: 0},
			wantNote: false,
		},
		{
			name:     "write exit 1 (ordinary failure) -> no note",
			r:        tools.CommandResult{Kind: "write", ExitCode: 1},
			wantNote: false,
		},
		{
			name:     "read exit 77 -> no note (reads never carry gate denies)",
			r:        tools.CommandResult{Kind: "read", ExitCode: 77},
			wantNote: false,
		},
		{
			name:     "read exit 65 -> no note",
			r:        tools.CommandResult{Kind: "read", ExitCode: 65},
			wantNote: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			note := gateDenyNoteFor(tc.r)
			if tc.wantNote {
				if note == "" {
					t.Fatalf("got empty note; want non-empty")
				}
				if !strings.Contains(note, tc.wantSubstr) {
					t.Errorf("note %q missing %q", note, tc.wantSubstr)
				}
			} else if note != "" {
				t.Errorf("got note %q; want empty", note)
			}
		})
	}
}

// TestFormatSummaries_EchoDenial pins the #26-core one-line denial summary
// echo appended to the fallback TextContent summaries (for text-only clients).
// The echo is strictly APPENDED — the existing summary text is unchanged.
func TestFormatSummaries_EchoDenial(t *testing.T) {
	t.Parallel()

	// run: a Denial on the RunOutput appends "denial: <summary>".
	d := &tools.Denial{VerdictClass: tools.VerdictReadOnlyServer, Summary: "ROSUMMARY"}
	runOut := tools.RunOutput{Kind: "write", ExitCode: 77, Denial: d}
	if got := formatRunSummary(runOut); !strings.Contains(got, "denial: ROSUMMARY") {
		t.Errorf("formatRunSummary missing denial echo: %q", got)
	}

	// run_batch, whole-batch denied path.
	batchDenied := tools.RunBatchOutput{
		Server: "h1", Denied: true, Reason: "denied",
		Denial: &tools.Denial{VerdictClass: tools.VerdictApprovalDenied, Summary: "DENYSUM"},
	}
	if got := formatRunBatchSummary(batchDenied); !strings.Contains(got, "denial: DENYSUM") {
		t.Errorf("formatRunBatchSummary (denied) missing denial echo: %q", got)
	}

	// run_batch, per-command gate deny (batch ran; Denied=false).
	batchRan := tools.RunBatchOutput{
		Server:  "h1",
		Results: []tools.CommandResult{{Command: "rm x", Kind: "write", ExitCode: 77}},
		Denial:  &tools.Denial{VerdictClass: tools.VerdictMissingSignature, Summary: "MISSSUM"},
	}
	got := formatRunBatchSummary(batchRan)
	if !strings.Contains(got, "denial: MISSSUM") {
		t.Errorf("formatRunBatchSummary (per-command deny) missing denial echo: %q", got)
	}
	// Appended, not replacing: the existing batch header line is still present.
	if !strings.Contains(got, "batch on h1") {
		t.Errorf("existing batch summary text was altered: %q", got)
	}
}

// TestTruncate covers the under-limit (untouched), at-limit (untouched),
// and over-limit (truncated + marker) cases.
func TestTruncate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		in        string
		max       int
		want      string
		truncated bool
	}{
		{name: "under limit unchanged", in: "abc", max: 5, want: "abc"},
		{name: "exactly at limit unchanged", in: "abcde", max: 5, want: "abcde"},
		{name: "over limit truncated", in: "abcdefgh", max: 5, truncated: true},
		{name: "empty unchanged", in: "", max: 5, want: ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := truncate(tc.in, tc.max)
			if tc.truncated {
				if !strings.HasPrefix(got, tc.in[:tc.max]) {
					t.Errorf("truncated output %q does not start with first %d bytes", got, tc.max)
				}
				if !strings.Contains(got, "[...truncated]") {
					t.Errorf("truncated output %q missing marker", got)
				}
			} else if got != tc.want {
				t.Errorf("truncate(%q,%d) = %q; want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

// TestIsCleanShutdown_TextualClassification asserts the textual
// last-resort matches (the SDK sometimes wraps EOF into a string that no
// longer satisfies errors.Is(io.EOF)) and the sentinel/typed matches,
// plus that an ordinary runtime error is NOT classified clean.
func TestIsCleanShutdown_TextualClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil is clean", err: nil, want: true},
		{name: "io.EOF sentinel", err: io.EOF, want: true},
		{name: "context.Canceled", err: context.Canceled, want: true},
		{name: "context.DeadlineExceeded", err: context.DeadlineExceeded, want: true},
		{name: "SDK ErrConnectionClosed", err: mcpsdk.ErrConnectionClosed, want: true},
		// Textual-only: a fresh error whose message contains the wrapper
		// phrase but is NOT errors.Is-linked to any sentinel.
		{name: "textual server is closing", err: errors.New("jsonrpc2: server is closing: read error"), want: true},
		{name: "textual EOF substring", err: errors.New("transport delivered EOF unexpectedly"), want: true},
		// A genuine runtime failure must NOT be swallowed as clean.
		{name: "runtime error not clean", err: errors.New("permission denied writing socket"), want: false},
		{name: "wrapped EOF via fmt", err: fmt.Errorf("read loop: %w", io.EOF), want: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isCleanShutdown(tc.err); got != tc.want {
				t.Errorf("isCleanShutdown(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}
