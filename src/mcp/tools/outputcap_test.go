package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// markerPrefix is the start of the truncation marker capOutput appends.
const markerPrefix = "\n[...truncated"

// TestRun_OutputCapTruncatesWithMarker asserts that a read whose output
// exceeds the cap is truncated to exactly the cap of ORIGINAL bytes, with a
// marker naming the total size appended OUTSIDE the budget (W5-11).
func TestRun_OutputCapTruncatesWithMarker(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	big := strings.Repeat("a", 5000)
	ssh := &fakeSSH{stdout: []byte(big)}
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: ssh, DefaultMaxOutputBytes: 1000}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "cat big"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	idx := strings.Index(out.Stdout, markerPrefix)
	if idx < 0 {
		t.Fatalf("Stdout missing truncation marker")
	}
	// Kept content is exactly the first 1000 bytes (all single-byte 'a').
	kept := out.Stdout[:idx]
	if kept != strings.Repeat("a", 1000) {
		t.Errorf("kept len=%d; want exactly 1000 bytes before the marker", len(kept))
	}
	// Marker names the total original size, so the reader knows how much was lost.
	if !strings.Contains(out.Stdout, "of 5000 bytes") {
		t.Errorf("marker should name total 5000 bytes: %q", out.Stdout[idx:])
	}
}

// TestRun_OutputUnderCapPassthrough asserts output at or under the cap is
// returned byte-identical, with no marker.
func TestRun_OutputUnderCapPassthrough(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	body := "hello world\n"
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte(body)}, DefaultMaxOutputBytes: 1000}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "echo hi"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Stdout != body {
		t.Errorf("Stdout=%q; want byte-identical passthrough %q", out.Stdout, body)
	}
}

// TestRun_OutputCapDisabledByDefaultZero asserts that a zero default cap
// (the value tests leave unset) means UNCAPPED — existing exact-output
// expectations are preserved.
func TestRun_OutputCapDisabledByDefaultZero(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	big := strings.Repeat("a", 100000)
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte(big)}} // DefaultMaxOutputBytes unset = 0

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "cat big"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Stdout != big {
		t.Error("output was capped despite a zero (disabled) default cap")
	}
}

// TestRun_MaxOutputBytesOverride asserts the per-call override threads
// through, in both directions: a small override caps under a large default,
// and an explicit 0 disables the cap under a small default.
func TestRun_MaxOutputBytesOverride(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	big := strings.Repeat("a", 5000)

	// Small override caps even though the default would not.
	capSmall := 500
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte(big)}, DefaultMaxOutputBytes: 100000}
	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "cat big", MaxOutputBytes: &capSmall})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.Stdout, markerPrefix) {
		t.Error("per-call MaxOutputBytes=500 did not cap the output")
	}

	// Explicit 0 disables the cap even though the default is small.
	zero := 0
	runner2 := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte(big)}, DefaultMaxOutputBytes: 100}
	out2, err := runner2.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "cat big", MaxOutputBytes: &zero})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out2.Stdout != big {
		t.Error("per-call MaxOutputBytes=0 did not disable the cap")
	}
}

// TestRun_OutputCapRuneBoundary asserts the cut is moved back to a UTF-8
// rune boundary so a multi-byte rune is never split (the kept content is
// always valid UTF-8).
func TestRun_OutputCapRuneBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	// "世" is 3 bytes; 100 of them = 300 bytes. A cap of 100 (not a multiple
	// of 3) would split the 34th rune under a naive byte cut.
	body := strings.Repeat("世", 100)
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte(body)}, DefaultMaxOutputBytes: 100}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "cat u"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	idx := strings.Index(out.Stdout, markerPrefix)
	if idx < 0 {
		t.Fatalf("no truncation marker: %q", out.Stdout)
	}
	kept := out.Stdout[:idx]
	if !utf8.ValidString(kept) {
		t.Error("kept content is not valid UTF-8 — a rune was split")
	}
	// 100 is not a multiple of 3, so the cut trims back to 99 (33 whole runes).
	if len(kept) != 99 {
		t.Errorf("kept len=%d; want 99 (trimmed back to the rune boundary)", len(kept))
	}
}

// TestRunBatch_OutputCapPerCommandIndependent asserts each command's stdout
// is capped independently across a batch's results.
func TestRunBatch_OutputCapPerCommandIndependent(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	big := strings.Repeat("b", 3000)
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "cat a", stdout: big},
			{match: "cat b", stdout: big},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: &batchSign{}, SSH: ssh, DefaultMaxOutputBytes: 500}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"cat a", "cat b"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("Results=%d; want 2", len(out.Results))
	}
	for i, res := range out.Results {
		idx := strings.Index(res.Stdout, markerPrefix)
		if idx < 0 {
			t.Errorf("Results[%d].Stdout not capped (no marker)", i)
			continue
		}
		if len(res.Stdout[:idx]) != 500 {
			t.Errorf("Results[%d] kept=%d bytes; want 500", i, len(res.Stdout[:idx]))
		}
	}
}
