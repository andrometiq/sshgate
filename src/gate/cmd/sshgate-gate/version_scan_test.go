package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gatever"
)

// TestVersionMarkerSelfMatch is the load-bearing proof of the safe-scan
// runtime-prefix rule + the lingering-default carve-out (spec §11.2 HIGH-1,
// §11.8 task 14). It builds a REAL gate binary with an injected version marker,
// then scans those exact bytes with the SAME gatever.Scan the gate and MCP use.
//
// A release gate binary contains the marker prefix in .rodata at least twice —
// the -X-injected value AND the lingering default SSHGATE_GATE_VERSION{dev} that
// -X does NOT strip. A naive first-match scan (or one whose search prefix is a
// folded .rodata constant) would resolve to garbage or a dev/release conflict.
// The safe scan must resolve to EXACTLY the injected version. This test builds
// the artifact and proves it end-to-end; the pure-logic cases live in
// src/gatever/marker_test.go.
func TestVersionMarkerSelfMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a gate binary; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH: %v", err)
	}

	const injected = "v9.9.9-selftest"
	// The full -X marker value. Written as a literal here is safe: this string
	// lands in the TEST binary, never in the freshly-built gate artifact we scan.
	const injectedMarker = "SSHGATE_GATE_VERSION{" + injected + "}"

	dir := t.TempDir()
	out := filepath.Join(dir, "gate-selftest")

	build := func(t *testing.T, ldflags string) []byte {
		t.Helper()
		args := []string{"build"}
		if ldflags != "" {
			args = append(args, "-ldflags", ldflags)
		}
		args = append(args, "-o", out, ".")
		cmd := exec.Command("go", args...)
		// Local toolchain is fine — the marker is toolchain-independent, and this
		// keeps the test fast/offline (no genuine-release-toolchain download).
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build failed: %v\n%s", err, b)
		}
		body, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read built gate: %v", err)
		}
		return body
	}

	t.Run("injected marker resolves to exactly that version", func(t *testing.T) {
		body := build(t, "-X main.versionMarker="+injectedMarker)
		got := gatever.Scan(body)
		if got != injected {
			t.Fatalf("Scan(injected gate) = %q; want %q — the runtime-prefix + skip-dev safe scan failed", got, injected)
		}
	})

	t.Run("default (dev) build yields unknown, not a spurious version", func(t *testing.T) {
		// No -X: the binary carries only the lingering default {dev}, which Scan
		// skips (a dev binary has no release version). This is the negative case:
		// a stripped/absent real marker → "unknown".
		body := build(t, "")
		if got := gatever.Scan(body); got != gatever.Unknown {
			t.Fatalf("Scan(default dev gate) = %q; want %q (dev sentinel must be skipped, no real marker present)", got, gatever.Unknown)
		}
	})
}
