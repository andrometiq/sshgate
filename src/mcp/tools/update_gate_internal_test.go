package tools

import (
	"context"
	"testing"
)

// TestUpdateReason pins the operator-facing Build line update_gate threads into
// CmdReq.Reason. The exact format must match what the signer's approval banner
// expects (backend/telegram_update_test.go: "rev abc1234 (2026-07-01) · running
// rev def5678"), because that string renders verbatim on the "Build:" line.
func TestUpdateReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		stagedRev  string
		stagedTime string
		runningRev string
		want       string
	}{
		{
			name:       "full — matches the telegram Build-line fixture",
			stagedRev:  "abc1234",
			stagedTime: "2026-07-01",
			runningRev: "def5678",
			want:       "rev abc1234 (2026-07-01) · running rev def5678",
		},
		{
			name:       "no build time omits the parenthesized part",
			stagedRev:  "abc1234",
			stagedTime: "",
			runningRev: "def5678",
			want:       "rev abc1234 · running rev def5678",
		},
		{
			name:       "unknown staged rev yields an empty reason (nothing useful to show)",
			stagedRev:  "unknown",
			stagedTime: "",
			runningRev: "def5678",
			want:       "",
		},
		{
			name:       "empty staged rev also yields an empty reason",
			stagedRev:  "",
			stagedTime: "2026-07-01",
			runningRev: "def5678",
			want:       "",
		},
		{
			name:       "running rev unknown still threads through",
			stagedRev:  "abc1234",
			stagedTime: "2026-07-01",
			runningRev: "unknown",
			want:       "rev abc1234 (2026-07-01) · running rev unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := updateReason(tc.stagedRev, tc.stagedTime, tc.runningRev); got != tc.want {
				t.Errorf("updateReason(%q,%q,%q) = %q; want %q", tc.stagedRev, tc.stagedTime, tc.runningRev, got, tc.want)
			}
		})
	}
}

// TestParseUpdatedMarker pins parsing of the gate's success marker
// "SSHGATE_UPDATED sha256=<hex> size=<n> rev=<vcs-or-unknown>".
func TestParseUpdatedMarker(t *testing.T) {
	t.Parallel()
	t.Run("well-formed marker", func(t *testing.T) {
		h, n, rev, ok := parseUpdatedMarker("SSHGATE_UPDATED sha256=deadbeef size=4096 rev=abc1234\n")
		if !ok {
			t.Fatal("ok = false; want true for a well-formed marker")
		}
		if h != "deadbeef" || n != 4096 || rev != "abc1234" {
			t.Errorf("parsed hash=%q size=%d rev=%q", h, n, rev)
		}
	})
	t.Run("rev absent defaults to unknown", func(t *testing.T) {
		_, _, rev, ok := parseUpdatedMarker("SSHGATE_UPDATED sha256=deadbeef size=1\n")
		if !ok {
			t.Fatal("ok = false; want true")
		}
		if rev != "unknown" {
			t.Errorf("rev = %q; want unknown", rev)
		}
	})
	t.Run("missing marker prefix", func(t *testing.T) {
		if _, _, _, ok := parseUpdatedMarker("nothing here"); ok {
			t.Error("ok = true; want false when the marker is absent")
		}
	})
	t.Run("missing required tokens", func(t *testing.T) {
		if _, _, _, ok := parseUpdatedMarker("SSHGATE_UPDATED rev=abc1234"); ok {
			t.Error("ok = true; want false when sha256/size are absent")
		}
	})
}

// TestProbeRunningRev pins the best-effort SSHGATE_VERSION parse.
func TestProbeRunningRev(t *testing.T) {
	t.Parallel()
	t.Run("parses rev= from a version line", func(t *testing.T) {
		ssh := &internalProbeSSH{out: []byte("SSHGATE_VERSION rev=abc1234\n"), exit: 0}
		if got := probeRunningRev(context.TODO(), ssh, "h", "u", 22); got != "abc1234" {
			t.Errorf("runningRev = %q; want abc1234", got)
		}
	})
	t.Run("old gate exit 77 → unknown", func(t *testing.T) {
		ssh := &internalProbeSSH{out: []byte("write refused\n"), exit: 77}
		if got := probeRunningRev(context.TODO(), ssh, "h", "u", 22); got != "unknown" {
			t.Errorf("runningRev = %q; want unknown on a non-zero exit", got)
		}
	})
	t.Run("no rev= token → unknown", func(t *testing.T) {
		ssh := &internalProbeSSH{out: []byte("garbage\n"), exit: 0}
		if got := probeRunningRev(context.TODO(), ssh, "h", "u", 22); got != "unknown" {
			t.Errorf("runningRev = %q; want unknown", got)
		}
	})
}

// internalProbeSSH is a minimal SSHRunner for the in-package helper tests.
type internalProbeSSH struct {
	out  []byte
	exit int
	err  error
}

func (f *internalProbeSSH) Run(_ context.Context, _, _ string, _ int, _ string) ([]byte, []byte, int, error) {
	return f.out, nil, f.exit, f.err
}
