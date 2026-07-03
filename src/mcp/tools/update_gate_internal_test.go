package tools

import (
	"context"
	"testing"
)

// TestUpdateReason pins the operator-facing Build line update_gate threads into
// CmdReq.Reason. Shape (spec §5.2/§11.8 task 4):
// "<staged-basename> · version <staged> · running version <running>" — no
// "(time)" (vcs stamping is off under the release recipe), always non-empty, and
// an unknown staged/running version renders "version unknown". This string
// renders verbatim on the signer banner's "Build:" line
// (backend/telegram_update_test.go).
func TestUpdateReason(t *testing.T) {
	t.Parallel()
	const basename = "sshgate-gate-linux-amd64"
	cases := []struct {
		name       string
		basename   string
		stagedVer  string
		runningVer string
		want       string
	}{
		{
			name:       "full — matches the telegram Build-line fixture",
			basename:   basename,
			stagedVer:  "v1.3.0",
			runningVer: "v1.2.9",
			want:       "sshgate-gate-linux-amd64 · version v1.3.0 · running version v1.2.9",
		},
		{
			name:       "unknown staged version still shows the running version (downgrade cue survives a stripped marker)",
			basename:   basename,
			stagedVer:  "unknown",
			runningVer: "v1.2.9",
			want:       "sshgate-gate-linux-amd64 · version unknown · running version v1.2.9",
		},
		{
			name:       "empty staged version renders version unknown",
			basename:   basename,
			stagedVer:  "",
			runningVer: "v1.2.9",
			want:       "sshgate-gate-linux-amd64 · version unknown · running version v1.2.9",
		},
		{
			name:       "running version unknown still threads through",
			basename:   basename,
			stagedVer:  "v1.3.0",
			runningVer: "unknown",
			want:       "sshgate-gate-linux-amd64 · version v1.3.0 · running version unknown",
		},
		{
			name:       "empty running version renders version unknown",
			basename:   basename,
			stagedVer:  "v1.3.0",
			runningVer: "",
			want:       "sshgate-gate-linux-amd64 · version v1.3.0 · running version unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := updateReason(tc.basename, tc.stagedVer, tc.runningVer); got != tc.want {
				t.Errorf("updateReason(%q,%q,%q) = %q; want %q", tc.basename, tc.stagedVer, tc.runningVer, got, tc.want)
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
