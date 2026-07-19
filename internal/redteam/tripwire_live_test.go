//go:build integration

package redteam

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// liveRepoRoot walks up from the test's cwd to the SSHGate repo root
// (go.mod + tests/integration/docker-compose.yml), mirroring the
// command's repoRoot so the live tests can find the compose file and the
// gate source.
func liveRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "tests", "integration", "docker-compose.yml")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate repo root from %s", wd)
	return ""
}

// newLiveTarget boots a disposable target for a live test, skipping
// cleanly when Docker is absent. It registers teardown via t.Cleanup.
func newLiveTarget(t *testing.T) *Target {
	t.Helper()
	if !DockerAvailable() {
		t.Skip("docker daemon not reachable; skipping live tripwire test")
	}
	root := liveRepoRoot(t)
	keyDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	target, teardown, err := NewTarget(ctx, root, keyDir)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	t.Cleanup(teardown)
	return target
}

// TestTripwire_SilentOnRead proves the tripwire is SPECIFIC: a plain read
// THROUGH the gate produces ZERO write events and write_alert=false. This
// is the no-false-positive guarantee — the curated clean zone + excludes
// stay quiet during legitimate reads.
func TestTripwire_SilentOnRead(t *testing.T) {
	target := newLiveTarget(t)
	ctx := context.Background()

	d := &Detector{
		Runner:      target,
		Snapshotter: target,
		Tripwire:    target,
		Sentinel:    target.Sentinel(),
		Resetter:    target.Reset,
	}

	// A pure read through the gate.
	v, err := d.Test(ctx, "live-read", "cat /etc/hostname")
	if err != nil {
		t.Fatalf("Test(read): %v", err)
	}
	if v.GateDecision != DecisionExecuted {
		t.Fatalf("gate_decision = %s; want executed for a read", v.GateDecision)
	}
	if v.WriteAlert {
		t.Errorf("write_alert = true on a plain read; tripwire false-positived on: %v", v.WriteEvents)
	}
	if len(v.WriteEvents) != 0 {
		t.Errorf("write_events = %v; want empty on a read", v.WriteEvents)
	}
	if v.BYPASS {
		t.Errorf("BYPASS = true on a plain read; want false")
	}

	// A spread of representative reads to harden the no-false-positive
	// claim across different tools — now that /config and /tmp are
	// watched. `sort` is included on purpose: GNU sort spills temp files to
	// /tmp on a large input, and the /tmp/sort exclude must keep that
	// quiet. `ls -la /config` exercises the real home (the new root).
	for _, rc := range []string{"ls -la /etc", "id", "df -h", "ls -la /config", "sort /etc/services", "sort -n /etc/passwd"} {
		rv, err := d.Test(ctx, "live-read", rc)
		if err != nil {
			t.Fatalf("Test(%q): %v", rc, err)
		}
		if rv.WriteAlert {
			t.Errorf("write_alert = true on read %q; events=%v", rc, rv.WriteEvents)
		}
	}
}

// TestTripwire_FiresOnOutOfBandWrite proves the tripwire is SENSITIVE: a
// DIRECT docker-exec write (bypassing the gate entirely) to a path
// OUTSIDE the canary tree, between mark and read, is recorded. This shows
// the tripwire catches writes by ANY means and anywhere in the clean
// zone — not just the canary the corpus aims at.
func TestTripwire_FiresOnOutOfBandWrite(t *testing.T) {
	target := newLiveTarget(t)
	ctx := context.Background()

	if target.tripwireFallback {
		t.Log("tripwire running in snapshot-fallback mode (inotify-tools unavailable)")
	}

	mark, err := target.WriteMark(ctx)
	if err != nil {
		t.Fatalf("WriteMark: %v", err)
	}

	// Out-of-band write: straight docker exec as root, NOT through the
	// gate. Lands under /etc — inside the clean zone, outside the canary.
	const probe = "/etc/redteam-tripwire-probe"
	if out, err := dockerExec(ctx, target.composeFile, nil, "touch "+probe); err != nil {
		t.Fatalf("out-of-band touch: %v\n%s", err, out)
	}
	// inotify is async; give the monitor a beat to flush the event. In
	// fallback mode WriteEventsSince re-snapshots, so this is harmless.
	if !target.tripwireFallback {
		_, _ = dockerExec(ctx, target.composeFile, nil, "sleep 1")
	}

	events, err := target.WriteEventsSince(ctx, mark)
	if err != nil {
		t.Fatalf("WriteEventsSince: %v", err)
	}
	found := false
	for _, e := range events {
		if strings.HasPrefix(e.Path, probe) {
			found = true
		}
	}
	if !found {
		t.Fatalf("tripwire did NOT record the out-of-band write to %s; events=%v", probe, events)
	}
}

// TestTripwire_FiresOnExpandedWatchSet proves the EXPANDED watch set
// (/config — the SSH user's real home — and /tmp) is live: a direct
// out-of-band write to each high-value persistence/pivot target the watch
// set newly covers is recorded. Most importantly it pins
// /config/.ssh/authorized_keys (self-escalation / persistence) and a
// runtime /etc/ssh/sshd_config.d drop-in (no longer blanket-excluded) —
// the writes that were INVISIBLE before this change. Each is a separate
// mark/write/read so a failure names the exact unwatched location.
func TestTripwire_FiresOnExpandedWatchSet(t *testing.T) {
	target := newLiveTarget(t)
	ctx := context.Background()

	if target.tripwireFallback {
		t.Log("tripwire running in snapshot-fallback mode (inotify-tools unavailable)")
	}

	cases := []struct {
		name  string
		probe string
	}{
		{"authorized_keys (persistence)", containerHome + "/.ssh/authorized_keys.redteam-probe"},
		{"/config home file", containerHome + "/.redteam-home-probe"},
		{"/tmp staging", "/tmp/redteam-tmp-probe"},
		{"runtime sshd_config drop-in", "/etc/ssh/sshd_config.d/99-redteam-probe.conf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mark, err := target.WriteMark(ctx)
			if err != nil {
				t.Fatalf("WriteMark: %v", err)
			}
			// Out-of-band write: straight docker exec, NOT through the gate.
			if out, err := dockerExec(ctx, target.composeFile, nil, "touch "+tc.probe); err != nil {
				t.Fatalf("out-of-band touch %s: %v\n%s", tc.probe, err, out)
			}
			if !target.tripwireFallback {
				_, _ = dockerExec(ctx, target.composeFile, nil, "sleep 1")
			}
			events, err := target.WriteEventsSince(ctx, mark)
			if err != nil {
				t.Fatalf("WriteEventsSince: %v", err)
			}
			found := false
			for _, e := range events {
				if strings.HasPrefix(e.Path, tc.probe) {
					found = true
				}
			}
			if !found {
				t.Fatalf("tripwire did NOT record the out-of-band write to %s (expanded watch set); events=%v", tc.probe, events)
			}
			// Tidy up so the probe does not contaminate later cases (and so
			// the authorized_keys neighbour file does not linger).
			_, _ = dockerExec(ctx, target.composeFile, nil, "rm -f "+tc.probe)
		})
	}
}
