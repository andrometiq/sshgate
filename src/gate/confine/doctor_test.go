//go:build linux

package confine

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDetectThisHost exercises the real host probe. On the Phase-0 go/no-go
// target (kernel 7.2.8, userns enabled, Landlock ABI 10) it must resolve to
// Rung1Full; on a host without unprivileged userns it skips with the reason.
func TestDetectThisHost(t *testing.T) {
	rep := Detect()
	if rep.ProbeErr != nil {
		t.Logf("probe note: %v", rep.ProbeErr)
	}
	if !rep.Userns {
		t.Skipf("host has no unprivileged userns (rung=%s, landlock_abi=%d): %v",
			rep.Rung, rep.LandlockABI, rep.ProbeErr)
	}
	if rep.Rung != Rung1Full {
		t.Errorf("rung=%s, want full", rep.Rung)
	}
	if rep.LandlockABI < 1 {
		t.Errorf("landlock_abi=%d, want >=1", rep.LandlockABI)
	}
	if !rep.Seccomp {
		t.Error("seccomp not detected")
	}
	if len(rep.LSMs) == 0 {
		t.Error("no LSMs reported")
	}
}

// TestDetectRungOrdering guards the >= semantics the rung constants promise.
func TestDetectRungOrdering(t *testing.T) {
	if !(Rung1Full > Rung2Landlock && Rung2Landlock > Rung3Unconfined) {
		t.Fatal("rung ordering broken: Full > Landlock > Unconfined must hold")
	}
}

// TestDecideInjected drives the rung decision with injected probe results, so
// each definitive-absence and fail-closed branch is pinned without needing the
// matching host.
func TestDecideInjected(t *testing.T) {
	enomem := fmt.Errorf("fork/exec /proc/self/exe: %w", unix.ENOMEM)
	cases := []struct {
		name     string
		fx       probeFacts
		rung     Rung
		userns   bool
		probeErr bool
	}{
		{"probe ok", probeFacts{landlockABI: 10, maxUserns: 100}, Rung1Full, true, false},
		{"probe ok, clamp overridden by a profile", probeFacts{landlockABI: 6, maxUserns: 100, clamp: true}, Rung1Full, true, false},
		{"max_user_namespaces=0 -> landlock", probeFacts{landlockABI: 10, maxUserns: 0}, Rung2Landlock, false, false},
		{"max_user_namespaces=0, no landlock", probeFacts{landlockABI: -1, maxUserns: 0}, Rung3Unconfined, false, false},
		{"clone EPERM (userns disabled)", probeFacts{landlockABI: 10, maxUserns: 100, cloneErr: unix.EPERM, probeExit: -1}, Rung2Landlock, false, false},
		{"clone EINVAL (no userns support)", probeFacts{landlockABI: 3, maxUserns: -1, cloneErr: unix.EINVAL, probeExit: -1}, Rung2Landlock, false, false},
		{"clone ENOSPC (namespace limit)", probeFacts{landlockABI: 10, maxUserns: 5, cloneErr: unix.ENOSPC, probeExit: -1}, Rung2Landlock, false, false},
		{"clone ENOMEM (transient) -> deny", probeFacts{landlockABI: 10, maxUserns: 100, cloneErr: enomem, probeExit: -1}, Rung2Landlock, false, true},
		{"clamp denies the mount -> landlock", probeFacts{landlockABI: 6, maxUserns: 100, clamp: true, probeExit: probeExitMountDenied}, Rung2Landlock, false, false},
		{"mount denied, no clamp to explain it -> deny", probeFacts{landlockABI: 10, maxUserns: 100, probeExit: probeExitMountDenied}, Rung2Landlock, false, true},
		{"other mount error -> deny", probeFacts{landlockABI: 10, maxUserns: 100, probeExit: probeExitMountError}, Rung2Landlock, false, true},
		{"probe killed -> deny", probeFacts{landlockABI: 10, maxUserns: 100, probeExit: -1}, Rung2Landlock, false, true},
	}
	for _, c := range cases {
		rep := decide(c.fx)
		if rep.Rung != c.rung || rep.Userns != c.userns || (rep.ProbeErr != nil) != c.probeErr {
			t.Errorf("%s: got rung=%s userns=%v probeErr=%v; want rung=%s userns=%v probeErr=%v",
				c.name, rep.Rung, rep.Userns, rep.ProbeErr, c.rung, c.userns, c.probeErr)
		}
		if c.fx.clamp != rep.AppArmorUsernsClamp {
			t.Errorf("%s: clamp not reported", c.name)
		}
	}
}

// TestRunProbeRefusesOutsideClone: called directly (not pid 1 of a fresh pid
// namespace) the probe must refuse before any mount, so it can never change the
// caller's mount propagation.
func TestRunProbeRefusesOutsideClone(t *testing.T) {
	if got := RunProbe(nil); got != probeExitNotInClone {
		t.Fatalf("RunProbe outside the clone = %d, want %d", got, probeExitNotInClone)
	}
}
