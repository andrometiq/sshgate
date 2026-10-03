//go:build linux

package confine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
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
	if rep.LandlockABI < 1 {
		if rep.Rung != Rung3Unconfined {
			t.Errorf("no Landlock: rung=%s", rep.Rung)
		}
		return
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
	if !(Rung1Full > Rung3Unconfined) {
		t.Fatal("rung ordering broken: Full > Unconfined must hold")
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
		{"namespaces without Landlock", probeFacts{landlockABI: -1, maxUserns: 100}, Rung3Unconfined, true, false},
		{"probe ok", probeFacts{landlockABI: 10, maxUserns: 100}, Rung1Full, true, false},
		{"probe ok, clamp overridden by a profile", probeFacts{landlockABI: 6, maxUserns: 100, clamp: true}, Rung1Full, true, false},
		{"max_user_namespaces=0 -> landlock", probeFacts{landlockABI: 10, maxUserns: 0}, Rung3Unconfined, false, false},
		{"max_user_namespaces=0, no landlock", probeFacts{landlockABI: -1, maxUserns: 0}, Rung3Unconfined, false, false},
		{"clone EPERM (userns disabled)", probeFacts{landlockABI: 10, maxUserns: 100, cloneErr: unix.EPERM, probeExit: -1}, Rung3Unconfined, false, false},
		{"clone EINVAL (no userns support)", probeFacts{landlockABI: 3, maxUserns: -1, cloneErr: unix.EINVAL, probeExit: -1}, Rung3Unconfined, false, false},
		{"clone ENOSPC (namespace count used up) -> deny", probeFacts{landlockABI: 10, maxUserns: 5, cloneErr: unix.ENOSPC, probeExit: -1}, Rung3Unconfined, false, true},
		{"clone ENOSPC, no landlock -> deny, never unconfined", probeFacts{landlockABI: -1, maxUserns: 5, cloneErr: unix.ENOSPC, probeExit: -1}, Rung3Unconfined, false, true},
		{"clone ENOMEM (transient) -> deny", probeFacts{landlockABI: 10, maxUserns: 100, cloneErr: enomem, probeExit: -1}, Rung3Unconfined, false, true},
		{"clamp denies the mount -> landlock", probeFacts{landlockABI: 6, maxUserns: 100, clamp: true, probeExit: probeExitMountDenied}, Rung3Unconfined, false, false},
		{"mount denied, no clamp to explain it -> deny", probeFacts{landlockABI: 10, maxUserns: 100, probeExit: probeExitMountDenied}, Rung3Unconfined, false, true},
		{"other mount error -> deny", probeFacts{landlockABI: 10, maxUserns: 100, probeExit: probeExitMountError}, Rung3Unconfined, false, true},
		{"probe killed -> deny", probeFacts{landlockABI: 10, maxUserns: 100, probeExit: -1}, Rung3Unconfined, false, true},
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

// TestDetectUsernsCountUsedUpDenies reproduces a used-up per-user namespace
// count on the real kernel: inside a throwaway user namespace it lowers
// max_user_namespaces to 1 and holds that one slot with a sibling namespace, so
// Detect's own clone fails with ENOSPC. That is a passing condition on a rung-1
// host, so Detect must report a ProbeErr (the gate denies) rather than a
// definitive absence that would downgrade the read jail or drop it entirely.
func TestDetectUsernsCountUsedUpDenies(t *testing.T) {
	if !Detect().Userns {
		t.Skip("SKIP rung: host has no unprivileged userns; the namespace-count test needs one")
	}
	c := exec.Command("/proc/self/exe", sentinelUsernsFullTest)
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("namespace-count child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "probe_err_enospc=true") {
		t.Fatalf("a used-up userns count did not surface as a ProbeErr wrapping ENOSPC:\n%s", out)
	}
}

// usernsFullChild is the __jailtest_usernsfull re-exec: root of its own user
// namespace, so the max_user_namespaces it lowers is that namespace's limit only.
func usernsFullChild() int {
	if err := os.WriteFile("/proc/sys/user/max_user_namespaces", []byte("1\n"), 0); err != nil {
		fmt.Fprintf(os.Stderr, "lower max_user_namespaces: %v\n", err)
		return 1
	}
	hold := exec.Command("/proc/self/exe", sentinelHoldTest)
	hold.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER, Pdeathsig: syscall.SIGKILL}
	in, err := hold.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "holder stdin: %v\n", err)
		return 1
	}
	if err := hold.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start holder: %v\n", err)
		return 1
	}
	rep := Detect()
	_ = in.Close()
	_ = hold.Wait()
	fmt.Printf("rung=%s userns=%v probe_err=%v notes=%q\n", rep.Rung, rep.Userns, rep.ProbeErr, rep.Notes)
	fmt.Printf("probe_err_enospc=%v\n", rep.ProbeErr != nil && errors.Is(rep.ProbeErr, unix.ENOSPC))
	return 0
}
