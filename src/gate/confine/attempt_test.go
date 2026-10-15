//go:build linux

package confine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// requireJailHost skips unless this host can run the jail: an Absent attempt
// skips, a Failed one fails.
func requireJailHost(t *testing.T) {
	t.Helper()
	jailed, err := Spec{Profile: ProfileROv1}.Command(context.Background(), ":")
	if err != nil {
		t.Fatal(err)
	}
	if err = jailed.Start(); err == nil {
		_ = jailed.Started()
		_ = jailed.Cmd.Wait()
		_, err = jailed.Status()
	}
	var setup *SetupError
	switch {
	case err == nil:
		return
	case errors.As(err, &setup) && ClassifySetupFailure(setup.Stage, setup.Errno, ReadHostFacts()) == Absent:
		t.Skipf("SKIP jail: %s", DenyReason(Absent, setup.Stage, setup.Errno))
	default:
		t.Fatalf("jail attempt: %v", err)
	}
}

// TestJailAttemptUsernsCountUsedUpIsFailed reproduces a used-up per-user
// namespace count on the real kernel: inside a throwaway user namespace it
// lowers max_user_namespaces to 1 and holds that one slot with a sibling
// namespace, so the jail's own clone fails with ENOSPC. The limit is not zero,
// so that is a transient condition on a jail host: Failed (the gate denies),
// never Absent (which would let an unpinned host run the read unconfined).
func TestJailAttemptUsernsCountUsedUpIsFailed(t *testing.T) {
	requireJailHost(t)
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
	if !strings.Contains(string(out), "attempt=clone:ENOSPC max_user_namespaces=1 class=failed\n") {
		t.Fatalf("a used-up userns count did not fail the jail's clone as Failed ENOSPC:\n%s", out)
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
	defer func() { _ = in.Close(); _ = hold.Wait() }()
	jailed, err := Spec{Profile: ProfileROv1}.Command(context.Background(), ":")
	if err != nil {
		fmt.Fprintf(os.Stderr, "build jail: %v\n", err)
		return 1
	}
	err = jailed.Start()
	var setup *SetupError
	if !errors.As(err, &setup) {
		if err == nil {
			_ = jailed.Cmd.Process.Kill()
			_ = jailed.Cmd.Wait()
		}
		fmt.Printf("attempt did not fail at setup: %v\n", err)
		return 0
	}
	facts := ReadHostFacts()
	fmt.Printf("attempt=%s:%s max_user_namespaces=%d class=%s\n", setup.Stage, unix.ErrnoName(setup.Errno), facts.MaxUserNS, ClassifySetupFailure(setup.Stage, setup.Errno, facts))
	return 0
}
