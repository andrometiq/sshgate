//go:build linux

package confine

import (
	"fmt"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"

	"golang.org/x/sys/unix"
)

// defaultRlimitNproc / defaultRlimitFsize bound a jailed command's process count
// and single-file write so a jailed read cannot fork-bomb or fill the host. They
// are deliberately generous for real reads; operator overrides are a later item.
const (
	defaultRlimitNproc = 256
	defaultRlimitFsize = 1 << 30 // 1 GiB per file
)

// setNoNewPrivs sets PR_SET_NO_NEW_PRIVS, the mandatory precondition for an
// unprivileged seccomp filter and a belt against setuid re-elevation (so sudo in
// the jail cannot gain privilege).
func setNoNewPrivs() error {
	if jailmut.On("P-NNP") {
		return nil
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	return nil
}

// setRlimits applies per-process size/core bounds and the namespace process bound.
func setRlimits() error {
	// §3.2 stage 10: core hygiene must not raise an inherited hard limit.
	var core unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &core); err != nil {
		return fmt.Errorf("getrlimit core: %w", err)
	}
	core.Max = min(uint64(1), core.Max)
	core.Cur = core.Max
	limits := []struct {
		res  int
		name string
		lim  unix.Rlimit
	}{
		{unix.RLIMIT_FSIZE, "fsize", unix.Rlimit{Cur: defaultRlimitFsize, Max: defaultRlimitFsize}},
		{unix.RLIMIT_CORE, "core", core},
		{unix.RLIMIT_NPROC, "nproc", unix.Rlimit{Cur: defaultRlimitNproc, Max: defaultRlimitNproc}},
	}
	for _, r := range limits {
		if (r.res == unix.RLIMIT_NPROC && jailmut.On("P-RL-NPROC")) || (r.res == unix.RLIMIT_FSIZE && jailmut.On("P-RL-FSIZE")) || (r.res == unix.RLIMIT_CORE && jailmut.On("P-RL-CORE")) {
			continue
		}
		if err := unix.Setrlimit(r.res, &r.lim); err != nil {
			return fmt.Errorf("setrlimit %s: %w", r.name, err)
		}
	}
	return nil
}

// capMask builds the two 32-bit capability words with the given cap bits set.
func capMask(caps ...int) [2]uint32 {
	var m [2]uint32
	for _, c := range caps {
		m[c>>5] |= 1 << (uint(c) & 31)
	}
	return m
}

// dropCaps clears ambient capabilities and the bounding set after mounting.
// Root SSH retains only DAC_READ_SEARCH; seccomp denies open_by_handle_at.
func dropCaps(rootSSH bool) error {
	if jailmut.On("P-CAPS") {
		return nil
	}
	keepDacRead := rootSSH

	// Drop every bounding-set capability (except a kept one) while
	// CAP_SETPCAP is still effective. Loop until PR_CAPBSET_DROP reports the
	// cap number is invalid, so a kernel with more caps than this build's
	// CAP_LAST_CAP is still fully cleared.
	for c := 0; ; c++ {
		if keepDacRead && c == unix.CAP_DAC_READ_SEARCH {
			continue
		}
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		if err == unix.EINVAL {
			break
		}
		if err != nil {
			return fmt.Errorf("capbset drop %d: %w", c, err)
		}
	}
	// Clear the ambient set (CAP_SYS_ADMIN/CAP_SETPCAP used for the mount phase).
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient caps: %w", err)
	}

	// Lower permitted/effective/inheritable. Lowering one's own caps never needs
	// privilege.
	var m [2]uint32
	if keepDacRead {
		m = capMask(unix.CAP_DAC_READ_SEARCH)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: m[0], Permitted: m[0], Inheritable: 0},
		{Effective: m[1], Permitted: m[1], Inheritable: 0},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}
