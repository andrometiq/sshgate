//go:build linux

package confine

import (
	"fmt"

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
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	return nil
}

// setRlimits applies the availability bounds. Lowering soft/hard limits is always
// permitted, so this works on every rung.
//
// RLIMIT_NPROC is applied ONLY on rung 1, where it counts the tasks of the fresh
// user namespace (a near-zero baseline), so a small cap bounds a fork bomb. On
// rung 2 there is no user namespace: the kernel checks the cap against every task
// the SSH uid runs host-wide, so once that uid already runs that many (a same-uid
// app server's threads count) every fork in the jail would fail and ordinary
// piped reads would break. The rung-2 fork-bomb bound is the cgroup pids.max
// harden item (not yet built). RLIMIT_FSIZE and RLIMIT_CORE are per-process
// and apply on every rung.
func setRlimits(rung Rung) error {
	limits := []struct {
		res  int
		name string
		lim  unix.Rlimit
	}{
		{unix.RLIMIT_FSIZE, "fsize", unix.Rlimit{Cur: defaultRlimitFsize, Max: defaultRlimitFsize}},
		{unix.RLIMIT_CORE, "core", unix.Rlimit{Cur: 0, Max: 0}},
	}
	if rung == Rung1Full {
		limits = append(limits, struct {
			res  int
			name string
			lim  unix.Rlimit
		}{unix.RLIMIT_NPROC, "nproc", unix.Rlimit{Cur: defaultRlimitNproc, Max: defaultRlimitNproc}})
	}
	for _, r := range limits {
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

// dropCaps reduces the worker's capabilities to the jail's floor, on the locked
// thread, after mounts and before Landlock/seccomp.
//
//   - rung 1 drops the whole bounding set (needs CAP_SETPCAP, carried as an
//     ambient cap from the parent clone for exactly this), clears ambient, and
//     sets permitted/effective/inheritable to empty — or, for a root SSH user,
//     keeps ONLY CAP_DAC_READ_SEARCH so root reads of other users' files still
//     work (open_by_handle_at is seccomp-denied so it cannot become an escape).
//   - rung 2 has no CAP_SETPCAP (the gate is already unprivileged), so it skips
//     the bounding-set drop and only clears ambient + lowers to empty.
func dropCaps(rung Rung, rootSSH bool) error {
	keepDacRead := rung == Rung1Full && rootSSH

	if rung == Rung1Full {
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
	}

	// Clear the ambient set (CAP_SYS_ADMIN/CAP_SETPCAP used for the mount phase).
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient caps: %w", err)
	}

	// Lower permitted/effective/inheritable. Lowering one's own caps never needs
	// privilege, so this is valid on every rung.
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
