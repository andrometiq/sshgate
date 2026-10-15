//go:build linux

package confine

import "golang.org/x/sys/unix"

// SealProcess makes the calling process non-dumpable. A process outside the
// jail with the same uid then needs CAP_SYS_PTRACE to reach its
// /proc/<pid>/fd, environ or memory. The gate seals itself right after a
// jailed read's child starts.
func SealProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// Dumpable returns the calling process's raw dumpable value: 1 for an
// ordinary process, 0 once sealed, and 2 (with fs.suid_dumpable=2) for a
// process whose binary it cannot read.
func Dumpable() (int, error) {
	return unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
}
