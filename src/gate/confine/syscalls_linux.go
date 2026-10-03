//go:build linux

package confine

import "golang.org/x/sys/unix"

// maxKnownSyscall is the highest syscall number this build's x/sys table knows
// about (currently SYS_RSEQ_SLICE_YIELD = 471 on amd64). The seccomp filter
// returns ENOSYS for any nr ABOVE this, so a kernel newer than the toolchain's
// table cannot slip a brand-new syscall past the denylist. The forward-compat
// cost — a kernel newer than the table could ENOSYS a syscall a newer libc wants — is the
// deliberate fail-closed choice; the e2e read-corpus leg is the tripwire, and a
// toolchain bump is the remedy, not a runtime derive. A unit test cross-checks
// this against the largest SYS_* we compile against so a bump trips the test.
const maxKnownSyscall = unix.SYS_RSEQ_SLICE_YIELD

const fsIocFssetxattr = 0x401c5820

var fileattrIoctlDeny = []uint32{unix.FS_IOC_SETFLAGS, 0x40046602, fsIocFssetxattr}

// nsCloneBits is every CLONE_NEW* namespace bit.
const nsCloneBits = unix.CLONE_NEWNS | unix.CLONE_NEWUSER | unix.CLONE_NEWPID |
	unix.CLONE_NEWNET | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWCGROUP | unix.CLONE_NEWTIME

// nsLegacyCloneBits is the namespace mask applied to the legacy clone() flags.
// It EXCLUDES CLONE_NEWTIME (0x80): that bit overlaps the CSIGNAL byte (0xff)
// legacy clone() uses for the child exit signal, so masking it would misfire on
// an ordinary thread clone. CLONE_NEWTIME is clone3-only, and clone3 is already
// ENOSYS-denied, so excluding it here loses nothing.
const nsLegacyCloneBits = nsCloneBits &^ unix.CLONE_NEWTIME
