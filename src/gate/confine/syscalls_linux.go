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

// flatDeny lists the syscalls the seccomp filter rejects with EPERM regardless
// of their arguments. clone/unshare/setns/ioctl/socket are NOT here — they are
// argument-filtered in buildFilter. clone3 is handled separately (ENOSYS, so
// glibc falls back to the arg-filtered legacy clone). truncate/ftruncate and
// open_by_handle_at are conditional and added by buildFilter.
var flatDeny = []uint32{
	// Mount API (the whole family): a jailed command must never remount rw or
	// clear the RDONLY attr the setup process applied.
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN,
	unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
	unix.SYS_FSCONFIG, unix.SYS_OPEN_TREE_ATTR,
	// Process reach: no ptrace/peek-poke/fd-steal of other processes.
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PROCESS_VM_READV,
	unix.SYS_PIDFD_GETFD,
	// Kernel attack surface.
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME,
	unix.SYS_ADJTIMEX,
	// personality: blocks ADDR_NO_RANDOMIZE, a common exploit-prep step.
	unix.SYS_PERSONALITY,
}

// metadataDeny lists the inode-metadata syscalls Landlock does NOT govern at any
// ABI (chmod/chown/xattr/utime families and file_setattr). On rung 1 EROFS already blocks these on
// every host path, but on rung 2 (Landlock-only) seccomp must deny them so an
// unsigned read cannot change a file's mode, owner, xattrs or timestamps. File
// CREATION, removal and rename stay governed by Landlock (MAKE_*/REMOVE_*/REFER),
// so they are not here; truncate is handled separately (Landlock ≥ABI 3, else
// seccomp via denyTruncate).
var metadataDeny = []uint32{
	unix.SYS_CHMOD, unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2,
	unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT,
	unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_FSETXATTR, unix.SYS_SETXATTRAT,
	unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR, unix.SYS_FREMOVEXATTR, unix.SYS_REMOVEXATTRAT,
	unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT, unix.SYS_UTIMENSAT,
	unix.SYS_FILE_SETATTR,
}

// mqueueDeny lists the POSIX message-queue calls that create or remove a queue
// without Landlock seeing it: mq_unlink removes the inode through an inode hook
// Landlock does not mediate, and mq_open(O_CREAT) creates the queue before
// Landlock refuses the open. Denied on rung 2, which shares the host's IPC
// namespace; rung 1's CLONE_NEWIPC gives the jail queues of its own. A jailed
// read has no use for a host queue, so mq_open is denied outright.
var mqueueDeny = []uint32{unix.SYS_MQ_OPEN, unix.SYS_MQ_UNLINK}

// fsIocFssetxattr is _IOW('X', 32, struct fsxattr); absent from x/sys v0.45.0.
const fsIocFssetxattr = 0x401c5820

// metadataIoctlDeny lists the ioctl requests (arg1 low word) that change inode
// metadata through a file opened READ-ONLY, so Landlock never sees a write
// (its IOCTL_DEV right covers device files only). Denied on rung 2 with the
// metadataDeny table; rung 1 gets EROFS from the read-only mounts.
var metadataIoctlDeny = []uint32{
	unix.FS_IOC_SETFLAGS,              // chattr: append-only, immutable, nodump, ...
	fsIocFssetxattr,                   // xflags, project id, extent size
	unix.FS_IOC_ENABLE_VERITY,         // makes the file permanently read-only
	unix.FS_IOC_SET_ENCRYPTION_POLICY, // sets an fscrypt policy on an empty dir
}

// ttyMutateIoctlDeny lists the tty ioctls (arg1 low word) that change a
// terminal's state through a read-only fd. Rung 2 shares /dev/pts with the
// host, so a jailed command could open another same-uid session's pty and
// retune it. At Landlock ABI ≥5 that is closed by not granting IOCTL_DEV
// beneath /; below ABI 5 Landlock does not mediate device ioctls, so rung 2
// denies these with seccomp instead (on every fd, including its own stdio).
var ttyMutateIoctlDeny = []uint32{
	unix.TCSETS, unix.TCSETSW, unix.TCSETSF,
	unix.TCSETA, unix.TCSETAW, unix.TCSETAF,
	unix.TCSETS2, unix.TCSETSW2, unix.TCSETSF2,
	unix.TIOCSWINSZ, // also signals SIGWINCH to the tty's foreground group
	unix.TCFLSH, unix.TCXONC, unix.TIOCSETD, unix.TIOCSPGRP,
}

// ioprioWhoProcess is IOPRIO_WHO_PROCESS (absent from x/sys v0.45.0): the
// ioprio_set `which` value that selects a single process by pid.
const ioprioWhoProcess = 1

// procStatePidSyscalls are the syscalls whose arg0 is a pid and that CHANGE a
// target process's scheduling state. On rung 2 (no pid namespace, shared /proc,
// same uid) a jailed unsigned command could otherwise retune any of the SSH
// uid's host processes — unsigned work must not modify the host. buildFilter
// denies each of these with EPERM when arg0 (the pid, low word) != 0, so a
// jailed command keeps the self-targeting (pid 0) forms that ordinary reads use
// but cannot reach another process. Rung 1 does not need them: the PID namespace
// hides every host pid. setpriority/ioprio_set are filtered on their
// (which, who) pair separately (they target a pid via `who`, not arg0).
var procStatePidSyscalls = []uint32{
	unix.SYS_SCHED_SETAFFINITY, unix.SYS_SCHED_SETSCHEDULER,
	unix.SYS_SCHED_SETPARAM, unix.SYS_SCHED_SETATTR,
}

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
