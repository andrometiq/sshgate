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
// glibc falls back to the arg-filtered legacy clone). open_by_handle_at is
// conditional and added by buildFilter.
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

// metadataDeny backs up read-only mounts for operations Landlock never governs.
var metadataDeny = []uint32{
	unix.SYS_CHMOD, unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2,
	unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT,
	unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_FSETXATTR, unix.SYS_SETXATTRAT,
	unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR, unix.SYS_FREMOVEXATTR, unix.SYS_REMOVEXATTRAT,
	unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT, unix.SYS_UTIMENSAT,
	unix.SYS_FILE_SETATTR,
}

// mqueueDeny also prevents consuming queues through descriptors opened as files.
var mqueueDeny = []uint32{unix.SYS_MQ_OPEN, unix.SYS_MQ_UNLINK, unix.SYS_MQ_TIMEDSEND, unix.SYS_MQ_TIMEDRECEIVE, unix.SYS_MQ_NOTIFY, unix.SYS_MQ_GETSETATTR}

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
