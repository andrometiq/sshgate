//go:build linux

package confine

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// evalFilter is a tiny cBPF interpreter covering exactly the instruction subset
// buildFilter emits (LD|W|ABS, ALU|AND|K, JMP JEQ/JGT/JSET/JA, RET|K). It lets
// the test assert the DECISION the kernel would make for a given syscall, which
// is far more robust than asserting instruction indices.
func evalFilter(t *testing.T, f []unix.SockFilter, data []byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(f); {
		ins := f[pc]
		switch ins.Code & 0x07 {
		case bpfLD:
			if int(ins.K)+4 > len(data) {
				t.Fatalf("filter loaded out-of-range offset %d", ins.K)
			}
			a = binary.LittleEndian.Uint32(data[ins.K:])
			pc++
		case bpfALU:
			a &= ins.K
			pc++
		case bpfJMP:
			switch ins.Code & 0xf0 {
			case bpfJA:
				pc += 1 + int(ins.K)
			case bpfJEQ:
				pc += 1 + jump(a == ins.K, ins)
			case bpfJGT:
				pc += 1 + jump(a > ins.K, ins)
			case bpfJSET:
				pc += 1 + jump(a&ins.K != 0, ins)
			default:
				t.Fatalf("unknown jump op %#x", ins.Code)
			}
		case bpfRET:
			return ins.K
		default:
			t.Fatalf("unknown instruction class %#x", ins.Code)
		}
	}
	t.Fatal("filter ran off the end without a RET")
	return 0
}

func jump(take bool, ins unix.SockFilter) int {
	if take {
		return int(ins.Jt)
	}
	return int(ins.Jf)
}

func dataFor(nr uint32, arch uint32, args ...uint64) []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[offNR:], nr)
	binary.LittleEndian.PutUint32(b[offArch:], arch)
	for i, v := range args {
		if i >= 6 {
			break
		}
		binary.LittleEndian.PutUint64(b[16+i*8:], v)
	}
	return b
}

const x8664 = uint32(unix.AUDIT_ARCH_X86_64)

var (
	actAllow  = uint32(unix.SECCOMP_RET_ALLOW)
	actDeny   = retErrno(unix.EPERM)
	actEnosys = retErrno(unix.ENOSYS)
	actKill   = uint32(unix.SECCOMP_RET_KILL_PROCESS)
)

func TestBuildFilterCoreDecisions(t *testing.T) {
	f := buildFilter(filterParams{allowInet: true})

	cases := []struct {
		name string
		data []byte
		want uint32
	}{
		{"wrong arch killed", dataFor(uint32(unix.SYS_READ), unix.AUDIT_ARCH_I386), actKill},
		{"x32 bit killed", dataFor(uint32(unix.SYS_READ)|0x40000000, x8664), actKill},
		{"unknown-high enosys", dataFor(uint32(maxKnownSyscall)+1, x8664), actEnosys},
		{"ordinary read allowed", dataFor(uint32(unix.SYS_READ), x8664), actAllow},
		{"openat allowed", dataFor(uint32(unix.SYS_OPENAT), x8664), actAllow},
		{"clone3 enosys", dataFor(uint32(unix.SYS_CLONE3), x8664), actEnosys},
		{"mount denied", dataFor(uint32(unix.SYS_MOUNT), x8664), actDeny},
		{"mount_setattr denied", dataFor(uint32(unix.SYS_MOUNT_SETATTR), x8664), actDeny},
		{"fsconfig denied", dataFor(uint32(unix.SYS_FSCONFIG), x8664), actDeny},
		{"open_tree_attr denied", dataFor(uint32(unix.SYS_OPEN_TREE_ATTR), x8664), actDeny},
		{"ptrace denied", dataFor(uint32(unix.SYS_PTRACE), x8664), actDeny},
		{"bpf denied", dataFor(uint32(unix.SYS_BPF), x8664), actDeny},
		{"personality denied", dataFor(uint32(unix.SYS_PERSONALITY), x8664), actDeny},
		{"pidfd_getfd denied", dataFor(uint32(unix.SYS_PIDFD_GETFD), x8664), actDeny},
	}
	for _, c := range cases {
		if got := evalFilter(t, f, c.data); got != c.want {
			t.Errorf("%s: got %#x want %#x", c.name, got, c.want)
		}
	}
}

func TestBuildFilterSocketDomain(t *testing.T) {
	f := buildFilter(filterParams{allowInet: false})
	socket := uint32(unix.SYS_SOCKET)
	cases := []struct {
		name   string
		domain uint64
		proto  uint64
		want   uint32
	}{
		{"AF_UNIX denied", unix.AF_UNIX, 0, actDeny},
		{"AF_PACKET denied", unix.AF_PACKET, 0, actDeny},
		{"AF_INET denied when inet off", unix.AF_INET, 0, actDeny},
		{"AF_INET6 denied when inet off", unix.AF_INET6, 0, actDeny},
		{"netlink route allowed", unix.AF_NETLINK, unix.NETLINK_ROUTE, actAllow},
		{"netlink sock_diag allowed", unix.AF_NETLINK, unix.NETLINK_SOCK_DIAG, actAllow},
		{"netlink other denied", unix.AF_NETLINK, 9 /*NETLINK_AUDIT*/, actDeny},
	}
	for _, c := range cases {
		got := evalFilter(t, f, dataFor(socket, x8664, c.domain, 0, c.proto))
		if got != c.want {
			t.Errorf("%s: got %#x want %#x", c.name, got, c.want)
		}
	}

	// With inet allowed, AF_INET/AF_INET6 pass; AF_UNIX stays denied.
	fi := buildFilter(filterParams{allowInet: true})
	if got := evalFilter(t, fi, dataFor(socket, x8664, unix.AF_INET)); got != actAllow {
		t.Errorf("AF_INET with inet on: got %#x want allow", got)
	}
	if got := evalFilter(t, fi, dataFor(socket, x8664, unix.AF_UNIX)); got != actDeny {
		t.Errorf("AF_UNIX with inet on: got %#x want deny", got)
	}
}

func TestBuildFilterIoctlAndCloneArgs(t *testing.T) {
	f := buildFilter(filterParams{allowInet: true})

	// ioctl: terminal-injection requests denied, others allowed (arg1 = request).
	ioctl := uint32(unix.SYS_IOCTL)
	if got := evalFilter(t, f, dataFor(ioctl, x8664, 0, unix.TIOCSTI)); got != actDeny {
		t.Errorf("ioctl TIOCSTI: got %#x want deny", got)
	}
	if got := evalFilter(t, f, dataFor(ioctl, x8664, 0, unix.TIOCLINUX)); got != actDeny {
		t.Errorf("ioctl TIOCLINUX: got %#x want deny", got)
	}
	if got := evalFilter(t, f, dataFor(ioctl, x8664, 0, unix.TIOCGWINSZ)); got != actAllow {
		t.Errorf("ioctl TIOCGWINSZ: got %#x want allow", got)
	}

	// clone: a namespace flag is denied; a plain thread clone (CLONE_VM...) allowed.
	clone := uint32(unix.SYS_CLONE)
	if got := evalFilter(t, f, dataFor(clone, x8664, unix.CLONE_NEWUSER)); got != actDeny {
		t.Errorf("clone CLONE_NEWUSER: got %#x want deny", got)
	}
	threadFlags := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_THREAD | unix.SIGCHLD)
	if got := evalFilter(t, f, dataFor(clone, x8664, threadFlags)); got != actAllow {
		t.Errorf("clone thread flags: got %#x want allow", got)
	}

	// setns uses arg1 for the nstype.
	setns := uint32(unix.SYS_SETNS)
	if got := evalFilter(t, f, dataFor(setns, x8664, 0, unix.CLONE_NEWNET)); got != actDeny {
		t.Errorf("setns CLONE_NEWNET: got %#x want deny", got)
	}
}

// TestLegacyCloneMaskExcludesNewtime guards the CSIGNAL/CLONE_NEWTIME overlap: a
// legacy clone() whose low byte is a child exit signal (e.g. SIGCHLD=0x11) must
// NOT be misread as carrying CLONE_NEWTIME (0x80) — so the legacy mask must omit
// NEWTIME while the unshare/setns mask keeps the full set.
func TestLegacyCloneMaskExcludesNewtime(t *testing.T) {
	if nsLegacyCloneBits&unix.CLONE_NEWTIME != 0 {
		t.Fatal("legacy clone mask must not include CLONE_NEWTIME (overlaps CSIGNAL)")
	}
	if nsCloneBits&unix.CLONE_NEWTIME == 0 {
		t.Fatal("full ns mask should include CLONE_NEWTIME")
	}
}

func TestBuildFilterTruncateByABI(t *testing.T) {
	// denyTruncate off: truncate is allowed (EROFS/Landlock cover it).
	f := buildFilter(filterParams{allowInet: true, denyTruncate: false})
	if got := evalFilter(t, f, dataFor(uint32(unix.SYS_TRUNCATE), x8664)); got != actAllow {
		t.Errorf("truncate with denyTruncate=false: got %#x want allow", got)
	}
	// denyTruncate on (rung 2, ABI<3): truncate/ftruncate denied by seccomp.
	fd := buildFilter(filterParams{allowInet: true, denyTruncate: true})
	if got := evalFilter(t, fd, dataFor(uint32(unix.SYS_TRUNCATE), x8664)); got != actDeny {
		t.Errorf("truncate with denyTruncate=true: got %#x want deny", got)
	}
	if got := evalFilter(t, fd, dataFor(uint32(unix.SYS_FTRUNCATE), x8664)); got != actDeny {
		t.Errorf("ftruncate with denyTruncate=true: got %#x want deny", got)
	}
}

func TestBuildFilterMetadata(t *testing.T) {
	// Rung 1 (denyMetadata off): EROFS covers metadata, so seccomp allows the
	// calls (a chmod on a writable tmpfs file is legitimate).
	f := buildFilter(filterParams{allowInet: true, denyMetadata: false})
	if got := evalFilter(t, f, dataFor(uint32(unix.SYS_CHMOD), x8664)); got != actAllow {
		t.Errorf("chmod with denyMetadata=false: got %#x want allow", got)
	}
	// Rung 2 (denyMetadata on): Landlock never covers these, so seccomp must deny
	// EVERY entry of the table — and only when denyMetadata is set.
	fd := buildFilter(filterParams{allowInet: true, denyMetadata: true})
	if len(metadataDeny) == 0 {
		t.Fatal("metadataDeny is empty")
	}
	for _, nr := range metadataDeny {
		if got := evalFilter(t, fd, dataFor(nr, x8664)); got != actDeny {
			t.Errorf("metadata syscall %d with denyMetadata=true: got %#x want deny", nr, got)
		}
		if got := evalFilter(t, f, dataFor(nr, x8664)); got != actAllow {
			t.Errorf("metadata syscall %d with denyMetadata=false: got %#x want allow", nr, got)
		}
	}
	// The table must name the whole family, not a sample.
	for _, nr := range []int{
		unix.SYS_CHMOD, unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2,
		unix.SYS_CHOWN, unix.SYS_LCHOWN, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT,
		unix.SYS_SETXATTR, unix.SYS_LSETXATTR, unix.SYS_FSETXATTR, unix.SYS_SETXATTRAT,
		unix.SYS_REMOVEXATTR, unix.SYS_LREMOVEXATTR, unix.SYS_FREMOVEXATTR, unix.SYS_REMOVEXATTRAT,
		unix.SYS_UTIME, unix.SYS_UTIMES, unix.SYS_FUTIMESAT, unix.SYS_UTIMENSAT,
		unix.SYS_FILE_SETATTR,
	} {
		found := false
		for _, d := range metadataDeny {
			found = found || d == uint32(nr)
		}
		if !found {
			t.Errorf("metadata syscall %d missing from metadataDeny", nr)
		}
	}
	// File creation/removal stay governed by Landlock, NOT seccomp-denied here.
	if got := evalFilter(t, fd, dataFor(uint32(unix.SYS_UNLINKAT), x8664)); got != actAllow {
		t.Errorf("unlinkat should be left to Landlock: got %#x want allow", got)
	}
}

// TestBuildFilterMQueue: rung 2 shares the host's IPC namespace and Landlock
// mediates neither mq_unlink nor mq_open's create, so seccomp denies both there
// and only there (rung 1 has its own IPC namespace).
func TestBuildFilterMQueue(t *testing.T) {
	r1 := buildFilter(filterParams{allowInet: true, denyMetadata: false})
	r2 := buildFilter(filterParams{allowInet: true, denyMetadata: true})
	for _, nr := range []uint32{unix.SYS_MQ_OPEN, unix.SYS_MQ_UNLINK} {
		if got := evalFilter(t, r2, dataFor(nr, x8664)); got != actDeny {
			t.Errorf("mqueue syscall %d on rung 2: got %#x want deny", nr, got)
		}
		if got := evalFilter(t, r1, dataFor(nr, x8664)); got != actAllow {
			t.Errorf("mqueue syscall %d on rung 1: got %#x want allow", nr, got)
		}
	}
}

// TestBuildFilterMetadataIoctls: on rung 2 the inode-flag ioctls are denied
// whatever the high word of the request, and only on rung 2; ordinary ioctls
// (including the read-side FS_IOC_GETFLAGS) stay allowed.
func TestBuildFilterMetadataIoctls(t *testing.T) {
	ioctl := uint32(unix.SYS_IOCTL)
	f := buildFilter(filterParams{allowInet: true, denyMetadata: false})
	fd := buildFilter(filterParams{allowInet: true, denyMetadata: true})
	want := []uint32{unix.FS_IOC_SETFLAGS, 0x401c5820 /*FS_IOC_FSSETXATTR*/, unix.FS_IOC_ENABLE_VERITY, unix.FS_IOC_SET_ENCRYPTION_POLICY}
	if len(metadataIoctlDeny) != len(want) {
		t.Fatalf("metadataIoctlDeny has %d entries, want %d", len(metadataIoctlDeny), len(want))
	}
	for i, req := range want {
		if metadataIoctlDeny[i] != req {
			t.Errorf("metadataIoctlDeny[%d]=%#x want %#x", i, metadataIoctlDeny[i], req)
		}
		for _, hi := range []uint64{0, 0xffffffff00000000} {
			if got := evalFilter(t, fd, dataFor(ioctl, x8664, 3, hi|uint64(req))); got != actDeny {
				t.Errorf("ioctl %#x (hi %#x) rung 2: got %#x want deny", req, hi, got)
			}
		}
		if got := evalFilter(t, f, dataFor(ioctl, x8664, 3, uint64(req))); got != actAllow {
			t.Errorf("ioctl %#x rung 1: got %#x want allow (EROFS covers it)", req, got)
		}
	}
	for _, req := range []uint32{unix.FS_IOC_GETFLAGS, unix.TIOCGWINSZ, unix.TCGETS} {
		if got := evalFilter(t, fd, dataFor(ioctl, x8664, 3, uint64(req))); got != actAllow {
			t.Errorf("read ioctl %#x rung 2: got %#x want allow", req, got)
		}
	}
	if got := evalFilter(t, fd, dataFor(ioctl, x8664, 0, unix.TIOCSTI)); got != actDeny {
		t.Errorf("TIOCSTI rung 2: got %#x want deny", got)
	}
}

// TestBuildFilterTtyIoctls covers rung 2 below Landlock ABI 5: every
// tty-state-changing request is denied (any high word), the read requests stay
// allowed, and with the param off (rung 1, or ABI ≥5) they are all allowed.
func TestBuildFilterTtyIoctls(t *testing.T) {
	ioctl := uint32(unix.SYS_IOCTL)
	off := buildFilter(filterParams{allowInet: true, denyMetadata: true})
	on := buildFilter(filterParams{allowInet: true, denyMetadata: true, denyTtyIoctl: true})
	want := []uint32{
		unix.TCSETS, unix.TCSETSW, unix.TCSETSF, unix.TCSETA, unix.TCSETAW, unix.TCSETAF,
		unix.TCSETS2, unix.TCSETSW2, unix.TCSETSF2,
		unix.TIOCSWINSZ, unix.TCFLSH, unix.TCXONC, unix.TIOCSETD, unix.TIOCSPGRP,
	}
	if len(ttyMutateIoctlDeny) != len(want) {
		t.Fatalf("ttyMutateIoctlDeny has %d entries, want %d", len(ttyMutateIoctlDeny), len(want))
	}
	for i, req := range want {
		if ttyMutateIoctlDeny[i] != req {
			t.Errorf("ttyMutateIoctlDeny[%d]=%#x want %#x", i, ttyMutateIoctlDeny[i], req)
		}
		for _, hi := range []uint64{0, 0xffffffff00000000} {
			if got := evalFilter(t, on, dataFor(ioctl, x8664, 3, hi|uint64(req))); got != actDeny {
				t.Errorf("tty ioctl %#x (hi %#x) denyTtyIoctl: got %#x want deny", req, hi, got)
			}
		}
		if got := evalFilter(t, off, dataFor(ioctl, x8664, 3, uint64(req))); got != actAllow {
			t.Errorf("tty ioctl %#x without denyTtyIoctl: got %#x want allow", req, got)
		}
	}
	for _, req := range []uint32{unix.TCGETS, unix.TIOCGWINSZ, unix.TIOCGPGRP, unix.TIOCINQ} {
		if got := evalFilter(t, on, dataFor(ioctl, x8664, 3, uint64(req))); got != actAllow {
			t.Errorf("read tty ioctl %#x denyTtyIoctl: got %#x want allow", req, got)
		}
	}
}

// TestBuildFilterProcState covers the rung-2 (denyMetadata) wall against retuning
// another host process: prlimit64/sched_set* targeting a non-zero pid are denied
// while the self (pid 0) forms stay allowed; setpriority/ioprio_set are allowed
// only for the self (which, who)==(PROCESS, 0) pair. On rung 1 (denyMetadata off)
// the pid namespace is the wall and seccomp leaves all of these alone.
func TestBuildFilterProcState(t *testing.T) {
	r1 := buildFilter(filterParams{allowInet: true, denyMetadata: false})
	r2 := buildFilter(filterParams{allowInet: true, denyMetadata: true})

	// prlimit64 + sched_set*: arg0 is the pid. pid!=0 denied on rung 2, pid 0
	// allowed; rung 1 leaves them allowed regardless.
	pidArg0 := append([]uint32{uint32(unix.SYS_PRLIMIT64)}, procStatePidSyscalls...)
	for _, nr := range pidArg0 {
		if got := evalFilter(t, r2, dataFor(nr, x8664, 1234)); got != actDeny {
			t.Errorf("rung2 syscall %d pid=1234: got %#x want deny", nr, got)
		}
		if got := evalFilter(t, r2, dataFor(nr, x8664, 0)); got != actAllow {
			t.Errorf("rung2 syscall %d pid=0 (self): got %#x want allow", nr, got)
		}
		if got := evalFilter(t, r1, dataFor(nr, x8664, 1234)); got != actAllow {
			t.Errorf("rung1 syscall %d pid=1234: got %#x want allow (pid ns is the wall)", nr, got)
		}
	}

	// setpriority(which, who, prio): only (PRIO_PROCESS, 0) self is allowed.
	setprio := uint32(unix.SYS_SETPRIORITY)
	if got := evalFilter(t, r2, dataFor(setprio, x8664, uint64(unix.PRIO_PROCESS), 0)); got != actAllow {
		t.Errorf("rung2 setpriority(PROCESS, self): got %#x want allow", got)
	}
	if got := evalFilter(t, r2, dataFor(setprio, x8664, uint64(unix.PRIO_PROCESS), 1234)); got != actDeny {
		t.Errorf("rung2 setpriority(PROCESS, 1234): got %#x want deny (renice -p)", got)
	}
	if got := evalFilter(t, r2, dataFor(setprio, x8664, uint64(unix.PRIO_USER), 0)); got != actDeny {
		t.Errorf("rung2 setpriority(USER, 0): got %#x want deny (renice -u)", got)
	}
	if got := evalFilter(t, r1, dataFor(setprio, x8664, uint64(unix.PRIO_USER), 0)); got != actAllow {
		t.Errorf("rung1 setpriority(USER, 0): got %#x want allow", got)
	}

	// ioprio_set(which, who, ioprio): only (IOPRIO_WHO_PROCESS, 0) self allowed.
	ioprio := uint32(unix.SYS_IOPRIO_SET)
	if got := evalFilter(t, r2, dataFor(ioprio, x8664, ioprioWhoProcess, 0)); got != actAllow {
		t.Errorf("rung2 ioprio_set(PROCESS, self): got %#x want allow", got)
	}
	if got := evalFilter(t, r2, dataFor(ioprio, x8664, ioprioWhoProcess, 1234)); got != actDeny {
		t.Errorf("rung2 ioprio_set(PROCESS, 1234): got %#x want deny", got)
	}
	if got := evalFilter(t, r2, dataFor(ioprio, x8664, 2 /*IOPRIO_WHO_PGRP*/, 0)); got != actDeny {
		t.Errorf("rung2 ioprio_set(PGRP, 0): got %#x want deny", got)
	}
	if got := evalFilter(t, r1, dataFor(ioprio, x8664, 2, 0)); got != actAllow {
		t.Errorf("rung1 ioprio_set(PGRP, 0): got %#x want allow", got)
	}
}

func TestBuildFilterOpenByHandle(t *testing.T) {
	f := buildFilter(filterParams{allowInet: true, denyOpenByHandle: false})
	if got := evalFilter(t, f, dataFor(uint32(unix.SYS_OPEN_BY_HANDLE_AT), x8664)); got != actAllow {
		t.Errorf("open_by_handle_at default: got %#x want allow", got)
	}
	fd := buildFilter(filterParams{allowInet: true, denyOpenByHandle: true})
	if got := evalFilter(t, fd, dataFor(uint32(unix.SYS_OPEN_BY_HANDLE_AT), x8664)); got != actDeny {
		t.Errorf("open_by_handle_at for root SSH user: got %#x want deny", got)
	}
}

// TestFilterJumpOffsetsInRange makes sure every conditional jump resolves within
// the 8-bit field across all parameter combinations (build() panics otherwise).
func TestFilterJumpOffsetsInRange(t *testing.T) {
	for _, inet := range []bool{false, true} {
		for _, md := range []bool{false, true} {
			for _, tr := range []bool{false, true} {
				for _, oh := range []bool{false, true} {
					for _, tty := range []bool{false, true} {
						f := buildFilter(filterParams{allowInet: inet, denyMetadata: md, denyTruncate: tr, denyOpenByHandle: oh, denyTtyIoctl: tty})
						if len(f) == 0 {
							t.Fatal("empty filter")
						}
					}
				}
			}
		}
	}
}
