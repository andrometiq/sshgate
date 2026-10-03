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
		{"netlink sock_diag denied", unix.AF_NETLINK, unix.NETLINK_SOCK_DIAG, actDeny},
		{"netlink other denied", unix.AF_NETLINK, 9 /*NETLINK_AUDIT*/, actDeny},
	}
	for _, c := range cases {
		got := evalFilter(t, f, dataFor(socket, x8664, c.domain, unix.SOCK_DGRAM, c.proto))
		if got != c.want {
			t.Errorf("%s: got %#x want %#x", c.name, got, c.want)
		}
	}

	// With inet allowed, AF_INET/AF_INET6 pass; AF_UNIX stays denied.
	fi := buildFilter(filterParams{allowInet: true})
	if got := evalFilter(t, fi, dataFor(socket, x8664, unix.AF_INET, unix.SOCK_STREAM)); got != actAllow {
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

func TestBuildFilterTruncateUsesFilesystemWalls(t *testing.T) {
	for _, nr := range []uint32{unix.SYS_TRUNCATE, unix.SYS_FTRUNCATE} {
		if got := evalFilter(t, buildFilter(filterParams{}), dataFor(nr, x8664)); got != actAllow {
			t.Errorf("truncate %d: %#x", nr, got)
		}
	}
}

func TestBuildFilterMetadata(t *testing.T) {
	for _, net := range []bool{false, true} {
		fd := buildFilter(filterParams{allowInet: net})
		if len(metadataDeny) == 0 {
			t.Fatal("metadataDeny is empty")
		}
		for _, nr := range metadataDeny {
			if got := evalFilter(t, fd, dataFor(nr, x8664)); got != actDeny {
				t.Errorf("metadata syscall %d with denyMetadata=true: got %#x want deny", nr, got)
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
}

func TestBuildFilterMQueue(t *testing.T) {
	for _, net := range []bool{false, true} {
		for _, nr := range []uint32{240, 241, 242, 243, 244, 245} {
			if got := evalFilter(t, buildFilter(filterParams{allowInet: net}), dataFor(nr, x8664)); got != actDeny {
				t.Errorf("mqueue %d: %#x", nr, got)
			}
		}
	}
}

func TestBuildFilterMetadataIoctls(t *testing.T) {
	f := buildFilter(filterParams{})
	want := []uint32{0x40086602, 0x40046602, 0x401c5820}
	if len(fileattrIoctlDeny) != len(want) {
		t.Fatalf("fileattr table length: %v", fileattrIoctlDeny)
	}
	for i, req := range want {
		if fileattrIoctlDeny[i] != req {
			t.Errorf("fileattr[%d]=%#x want %#x", i, fileattrIoctlDeny[i], req)
		}
		for _, net := range []bool{false, true} {
			f = buildFilter(filterParams{allowInet: net})
			for _, hi := range []uint64{0, 0xffffffff00000000} {
				if got := evalFilter(t, f, dataFor(unix.SYS_IOCTL, x8664, 3, hi|uint64(req))); got != actDeny {
					t.Errorf("fileattr %#x: %#x", hi|uint64(req), got)
				}
			}
		}
	}
	for _, req := range []uint64{unix.FS_IOC_GETFLAGS, unix.TIOCGWINSZ, unix.TCGETS, unix.FS_IOC_ENABLE_VERITY, unix.FS_IOC_SET_ENCRYPTION_POLICY} {
		if got := evalFilter(t, f, dataFor(unix.SYS_IOCTL, x8664, 3, req)); got != actAllow {
			t.Errorf("ioctl %#x: %#x", req, got)
		}
	}
	if got := evalFilter(t, f, dataFor(unix.SYS_IOCTL, x8664, 0, unix.TIOCSTI)); got != actDeny {
		t.Errorf("TIOCSTI: %#x", got)
	}
}

func TestBuildFilterTtyUsesDeviceWall(t *testing.T) {
	f := buildFilter(filterParams{})
	for _, req := range []uint64{unix.TCSETS, unix.TCSETSW, unix.TCSETSF, unix.TCSETA, unix.TCSETAW, unix.TCSETAF, unix.TCSETS2, unix.TCSETSW2, unix.TCSETSF2, unix.TIOCSWINSZ, unix.TCFLSH, unix.TCXONC, unix.TIOCSETD, unix.TIOCSPGRP, unix.TCGETS, unix.TIOCGWINSZ, unix.TIOCGPGRP, unix.TIOCINQ} {
		for _, hi := range []uint64{0, 0xffffffff00000000} {
			if got := evalFilter(t, f, dataFor(unix.SYS_IOCTL, x8664, 3, req|hi)); got != actAllow {
				t.Errorf("tty %#x: %#x", req, got)
			}
		}
	}
}

func TestBuildFilterProcStateUsesPIDNamespace(t *testing.T) {
	f := buildFilter(filterParams{})
	for _, nr := range []uint32{unix.SYS_PRLIMIT64, unix.SYS_SCHED_SETAFFINITY, unix.SYS_SCHED_SETSCHEDULER, unix.SYS_SCHED_SETPARAM, unix.SYS_SCHED_SETATTR, unix.SYS_SETPRIORITY, unix.SYS_IOPRIO_SET} {
		for _, which := range []uint64{0, 1, 2, 1234} {
			for _, who := range []uint64{0, 1234} {
				if got := evalFilter(t, f, dataFor(nr, x8664, which, who)); got != actAllow {
					t.Errorf("process syscall %d: %#x", nr, got)
				}
			}
		}
	}
}

func TestBuildFilterOpenByHandle(t *testing.T) {
	f := buildFilter(filterParams{allowInet: true})
	if got := evalFilter(t, f, dataFor(uint32(unix.SYS_OPEN_BY_HANDLE_AT), x8664)); got != actDeny {
		t.Errorf("open_by_handle_at default: got %#x want deny", got)
	}
	fd := buildFilter(filterParams{allowInet: true})
	if got := evalFilter(t, fd, dataFor(uint32(unix.SYS_OPEN_BY_HANDLE_AT), x8664)); got != actDeny {
		t.Errorf("open_by_handle_at for root SSH user: got %#x want deny", got)
	}
}

// TestFilterJumpOffsetsInRange makes sure every conditional jump resolves within
// the 8-bit field across all parameter combinations (build() panics otherwise).
func TestFilterJumpOffsetsInRange(t *testing.T) {
	for _, inet := range []bool{false, true} {
		for range []bool{false, true} {
			if len(buildFilter(filterParams{allowInet: inet})) == 0 {
				t.Fatal("empty filter")
			}
		}
	}
}
