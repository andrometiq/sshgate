//go:build linux

package confine

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMaxKnownSyscallMatchesXSysTable reads the amd64 syscall table of the
// x/sys version this module builds against and requires maxKnownSyscall to be
// its maximum. An x/sys bump that adds a higher syscall fails here, so the
// ENOSYS ceiling is raised deliberately instead of silently lagging the table.
func TestMaxKnownSyscallMatchesXSysTable(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys").Output()
	if err != nil {
		t.Fatalf("locate golang.org/x/sys: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	src, err := os.ReadFile(filepath.Join(dir, "unix", "zsysnum_linux_amd64.go"))
	if err != nil {
		t.Fatalf("read x/sys amd64 syscall table: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*SYS_[A-Z0-9_]+\s*=\s*(\d+)\s*$`)
	maxNR, n := -1, 0
	for _, m := range re.FindAllSubmatch(src, -1) {
		v, err := strconv.Atoi(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		n++
		if v > maxNR {
			maxNR = v
		}
	}
	if n < 300 {
		t.Fatalf("parsed only %d syscalls from %s; table format changed?", n, dir)
	}
	if maxKnownSyscall != maxNR {
		t.Fatalf("maxKnownSyscall=%d but the x/sys amd64 table (%s) tops out at %d: raise the ceiling deliberately",
			maxKnownSyscall, dir, maxNR)
	}
}

// TestDeniedSyscallsWithinCeiling makes sure every syscall our rules target is
// within the known range, so none of them is dead-shadowed by the ENOSYS rule.
func TestDeniedSyscallsWithinCeiling(t *testing.T) {
	targeted := append([]uint32{}, flatDeny...)
	targeted = append(targeted, metadataDeny...)
	targeted = append(targeted, mqueueDeny...)
	targeted = append(targeted,
		uint32(unix.SYS_CLONE), uint32(unix.SYS_CLONE3), uint32(unix.SYS_UNSHARE),
		uint32(unix.SYS_SETNS), uint32(unix.SYS_IOCTL), uint32(unix.SYS_SOCKET),
		uint32(unix.SYS_TRUNCATE), uint32(unix.SYS_FTRUNCATE), uint32(unix.SYS_OPEN_BY_HANDLE_AT),
		uint32(unix.SYS_PRLIMIT64), uint32(unix.SYS_SETPRIORITY), uint32(unix.SYS_IOPRIO_SET),
	)
	for _, s := range targeted {
		if s > uint32(maxKnownSyscall) {
			t.Errorf("targeted syscall %d exceeds ceiling %d", s, maxKnownSyscall)
		}
	}
}

// Historical family literals remain independent of the production total table.
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
