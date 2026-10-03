//go:build linux

package confine

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Independent specification literals: do not derive expectations from production rows.
const pinnedDeny = `MOUNT UMOUNT2 PIVOT_ROOT OPEN_TREE MOVE_MOUNT FSOPEN FSMOUNT FSPICK MOUNT_SETATTR FSCONFIG OPEN_TREE_ATTR
PTRACE PROCESS_VM_READV PROCESS_VM_WRITEV PIDFD_GETFD BPF PERF_EVENT_OPEN USERFAULTFD KEYCTL ADD_KEY REQUEST_KEY
IO_URING_SETUP IO_URING_ENTER IO_URING_REGISTER KEXEC_LOAD KEXEC_FILE_LOAD INIT_MODULE FINIT_MODULE DELETE_MODULE REBOOT SWAPON SWAPOFF SETTIMEOFDAY CLOCK_SETTIME CLOCK_ADJTIME ADJTIMEX
PERSONALITY OPEN_BY_HANDLE_AT SETNS LISTEN CHMOD FCHMOD FCHMODAT FCHMODAT2 CHOWN LCHOWN FCHOWN FCHOWNAT SETXATTR LSETXATTR FSETXATTR SETXATTRAT REMOVEXATTR LREMOVEXATTR FREMOVEXATTR REMOVEXATTRAT UTIME UTIMES FUTIMESAT UTIMENSAT FILE_SETATTR
MQ_OPEN MQ_UNLINK MQ_TIMEDSEND MQ_TIMEDRECEIVE MQ_NOTIFY MQ_GETSETATTR SYNC SYNCFS`
const pinnedEnosys = `CLONE3 USELIB _SYSCTL CREATE_MODULE GET_KERNEL_SYMS QUERY_MODULE NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE EPOLL_CTL_OLD EPOLL_WAIT_OLD VSERVER`
const pinnedFilters = `CLONE UNSHARE SOCKET SOCKETPAIR IOCTL FCNTL FLOCK SETRLIMIT PRLIMIT64`

func xsysNames(t *testing.T) map[string]uint32 {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys").Output()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "unix/zsysnum_linux_amd64.go"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]uint32{}
	for _, m := range regexp.MustCompile(`(?m)^\s*SYS_([A-Z0-9_]+)\s*=\s*(\d+)\s*$`).FindAllSubmatch(source, -1) {
		nr, _ := strconv.ParseUint(string(m[2]), 10, 32)
		names[string(m[1])] = uint32(nr)
	}
	if len(names) != 385 {
		t.Fatalf("x/sys named syscall count %d", len(names))
	}
	return names
}

func TestSyscallTableTotal(t *testing.T) {
	want := xsysNames(t)
	got := map[string]uint32{}
	numbers := map[uint32]bool{}
	for _, row := range syscallTable {
		if _, ok := got[row.name]; ok || numbers[row.nr] {
			t.Fatalf("duplicate row %+v", row)
		}
		got[row.name] = row.nr
		numbers[row.nr] = true
		if row.why == "" {
			t.Errorf("empty rationale %+v", row)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("table differs from x/sys names/numbers")
	}
}

func TestSyscallTableNonAllowRowsPinned(t *testing.T) {
	for action, literal := range map[string]string{"deny": pinnedDeny, "enosys": pinnedEnosys, "filter": pinnedFilters} {
		var got []string
		for _, row := range syscallTable {
			if strings.Split(row.action, ":")[0] == action {
				got = append(got, row.name)
			}
		}
		want := strings.Fields(literal)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s got %v want %v", action, got, want)
		}
	}
	for _, row := range syscallTable {
		if strings.HasPrefix(row.action, "filter:") && row.action != "filter:"+strings.ToLower(row.name) {
			t.Errorf("wrong handler %+v", row)
		}
		if row.action != "allow" && row.action != "deny" && row.action != "enosys" && !strings.HasPrefix(row.action, "filter:") {
			t.Errorf("unknown action %+v", row)
		}
	}
	allowedCategories := strings.Fields("fs-read fs-mutate proc-other ipc net-io cred cap-gated-init sandbox self")
	for _, row := range syscallTable {
		if row.action == "allow" {
			found := false
			for _, why := range allowedCategories {
				found = found || row.why == why
			}
			if !found {
				t.Errorf("bad allow rationale %+v", row)
			}
		}
	}
}

func TestFilterDecisionsExhaustive(t *testing.T) {
	names := xsysNames(t)
	want := map[uint32]uint32{}
	for _, nr := range names {
		want[nr] = actAllow
	}
	for _, name := range strings.Fields(pinnedDeny) {
		want[names[name]] = actDeny
	}
	for _, name := range strings.Fields(pinnedEnosys) {
		want[names[name]] = actEnosys
	}
	// All-zero arguments: socket/socketpair/flock are denied; others permit.
	for _, name := range []string{"SOCKET", "SOCKETPAIR", "FLOCK"} {
		want[names[name]] = actDeny
	}
	for _, net := range []bool{false, true} {
		f := buildFilter(filterParams{allowInet: net})
		for nr := uint32(0); nr <= maxKnownSyscall+16; nr++ {
			expected, ok := want[nr]
			if !ok {
				expected = actEnosys
			}
			if got := evalFilter(t, f, dataFor(nr, x8664)); got != expected {
				t.Errorf("nr %d got %#x want %#x", nr, got, expected)
			}
		}
		for nr := uint32(0); nr <= maxKnownSyscall; nr++ {
			if evalFilter(t, f, dataFor(nr|0x40000000, x8664)) != actKill {
				t.Errorf("x32 %d allowed", nr)
			}
			if evalFilter(t, f, dataFor(nr, 0)) != actKill {
				t.Errorf("foreign arch %d allowed", nr)
			}
		}
	}
}

func TestFilterLength(t *testing.T) {
	for _, net := range []bool{false, true} {
		f := buildFilter(filterParams{allowInet: net})
		if len(f) >= 4096 {
			t.Fatalf("BPF length %d", len(f))
		}
		t.Logf("inet=%t: %d instructions", net, len(f))
	}
}
