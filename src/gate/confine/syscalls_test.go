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
