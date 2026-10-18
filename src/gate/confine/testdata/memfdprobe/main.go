// Command memfdprobe answers, for the mutation registry, whether narrow
// Landlock EXECUTE alone stops a memfd exec on this kernel. It is built and run
// by the confine tests as its own static binary, and Landlocks only a child of
// itself.
//
// The attempt matches the daemon-read fixture's memfd mode
// (cmd/sshgate-gate/testdata/lane2client): memfd_create with MFD_EXEC where the
// kernel has it, a copy of a dynamic program, and fexecve's
// execveat(fd, "", AT_EMPTY_PATH). Only an execution-stage EACCES from an
// executable memfd is "blocked"; anything else that goes wrong (creation
// refused, a memfd that is not executable, another errno) is an error, never a
// verdict.
//
// Usage: memfdprobe native|abi1. It prints "blocked", "runs" or "no-landlock"
// (the kernel has no Landlock, so nothing blocks), or an error and exits 1.
// "native" handles every probe right the kernel's Landlock ABI supports (REFER
// from ABI 2); "abi1" handles the ABI 1 rights on any kernel. On stderr it
// prints "abi=<native ABI> handled=<rights> flags=<memfd flags>". The tests
// set MEMFDPROBE_NATIVE_ABI to stand in for the kernel's ABI answer.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// childArg makes the attempt: Landlock is irreversible, so the parent stays
// unrestricted to read the child's outcome. The child exits 0 only as the
// payload (/bin/true) having run.
const childArg = "__memfdprobe_child"

const (
	childBlocked    = 3
	childNoLandlock = 4
	childFailed     = 5
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == childArg {
		os.Exit(child(os.Args[2] == "abi1"))
	}
	verdict, err := probe(len(os.Args) > 1 && os.Args[1] == "abi1")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println(verdict)
}

func probe(abi1 bool) (string, error) {
	abi := "native"
	if abi1 {
		abi = "abi1"
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	attempt := exec.Command(self, childArg, abi)
	var stderr strings.Builder
	attempt.Stderr = &stderr
	err = attempt.Run()
	fmt.Fprint(os.Stderr, stderr.String())
	var exit *exec.ExitError
	switch {
	case err == nil:
		return "runs", nil
	case !errors.As(err, &exit):
		return "", err
	case exit.ExitCode() == childBlocked:
		return "blocked", nil
	case exit.ExitCode() == childNoLandlock:
		return "no-landlock", nil
	}
	return "", fmt.Errorf("attempt: %v: %s", err, strings.TrimSpace(stderr.String()))
}

func child(abi1 bool) int {
	// Landlock and no_new_privs bind the calling thread; the execveat must
	// come from that thread.
	runtime.LockOSThread()
	payload, err := os.ReadFile("/bin/true")
	if err != nil {
		return fail("read /bin/true: %v", err)
	}
	interp, err := filepath.EvalSymlinks("/lib64/ld-linux-x86-64.so.2")
	if err != nil {
		return fail("interpreter: %v", err)
	}
	native, errno := landlockABI()
	if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
		return childNoLandlock
	}
	if errno != 0 {
		return fail("landlock ABI: %v", errno)
	}
	abi := native
	if abi1 {
		abi = 1
	}
	handled := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	if abi >= 2 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	fmt.Fprintf(os.Stderr, "abi=%d handled=%#x flags=%#x\n", native, handled, memfdFlags)
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	ruleset, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fail("landlock: %v", errno)
	}
	grant := func(path string, access uint64) error {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}
		if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, ruleset, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
			return errno
		}
		return nil
	}
	if err := grant("/", unix.LANDLOCK_ACCESS_FS_READ_FILE|unix.LANDLOCK_ACCESS_FS_READ_DIR); err != nil {
		return fail("grant /: %v", err)
	}
	if err := grant(interp, unix.LANDLOCK_ACCESS_FS_EXECUTE|unix.LANDLOCK_ACCESS_FS_READ_FILE); err != nil {
		return fail("grant %s: %v", interp, err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fail("no_new_privs: %v", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0, 0); errno != 0 {
		return fail("restrict: %v", errno)
	}
	// As the fixture: MFD_EXEC where the kernel has it (EINVAL before 6.3,
	// where every memfd is executable), so vm.memfd_noexec=1 does not decide.
	fd, err := unix.MemfdCreate("memfdprobe", memfdFlags)
	if err == unix.EINVAL {
		fd, err = unix.MemfdCreate("memfdprobe", unix.MFD_CLOEXEC)
	}
	if err != nil {
		return fail("memfd_create: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&0o111 == 0 {
		return fail("the memfd is not executable: mode %o, %v", st.Mode, err)
	}
	if _, err := unix.Write(fd, payload); err != nil {
		return fail("write: %v", err)
	}
	empty, _ := unix.BytePtrFromString("")
	argv, _ := syscall.SlicePtrFromStrings([]string{"true"})
	envv := []*byte{nil}
	_, _, errno = unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envv[0])), unix.AT_EMPTY_PATH, 0)
	if errno == unix.EACCES {
		return childBlocked
	}
	return fail("execveat: %v", errno)
}

// memfdFlags is the fixture's SG_MEMFD_FLAGS.
const memfdFlags = unix.MFD_CLOEXEC | unix.MFD_EXEC

// landlockABI is the kernel's Landlock ABI version, or MEMFDPROBE_NATIVE_ABI
// when a test sets it.
func landlockABI() (int, unix.Errno) {
	if fake := os.Getenv("MEMFDPROBE_NATIVE_ABI"); fake != "" {
		abi, err := strconv.Atoi(fake)
		if err != nil || abi < 1 {
			return 0, unix.EINVAL
		}
		return abi, 0
	}
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	return int(abi), errno
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	return childFailed
}
