// Command memfdprobe answers, for the mutation registry, whether narrow
// Landlock EXECUTE alone stops a memfd exec on this kernel. It is built and run
// by the confine tests as its own static binary: it Landlocks only itself.
//
// Usage: memfdprobe native|abi1. It prints "blocked" or "runs", or an error
// and exits 1.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	verdict, err := probe(len(os.Args) > 1 && os.Args[1] == "abi1")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println(verdict)
}

func probe(abi1 bool) (string, error) {
	payload, err := os.ReadFile("/bin/true")
	if err != nil {
		return "", err
	}
	interp, err := filepath.EvalSymlinks("/lib64/ld-linux-x86-64.so.2")
	if err != nil {
		return "", err
	}
	handled := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	if !abi1 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	ruleset, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return "", fmt.Errorf("landlock: %w", errno)
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
		return "", err
	}
	if err := grant(interp, unix.LANDLOCK_ACCESS_FS_EXECUTE|unix.LANDLOCK_ACCESS_FS_READ_FILE); err != nil {
		return "", err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return "", err
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0, 0); errno != 0 {
		return "", fmt.Errorf("restrict: %w", errno)
	}
	fd, err := unix.MemfdCreate("memfdprobe", unix.MFD_CLOEXEC)
	if err != nil {
		return "", err
	}
	if _, err := unix.Write(fd, payload); err != nil {
		return "", err
	}
	process, err := os.StartProcess(fmt.Sprintf("/proc/self/fd/%d", fd), []string{"true"}, &os.ProcAttr{})
	if err != nil {
		return "blocked", nil
	}
	if state, err := process.Wait(); err != nil || !state.Success() {
		return "", fmt.Errorf("the memfd copy of true ran and failed: %v", err)
	}
	return "runs", nil
}
