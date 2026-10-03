// Command probe is a tiny jail-test helper (built by the jail_e2e suite, ignored
// by ./... because it lives under testdata). Each op makes raw syscalls and
// prints one "<syscall>=<result>" line per attempt, result being "ok" or the
// errno number, so the test observes exactly which call the jail refused. Exit
// status: 0 if every attempt succeeded, 1 if every attempt failed, 3 if mixed.
//
//	probe dial-unix <socket-path>          socket(AF_UNIX) + connect
//	probe read-mem  <pid>                  open + read /proc/<pid>/mem
//	probe xattr-set <path> <name> <value>  setxattr, lsetxattr, fsetxattr
//	probe xattr-rm  <path> <name>          removexattr, lremovexattr, fremovexattr
//	probe shm-rmid  <shmid>                shmctl(IPC_RMID)
//	probe setflags  <path>                 FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR, file_setattr (+nodump)
//	probe proc-state <pid>                 prlimit64, setpriority, sched_setaffinity on another pid
package main

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Not in x/sys v0.45.0 (linux/fs.h).
const (
	fsNodumpFl        = 0x40       // FS_NODUMP_FL
	fsXflagNodump     = 0x80       // FS_XFLAG_NODUMP
	fsIocFsgetxattr   = 0x801c581f // _IOR('X', 31, struct fsxattr)
	fsIocFssetxattr   = 0x401c5820 // _IOW('X', 32, struct fsxattr)
	fsxattrSize       = 28         // sizeof(struct fsxattr)
	fileAttrSize      = 24         // sizeof(struct file_attr)
	fileAttrXflagsOff = 0          // file_attr.fa_xflags
	fsxattrXflagsOff  = 0          // fsxattr.fsx_xflags (u32)
)

var ok, failed int

func report(name string, err error) bool {
	if err == nil {
		ok++
		fmt.Printf("%s=ok\n", name)
		return true
	}
	failed++
	if e, isErrno := err.(unix.Errno); isErrno {
		fmt.Printf("%s=%d\n", name, int(e))
	} else {
		fmt.Printf("%s=%q\n", name, err.Error())
	}
	return false
}

func ioctlPtr(fd int, req uintptr, p unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(p)); e != 0 {
		return e
	}
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: probe <op> <args>")
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "dial-unix":
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if report("socket", err) {
			report("connect", unix.Connect(fd, &unix.SockaddrUnix{Name: args[0]}))
		}
	case "read-mem":
		fd, err := unix.Open("/proc/"+args[0]+"/mem", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if report("open", err) {
			buf := make([]byte, 16)
			_, err := unix.Pread(fd, buf, 0x400000)
			report("pread", err)
		}
	case "xattr-set":
		p, name, val := args[0], args[1], []byte(args[2])
		report("setxattr", unix.Setxattr(p, name, val, 0))
		report("lsetxattr", unix.Lsetxattr(p, name, val, 0))
		if fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0); report("open", err) {
			report("fsetxattr", unix.Fsetxattr(fd, name, val, 0))
		}
	case "xattr-rm":
		p, name := args[0], args[1]
		report("removexattr", unix.Removexattr(p, name))
		report("lremovexattr", unix.Lremovexattr(p, name))
		if fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0); report("open", err) {
			report("fremovexattr", unix.Fremovexattr(fd, name))
		}
	case "shm-rmid":
		id, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad shmid:", err)
			os.Exit(2)
		}
		_, err = unix.SysvShmCtl(id, unix.IPC_RMID, nil)
		report("shmctl", err)
	case "setflags":
		p := args[0]
		if fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0); report("open", err) {
			flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
			if report("getflags", err) {
				report("setflags", unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags|fsNodumpFl)))
			}
			var fsx [fsxattrSize]byte
			if report("fsgetxattr", ioctlPtr(fd, fsIocFsgetxattr, unsafe.Pointer(&fsx[0]))) {
				*(*uint32)(unsafe.Pointer(&fsx[fsxattrXflagsOff])) |= fsXflagNodump
				report("fssetxattr", ioctlPtr(fd, fsIocFssetxattr, unsafe.Pointer(&fsx[0])))
			}
		}
		// file_setattr(dfd, path, attr, size, flags) with fa_xflags = NODUMP.
		var attr [fileAttrSize]byte
		*(*uint64)(unsafe.Pointer(&attr[fileAttrXflagsOff])) = fsXflagNodump
		pp, _ := unix.BytePtrFromString(p)
		_, _, e := unix.Syscall6(unix.SYS_FILE_SETATTR, uintptr(unix.AT_FDCWD&0xffffffff), uintptr(unsafe.Pointer(pp)),
			uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)), 0, 0)
		if e != 0 {
			report("file_setattr", e)
		} else {
			report("file_setattr", nil)
		}
	case "proc-state":
		pid, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad pid:", err)
			os.Exit(2)
		}
		// Each op changes ANOTHER process's scheduling state. On rung 2 the jail's
		// seccomp must refuse all three (EPERM); unjailed they succeed.
		lim := unix.Rlimit{Cur: 7, Max: 7}
		report("prlimit", unix.Prlimit(pid, unix.RLIMIT_NOFILE, &lim, nil))
		// Raise niceness (prio 19): increasing niceness is always permitted, so the
		// unjailed control cannot be defeated by a low RLIMIT_NICE on the host.
		report("setpriority", unix.Setpriority(unix.PRIO_PROCESS, pid, 19))
		var set unix.CPUSet
		set.Zero()
		set.Set(0)
		report("setaffinity", unix.SchedSetaffinity(pid, &set))
	default:
		fmt.Fprintln(os.Stderr, "unknown op:", os.Args[1])
		os.Exit(2)
	}
	switch {
	case failed == 0:
		os.Exit(0)
	case ok == 0:
		os.Exit(1)
	default:
		os.Exit(3)
	}
}
