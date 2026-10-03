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
//	probe mq-create <name>                 mq_open(O_CREAT|O_EXCL) of a POSIX message queue
//	probe mq-unlink <name>                 mq_unlink of a POSIX message queue
package main

import (
	"fmt"
	"os"
	"os/exec"
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

func errnoOrNil(e unix.Errno) error {
	if e != 0 {
		return e
	}
	return nil
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
	case "tiocexcl":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if report("open", err) {
			_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCEXCL, 0)
			report("tiocexcl", errnoOrNil(e))
			unix.Close(fd)
		}
	case "device-write":
		fd, err := unix.Open(args[0], unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if report("open", err) {
			_, err = unix.Write(fd, []byte("x"))
			report("write", err)
			unix.Close(fd)
		}
	case "write-sweep":
		dir := args[0]
		for _, item := range []struct {
			name  string
			flags int
		}{{"write", unix.O_WRONLY}, {"append", unix.O_WRONLY | unix.O_APPEND}, {"open-trunc", unix.O_WRONLY | unix.O_TRUNC}, {"open-rdonly-trunc", unix.O_RDONLY | unix.O_TRUNC}} {
			fd, err := unix.Open(dir+"/file", item.flags|unix.O_CLOEXEC, 0)
			if err == nil {
				if item.flags&unix.O_WRONLY != 0 {
					_, err = unix.Write(fd, []byte("changed"))
				}
				unix.Close(fd)
			}
			report(item.name, err)
		}
		report("truncate-path", unix.Truncate(dir+"/file", 0))
		report("unlink", unix.Unlink(dir+"/remove"))
		report("rmdir", unix.Rmdir(dir+"/empty"))
		report("mkdir", unix.Mkdir(dir+"/made", 0700))
		report("symlink", unix.Symlink("file", dir+"/symlink"))
		report("link", unix.Link(dir+"/file", dir+"/link"))
		report("rename", unix.Rename(dir+"/move", dir+"/moved"))
		report("mkfifo", unix.Mkfifo(dir+"/fifo", 0600))
	case "core-limit":
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
			report("getrlimit", err)
		} else {
			fmt.Printf("core=%d:%d\n", limit.Cur, limit.Max)
		}
	case "mq-errno":
		name, _ := unix.BytePtrFromString(args[0])
		fd, _, e := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(name)), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0, 0, 0, 0)
		report("mq_open", errnoOrNil(e))
		if e == 0 {
			unix.Close(int(fd))
		}
		buffer := make([]byte, 8192)
		_, _, e = unix.Syscall6(unix.SYS_MQ_TIMEDRECEIVE, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0, 0)
		report("mq_timedreceive", errnoOrNil(e))
	case "mq-drain":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if report("open", err) {
			buffer := make([]byte, 8192)
			_, _, e := unix.Syscall6(unix.SYS_MQ_TIMEDRECEIVE, uintptr(fd), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0, 0)
			report("mq_timedreceive", errnoOrNil(e))
			unix.Close(fd)
		}
	case "metadata":
		p := args[0]
		report("chmod", unix.Chmod(p, 0644))
		report("chown", unix.Chown(p, os.Getuid(), os.Getgid()))
		report("setxattr", unix.Setxattr(p, "user.sshgate", []byte("test"), 0))
		report("utimensat", unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{{Sec: 1000}, {Sec: 1000}}, 0))
		var stat unix.Stat_t
		if unix.Stat(p, &stat) == nil {
			fmt.Printf("mode=%o\nmtime=%d\n", stat.Mode&0777, stat.Mtim.Sec)
		}
		value := make([]byte, 16)
		if n, err := unix.Getxattr(p, "user.sshgate", value); err == nil {
			fmt.Printf("xattr=%s\n", value[:n])
		}

	case "fileattr":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !report("open", err) {
			os.Exit(2)
		}
		defer unix.Close(fd)
		flags := uint32(fsNodumpFl)
		report("setflags", ioctlPtr(fd, unix.FS_IOC_SETFLAGS, unsafe.Pointer(&flags)))
		report("setflags32", ioctlPtr(fd, 0x40046602, unsafe.Pointer(&flags)))
		var fsx [fsxattrSize]byte
		*(*uint32)(unsafe.Pointer(&fsx[0])) = fsXflagNodump
		report("fssetxattr", ioctlPtr(fd, fsIocFssetxattr, unsafe.Pointer(&fsx[0])))
	case "root-state":
		for _, name := range []string{"uid_map", "gid_map", "status"} {
			data, err := os.ReadFile("/proc/self/" + name)
			if report(name, err) {
				fmt.Printf("%s:\n%s", name, data)
			}
		}
		_, _, errno := unix.Syscall(unix.SYS_OPEN_BY_HANDLE_AT, ^uintptr(0), 0, 0)
		fmt.Printf("open_by_handle_at=%d\n", errno)
	case "root-nproc":
		if os.Getuid() != 0 {
			fmt.Fprintln(os.Stderr, "root required")
			os.Exit(2)
		}
		var limit unix.Rlimit
		if report("getrlimit", unix.Getrlimit(unix.RLIMIT_NPROC, &limit)) {
			fmt.Printf("nproc=%d:%d\n", limit.Cur, limit.Max)
		}
		if report("setrlimit", unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 0, Max: 0})) {
			report("fork-root", exec.Command("/bin/true").Run())
		}

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
		// PID-addressed calls are contained by the jail PID namespace.
		lim := unix.Rlimit{Cur: 7, Max: 7}
		report("prlimit", unix.Prlimit(pid, unix.RLIMIT_NOFILE, &lim, nil))
		// Raise niceness (prio 19): increasing niceness is always permitted, so the
		// unjailed control cannot be defeated by a low RLIMIT_NICE on the host.
		report("setpriority", unix.Setpriority(unix.PRIO_PROCESS, pid, 19))
		var set unix.CPUSet
		set.Zero()
		var available unix.CPUSet
		if err := unix.SchedGetaffinity(0, &available); err != nil {
			panic(err)
		}
		for cpu := 0; cpu < 1024; cpu++ {
			if available.IsSet(cpu) {
				set.Set(cpu)
				break
			}
		}
		report("setaffinity", unix.SchedSetaffinity(pid, &set))
	case "mq-create", "mq-unlink":
		// Raw syscalls take the queue name without libc's leading slash.
		name, err := unix.BytePtrFromString(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad name:", err)
			os.Exit(2)
		}
		if os.Args[1] == "mq-unlink" {
			_, _, e := unix.Syscall(unix.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(name)), 0, 0)
			report("mq_unlink", errnoOrNil(e))
			break
		}
		fd, _, e := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(name)),
			uintptr(unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC), 0o600, 0, 0, 0)
		if report("mq_open", errnoOrNil(e)) {
			_ = unix.Close(int(fd))
		}
	default:
		if filterProbe(os.Args[1], args) {
			break
		}
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
