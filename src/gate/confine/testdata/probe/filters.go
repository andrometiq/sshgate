package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

func filterProbe(op string, args []string) bool {
	number := func(s string) uintptr {
		n, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			panic(err)
		}
		return uintptr(n)
	}
	switch op {
	case "keyring-add":
		_, err := unix.AddKey("user", args[1], []byte("changed"), int(number(args[0])))
		report("keyring", err)
	case "keyring-clear":
		_, err := unix.KeyctlInt(unix.KEYCTL_CLEAR, int(number(args[0])), 0, 0, 0)
		report("keyring", err)
	case "keyring-request":
		_, err := unix.RequestKey("user", args[1], "", int(number(args[0])))
		report("keyring", err)
	case "uring":
		uringProbe(args[0], int(number(args[1])))
	case "metadata-errno":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !report("open", err) {
			return true
		}
		defer unix.Close(fd)
		report("fchmod", unix.Fchmod(fd, 0644))
		report("chmod", unix.Chmod(args[0], 0644))
		report("chown", unix.Chown(args[0], os.Getuid(), os.Getgid()))
		// A minimal access ACL also works on tmpfs before user xattrs were supported.
		acl := make([]byte, 28)
		binary.LittleEndian.PutUint32(acl, 2)
		for i, entry := range []struct{ tag, permissions uint16 }{{1, 6}, {4, 4}, {32, 0}} {
			offset := 4 + 8*i
			binary.LittleEndian.PutUint16(acl[offset:], entry.tag)
			binary.LittleEndian.PutUint16(acl[offset+2:], entry.permissions)
			binary.LittleEndian.PutUint32(acl[offset+4:], ^uint32(0))
		}
		report("setxattr", unix.Setxattr(args[0], "system.posix_acl_access", acl, 0))
		report("utimensat", unix.UtimesNanoAt(unix.AT_FDCWD, args[0], []unix.Timespec{{Sec: 1}, {Sec: 1}}, 0))
	case "ioctl-scratch":
		file, err := os.CreateTemp("/dev/shm", "sshgate-ioctl-")
		if !report("open", err) {
			return true
		}
		defer file.Close()
		defer os.Remove(file.Name())
		var argument [80]byte
		_, _, e := unix.Syscall(unix.SYS_IOCTL, file.Fd(), number(args[0]), uintptr(unsafe.Pointer(&argument[0])))
		report("ioctl", errnoOrNil(e))
	case "tiocsti":
		character := byte('x')
		_, _, e := unix.Syscall(unix.SYS_IOCTL, 0, unix.TIOCSTI, uintptr(unsafe.Pointer(&character)))
		report("tiocsti", errnoOrNil(e))
	case "raw":
		var a [7]uintptr
		for i, s := range args {
			if i < len(a) {
				a[i] = number(s)
			}
		}
		_, _, e := unix.Syscall6(a[0], a[1], a[2], a[3], a[4], a[5], a[6])
		report("raw", errnoOrNil(e))
	case "pipesz":
		size, err := unix.FcntlInt(0, unix.F_SETPIPE_SZ, int(number(args[0])))
		report("pipesz", err)
		fmt.Printf("size=%d\n", size)
	case "rwhint", "flock-hold":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !report("open", err) {
			return true
		}
		defer unix.Close(fd)
		if op == "rwhint" {
			hint := uint64(4)
			_, _, e := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_SET_RW_HINT, uintptr(unsafe.Pointer(&hint)))
			report("rwhint", errnoOrNil(e))
		} else {
			report("flock", unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB))
			fmt.Println("READY")
			var b [1]byte
			_, _ = os.Stdin.Read(b[:])
		}
	case "rlimit-lock":
		var before unix.Rlimit
		report("getrlimit", unix.Getrlimit(unix.RLIMIT_CORE, &before))
		fmt.Printf("before=%d:%d\n", before.Cur, before.Max)
		zero := unix.Rlimit{Cur: 0, Max: before.Max}
		_, _, e := unix.Syscall(unix.SYS_SETRLIMIT, unix.RLIMIT_CORE, uintptr(unsafe.Pointer(&zero)), 0)
		report("setrlimit", errnoOrNil(e))
		_, _, e = unix.Syscall6(unix.SYS_PRLIMIT64, 0, unix.RLIMIT_CORE, uintptr(unsafe.Pointer(&zero)), 0, 0, 0)
		report("prlimit64", errnoOrNil(e))
		var after unix.Rlimit
		report("getrlimit-after", unix.Getrlimit(unix.RLIMIT_CORE, &after))
		fmt.Printf("after=%d:%d\n", after.Cur, after.Max)
	case "syncfs":
		fd, err := unix.Open(args[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !report("open", err) {
			return true
		}
		defer unix.Close(fd)
		report("syncfs", unix.Syncfs(fd))
	case "socket-sweep":
		grant := args[0] == "grant"
		protocols := []int{}
		for p := 0; p < 32; p++ {
			protocols = append(protocols, p)
		}
		protocols = append(protocols, 58, 115, 132, 136, 255, 256, 262)
		attempts, denied := 0, 0
		for domain := 0; domain < 64; domain++ {
			for kind := 1; kind <= 10; kind++ {
				for _, protocol := range protocols {
					allowed := domain == 16 && (kind == 2 || kind == 3) && protocol == 0
					if grant && (domain == 2 || domain == 10) {
						allowed = allowed || kind == 1 && (protocol == 0 || protocol == 6) || kind == 2 && (protocol == 0 || protocol == 17 || domain == 2 && protocol == 1 || domain == 10 && protocol == 58)
					}
					if allowed {
						continue
					}
					attempts++
					fd, err := unix.Socket(domain, kind, protocol)
					if err == unix.EPERM {
						denied++
					}
					if err == nil {
						unix.Close(fd)
					}
				}
			}
		}
		fmt.Printf("attempts=%d denied=%d\n", attempts, denied)
	case "sockdiag-request":
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, 4)
		if !report("socket", err) {
			return true
		}
		defer unix.Close(fd)
		request := make([]byte, 72)
		binary.LittleEndian.PutUint32(request, 72)
		binary.LittleEndian.PutUint16(request[4:], 20)
		binary.LittleEndian.PutUint16(request[6:], 0x301)
		binary.LittleEndian.PutUint32(request[8:], 1)
		request[16] = 10
		request[17] = 255
		binary.LittleEndian.PutUint32(request[20:], 0xffffffff)
		report("sockdiag", unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}))
	case "socket-tuple":
		fd, err := unix.Socket(int(number(args[0])), int(number(args[1])), int(number(args[2])))
		report("socket", err)
		if err == nil {
			unix.Close(fd)
		}
	case "socketpair-tuple":
		fds, err := unix.Socketpair(int(number(args[0])), int(number(args[1])), 0)
		report("socketpair", err)
		if err == nil {
			unix.Close(fds[0])
			unix.Close(fds[1])
		}
	case "dgram-send":
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
		if !report("socketpair", err) {
			return true
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		report("sendto", unix.Sendto(fds[0], []byte("canary"), 0, &unix.SockaddrUnix{Name: args[0]}))
	case "unix-connect":
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if !report("socket", err) {
			return true
		}
		defer unix.Close(fd)
		report("connect", unix.Connect(fd, &unix.SockaddrUnix{Name: args[0]}))
	case "listen":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if !report("socket", err) {
			return true
		}
		defer unix.Close(fd)
		report("listen", unix.Listen(fd, 1))
	case "setns":
		fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !report("open", err) {
			return true
		}
		defer unix.Close(fd)
		report("setns", unix.Setns(fd, 0))
	case "clone-ns":
		runtime.LockOSThread()
		pid, _, e := unix.RawSyscall6(unix.SYS_CLONE, number(args[0])|uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
		if e == 0 && pid == 0 {
			unix.RawSyscall(unix.SYS_EXIT, 0, 0, 0)
			for {
			}
		}
		report("clone", errnoOrNil(e))
		if e == 0 {
			var status unix.WaitStatus
			_, err := unix.Wait4(int(pid), &status, 0, nil)
			report("wait", err)
		}
	case "dial-inet6":
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		if !report("socket", err) {
			return true
		}
		defer unix.Close(fd)
		address := unix.SockaddrInet6{Port: int(number(args[0]))}
		address.Addr[15] = 1
		report("connect", unix.Connect(fd, &address))
	case "dial-inet":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if !report("socket", err) {
			return true
		}
		defer unix.Close(fd)
		report("connect", unix.Connect(fd, &unix.SockaddrInet4{Port: int(number(args[0])), Addr: [4]byte{127, 0, 0, 1}}))
	case "signal":
		report("kill", unix.Kill(int(number(args[0])), unix.SIGUSR1))
	case "scheduler", "scheduler-state":
		pid := int(number(args[0]))
		limit := unix.Rlimit{Cur: 7, Max: 7}
		var one unix.CPUSet
		if op == "scheduler" {
			report("prlimit", unix.Prlimit(pid, unix.RLIMIT_NOFILE, &limit, nil))
			report("nice", unix.Setpriority(unix.PRIO_PROCESS, pid, 19))
			_, _, e := unix.Syscall(unix.SYS_IOPRIO_SET, 1, uintptr(pid), 3<<13)
			report("ioprio", errnoOrNil(e))
			var priority int32
			_, _, e = unix.Syscall(unix.SYS_SCHED_SETSCHEDULER, uintptr(pid), 3, uintptr(unsafe.Pointer(&priority)))
			report("policy", errnoOrNil(e))
			var available unix.CPUSet
			err := unix.SchedGetaffinity(0, &available)
			if err != nil {
				panic(err)
			}
			for cpu := 0; cpu < 1024; cpu++ {
				if available.IsSet(cpu) {
					one.Set(cpu)
					break
				}
			}
			report("affinity", unix.SchedSetaffinity(pid, &one))
		}
		nice, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
		if err != nil {
			report("observe", err)
			return true
		}
		io, _, e := unix.Syscall(unix.SYS_IOPRIO_GET, 1, uintptr(pid), 0)
		if e != 0 {
			panic(e)
		}
		policy, _, e := unix.Syscall(unix.SYS_SCHED_GETSCHEDULER, uintptr(pid), 0, 0)
		if e != 0 {
			panic(e)
		}
		err = unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &limit)
		if err != nil {
			panic(err)
		}
		err = unix.SchedGetaffinity(pid, &one)
		if err != nil {
			panic(err)
		}
		// Idle-class priority data is ignored by the kernel.
		if io>>13 == 3 {
			io = 3 << 13
		}
		fmt.Printf("state=%d:%d:%d:%d:%d\n", 20-nice, io, policy, limit.Cur, one.Count())
	case "prio-user":
		report("prio-user", unix.Setpriority(unix.PRIO_USER, 0, 19))
	case "ioprio-user":
		_, _, e := unix.Syscall(unix.SYS_IOPRIO_SET, 3, 0, 3<<13)
		report("ioprio-user", errnoOrNil(e))
	case "crash":
		if args[0] == "lower" {
			var limit unix.Rlimit
			unix.Getrlimit(unix.RLIMIT_CORE, &limit)
			limit.Cur = 0
			report("lower", unix.Setrlimit(unix.RLIMIT_CORE, &limit))
		}
		fmt.Printf("pid=%d\n", os.Getpid())
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			panic(err)
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "NSpid:") {
				fmt.Printf("hostpid=%s\n", strings.Fields(line)[1])
			}
		}
		runtime.LockOSThread()
		// Restore the kernel default action; Go normally intercepts SIGSEGV.
		var action [4]uint64
		_, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGSEGV), uintptr(unsafe.Pointer(&action[0])), 0, 8, 0, 0)
		if e != 0 {
			panic(e)
		}
		unix.RawSyscall(unix.SYS_TGKILL, uintptr(os.Getpid()), uintptr(unix.Gettid()), uintptr(unix.SIGSEGV))
		panic("crash returned")
	default:
		return false
	}
	return true
}
