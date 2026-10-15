package main

// The jailed selftest is the rehearsal's probe menu: a fixed list of actions
// against doctor-made fixtures, each reported by its errno name. It runs only
// as the command of a real jail attempt, never runs other code, and prints
// nothing but its rows. TestSelftestNeverExecs holds this file to its import
// and call allowlists.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// sentinelSelftest is the argv sentinel of the jailed selftest.
const sentinelSelftest = "__jailselftest"

// rehearsalRows are the selftest's rows, in order. tcp6-connect is optional.
var rehearsalRows = []string{
	"canary-write", "canary-trunc", "canary-chmod", "canary-utime", "canary-unlink",
	"dir-create", "dir-mkdir", "dir-symlink", "canary-rename", "canary-link",
	"fifo-write", "unix-connect", "abstract-connect", "tcp4-connect", "tcp6-connect",
	"pid-stop", "pid-ptrace", "pid-nice", "pid-environ", "pid-vmread",
	"tmp-write", "tmp-create", "shm-write",
}

// rowErrnos are the errnos each row may end with in the jail; "0" is success.
// The connect rows depend on the pin's network (tcpRowErrnos). Errnos that
// mean "the probe missed its target" (ENOENT, EBADF, EINVAL, ESRCH, ENOSYS,
// ENXIO, EXDEV) are never in a set.
var rowErrnos = map[string][]string{
	"canary-write": {"EROFS", "EACCES", "EPERM"}, "canary-trunc": {"EROFS", "EACCES", "EPERM"},
	"canary-chmod": {"EROFS", "EACCES", "EPERM"}, "canary-utime": {"EROFS", "EACCES", "EPERM"},
	"canary-unlink": {"EROFS", "EACCES", "EPERM"}, "dir-create": {"EROFS", "EACCES", "EPERM"},
	"dir-mkdir": {"EROFS", "EACCES", "EPERM"}, "dir-symlink": {"EROFS", "EACCES", "EPERM"},
	"canary-rename": {"EROFS", "EACCES", "EPERM"}, "canary-link": {"EROFS", "EACCES", "EPERM"},
	"fifo-write":   {"EACCES"},
	"unix-connect": {"EACCES", "EPERM"}, "abstract-connect": {"EPERM", "EACCES"},
	"pid-stop": {"EPERM"}, "pid-ptrace": {"EPERM"}, "pid-nice": {"EPERM"},
	"pid-environ": {"EACCES", "EPERM"}, "pid-vmread": {"EACCES", "EPERM"},
	"tmp-write": {"EROFS", "EACCES"}, "tmp-create": {"EROFS", "EACCES"},
	"shm-write": {"0"},
}

// tcpRowErrnos are the connect rows' errnos with and without network.
func tcpRowErrnos(net bool) []string {
	if net {
		return []string{"0"}
	}
	return []string{"EPERM", "EACCES"}
}

// selftestAllowed is the selftest's refusal: it runs only with the jailed
// command's credentials, in a user and a mount namespace other than the
// declared outer ones.
func selftestAllowed(status string, root bool, outer, own [2]uint64) bool {
	ok := confine.CheckJailedCredentials(status, root) == nil && outer[0] != 0 && outer[1] != 0 &&
		own[0] != outer[0] && own[1] != outer[1]
	return ok || jailmut.On("P-G-SELFTEST-JAILED")
}

// selftestFlags are the selftest's arguments, each given exactly once.
var selftestFlags = []string{"canary", "fifo", "unix", "abstract", "tcp4", "tcp6", "pid", "tmp", "shm", "nonce", "net"}

// runJailSelftest is the __jailselftest sentinel: 77 unless jailed, 65 on any
// argument error, otherwise one SELFTEST line per row, then SELFTEST-END with
// the number of rows probed, and 0.
func runJailSelftest(args []string) int {
	if len(args) == 0 {
		return exitNoPermVal
	}
	outerText, ok := strings.CutPrefix(args[0], "--outer-ns=")
	var outer [2]uint64
	if ok {
		outer = parseOuterNS(outerText)
	}
	status, err := os.ReadFile("/proc/thread-self/status")
	own, ownErr := ownNamespaces()
	if err != nil || ownErr != nil || !selftestAllowed(string(status), os.Geteuid() == 0, outer, own) {
		return exitNoPermVal
	}
	flags, ok := parseSelftestFlags(args[1:])
	if !ok {
		return exitDataErr
	}
	count := 0
	for _, row := range rehearsalRows {
		if row == "tcp6-connect" && flags["tcp6"] == "" {
			fmt.Println("SELFTEST tcp6-connect skipped")
			continue
		}
		fmt.Printf("SELFTEST %s errno=%s\n", row, selftestErrno(selftestProbe(row, flags)))
		count++
	}
	fmt.Printf("SELFTEST-END %d\n", count)
	return exitOK
}

// parseOuterNS reads "<user-ino>:<mnt-ino>"; zeros mean invalid.
func parseOuterNS(text string) [2]uint64 {
	user, mnt, ok := strings.Cut(text, ":")
	u, userErr := strconv.ParseUint(user, 10, 64)
	m, mntErr := strconv.ParseUint(mnt, 10, 64)
	if !ok || userErr != nil || mntErr != nil {
		return [2]uint64{}
	}
	return [2]uint64{u, m}
}

func ownNamespaces() ([2]uint64, error) {
	var ids [2]uint64
	for i, name := range []string{"user", "mnt"} {
		var stat unix.Stat_t
		if err := unix.Stat("/proc/self/ns/"+name, &stat); err != nil {
			return ids, err
		}
		ids[i] = stat.Ino
	}
	return ids, nil
}

// parseSelftestFlags is the closed grammar: each flag at most once, every one
// but tcp6 present, each value well formed.
func parseSelftestFlags(args []string) (map[string]string, bool) {
	flags := map[string]string{}
	for _, arg := range args {
		name, value, ok := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !ok || !strings.HasPrefix(arg, "--") || !containsString(selftestFlags, name) || flags[name] != "" || value == "" {
			return nil, false
		}
		flags[name] = value
	}
	for _, name := range selftestFlags {
		if name != "tcp6" && flags[name] == "" {
			return nil, false
		}
	}
	for _, name := range []string{"canary", "fifo", "unix", "tmp"} {
		if !strings.HasPrefix(flags[name], "/") {
			return nil, false
		}
	}
	pid, err := strconv.Atoi(flags["pid"])
	_, tcp4 := parseLoopback(flags["tcp4"])
	_, tcp6 := parseLoopback(flags["tcp6"])
	valid := err == nil && pid > 1 && tcp4 && (flags["tcp6"] == "" || tcp6) && len(flags["nonce"]) == 32 &&
		(flags["net"] == "allow" || flags["net"] == "deny") && !strings.ContainsAny(flags["shm"]+flags["abstract"], "/\x00")
	return flags, valid
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// parseLoopback reads "127.0.0.1:<port>" or "[::1]:<port>", the only
// addresses doctor listens on.
func parseLoopback(address string) (unix.Sockaddr, bool) {
	host, portText, ok := strings.Cut(address, "]:")
	if ok && host == "[::1" {
		port, err := strconv.Atoi(portText)
		return &unix.SockaddrInet6{Port: port, Addr: [16]byte{15: 1}}, err == nil && port > 0 && port < 65536
	}
	host, portText, ok = strings.Cut(address, ":")
	port, err := strconv.Atoi(portText)
	if !ok || host != "127.0.0.1" || err != nil || port <= 0 || port >= 65536 {
		return nil, false
	}
	return &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}, true
}

func selftestErrno(err error) string {
	if err == nil {
		return "0"
	}
	if errno, ok := err.(syscall.Errno); ok {
		return unix.ErrnoName(errno)
	}
	return "EIO"
}

// openWrite opens path with flag and writes one byte.
func openWrite(path string, flag int) error {
	fd, err := unix.Open(path, flag|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.Write(fd, []byte("X"))
	return err
}

// connectTo connects a new socket and, for TCP, sends the nonce.
func connectTo(family int, address unix.Sockaddr, nonce string) error {
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return err
	}
	deadline := now.Nano() + acceptBudget.Nanoseconds()
	if err := unix.Connect(fd, address); err != nil {
		// AF_UNIX backlog saturation is EAGAIN, not a pending connect.
		if err != unix.EINPROGRESS {
			return err
		}
		if err := waitWritable(fd, deadline); err != nil {
			return err
		}
		code, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if code != 0 {
			return syscall.Errno(code)
		}
	}
	if family != unix.AF_UNIX {
		payload := []byte(nonce)
		for len(payload) > 0 {
			if err := waitWritable(fd, deadline); err != nil {
				return err
			}
			n, err := unix.Write(fd, payload)
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return unix.EIO
			}
			payload = payload[n:]
		}
	}
	return nil
}

func waitWritable(fd int, deadline int64) error {
	for {
		var now unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
			return err
		}
		remaining := deadline - now.Nano()
		if remaining <= 0 {
			return unix.ETIMEDOUT
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(poll, int((remaining+999999)/1000000))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return unix.ETIMEDOUT
		}
		return nil
	}
}

// selftestProbe performs one row's action.
func selftestProbe(row string, flags map[string]string) error {
	canary := flags["canary"]
	dir := canary[:strings.LastIndexByte(canary, '/')+1]
	pid, _ := strconv.Atoi(flags["pid"])
	switch row {
	case "canary-write":
		return openWrite(canary, unix.O_WRONLY|unix.O_APPEND)
	case "canary-trunc":
		return unix.Truncate(canary, 0)
	case "canary-chmod":
		return unix.Chmod(canary, 0o600)
	case "canary-utime":
		return unix.UtimesNano(canary, nil)
	case "canary-unlink":
		return unix.Unlink(canary)
	case "dir-create":
		return openWrite(dir+"selftest-created", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	case "dir-mkdir":
		return unix.Mkdir(dir+"selftest-dir", 0o755)
	case "dir-symlink":
		return unix.Symlink("canary", dir+"selftest-symlink")
	case "canary-rename":
		return unix.Rename(canary, canary+".r")
	case "canary-link":
		return unix.Link(canary, canary+".l")
	case "fifo-write":
		return openWrite(flags["fifo"], unix.O_WRONLY|unix.O_NONBLOCK)
	case "unix-connect":
		return connectTo(unix.AF_UNIX, &unix.SockaddrUnix{Name: flags["unix"]}, "")
	case "abstract-connect":
		return connectTo(unix.AF_UNIX, &unix.SockaddrUnix{Name: "@" + flags["abstract"]}, "")
	case "tcp4-connect":
		address, _ := parseLoopback(flags["tcp4"])
		return connectTo(unix.AF_INET, address, flags["nonce"])
	case "tcp6-connect":
		address, _ := parseLoopback(flags["tcp6"])
		return connectTo(unix.AF_INET6, address, flags["nonce"])
	case "pid-stop":
		return unix.Kill(pid, unix.SIGSTOP)
	case "pid-ptrace":
		return unix.PtraceAttach(pid)
	case "pid-nice":
		return unix.Setpriority(unix.PRIO_PROCESS, pid, 5)
	case "pid-environ":
		fd, err := unix.Open("/proc/"+flags["pid"]+"/environ", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		_, err = unix.Read(fd, make([]byte, 64))
		return err
	case "pid-vmread":
		buffer := make([]byte, 64)
		local := []unix.Iovec{{Base: &buffer[0], Len: 64}}
		remote := []unix.RemoteIovec{{Base: 0x400000, Len: 64}}
		_, err := unix.ProcessVMReadv(pid, local, remote, 0)
		return err
	case "tmp-write":
		return openWrite(flags["tmp"], unix.O_WRONLY|unix.O_APPEND)
	case "tmp-create":
		return openWrite(flags["tmp"]+".sibling", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	case "shm-write":
		return openWrite("/dev/shm/"+flags["shm"], unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	}
	return syscall.EINVAL
}
