//go:build linux

package confine

import (
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

const cloneAllowed = 0xff | unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_PIDFD | unix.CLONE_PTRACE | unix.CLONE_VFORK | unix.CLONE_PARENT | unix.CLONE_THREAD | unix.CLONE_SYSVSEM | unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID | unix.CLONE_DETACHED | unix.CLONE_UNTRACED | unix.CLONE_CHILD_SETTID | unix.CLONE_IO
const unshareAllowed = unix.CLONE_FILES | unix.CLONE_FS | unix.CLONE_SYSVSEM

var fcntlAllowed = []uint32{0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 16, 36, 37, 38, 0x403, 0x404, 0x406, 0x408, 0x409, 0x40a, 0x40b, 0x40d}
var ioctlBlocks = []uint32{0x5412, 0x541c, 0xc0506617, 0xc0406618, 0xc0406619, 0x9408, 0x80089418, 0x40089416}

func buildArgumentFilters(a *bpfAsm, p filterParams) {
	buildProcessFilters(a, p)
	a.mark("filter:clone")
	if !jailmut.On("P-SC-CLONE-MASK") {
		a.ld(offArg0)
		a.jset(^uint32(cloneAllowed), "deny", "")
	}
	a.ja("allow")
	a.mark("filter:unshare")
	if !jailmut.On("P-SC-UNSHARE-MASK") {
		a.ld(offArg0 + 4)
		a.jeq(0, "", "deny")
		a.ld(offArg0)
		a.jset(^uint32(unshareAllowed), "deny", "")
	}
	a.ja("allow")
	a.mark("filter:fcntl")
	if jailmut.On("P-SC-FCNTL") {
		a.ja("allow")
	}
	a.ld(offArg1)
	a.jeq(8, "fcntl-owner", "")
	if jailmut.On("P-SC-ASYNC-OWNER") {
		a.jeq(15, "allow", "")
	}
	for _, command := range fcntlAllowed {
		a.jeq(command, "allow", "")
	}
	a.ja("deny")
	a.mark("fcntl-owner")
	if !jailmut.On("P-SC-ASYNC-OWNER") {
		a.ld(offArg2)
		a.jeq(0, "allow", "deny")
	}
	a.ja("allow")
	a.mark("filter:flock")
	if jailmut.On("P-SC-FLOCK") {
		a.ja("allow")
	}
	a.ld(offArg1)
	for _, op := range []uint32{1, 8, 5, 12} {
		a.jeq(op, "allow", "")
	}
	a.ja("deny")
	a.mark("filter:prlimit64")
	a.ld(offArg2)
	a.jeq(0, "", "rlimit-target")
	a.ld(offArg2 + 4)
	a.jeq(0, "allow", "")
	a.mark("rlimit-target")
	if !jailmut.On("P-SC-RETUNE") {
		a.ld(offArg0)
		a.jeq(0, "", "deny")
	}
	if jailmut.On("P-SC-RLIMIT-CORE") {
		a.ja("allow")
	}
	a.ld(offArg1)
	a.ja("rlimit-value")
	a.mark("filter:setrlimit")
	if jailmut.On("P-SC-RLIMIT-CORE") {
		a.ja("allow")
	}
	a.ld(offArg0)
	a.mark("rlimit-value")
	a.jgt(15, "deny", "")
	a.jeq(4, "deny", "allow")
	a.mark("filter:ioctl")
	a.ld(offArg1)
	if !jailmut.On("P-SC-ASYNC-OWNER") {
		for _, request := range []uint32{0x8901, 0x8902, 0x5410} {
			a.jeq(request, "deny", "")
		}
	}

	if !jailmut.On("P-SC-IOCTL-TIOCSTI") {
		a.jeq(0x5412, "deny", "")
	}
	if !jailmut.On("P-SC-IOCTL-TIOCLINUX") {
		a.jeq(0x541c, "deny", "")
	}
	if !jailmut.On("P-SC-IOCTL-FSCRYPT-ADD") {
		a.jeq(0xc0506617, "deny", "")
	}
	if !jailmut.On("P-SC-IOCTL-FSCRYPT-REMOVE") {
		a.jeq(0xc0406618, "deny", "")
	}
	if !jailmut.On("P-SC-IOCTL-FSCRYPT-REMOVE-ALL") {
		a.jeq(0xc0406619, "deny", "")
	}
	for _, req := range ioctlBlocks[5:] {
		a.jeq(req, "deny", "")
	}
	if !jailmut.On("P-SC-META") {
		for _, req := range fileattrIoctlDeny {
			a.jeq(req, "deny", "")
		}
	}
	a.ja("allow")
	a.mark("filter:socketpair")
	if jailmut.On("P-SC-SOCKPAIR") {
		a.ja("allow")
	}
	a.ld(offArg0)
	a.jeq(unix.AF_UNIX, "", "deny")
	a.ld(offArg1)
	a.and(0xf)
	a.jeq(unix.SOCK_STREAM, "allow", "")
	a.jeq(unix.SOCK_SEQPACKET, "allow", "deny")
	buildSocketFilter(a, p)
}

func buildSocketFilter(a *bpfAsm, p filterParams) {
	a.mark("filter:socket")
	a.ld(offArg0)
	a.jeq(unix.AF_NETLINK, "socket-netlink", "")
	a.jeq(unix.AF_INET, "socket-inet", "")
	a.jeq(unix.AF_INET6, "socket-inet6", "")
	if jailmut.On("P-SC-SOCK-FAM") {
		a.ja("allow")
	} else {
		a.ja("deny")
	}
	a.mark("socket-netlink")
	a.ld(offArg1)
	a.and(0xf)
	if !jailmut.On("P-SC-SOCK-TYPE") {
		a.jeq(unix.SOCK_RAW, "socket-netlink-proto", "")
		a.jeq(unix.SOCK_DGRAM, "", "deny")
	}
	a.mark("socket-netlink-proto")
	a.ld(offArg2)
	if !jailmut.On("P-SC-SOCKDIAG") {
		a.jeq(unix.NETLINK_SOCK_DIAG, "deny", "")
	} else {
		a.jeq(unix.NETLINK_SOCK_DIAG, "allow", "")
	}
	if jailmut.On("P-SC-NETLINK-PROTO") {
		a.ja("allow")
	} else {
		a.jeq(unix.NETLINK_ROUTE, "allow", "deny")
	}
	for _, item := range []struct {
		name string
		ping uint32
	}{{"socket-inet", unix.IPPROTO_ICMP}, {"socket-inet6", unix.IPPROTO_ICMPV6}} {
		a.mark(item.name)
		if !p.allowInet && !jailmut.On("P-SC-NET") {
			a.ja("deny")
		}
		a.ld(offArg1)
		a.and(0xf)
		a.jeq(unix.SOCK_STREAM, "socket-tcp", "")
		a.jeq(unix.SOCK_DGRAM, item.name+"-udp", "")
		if jailmut.On("P-SC-SOCK-TYPE") {
			a.ja("allow")
		} else {
			a.ja("deny")
		}
		a.mark(item.name + "-udp")
		a.ld(offArg2)
		if jailmut.On("P-SC-INET-PROTO") {
			a.ja("allow")
		}
		a.jeq(0, "allow", "")
		a.jeq(unix.IPPROTO_UDP, "allow", "")
		a.jeq(item.ping, "allow", "deny")
	}
	a.mark("socket-tcp")
	a.ld(offArg2)
	if jailmut.On("P-SC-INET-PROTO") {
		a.ja("allow")
	}
	a.jeq(0, "allow", "")
	a.jeq(unix.IPPROTO_TCP, "allow", "deny")
}

// Linux truncates pid_t, int and unsigned int arguments to 32 bits.
func buildProcessFilters(a *bpfAsm, p filterParams) {
	a.mark("filter:kill")
	if p.abi < 6 && !jailmut.On("P-SC-SIGNAL") {
		a.ld(offArg0)
		a.jeq(0, "allow", "")
		a.ld(offArg1)
		a.jeq(0, "allow", "deny")
	}
	a.ja("allow")
	for _, name := range []string{"tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_send_signal"} {
		a.mark("filter:" + name)
		if p.abi < 6 && !jailmut.On("P-SC-SIGNAL") {
			a.ja("deny")
		} else {
			a.ja("allow")
		}
	}
	for _, item := range []struct {
		name          string
		first, second uint32
	}{{"setpriority", 0, 1}, {"ioprio_set", 1, 2}} {
		a.mark("filter:" + item.name)
		if !jailmut.On("P-SC-RETUNE") {
			a.ld(offArg0)
			a.jeq(item.first, item.name+"-who", "")
			a.jeq(item.second, item.name+"-who", "deny")
			a.mark(item.name + "-who")
			a.ld(offArg1)
			a.jeq(0, "allow", "deny")
		}
		a.ja("allow")
	}
	for _, name := range []string{"sched_setparam", "sched_setscheduler", "sched_setattr", "sched_setaffinity", "migrate_pages", "move_pages"} {
		a.mark("filter:" + name)
		if !jailmut.On("P-SC-RETUNE") {
			a.ld(offArg0)
			a.jeq(0, "allow", "deny")
		}
		a.ja("allow")
	}
}
