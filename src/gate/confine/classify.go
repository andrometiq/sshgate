package confine

import (
	"strconv"
	"syscall"
)

// FailureClass is the class of a jail setup failure that never reached X. The
// zero value is Failed, so an unclassified failure denies.
type FailureClass int

const (
	// Failed: an unexplained or transient failure. Reads are denied.
	Failed FailureClass = iota
	// Absent: the host lacks the jail because of boot configuration, a
	// root-only sysctl or LSM policy. Nothing the agent controls produces it.
	Absent
)

func (c FailureClass) String() string {
	if c == Absent {
		return "absent"
	}
	return "failed"
}

// HostFacts is root-controlled host state, read after a setup failure to
// classify it. Nothing in it is agent-controlled.
type HostFacts struct {
	MaxUserNS           int  // /proc/sys/user/max_user_namespaces; -1 when unreadable
	AppArmorUsernsClamp bool // kernel.apparmor_restrict_unprivileged_userns == 1
	DevShmDir           bool // /dev/shm resolves to a directory
	SeccompFilter       bool // /proc/sys/kernel/seccomp/actions_avail exists
	LandlockABI         int  // the Landlock ABI; -1 when unavailable
	LandlockErrno       syscall.Errno
	LSMs                []string // /sys/kernel/security/lsm
}

// ClassifySetupFailure classifies a setup failure by its stage and errno. Only
// the rows in absentCondition are Absent; everything else, including every
// stage at or after X, is Failed.
func ClassifySetupFailure(stage string, errno syscall.Errno, facts HostFacts) FailureClass {
	if condition := absentCondition(stage, errno); condition != nil && condition(facts) {
		return Absent
	}
	return Failed
}

// AbsentCandidate reports whether (stage, errno) can be Absent on some host. It
// ignores host facts and only keeps the worker's diagnostic quiet; it never
// decides anything.
func AbsentCandidate(stage string, errno syscall.Errno) bool {
	return absentCondition(stage, errno) != nil
}

// absentCondition returns the host-fact condition under which (stage, errno)
// is Absent, or nil when it is always Failed.
//
// The clone errno is composite: it is whatever Cmd.Start returns, from the
// clone itself, the parent's uid/gid map writes, or the child's pre-exec steps
// up to the execve of /proc/self/exe.
//
// Two outcomes rest on other walls: with both the mount namespace and nsverify
// removed, MS_PRIVATE on the host namespace fails EPERM at "private"; and an
// unprivileged clone without CLONE_NEWUSER fails EPERM at "clone". Both read
// as Absent, so an unpinned host falls back to classifier-only. Each of those
// walls has its own legs.
func absentCondition(stage string, errno syscall.Errno) func(HostFacts) bool {
	always := func(HostFacts) bool { return true }
	switch stage {
	case "clone":
		switch errno {
		case syscall.EPERM, syscall.EINVAL: // user namespaces disabled or unsupported
			return always
		case syscall.ENOSPC: // a zero limit; a used-up count is transient
			return func(f HostFacts) bool { return f.MaxUserNS == 0 }
		case syscall.EACCES: // Ubuntu's AppArmor userns restriction
			return func(f HostFacts) bool { return f.AppArmorUsernsClamp }
		}
	case "private", "setattr", "devnodes", "scratch":
		switch {
		case errno == syscall.EPERM || errno == syscall.EACCES: // mount refused by an LSM
			return always
		case stage == "setattr" && errno == syscall.ENOSYS: // no mount_setattr
			return always
		case stage == "scratch" && errno == syscall.ENOENT: // no /dev/shm
			return func(f HostFacts) bool { return !f.DevShmDir }
		}
	case "landlock":
		if errno == syscall.ENOSYS || errno == syscall.EOPNOTSUPP {
			return always
		}
	case "seccomp":
		switch errno {
		case syscall.ENOSYS: // no CONFIG_SECCOMP
			return always
		case syscall.EINVAL:
			// No CONFIG_SECCOMP_FILTER, not a filter we got wrong. Kernels
			// before 4.14 lack actions_avail and SECCOMP_RET_KILL_PROCESS,
			// so ro-v1 is unavailable there and Absent is right.
			return func(f HostFacts) bool { return !f.SeccompFilter }
		}
	}
	return nil
}

// DenyReason is the audit deny_reason for a classified setup failure:
// "jail:<absent|failed>:<stage>[:<ERRNO>]".
func DenyReason(class FailureClass, stage string, errno syscall.Errno) string {
	reason := "jail:" + class.String() + ":" + stage
	if errno != 0 {
		reason += ":" + errnoName(errno)
	}
	return reason
}

func errnoName(errno syscall.Errno) string {
	if name := errnoSymbol(errno); name != "" {
		return name
	}
	return strconv.Itoa(int(errno))
}
