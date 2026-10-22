//go:build linux

package confine

import (
	"fmt"
	"unsafe"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// landlockFSBaseABI1 is every filesystem access right defined at Landlock ABI 1.
const landlockFSBaseABI1 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
	unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
	unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
	unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_MAKE_REG |
	unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
	unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_SYM

// handledFS is the full set of fs rights the ruleset governs at the given ABI.
// A right that is "handled" but not granted by any rule is denied.
func handledFS(abi int) uint64 {
	h := uint64(landlockFSBaseABI1)
	if abi >= 2 && !jailmut.On("P-LL-REFER") {
		h |= unix.LANDLOCK_ACCESS_FS_REFER // deny cross-dir link/rename implicitly
	}
	if abi >= 3 && !jailmut.On("P-LL-TRUNCATE") {
		h |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 && !jailmut.On("P-LL-IOCTL-DEV") {
		h |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	if abi >= 9 && !jailmut.On("P-LL-RESOLVE-UNIX") {
		h |= landlockAccessFSResolveUnix
	}
	return h
}

// readRights is what we allow beneath / so reads just work: open-for-read, list
// directories, execute. IOCTL_DEV (ABI ≥5) is handled but deliberately NOT
// granted here: a device opened read-only inside the jail (e.g. another
// session's pty) must not take state-changing ioctls. It is granted only on the
// writable set; fds inherited from before restrict_self (stdio) keep it.
func readRights() uint64 {
	return uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_EXECUTE)
}

// writeRights is what we allow beneath each writable path: everything the ABI
// handles EXCEPT REFER (no cross-directory link/rename out of the writable set).
func writeRights(abi int) uint64 {
	return handledFS(abi) &^ uint64(unix.LANDLOCK_ACCESS_FS_REFER|landlockAccessFSResolveUnix)
}

// landlockFileRights is the subset of access rights the kernel accepts on a
// non-directory inode. Granting directory-only rights (READ_DIR, REMOVE_*,
// MAKE_*, REFER) on a regular file or device makes LANDLOCK_ADD_RULE fail EINVAL,
// so a rule on /dev/null must be masked down to these.
const landlockFileRights = uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE |
	unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE |
	unix.LANDLOCK_ACCESS_FS_TRUNCATE |
	unix.LANDLOCK_ACCESS_FS_IOCTL_DEV | landlockAccessFSResolveUnix)

// probeLandlockABI preserves failures so only documented absence permits fallback.
func probeLandlockABI() (int, unix.Errno) {
	abi, _, errno := unix.Syscall(uintptr(unix.SYS_LANDLOCK_CREATE_RULESET),
		0, 0, uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION))
	if errno != 0 {
		return -1, errno
	}
	return int(abi), 0
}

// lane2FDs are a daemon read's admitted inodes, opened inside the jail's view:
// the client binary, its interpreter (-1 for a static client) and its sockets.
type lane2FDs struct {
	binary, interp int
	sockets        []int
}

// landlockRule grants rights beneath path, or, when fd >= 0, on the inode fd
// already names (a daemon read's checked object, never walked again).
type landlockRule struct {
	path     string
	fd       int
	rights   uint64
	optional bool // a missing path is skipped
}

// landlockPlan is the jail's Landlock rules: reads beneath /, writes beneath the
// writable set, and for a daemon read (lane2 != nil) EXECUTE only on its client
// and interpreter and, from ABI 9, Unix-socket connects only to its sockets.
// The daemon-read rules come last; a failure adding one is stage lane2id.
func landlockPlan(abi int, writable []string, lane2 *lane2FDs) []landlockRule {
	read, write := readRights(), writeRights(abi)
	if lane2 != nil {
		if !jailmut.On("P-L2-EXEC-NARROW") {
			read &^= unix.LANDLOCK_ACCESS_FS_EXECUTE
		}
		write &^= unix.LANDLOCK_ACCESS_FS_EXECUTE
		if abi >= 9 && jailmut.On("P-L2-SOCK-PIN") {
			read |= landlockAccessFSResolveUnix
		}
	}
	if jailmut.On("P-LL-FS") {
		read = handledFS(abi)
	}
	rules := []landlockRule{{path: "/", fd: -1, rights: read}}
	for _, path := range writable {
		rules = append(rules, landlockRule{path: path, fd: -1, rights: write, optional: true})
	}
	if lane2 == nil {
		return rules
	}
	execute := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE)
	rules = append(rules, landlockRule{fd: lane2.binary, rights: execute})
	if lane2.interp >= 0 {
		rules = append(rules, landlockRule{fd: lane2.interp, rights: execute})
	}
	if abi >= 9 {
		for _, socket := range lane2.sockets {
			rules = append(rules, landlockRule{fd: socket, rights: landlockAccessFSResolveUnix})
		}
	}
	return rules
}

// applyLandlock requires Landlock even when mounts provide another wall. The
// ruleset and its shared rules are stage landlock; a daemon read's own rules
// are stage lane2id, so they can never make the jail look Absent.
func applyLandlock(abi int, writable []string, lane2 *lane2FDs) error {
	if abi < 1 {
		if jailmut.On("P-LL-REQUIRED") {
			return nil
		}
		return unix.ENOSYS
	}

	attr := landlockRuleset(abi)
	rfd, _, errno := unix.Syscall(uintptr(unix.SYS_LANDLOCK_CREATE_RULESET),
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock create ruleset: %w", errno)
	}
	defer unix.Close(int(rfd))

	for _, rule := range landlockPlan(abi, writable, lane2) {
		if rule.fd >= 0 {
			if err := addLandlockRuleFD(rfd, rule.fd, rule.rights); err != nil {
				return &SetupError{Stage: "lane2id", Errno: errnoOf(err)}
			}
			continue
		}
		if err := addLandlockRule(rfd, rule.path, rule.rights, rule.optional); err != nil {
			return err
		}
	}

	if _, _, errno := unix.Syscall(uintptr(unix.SYS_LANDLOCK_RESTRICT_SELF), rfd, 0, 0); errno != 0 {
		return fmt.Errorf("landlock restrict self: %w", errno)
	}
	return nil
}

// addLandlockRuleFD grants file rights on the inode fd names.
func addLandlockRuleFD(rfd uintptr, fd int, rights uint64) error {
	pb := unix.LandlockPathBeneathAttr{Allowed_access: rights & landlockFileRights, Parent_fd: int32(fd)}
	_, _, errno := unix.Syscall6(uintptr(unix.SYS_LANDLOCK_ADD_RULE), rfd,
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(&pb)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// addLandlockRule grants rights beneath path. When skipMissing is set an absent
// path is ignored (optional writable targets); otherwise ENOENT is an error.
func addLandlockRule(rfd uintptr, path string, rights uint64, skipMissing bool) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if skipMissing && err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("landlock open %s: %w", path, err)
	}
	defer unix.Close(fd)
	// A non-directory inode accepts only file-applicable rights; granting
	// directory rights on it is an EINVAL from the kernel.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("landlock fstat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		rights &= landlockFileRights
	}
	pb := unix.LandlockPathBeneathAttr{Allowed_access: rights, Parent_fd: int32(fd)}
	_, _, errno := unix.Syscall6(uintptr(unix.SYS_LANDLOCK_ADD_RULE), rfd,
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH), uintptr(unsafe.Pointer(&pb)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock add rule %s: %w", path, errno)
	}
	return nil
}

func landlockRuleset(abi int) unix.LandlockRulesetAttr {
	attr := unix.LandlockRulesetAttr{Access_fs: handledFS(abi)}
	if abi >= 6 {
		if !jailmut.On("P-LL-SCOPE-SIGNAL") {
			attr.Scoped |= unix.LANDLOCK_SCOPE_SIGNAL
		}
		if !jailmut.On("P-LL-SCOPE-ABSTRACT") {
			attr.Scoped |= unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
		}
	}
	return attr
}
