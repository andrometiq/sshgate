//go:build linux

package confine

import (
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReadHostFacts reads the root-controlled host state a setup failure is
// classified by. It only reads; it never changes the host.
func ReadHostFacts() HostFacts {
	abi, errno := probeLandlockABI()
	shm, shmErr := os.Stat("/dev/shm") // mount(2) follows a symlink here
	_, seccompErr := os.Stat("/proc/sys/kernel/seccomp/actions_avail")
	return HostFacts{
		MaxUserNS:           readMaxUserns(),
		AppArmorUsernsClamp: readAppArmorUsernsClamp(),
		DevShmDir:           shmErr == nil && shm.IsDir(),
		SeccompFilter:       seccompErr == nil,
		LandlockABI:         abi,
		LandlockErrno:       errno,
		LSMs:                readLSMs(),
	}
}

func readMaxUserns() int {
	b, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return n
}

func readLSMs() []string {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), ",")
}

// readAppArmorUsernsClamp reports whether Ubuntu's AppArmor unprivileged-userns
// restriction is on (sysctl absent means no clamp).
func readAppArmorUsernsClamp() bool {
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func errnoSymbol(errno syscall.Errno) string { return unix.ErrnoName(errno) }
