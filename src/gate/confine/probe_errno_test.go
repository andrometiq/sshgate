//go:build linux

package confine

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWorkerLandlockProbeErrno(t *testing.T) {
	for _, errno := range []unix.Errno{unix.ENOSYS, unix.EOPNOTSUPP, unix.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			abi, got := workerLandlockABI(0, func() (int, unix.Errno) { return -1, errno })
			if abi >= 1 || !errors.Is(applyWorkerLandlock(abi, got), errno) {
				t.Fatalf("worker landlock abort: abi=%d errno=%v, want %v", abi, got, errno)
			}
		})
	}
	abi, errno := workerLandlockABI(ForceNoLandlock, func() (int, unix.Errno) { return 6, 0 })
	if abi != 0 || !errors.Is(applyWorkerLandlock(abi, errno), unix.ENOSYS) {
		t.Fatalf("forced absence: abi=%d errno=%v", abi, errno)
	}
}
