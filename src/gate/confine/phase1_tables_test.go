//go:build linux

package confine

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestPhase1Tables(t *testing.T) {
	t.Run("U-DevNodesLiteral", TestDevNodesLiteral)
	t.Run("U-CloneUSER", func(t *testing.T) {
		mutationEffect(t, "U-CloneUSER", "decision", cloneSysProcAttr().Cloneflags&unix.CLONE_NEWUSER == 0)
	})
	t.Run("U-CloneMNT", func(t *testing.T) {
		mutationEffect(t, "U-CloneMNT", "decision", cloneSysProcAttr().Cloneflags&unix.CLONE_NEWNS == 0)
	})
	t.Run("U-Handled-IOCTL-DEV", func(t *testing.T) {
		mutationEffect(t, "U-Handled-IOCTL-DEV", "decision", handledFS(5)&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV == 0)
	})
	t.Run("U-Handled-TRUNCATE", func(t *testing.T) {
		mutationEffect(t, "U-Handled-TRUNCATE", "decision", handledFS(3)&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0)
	})
	t.Run("U-Handled-REFER", func(t *testing.T) {
		mutationEffect(t, "U-Handled-REFER", "decision", handledFS(2)&unix.LANDLOCK_ACCESS_FS_REFER == 0)
	})
}
