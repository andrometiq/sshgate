//go:build linux

package confine

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestPhase1Tables(t *testing.T) {
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("U-DevNodesLiteral", func(t *testing.T) {
				p := newProof(t, "U-DevNodesLiteral")
				TestDevNodesLiteral(t)
				p.Control("literal", ControlResult{Valid: !t.Failed(), Detail: "device literal comparison"})
				p.Finish()
			})
			t.Run("U-CloneUSER", func(t *testing.T) {
				p := newProof(t, "U-CloneUSER")
				decision := cloneSysProcAttr().Cloneflags&unix.CLONE_NEWUSER == 0
				mutationEffect(t, "U-CloneUSER", "decision", decision)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "direct decision evaluated against independent literal"})
				p.Finish()
			})
			t.Run("U-CloneMNT", func(t *testing.T) {
				p := newProof(t, "U-CloneMNT")
				decision := cloneSysProcAttr().Cloneflags&unix.CLONE_NEWNS == 0
				mutationEffect(t, "U-CloneMNT", "decision", decision)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "direct decision evaluated against independent literal"})
				p.Finish()
			})
			t.Run("U-Handled-IOCTL-DEV", func(t *testing.T) {
				p := newProof(t, "U-Handled-IOCTL-DEV")
				decision := handledFS(5)&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV == 0
				mutationEffect(t, "U-Handled-IOCTL-DEV", "decision", decision)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "direct decision evaluated against independent literal"})
				p.Finish()
			})
			t.Run("U-Handled-TRUNCATE", func(t *testing.T) {
				p := newProof(t, "U-Handled-TRUNCATE")
				decision := handledFS(3)&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0
				mutationEffect(t, "U-Handled-TRUNCATE", "decision", decision)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "direct decision evaluated against independent literal"})
				p.Finish()
			})
			t.Run("U-Handled-REFER", func(t *testing.T) {
				p := newProof(t, "U-Handled-REFER")
				decision := handledFS(2)&unix.LANDLOCK_ACCESS_FS_REFER == 0
				mutationEffect(t, "U-Handled-REFER", "decision", decision)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "direct decision evaluated against independent literal"})
				p.Finish()
			})
		})
	}
}
