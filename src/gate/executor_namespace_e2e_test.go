//go:build linux && jail_e2e

package gate

import "testing"

func TestExecWithRedactionConfineNSVerify(t *testing.T) {
	t.Run("native", func(t *testing.T) { t.Run("L-NSVERIFY", testExecutorNamespaceClobber) })
	t.Run("abi1", func(t *testing.T) { t.Run("L-NSVERIFY", testExecutorNamespaceClobber) })
}
