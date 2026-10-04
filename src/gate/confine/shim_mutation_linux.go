//go:build linux && jail_mutation

package confine

import (
	"os"
	"runtime"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
)

func init() {
	// Proc ptrace checks use the thread-group leader's credentials.
	if len(os.Args) > 1 && os.Args[1] == SentinelShim && jailmut.On("SHIM-NOCAPS") {
		runtime.LockOSThread()
	}
}
