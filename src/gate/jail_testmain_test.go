//go:build linux

package gate

import (
	"os"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// TestMain dispatches the confine re-exec sentinels. ExecWithRedaction with a
// Confine spec re-execs /proc/self/exe — which, in a test build, is THIS test
// binary — as the jail shim/worker/probe, so the binary must route those argv
// markers to confine exactly as the real gate's main does. Ordinary `go test`
// args (-test.*) match no sentinel and fall through to the normal run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case confine.SentinelShim:
			os.Exit(confine.RunShim(os.Args[2:]))
		case confine.SentinelWorker:
			os.Exit(confine.RunWorker(os.Args[2:]))
		case confine.SentinelProbe:
			os.Exit(confine.RunProbe(os.Args[2:]))
		}
	}
	// Under -race each re-exec'd hop that exits 0 would otherwise sleep 1s at
	// exit (the race runtime's atexit_sleep_ms default); zero it for the hops.
	if os.Getenv("GORACE") == "" {
		_ = os.Setenv("GORACE", "atexit_sleep_ms=0")
	}
	os.Exit(m.Run())
}
