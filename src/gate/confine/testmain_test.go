//go:build linux

package confine

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// sentinelUsernsFullTest re-execs the test binary as usernsFullChild, and
// sentinelHoldTest as a process that just holds its user namespace open.
const (
	sentinelUsernsFullTest = "__jailtest_usernsfull"
	sentinelHoldTest       = "__jailtest_hold"
)

// TestMain dispatches the re-exec sentinels when the test binary is invoked as
// the jail shim/worker/probe (confine re-execs /proc/self/exe, which is this test
// binary during tests). Ordinary `go test` args (-test.*) never match a sentinel,
// so they fall through to the normal test run.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case SentinelShim:
			os.Exit(RunShim(os.Args[2:]))
		case SentinelWorker:
			args := os.Args[2:]
			if len(args) == 2 && strings.HasPrefix(args[1], "same-") {
				var spec Spec
				if json.Unmarshal([]byte(args[0]), &spec) != nil {
					os.Exit(99)
				}
				ids, err := namespaceIDs()
				if err != nil {
					os.Exit(99)
				}
				switch args[1] {
				case "same-user":
					spec.ParentNS.User = ids.User
				case "same-mnt":
					spec.ParentNS.Mnt = ids.Mnt
				case "same-pid":
					spec.ParentNS.Pid = ids.Pid + 1
				case "same-ipc":
					spec.ParentNS.IPC = ids.IPC
				}
				raw, _ := json.Marshal(spec)
				args = []string{string(raw)}
			}
			os.Exit(RunWorker(args))
		case SentinelProbe:
			os.Exit(RunProbe(os.Args[2:]))
		case sentinelUsernsFullTest:
			os.Exit(usernsFullChild())
		case sentinelHoldTest:
			_, _ = io.Copy(io.Discard, os.Stdin) // hold until the parent closes stdin
			os.Exit(0)
		}
	}
	// Under -race every re-exec'd hop that exits 0 would otherwise sleep 1s at
	// exit (the race runtime's atexit_sleep_ms default).
	if os.Getenv("GORACE") == "" {
		_ = os.Setenv("GORACE", "atexit_sleep_ms=0")
	}
	os.Exit(m.Run())
}
