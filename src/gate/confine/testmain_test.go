//go:build linux

package confine

import (
	"os"
	"testing"
)

// sentinelROFallbackTest re-execs the test binary as roFallbackChild.
const sentinelROFallbackTest = "__jailtest_rofallback"

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
			os.Exit(RunWorker(os.Args[2:]))
		case SentinelProbe:
			os.Exit(RunProbe(os.Args[2:]))
		case sentinelROFallbackTest:
			os.Exit(roFallbackChild(os.Args[2:]))
		}
	}
	// Under -race every re-exec'd hop that exits 0 would otherwise sleep 1s at
	// exit (the race runtime's atexit_sleep_ms default).
	if os.Getenv("GORACE") == "" {
		_ = os.Setenv("GORACE", "atexit_sleep_ms=0")
	}
	os.Exit(m.Run())
}
