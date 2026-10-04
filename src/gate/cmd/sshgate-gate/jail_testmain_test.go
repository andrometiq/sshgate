//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"golang.org/x/sys/unix"
)

// TestMain makes this test binary behave like the real gate where the read
// path re-execs it, and gives the run() tests a jail-visible temp dir.
//
//   - The jail (and its probe) re-exec /proc/self/exe — in a test build, THIS
//     binary — with confine's sentinels, so they are dispatched exactly as
//     main() does.
//   - Invoked under the name of a Lane-2 binary (via a symlink a test plants in
//     lane2BinDirs), it reports how it was exec'd instead of running tests.
//   - On a rung-1 host the jail mounts a private tmpfs over /tmp, so a fixture
//     under the host /tmp is invisible to a jailed read. TMPDIR is moved under
//     the user cache dir (read-only but visible inside the jail) so t.TempDir
//     fixtures stay readable by the jailed child, as the gate dir and the
//     operator's files are on a real host.
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
	switch filepath.Base(os.Args[0]) {
	case "systemctl", "docker":
		os.Exit(reportExec())
	}
	if os.Getenv("GORACE") == "" {
		_ = os.Setenv("GORACE", "atexit_sleep_ms=0")
	}
	base, err := os.UserCacheDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: user cache dir:", err)
		os.Exit(2)
	}
	tmp, err := os.MkdirTemp(base, "sshgate-gate-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: temp dir:", err)
		os.Exit(2)
	}
	_ = os.Setenv("TMPDIR", tmp)
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// execReport is what a fake Lane-2 binary prints about its own exec.
type execReport struct {
	Path       string   `json:"path"`
	Args       []string `json:"args"`
	Env        []string `json:"env"`
	StdinIsNul bool     `json:"stdin_is_devnull"`
}

// lane2PlantedSecret is printed by a fake Lane-2 binary asked about the
// container lane2SecretArg, so a test can watch Lane-2 output meet the redactor.
const (
	lane2SecretArg     = "planted-secret"
	lane2PlantedSecret = "AKIA1234567890ABCDEF"
)

func reportExec() int {
	if slices.Contains(os.Args, lane2SecretArg) {
		fmt.Println("env AWS_ACCESS_KEY_ID=" + lane2PlantedSecret)
		return 0
	}
	exe, _ := os.Readlink("/proc/self/exe")
	var st, nul unix.Stat_t
	stdinNul := unix.Fstat(0, &st) == nil && unix.Stat("/dev/null", &nul) == nil &&
		st.Rdev == nul.Rdev && st.Mode&unix.S_IFMT == unix.S_IFCHR
	_ = json.NewEncoder(os.Stdout).Encode(execReport{
		Path: exe, Args: os.Args, Env: os.Environ(), StdinIsNul: stdinNul,
	})
	return 0
}
