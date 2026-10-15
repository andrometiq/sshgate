//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"golang.org/x/sys/unix"
)

// TestMain makes this test binary behave like the real gate where the read
// path re-execs it, and gives the run() tests a jail-visible temp dir.
//
//   - The jail re-execs /proc/self/exe — in a test build, THIS
//     binary — with confine's sentinels, so they are dispatched exactly as
//     main() does.
//   - Invoked under the name of a Lane-2 binary (via a symlink a test plants in
//     lane2BinDirs), it reports how it was exec'd instead of running tests.
//   - On a jail host the jail mounts a private tmpfs over /tmp, so a fixture
//     under the host /tmp is invisible to a jailed read. TMPDIR is moved under
//     the user cache dir (read-only but visible inside the jail) so t.TempDir
//     fixtures stay readable by the jailed child, as the gate dir and the
//     operator's files are on a real host.
//   - In-process reads record their seal instead of sealing (sealCalls) and
//     the verb records its environment reset (verbEnvResets); the test-only
//     __jailtest_capless sentinel runs the capless reader.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case confine.SentinelShim:
			os.Exit(confine.RunShim(os.Args[2:]))
		case confine.SentinelWorker:
			os.Exit(confine.RunWorker(os.Args[2:]))
		case sentinelCaplessReader:
			os.Exit(runCaplessReader(os.Args[2:]))
		}
	}
	switch filepath.Base(os.Args[0]) {
	case "systemctl", "docker":
		os.Exit(reportExec())
	}
	if config := os.Getenv(testGateEnv); config != "" {
		os.Exit(testGateMain(config))
	}
	// In-process reads record their seal: a sealed test binary would refuse
	// its next jail attempt. Subprocess gates keep the real seal.
	sealFn = func() error {
		sealCalls.Add(1)
		return nil
	}
	resetVerbEnv = func() { verbEnvResets.Add(1) }
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

// testGateEnv makes this binary act as the gate for one forced-command run,
// with this package's test seams set from the leg's config. It stands in for
// the gate binary where a leg needs the gate in its own process (a FUSE server
// must not be the gate's child: the gate reaps its children after a jailed
// run). The gate itself reads no policy from the environment.
const testGateEnv = "SSHGATE_TEST_GATE"

type testGateConfig struct {
	Dir, ABI string
	Grant    bool
	// NoSeal runs the jailed read without sealing the gate (a leg's twin).
	NoSeal bool
	// Repeat runs the read a second time in the same gate process, after the
	// first one sealed it; the exit code is the second read's.
	Repeat bool
}

// sealCalls counts the seals of in-process reads; verbEnvResets counts the
// SSHGATE_JAIL environment resets, which would clear the test binary's own.
var sealCalls, verbEnvResets atomic.Int32

func testGateMain(raw string) int {
	var config testGateConfig
	if json.Unmarshal([]byte(raw), &config) != nil || config.Dir == "" {
		fmt.Fprintln(os.Stderr, "TestMain: bad test gate config")
		return 2
	}
	gateDirFn = func() (string, string, error) { return config.Dir, filepath.Join(config.Dir, "gate"), nil }
	forceNetGrant = config.Grant
	if config.ABI == "abi1" {
		readSpecHook = func(spec *confine.Spec) { spec.ForceABI = 1 }
	}
	if config.NoSeal {
		sealFn = func() error { return nil }
	}
	if config.Repeat {
		if code := run(); code != exitOK {
			fmt.Fprintln(os.Stderr, "TestMain: first read exited", code)
			return 2
		}
	}
	return run()
}

// sentinelCaplessReader runs this binary as a same-uid process with no
// capabilities and no_new_privs: the shape of another of the user's processes
// outside the jail. It reads a gate's environ and writes into its stdout
// through /proc, and prints what happened as one JSON line.
const sentinelCaplessReader = "__jailtest_capless"

// caplessReport is what the capless reader prints. The errors are errno
// names, "0" on success.
type caplessReport struct {
	Caps       []string `json:"caps"`
	EnvironErr string   `json:"environ_err"`
	NonceFound bool     `json:"nonce_found"`
	FDWriteErr string   `json:"fd_write_err"`
}

// runCaplessReader takes the gate pid, the nonce to look for in its environ,
// and the marker to write into its fd 1.
func runCaplessReader(args []string) int {
	if len(args) != 3 {
		return 2
	}
	pid, nonce, marker := args[0], args[1], args[2]
	// Capabilities, no_new_privs and the bounding set are per thread.
	runtime.LockOSThread()
	if err := dropToCapless(); err != nil {
		fmt.Fprintln(os.Stderr, "capless reader:", err)
		return 2
	}
	report := caplessReport{}
	status, _ := os.ReadFile("/proc/thread-self/status")
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Cap") || strings.HasPrefix(line, "NoNewPrivs") {
			report.Caps = append(report.Caps, strings.Join(strings.Fields(line), " "))
		}
	}
	environ, err := os.ReadFile("/proc/" + pid + "/environ")
	report.EnvironErr, report.NonceFound = errnoName(err), bytes.Contains(environ, []byte(nonce))
	fd, err := unix.Open("/proc/"+pid+"/fd/1", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_, err = unix.Write(fd, []byte(marker+"\n"))
		_ = unix.Close(fd)
	}
	report.FDWriteErr = errnoName(err)
	if json.NewEncoder(os.Stdout).Encode(report) != nil {
		return 2
	}
	return 0
}

// dropToCapless sets no_new_privs, empties the bounding set (root), and
// clears the permitted, effective, inheritable and ambient sets.
func dropToCapless() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		for capability := 0; capability <= unix.CAP_LAST_CAP; capability++ {
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && err != unix.EINVAL {
				return err
			}
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	return unix.Capset(&header, &data[0])
}

func errnoName(err error) string {
	var errno syscall.Errno
	switch {
	case err == nil:
		return "0"
	case errors.As(err, &errno):
		return unix.ErrnoName(errno)
	}
	return err.Error()
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
