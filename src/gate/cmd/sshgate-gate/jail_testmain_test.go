//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
		case sentinelSelftest:
			os.Exit(runJailSelftest(os.Args[2:]))
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
	// Fixtures (cc outputs, t.TempDir, gate dirs) take their modes from the
	// umask; admission rightly refuses group-writable ones, so a caller's 0002
	// (Ubuntu) must not decide results. Subprocess gates inherit it; product
	// umask handling has its own explicit tests (doctor "umask 0").
	syscall.Umask(0o022)
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
	// Rehearse runs the rehearsal of this candidate pin in Dir instead of a
	// read, with SelftestBinary as the selftest, and prints its result as
	// JSON. Unjailed runs the selftest outside the jail instead.
	Rehearse       *confine.Pin
	Unjailed       bool
	SelftestBinary string
	// Args runs these operator subcommand arguments (doctor) instead of a
	// read. FailRow makes the rehearsal report that row as failed.
	Args    []string
	FailRow string
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
		rehearsalSpecHook = readSpecHook
	}
	if config.NoSeal {
		sealFn = func() error { return nil }
	}
	if config.SelftestBinary != "" {
		selftestBinaryFn = func() (string, error) { return config.SelftestBinary, nil }
	}
	if config.FailRow != "" {
		rehearsalObserveHook = func(r *rehearsalResult) {
			for i := range r.Rows {
				if r.Rows[i].Name == config.FailRow {
					r.Rows[i].Pass = false
				}
			}
		}
	}
	if config.Rehearse != nil {
		return testRehearsalMain(config)
	}
	if len(config.Args) > 0 {
		return runLocalSubcommand(config.Args)
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
	Cwd        string   `json:"cwd"`
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
	cwd, _ := os.Getwd()
	var st, nul unix.Stat_t
	stdinNul := unix.Fstat(0, &st) == nil && unix.Stat("/dev/null", &nul) == nil &&
		st.Rdev == nul.Rdev && st.Mode&unix.S_IFMT == unix.S_IFCHR
	_ = json.NewEncoder(os.Stdout).Encode(execReport{
		Path: exe, Args: os.Args, Env: os.Environ(), Cwd: cwd, StdinIsNul: stdinNul,
	})
	return 0
}

// testRehearsal is what a Rehearse-mode test gate prints. Exit and Control are
// set by an unjailed run only.
type testRehearsal struct {
	rehearsalResult
	Exit    int  `json:"exit"`
	Control bool `json:"control"`
}

// testRehearsalMain builds the fixtures in a process that has made no jail
// attempt, runs the rehearsal (sealed, as doctor does) or the unjailed
// selftest, and prints the result.
func testRehearsalMain(config testGateConfig) int {
	fx, err := buildFixtures(config.Dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: fixtures:", err)
		return 2
	}
	var result testRehearsal
	if config.Unjailed {
		result = rehearseUnjailed(fx)
	} else {
		result.rehearsalResult = fx.rehearse(context.Background(), *config.Rehearse, sealRead)
	}
	if err := fx.teardown(); err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: teardown:", err)
		return 2
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 2
	}
	return 0
}

// rehearseUnjailed runs the selftest outside any jail, with this process's
// own namespaces as the declared outer ones, and makes the rehearsal's outside
// checks. Control is a direct append to a sibling of the canary.
func rehearseUnjailed(fx *fixtures) testRehearsal {
	var result testRehearsal
	if reason := fx.liveness(); reason != "" {
		result.Skipped = "could not run: " + reason
		return result
	}
	sibling := filepath.Join(fx.dir, "sibling")
	result.Control = os.WriteFile(sibling, []byte("before\n"), 0o644) == nil && appendText(sibling, "after\n") == nil
	if data, err := os.ReadFile(sibling); err != nil || string(data) != "before\nafter\n" {
		result.Control = false
	}
	before, err := fx.snapshot()
	binary, binaryErr := selftestBinaryFn()
	outer, outerErr := ownNamespaces()
	if err = errors.Join(err, binaryErr, outerErr); err != nil {
		result.Skipped = "could not run: " + err.Error()
		return result
	}
	command := exec.Command(binary, append([]string{sentinelSelftest}, fx.selftestArgs(outer, false)...)...)
	if err := command.Run(); command.ProcessState == nil {
		result.fail("selftest: %v", err)
	} else {
		result.Ran, result.Exit = true, command.ProcessState.ExitCode()
	}
	fx.observe(&result.rehearsalResult, before)
	return result
}

func appendText(path, text string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, err = file.WriteString(text)
	return errors.Join(err, file.Close())
}
