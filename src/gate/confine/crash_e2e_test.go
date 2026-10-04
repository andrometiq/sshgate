//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func legCrashNoHelper(t *testing.T, spec Spec) {
	legCrash(t, spec, false)
}

func legCrashLowerPipe(t *testing.T, spec Spec) {
	legCrash(t, spec, true)
}

func legCrash(t *testing.T, spec Spec, lower bool) {
	leg := "L-CRASH-NO-HELPER"
	if lower {
		leg = "L-CRASH-LOWER-PIPE"
	}
	var limit unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &limit))
	patternBytes, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	mutationSetup(t, err)
	pattern := strings.TrimSpace(string(patternBytes))
	isPipe := strings.HasPrefix(pattern, "|")
	if strings.HasPrefix(pattern, "@") || (lower && !isPipe) {
		t.Log("NOT-APPLICABLE: " + leg + " requires " + map[bool]string{true: "pipe", false: "file or pipe"}[lower] + " core_pattern")
		return
	}
	if limit.Max < 1 {
		if os.Getenv("SSHGATE_JAIL_CI") == "1" {
			t.Fatal("SETUP: inherited hard core limit is zero")
		}
		t.Log("NOT-APPLICABLE: " + leg + " inherited hard core limit is zero")
		return
	}
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Log("CONTROL-SKIPPED(ci-only): " + leg)
		return
	}
	if isPipe && !strings.Contains(pattern, "systemd-coredump") && !strings.Contains(pattern, "apport") {
		t.Fatalf("SETUP: no observer for pipe handler %q", pattern)
	}
	prlimit, err := exec.LookPath("prlimit")
	mutationSetup(t, err)
	probe := buildProbe(t)
	directory := filterFixture(t)
	coreGlob := ""
	if !isPipe {
		if filepath.IsAbs(pattern) || strings.Contains(pattern, "/") {
			t.Fatalf("SETUP: file core_pattern %q is outside the owned fixture; provision a filename-only pattern", pattern)
		}
		usesPID, err := os.ReadFile("/proc/sys/kernel/core_uses_pid")
		mutationSetup(t, err)
		if strings.TrimSpace(string(usesPID)) == "1" && !strings.Contains(pattern, "%p") {
			pattern += ".%p"
		}
		coreGlob = crashFileGlob(pattern, directory)
		if coreGlob == "" {
			t.Fatal("SETUP: empty file core_pattern")
		}
		existing, err := filepath.Glob(coreGlob)
		mutationSetup(t, err)
		if len(existing) != 0 {
			t.Fatalf("SETUP: file core_pattern observer requires an empty fixture destination: %q", coreGlob)
		}
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	control := exec.CommandContext(ctx, prlimit, "--core=unlimited:unlimited", "--", probe, "crash", "normal")
	control.Dir = directory
	var stdout, stderr bytes.Buffer
	control.Stdout, control.Stderr = &stdout, &stderr
	err = control.Run()
	hostpid := requireCrashOutput(t, jailResult{exit: exitCodeOf(err), stdout: stdout.String(), stderr: stderr.String()}, false)
	if !isPipe {
		coreGlob = crashPIDFileGlob(pattern, directory, stdout.String(), hostpid)
	}
	observe := func(pid int, since time.Time, timeout time.Duration) (bool, string) {
		if isPipe {
			return waitCoreRecord(t, pid, probe, pattern, since, timeout)
		}
		return waitFileCoreGlob(t, coreGlob, since, timeout), ""
	}
	found, report := observe(hostpid, started, 10*time.Second)
	if !found {
		t.Fatalf("SETUP: unlimited control crash %d was not recorded", hostpid)
	}
	if report != "" {
		mutationSetup(t, os.Remove(report))
		if present, _ := observe(hostpid, started, 0); present {
			t.Fatal("SETUP: apport fixture report reset failed")
		}
	}
	if !isPipe {
		paths, err := filepath.Glob(coreGlob)
		mutationSetup(t, err)
		for _, path := range paths {
			mutationSetup(t, os.Remove(path))
		}
	}

	spec.Cwd = directory
	started = time.Now()
	mode := "normal"
	if lower {
		mode = "lower"
	}
	result := runP12(t, spec, "exec "+probe+" crash "+mode, func(jailed *Jailed) {
		mutationSetup(t, wrapCrashLimits(jailed.Cmd, prlimit))
	})
	hostpid = requireCrashOutput(t, result, lower)
	if !isPipe {
		coreGlob = crashPIDFileGlob(pattern, directory, result.stdout, hostpid)
	}
	recorded, report := observe(hostpid, started, 5*time.Second)
	if !isPipe && recorded {
		paths, err := filepath.Glob(coreGlob)
		mutationSetup(t, err)
		t.Cleanup(func() {
			for _, path := range paths {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Errorf("core fixture cleanup: %v", err)
				}
			}
		})
	}
	if report != "" {
		t.Cleanup(func() {
			if err := os.Remove(report); err != nil && !os.IsNotExist(err) {
				t.Errorf("fixture report cleanup: %v", err)
			}
		})
	}
	mutationEffect(t, leg, "helper-record", recorded)
}

func wrapCrashLimits(command *exec.Cmd, prlimit string) error {
	executable := command.Path
	if executable == "/proc/self/exe" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return err
		}
	}
	// /proc/self/exe would name prlimit after the wrapper starts.
	arguments := append([]string{prlimit, "--core=unlimited:unlimited", "--", executable}, command.Args[1:]...)
	command.Path, command.Args = prlimit, arguments
	return nil
}

func requireCrashOutput(t *testing.T, result jailResult, lower bool) int {
	t.Helper()
	if err := crashOutputError(result, lower); err != nil {
		t.Fatalf("SETUP: %v", err)
	}
	return crashPID(t, result.stdout)
}

func crashOutputError(result jailResult, lower bool) error {
	if result.setupErr != nil || result.exit != 128+int(unix.SIGSEGV) || result.stderr != "" {
		return fmt.Errorf("crash must terminate with SIGSEGV and empty stderr: %+v", result)
	}
	lines := strings.Split(strings.TrimSpace(result.stdout), "\n")
	expected := 2
	if lower {
		expected++
	}
	if len(lines) != expected {
		return fmt.Errorf("incomplete crash report: %q", result.stdout)
	}
	if lower {
		if lines[0] != "lower=ok" && lines[0] != "lower=1" {
			return fmt.Errorf("unexpected lowering report: %q", lines[0])
		}
		lines = lines[1:]
	}
	for i, prefix := range []string{"pid=", "hostpid="} {
		value, err := strconv.Atoi(strings.TrimPrefix(lines[i], prefix))
		if !strings.HasPrefix(lines[i], prefix) || err != nil || value <= 0 {
			return fmt.Errorf("invalid crash report: %q", result.stdout)
		}
	}
	return nil
}

func waitFileCore(t *testing.T, directory string, since time.Time, timeout time.Duration) bool {
	t.Helper()
	return waitFileCoreGlob(t, filepath.Join(directory, "*"), since, timeout)
}

func crashPIDFileGlob(pattern, directory, output string, hostPID int) string {
	namespacePID := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "pid=") {
			namespacePID = strings.TrimPrefix(line, "pid=")
		}
	}
	pattern = strings.ReplaceAll(pattern, "%P", strconv.Itoa(hostPID))
	pattern = strings.ReplaceAll(pattern, "%p", namespacePID)
	return crashFileGlob(pattern, directory)
}

func crashFileGlob(pattern, directory string) string {
	if pattern == "" {
		return ""
	}
	var result strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '%' && i+1 < len(pattern) {
			i++
			if pattern[i] == '%' {
				result.WriteByte('%')
			} else {
				result.WriteByte('*')
			}
		} else {
			if strings.ContainsRune(`*?[\`, rune(pattern[i])) {
				result.WriteByte('\\')
			}
			result.WriteByte(pattern[i])
		}
	}
	path := result.String()
	if !filepath.IsAbs(path) {
		path = filepath.Join(directory, path)
	}
	return path
}

func waitFileCoreGlob(t *testing.T, pattern string, since time.Time, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		paths, err := filepath.Glob(pattern)
		mutationSetup(t, err)
		for _, path := range paths {
			info, err := os.Stat(path)
			mutationSetup(t, err)
			if info.Mode().IsRegular() && info.Size() > 0 && !info.ModTime().Before(since) {
				file, err := os.Open(path)
				mutationSetup(t, err)
				var header [18]byte
				n, readErr := file.Read(header[:])
				mutationSetup(t, file.Close())
				if readErr != nil && readErr != io.EOF {
					mutationSetup(t, readErr)
				}
				if readErr == nil && n == len(header) && bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) && header[16] == 4 && header[17] == 0 {
					return true
				}
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func crashPID(t *testing.T, output string) int {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "hostpid=") {
			pid, err := strconv.Atoi(strings.TrimPrefix(line, "hostpid="))
			mutationSetup(t, err)
			return pid
		}
	}
	t.Fatalf("SETUP: crash did not report host pid: %s", output)
	return 0
}
func waitCoreRecord(t *testing.T, pid int, executable, pattern string, since time.Time, timeout time.Duration) (bool, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(pattern, "systemd-coredump") {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			command := exec.CommandContext(ctx, "coredumpctl", "--no-pager", "--no-legend", "--since", since.UTC().Format("2006-01-02 15:04:05.000000 UTC"), "list", fmt.Sprintf("COREDUMP_PID=%d", pid), "COREDUMP_EXE="+executable)
			output, err := command.CombinedOutput()
			cancel()
			if err == nil && len(bytes.TrimSpace(output)) > 0 {
				return true, ""
			}
			if err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					t.Fatalf("SETUP: coredumpctl: %v", err)
				}
			}
		} else {
			paths, err := filepath.Glob("/var/crash/*.crash")
			mutationSetup(t, err)
			pidLine := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*Pid:\s*%d\s*$`, pid))
			for _, path := range paths {
				info, err := os.Stat(path)
				mutationSetup(t, err)
				if info.ModTime().Before(since) {
					continue
				}
				data, err := os.ReadFile(path)
				mutationSetup(t, err)
				if bytes.Contains(data, []byte("ExecutablePath: "+executable+"\n")) && pidLine.Match(data) {
					return true, path
				}
			}
		}
		if time.Now().After(deadline) {
			return false, ""
		}
		time.Sleep(100 * time.Millisecond)
	}
}
