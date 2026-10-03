//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
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
	var limit unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &limit))
	pattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	mutationSetup(t, err)
	reason := ""
	if limit.Max < 1 {
		reason = "inherited hard core limit is zero"
	} else if !bytes.HasPrefix(pattern, []byte("|")) {
		reason = "core_pattern is not a pipe handler"
	}
	// Only a pipe handler can be re-enabled by lowering the locked limit to zero.
	if reason != "" {
		if os.Getenv("SSHGATE_JAIL_CI") == "1" {
			t.Fatalf("SETUP: L-CRASH-NO-HELPER %s", reason)
		}
		t.Log("NOT-APPLICABLE: L-CRASH-NO-HELPER " + reason)
		return
	}
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Log("CONTROL-SKIPPED(ci-only): L-CRASH-NO-HELPER")
		return
	}
	if !bytes.Contains(pattern, []byte("systemd-coredump")) && !bytes.Contains(pattern, []byte("apport")) {
		t.Fatalf("SETUP: no observer for for pipe handler %q", pattern)
	}
	probe := buildProbe(t)
	directory := filterFixture(t)
	started := time.Now()
	control := exec.Command("prlimit", "--core=0:", "--", probe, "crash", "normal")
	control.Dir = directory
	output, err := control.CombinedOutput()
	if err == nil {
		t.Fatalf("SETUP: crash control survived: %s", output)
	}
	hostpid := crashPID(t, string(output))
	found, report := waitCoreRecord(t, hostpid, probe, string(pattern), started, 10*time.Second)
	if !found {
		t.Fatalf("SETUP: control crash %d was not recorded: %s", hostpid, output)
	}
	if report != "" {
		// Apport suppresses a second unseen report for the same executable and uid.
		// Reset only this newly created, exact-executable/PID/time-matched fixture report.
		mutationSetup(t, os.Remove(report))
		if stillPresent, _ := waitCoreRecord(t, hostpid, probe, string(pattern), started, 0); stillPresent {
			t.Fatal("SETUP: apport fixture report reset failed")
		}
	}
	started = time.Now()
	result := runP12(t, spec, probe+" crash lower", nil)
	outputText := requireProbeOutput(t, result)
	hostpid = crashPID(t, outputText)
	recorded, report := waitCoreRecord(t, hostpid, probe, string(pattern), started, 5*time.Second)
	if report != "" {
		t.Cleanup(func() {
			if err := os.Remove(report); err != nil && !os.IsNotExist(err) {
				t.Errorf("fixture report cleanup: %v", err)
			}
		})
	}
	mutationEffect(t, "L-CRASH-NO-HELPER", "helper-record", recorded)
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
			command := exec.Command("coredumpctl", "--no-pager", "--no-legend", "--since", since.UTC().Format("2006-01-02 15:04:05.000000 UTC"), "list", fmt.Sprintf("COREDUMP_PID=%d", pid), "COREDUMP_EXE="+executable)
			output, err := command.CombinedOutput()
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
