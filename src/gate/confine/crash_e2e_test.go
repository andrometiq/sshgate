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
	p := newProof(t, leg)
	patternBytes, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	mutationSetup(t, err)
	pattern := strings.TrimSpace(string(patternBytes))
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		if lower || strings.HasPrefix(pattern, "|") || strings.HasPrefix(pattern, "@") {
			p.Omit("core-pattern-uncontrolled")
		} else {
			p.Omit("ci-only")
		}
		return
	}
	controlled := os.Geteuid() == 0
	if lower && !controlled {
		p.Omit("root-only")
		return
	}
	if !controlled && (lower || strings.HasPrefix(pattern, "|") || strings.HasPrefix(pattern, "@")) {
		p.Omit("core-pattern-uncontrolled")
		return
	}
	var limit unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &limit))
	if limit.Max < 1 {
		t.Fatal("SETUP: inherited hard core limit is zero")
	}
	prlimit, err := exec.LookPath("prlimit")
	mutationSetup(t, err)
	probe := buildProbe(t)
	directory := filterFixture(t)
	observer := &m2CoreObserver{directory: directory, pattern: pattern}
	if controlled {
		observer.install(t)
	}
	p.ObserveWith("core", observer)
	crashControl := func() int {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, prlimit, "--core=unlimited:unlimited", "--", probe, "crash", "normal")
		command.Dir = directory
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		result := jailResult{exit: exitCodeOf(err), stdout: stdout.String(), stderr: stderr.String()}
		pid := requireCrashOutput(t, result, false)
		mutationSetup(t, m2CrashControlStatus(command.ProcessState, unix.SIGSEGV))
		observer.output = result.stdout
		return pid
	}
	mark := observer.Mark()
	controlPID := crashControl()
	observer.target = controlPID
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "worker-reaped"}))
	records := observer.Since(mark)
	p.Control("crash", ControlResult{Valid: records.Err == nil && records.Conclusive && len(records.Records) == 1, Detail: fmt.Sprint(records)})
	if !controlled {
		for _, path := range records.Records {
			mutationSetup(t, os.Remove(path))
		}
	}
	spec.Cwd = directory
	mode := "normal"
	if lower {
		mode = "lower"
	}
	mark = observer.Mark()
	result := runJailed(t, p, spec, RunPlan{Mode: ExpectedSignal, Signal: unix.SIGSEGV, Command: "exec " + proofShellQuote(probe) + " crash " + mode,
		Configure: func(jailed *Jailed) { mutationSetup(t, wrapCrashLimits(jailed.Cmd, prlimit)) },
		Validate: func(stdout, stderr string, exit int) error {
			return crashOutputError(jailResult{exit: exit, stdout: stdout, stderr: stderr}, lower)
		},
	})
	p.Jailed("crash", result)
	observer.target = crashPID(t, result.stdout)
	observer.output = result.stdout
	if controlled {
		targetOutput := observer.output
		observer.sentinel = crashControl()
		observer.output = targetOutput
	}
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "worker-reaped"}))
	records = observer.Since(mark)
	p.Observed("core", Observation{Valid: records.Err == nil, Conclusive: records.Conclusive, Sealed: records.Sealed, Detail: fmt.Sprint(records.Err)})
	mutationEffect(t, leg, "helper-record", len(records.Records) != 0)
	p.Finish()
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
