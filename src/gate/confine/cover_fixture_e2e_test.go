//go:build linux && jail_e2e

package confine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const coverNamespaceEnv = "SSHGATE_COVER_NAMESPACE"

func coverNamespace(t *testing.T, nonroot bool) bool {
	t.Helper()
	if os.Getenv(coverNamespaceEnv) == t.Name() {
		mutationSetup(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
		return true
	}
	needsFuse := !strings.HasSuffix(t.Name(), "/L-SHIM-PROC") && !strings.HasSuffix(t.Name(), "/L-COVER-LOOP") && !strings.HasSuffix(t.Name(), "/L-COVER-UNKNOWN")
	if needsFuse {
		if _, err := os.Stat("/dev/fuse"); err != nil {
			coverUnavailable(t, err)
			return false
		}
		if _, err := exec.LookPath("fusermount3"); err != nil {
			coverUnavailable(t, err)
			return false
		}
	}
	directory, err := os.MkdirTemp("/tmp", "sshgate-cover-tools-")
	mutationSetup(t, err)
	mutationSetup(t, os.Chmod(directory, 0755))
	t.Cleanup(func() { os.RemoveAll(directory) })
	probe := filepath.Join(directory, "probe")
	server := filepath.Join(directory, "fuseioctl")
	for _, item := range []struct{ output, source string }{{probe, "./testdata/probe"}, {server, "./testdata/fuseioctl"}} {
		command := exec.Command("go", "build", "-o", item.output, item.source)
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("SETUP: helper build: %v\n%s", err, output)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	testBinary := os.Args[0]
	if nonroot && os.Getuid() == 0 {
		data, err := os.ReadFile(testBinary)
		mutationSetup(t, err)
		testBinary = filepath.Join(directory, "test")
		mutationSetup(t, os.WriteFile(testBinary, data, 0755))
	}
	command := exec.CommandContext(ctx, testBinary, "-test.run=^"+strings.ReplaceAll(regexp.QuoteMeta(t.Name()), "/", "$/^")+"$", "-test.v")
	command.Env = append(os.Environ(), coverNamespaceEnv+"="+t.Name(), "SSHGATE_COVER_PROBE="+probe, "SSHGATE_COVER_SERVER="+server)
	uid, gid := os.Getuid(), os.Getgid()
	mappedUID, mappedGID := uid, gid
	if nonroot && uid == 0 {
		mappedUID, mappedGID = 1000, 1000
	}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: mappedUID, HostID: uid, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: mappedGID, HostID: gid, Size: 1}}, AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP}, Pdeathsig: syscall.SIGKILL}
	if uid == 0 && !nonroot {
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	}
	if mappedUID != uid {
		const fullRange = 4294967295
		command.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: fullRange}}
		command.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: fullRange}}
		command.SysProcAttr.AmbientCaps = append(command.SysProcAttr.AmbientCaps, unix.CAP_CHOWN, unix.CAP_FOWNER, unix.CAP_SETUID, unix.CAP_SETGID)
		command.Env = append(command.Env, "SSHGATE_COVER_ROOT_RUN=1")
		command.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(mappedUID), Gid: uint32(mappedGID), NoSetGroups: true}
	}
	output, err := command.CombinedOutput()
	fmt.Print(string(output))
	propagateFixtureFailure(t, output, err)
	return false
}
func coverUnavailable(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("SSHGATE_JAIL_CI") == "1" {
		t.Fatalf("SETUP: FUSE unavailable: %v", err)
	}
	t.Logf("NOT-APPLICABLE: FUSE unavailable: %v", err)
}
func coverProbe() string             { return os.Getenv("SSHGATE_COVER_PROBE") }
func coverQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func coverCommand(operation, path string) string {
	return coverProbeCommand(operation, path)
}
func coverSetter(path string) string {
	return coverProbeCommand("fuse-ioctl", path, "0x40085301", "42")
}

// Frame each probe separately: a later shell command must not hide its failure.
func coverProbeCommand(operation string, arguments ...string) string {
	command := coverQuote(coverProbe()) + " " + operation
	for _, argument := range arguments {
		command += " " + coverQuote(argument)
	}
	return "{ printf 'COVER-BEGIN " + operation + "\\n'; " + command + "; printf 'COVER-END %s\\n' \"$?\"; }"
}

func validateCoverReports(result jailResult, count int) (string, error) {
	if result.setupErr != nil || result.exit != 0 || result.stderr != "" || (result.stdout != "" && !strings.HasSuffix(result.stdout, "\n")) {
		return "", fmt.Errorf("abnormal cover command completion")
	}
	var output strings.Builder
	lines := strings.SplitAfter(result.stdout, "\n")
	seen := 0
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		if !strings.HasPrefix(line, "COVER-BEGIN ") {
			if strings.HasPrefix(line, "COVER-END ") {
				return "", fmt.Errorf("orphan probe completion")
			}
			output.WriteString(line)
			continue
		}
		operation := strings.TrimSuffix(strings.TrimPrefix(line, "COVER-BEGIN "), "\n")
		expected := map[string][]string{
			"fuse-ioctl":  {"open", "open>ioctl"},
			"read":        {"open", "open>read", "read>bytes"},
			"mntid":       {"statx", "statx>bytes"},
			"sync":        {"sync"},
			"jail-proc":   {"target", "open", "open>read", "read>bytes"},
			"cover-write": {"open", "open>write"},
		}[operation]
		if expected == nil {
			return "", fmt.Errorf("undeclared cover probe %q", operation)
		}
		var report strings.Builder
		index++
		for index < len(lines) && !strings.HasPrefix(lines[index], "COVER-END ") {
			report.WriteString(lines[index])
			index++
		}
		if index >= len(lines) {
			return "", fmt.Errorf("missing probe completion")
		}
		status, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(lines[index], "COVER-END "), "\n"))
		if err != nil {
			return "", fmt.Errorf("malformed probe completion")
		}
		validation := report.String()
		if operation == "mntid" {
			validation = strings.ReplaceAll(validation, "mntid=", "bytes=")
		}
		if err := validateProbeOutput(jailResult{stdout: validation, exit: status}, expected, probeExitAnyFailure); err != nil {
			return "", fmt.Errorf("%s: %w", operation, err)
		}
		output.WriteString(report.String())
		seen++
	}
	if seen != count {
		return "", fmt.Errorf("got %d probes, want %d", seen, count)
	}
	return output.String(), nil
}

type fuseFixture struct {
	point, log string
	command    *exec.Cmd
}

func startCoverFuse(t *testing.T, point string, flags ...string) *fuseFixture {
	t.Helper()
	mutationSetup(t, os.MkdirAll(point, 0755))
	log := filepath.Join(t.TempDir(), "requests")
	arguments := []string{"--mount", point, "--log", log}
	arguments = append(arguments, flags...)
	command := exec.Command(os.Getenv("SSHGATE_COVER_SERVER"), arguments...)
	var diagnostic coverLogBuffer
	command.Stderr = &diagnostic
	stdout, err := command.StdoutPipe()
	mutationSetup(t, err)
	mutationSetup(t, command.Start())
	t.Cleanup(func() {
		command.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			command.Process.Kill()
			<-done
		}
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "READY") {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatalf("SETUP: FUSE start: %s", diagnostic.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SETUP: FUSE readiness timeout")
	}
	return &fuseFixture{point: point, log: log, command: command}
}
func (f *fuseFixture) mark(t *testing.T) int64 {
	t.Helper()
	state, err := os.Stat(f.log)
	mutationSetup(t, err)
	return state.Size()
}
func (f *fuseFixture) since(t *testing.T, offset int64) string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	mutationSetup(t, err)
	if offset > int64(len(data)) {
		t.Fatal("SETUP: FUSE log shrank")
	}
	return string(data[offset:])
}
func (f *fuseFixture) control(t *testing.T) {
	t.Helper()
	mark := f.mark(t)
	out, err := exec.Command(coverProbe(), "fuse-ioctl", f.point+"/f", "0x40085301", "42").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ioctl=ok") || !strings.Contains(f.since(t, mark), "IOCTL") {
		t.Fatalf("SETUP: FUSE ioctl control: %v %s", err, out)
	}
	f.waitRelease(t, mark)
}

func (f *fuseFixture) waitRelease(t *testing.T, mark int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(f.since(t, mark), "RELEASE\n") {
		if time.Now().After(deadline) {
			t.Fatal("SETUP: FUSE control release not observed")
		}
		time.Sleep(time.Millisecond)
	}

}

func coverResult(t *testing.T, spec Spec, command string, afterX func()) (result jailResult, facts Facts) {
	defer func() {
		// L-SHIM-PROC validates its raw report after its explicit no-Landlock facts exception.
		if result.setupErr != nil || (strings.Contains(command, coverQuote(coverProbe())+" jail-proc") && !strings.Contains(command, "COVER-BEGIN ")) {
			return
		}
		// A reset cwd legitimately adds the worker's one fixed note.
		const cwdNote = "gate: note: the working directory is not visible in the read view; the read ran from /\n"
		if facts.CwdReset {
			validated := result
			validated.stderr = strings.Replace(result.stderr, cwdNote, "", 1)
			output, err := validateCoverReports(validated, strings.Count(command, "COVER-BEGIN "))
			if err != nil {
				t.Fatalf("SETUP: cover probe: %v: %+v", err, result)
			}
			result.stdout = output
			return
		}
		output, err := validateCoverReports(result, strings.Count(command, "COVER-BEGIN "))
		if err != nil {
			t.Fatalf("SETUP: cover probe: %v: %+v", err, result)
		}
		result.stdout = output
	}()
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	jailed, err := spec.Command(ctx, command)
	mutationSetup(t, err)
	defer jailed.Abort()
	var out, diagnostic bytes.Buffer
	var input *os.File
	if afterX != nil {
		reader, writer, err := os.Pipe()
		mutationSetup(t, err)
		defer reader.Close()
		defer writer.Close()
		input = writer
		jailed.Cmd.Stdin = reader
		ready := make(chan bool, 1)
		handshake := &coverHandshake{ready: ready}
		jailed.Cmd.Stdout = handshake
		jailed.Cmd.Stderr = &diagnostic
		mutationSetup(t, jailed.Cmd.Start())
		_ = jailed.Started()
		done := make(chan error, 1)
		go func() { done <- jailed.Cmd.Wait() }()
		select {
		case <-ready:
			afterX()
			_, err = input.WriteString("go\n")
			mutationSetup(t, err)
			err = <-done
		case err = <-done:
		case <-ctx.Done():
			t.Fatal("SETUP: post-X handshake timeout")
		}
		facts, statusErr := jailed.Status()
		return jailResult{exit: exitCodeOf(err), stdout: strings.TrimPrefix(handshake.output.String(), "POST_X\n"), stderr: diagnostic.String(), setupErr: statusErr}, facts
	} else {
		jailed.Cmd.Stdout = &out
		jailed.Cmd.Stderr = &diagnostic
		mutationSetup(t, jailed.Cmd.Start())
		_ = jailed.Started()
	}
	err = jailed.Cmd.Wait()
	facts, statusErr := jailed.Status()
	return jailResult{exit: exitCodeOf(err), stdout: out.String(), stderr: diagnostic.String(), setupErr: statusErr}, facts
}
func coverRan(t *testing.T, result jailResult) {
	t.Helper()
	if result.setupErr != nil {
		t.Fatalf("SETUP: jail failed: %+v", result)
	}
}
func coverAbort(t *testing.T, leg string, result jailResult) bool {
	t.Helper()
	if result.setupErr == nil {
		return false
	}
	var setup *SetupError
	if !errors.As(result.setupErr, &setup) || setup.Stage != "selfcheck" || result.stdout != "" {
		t.Fatalf("SETUP: expected selfcheck before X: %+v", result)
	}
	t.Logf("selfcheck abort: %v", result.setupErr)
	mutationAbort(t, leg, "selfcheck", true)
	return true
}

type coverHandshake struct {
	output   bytes.Buffer
	ready    chan bool
	notified bool
}

func (w *coverHandshake) Write(data []byte) (int, error) {
	n, err := w.output.Write(data)
	if !w.notified && strings.HasPrefix(w.output.String(), "POST_X\n") {
		w.notified = true
		w.ready <- true
	}
	return n, err
}

type coverLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *coverLogBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(data)
}
func (b *coverLogBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

func coverControlAfterX(t *testing.T, command string, after func()) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "/bin/sh", "-c", "echo POST_X; read release; "+command)
	ready := make(chan bool, 1)
	output := &coverHandshake{ready: ready}
	child.Stdout = output
	var diagnostic bytes.Buffer
	child.Stderr = &diagnostic
	input, err := child.StdinPipe()
	mutationSetup(t, err)
	defer input.Close()
	mutationSetup(t, child.Start())
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-ready:
		after()
		_, err = input.Write([]byte("go\n"))
		mutationSetup(t, err)
		err = <-done
	case err = <-done:
	case <-ctx.Done():
		t.Fatal("SETUP: unjailed handshake timeout")
	}
	if err != nil {
		t.Fatalf("SETUP: unjailed post-X control: %v %s", err, diagnostic.String())
	}
	report, validationErr := validateCoverReports(jailResult{stdout: strings.TrimPrefix(output.output.String(), "POST_X\n"), stderr: diagnostic.String(), exit: exitCodeOf(err)}, strings.Count(command, "COVER-BEGIN "))
	if validationErr != nil {
		t.Fatalf("SETUP: unjailed probe completion: %v", validationErr)
	}
	return report
}

func coverPropagationControl(t *testing.T, command string) func() string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	child := exec.CommandContext(ctx, "/bin/sh", "-c", "echo POST_X; read release; "+command)
	child.SysProcAttr = cloneSysProcAttr()
	child.SysProcAttr.Cloneflags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS
	ready := make(chan bool, 1)
	output := &coverHandshake{ready: ready}
	child.Stdout = output
	var diagnostic coverLogBuffer
	child.Stderr = &diagnostic
	input, err := child.StdinPipe()
	mutationSetup(t, err)
	t.Cleanup(func() { input.Close() })
	mutationSetup(t, child.Start())
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("SETUP: propagation control before handshake: %v %s", err, diagnostic.String())
	case <-ctx.Done():
		t.Fatal("SETUP: propagation control timeout")
	}
	return func() string {
		_, err := input.Write([]byte("go\n"))
		mutationSetup(t, err)
		if err := <-done; err != nil {
			t.Fatalf("SETUP: propagation control: %v %s", err, diagnostic.String())
		}
		report, err := validateCoverReports(jailResult{stdout: strings.TrimPrefix(output.output.String(), "POST_X\n"), stderr: diagnostic.String()}, strings.Count(command, "COVER-BEGIN "))
		if err != nil {
			t.Fatalf("SETUP: propagation probe completion: %v", err)
		}
		return report
	}
}
