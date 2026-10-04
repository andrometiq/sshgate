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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"golang.org/x/sys/unix"
)

const coverNamespaceEnv = "SSHGATE_COVER_NAMESPACE"

func coverNamespace(t *testing.T, nonroot bool) bool {
	t.Helper()
	if os.Getenv(coverNamespaceEnv) == t.Name() {
		mutationSetup(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
		return true
	}
	needsFuse := !strings.HasSuffix(t.Name(), "/L-TRACEFS") && !strings.HasSuffix(t.Name(), "/L-SHIM-PROC") && !strings.HasSuffix(t.Name(), "/L-COVER-LOOP") && !strings.HasSuffix(t.Name(), "/L-COVER-UNKNOWN")
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
	run := "^" + strings.ReplaceAll(regexp.QuoteMeta(t.Name()), "/", "$/^") + "$"
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-test.run=") {
			parts := strings.Split(strings.TrimPrefix(arg, "-test.run="), "/")
			depth := len(strings.Split(t.Name(), "/"))
			if len(parts) > depth {
				run += "/" + strings.Join(parts[depth:], "/")
			}
		}
	}
	command := exec.CommandContext(ctx, testBinary, "-test.run="+run, "-test.v")
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
	forwardCoverProof(t, output, err)
	return false
}
func forwardCoverProof(t *testing.T, output []byte, processErr error) {
	t.Helper()
	index := strings.Index(t.Name(), "/L-")
	if index < 0 {
		t.Fatal("SETUP: unnamed cover proof transport")
	}
	name := t.Name()[index+1:]
	var declaration harness.Case
	found := false
	for _, candidate := range legCases {
		if candidate.Name == name {
			declaration = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("SETUP: undeclared cover child %s", name)
	}
	abi := "native"
	if strings.Contains(t.Name(), "/abi1/") {
		abi = "abi1"
	}
	declaration.ABIs = []string{abi}
	convert := exec.Command("go", "tool", "test2json", "-p", "cover-child")
	convert.Stdin = bytes.NewReader(output)
	stream, err := convert.Output()
	mutationSetup(t, err)
	records, err := harness.CheckBaseline(bytes.NewReader(stream), proofExit(processErr), []harness.Case{declaration}, os.Geteuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1")
	if err != nil {
		t.Fatalf("SETUP: cover child proof: %v: %s", err, output)
	}
	if len(records) != 1 {
		t.Fatal("SETUP: cover child did not produce exactly one proof")
	}
	record := records[0]
	if record.Outcome == "COMPLETE" {
		if !proofMutationBuild && len(record.Markers) > 0 {
			t.Fatal("SETUP: normal child reported effects")
		}
		t.Logf("PROOF-COMPLETE %s %s markers=%s", record.Leg, record.ABI, strings.Join(record.Markers, ","))
	} else {
		t.Logf("PROOF-%s %s %s %s", record.Outcome, record.Leg, record.ABI, record.Code)
	}
}

func coverUnavailable(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("SSHGATE_JAIL_CI") == "1" {
		t.Fatalf("SETUP: FUSE unavailable: %v", err)
	}
	name := t.Name()
	index := strings.Index(name, "/L-")
	if index < 0 {
		t.Fatalf("SETUP: missing case name: %s", name)
	}
	newProof(t, name[index+1:]).Omit("fuse-unavailable")
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

func coverExecCommand(command string) string {
	return "{ printf 'COVER-BEGIN exec\\n'; " + command + "; printf 'COVER-END %s\\n' \"$?\"; }"
}

func validateCoverReports(result jailResult, count int, contexts ...map[string]map[string][]int) (string, error) {
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
		if expected == nil && operation != "exec" {
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
		if operation == "exec" {
			if status != 0 {
				return "", fmt.Errorf("utility exit %d", status)
			}
		} else if err := validateProbeOutput(jailResult{stdout: validation, exit: status}, expected, probeExitAnyFailure); err != nil {
			return "", fmt.Errorf("%s: %w", operation, err)
		}
		if len(contexts) > 0 && operation != "exec" {
			allowed := contexts[0][operation]
			for _, line := range strings.Split(strings.TrimSuffix(report.String(), "\n"), "\n") {
				step, value, ok := strings.Cut(line, "=")
				if !ok || value == "ok" || step == "target" || step == "mntid" || step == "bytes" {
					continue
				}
				errno, err := strconv.Atoi(value)
				if err != nil || !slices.Contains(allowed[step], errno) {
					return "", fmt.Errorf("%s undeclared stop %s", operation, line)
				}
			}
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
	diagnostic *coverLogBuffer
	stopped    bool
	stopErr    error
	loop       bool
	sealed     bool
	snapshot   []byte
	testing    *testing.T
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
	fixture := &fuseFixture{point: point, log: log, command: command, diagnostic: &diagnostic, loop: slices.Contains(flags, "--loop")}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("SETUP: FUSE observer stop: %v", err)
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
	return fixture
}
func (f *fuseFixture) Start(t *testing.T) { f.testing = t; mutationSetup(t, f.Healthy()) }
func (f *fuseFixture) Mark() ObserverMark { f.sealed = false; return ObserverMark(f.mark(f.testing)) }
func (f *fuseFixture) Since(mark ObserverMark) ObservationRecords {
	if !f.sealed {
		return ObservationRecords{Err: fmt.Errorf("inconclusive: unsealed FUSE window")}
	}
	if mark < 0 || int64(mark) > int64(len(f.snapshot)) {
		return ObservationRecords{Err: fmt.Errorf("invalid FUSE mark")}
	}
	records := strings.ReplaceAll(string(f.snapshot[int64(mark):]), "BARRIER\n", "")
	return ObservationRecords{Records: strings.Split(strings.TrimSuffix(records, "\n"), "\n"), Sealed: true, Conclusive: true}
}
func (f *fuseFixture) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("inconclusive: FUSE producer has not completed")
	}
	f.seal(f.testing)
	f.sealed = true
	return nil
}
func (f *fuseFixture) Healthy() error {
	if f.stopped {
		return fmt.Errorf("FUSE observer already stopped")
	}
	if err := f.command.Process.Signal(syscall.Signal(0)); err != nil {
		return err
	}
	if diagnostic := f.diagnostic.String(); diagnostic != "" {
		return fmt.Errorf("FUSE observer: %s", diagnostic)
	}
	return nil
}
func (f *fuseFixture) Stop() error {
	if f.stopped {
		return f.stopErr
	}
	f.stopped = true
	if err := f.command.Process.Signal(syscall.SIGTERM); err != nil {
		f.stopErr = err
	}
	done := make(chan error, 1)
	go func() { done <- f.command.Wait() }()
	select {
	case err := <-done:
		f.stopErr = errors.Join(f.stopErr, err)
	case <-time.After(3 * time.Second):
		f.command.Process.Kill()
		f.stopErr = errors.Join(f.stopErr, <-done, fmt.Errorf("FUSE shutdown timeout"))
	}
	if text := f.diagnostic.String(); text != "" {
		f.stopErr = errors.Join(f.stopErr, fmt.Errorf("FUSE stderr: %s", text))
	}
	if !f.loop {
		data, err := os.ReadFile(f.log)
		f.stopErr = errors.Join(f.stopErr, err)
		if strings.Count(string(data), "VERDICT ") != 1 || !strings.HasSuffix(string(data), "VERDICT ok\n") {
			f.stopErr = errors.Join(f.stopErr, fmt.Errorf("FUSE missing clean final verdict: %s", data))
		}
	}
	return f.stopErr
}

// A completed synchronous FUSE request records its effect before its response.
// The barrier flushes those records without unmounting or inducing writeback.
func (f *fuseFixture) seal(t *testing.T) {
	t.Helper()
	mutationSetup(t, f.Healthy())
	mark := f.mark(t)
	mutationSetup(t, f.command.Process.Signal(syscall.SIGUSR1))
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(f.log)
		mutationSetup(t, err)
		if mark > int64(len(data)) {
			t.Fatal("SETUP: FUSE log shrank")
		}
		if index := strings.Index(string(data[mark:]), "BARRIER\n"); index >= 0 {
			f.snapshot = append([]byte(nil), data[:int(mark)+index+len("BARRIER\n")]...)
			f.sealed = true
			return
		}
		mutationSetup(t, f.Healthy())
		if time.Now().After(deadline) {
			t.Fatal("SETUP: inconclusive FUSE record barrier")
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *fuseFixture) mark(t *testing.T) int64 {
	t.Helper()
	f.sealed = false
	f.snapshot = nil
	state, err := os.Stat(f.log)
	mutationSetup(t, err)
	return state.Size()
}
func (f *fuseFixture) since(t *testing.T, offset int64) string {
	t.Helper()
	records := f.Since(ObserverMark(offset))
	if records.Err != nil || !records.Sealed || !records.Conclusive {
		t.Fatalf("SETUP: inconclusive FUSE observation: %v", records.Err)
	}
	if len(records.Records) == 1 && records.Records[0] == "" {
		return ""
	}
	return strings.Join(records.Records, "\n") + "\n"
}
func (f *fuseFixture) rawSince(t *testing.T, offset int64) string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	mutationSetup(t, err)
	if offset > int64(len(data)) {
		t.Fatal("SETUP: FUSE log shrank")
	}
	return strings.ReplaceAll(string(data[offset:]), "BARRIER\n", "")
}
func coverHasRecord(log, record string) bool {
	return slices.Contains(strings.Split(log, "\n"), record)
}

func (f *fuseFixture) control(t *testing.T) ControlResult {
	t.Helper()
	mark := f.mark(t)
	out, err := exec.Command(coverProbe(), "fuse-ioctl", f.point+"/f", "0x40085301", "42").CombinedOutput()
	f.waitRelease(t, mark)
	f.seal(t)
	if err != nil || !strings.Contains(string(out), "ioctl=ok") || !coverHasRecord(f.since(t, mark), "IOCTL 42") {
		t.Fatalf("SETUP: FUSE ioctl control: %v %s", err, out)
	}
	return ControlResult{Valid: err == nil && strings.Contains(string(out), "ioctl=ok") && coverHasRecord(f.since(t, mark), "IOCTL 42"), Detail: "synchronous ioctl 42 control"}
}

func (f *fuseFixture) waitRelease(t *testing.T, mark int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !coverHasRecord(f.rawSince(t, mark), "RELEASE") {
		if time.Now().After(deadline) {
			t.Fatal("SETUP: FUSE control release not observed")
		}
		time.Sleep(time.Millisecond)
	}

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

func coverStopContext(leg string) map[string]map[string][]int {
	context := map[string]map[string][]int{
		"fuse-ioctl": {"open": {int(unix.ENOENT)}},
		"read":       {"open": {int(unix.ENOENT)}},
		"jail-proc":  {"open": {int(unix.EACCES)}},
		"mntid":      {}, "sync": {}, "cover-write": {},
	}
	if leg == "L-COVER-STACKED" {
		context["fuse-ioctl"]["ioctl"] = []int{int(unix.ENOTTY)}
	}
	if !jailmut.On("P-SC-SYNC") {
		context["sync"]["sync"] = []int{int(unix.EPERM)}
	}
	if !jailmut.On("P-LL-FS") {
		context["cover-write"]["open"] = []int{int(unix.EACCES)}
	}
	if !jailmut.On("P-PRIVATE") {
		context["cover-write"]["open"] = append(context["cover-write"]["open"], int(unix.EROFS))
	}
	return context
}

func coverProofRun(t *testing.T, p *proof, spec Spec, command string, afterReady func()) (JailedResult, Facts) {
	t.Helper()
	command = strings.TrimPrefix(command, "echo POST_X; read release; ")
	count := strings.Count(command, "COVER-BEGIN ")
	stops := coverStopContext(p.caseDef.Name)
	plan := RunPlan{Mode: Execute, AfterReady: afterReady, Ops: []ProofOp{{Name: "cover", Command: command, Validate: func(stdout, stderr string, exit int) error {
		_, err := validateCoverReports(jailResult{stdout: stdout, stderr: stderr, exit: exit}, count, stops)
		return err
	}}}}
	abort := spec.Strict && ((jailmut.On("P-COVERS") && !jailmut.On("P-SELFCHECK-MOUNTS")) ||
		(p.caseDef.Name == "L-COVER-CWD" && jailmut.On("P-CWD") && !jailmut.On("P-SELFCHECK-MOUNTS")) ||
		(p.caseDef.Name == "L-COVER-STACKED" && (jailmut.On("P-REACH") || jailmut.On("REACH-R3")) && !jailmut.On("P-SELFCHECK-REACH")) ||
		(p.caseDef.Name == "L-SELFCHECK-MOUNTS" && jailmut.On("P-PRIVATE") && !jailmut.On("P-SELFCHECK-MOUNTS")))
	if abort {
		return runJailed(t, p, spec, RunPlan{Mode: SetupAbort, Command: command, Stage: "selfcheck", Errno: 0}), Facts{}
	}
	if afterReady != nil {
		plan.Mode = Interactive
		plan.ReadyPoint = "post-exec"
	}
	result := runJailed(t, p, spec, plan)
	output, err := validateCoverReports(result.jailResult, count, stops)
	mutationSetup(t, err)
	result.stdout = output
	return result, result.Facts
}
