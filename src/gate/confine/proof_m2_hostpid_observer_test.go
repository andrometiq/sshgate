//go:build linux && jail_e2e

package confine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type m2Recipient struct {
	command         *exec.Cmd
	input           *os.File
	scanner         *bufio.Scanner
	diagnostic      bytes.Buffer
	cancel          context.CancelFunc
	sealed, stopped bool
	record          string
	reportKey       string
	err             error
}

func buildM2Recipient(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recipient")
	command := exec.Command("cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-o", path, "testdata/signal-recipient/main.c")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build signal recipient: %v %s", err, output)
	}
	return path
}
func newM2Recipient(t *testing.T, binary string, signal syscall.Signal) *m2Recipient {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	key := "signal"
	if signal == syscall.SIGIO {
		key = "sigio"
	}
	observer := &m2Recipient{reportKey: key, command: exec.CommandContext(ctx, binary, strconv.Itoa(int(signal))), cancel: cancel}
	reader, writer, err := os.Pipe()
	mutationSetup(t, err)
	observer.input = writer
	observer.command.Stdin = reader
	output, err := observer.command.StdoutPipe()
	mutationSetup(t, err)
	observer.command.Stderr = &observer.diagnostic
	observer.scanner = bufio.NewScanner(output)
	mutationSetup(t, observer.command.Start())
	reader.Close()
	t.Cleanup(func() {
		if !observer.stopped {
			_ = observer.command.Process.Kill()
			_ = observer.command.Wait()
			observer.stopped = true
		}
		writer.Close()
		cancel()
	})
	if !observer.scanner.Scan() || observer.scanner.Text() != "READY" {
		t.Fatal("SETUP: recipient readiness")
	}
	return observer
}
func (*m2Recipient) Start(*testing.T) {}
func (o *m2Recipient) Mark() ObserverMark {
	if o.sealed {
		o.err = fmt.Errorf("recipient reused after sealing")
	}
	return 0
}
func (o *m2Recipient) Healthy() error {
	if o.err != nil {
		return o.err
	}
	if !o.stopped {
		return o.command.Process.Signal(syscall.Signal(0))
	}
	return nil
}
func (o *m2Recipient) Seal(sync ProducerSync) error {
	if o.sealed || !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("recipient synchronization invalid")
	}
	if _, o.err = o.input.WriteString("s\n"); o.err != nil {
		return o.err
	}
	o.input.Close()
	if !o.scanner.Scan() {
		o.err = fmt.Errorf("recipient missing pending report")
	} else {
		o.record = o.scanner.Text()
		if o.record != o.reportKey+"=pending" && o.record != o.reportKey+"=absent" {
			o.err = fmt.Errorf("recipient invalid pending report %q", o.record)
		}
	}
	if !o.scanner.Scan() || o.scanner.Text() != "VERDICT ok" {
		o.err = fmt.Errorf("recipient missing verdict")
	}
	if o.scanner.Scan() || o.scanner.Err() != nil {
		o.err = fmt.Errorf("recipient trailing output or read error: %v", o.scanner.Err())
	}
	if err := o.command.Wait(); err != nil {
		o.err = fmt.Errorf("recipient exit: %w", err)
	}
	o.stopped = true
	o.cancel()
	if o.diagnostic.Len() != 0 {
		o.err = fmt.Errorf("recipient diagnostics: %s", o.diagnostic.String())
	}
	o.sealed = o.err == nil
	return o.err
}
func (o *m2Recipient) Since(mark ObserverMark) ObservationRecords {
	return ObservationRecords{Records: []string{o.record}, Sealed: o.sealed, Conclusive: o.sealed && mark == 0 && o.err == nil, Err: o.err}
}
func (o *m2Recipient) Stop() error {
	if !o.stopped {
		killErr := o.command.Process.Kill()
		waitErr := o.command.Wait()
		o.stopped = true
		o.cancel()
		o.input.Close()
		return fmt.Errorf("recipient unsealed: kill=%v wait=%v", killErr, waitErr)
	}
	if !o.sealed {
		return fmt.Errorf("recipient was not sealed: %v", o.err)
	}
	return o.err
}

// Synchronous kernel snapshots are read only after the producing operation ends.
type m2StateObserver struct {
	sample         func() string
	before, after  string
	marked, sealed bool
}

func (*m2StateObserver) Start(*testing.T) {}
func (o *m2StateObserver) Mark() ObserverMark {
	o.before = o.sample()
	o.marked = true
	o.sealed = false
	return 0
}
func (o *m2StateObserver) Healthy() error { return nil }
func (o *m2StateObserver) Seal(sync ProducerSync) error {
	if !o.marked || !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("state synchronization missing")
	}
	o.after = o.sample()
	o.sealed = true
	return nil
}
func (o *m2StateObserver) Since(mark ObserverMark) ObservationRecords {
	return ObservationRecords{Records: []string{o.before, o.after}, Sealed: o.sealed, Conclusive: o.sealed && mark == 0}
}
func (o *m2StateObserver) Stop() error {
	if !o.sealed {
		return fmt.Errorf("state observer unsealed")
	}
	return nil
}
func m2Seal(t *testing.T, observer Observer, mark ObserverMark) []string {
	t.Helper()
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	if !records.Sealed || !records.Conclusive || records.Err != nil {
		t.Fatalf("SETUP: observer: %+v", records)
	}
	return records.Records
}

func runM2Probe(t *testing.T, p *proof, spec Spec, command string, fields ...string) JailedResult {
	return runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "probe", Command: command, Validate: func(stdout, stderr string, exit int) error {
		if err := validateProbeOutput(jailResult{stdout: stdout, stderr: stderr, exit: exit}, fields, probeExitMixed); err != nil {
			return err
		}
		allowed := map[string]bool{}
		for _, field := range fields {
			allowed[field] = true
		}
		for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
			key, _, _ := strings.Cut(line, "=")
			if !allowed[key] {
				return fmt.Errorf("unknown report %q", line)
			}
		}
		return nil
	}}}})
}

func TestM2RecipientDelayedInspection(t *testing.T) {
	binary := buildM2Recipient(t)
	for _, signal := range []syscall.Signal{syscall.SIGIO, syscall.SIGUSR1} {
		for _, send := range []bool{false, true} {
			observer := newM2Recipient(t, binary, signal)
			mark := observer.Mark()
			if send {
				mutationSetup(t, observer.command.Process.Signal(signal))
			}
			// Sender completion precedes the recipient's synchronous inspection.
			records := m2Seal(t, observer, mark)
			want := observer.reportKey + "=absent"
			if send {
				want = observer.reportKey + "=pending"
			}
			if len(records) != 1 || records[0] != want {
				t.Fatalf("records %v want %s", records, want)
			}
			mutationSetup(t, observer.Stop())
		}
	}
}
func startRetuneVictim(t *testing.T, p *proof) *exec.Cmd {
	t.Helper()
	victim := exec.Command("sleep", "300")
	if os.Geteuid() == 0 {
		victim = exec.Command(buildProbe(t), "retune-victim", "drop")
	}
	owner := &m2ProcessOwner{command: victim}
	victim.Stderr = &owner.diagnostic
	reader, err := victim.StdoutPipe()
	mutationSetup(t, err)
	mutationSetup(t, victim.Start())
	p.ObserveWith(fmt.Sprintf("victim-%d", len(p.observers)), owner)
	t.Cleanup(func() {
		if !owner.stopped {
			if err := owner.Stop(); err != nil {
				t.Errorf("SETUP: victim cleanup: %v", err)
			}
		}
	})
	if os.Geteuid() != 0 {
		return victim
	}
	scan := bufio.NewScanner(reader)
	if !scan.Scan() || scan.Text() != "READY" {
		t.Fatalf("SETUP: retune victim readiness: %v %s", scan.Err(), owner.diagnostic.String())
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", victim.Process.Pid))
	mutationSetup(t, err)
	for _, field := range []string{"Uid", "CapPrm", "CapEff", "CapInh", "CapBnd", "CapAmb"} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			values := strings.Fields(line)
			if len(values) == 0 || values[0] != field+":" {
				continue
			}
			expected := 2
			if field == "Uid" {
				expected = 5
			}
			if len(values) != expected {
				t.Fatalf("SETUP: retune victim malformed %s", line)
			}
			for _, value := range values[1:] {
				n, err := strconv.ParseUint(value, 16, 64)
				if err != nil || n != 0 {
					t.Fatalf("SETUP: retune victim nonzero %s", line)
				}
			}
			found = true
		}
		if !found {
			t.Fatalf("SETUP: retune victim missing %s", field)
		}
	}
	return victim
}

func initializeRetuneVictim(t *testing.T, victim *exec.Cmd, targetCPU int) schedulerState {
	t.Helper()
	pid := victim.Process.Pid
	mutationSetup(t, unix.Setpriority(unix.PRIO_PROCESS, pid, 18))
	_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, 1, uintptr(pid), 2<<13|4)
	if errno != 0 {
		t.Fatalf("SETUP: initial ioprio: %v", errno)
	}
	var available, pinned unix.CPUSet
	mutationSetup(t, unix.SchedGetaffinity(0, &available))
	for cpu := 0; cpu < 1024; cpu++ {
		if cpu != targetCPU && available.IsSet(cpu) {
			pinned.Set(cpu)
			break
		}
	}
	if pinned.Count() != 1 {
		t.Fatal("SETUP: retune affinity requires at least two available CPUs")
	}
	mutationSetup(t, unix.SchedSetaffinity(pid, &pinned))
	limit := unix.Rlimit{Cur: 64, Max: 64}
	mutationSetup(t, unix.Prlimit(pid, unix.RLIMIT_NOFILE, &limit, nil))
	var priority int32
	_, _, errno = unix.Syscall(unix.SYS_SCHED_SETSCHEDULER, uintptr(pid), 0, uintptr(unsafe.Pointer(&priority)))
	if errno != 0 {
		t.Fatalf("SETUP: initial scheduler policy: %v", errno)
	}
	initial := readScheduler(t, pid)
	if initial.nice != 2 || initial.io != 2<<13|4 || initial.policy != 0 || initial.nofile != 64 || initial.affinity != pinned {
		t.Fatalf("SETUP: retune victim initial state: %+v", initial)
	}
	return initial
}

func readRealtimePriority(t *testing.T, pid int) int32 {
	t.Helper()
	var priority int32
	_, _, errno := unix.Syscall(unix.SYS_SCHED_GETPARAM, uintptr(pid), uintptr(unsafe.Pointer(&priority)), 0)
	if errno != 0 {
		t.Fatalf("SETUP: observe realtime priority: %v", errno)
	}
	return priority
}

func exitStopVictim(t *testing.T, p *proof) int {
	t.Helper()
	command := exec.Command("/bin/sh", "-c", "exit 0")
	command.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	mutationSetup(t, command.Start())
	pid := command.Process.Pid
	owner := &m2ProcessOwner{command: command, ptraced: true}
	p.ObserveWith(fmt.Sprintf("exit-stop-%d", len(p.observers)), owner)
	t.Cleanup(func() {
		if !owner.stopped {
			if err := owner.Stop(); err != nil {
				t.Errorf("SETUP: exit-stop cleanup: %v", err)
			}
		}
	})
	var status unix.WaitStatus
	_, err := unix.Wait4(pid, &status, 0, nil)
	mutationSetup(t, err)
	if !status.Stopped() {
		t.Fatal("SETUP: missing initial ptrace stop")
	}
	mutationSetup(t, unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACEEXIT))
	mutationSetup(t, unix.PtraceCont(pid, 0))
	_, err = unix.Wait4(pid, &status, 0, nil)
	mutationSetup(t, err)
	if !status.Stopped() || status.TrapCause() != unix.PTRACE_EVENT_EXIT {
		t.Fatalf("SETUP: missing exit stop: %v", status)
	}
	return pid
}
func residentPages(t *testing.T, pid int) uint64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	mutationSetup(t, err)
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatal("SETUP: statm", string(data))
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	mutationSetup(t, err)
	return pages
}

type m2LifecycleObserver struct {
	pids             map[int]bool
	sealed, remained bool
	err              error
}

func (o *m2LifecycleObserver) Start(*testing.T)   { o.pids = map[int]bool{} }
func (o *m2LifecycleObserver) Mark() ObserverMark { o.sealed = false; return 0 }
func (o *m2LifecycleObserver) Healthy() error     { return o.err }

// capture walks every task: a multithreaded parent (the Go shim) lists each child
// under the thread that forked it, not under its main thread.
func (o *m2LifecycleObserver) capture(t *testing.T, pid int) {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	mutationSetup(t, err)
	for _, task := range tasks {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, task.Name()))
		mutationSetup(t, err)
		for _, field := range strings.Fields(string(data)) {
			child, err := strconv.Atoi(field)
			mutationSetup(t, err)
			o.pids[child] = true
			o.capture(t, child)
		}
	}
}
func (o *m2LifecycleObserver) addReport(t *testing.T, report string) {
	for _, field := range strings.Fields(report) {
		if strings.HasPrefix(field, "CHILD=") || strings.HasPrefix(field, "SPAWN=") {
			_, value, _ := strings.Cut(field, "=")
			pid, err := strconv.Atoi(value)
			mutationSetup(t, err)
			o.pids[pid] = true
		}
	}
}
func (o *m2LifecycleObserver) inspect() error {
	if len(o.pids) == 0 {
		return fmt.Errorf("no identified descendants")
	}
	for pid := range o.pids {
		err := unix.Kill(pid, 0)
		if err == nil {
			o.remained = true
		} else if err != unix.ESRCH {
			return fmt.Errorf("descendant %d observation: %w", pid, err)
		}
	}
	return nil
}
func (o *m2LifecycleObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("lifecycle synchronization missing")
	}
	o.err = o.inspect()
	o.sealed = o.err == nil
	return o.err
}
func (o *m2LifecycleObserver) Since(mark ObserverMark) ObservationRecords {
	return ObservationRecords{Records: []string{strconv.FormatBool(o.remained)}, Sealed: o.sealed, Conclusive: o.sealed && mark == 0, Err: o.err}
}
func (o *m2LifecycleObserver) Stop() error {
	for pid := range o.pids {
		fd, err := unix.PidfdOpen(pid, 0)
		if err == unix.ESRCH {
			continue
		}
		if err != nil {
			o.err = fmt.Errorf("open descendant %d: %w", pid, err)
			return o.err
		}
		err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		if err != nil && err != unix.ESRCH {
			unix.Close(fd)
			o.err = fmt.Errorf("stop descendant %d: %w", pid, err)
			return o.err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		deadline := time.Now().Add(2 * time.Second)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				err = fmt.Errorf("descendant %d did not exit", pid)
				break
			}
			_, err = unix.Poll(poll, int(remaining.Milliseconds())+1)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				break
			}
			if poll[0].Revents&unix.POLLIN != 0 {
				break
			}
			err = fmt.Errorf("descendant %d exit barrier: %d", pid, poll[0].Revents)
			break
		}
		unix.Close(fd)
		if err != nil {
			o.err = err
			return err
		}
	}
	if !o.sealed {
		return fmt.Errorf("lifecycle observation unsealed")
	}
	return o.err
}

func validateM2LifecycleReport(report, mode string) error {
	if !strings.HasSuffix(report, "\n") {
		return fmt.Errorf("unterminated lifecycle report")
	}
	children, ready, teardown := 0, 0, 0
	seen := map[int]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(report, "\n"), "\n") {
		if line == "READY" && (mode == "cancel" || mode == "term") {
			ready++
			if children != 2 {
				return fmt.Errorf("readiness before descendants")
			}
			continue
		}
		if line == "TEARDOWN" && mode == "forking" {
			teardown++
			continue
		}
		kind, value, ok := strings.Cut(line, "=")
		pid, err := strconv.Atoi(value)
		if !ok || err != nil || pid <= 1 || (kind != "CHILD" && kind != "SPAWN") || (kind == "SPAWN" && mode != "forking") {
			return fmt.Errorf("invalid lifecycle report %q", line)
		}
		if seen[pid] {
			return fmt.Errorf("duplicate descendant %d", pid)
		}
		seen[pid] = true
		if kind == "CHILD" {
			children++
		}
	}
	if (mode == "cancel" || mode == "term") && ready != 1 {
		return fmt.Errorf("missing or duplicate readiness")
	}
	if mode == "forking" && teardown != 1 {
		return fmt.Errorf("missing or duplicate teardown")
	}
	if children != 2 {
		return fmt.Errorf("lifecycle children: %q", report)
	}
	if mode == "forking" {
		before, _, found := strings.Cut(report, "TEARDOWN\n")
		count := strings.Count(before, "SPAWN=")
		if !found || count < 3 || count >= 32 {
			return fmt.Errorf("repeated creation missing: %q", report)
		}
	}
	return nil
}

type m2ProcessOwner struct {
	command    *exec.Cmd
	diagnostic bytes.Buffer
	stopped    bool
	sealed     bool
	ptraced    bool
}

func (*m2ProcessOwner) Start(*testing.T)   {}
func (*m2ProcessOwner) Mark() ObserverMark { return 0 }
func (o *m2ProcessOwner) Since(ObserverMark) ObservationRecords {
	err := o.Healthy()
	return ObservationRecords{Sealed: o.sealed, Conclusive: o.sealed && err == nil, Err: err}
}
func (o *m2ProcessOwner) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("process lifetime unsealed")
	}
	if err := o.Healthy(); err != nil {
		return err
	}
	o.sealed = true
	return nil
}
func (o *m2ProcessOwner) Healthy() error {
	if o.stopped {
		return fmt.Errorf("victim already stopped")
	}
	return o.command.Process.Signal(syscall.Signal(0))
}
func (o *m2ProcessOwner) Stop() error {
	if o.stopped {
		return nil
	}
	o.stopped = true
	if o.ptraced {
		pid := o.command.Process.Pid
		if err := unix.PtraceCont(pid, 0); err != nil {
			return fmt.Errorf("resume exit-stop: %w", err)
		}
		var status unix.WaitStatus
		got, err := unix.Wait4(pid, &status, 0, nil)
		if err != nil || got != pid || !status.Exited() || status.ExitStatus() != 0 {
			return fmt.Errorf("exit-stop teardown: pid=%d status=%v error=%v", got, status, err)
		}
		if err := o.command.Process.Release(); err != nil {
			return err
		}
	} else {
		if err := o.command.Process.Kill(); err != nil {
			return err
		}
		err := o.command.Wait()
		if o.command.ProcessState == nil {
			return fmt.Errorf("victim missing wait state: %v", err)
		}
		status, ok := o.command.ProcessState.Sys().(syscall.WaitStatus)
		if err == nil || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			return fmt.Errorf("victim teardown: %v", err)
		}
	}
	if o.diagnostic.Len() != 0 {
		return fmt.Errorf("victim diagnostics: %s", o.diagnostic.String())
	}
	return nil
}

func m2LifecycleControl(t *testing.T) {
	t.Helper()
	command := exec.Command("sh", "-c", "sleep 30 >/dev/null 2>&1 & echo CHILD=$!; sleep 30 >/dev/null 2>&1 & echo CHILD=$!")
	output, err := command.CombinedOutput()
	mutationSetup(t, err)
	if err := validateM2LifecycleReport(string(output), "normal"); err != nil {
		t.Fatal("SETUP:", err)
	}
	observer := &m2LifecycleObserver{}
	observer.Start(t)
	observer.Mark()
	observer.addReport(t, string(output))
	m2Seal(t, observer, 0)
	if !observer.remained {
		t.Fatal("SETUP: unjailed descendants did not survive their parent")
	}
	mutationSetup(t, observer.Stop())
}

func sealM2Processes(t *testing.T, p *proof) {
	for _, observer := range p.observers {
		if owner, ok := observer.(*m2ProcessOwner); ok {
			mutationSetup(t, owner.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
		}
	}
}

func TestM2ProcessOwnerSealing(t *testing.T) {
	command := exec.Command("sleep", "30")
	owner := &m2ProcessOwner{command: command}
	command.Stderr = &owner.diagnostic
	mutationSetup(t, command.Start())
	t.Cleanup(func() {
		if !owner.stopped {
			_ = owner.Stop()
		}
	})
	if records := owner.Since(0); records.Conclusive || records.Sealed {
		t.Fatal("unsealed owner accepted")
	}
	if owner.Seal(ProducerSync{Complete: true, Kind: "wrong"}) == nil {
		t.Fatal("invalid synchronization accepted")
	}
	mutationSetup(t, owner.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	if records := owner.Since(0); !records.Conclusive || !records.Sealed || records.Err != nil {
		t.Fatalf("sealed owner: %+v", records)
	}
	mutationSetup(t, owner.Stop())
}
func TestM2LifecycleReportContract(t *testing.T) {
	valid := "CHILD=123\nCHILD=456\nSPAWN=111\nSPAWN=222\nSPAWN=333\nTEARDOWN\nSPAWN=444\n"
	if err := validateM2LifecycleReport(valid, "forking"); err != nil {
		t.Fatal(err)
	}
	for _, report := range []string{"", "CHILD=123\n", strings.Replace(valid, "CHILD=123", "CHILD=bad", 1), strings.Replace(valid, "CHILD=456", "CHILD=123", 1), strings.Replace(valid, "TEARDOWN\n", "", 1), valid + "TEARDOWN\n", strings.TrimSuffix(valid, "\n"), valid + "unexpected\n"} {
		if validateM2LifecycleReport(report, "forking") == nil {
			t.Fatalf("invalid report accepted: %q", report)
		}
	}
	for _, mode := range []string{"cancel", "term"} {
		complete := "CHILD=123\nCHILD=456\nREADY\n"
		if err := validateM2LifecycleReport(complete, mode); err != nil {
			t.Fatal(err)
		}
		for _, report := range []string{strings.TrimSuffix(complete, "READY\n"), complete + "READY\n", "READY\nCHILD=123\nCHILD=456\n"} {
			if validateM2LifecycleReport(report, mode) == nil {
				t.Fatalf("invalid readiness accepted: %q", report)
			}
		}
	}
	m2LifecycleControl(t)
}
