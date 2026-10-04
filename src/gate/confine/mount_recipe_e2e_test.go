//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func TestJailMatrixP14(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: cfg.abi, Net: true}
			t.Run("L-FAULT-fds-ENOSYS", func(t *testing.T) {
				p := newProof(t, "L-FAULT-fds-ENOSYS")
				control := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}})
				p.Control("intact", ControlResult{Valid: true, Jailed: &control})
				injected := spec
				injected.InjectFailAt = "fds:ENOSYS"
				plan := hardeningAbortPlan("fds", unix.ENOSYS, jailmut.On("P-FAULT-fds"))
				p.Jailed("attempt", runJailed(t, p, injected, plan))
				mutationEffect(t, "L-FAULT-fds-ENOSYS", "reached-exec", plan.Mode == Execute)
				p.Finish()
			})
			t.Run("L-MOUNT-STAGES", func(t *testing.T) {
				p := newProof(t, "L-MOUNT-STAGES")
				control := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}})
				p.Control("intact", ControlResult{Valid: true, Jailed: &control})
				var results []JailedResult
				for _, stage := range []string{"private", "setattr", "devnodes", "covers", "scratch"} {
					injected := spec
					injected.InjectFailAt = stage
					plan := hardeningAbortPlan(stage, unix.EIO, false)
					results = append(results, runJailed(t, p, injected, plan))
				}
				p.Jailed("attempt", results...)
				p.Finish()
			})
			t.Run("L-DEVICES", func(t *testing.T) {
				p := newProof(t, "L-DEVICES")
				probe := buildProbe(t)
				var results []JailedResult
				for _, node := range []string{"null", "zero", "full", "urandom"} {
					path := "/dev/" + node
					controlWant := "open=ok\nwrite=ok\n"
					controlExit := 0
					if node == "full" {
						controlWant = "open=ok\nwrite=28\n"
						controlExit = 3
					}
					control := mountControl(t, exec.Command(probe, "device-write", path), controlExit)
					if string(control) != controlWant {
						t.Fatalf("SETUP: device control %s", control)
					}
					want := OpOutcome{Stdout: "open=13\n", Exit: 1}
					if node == "null" {
						want = OpOutcome{Stdout: "open=ok\nwrite=ok\n"}
					}
					results = append(results, runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: node, Command: probe + " device-write " + path, Outcomes: []OpOutcome{want}}}}))
				}
				p.Control("devices", ControlResult{Valid: true})
				p.Jailed("devices", results...)
				p.Finish()
			})
			t.Run("L-TTY-NODEV", func(t *testing.T) {
				p := newProof(t, "L-TTY-NODEV")
				probe := buildProbe(t)
				path, fd := openPty(t)
				control := mountControl(t, exec.Command(probe, "tiocexcl", path), 0)
				if string(control) != "open=ok\ntiocexcl=ok\n" {
					t.Fatalf("SETUP: ioctl control %s", control)
				}
				exclusive, err := unix.IoctlGetInt(fd, unix.TIOCGEXCL)
				mutationSetup(t, err)
				if exclusive != 1 {
					t.Fatal("SETUP: TIOCEXCL had no effect")
				}
				mutationSetup(t, unix.IoctlSetInt(fd, unix.TIOCNXCL, 0))
				p.Control("tty", ControlResult{Valid: true})
				observer := &mountStateObserver{sample: func() []string {
					exclusive, err = unix.IoctlGetInt(fd, unix.TIOCGEXCL)
					mutationSetup(t, err)
					return []string{fmt.Sprint(exclusive)}
				}}
				p.ObserveWith("tty", observer)
				mark := observer.Mark()
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "tty", Command: probe + " tiocexcl " + path, Outcomes: []OpOutcome{{Stdout: "open=13\n", Exit: 1}}}}})
				p.Jailed("tty", result)
				if result.setupErr != nil {
					t.Fatalf("SETUP: %+v", result)
				}
				if !strings.Contains(result.stdout, "open=13\n") {
					unexpected(t, "pty open not denied: %+v", result)
				}
				sealMountState(t, observer, mark)
				if exclusive != 0 {
					unexpected(t, "outside tty changed")
				}
				p.Observed("tty", Observation{Conclusive: true, Sealed: true, Valid: exclusive == 0})
				p.Finish()
			})
			t.Run("L-SCRATCH", func(t *testing.T) {
				p := newProof(t, "L-SCRATCH")
				file, err := os.CreateTemp("/dev/shm", "sshgate-host-")
				mutationSetup(t, err)
				_, err = file.WriteString("host-shm-canary")
				mutationSetup(t, err)
				mutationSetup(t, file.Close())
				mountControl(t, exec.Command("/bin/true"), 0)
				t.Cleanup(func() { os.Remove(file.Name()) })
				p.Control("scratch", ControlResult{Valid: true})
				var after []byte
				observer := &mountStateObserver{sample: func() []string {
					after, err = os.ReadFile(file.Name())
					mutationSetup(t, err)
					return []string{string(after)}
				}}
				p.ObserveWith("scratch", observer)
				mark := observer.Mark()
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "scratch", Command: "test ! -e " + file.Name() + " && printf scratch > /dev/shm/file && test $(cat /dev/shm/file) = scratch && cp /bin/true /dev/shm/exec && { /dev/shm/exec; code=$?; test $code = 126; }", Validate: func(stdout, stderr string, exit int) error {
					if exit != 0 || stdout != "" || (!strings.HasSuffix(strings.ToLower(stderr), "/dev/shm/exec: permission denied\n") || strings.Count(stderr, "\n") != 1) {
						return fmt.Errorf("scratch noexec: %d %q %q", exit, stdout, stderr)
					}
					return nil
				}}}})
				p.Jailed("scratch", result)
				if result.setupErr != nil {
					t.Fatalf("SETUP: %+v", result)
				}
				if result.exit != 0 || !strings.Contains(strings.ToLower(result.stderr), "permission denied") {
					unexpected(t, "scratch isolation/noexec: %+v", result)
				}
				sealMountState(t, observer, mark)
				if string(after) != "host-shm-canary" {
					unexpected(t, "host scratch object changed")
				}
				p.Observed("scratch", Observation{Conclusive: true, Sealed: true, Valid: string(after) == "host-shm-canary"})
				p.Finish()
			})
			t.Run("L-WRITE-ROOT", func(t *testing.T) { legWriteSweep(t, spec, false) })
			t.Run("L-WRITE-SUBMOUNT", func(t *testing.T) { legWriteSweep(t, spec, true) })
			t.Run("L-MQUEUE", func(t *testing.T) { legMqueueCover(t, spec) })
			t.Run("L-MQUEUE-ERRNO", func(t *testing.T) { legMqueueErrno(t, spec) })
			t.Run("L-TMP-VISIBLE", func(t *testing.T) {
				p := newProof(t, "L-TMP-VISIBLE")
				file, err := os.CreateTemp("/tmp", "sshgate-visible-")
				mutationSetup(t, err)
				path := file.Name()
				t.Cleanup(func() { os.Remove(path) })
				_, err = file.WriteString("host-tmp-canary")
				mutationSetup(t, err)
				mutationSetup(t, file.Close())
				control, err := os.ReadFile(path)
				mutationSetup(t, err)
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "read", Command: "cat " + path, Outcomes: []OpOutcome{{Stdout: string(control)}}}}})
				p.Jailed("read", result)
				if result.setupErr != nil || result.exit != 0 || result.stdout != string(control) {
					unexpected(t, "tmp invisible: %+v", result)
					t.FailNow()
				}
				p.Finish()
			})
			t.Run("L-PS-VISIBLE", func(t *testing.T) {
				p := newProof(t, "L-PS-VISIBLE")
				var results []JailedResult
				all := mountControl(t, exec.Command("ps", "aux"), 0)
				if len(psRows(string(all))) <= 5 {
					t.Fatal("SETUP: host ps needs more than five processes")
				}
				command := fmt.Sprintf("ps -p %d -o comm=", os.Getpid())
				control := mountControl(t, exec.Command("/bin/sh", "-c", command), 0)
				if len(bytes.TrimSpace(control)) == 0 {
					t.Fatal("SETUP: missing host process")
				}
				for repetition := 0; repetition < 20; repetition++ {
					result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "ps", Command: command, Outcomes: []OpOutcome{{Stdout: string(control)}}}}})
					results = append(results, result)
					if result.setupErr != nil || result.exit != 0 || result.stdout != string(control) {
						unexpected(t, "host process invisible: %+v", result)
						t.FailNow()
					}
				}
				p.Jailed("ps", results...)
				p.Finish()
			})
		})
	}
}

var queueSequence atomic.Uint64

func queueFixture(t *testing.T) (string, *os.File) {
	t.Helper()
	name := fmt.Sprintf("sshgate-p14-%d-%d", os.Getpid(), queueSequence.Add(1))
	fd, _, errno := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(cstr(t, name))), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600, 0, 0, 0)
	if errno != 0 {
		t.Fatalf("SETUP: create queue: %v", errno)
	}
	file := os.NewFile(fd, name)
	t.Cleanup(func() { file.Close(); mqUnlink(t, name) })
	send := func() {
		message := []byte("canary")
		_, _, errno := unix.Syscall6(unix.SYS_MQ_TIMEDSEND, fd, uintptr(unsafe.Pointer(&message[0])), uintptr(len(message)), 0, 0, 0)
		if errno != 0 {
			t.Fatalf("SETUP: send queue: %v", errno)
		}
	}
	send()
	buffer := make([]byte, 8192)
	n, _, errno := unix.Syscall6(unix.SYS_MQ_TIMEDRECEIVE, fd, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0, 0)
	if errno != 0 {
		t.Fatalf("SETUP: drain control: %v", errno)
	}
	if string(buffer[:n]) != "canary" {
		t.Fatalf("SETUP: drain control: %v", errno)
	}
	send()
	return name, file
}
func legMqueueErrno(t *testing.T, spec Spec) {
	p := newProof(t, "L-MQUEUE-ERRNO")
	name, file := queueFixture(t)
	probe := buildProbe(t)
	plan := RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "mq", Command: probe + " mq-errno " + name, Outcomes: []OpOutcome{{Stdout: "mq_open=1\nmq_timedreceive=1\n", Exit: 1}, {Stdout: "mq_open=2\nmq_timedreceive=ok\n", Exit: 3}}}}}
	plan.Configure = func(j *Jailed) { j.Cmd.Stdin = file }
	result := runJailed(t, p, spec, plan)
	p.Jailed("errno", result)
	output := result.stdout
	denied := strings.Contains(output, "mq_open=1\n") && strings.Contains(result.stdout, "mq_timedreceive=1\n")
	mutated := strings.Contains(result.stdout, "mq_open=2\n") && strings.Contains(result.stdout, "mq_timedreceive=ok\n")
	if !denied && !mutated {
		t.Fatalf("SETUP: unexpected MQ result %+v", result)
	}
	mutationEffect(t, "L-MQUEUE-ERRNO", "mq-errno", mutated)
	p.Finish()
}
func legMqueueCover(t *testing.T, spec Spec) {
	p := newProof(t, "L-MQUEUE")
	var results []JailedResult
	entries, err := readMountInfo()
	mutationSetup(t, err)
	count := 0
	drained := false
	for _, entry := range entries {
		if entry.fstype != "mqueue" {
			continue
		}
		// Each alias of the queue filesystem needs a fresh message.
		name, _ := queueFixture(t)
		path := filepath.Join(entry.point, name)
		before, err := os.ReadFile(path)
		mutationSetup(t, err)
		if !strings.Contains(string(before), "QSIZE:6") {
			t.Fatalf("SETUP: queue not populated: %s", before)
		}
		var after []byte
		observer := &mountStateObserver{sample: func() []string { after, err = os.ReadFile(path); mutationSetup(t, err); return []string{string(after)} }}
		p.ObserveWith(fmt.Sprintf("queue-%d", count), observer)
		mark := observer.Mark()
		result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "mq", Command: buildProbe(t) + " mq-drain " + path, Outcomes: []OpOutcome{{Stdout: "open=2\n", Exit: 1}, {Stdout: "open=ok\nmq_timedreceive=ok\n"}}}}})
		results = append(results, result)
		output := result.stdout
		if !strings.Contains(output, "open=2\n") && !strings.Contains(result.stdout, "mq_timedreceive=ok\n") {
			t.Fatalf("SETUP: unexpected queue result: %+v", result)
		}
		sealMountState(t, observer, mark)
		pathDrained := !bytes.Equal(before, after)
		if pathDrained != strings.Contains(output, "mq_timedreceive=ok\n") {
			t.Fatalf("SETUP: queue drain report disagrees with sealed state: %q %q", output, after)
		}
		if count > 0 && pathDrained != drained {
			t.Fatal("SETUP: inconsistent drain observations across mqueue mounts")
		}
		drained = pathDrained
		count++
	}
	if count == 0 {
		t.Fatal("SETUP: no mqueue mount")
	}
	p.Control("queue", ControlResult{Valid: count > 0, Detail: "each fresh queue control sent, received and re-seeded canary"})
	p.Jailed("drain", results...)
	p.Observed("queue", Observation{Conclusive: true, Sealed: true, Valid: true, Detail: "queue size sampled after each framed drain ended"})
	mutationEffect(t, "L-MQUEUE", "queue-drained", drained)
	p.Finish()
}

func legWriteSweep(t *testing.T, spec Spec, submount bool) {
	leg := "L-WRITE-ROOT"
	if submount {
		leg = "L-WRITE-SUBMOUNT"
	}
	p := newProof(t, leg)
	directory := writeSweepFixture(t, submount)
	seed := func() { seedWriteSweep(t, directory) }
	seed()
	probe := buildProbe(t)
	control := mountControl(t, exec.Command(probe, "write-sweep", directory), 0)
	operations := writeSweepOperations
	var controlWant strings.Builder
	for _, name := range operations {
		fmt.Fprintf(&controlWant, "%s=ok\n", name)
	}
	if string(control) != controlWant.String() {
		t.Fatalf("SETUP: incomplete write control: %q", control)
	}
	for _, name := range operations {
		if !strings.Contains(string(control), name+"=ok\n") {
			t.Fatalf("SETUP: control %s", control)
		}
	}
	for name, want := range map[string]string{"write": "changed", "append": "canarychanged", "open-trunc": "changed", "open-rdonly-trunc": "", "truncate-path": ""} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		mutationSetup(t, err)
		if string(data) != want {
			t.Fatalf("SETUP: %s control content %q, want %q", name, data, want)
		}
	}
	p.Control("write", ControlResult{Valid: true})
	seed()
	var writeChanged, truncated bool
	observer := &mountStateObserver{sample: func() []string {
		writeChanged, truncated = observeWriteSweep(t, directory)
		return []string{fmt.Sprintf("write=%t truncate=%t", writeChanged, truncated)}
	}}
	p.ObserveWith("write", observer)
	mark := observer.Mark()
	result := runJailed(t, p, spec, mountProbePlan(probe+" write-sweep "+directory, mountWriteOutcomes(), operations...))
	p.Jailed("write", result)
	output := result.stdout
	for _, name := range operations {
		if jailmut.On("P-RO") && !jailmut.On("P-LL-FS") && (name == "write" || name == "append" || name == "open-trunc") && !strings.Contains(output, name+"=13\n") {
			t.Fatalf("SETUP: Landlock write denial invariant failed for %s: %s", name, output)
		}
		if strings.Contains(output, name+"=ok\n") {
			continue
		}
		want := "30"
		if jailmut.On("P-RO") {
			want = "13"
		}
		if !strings.Contains(output, name+"="+want+"\n") {
			t.Fatalf("SETUP: %s expected errno %s: %+v", name, want, result)
		}
	}
	sealMountState(t, observer, mark)
	mutationEffect(t, leg, "write", writeChanged)
	mutationEffect(t, leg, "truncate", truncated)
	p.Observed("write", Observation{Conclusive: true, Sealed: true, Valid: true, Detail: "all file contents and directory entries sampled after framed sweep ended"})
	p.Finish()
}

var writeSweepOperations = []string{"write", "append", "open-trunc", "open-rdonly-trunc", "truncate-path", "unlink", "rmdir", "mkdir", "symlink", "link", "rename", "mkfifo"}
var writeSweepFiles = []string{"write", "append", "open-trunc", "open-rdonly-trunc", "truncate-path", "file", "remove", "move"}

func seedWriteSweep(t *testing.T, directory string) {
	t.Helper()
	mutationSetup(t, os.RemoveAll(directory))
	mutationSetup(t, os.Mkdir(directory, 0700))
	for _, name := range writeSweepFiles {
		mutationSetup(t, os.WriteFile(filepath.Join(directory, name), []byte("canary"), 0600))
	}
	mutationSetup(t, os.Mkdir(filepath.Join(directory, "empty"), 0700))
}

func observeWriteSweep(t *testing.T, directory string) (writeChanged, truncated bool) {
	t.Helper()
	for _, name := range writeSweepFiles {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil && !os.IsNotExist(err) {
			mutationSetup(t, err)
		}
		changed := err != nil || string(data) != "canary"
		if name == "open-rdonly-trunc" || name == "truncate-path" {
			truncated = truncated || changed
		} else {
			writeChanged = writeChanged || changed
		}
	}
	for _, name := range []string{"made", "symlink", "link", "moved", "fifo"} {
		_, err := os.Lstat(filepath.Join(directory, name))
		if err != nil && !os.IsNotExist(err) {
			mutationSetup(t, err)
		}
		writeChanged = writeChanged || err == nil
	}
	_, err := os.Stat(filepath.Join(directory, "empty"))
	if err != nil && !os.IsNotExist(err) {
		mutationSetup(t, err)
	}
	return writeChanged || os.IsNotExist(err), truncated
}

func TestPhase1WriteSweepObservationsIndependent(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sweep")
	for _, operation := range []string{"write", "append", "open-trunc"} {
		t.Run(operation, func(t *testing.T) {
			seedWriteSweep(t, directory)
			mutationSetup(t, os.WriteFile(filepath.Join(directory, operation), []byte("changed"), 0600))
			for _, name := range []string{"open-rdonly-trunc", "truncate-path"} {
				mutationSetup(t, os.Truncate(filepath.Join(directory, name), 0))
			}
			writeChanged, truncated := observeWriteSweep(t, directory)
			if !writeChanged || !truncated {
				t.Fatalf("write=%t truncate=%t: truncation hid %s", writeChanged, truncated, operation)
			}
		})
	}
}

func writeSweepFixture(t *testing.T, submount bool) string {
	t.Helper()
	base := homeDir(t)
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	rootID, err := mountID(root)
	unix.Close(root)
	mutationSetup(t, err)
	if submount {
		entries, err := readMountInfo()
		mutationSetup(t, err)
		base = ""
		for _, entry := range entries {
			if entry.id == rootID || pathWithin(entry.point, "/dev") || entry.point == "/proc" || entry.point == "/sys" {
				continue
			}
			if entry.fstype != "tmpfs" && entry.fstype != "ext4" && entry.fstype != "xfs" {
				continue
			}
			if unix.Access(entry.point, unix.W_OK|unix.X_OK) == nil {
				base = entry.point
				break
			}
		}
		if base == "" {
			t.Fatal("SETUP: no user-writable submount; provision /mnt/sg-sub")
		}
	}
	directory, err := os.MkdirTemp(base, ".sshgate-sweep-")
	mutationSetup(t, err)
	t.Cleanup(func() { os.RemoveAll(directory) })
	fd, err := unix.Open(directory, unix.O_PATH|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	id, err := mountID(fd)
	unix.Close(fd)
	mutationSetup(t, err)
	if (id != rootID) != submount {
		t.Fatal("SETUP: fixture on wrong mount")
	}
	return directory
}
