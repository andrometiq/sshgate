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
				p12Control(t, spec)
				injected := spec
				injected.InjectFailAt = "fds:ENOSYS"
				result := runP12(t, injected, "echo COMMAND_RAN", nil)
				expectP12Abort(t, "L-FAULT-fds-ENOSYS", "fds", unix.ENOSYS, result)
			})
			t.Run("L-MOUNT-STAGES", func(t *testing.T) {
				for _, stage := range []string{"private", "setattr", "devnodes", "covers", "scratch"} {
					t.Run(stage, func(t *testing.T) { legFault(t, spec, stage) })
				}
			})
			t.Run("L-DEVICES", func(t *testing.T) {
				probe := buildProbe(t)
				for _, node := range []string{"null", "zero", "full", "urandom"} {
					t.Run(node, func(t *testing.T) {
						path := "/dev/" + node
						control, _ := exec.Command(probe, "device-write", path).CombinedOutput()
						if !strings.Contains(string(control), "open=ok\n") {
							t.Fatalf("SETUP: device control %s", control)
						}
						result := runP12(t, spec, probe+" device-write "+path, nil)
						if result.setupErr != nil {
							t.Fatalf("SETUP: %+v", result)
						}
						if node == "null" {
							if result.exit != 0 || !strings.Contains(result.stdout, "write=ok\n") {
								unexpected(t, "null broke: %+v", result)
								t.FailNow()
							}
						} else if !strings.Contains(result.stdout, "open=13\n") {
							unexpected(t, "device write not EACCES: %+v", result)
						}
					})
				}
			})
			t.Run("L-TTY-NODEV", func(t *testing.T) {
				probe := buildProbe(t)
				path, fd := openPty(t)
				control, err := exec.Command(probe, "tiocexcl", path).CombinedOutput()
				mutationSetup(t, err)
				if !strings.Contains(string(control), "tiocexcl=ok\n") {
					t.Fatalf("SETUP: ioctl control %s", control)
				}
				exclusive, err := unix.IoctlGetInt(fd, unix.TIOCGEXCL)
				mutationSetup(t, err)
				if exclusive != 1 {
					t.Fatal("SETUP: TIOCEXCL had no effect")
				}
				mutationSetup(t, unix.IoctlSetInt(fd, unix.TIOCNXCL, 0))
				result := runP12(t, spec, probe+" tiocexcl "+path, nil)
				if result.setupErr != nil {
					t.Fatalf("SETUP: %+v", result)
				}
				if !strings.Contains(result.stdout, "open=13\n") {
					unexpected(t, "pty open not denied: %+v", result)
				}
				exclusive, err = unix.IoctlGetInt(fd, unix.TIOCGEXCL)
				mutationSetup(t, err)
				if exclusive != 0 {
					unexpected(t, "outside tty changed")
				}
			})
			t.Run("L-SCRATCH", func(t *testing.T) {
				file, err := os.CreateTemp("/dev/shm", "sshgate-host-")
				mutationSetup(t, err)
				_, err = file.WriteString("host-shm-canary")
				mutationSetup(t, err)
				mutationSetup(t, file.Close())
				mutationSetup(t, exec.Command("/bin/true").Run())
				t.Cleanup(func() { os.Remove(file.Name()) })
				result := runP12(t, spec, "test ! -e "+file.Name()+" && printf scratch > /dev/shm/file && test $(cat /dev/shm/file) = scratch && cp /bin/true /dev/shm/exec && /dev/shm/exec", nil)
				if result.setupErr != nil {
					t.Fatalf("SETUP: %+v", result)
				}
				if result.exit != 126 || !strings.Contains(strings.ToLower(result.stderr), "permission denied") {
					unexpected(t, "scratch isolation/noexec: %+v", result)
				}
				after, err := os.ReadFile(file.Name())
				mutationSetup(t, err)
				if string(after) != "host-shm-canary" {
					unexpected(t, "host scratch object changed")
				}
			})
			t.Run("L-WRITE-ROOT", func(t *testing.T) { legWriteSweep(t, spec, false) })
			t.Run("L-WRITE-SUBMOUNT", func(t *testing.T) { legWriteSweep(t, spec, true) })
			t.Run("L-MQUEUE", func(t *testing.T) { legMqueueCover(t, spec) })
			t.Run("L-MQUEUE-ERRNO", func(t *testing.T) { legMqueueErrno(t, spec) })
			t.Run("L-RL-CORE", func(t *testing.T) {
				probe := buildProbe(t)
				control, err := exec.Command(probe, "core-limit", "unused").CombinedOutput()
				mutationSetup(t, err)
				var soft, hard uint64
				_, err = fmt.Sscanf(strings.TrimSpace(string(control)), "core=%d:%d", &soft, &hard)
				mutationSetup(t, err)
				want := min(uint64(1), hard)
				result := runP12(t, spec, probe+" core-limit unused", nil)
				if result.setupErr != nil || result.exit != 0 || strings.TrimSpace(result.stdout) != fmt.Sprintf("core=%d:%d", want, want) {
					unexpected(t, "core limit (inherited hard=%d): %+v", hard, result)
					t.FailNow()
				}
			})
			t.Run("L-TMP-VISIBLE", func(t *testing.T) {
				file, err := os.CreateTemp("/tmp", "sshgate-visible-")
				mutationSetup(t, err)
				path := file.Name()
				t.Cleanup(func() { os.Remove(path) })
				_, err = file.WriteString("host-tmp-canary")
				mutationSetup(t, err)
				mutationSetup(t, file.Close())
				control, err := os.ReadFile(path)
				mutationSetup(t, err)
				result := runP12(t, spec, "cat "+path, nil)
				if result.setupErr != nil || result.exit != 0 || result.stdout != string(control) {
					unexpected(t, "tmp invisible: %+v", result)
					t.FailNow()
				}
			})
			t.Run("L-PS-VISIBLE", func(t *testing.T) {
				all, err := exec.Command("ps", "aux").Output()
				mutationSetup(t, err)
				if len(psRows(string(all))) <= 5 {
					t.Fatal("SETUP: host ps needs more than five processes")
				}
				command := fmt.Sprintf("ps -p %d -o comm=", os.Getpid())
				control, err := exec.Command("/bin/sh", "-c", command).Output()
				mutationSetup(t, err)
				if len(bytes.TrimSpace(control)) == 0 {
					t.Fatal("SETUP: missing host process")
				}
				for repetition := 0; repetition < 20; repetition++ {
					result := runP12(t, spec, command, nil)
					if result.setupErr != nil || result.exit != 0 || result.stdout != string(control) {
						unexpected(t, "host process invisible: %+v", result)
						t.FailNow()
					}
				}

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
	name, file := queueFixture(t)
	probe := buildProbe(t)
	result := runP12(t, spec, probe+" mq-errno "+name, func(j *Jailed) { j.Cmd.Stdin = file })
	output := requireProbeOutput(t, result, "mq_open", "mq_timedreceive")
	denied := strings.Contains(output, "mq_open=1\n") && strings.Contains(result.stdout, "mq_timedreceive=1\n")
	mutated := strings.Contains(result.stdout, "mq_open=2\n") && strings.Contains(result.stdout, "mq_timedreceive=ok\n")
	if !denied && !mutated {
		t.Fatalf("SETUP: unexpected MQ result %+v", result)
	}
	mutationEffect(t, "L-MQUEUE-ERRNO", "mq-errno", mutated)
}
func legMqueueCover(t *testing.T, spec Spec) {
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
		result := runP12(t, spec, buildProbe(t)+" mq-drain "+path, nil)
		output := requireProbeOutput(t, result, "open", "open>mq_timedreceive")
		if !strings.Contains(output, "open=2\n") && !strings.Contains(result.stdout, "mq_timedreceive=ok\n") {
			t.Fatalf("SETUP: unexpected queue result: %+v", result)
		}
		after, err := os.ReadFile(path)
		mutationSetup(t, err)
		pathDrained := !bytes.Equal(before, after)
		if count > 0 && pathDrained != drained {
			t.Fatal("SETUP: inconsistent drain observations across mqueue mounts")
		}
		drained = pathDrained
		count++
	}
	if count == 0 {
		t.Fatal("SETUP: no mqueue mount")
	}
	mutationEffect(t, "L-MQUEUE", "queue-drained", drained)
}

func legWriteSweep(t *testing.T, spec Spec, submount bool) {
	directory := writeSweepFixture(t, submount)
	seed := func() { seedWriteSweep(t, directory) }
	seed()
	probe := buildProbe(t)
	control, err := exec.Command(probe, "write-sweep", directory).CombinedOutput()
	mutationSetup(t, err)
	operations := writeSweepOperations
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
	seed()
	result := runP12(t, spec, probe+" write-sweep "+directory, nil)
	output := requireProbeOutput(t, result, operations...)
	leg := "L-WRITE-ROOT"
	if submount {
		leg = "L-WRITE-SUBMOUNT"
	}
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
	writeChanged, truncated := observeWriteSweep(t, directory)
	mutationEffect(t, leg, "write", writeChanged)
	mutationEffect(t, leg, "truncate", truncated)
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
