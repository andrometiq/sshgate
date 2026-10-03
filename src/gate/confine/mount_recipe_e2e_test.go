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
								t.Fatalf("null broke: %+v", result)
							}
						} else if !strings.Contains(result.stdout, "open=13\n") {
							t.Errorf("device write not EACCES: %+v", result)
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
					t.Errorf("pty open not denied: %+v", result)
				}
				exclusive, err = unix.IoctlGetInt(fd, unix.TIOCGEXCL)
				mutationSetup(t, err)
				if exclusive != 0 {
					t.Error("outside tty changed")
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
					t.Errorf("scratch isolation/noexec: %+v", result)
				}
				after, err := os.ReadFile(file.Name())
				mutationSetup(t, err)
				if string(after) != "host-shm-canary" {
					t.Error("host scratch object changed")
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
					t.Fatalf("core limit (inherited hard=%d): %+v", hard, result)
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
					t.Fatalf("tmp invisible: %+v", result)
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
				result := runP12(t, spec, command, nil)
				if result.setupErr != nil || result.exit != 0 || result.stdout != string(control) {
					t.Fatalf("host process invisible: %+v", result)
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
	if result.setupErr != nil {
		t.Fatalf("SETUP: %+v", result)
	}
	denied := strings.Contains(result.stdout, "mq_open=1\n") && strings.Contains(result.stdout, "mq_timedreceive=1\n")
	mutated := strings.Contains(result.stdout, "mq_open=2\n") && strings.Contains(result.stdout, "mq_timedreceive=ok\n")
	if !denied && !mutated {
		t.Fatalf("SETUP: unexpected MQ result %+v", result)
	}
	mutationEffect(t, "L-MQUEUE-ERRNO", "mq-errno", mutated)
}
func legMqueueCover(t *testing.T, spec Spec) {
	name, _ := queueFixture(t)
	entries, err := readMountInfo()
	mutationSetup(t, err)
	count := 0
	for _, entry := range entries {
		if entry.fstype != "mqueue" {
			continue
		}
		path := filepath.Join(entry.point, name)
		before, err := os.ReadFile(path)
		mutationSetup(t, err)
		if !strings.Contains(string(before), "QSIZE:6") {
			t.Fatalf("SETUP: queue not populated: %s", before)
		}
		result := runP12(t, spec, buildProbe(t)+" mq-drain "+path, nil)
		if result.setupErr != nil {
			t.Fatalf("SETUP: %+v", result)
		}
		if !strings.Contains(result.stdout, "open=2\n") {
			t.Errorf("queue was not covered: %+v", result)
		}
		after, err := os.ReadFile(path)
		mutationSetup(t, err)
		if !bytes.Equal(before, after) {
			t.Error("host queue changed")
		}
		count++
	}
	if count == 0 {
		t.Fatal("SETUP: no mqueue mount")
	}
}

func legWriteSweep(t *testing.T, spec Spec, submount bool) {
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
	seed := func() {
		mutationSetup(t, os.RemoveAll(directory))
		mutationSetup(t, os.Mkdir(directory, 0700))
		for _, name := range []string{"file", "remove", "move"} {
			mutationSetup(t, os.WriteFile(filepath.Join(directory, name), []byte("canary"), 0600))
		}
		mutationSetup(t, os.Mkdir(filepath.Join(directory, "empty"), 0700))
	}
	seed()
	probe := buildProbe(t)
	control, err := exec.Command(probe, "write-sweep", directory).CombinedOutput()
	mutationSetup(t, err)
	operations := []string{"write", "append", "open-trunc", "open-rdonly-trunc", "truncate-path", "unlink", "rmdir", "mkdir", "symlink", "link", "rename", "mkfifo"}
	for _, name := range operations {
		if !strings.Contains(string(control), name+"=ok\n") {
			t.Fatalf("SETUP: control %s", control)
		}
	}
	seed()
	result := runP12(t, spec, probe+" write-sweep "+directory, nil)
	if result.setupErr != nil {
		t.Fatalf("SETUP: %+v", result)
	}
	for _, name := range operations {
		if !strings.Contains(result.stdout, name+"=30\n") {
			t.Errorf("%s expected EROFS at ABI %d: %+v", name, spec.ForceABI, result)
		}
	}
	entries, err := os.ReadDir(directory)
	mutationSetup(t, err)
	if len(entries) != 4 {
		t.Errorf("directory changed: %v", entries)
	}
	for _, name := range []string{"file", "remove", "move"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		mutationSetup(t, err)
		if string(data) != "canary" {
			t.Errorf("%s changed", name)
		}
	}
}
