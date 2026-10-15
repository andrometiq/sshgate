//go:build linux && jail_e2e

package confine

import (
	"debug/elf"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// lane2Held opens path as the gate holds an admitted object and returns its
// identity.
func lane2Held(t *testing.T, path string, flags int) (*os.File, FileID) {
	t.Helper()
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), path)
	t.Cleanup(func() { file.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return file, FileID{Dev: uint64(st.Dev), Ino: st.Ino}
}

// lane2Client admits path as a "docker" client with one socket at socket.
func lane2Client(t *testing.T, path, socket string) *Lane2 {
	t.Helper()
	binary, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := elf.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	l := &Lane2{Client: "docker", Binary: binary}
	l.BinaryFile, l.BinaryID = lane2Held(t, binary, unix.O_RDONLY)
	for _, ph := range executable.Progs {
		if ph.Type == elf.PT_INTERP {
			raw := make([]byte, ph.Filesz)
			if _, err := ph.ReadAt(raw, 0); err != nil {
				t.Fatal(err)
			}
			if l.Interp, err = filepath.EvalSymlinks(strings.TrimRight(string(raw), "\x00")); err != nil {
				t.Fatal(err)
			}
			l.InterpFile, l.InterpID = lane2Held(t, l.Interp, unix.O_RDONLY)
		}
	}
	file, id := lane2Held(t, socket, unix.O_PATH)
	l.Sockets = []Endpoint{{Path: socket, ID: id, File: file}}
	return l
}

// lane2MemfdClient builds a client that reports memfd_create's result.
func lane2MemfdClient(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "memfd.c"), filepath.Join(dir, "memfd")
	program := "#define _GNU_SOURCE\n#include <errno.h>\n#include <stdio.h>\n#include <string.h>\n#include <sys/mman.h>\n" +
		"int main(void) { int fd = memfd_create(\"sg\", 0); printf(\"memfd:%s\\n\", fd < 0 ? strerror(errno) : \"created\"); return 0; }\n"
	if err := os.WriteFile(source, []byte(program), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cc", "-O2", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("SETUP: cc: %v: %s", err, output)
	}
	return binary
}

// lane2Listen binds a listener at dir/name.
func lane2Listen(t *testing.T, dir, name string) (string, net.Listener) {
	t.Helper()
	path := filepath.Join(dir, name)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return path, listener
}

// TestLane2WorkerJail: the worker runs a daemon read's admitted client, with
// the argv from fd 3 and Lane2Env, after checking every admitted inode inside
// the jail's view; any mismatch fails at its own stage and nothing runs.
func TestLane2WorkerJail(t *testing.T) {
	requireJailHost(t)
	for _, abi := range []int{0, 1} {
		t.Run(map[int]string{0: "native", 1: "abi1"}[abi], func(t *testing.T) {
			dir, err := os.MkdirTemp("", "l2w-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			socket, listener := lane2Listen(t, dir, "s")
			defer listener.Close()
			run := func(lane2 *Lane2, argv ...string) jailResult {
				spec := Spec{Profile: ProfileROv1, Cwd: "/", ForceABI: abi, Lane2: lane2}
				return runJailedTimeout(t, spec, EncodeArgv(append([]string{"/usr/bin/docker"}, argv...)), 30*time.Second)
			}
			stage := func(result jailResult) string {
				var setup *SetupError
				if errors.As(result.setupErr, &setup) {
					return setup.Stage + ":" + setup.Errno.Error()
				}
				return ""
			}

			result := run(lane2Client(t, "/usr/bin/env", socket), "--")
			if result.setupErr != nil || result.exit != 0 || result.stdout != strings.Join(Lane2Env(), "\n")+"\n" {
				t.Fatalf("env client: exit=%d setup=%v stdout=%q stderr=%q", result.exit, result.setupErr, result.stdout, result.stderr)
			}
			result = run(lane2Client(t, "/usr/bin/ls", socket), "/proc/self/fd")
			if result.setupErr != nil || result.stdout != "0\n1\n2\n3\n" {
				t.Fatalf("held references reached the client: setup=%v fds=%q", result.setupErr, result.stdout)
			}

			client := lane2Client(t, "/usr/bin/env", socket)
			spec := Spec{Profile: ProfileROv1, Cwd: "/", ForceABI: abi, Lane2: client}
			result = runJailedTimeout(t, spec, EncodeArgv([]string{"/usr/bin/systemctl", "status"}), 30*time.Second)
			if got := stage(result); got != "lane2argv:"+syscall.EINVAL.Error() || result.stdout != "" {
				t.Errorf("argv for another client: %s %q", got, result.stdout)
			}

			wrongID := lane2Client(t, "/usr/bin/env", socket)
			wrongID.BinaryID.Ino++
			other := lane2Client(t, "/usr/bin/env", socket)
			other.BinaryFile, _ = lane2Held(t, "/usr/bin/true", unix.O_RDONLY)
			notSocket := lane2Client(t, "/usr/bin/env", socket)
			regular := filepath.Join(dir, "regular")
			if err := os.WriteFile(regular, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			notSocket.Sockets[0].File, notSocket.Sockets[0].ID = lane2Held(t, regular, unix.O_PATH)
			notSocket.Sockets[0].Path = regular
			replaced := lane2Client(t, "/usr/bin/env", socket)
			for name, lane2 := range map[string]*Lane2{"binary ID": wrongID, "held binary": other, "file as socket": notSocket} {
				if got := run(lane2, "--"); stage(got) != "lane2id:"+syscall.ESTALE.Error() || got.stdout != "" {
					t.Errorf("%s: %s %q", name, stage(got), got.stdout)
				}
			}
			// The admitted socket is closed and unlinked, and a new one takes its
			// path; the held reference keeps the old inode, so they differ.
			listener.Close()
			_ = os.Remove(socket)
			_, again := lane2Listen(t, dir, "s")
			defer again.Close()
			if got := run(replaced, "--"); stage(got) != "lane2id:"+syscall.ESTALE.Error() || got.stdout != "" {
				t.Errorf("replaced socket: %s %q", stage(got), got.stdout)
			}

			// Narrow EXECUTE: the admitted client cannot run another program.
			got := run(lane2Client(t, "/usr/bin/env", socket), "/usr/bin/true")
			if got.setupErr != nil || got.exit != 126 || !strings.Contains(got.stderr, "Permission denied") {
				t.Errorf("client exec of another program: exit=%d setup=%v stderr=%q", got.exit, got.setupErr, got.stderr)
			}

			// A daemon read cannot create a memfd (no anonymous executable past
			// narrow EXECUTE).
			if got := run(lane2Client(t, lane2MemfdClient(t), socket), "--"); got.setupErr != nil || got.stdout != "memfd:Operation not permitted\n" {
				t.Errorf("memfd_create in a daemon read: setup=%v stdout=%q stderr=%q", got.setupErr, got.stdout, got.stderr)
			}

			// A daemon read reaches its admitted daemon over a Unix stream socket,
			// and, from Landlock ABI 9, no other socket.
			systemctl := func(sockets ...string) jailResult {
				l := lane2Client(t, "/usr/bin/systemctl", sockets[0])
				l.Client = "systemctl"
				for _, path := range sockets[1:] {
					file, id := lane2Held(t, path, unix.O_PATH)
					l.Sockets = append(l.Sockets, Endpoint{Path: path, ID: id, File: file})
				}
				spec := Spec{Profile: ProfileROv1, Cwd: "/", ForceABI: abi, Lane2: l}
				return runJailedTimeout(t, spec, EncodeArgv([]string{"/usr/bin/systemctl", "--no-pager", "is-system-running"}), 30*time.Second)
			}
			endpoints := []string{"/run/dbus/system_bus_socket"}
			if os.Geteuid() == 0 {
				endpoints = append(endpoints, "/run/systemd/private")
			}
			direct := exec.Command("/usr/bin/systemctl", "--no-pager", "is-system-running")
			direct.Env, direct.Dir = Lane2Env(), "/"
			want, _ := direct.Output()
			if got := systemctl(endpoints...); got.setupErr != nil || got.stdout != string(want) || strings.Contains(got.stderr, "Failed to connect") {
				t.Errorf("admitted daemon: stdout=%q want %q setup=%v stderr=%q", got.stdout, want, got.setupErr, got.stderr)
			}
			native, _ := probeLandlockABI()
			got = systemctl(socket)
			// systemd words the refusal differently across versions.
			if pinned := abi == 0 && native >= 9; pinned != strings.Contains(got.stderr, "Failed to connect") || pinned == (got.stdout == string(want)) {
				t.Errorf("unadmitted daemon at ABI %d (pinned=%t): stdout=%q stderr=%q", native, pinned, got.stdout, got.stderr)
			}
		})
	}
}
