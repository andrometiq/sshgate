//go:build linux

package executor

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	"golang.org/x/sys/unix"
)

func roots(t *testing.T) (string, string) {
	t.Helper()
	// Unix socket paths have a small fixed maximum.
	root, err := os.MkdirTemp("/tmp", "executor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, config := filepath.Join(root, "run"), filepath.Join(root, "config")
	for _, p := range []string{runtime, config} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return runtime, config
}

func openLocal(t *testing.T, runtime, config string) *Local {
	t.Helper()
	l, err := OpenLocal(runtime, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	return l
}

func TestLockChild(t *testing.T) {
	if os.Getenv("EXECUTOR_LOCK_CHILD") != "1" {
		return
	}
	l, err := OpenLocal(os.Getenv("EXECUTOR_RUNTIME"), os.Getenv("EXECUTOR_CONFIG"))
	if err == nil {
		l.Close()
		t.Fatal("second process acquired locks")
	}
	if !strings.Contains(err.Error(), os.Getenv("EXECUTOR_EXPECT")) {
		t.Fatalf("unexpected startup refusal: %v", err)
	}
}

func TestProcessLocks(t *testing.T) {
	runtime, config := roots(t)
	l := openLocal(t, runtime, config)
	otherRuntime, otherConfig := roots(t)
	alias := filepath.Join(otherConfig, "alias")
	if err := os.Symlink(filepath.Dir(config), alias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, runtime, config, want string }{
		{"singleton", runtime, otherConfig, "singleton is held"},
		{"ownership", otherRuntime, config, filepath.Join(config, "executor") + " is held"},
		{"symlink-parent", otherRuntime, filepath.Join(alias, "config"), "is held"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestLockChild$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "EXECUTOR_LOCK_CHILD=1", "EXECUTOR_RUNTIME="+tc.runtime, "EXECUTOR_CONFIG="+tc.config, "EXECUTOR_EXPECT="+tc.want)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	openLocal(t, runtime, config)
}

func TestOwnershipSurvivesStoreCloseAndRename(t *testing.T) {
	runtime, config := roots(t)
	l := openLocal(t, runtime, config)
	store, err := l.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(tx *securestate.Transaction) error { return tx.WriteFile("job", []byte("original"), 100) }); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(config, "executor")
	moved := filepath.Join(config, "moved")
	if err := os.Rename(old, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(old, 0700); err != nil {
		t.Fatal(err)
	}
	store, err = l.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.View(func(tx *securestate.Transaction) error {
		b, err := tx.ReadFile("job", 100)
		if string(b) != "original" {
			t.Errorf("reopened replacement: %q", b)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(moved, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("ownership lost: %v", err)
	}
}

func TestSocketPeers(t *testing.T) {
	for _, kind := range []string{"same", "foreign", "unverifiable"} {
		t.Run(kind, func(t *testing.T) {
			runtime, config := roots(t)
			l := openLocal(t, runtime, config)
			if kind == "foreign" {
				l.peerUID = func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()) + 1, nil }
			}
			if kind == "unverifiable" {
				l.peerUID = func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()), unix.EBADF }
			}
			for path, mode := range map[string]os.FileMode{filepath.Join(runtime, "sshgate"): 0700, filepath.Join(runtime, "sshgate", "executor.sock"): 0600} {
				st, err := os.Stat(path)
				if err != nil || st.Mode().Perm() != mode {
					t.Fatalf("posture %s: %v %v", path, st, err)
				}
			}
			client, err := net.Dial("unix", filepath.Join(runtime, "sshgate", "executor.sock"))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := l.AcceptUnix()
			if kind == "same" {
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := conn.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				var b [2]byte
				n, err := client.Read(b[:])
				if err != nil || string(b[:n]) != "ok" {
					t.Fatalf("accepted connection unusable: %q %v", b, err)
				}
			} else {
				if conn != nil {
					conn.Close()
					t.Fatal("unauthorized connection returned")
				}
				if err == nil {
					t.Fatal("missing refusal")
				}
				var b [1]byte
				if _, err := client.Read(b[:]); err == nil {
					t.Fatal("peer not closed")
				} else if e, ok := err.(net.Error); ok && e.Timeout() {
					t.Fatal("peer left open")
				}
			}
		})
	}
}

func TestUnsafeObjects(t *testing.T) {
	for _, kind := range []string{"runtime-mode", "store-mode", "store-symlink", "singleton-symlink", "socket-file"} {
		t.Run(kind, func(t *testing.T) {
			runtime, config := roots(t)
			if err := os.Mkdir(filepath.Join(runtime, "sshgate"), 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "runtime-mode":
				os.Chmod(filepath.Join(runtime, "sshgate"), 0755)
			case "store-mode":
				os.Mkdir(filepath.Join(config, "executor"), 0755)
			case "store-symlink":
				os.Symlink(runtime, filepath.Join(config, "executor"))
			case "singleton-symlink":
				os.Symlink(filepath.Join(config, "target"), filepath.Join(runtime, "sshgate", "executor.lock"))
			case "socket-file":
				os.WriteFile(filepath.Join(runtime, "sshgate", "executor.sock"), []byte("keep"), 0600)
			}
			l, err := OpenLocal(runtime, config)
			if err == nil {
				l.Close()
				t.Fatal("unsafe object accepted")
			}
			if kind == "socket-file" {
				b, err := os.ReadFile(filepath.Join(runtime, "sshgate", "executor.sock"))
				if err != nil || string(b) != "keep" {
					t.Fatal("non-socket removed")
				}
			}
		})
	}
}

func TestLockErrorsFatal(t *testing.T) {
	err := lock(-1, "jobs")
	if !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "local filesystem") {
		t.Fatalf("%v", err)
	}
}

func TestStaleSocketAndFailedStartupRelease(t *testing.T) {
	runtime, config := roots(t)
	os.Mkdir(filepath.Join(runtime, "sshgate"), 0700)
	path := filepath.Join(runtime, "sshgate", "executor.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(config, "executor"), 0755)
	if l, err := OpenLocal(runtime, config); err == nil {
		l.Close()
		t.Fatal("unsafe store accepted")
	}
	if err := os.Chmod(filepath.Join(config, "executor"), 0700); err != nil {
		t.Fatal(err)
	}
	openLocal(t, runtime, config)
}

func TestSingletonPosture(t *testing.T) {
	for _, kind := range []string{"mode", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			runtime, config := roots(t)
			os.Mkdir(filepath.Join(runtime, "sshgate"), 0700)
			path := filepath.Join(runtime, "sshgate", "executor.lock")
			var err error
			switch kind {
			case "mode":
				err = os.WriteFile(path, nil, 0644)
			case "hardlink":
				err = os.WriteFile(path, nil, 0600)
				if err == nil {
					err = os.Link(path, filepath.Join(runtime, "alias"))
				}
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if l, err := OpenLocal(runtime, config); err == nil {
				l.Close()
				t.Fatal("unsafe singleton accepted")
			}
		})
	}
}

func TestAbsoluteRootsRequired(t *testing.T) {
	runtime, config := roots(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeRuntime, err := filepath.Rel(cwd, runtime)
	if err != nil {
		t.Fatal(err)
	}
	relativeConfig, err := filepath.Rel(cwd, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, roots := range [][2]string{{relativeRuntime, config}, {runtime, relativeConfig}} {
		if l, err := OpenLocal(roots[0], roots[1]); err == nil {
			l.Close()
			t.Fatal("relative root accepted")
		}
	}
}
