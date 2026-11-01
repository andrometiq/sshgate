//go:build linux

package lifecycle_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"golang.org/x/sys/unix"
)

func TestFileStoreAcquisitionFatal(t *testing.T) {
	for _, kind := range []string{"parent", "path", "symlink", "mode", "special-mode", "uid", "busy"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "approvals")
			uid := uint32(os.Getuid())
			var cause error
			switch kind {
			case "parent":
				path = filepath.Join(root, "missing", "approvals")
				cause = unix.ENOENT
			case "path":
				path = "/"
			case "symlink":
				if err := os.Symlink(root, path); err != nil {
					t.Fatal(err)
				}
			case "mode", "special-mode":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0750)
				if kind == "special-mode" {
					mode = 0700 | os.ModeSticky
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				cause = securestate.ErrUnsafe
			case "uid":
				uid++
				cause = securestate.ErrUnsafe
			case "busy":
				s, err := lc.AcquireFileStore(path, uid)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				cause = unix.EWOULDBLOCK
			}
			s, err := lc.AcquireFileStore(path, uid)
			if s != nil {
				s.Close()
				t.Fatal("acquired invalid ownership")
			}
			if !errors.Is(err, lc.ErrStoreFatal) {
				t.Fatalf("not fatal: %v", err)
			}
			if cause != nil && !errors.Is(err, cause) {
				t.Fatalf("lost cause %v: %v", cause, err)
			}
		})
	}
}

func TestFileStoreReloadRecoverable(t *testing.T) {
	s, path := fileStore(t)
	if err := unix.Mkfifo(filepath.Join(path, "unexpected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err == nil || errors.Is(err, lc.ErrStoreFatal) {
		t.Fatalf("reload must be recoverable: %v", err)
	}
	if other, err := lc.AcquireFileStore(path, uint32(os.Getuid())); !errors.Is(err, lc.ErrStoreFatal) || !errors.Is(err, unix.EWOULDBLOCK) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("reload lost ownership: %v", err)
	}
	if err := os.Remove(filepath.Join(path, "unexpected")); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}
}

func TestFileStoreInitialLoadRecoverable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(path, "unexpected")
	if err := unix.Mkfifo(entry, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := lc.OpenFileStore(path, uint32(os.Getuid()))
	if s == nil || err == nil || errors.Is(err, lc.ErrStoreFatal) {
		t.Fatalf("initial load: store=%v err=%v", s, err)
	}
	defer s.Close()
	if other, err := lc.AcquireFileStore(path, uint32(os.Getuid())); !errors.Is(err, unix.EWOULDBLOCK) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("initial load lost ownership: %v", err)
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	key, rec := record(t, 1)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(key); err != nil {
		t.Fatal(err)
	}
}
