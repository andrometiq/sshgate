//go:build linux

package lifecycle_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"golang.org/x/sys/unix"
)

func fileStore(t *testing.T) (*lc.FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approvals")
	store, err := lc.OpenFileStore(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, path
}

func TestFileStoreConformance(t *testing.T) {
	lifecycletest.Run(t, func(t *testing.T) lc.Store { s, _ := fileStore(t); return s })
}

func TestFileStoreDurabilityAndIsolation(t *testing.T) {
	s, _ := fileStore(t)
	key, rec := record(t, 1)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	rec.Payload.ReviewSnapshot[0] = '!'
	loaded, err := s.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Payload.ReviewSnapshot[0] == '!' {
		t.Fatal("commit aliases input")
	}
	_, original := record(t, 1)
	loaded.Payload.ReviewSnapshot = []byte(`null`)
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load(key)
	if err != nil || !reflect.DeepEqual(loaded, original) {
		t.Fatalf("reload: %v", err)
	}
	if err := s.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(key); !errors.Is(err, lc.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestFileStoreHeldInodeAndOwnership(t *testing.T) {
	s, path := fileStore(t)
	key, rec := record(t, 1)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	if second, err := lc.OpenFileStore(path, uint32(os.Getuid())); err == nil {
		second.Close()
		t.Fatal("second owner admitted")
	}
	old := path + "-old"
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(key); err != nil {
		t.Fatal(err)
	}
	if second, err := lc.OpenFileStore(old, uint32(os.Getuid())); err == nil {
		second.Close()
		t.Fatal("reopen released ownership")
	}
	if _, err := os.Stat(filepath.Join(path, key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reopen used replacement path")
	}
}

func TestFileStoreQuarantine(t *testing.T) {
	s, path := fileStore(t)
	key, rec := record(t, 1)
	body := []byte(strings.Repeat("x", 400<<10))
	if err := os.WriteFile(filepath.Join(path, key), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	entries, err := s.List()
	if err != nil || len(entries) != 1 || !entries[0].Quarantined || entries[0].EncodedSize != int64(len(body)) {
		t.Fatalf("quarantine: %+v %v", entries, err)
	}
	for _, err := range []error{s.Commit(key, rec), s.Remove(key)} {
		if err == nil {
			t.Fatal("quarantine mutated")
		}
	}
	if _, err := s.Load(key); err == nil {
		t.Fatal("quarantine loaded")
	}
	got, err := os.ReadFile(filepath.Join(path, key))
	if err != nil || string(got) != string(body) {
		t.Fatal("quarantine overwritten")
	}
	if err := os.Remove(filepath.Join(path, key)); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	entries, err = s.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("removed quarantine: %v %v", entries, err)
	}
}

func TestFileStoreUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "mode", "oversize", "unknown", "wrong-key"} {
		t.Run(kind, func(t *testing.T) {
			s, path := fileStore(t)
			key, rec := record(t, 1)
			target := filepath.Join(path, key)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("missing", target)
			case "fifo":
				err = unix.Mkfifo(target, 0600)
			case "mode":
				err = os.WriteFile(target, []byte("{}"), 0644)
			case "oversize":
				err = os.WriteFile(target, make([]byte, ap.R1Max+1), 0600)
			case "unknown":
				target = filepath.Join(path, "unexpected")
				err = os.WriteFile(target, []byte("{}"), 0600)
			case "wrong-key":
				_, other := record(t, 2)
				body, e := ap.EncodeR1(other)
				if e != nil {
					t.Fatal(e)
				}
				err = os.WriteFile(target, body, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = s.Reopen()
			if kind == "wrong-key" {
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Commit(key, rec); err == nil {
					t.Fatal("key mismatch not quarantined")
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe entry accepted")
			}
			if !strings.Contains(err.Error(), filepath.Base(target)) {
				t.Fatalf("error does not name entry: %v", err)
			}
			if _, err := s.List(); err == nil {
				t.Fatal("failed reopen exposed cache")
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := s.Reopen(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFileStoreOrphanTempsAndCache(t *testing.T) {
	s, path := fileStore(t)
	temp := filepath.Join(path, ".tmp-"+strings.Repeat("a", 24))
	if err := os.WriteFile(temp, []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan remains")
	}
	key, rec := record(t, 1)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	// Breaking disk access must not break cached reads or lists.
	if err := os.Remove(filepath.Join(path, ".securestate.lock")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := s.Load(key); err != nil {
			t.Fatal(err)
		}
		if entries, err := s.List(); err != nil || len(entries) != 1 {
			t.Fatal(entries, err)
		}
	}
	if err := s.Commit(key, rec); err == nil {
		t.Fatal("write ignored broken lock")
	}
}

func TestFileStoreDirectorySafety(t *testing.T) {
	for _, kind := range []string{"mode", "owner", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "approvals")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			switch kind {
			case "mode":
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "owner":
				uid++
			case "symlink":
				link := filepath.Join(parent, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			if store, err := lc.OpenFileStore(path, uid); err == nil {
				store.Close()
				t.Fatal("unsafe journal opened")
			}
		})
	}
}

func TestFileStoreRejectsInvalidCommitWithoutChangingDisk(t *testing.T) {
	s, path := fileStore(t)
	key, rec := record(t, 1)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, key))
	if err != nil {
		t.Fatal(err)
	}
	rec.Header.Version++
	if err := s.Commit(key, rec); err == nil {
		t.Fatal("invalid record accepted")
	}
	after, err := os.ReadFile(filepath.Join(path, key))
	if err != nil || string(before) != string(after) {
		t.Fatal("invalid replacement changed file")
	}
	for _, bad := range []string{"", "../record", "r-" + strings.Repeat("!", 52)} {
		if _, err := s.Load(bad); err == nil {
			t.Fatal("invalid Load accepted")
		}
		if err := s.Remove(bad); err == nil {
			t.Fatal("invalid Remove accepted")
		}
		if err := s.Commit(bad, rec); err == nil {
			t.Fatal("invalid Commit accepted")
		}
	}
}

func TestFileStoreOwnershipProcess(t *testing.T) {
	if path := os.Getenv("SSHGATE_FILESTORE_TEST_OWNER"); path != "" {
		store, err := lc.OpenFileStore(path, uint32(os.Getuid()))
		if err == nil {
			store.Close()
			t.Fatal("second process loaded store")
		}
		if !strings.Contains(err.Error(), "is held by another signer process") {
			t.Fatal(err)
		}
		return
	}
	s, path := fileStore(t)
	key, rec := record(t, 1)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, reopened := range []bool{false, true} {
		if reopened {
			if err := s.Reopen(); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(executable, "-test.run=^TestFileStoreOwnershipProcess$")
		cmd.Env = append(os.Environ(), "SSHGATE_FILESTORE_TEST_OWNER="+path)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("second process: %v %s", err, output)
		}
		got, err := s.Load(key)
		if err != nil || !reflect.DeepEqual(got, rec) {
			t.Fatal("second process changed first owner's record", err)
		}
	}
}
