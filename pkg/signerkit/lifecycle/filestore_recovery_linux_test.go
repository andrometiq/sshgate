//go:build linux

package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"golang.org/x/sys/unix"
)

func assertFileStorePoisoned(t *testing.T, s *FileStore) {
	t.Helper()
	// Invalid and absent keys must not mask poison, nor may empty List succeed.
	for _, key := range []string{"invalid", ap.RecordKey("local-uid:1000", "a2_0000000000000000000001")} {
		_, err := s.Load(key)
		checkCode(t, err, ap.CodeStorageUncertain)
		checkCode(t, s.Commit(key, ap.R1{}), ap.CodeStorageUncertain)
		checkCode(t, s.Remove(key), ap.CodeStorageUncertain)
	}
	_, err := s.List()
	checkCode(t, err, ap.CodeStorageUncertain)
}

func TestFileStoreAcquireAndInitialFailureRetainOwnership(t *testing.T) {
	for _, load := range []bool{false, true} {
		t.Run(map[bool]string{false: "acquire", true: "open"}[load], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "approvals")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(path, "blocked")
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			constructor := AcquireFileStore
			if load {
				constructor = OpenFileStore
			}
			s, err := constructor(path, uint32(os.Getuid()))
			if s == nil {
				t.Fatalf("ownership lost: %v", err)
			}
			defer s.Close()
			if load && (err == nil || !strings.Contains(err.Error(), "blocked")) {
				t.Fatalf("missing load diagnostic: %v", err)
			}
			if !load && err != nil {
				t.Fatal(err)
			}
			assertFileStorePoisoned(t, s)
			for range 2 {
				if err := s.Reopen(); err == nil {
					t.Fatal("FIFO accepted")
				}
				assertFileStorePoisoned(t, s)
				other, err := AcquireFileStore(path, uint32(os.Getuid()))
				if other != nil {
					other.Close()
					t.Fatal("failed load released ownership")
				}
				if err == nil || !strings.Contains(err.Error(), "held by another signer") {
					t.Fatal(err)
				}
			}
			held := path + "-held"
			if err := os.Rename(path, held); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(held, "blocked")); err != nil {
				t.Fatal(err)
			}
			if err := s.Reopen(); err != nil {
				t.Fatal(err)
			}
			key, rec := fileRecordFixture(t)
			if err := s.Commit(key, rec); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(held, key)); err != nil {
				t.Fatal("lost held inode", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			checkCode(t, s.Reopen(), ap.CodeLifecycleUnavailable)
			next, err := OpenFileStore(held, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			if _, err := next.Load(key); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFileStoreCloseWithoutSuccessfulLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals")
	first, err := AcquireFileStore(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := AcquireFileStore(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal("Close retained ownership", err)
	}
	defer next.Close()
	assertFileStorePoisoned(t, next)
	if err := next.Reopen(); err != nil {
		t.Fatal(err)
	}
	if entries, err := next.List(); err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
}
