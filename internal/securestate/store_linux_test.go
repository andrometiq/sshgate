//go:build linux

package securestate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type testRecord struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

func openTestStore(t testing.TB) (*Store, string, int) {
	t.Helper()
	parent := t.TempDir()
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(parentFD) })
	store, err := OpenAt(parentFD, "state", uint32(os.Getuid()), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, filepath.Join(parent, "state"), parentFD
}

func TestStoreCanonicalRoundTripAndExactModes(t *testing.T) {
	store, path, _ := openTestStore(t)
	want := testRecord{Name: "request", Version: 3}
	var written []byte
	if err := store.Update(func(tx *Transaction) error {
		var err error
		written, err = tx.WriteCanonicalJSON("request.json", want, 1024)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if string(written) != `{"name":"request","version":3}` {
		t.Fatalf("canonical bytes = %q", written)
	}
	info, err := os.Stat(filepath.Join(path, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %04o; want 0600", info.Mode().Perm())
	}
	rootInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %04o; want 0700", rootInfo.Mode().Perm())
	}

	var got testRecord
	if err := store.View(func(tx *Transaction) error {
		body, err := tx.ReadCanonicalJSON("request.json", 1024, &got)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, written) {
			t.Fatalf("read bytes = %q; want %q", body, written)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("record = %#v; want %#v", got, want)
	}
}

func TestStoreRejectsNoncanonicalUnknownAndOversizeJSON(t *testing.T) {
	store, path, _ := openTestStore(t)
	file := filepath.Join(path, "request.json")
	cases := map[string]string{
		"duplicate":  `{"name":"one","name":"two","version":1}`,
		"unknown":    `{"name":"one","version":1,"extra":true}`,
		"whitespace": ` {"name":"one","version":1}`,
		"reordered":  `{"version":1,"name":"one"}`,
		"trailing":   `{"name":"one","version":1}{}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			var got testRecord
			if err := store.View(func(tx *Transaction) error {
				_, err := tx.ReadCanonicalJSON("request.json", 1024, &got)
				return err
			}); err == nil {
				t.Fatalf("accepted %s JSON", name)
			}
		})
	}
	if err := os.WriteFile(file, []byte(`{"name":"one","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.View(func(tx *Transaction) error {
		_, err := tx.ReadFile("request.json", 4)
		return err
	}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize error = %v; want ErrTooLarge", err)
	}
}

func TestStoreRejectsUnsafeDirectoryAndFiles(t *testing.T) {
	t.Run("wrong expected owner", func(t *testing.T) {
		parent := t.TempDir()
		fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if _, err := OpenDirectory(fd, uint32(os.Getuid()+1), true); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("error = %v; want ErrUnsafe", err)
		}
	})

	tests := map[string]func(t *testing.T, path string){
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink("target", filepath.Join(path, "bad")); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, path string) {
			if err := unix.Mkfifo(filepath.Join(path, "bad"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, path string) {
			if err := os.WriteFile(filepath.Join(path, "bad"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(path, "bad"), filepath.Join(path, "other")); err != nil {
				t.Fatal(err)
			}
		},
		"wrong mode": func(t *testing.T, path string) {
			if err := os.WriteFile(filepath.Join(path, "bad"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			store, path, _ := openTestStore(t)
			setup(t, path)
			err := store.View(func(tx *Transaction) error {
				_, err := tx.ReadFile("bad", 16)
				return err
			})
			if !errors.Is(err, ErrUnsafe) {
				t.Fatalf("error = %v; want ErrUnsafe", err)
			}
		})
	}
}

func TestStorePinsParentDirectoryAcrossPathReplacement(t *testing.T) {
	store, path, _ := openTestStore(t)
	parent := filepath.Dir(path)
	original := filepath.Join(parent, "original-state")
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(tx *Transaction) error {
		return tx.WriteFile("pinned", []byte("old inode"), 64)
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(original, "pinned")); err != nil || string(got) != "old inode" {
		t.Fatalf("pinned directory body = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(path, "pinned")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory was written: %v", err)
	}
}

func TestStoreRejectsReplacedLockInode(t *testing.T) {
	store, path, _ := openTestStore(t)
	if err := os.Rename(filepath.Join(path, lockName), filepath.Join(path, "old-lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, lockName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := store.Update(func(tx *Transaction) error {
		return tx.WriteFile("must-not-write", []byte("x"), 1)
	})
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("error = %v; want ErrUnsafe", err)
	}
	if _, err := os.Stat(filepath.Join(path, "must-not-write")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("write occurred after lock replacement: %v", err)
	}
}

func TestStoreFlockSerializesIndependentInstances(t *testing.T) {
	first, path, _ := openTestStore(t)
	dirFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	second, err := OpenDirectory(dirFD, uint32(os.Getuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.Update(func(*Transaction) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- second.Update(func(*Transaction) error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second Store entered while first held flock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second Store did not enter after flock release")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestStoreAtomicReplaceIsOldOrNewAndCleansTempOnFailure(t *testing.T) {
	store, path, _ := openTestStore(t)
	oldBody := bytes.Repeat([]byte("o"), 128<<10)
	newBody := bytes.Repeat([]byte("n"), 128<<10)
	if err := store.Update(func(tx *Transaction) error {
		return tx.WriteFile("record", oldBody, len(oldBody))
	}); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected before rename")
	store.beforeRename = func() error { return injected }
	err := store.Update(func(tx *Transaction) error {
		return tx.WriteFile("record", newBody, len(newBody))
	})
	if !errors.Is(err, injected) {
		t.Fatalf("injected error = %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(path, "record")); err != nil || !bytes.Equal(got, oldBody) {
		t.Fatalf("failed replacement exposed non-old body: len=%d err=%v", len(got), err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("failed replacement leaked temp %q", entry.Name())
		}
	}

	store.beforeRename = nil
	var sawInvalid atomic.Bool
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			body, err := os.ReadFile(filepath.Join(path, "record"))
			if err != nil || (!bytes.Equal(body, oldBody) && !bytes.Equal(body, newBody)) {
				sawInvalid.Store(true)
				return
			}
		}
	}()
	if err := store.Update(func(tx *Transaction) error {
		return tx.WriteFile("record", newBody, len(newBody))
	}); err != nil {
		close(stop)
		<-done
		t.Fatal(err)
	}
	close(stop)
	<-done
	if sawInvalid.Load() {
		t.Fatal("concurrent path reader observed torn/missing body")
	}
	if got, err := os.ReadFile(filepath.Join(path, "record")); err != nil || !bytes.Equal(got, newBody) {
		t.Fatalf("successful replacement did not expose new body: len=%d err=%v", len(got), err)
	}
}

func TestStoreTransactionScopeNamesAndClose(t *testing.T) {
	store, _, _ := openTestStore(t)
	var retained *Transaction
	if err := store.View(func(tx *Transaction) error {
		retained = tx
		if err := tx.WriteFile("nope", []byte("x"), 1); err == nil {
			t.Fatal("View allowed mutation")
		}
		for _, name := range []string{"", ".", "..", "a/b", lockName, ".tmp-owned"} {
			if _, err := tx.ReadFile(name, 1); err == nil {
				t.Fatalf("unsafe/reserved name %q accepted", name)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.ReadFile("x", 1); !errors.Is(err, ErrInactiveTransaction) {
		t.Fatalf("retained transaction error = %v; want ErrInactiveTransaction", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.View(func(*Transaction) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Store error = %v; want ErrClosed", err)
	}
}
