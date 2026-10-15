//go:build linux

package securestate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const orphanName = ".tmp-0123456789abcdef01234567"

func TestListNamesFreshDescriptorAndBounds(t *testing.T) {
	store, path, _ := openTestStore(t)
	if err := os.WriteFile(filepath.Join(path, orphanName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := store.Update(func(tx *Transaction) error {
		for _, name := range []string{"z", "a"} {
			if err := tx.WriteFile(name, []byte(name), 8); err != nil {
				return err
			}
		}
		for i := 0; i < 3; i++ {
			if _, err := tx.ReadFile("a", 8); err != nil {
				return err
			}
			got, err := tx.ListNames(2)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(got, []string{"a", "z"}) {
				t.Fatalf("names = %v", got)
			}
			if err := tx.WriteFile("a", []byte("a"), 8); err != nil {
				return err
			}
		}
		if names, err := tx.ListNames(1); !errors.Is(err, ErrTooLarge) || names != nil {
			t.Fatalf("over bound = %v, %v", names, err)
		}
		for _, max := range []int{0, -1} {
			if _, err := tx.ListNames(max); err == nil {
				t.Fatalf("accepted max %d", max)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force multiple getdents buffers and a second complete scan.
	if err := store.Update(func(tx *Transaction) error {
		for i := 0; i < 400; i++ {
			if err := tx.WriteFile(fmt.Sprintf("record-%03d", i), nil, 1); err != nil {
				return err
			}
		}
		for i := 0; i < 2; i++ {
			names, err := tx.ListNames(402)
			if err != nil {
				return err
			}
			if len(names) != 402 {
				t.Fatalf("names count = %d", len(names))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListNamesAndRemoveRejectUnsafeFiles(t *testing.T) {
	setups := map[string]func(string) error{
		"symlink":   func(p string) error { return os.Symlink("target", p) },
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
		"fifo":      func(p string) error { return unix.Mkfifo(p, 0o600) },
		"mode":      func(p string) error { return os.WriteFile(p, nil, 0o644) },
		"hardlink": func(p string) error {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				return err
			}
			return os.Link(p, p+"-link")
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			store, path, _ := openTestStore(t)
			if err := setup(filepath.Join(path, "bad")); err != nil {
				t.Fatal(err)
			}
			if err := store.View(func(tx *Transaction) error { _, err := tx.ListNames(10); return err }); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("ListNames = %v", err)
			}
			if err := store.Update(func(tx *Transaction) error { return tx.Remove("bad") }); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("Remove = %v", err)
			}
			if _, err := os.Lstat(filepath.Join(path, "bad")); err != nil {
				t.Fatalf("unsafe entry removed: %v", err)
			}
		})
	}
	t.Run("owner", func(t *testing.T) {
		store, path, _ := openTestStore(t)
		if err := os.WriteFile(filepath.Join(path, "bad"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Chown(filepath.Join(path, "bad"), os.Getuid()+1, -1); err != nil {
			t.Skipf("chown unavailable: %v", err)
		}
		if err := store.View(func(tx *Transaction) error { _, err := tx.ListNames(10); return err }); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("ListNames = %v", err)
		}
		if err := store.Update(func(tx *Transaction) error { return tx.Remove("bad") }); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("Remove = %v", err)
		}
	})
}

func TestRemoveDurabilityAndTransactionScope(t *testing.T) {
	store, path, parentFD := openTestStore(t)
	if err := store.Update(func(tx *Transaction) error { return tx.WriteFile("record", []byte("data"), 4) }); err != nil {
		t.Fatal(err)
	}
	if err := store.View(func(tx *Transaction) error {
		if err := tx.Remove("record"); err == nil {
			t.Fatal("read transaction removed record")
		}
		if _, err := tx.RemoveOrphanTemps(); err == nil {
			t.Fatal("read transaction removed temps")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(tx *Transaction) error {
		for _, name := range []string{"", ".", "..", "a/b", "a\x00b", lockName, orphanName, strings.Repeat("a", 256)} {
			if err := tx.Remove(name); err == nil {
				t.Fatalf("accepted name %q", name)
			}
		}
		return tx.Remove("record")
	}); err != nil {
		t.Fatal(err)
	}
	peer, err := OpenAt(parentFD, "state", uint32(os.Getuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.View(func(tx *Transaction) error { _, err := tx.ReadFile("record", 4); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed read = %v", err)
	}
	if err := store.Update(func(tx *Transaction) error { return tx.Remove("record") }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing remove = %v", err)
	}
	if err := store.Update(func(tx *Transaction) error { return tx.WriteFile("record", nil, 1) }); err != nil {
		t.Fatal(err)
	}
	store.afterUnlink = func() error { return errors.New("lost fsync acknowledgement") }
	if err := store.Update(func(tx *Transaction) error { return tx.Remove("record") }); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("uncertain remove = %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "record")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record still present: %v", err)
	}
	store.afterUnlink = nil
	if err := store.Update(func(tx *Transaction) error {
		names, err := tx.ListNames(1)
		if len(names) != 0 {
			t.Fatalf("names = %v", names)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var retained *Transaction
	if err := store.View(func(tx *Transaction) error { retained = tx; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.ListNames(1); !errors.Is(err, ErrInactiveTransaction) {
		t.Fatal(err)
	}
	if err := retained.Remove("x"); !errors.Is(err, ErrInactiveTransaction) {
		t.Fatal(err)
	}
	if _, err := retained.RemoveOrphanTemps(); !errors.Is(err, ErrInactiveTransaction) {
		t.Fatal(err)
	}
	var inactive *Transaction
	if _, err := inactive.ListNames(1); !errors.Is(err, ErrInactiveTransaction) {
		t.Fatal(err)
	}
}

func TestOrphanTempsPrevalidateAllEntries(t *testing.T) {
	cases := map[string]func(string) error{
		"short":     func(p string) error { return os.WriteFile(p+"/.tmp-bad", nil, 0o600) },
		"uppercase": func(p string) error { return os.WriteFile(p+"/.tmp-ABCDEF012345678901234567", nil, 0o600) },
		"long":      func(p string) error { return os.WriteFile(p+"/"+orphanName+"0", nil, 0o600) },
		"symlink":   func(p string) error { return os.Symlink("target", p+"/.tmp-aaaaaaaaaaaaaaaaaaaaaaaa") },
		"directory": func(p string) error { return os.Mkdir(p+"/.tmp-aaaaaaaaaaaaaaaaaaaaaaaa", 0o700) },
		"fifo":      func(p string) error { return unix.Mkfifo(p+"/.tmp-aaaaaaaaaaaaaaaaaaaaaaaa", 0o600) },
		"mode":      func(p string) error { return os.WriteFile(p+"/.tmp-aaaaaaaaaaaaaaaaaaaaaaaa", nil, 0o644) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			store, path, _ := openTestStore(t)
			if err := os.WriteFile(filepath.Join(path, orphanName), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := setup(path); err != nil {
				t.Fatal(err)
			}
			if err := store.Update(func(tx *Transaction) error {
				n, err := tx.RemoveOrphanTemps()
				if n != 0 {
					t.Fatalf("removed %d before validation", n)
				}
				return err
			}); !errors.Is(err, ErrUnsafe) {
				t.Fatalf("cleanup = %v", err)
			}
			if _, err := os.Stat(filepath.Join(path, orphanName)); err != nil {
				t.Fatalf("valid orphan deleted: %v", err)
			}
			if name == "short" || name == "uppercase" || name == "long" {
				if err := store.View(func(tx *Transaction) error { _, err := tx.ListNames(1); return err }); err == nil {
					t.Fatal("listed malformed temp")
				}
			}
		})
	}
}

func TestOrphanTempsRestrictedModesAndUncertainty(t *testing.T) {
	store, path, _ := openTestStore(t)
	for i, mode := range []os.FileMode{0, 0o200, 0o400, 0o600} {
		name := fmt.Sprintf(".tmp-%024x", i)
		if err := os.WriteFile(filepath.Join(path, name), nil, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Update(func(tx *Transaction) error {
		if err := tx.WriteFile("record", []byte("keep"), 4); err != nil {
			return err
		}
		n, err := tx.RemoveOrphanTemps()
		if n != 4 {
			t.Fatalf("removed = %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(path, "record")); err != nil || string(body) != "keep" {
		t.Fatalf("data = %q, %v", body, err)
	}
	if err := os.WriteFile(filepath.Join(path, orphanName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store.afterUnlink = func() error { return errors.New("lost sync") }
	if err := store.Update(func(tx *Transaction) error {
		n, err := tx.RemoveOrphanTemps()
		if n != 1 {
			t.Fatalf("removed = %d", n)
		}
		return err
	}); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal(err)
	}
	store.afterUnlink = nil
	if err := store.Update(func(tx *Transaction) error {
		n, err := tx.RemoveOrphanTemps()
		if n != 0 {
			t.Fatalf("removed = %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// Re-exec keeps the crash and cross-process flock checks on the real store path.
func TestNamesSubprocess(t *testing.T) {
	mode := os.Getenv("SSHGATE_NAMES_TEST_MODE")
	if mode == "" {
		return
	}
	fd, err := unix.Open(os.Getenv("SSHGATE_NAMES_TEST_PATH"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	store, err := OpenDirectory(fd, uint32(os.Getuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if mode == "crash" {
		store.beforeRename = func() error { os.Exit(23); return nil }
		_ = store.Update(func(tx *Transaction) error { return tx.WriteFile("crashed", []byte("uncommitted"), 64) })
		t.Fatal("crash hook not called")
	}
	fmt.Println("ready")
	if err := store.View(func(tx *Transaction) error {
		names, err := tx.ListNames(10)
		if err == nil && !reflect.DeepEqual(names, []string{"a", "b"}) {
			return fmt.Errorf("listing = %v", names)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func namesSubprocess(path, mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestNamesSubprocess$")
	cmd.Env = append(os.Environ(), "SSHGATE_NAMES_TEST_MODE="+mode, "SSHGATE_NAMES_TEST_PATH="+path)
	return cmd
}

func TestOrphanTempFromCrashedProcess(t *testing.T) {
	store, path, _ := openTestStore(t)
	err := namesSubprocess(path, "crash").Run()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 23 {
		t.Fatalf("child = %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	temps := 0
	for _, entry := range entries {
		if isTempName(entry.Name()) {
			temps++
		}
	}
	if temps != 1 {
		t.Fatalf("orphan count = %d", temps)
	}
	if err := store.Update(func(tx *Transaction) error {
		n, err := tx.RemoveOrphanTemps()
		if n != 1 {
			t.Fatalf("removed = %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.View(func(tx *Transaction) error {
		names, err := tx.ListNames(1)
		if len(names) != 0 {
			t.Fatalf("data = %v", names)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNamesCrossProcessFlock(t *testing.T) {
	store, path, _ := openTestStore(t)
	cmd := namesSubprocess(path, "list")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	err = store.Update(func(tx *Transaction) error {
		if err := tx.WriteFile("a", nil, 1); err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		ready := make(chan error, 1)
		go func() {
			var line [6]byte
			_, err := io.ReadFull(stdout, line[:])
			if err == nil && string(line[:]) != "ready\n" {
				err = fmt.Errorf("child ready = %q", line)
			}
			ready <- err
		}()
		select {
		case err := <-ready:
			if err != nil {
				return err
			}
		case <-time.After(10 * time.Second):
			return errors.New("child not ready")
		}
		// The child is open but cannot finish its listing until this Update releases.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			return fmt.Errorf("child bypassed flock: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		if err := tx.WriteFile("b", nil, 1); err != nil {
			return err
		}
		t.Cleanup(func() {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("child listing: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("child stuck after unlock")
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNamesPinnedDirectory(t *testing.T) {
	store, path, _ := openTestStore(t)
	original := path + "-original"
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{path, original} {
		if err := os.WriteFile(filepath.Join(dir, orphanName), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(path, "replacement"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(tx *Transaction) error {
		if err := tx.WriteFile("pinned", nil, 1); err != nil {
			return err
		}
		names, err := tx.ListNames(1)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(names, []string{"pinned"}) {
			t.Fatalf("names = %v", names)
		}
		if err := tx.Remove("pinned"); err != nil {
			return err
		}
		n, err := tx.RemoveOrphanTemps()
		if n != 1 {
			t.Fatalf("removed = %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{orphanName, "replacement"} {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatalf("replacement changed: %v", err)
		}
	}
}

func TestOrphanTempRejectsWrongOwner(t *testing.T) {
	store, path, _ := openTestStore(t)
	file := filepath.Join(path, orphanName)
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chown(file, os.Getuid()+1, -1); err != nil {
		t.Skipf("chown unavailable: %v", err)
	}
	if err := store.Update(func(tx *Transaction) error {
		n, err := tx.RemoveOrphanTemps()
		if n != 0 {
			t.Fatalf("removed = %d", n)
		}
		return err
	}); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
}
