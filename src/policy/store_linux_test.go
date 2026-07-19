//go:build linux

package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

const storeTestHost = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type storeFixture struct {
	dir   string
	dirFD int
	cfg   StoreConfig
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	store *Store
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(dirFD) })
	cfg := StoreConfig{ExpectedUID: uint32(os.Geteuid()), DirectoryMode: 0o700, FileMode: 0o600}
	store, err := InitializeStore(dirFD, cfg, pub, storeTestHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &storeFixture{dir: dir, dirFD: dirFD, cfg: cfg, pub: pub, priv: priv, store: store}
}

func testManifest(epoch, revision uint64) BaseManifest {
	return BaseManifest{
		Schema:     SchemaV1,
		Host:       storeTestHost,
		Epoch:      epoch,
		MissAction: MissActionAsk,
		Growth:     GrowthOutOfBand,
		Revision:   revision,
	}
}

func signTestManifest(t *testing.T, privateKey ed25519.PrivateKey, manifest BaseManifest) []byte {
	t.Helper()
	envelope, err := SignBaseManifest(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func replaceTestBase(t *testing.T, fixture *storeFixture, epoch, revision uint64) []byte {
	t.Helper()
	envelope := signTestManifest(t, fixture.priv, testManifest(epoch, revision))
	if _, err := fixture.store.ReplaceBase(envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func writePolicyFile(t *testing.T, fixture *storeFixture, name string, body []byte) {
	t.Helper()
	path := filepath.Join(fixture.dir, name)
	if err := os.WriteFile(path, body, fixture.cfg.FileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, fixture.cfg.FileMode); err != nil {
		t.Fatal(err)
	}
}

func TestStoreInitializeReplaceLoadAndReopen(t *testing.T) {
	fixture := newStoreFixture(t)
	if _, err := fixture.store.LoadBase(); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("LoadBase before initialization error = %v, want ErrPolicyNotFound", err)
	}

	first := replaceTestBase(t, fixture, 1, 1)
	loaded, err := fixture.store.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manifest.Epoch != 1 || loaded.Manifest.Revision != 1 || loaded.Manifest.Host != storeTestHost {
		t.Fatalf("unexpected loaded manifest: %+v", loaded.Manifest)
	}
	payload, _, err := DecodeBaseManifestEnvelope(first)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := BaseManifestPayloadDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Digest != wantDigest {
		t.Fatal("loaded digest does not bind exact canonical payload")
	}

	for _, name := range []string{lockFile, anchorFile, manifestFile} {
		info, err := os.Stat(filepath.Join(fixture.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != fixture.cfg.FileMode {
			t.Fatalf("%s mode = %04o, want %04o", name, got, fixture.cfg.FileMode)
		}
	}
	matches, err := filepath.Glob(filepath.Join(fixture.dir, ".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain after replacement: %v", matches)
	}

	reopened, err := OpenStore(fixture.dirFD, fixture.cfg, fixture.pub, storeTestHost)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.LoadBase(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsUnsafeFiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *storeFixture)
	}{
		{
			name: "insecure mode",
			mutate: func(t *testing.T, f *storeFixture) {
				if err := os.Chmod(filepath.Join(f.dir, manifestFile), 0o660); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, f *storeFixture) {
				path := filepath.Join(f.dir, manifestFile)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(anchorFile, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "fifo",
			mutate: func(t *testing.T, f *storeFixture) {
				path := filepath.Join(f.dir, manifestFile)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, uint32(f.cfg.FileMode)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, f *storeFixture) {
				if err := os.Link(filepath.Join(f.dir, manifestFile), filepath.Join(f.dir, "second-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			mutate: func(t *testing.T, f *storeFixture) {
				writePolicyFile(t, f, manifestFile, make([]byte, MaxPolicyEnvelopeBytes+1))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newStoreFixture(t)
			replaceTestBase(t, fixture, 1, 1)
			tt.mutate(t, fixture)
			_, err := fixture.store.LoadBase()
			if tt.name == "oversized" {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("LoadBase error = %v, want ErrTooLarge", err)
				}
			} else if !errors.Is(err, ErrUnsafePolicyFile) {
				t.Fatalf("LoadBase error = %v, want ErrUnsafePolicyFile", err)
			}
		})
	}
}

func TestStoreRejectsWrongOwnerWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	fixture := newStoreFixture(t)
	replaceTestBase(t, fixture, 1, 1)
	if err := os.Chown(filepath.Join(fixture.dir, manifestFile), 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.LoadBase(); !errors.Is(err, ErrUnsafePolicyFile) {
		t.Fatalf("LoadBase error = %v, want ErrUnsafePolicyFile", err)
	}
}

func TestStoreVerifiesSignatureAndHostBeforeUse(t *testing.T) {
	t.Run("wrong signing key", func(t *testing.T) {
		fixture := newStoreFixture(t)
		replaceTestBase(t, fixture, 1, 1)
		_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		writePolicyFile(t, fixture, manifestFile, signTestManifest(t, wrongPrivate, testManifest(1, 1)))
		if _, err := fixture.store.LoadBase(); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("LoadBase error = %v, want ErrBadSignature", err)
		}
	})

	t.Run("wrong host", func(t *testing.T) {
		fixture := newStoreFixture(t)
		replaceTestBase(t, fixture, 1, 1)
		manifest := testManifest(1, 1)
		manifest.Host = "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		writePolicyFile(t, fixture, manifestFile, signTestManifest(t, fixture.priv, manifest))
		if _, err := fixture.store.LoadBase(); err == nil || !strings.Contains(err.Error(), "does not match expected host") {
			t.Fatalf("LoadBase error = %v, want host mismatch", err)
		}
	})
}

func TestStoreRollbackAndSameVersionConflict(t *testing.T) {
	fixture := newStoreFixture(t)
	replaceTestBase(t, fixture, 3, 7)

	older := signTestManifest(t, fixture.priv, testManifest(3, 6))
	if _, err := fixture.store.ReplaceBase(older); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("ReplaceBase older error = %v, want ErrPolicyRollback", err)
	}
	writePolicyFile(t, fixture, manifestFile, older)
	if _, err := fixture.store.LoadBase(); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("LoadBase replayed older error = %v, want ErrPolicyRollback", err)
	}

	// Restore the pinned manifest, then prove that a distinct signed payload
	// cannot reuse its epoch/revision.
	current := signTestManifest(t, fixture.priv, testManifest(3, 7))
	writePolicyFile(t, fixture, manifestFile, current)
	conflictManifest := testManifest(3, 7)
	conflictManifest.MissAction = MissActionDeny
	conflictManifest.Growth = GrowthNone
	conflict := signTestManifest(t, fixture.priv, conflictManifest)
	if _, err := fixture.store.ReplaceBase(conflict); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("ReplaceBase same-version conflict error = %v, want ErrPolicyConflict", err)
	}

	// A new epoch may restart the revision counter.
	if _, err := fixture.store.ReplaceBase(signTestManifest(t, fixture.priv, testManifest(4, 1))); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCrashBetweenAnchorAndManifestFailsClosedAndResumes(t *testing.T) {
	fixture := newStoreFixture(t)
	replaceTestBase(t, fixture, 1, 1)
	next := signTestManifest(t, fixture.priv, testManifest(1, 2))
	crash := errors.New("injected crash after anchor fsync")
	fixture.store.afterAnchor = func() error { return crash }
	if _, err := fixture.store.ReplaceBase(next); !errors.Is(err, crash) {
		t.Fatalf("ReplaceBase interrupted error = %v, want injected crash", err)
	}
	fixture.store.afterAnchor = nil

	if _, err := fixture.store.LoadBase(); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("LoadBase interrupted state error = %v, want ErrPolicyRollback", err)
	}
	if _, err := fixture.store.ReplaceBase(signTestManifest(t, fixture.priv, testManifest(1, 1))); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("old authority after interrupted update error = %v, want ErrPolicyRollback", err)
	}
	if _, err := fixture.store.ReplaceBase(next); err != nil {
		t.Fatalf("resume exact pinned candidate: %v", err)
	}
	loaded, err := fixture.store.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != (PolicyVersion{Epoch: 1, Revision: 2}) {
		t.Fatalf("loaded version = %+v, want epoch 1 revision 2", loaded.Version)
	}
}

func TestStoreCanRepairCorruptManifestOnlyWithPinnedOrNewerCandidate(t *testing.T) {
	fixture := newStoreFixture(t)
	current := replaceTestBase(t, fixture, 1, 1)
	writePolicyFile(t, fixture, manifestFile, []byte("corrupt"))
	if _, err := fixture.store.ReplaceBase(current); err != nil {
		t.Fatalf("repair with anchor-pinned candidate: %v", err)
	}

	writePolicyFile(t, fixture, manifestFile, []byte("corrupt again"))
	if _, err := fixture.store.ReplaceBase(signTestManifest(t, fixture.priv, testManifest(1, 2))); err != nil {
		t.Fatalf("repair with newer signed candidate: %v", err)
	}
	if _, err := fixture.store.LoadBase(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreDirectoryDescriptorResistsParentPathReplacement(t *testing.T) {
	fixture := newStoreFixture(t)
	replaceTestBase(t, fixture, 1, 1)
	moved := fixture.dir + "-moved"
	if err := os.Rename(fixture.dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.LoadBase(); err != nil {
		t.Fatalf("descriptor-backed load followed replaced parent path: %v", err)
	}
}

func TestStoreRejectsOPathDirectory(t *testing.T) {
	fixture := newStoreFixture(t)
	pathFD, err := unix.Open(fixture.dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pathFD)
	if _, err := OpenStore(pathFD, fixture.cfg, fixture.pub, storeTestHost); !errors.Is(err, ErrUnsafePolicyFile) {
		t.Fatalf("OpenStore O_PATH error = %v, want ErrUnsafePolicyFile", err)
	}
}

func TestStoreRejectsUnsafeConfigurationAndExpectedOwner(t *testing.T) {
	fixture := newStoreFixture(t)
	tests := []StoreConfig{
		{ExpectedUID: fixture.cfg.ExpectedUID, DirectoryMode: 0o720, FileMode: 0o600},
		{ExpectedUID: fixture.cfg.ExpectedUID, DirectoryMode: 0o700, FileMode: 0o620},
		{ExpectedUID: fixture.cfg.ExpectedUID, DirectoryMode: 0o500, FileMode: 0o600},
		{ExpectedUID: fixture.cfg.ExpectedUID, DirectoryMode: 0o700, FileMode: 0o400},
	}
	for _, config := range tests {
		if _, err := OpenStore(fixture.dirFD, config, fixture.pub, storeTestHost); err == nil {
			t.Fatalf("OpenStore unexpectedly accepted unsafe config %+v", config)
		}
	}

	wrongOwner := fixture.cfg
	wrongOwner.ExpectedUID++
	if _, err := OpenStore(fixture.dirFD, wrongOwner, fixture.pub, storeTestHost); !errors.Is(err, ErrUnsafePolicyFile) {
		t.Fatalf("OpenStore wrong expected owner error = %v, want ErrUnsafePolicyFile", err)
	}
}

func TestStoreRevalidatesInodeStableLock(t *testing.T) {
	fixture := newStoreFixture(t)
	replaceTestBase(t, fixture, 1, 1)
	path := filepath.Join(fixture.dir, lockFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(manifestFile, path); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.LoadBase(); !errors.Is(err, ErrUnsafePolicyFile) {
		t.Fatalf("LoadBase replaced lock error = %v, want ErrUnsafePolicyFile", err)
	}
}

func TestStoreInterprocessWritersSerializeAndPreserveHighestRevision(t *testing.T) {
	fixture := newStoreFixture(t)
	replaceTestBase(t, fixture, 1, 1)

	const writers = 8
	commands := make([]*exec.Cmd, 0, writers)
	for revision := 2; revision < 2+writers; revision++ {
		envelope := signTestManifest(t, fixture.priv, testManifest(1, uint64(revision)))
		cmd := exec.Command(os.Args[0], "-test.run=^TestPolicyStoreHelperProcess$")
		cmd.Env = append(os.Environ(),
			"SSHGATE_POLICY_STORE_HELPER=1",
			"SSHGATE_POLICY_STORE_DIR="+fixture.dir,
			"SSHGATE_POLICY_STORE_UID="+strconv.Itoa(os.Geteuid()),
			"SSHGATE_POLICY_STORE_PUB="+base64.StdEncoding.EncodeToString(fixture.pub),
			"SSHGATE_POLICY_STORE_ENVELOPE="+base64.StdEncoding.EncodeToString(envelope),
		)
		commands = append(commands, cmd)
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(commands))
	for _, cmd := range commands {
		wg.Add(1)
		go func(cmd *exec.Cmd) {
			defer wg.Done()
			if output, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("helper failed: %w\n%s", err, output)
			}
		}(cmd)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	loaded, err := fixture.store.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	wantRevision := uint64(1 + writers)
	if loaded.Version != (PolicyVersion{Epoch: 1, Revision: wantRevision}) {
		t.Fatalf("final version = %+v, want epoch 1 revision %d", loaded.Version, wantRevision)
	}
}

func TestPolicyStoreHelperProcess(t *testing.T) {
	if os.Getenv("SSHGATE_POLICY_STORE_HELPER") != "1" {
		return
	}
	dir := os.Getenv("SSHGATE_POLICY_STORE_DIR")
	uid, err := strconv.ParseUint(os.Getenv("SSHGATE_POLICY_STORE_UID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(os.Getenv("SSHGATE_POLICY_STORE_PUB"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := base64.StdEncoding.DecodeString(os.Getenv("SSHGATE_POLICY_STORE_ENVELOPE"))
	if err != nil {
		t.Fatal(err)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	config := StoreConfig{ExpectedUID: uint32(uid), DirectoryMode: 0o700, FileMode: 0o600}
	store, err := OpenStore(dirFD, config, ed25519.PublicKey(publicKey), storeTestHost)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ReplaceBase(envelope); err != nil && !errors.Is(err, ErrPolicyRollback) {
		t.Fatal(err)
	}
}
