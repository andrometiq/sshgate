//go:build linux

package policyarchive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func newTestLease(t *testing.T, mode LeaseMode) *MaintenanceLease {
	t.Helper()
	lease, err := AcquireMaintenanceLease(filepath.Join(t.TempDir(), "policy.db"), mode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Errorf("close maintenance lease: %v", err)
		}
	})
	return lease
}

func newArchiveRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "archive")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func openTestArchive(t *testing.T, lease *MaintenanceLease) (*Archive, string) {
	t.Helper()
	root := newArchiveRoot(t)
	archive, err := OpenServing(root, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err != nil {
		t.Fatal(err)
	}
	if err := archive.PrepareServingShards(lease); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := archive.Close(); err != nil {
			t.Errorf("close archive: %v", err)
		}
	})
	return archive, root
}

func TestOpenServingCreatesAllShardsAndOpenExistingVerifies(t *testing.T) {
	lease := newTestLease(t, LeaseShared)
	root := newArchiveRoot(t)
	archive, err := OpenServing(root, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.PrepareServingShards(lease); err == nil {
		t.Fatal("PrepareServingShards ran before binding verification")
	}
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err != nil {
		t.Fatal(err)
	}
	if err := archive.PrepareServingShards(lease); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 257 {
		t.Fatalf("archive entries = %d; want 256 shards plus binding", len(entries))
	}
	shards := make([]os.DirEntry, 0, 256)
	for _, entry := range entries {
		if entry.Name() != BindingFilename {
			shards = append(shards, entry)
		}
	}
	for index, entry := range shards {
		want := strings.ToLower(hex.EncodeToString([]byte{byte(index)}))
		if entry.Name() != want || !entry.IsDir() {
			t.Fatalf("entry %d = %q dir=%v; want %q directory", index, entry.Name(), entry.IsDir(), want)
		}
		status, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if status.Mode().Perm() != 0o700 {
			t.Fatalf("shard %s mode = %#o; want 0700", entry.Name(), status.Mode().Perm())
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := OpenExisting(root, lease)
	if err != nil {
		t.Fatalf("OpenExisting: %v", err)
	}
	if err := existing.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenArchiveRejectsUnsafeRoots(t *testing.T) {
	lease := newTestLease(t, LeaseShared)
	t.Run("relative", func(t *testing.T) {
		if archive, err := OpenServing("relative", lease); err == nil {
			_ = archive.Close()
			t.Fatal("OpenServing accepted a relative root")
		}
	})
	t.Run("symlink root", func(t *testing.T) {
		directory := t.TempDir()
		realRoot := filepath.Join(directory, "real")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "link")
		if err := os.Symlink(realRoot, link); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenServing(link, lease); err == nil {
			_ = archive.Close()
			t.Fatal("OpenServing accepted a symlink root")
		}
	})
	t.Run("symlink parent", func(t *testing.T) {
		directory := t.TempDir()
		realParent := filepath.Join(directory, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(realParent, "archive")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(directory, "alias")
		if err := os.Symlink(realParent, alias); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenServing(filepath.Join(alias, "archive"), lease); err == nil {
			_ = archive.Close()
			t.Fatal("OpenServing traversed a symlink parent")
		}
	})
	t.Run("wrong mode", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "archive")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenServing(root, lease); err == nil {
			_ = archive.Close()
			t.Fatal("OpenServing accepted root mode 0755")
		}
	})
	t.Run("regular file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "archive")
		if err := os.WriteFile(root, nil, 0o700); err != nil {
			t.Fatal(err)
		}
		if archive, err := OpenServing(root, lease); err == nil {
			_ = archive.Close()
			t.Fatal("OpenServing accepted a regular file")
		}
	})
	if os.Geteuid() == 0 {
		t.Run("wrong owner", func(t *testing.T) {
			root := newArchiveRoot(t)
			if err := os.Chown(root, 1, -1); err != nil {
				t.Fatal(err)
			}
			if archive, err := OpenServing(root, lease); err == nil {
				_ = archive.Close()
				t.Fatal("OpenServing accepted a root owned by another uid")
			}
		})
	}
}

func TestArchiveRootRevalidationRejectsPathSubstitution(t *testing.T) {
	lease := newTestLease(t, LeaseShared)
	root := newArchiveRoot(t)
	archive, err := OpenServing(root, lease)
	if err != nil {
		t.Fatal(err)
	}
	displaced := root + ".displaced"
	if err := os.Rename(root, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := archive.VerifyShards(); err == nil {
		t.Fatal("VerifyShards accepted a substituted archive root")
	}
	if err := archive.Close(); err == nil {
		t.Fatal("Close did not report the substituted archive root")
	}
}

func TestOwnedNodeValidationChecksUIDDeviceAndDirectoryLinks(t *testing.T) {
	device := uint64(7)
	status := unix.Stat_t{
		Mode:  unix.S_IFDIR | 0o700,
		Uid:   uint32(os.Geteuid()),
		Dev:   device,
		Nlink: 2,
	}
	if err := validateOwnedStat(status, nodeSpec{kind: unix.S_IFDIR, mode: 0o700, device: &device}); err != nil {
		t.Fatalf("normal directory with link count 2 was rejected: %v", err)
	}
	status.Uid++
	if err := validateOwnedStat(status, nodeSpec{kind: unix.S_IFDIR, mode: 0o700, device: &device}); err == nil {
		t.Fatal("wrong uid was accepted")
	}
	status.Uid--
	otherDevice := device + 1
	if err := validateOwnedStat(status, nodeSpec{kind: unix.S_IFDIR, mode: 0o700, device: &otherDevice}); err == nil {
		t.Fatal("wrong device was accepted")
	}
}

func TestShardRevalidationRejectsMutationWithoutRepair(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, shard string)
	}{
		{name: "missing", mutate: func(t *testing.T, shard string) {
			t.Helper()
			if err := os.Remove(shard); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", mutate: func(t *testing.T, shard string) {
			t.Helper()
			if err := os.Remove(shard); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(shard), "01"), shard); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "regular file", mutate: func(t *testing.T, shard string) {
			t.Helper()
			if err := os.Remove(shard); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(shard, nil, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong mode", mutate: func(t *testing.T, shard string) {
			t.Helper()
			if err := os.Chmod(shard, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease := newTestLease(t, LeaseShared)
			archive, root := openTestArchive(t, lease)
			test.mutate(t, filepath.Join(root, "00"))
			if err := archive.VerifyShards(); err == nil {
				t.Fatal("VerifyShards accepted a mutated shard")
			}
			if _, err := os.Lstat(filepath.Join(root, "00")); errors.Is(err, os.ErrNotExist) == false && test.name == "missing" {
				t.Fatalf("missing shard was repaired: %v", err)
			}
		})
	}
}

func TestBindingFirstCreateCrashRewriteEqualAndMismatch(t *testing.T) {
	lease := newTestLease(t, LeaseShared)
	root := newArchiveRoot(t)
	archive, err := OpenServing(root, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if err := archive.VerifyBinding(testArchiveID, testAuthorityID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err != nil {
		t.Fatalf("equal reconcile: %v", err)
	}

	bindingPath := filepath.Join(root, BindingFilename)
	if err := os.Remove(bindingPath); err != nil {
		t.Fatal(err)
	}
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err != nil {
		t.Fatalf("bound-DB absent-record rewrite: %v", err)
	}
	want, _ := EncodeBinding(testArchiveID, testAuthorityID)
	got, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("rewritten binding bytes differ")
	}

	corrupt := bytes.Repeat([]byte{'x'}, len(want))
	if err := os.WriteFile(bindingPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err == nil {
		t.Fatal("PublishBinding accepted mismatching existing bytes")
	}
	after, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatal("PublishBinding replaced mismatching bytes")
	}
}

func TestBindingEqualRenameEEXISTIsIdempotentAndCleansTemporary(t *testing.T) {
	lease := newTestLease(t, LeaseShared)
	root := newArchiveRoot(t)
	archive, err := OpenServing(root, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	record, err := EncodeBinding(testArchiveID, testAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	originalRename := archive.renameNoReplace
	archive.renameNoReplace = func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if err := os.WriteFile(filepath.Join(root, BindingFilename), record, 0o600); err != nil {
			return err
		}
		return originalRename(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := archive.PublishBinding(lease, testArchiveID, testAuthorityID); err != nil {
		t.Fatalf("equal rename EEXIST: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), BindingFilename+".tmp-") {
			t.Fatalf("binding temporary %q remains after equal EEXIST", entry.Name())
		}
	}
}

func TestBindingExistingOnlyNeverCreatesOrRepairs(t *testing.T) {
	shared := newTestLease(t, LeaseShared)
	archive, root := openTestArchive(t, shared)
	if err := os.Remove(filepath.Join(root, BindingFilename)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := OpenExisting(root, shared)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	if err := existing.PublishBinding(shared, testArchiveID, testAuthorityID); err == nil {
		t.Fatal("OpenExisting handle created a missing binding")
	}
	if _, err := os.Lstat(filepath.Join(root, BindingFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("binding exists after refused publish: %v", err)
	}
	if err := existing.VerifyBinding(testArchiveID, testAuthorityID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("VerifyBinding error = %v; want not-exist", err)
	}
}

func TestBindingRejectsUnsafeExistingNodes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, path string, good []byte)
	}{
		{name: "symlink", setup: func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Symlink("missing", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong mode", setup: func(t *testing.T, path string, good []byte) {
			t.Helper()
			if err := os.WriteFile(path, good, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard link", setup: func(t *testing.T, path string, good []byte) {
			t.Helper()
			other := path + ".other"
			if err := os.WriteFile(other, good, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(other, path); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease := newTestLease(t, LeaseShared)
			archive, root := openTestArchive(t, lease)
			good, _ := EncodeBinding(testArchiveID, testAuthorityID)
			if err := os.Remove(filepath.Join(root, BindingFilename)); err != nil {
				t.Fatal(err)
			}
			test.setup(t, filepath.Join(root, BindingFilename), good)
			if err := archive.VerifyBinding(testArchiveID, testAuthorityID); err == nil {
				t.Fatal("VerifyBinding accepted an unsafe node")
			}
		})
	}
}

func TestObjectPublishReadAndEqualEEXIST(t *testing.T) {
	lease := newTestLease(t, LeaseExclusive)
	archive, root := openTestArchive(t, lease)
	record := []byte("canonical-policy-archive-v3-record")
	reference, err := archive.PublishObject(lease, record)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(record)
	wantHash := hex.EncodeToString(digest[:])
	if reference != (ObjectRef{SHA256: wantHash, Bytes: int64(len(record))}) {
		t.Fatalf("reference = %+v", reference)
	}
	path := filepath.Join(root, wantHash[:2], wantHash+objectSuffix)
	status, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Mode().IsRegular() || status.Mode().Perm() != 0o600 {
		t.Fatalf("object mode = %v; want regular 0600", status.Mode())
	}
	got, err := archive.ReadObject(reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, record) {
		t.Fatalf("ReadObject = %q; want %q", got, record)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.PublishObject(lease, record); err != nil {
		t.Fatalf("equal EEXIST: %v", err)
	}
}

func TestObjectEEXISTNeverReplacesTornOrUnequalFinal(t *testing.T) {
	for _, test := range []struct {
		name     string
		existing func([]byte) []byte
	}{
		{name: "torn", existing: func(record []byte) []byte { return append([]byte(nil), record[:len(record)-1]...) }},
		{name: "unequal", existing: func(record []byte) []byte { body := append([]byte(nil), record...); body[0] ^= 0xff; return body }},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := newTestLease(t, LeaseExclusive)
			archive, root := openTestArchive(t, lease)
			record := []byte("canonical-policy-archive-v3-record")
			reference, err := objectReference(record)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, reference.SHA256[:2], objectName(reference))
			bad := test.existing(record)
			if err := os.WriteFile(path, bad, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.PublishObject(lease, record); err == nil {
				t.Fatal("PublishObject accepted a corrupt EEXIST final")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, bad) {
				t.Fatal("PublishObject replaced a corrupt EEXIST final")
			}
		})
	}
}

func TestObjectPublishDoesNotFallbackWithoutNoReplacePrimitive(t *testing.T) {
	lease := newTestLease(t, LeaseExclusive)
	archive, root := openTestArchive(t, lease)
	record := []byte("canonical-policy-archive-v3-record")
	reference, err := objectReference(record)
	if err != nil {
		t.Fatal(err)
	}
	archive.renameNoReplace = func(_ int, _ string, _ int, _ string, flags uint) error {
		if flags != unix.RENAME_NOREPLACE {
			t.Fatalf("rename flags = %#x; want RENAME_NOREPLACE", flags)
		}
		return unix.ENOSYS
	}
	if _, err := archive.PublishObject(lease, record); !errors.Is(err, unix.ENOSYS) {
		t.Fatalf("PublishObject error = %v; want ENOSYS", err)
	}
	finalPath := filepath.Join(root, reference.SHA256[:2], objectName(reference))
	if _, err := os.Lstat(finalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final object exists after no-replace failure: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(finalPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if validTemporaryObjectName(entry.Name()) {
			t.Fatalf("temporary object %q remains after failure", entry.Name())
		}
	}
}

func TestReadObjectRejectsCorruptionAndUnsafeNode(t *testing.T) {
	lease := newTestLease(t, LeaseExclusive)
	archive, root := openTestArchive(t, lease)
	record := []byte("canonical-policy-archive-v3-record")
	reference, err := archive.PublishObject(lease, record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, reference.SHA256[:2], objectName(reference))
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.ReadObject(reference); err == nil {
		t.Fatal("ReadObject accepted wrong object mode")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.ReadObject(reference); err == nil {
		t.Fatal("ReadObject accepted a multiply-linked object")
	}
}

func TestObjectOperationsRequireExclusiveLease(t *testing.T) {
	shared := newTestLease(t, LeaseShared)
	archive, _ := openTestArchive(t, shared)
	if _, err := archive.PublishObject(shared, []byte("record")); err == nil {
		t.Fatal("PublishObject accepted a shared lease")
	}
	if _, err := archive.CleanupTemporaryObjects(shared, nil); err == nil {
		t.Fatal("CleanupTemporaryObjects accepted a shared lease")
	}
}

func TestCleanupTemporaryObjectsExactGrammarAndLogging(t *testing.T) {
	lease := newTestLease(t, LeaseExclusive)
	archive, root := openTestArchive(t, lease)
	shard := filepath.Join(root, "00")
	exact := []string{
		".pja-tmp-0123456789abcdef0123456789abcdef",
		".pja-tmp-fedcba9876543210fedcba9876543210",
	}
	for _, name := range exact {
		if err := os.WriteFile(filepath.Join(shard, name), []byte("torn"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	near := []string{
		"pja-tmp-0123456789abcdef0123456789abcdef",
		".pja-tmp-0123456789abcdef0123456789abcde",
		".pja-tmp-0123456789abcdef0123456789abcdef0",
		".pja-tmp-0123456789abcdef0123456789abcdeF",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.pja",
	}
	for _, name := range near {
		if err := os.WriteFile(filepath.Join(shard, name), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	matchingSymlink := ".pja-tmp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.Symlink("missing", filepath.Join(shard, matchingSymlink)); err != nil {
		t.Fatal(err)
	}
	exact = append(exact, matchingSymlink)

	var logged []string
	removed, err := archive.CleanupTemporaryObjects(lease, func(path string) { logged = append(logged, path) })
	if err != nil {
		t.Fatal(err)
	}
	if removed != len(exact) {
		t.Fatalf("removed = %d; want %d", removed, len(exact))
	}
	for _, name := range exact {
		if _, err := os.Lstat(filepath.Join(shard, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("exact temporary %q remains: %v", name, err)
		}
	}
	for _, name := range near {
		if _, err := os.Lstat(filepath.Join(shard, name)); err != nil {
			t.Fatalf("near-match %q was removed: %v", name, err)
		}
	}
	wantLogged := make([]string, len(exact))
	for index, name := range exact {
		wantLogged[index] = filepath.Join(shard, name)
	}
	sort.Strings(wantLogged)
	sort.Strings(logged)
	if !equalStrings(logged, wantLogged) {
		t.Fatalf("logged = %q; want %q", logged, wantLogged)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
