//go:build linux

package policyarchive

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

var cryptographicRandom = rand.Reader

// Archive is a held-root, no-follow archive filesystem handle.
type Archive struct {
	mu              sync.Mutex
	parentFD        int
	rootFD          int
	rootName        string
	rootPath        string
	device          uint64
	serving         bool
	bindingReady    bool
	shardsReady     bool
	closed          bool
	renameNoReplace func(int, string, int, string, uint) error
}

// OpenServing validates and holds an absolute owner-only root. After the DB is
// bound, callers publish/reconcile the binding and then call
// PrepareServingShards, preserving the serving startup order.
func OpenServing(rootPath string, lease *MaintenanceLease) (*Archive, error) {
	return openArchive(rootPath, lease, true)
}

// OpenExisting validates an absolute owner-only root and the complete existing
// shard set without creating or repairing any entry.
func OpenExisting(rootPath string, lease *MaintenanceLease) (*Archive, error) {
	return openArchive(rootPath, lease, false)
}

func openArchive(rootPath string, lease *MaintenanceLease, serving bool) (*Archive, error) {
	if !filepath.IsAbs(rootPath) {
		return nil, errors.New("policy archive: archive root must be absolute")
	}
	if err := lease.Revalidate(); err != nil {
		return nil, fmt.Errorf("policy archive: validate maintenance lease before archive open: %w", err)
	}
	parentFD, rootName, absolute, err := openParentNoSymlinks(rootPath)
	if err != nil {
		return nil, err
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = unix.Close(parentFD)
		}
	}()

	rootFD, err := unix.Openat(parentFD, rootName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("policy archive: open archive root: %w", err)
	}
	closeRoot := true
	defer func() {
		if closeRoot {
			_ = unix.Close(rootFD)
		}
	}()
	status, err := validateNamedIdentity(parentFD, rootName, rootFD, nodeSpec{kind: unix.S_IFDIR, mode: 0o700})
	if err != nil {
		return nil, fmt.Errorf("policy archive: validate archive root: %w", err)
	}
	archive := &Archive{
		parentFD:        parentFD,
		rootFD:          rootFD,
		rootName:        rootName,
		rootPath:        absolute,
		device:          uint64(status.Dev),
		serving:         serving,
		renameNoReplace: unix.Renameat2,
	}
	if !serving {
		if err := archive.prepareShardsLocked(false); err != nil {
			return nil, err
		}
		archive.shardsReady = true
	}
	if err := lease.Revalidate(); err != nil {
		return nil, fmt.Errorf("policy archive: validate maintenance lease after archive open: %w", err)
	}
	closeParent = false
	closeRoot = false
	return archive, nil
}

// PrepareServingShards creates, validates, and fsyncs all 256 shards and then
// fsyncs the root. Binding publication/reconciliation must succeed first.
func (archive *Archive) PrepareServingShards(lease *MaintenanceLease) error {
	if archive == nil {
		return errors.New("policy archive: nil archive")
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if !archive.serving {
		return errors.New("policy archive: existing-only archive cannot create shards")
	}
	if !archive.bindingReady {
		return errors.New("policy archive: binding record must be verified before shard creation")
	}
	if err := lease.Revalidate(); err != nil {
		return err
	}
	if err := archive.prepareShardsLocked(true); err != nil {
		return err
	}
	archive.shardsReady = true
	return lease.Revalidate()
}

// Root returns the validated absolute archive root path.
func (archive *Archive) Root() string {
	if archive == nil {
		return ""
	}
	return archive.rootPath
}

// VerifyShards revalidates the root and all existing shards without creating.
func (archive *Archive) VerifyShards() error {
	if archive == nil {
		return errors.New("policy archive: nil archive")
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if err := archive.usableLocked(); err != nil {
		return err
	}
	if err := archive.prepareShardsLocked(false); err != nil {
		return err
	}
	archive.shardsReady = true
	return nil
}

func (archive *Archive) prepareShardsLocked(create bool) error {
	if err := archive.revalidateRootLocked(); err != nil {
		return err
	}
	for shard := 0; shard < 256; shard++ {
		name := fmt.Sprintf("%02x", shard)
		if create {
			if err := unix.Mkdirat(archive.rootFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("policy archive: create shard %s: %w", name, err)
			}
		}
		fd, err := archive.openShardLocked(name)
		if err != nil {
			return err
		}
		if create {
			if err := unix.Fsync(fd); err != nil {
				_ = unix.Close(fd)
				return fmt.Errorf("policy archive: fsync shard %s: %w", name, err)
			}
		}
		if _, err := archive.validateShardIdentityLocked(name, fd); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("policy archive: revalidate shard %s: %w", name, err)
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("policy archive: close shard %s: %w", name, err)
		}
	}
	if create {
		if err := unix.Fsync(archive.rootFD); err != nil {
			return fmt.Errorf("policy archive: fsync archive root: %w", err)
		}
	}
	return archive.revalidateRootLocked()
}

func (archive *Archive) openShardLocked(name string) (int, error) {
	if !validLowerHex(name, 2) {
		return -1, errors.New("policy archive: invalid shard name")
	}
	fd, err := unix.Openat(archive.rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("policy archive: open shard %s: %w", name, err)
	}
	if _, err := archive.validateShardIdentityLocked(name, fd); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("policy archive: validate shard %s: %w", name, err)
	}
	return fd, nil
}

func (archive *Archive) validateShardIdentityLocked(name string, fd int) (unix.Stat_t, error) {
	return validateNamedIdentity(archive.rootFD, name, fd, nodeSpec{
		kind: unix.S_IFDIR, mode: 0o700, device: &archive.device,
	})
}

func (archive *Archive) revalidateRootLocked() error {
	if archive.closed {
		return errors.New("policy archive: archive is closed")
	}
	status, err := validateNamedIdentity(archive.parentFD, archive.rootName, archive.rootFD, nodeSpec{kind: unix.S_IFDIR, mode: 0o700})
	if err != nil {
		return fmt.Errorf("policy archive: archive root identity: %w", err)
	}
	if uint64(status.Dev) != archive.device {
		return errors.New("policy archive: archive root device changed")
	}
	return nil
}

func (archive *Archive) usableLocked() error {
	if archive.closed {
		return errors.New("policy archive: archive is closed")
	}
	return archive.revalidateRootLocked()
}

// PublishBinding creates or reconciles the deterministic root binding record.
// Existing equal bytes are idempotent success; any mismatch is corruption.
func (archive *Archive) PublishBinding(lease *MaintenanceLease, archiveID, authorityID string) error {
	if archive == nil {
		return errors.New("policy archive: nil archive")
	}
	record, err := EncodeBinding(archiveID, authorityID)
	if err != nil {
		return err
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if !archive.serving {
		return errors.New("policy archive: existing-only archive cannot publish a binding record")
	}
	if err := lease.Revalidate(); err != nil {
		return err
	}
	if err := archive.usableLocked(); err != nil {
		return err
	}
	if existing, err := archive.readBindingLocked(int64(len(record))); err == nil {
		if !bytes.Equal(existing, record) {
			return errors.New("policy archive: binding record mismatch")
		}
		archive.bindingReady = true
		return nil
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}

	temporaryName, err := randomLowerHexName(BindingFilename + ".tmp-")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(archive.rootFD, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("policy archive: create binding temporary file: %w", err)
	}
	open := true
	temporaryPresent := true
	defer func() {
		if open {
			_ = unix.Close(fd)
		}
		if temporaryPresent {
			_ = unix.Unlinkat(archive.rootFD, temporaryName, 0)
		}
	}()
	specification := nodeSpec{kind: unix.S_IFREG, mode: 0o600, singleLink: true}
	if _, err := validateNamedIdentity(archive.rootFD, temporaryName, fd, specification); err != nil {
		return fmt.Errorf("policy archive: validate binding temporary file: %w", err)
	}
	if err := writeAll(fd, record); err != nil {
		return fmt.Errorf("policy archive: write binding temporary file: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("policy archive: fsync binding temporary file: %w", err)
	}
	if _, err := validateNamedIdentity(archive.rootFD, temporaryName, fd, specification); err != nil {
		return fmt.Errorf("policy archive: revalidate binding temporary file: %w", err)
	}
	if err := archive.renameNoReplace(archive.rootFD, temporaryName, archive.rootFD, BindingFilename, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("policy archive: publish binding record without replacement: %w", err)
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("policy archive: close binding temporary file: %w", err)
		}
		open = false
		existing, readErr := archive.readBindingLocked(int64(len(record)))
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, record) {
			return errors.New("policy archive: binding record mismatch")
		}
		if err := unix.Unlinkat(archive.rootFD, temporaryName, 0); err != nil {
			return fmt.Errorf("policy archive: remove redundant binding temporary file: %w", err)
		}
		temporaryPresent = false
		if err := unix.Fsync(archive.rootFD); err != nil {
			return fmt.Errorf("policy archive: fsync reconciled binding directory: %w", err)
		}
		if err := lease.Revalidate(); err != nil {
			return err
		}
		archive.bindingReady = true
		return nil
	}
	temporaryPresent = false
	if _, err := validateNamedIdentity(archive.rootFD, BindingFilename, fd, specification); err != nil {
		return fmt.Errorf("policy archive: validate published binding record: %w", err)
	}
	if err := unix.Fsync(archive.rootFD); err != nil {
		return fmt.Errorf("policy archive: fsync binding record directory: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("policy archive: close binding record: %w", err)
	}
	open = false
	if err := lease.Revalidate(); err != nil {
		return err
	}
	archive.bindingReady = true
	return nil
}

// VerifyBinding reads and byte-verifies an existing deterministic binding.
func (archive *Archive) VerifyBinding(archiveID, authorityID string) error {
	if archive == nil {
		return errors.New("policy archive: nil archive")
	}
	record, err := EncodeBinding(archiveID, authorityID)
	if err != nil {
		return err
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if err := archive.usableLocked(); err != nil {
		return err
	}
	existing, err := archive.readBindingLocked(int64(len(record)))
	if err != nil {
		return fmt.Errorf("policy archive: verify binding record: %w", err)
	}
	if !bytes.Equal(existing, record) {
		return errors.New("policy archive: binding record mismatch")
	}
	archive.bindingReady = true
	return nil
}

func (archive *Archive) readBindingLocked(size int64) ([]byte, error) {
	body, err := readOwnedFileAt(archive.rootFD, BindingFilename, size)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// PublishObject atomically publishes complete canonical record bytes under an
// exclusive lease. A byte-equal EEXIST is idempotent success.
func (archive *Archive) PublishObject(lease *MaintenanceLease, record []byte) (ObjectRef, error) {
	reference, err := objectReference(record)
	if err != nil {
		return ObjectRef{}, err
	}
	if lease == nil || !lease.Exclusive() {
		return ObjectRef{}, errors.New("policy archive: object publication requires an exclusive maintenance lease")
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if err := lease.Revalidate(); err != nil {
		return ObjectRef{}, err
	}
	if err := archive.usableLocked(); err != nil {
		return ObjectRef{}, err
	}
	if !archive.shardsReady {
		return ObjectRef{}, errors.New("policy archive: archive shards are not ready")
	}
	if !archive.bindingReady {
		return ObjectRef{}, errors.New("policy archive: archive binding is not verified")
	}
	shardName := reference.SHA256[:2]
	shardFD, err := archive.openShardLocked(shardName)
	if err != nil {
		return ObjectRef{}, err
	}
	defer unix.Close(shardFD)

	temporaryName, err := randomLowerHexName(temporaryObjectPrefix)
	if err != nil {
		return ObjectRef{}, err
	}
	fd, err := unix.Openat(shardFD, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: create object temporary file: %w", err)
	}
	open := true
	temporaryPresent := true
	defer func() {
		if open {
			_ = unix.Close(fd)
		}
		if temporaryPresent {
			_ = unix.Unlinkat(shardFD, temporaryName, 0)
		}
	}()
	specification := nodeSpec{kind: unix.S_IFREG, mode: 0o600, singleLink: true}
	if _, err := validateNamedIdentity(shardFD, temporaryName, fd, specification); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: validate object temporary file: %w", err)
	}
	if err := writeAll(fd, record); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: write object temporary file: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: fsync object temporary file: %w", err)
	}
	if _, err := validateNamedIdentity(shardFD, temporaryName, fd, specification); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: revalidate object temporary file: %w", err)
	}
	finalName := objectName(reference)
	if err := archive.renameNoReplace(shardFD, temporaryName, shardFD, finalName, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return ObjectRef{}, fmt.Errorf("policy archive: publish object without replacement: %w", err)
		}
		if err := unix.Close(fd); err != nil {
			return ObjectRef{}, fmt.Errorf("policy archive: close object temporary file: %w", err)
		}
		open = false
		existing, readErr := archive.readObjectFromShardLocked(shardFD, reference)
		if readErr != nil {
			return ObjectRef{}, readErr
		}
		if !bytes.Equal(existing, record) {
			return ObjectRef{}, errors.New("policy archive: existing object bytes mismatch")
		}
		if err := unix.Unlinkat(shardFD, temporaryName, 0); err != nil {
			return ObjectRef{}, fmt.Errorf("policy archive: remove redundant object temporary file: %w", err)
		}
		temporaryPresent = false
		if err := unix.Fsync(shardFD); err != nil {
			return ObjectRef{}, fmt.Errorf("policy archive: fsync reconciled object shard: %w", err)
		}
		if _, err := archive.validateShardIdentityLocked(shardName, shardFD); err != nil {
			return ObjectRef{}, err
		}
		if err := lease.Revalidate(); err != nil {
			return ObjectRef{}, err
		}
		return reference, nil
	}
	temporaryPresent = false
	if _, err := validateNamedIdentity(shardFD, finalName, fd, specification); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: validate published object: %w", err)
	}
	if err := unix.Fsync(shardFD); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: fsync object shard: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: close published object: %w", err)
	}
	open = false
	if _, err := archive.validateShardIdentityLocked(shardName, shardFD); err != nil {
		return ObjectRef{}, fmt.Errorf("policy archive: revalidate published object shard: %w", err)
	}
	if err := archive.revalidateRootLocked(); err != nil {
		return ObjectRef{}, err
	}
	if err := lease.Revalidate(); err != nil {
		return ObjectRef{}, err
	}
	return reference, nil
}

// ReadObject securely reads an exact content-addressed record.
func (archive *Archive) ReadObject(reference ObjectRef) ([]byte, error) {
	if archive == nil {
		return nil, errors.New("policy archive: nil archive")
	}
	if err := validateObjectReference(reference); err != nil {
		return nil, err
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if err := archive.usableLocked(); err != nil {
		return nil, err
	}
	if !archive.shardsReady {
		return nil, errors.New("policy archive: archive shards are not ready")
	}
	if !archive.bindingReady {
		return nil, errors.New("policy archive: archive binding is not verified")
	}
	shardName := reference.SHA256[:2]
	shardFD, err := archive.openShardLocked(shardName)
	if err != nil {
		return nil, err
	}
	defer unix.Close(shardFD)
	body, err := archive.readObjectFromShardLocked(shardFD, reference)
	if err != nil {
		return nil, err
	}
	if _, err := archive.validateShardIdentityLocked(shardName, shardFD); err != nil {
		return nil, fmt.Errorf("policy archive: revalidate object shard: %w", err)
	}
	if err := archive.revalidateRootLocked(); err != nil {
		return nil, err
	}
	return body, nil
}

func (archive *Archive) readObjectFromShardLocked(shardFD int, reference ObjectRef) ([]byte, error) {
	body, err := readOwnedFileAt(shardFD, objectName(reference), reference.Bytes)
	if err != nil {
		return nil, fmt.Errorf("policy archive: read object: %w", err)
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != reference.SHA256 {
		return nil, errors.New("policy archive: object SHA-256 mismatch")
	}
	return body, nil
}

// CleanupTemporaryObjects removes and logs only exact private object-temp names.
func (archive *Archive) CleanupTemporaryObjects(lease *MaintenanceLease, logRemoval func(string)) (int, error) {
	if archive == nil {
		return 0, errors.New("policy archive: nil archive")
	}
	if lease == nil || !lease.Exclusive() {
		return 0, errors.New("policy archive: temporary cleanup requires an exclusive maintenance lease")
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if err := lease.Revalidate(); err != nil {
		return 0, err
	}
	if !archive.shardsReady {
		return 0, errors.New("policy archive: archive shards are not ready")
	}
	if !archive.bindingReady {
		return 0, errors.New("policy archive: archive binding is not verified")
	}
	if err := archive.prepareShardsLocked(false); err != nil {
		return 0, err
	}
	removed := 0
	for shard := 0; shard < 256; shard++ {
		shardName := fmt.Sprintf("%02x", shard)
		shardFD, err := archive.openShardLocked(shardName)
		if err != nil {
			return removed, err
		}
		names, err := directoryNames(shardFD)
		if err != nil {
			_ = unix.Close(shardFD)
			return removed, fmt.Errorf("policy archive: list shard %s: %w", shardName, err)
		}
		sort.Strings(names)
		removedPaths := make([]string, 0)
		for _, name := range names {
			if !validTemporaryObjectName(name) {
				continue
			}
			if err := lease.Revalidate(); err != nil {
				_ = unix.Close(shardFD)
				return removed, err
			}
			if err := unix.Unlinkat(shardFD, name, 0); err != nil {
				_ = unix.Close(shardFD)
				return removed, fmt.Errorf("policy archive: remove temporary object %s/%s: %w", shardName, name, err)
			}
			removedPaths = append(removedPaths, filepath.Join(archive.rootPath, shardName, name))
		}
		if len(removedPaths) > 0 {
			if err := unix.Fsync(shardFD); err != nil {
				_ = unix.Close(shardFD)
				return removed, fmt.Errorf("policy archive: fsync cleaned shard %s: %w", shardName, err)
			}
			for _, path := range removedPaths {
				removed++
				if logRemoval != nil {
					logRemoval(path)
				}
			}
		}
		if _, err := archive.validateShardIdentityLocked(shardName, shardFD); err != nil {
			_ = unix.Close(shardFD)
			return removed, err
		}
		if err := unix.Close(shardFD); err != nil {
			return removed, err
		}
	}
	if err := archive.revalidateRootLocked(); err != nil {
		return removed, err
	}
	if err := lease.Revalidate(); err != nil {
		return removed, err
	}
	return removed, nil
}

func directoryNames(fd int) ([]string, error) {
	listingFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(listingFD), "policy-archive-shard")
	if file == nil {
		_ = unix.Close(listingFD)
		return nil, errors.New("policy archive: create shard directory handle")
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for index := range entries {
		names[index] = entries[index].Name()
	}
	return names, nil
}

// Close releases the held archive-root and parent descriptors.
func (archive *Archive) Close() error {
	if archive == nil {
		return nil
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if archive.closed {
		return nil
	}
	identityErr := archive.revalidateRootLocked()
	archive.closed = true
	rootErr := unix.Close(archive.rootFD)
	parentErr := unix.Close(archive.parentFD)
	return errors.Join(identityErr, rootErr, parentErr)
}
