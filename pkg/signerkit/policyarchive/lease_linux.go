//go:build linux

package policyarchive

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// LeaseMode selects the process-lifetime maintenance exclusion class.
type LeaseMode uint8

const (
	LeaseShared LeaseMode = iota + 1
	LeaseExclusive
)

// MaintenanceLease is a held and pathname-revalidated DB-adjacent flock.
type MaintenanceLease struct {
	mu       sync.Mutex
	parentFD int
	fd       int
	name     string
	path     string
	mode     LeaseMode
	closed   bool
}

// AcquireMaintenanceLease acquires <databasePath>.policy-maintenance.lock.
// It must be called before opening the database or archive.
func AcquireMaintenanceLease(databasePath string, mode LeaseMode) (*MaintenanceLease, error) {
	return acquireMaintenanceLease(databasePath, mode, nil)
}

func acquireMaintenanceLease(databasePath string, mode LeaseMode, afterFlock func(string) error) (*MaintenanceLease, error) {
	if mode != LeaseShared && mode != LeaseExclusive {
		return nil, errors.New("policy archive: invalid maintenance lease mode")
	}
	parentFD, name, path, err := openParentNoSymlinks(databasePath + maintenanceLockSuffix)
	if err != nil {
		return nil, err
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = unix.Close(parentFD)
		}
	}()

	fd, err := unix.Openat(parentFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parentFD, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("policy archive: open maintenance lock: %w", err)
	}
	closeLock := true
	defer func() {
		if closeLock {
			_ = unix.Close(fd)
		}
	}()

	specification := nodeSpec{kind: unix.S_IFREG, mode: 0o600}
	if _, err := validateNamedIdentity(parentFD, name, fd, specification); err != nil {
		return nil, fmt.Errorf("policy archive: validate maintenance lock: %w", err)
	}
	if created {
		if err := unix.Fsync(fd); err != nil {
			return nil, fmt.Errorf("policy archive: fsync maintenance lock: %w", err)
		}
		if err := unix.Fsync(parentFD); err != nil {
			return nil, fmt.Errorf("policy archive: fsync maintenance lock parent: %w", err)
		}
	}
	operation := unix.LOCK_SH
	if mode == LeaseExclusive {
		operation = unix.LOCK_EX
	}
	if err := unix.Flock(fd, operation); err != nil {
		return nil, fmt.Errorf("policy archive: acquire maintenance lock: %w", err)
	}
	if afterFlock != nil {
		if err := afterFlock(path); err != nil {
			_ = unix.Flock(fd, unix.LOCK_UN)
			return nil, err
		}
	}
	lease := &MaintenanceLease{parentFD: parentFD, fd: fd, name: name, path: path, mode: mode}
	if err := lease.revalidateLocked(); err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return nil, fmt.Errorf("policy archive: post-flock maintenance lock validation: %w", err)
	}
	closeParent = false
	closeLock = false
	return lease, nil
}

// Path returns the exact absolute lock pathname.
func (lease *MaintenanceLease) Path() string {
	if lease == nil {
		return ""
	}
	return lease.path
}

// Exclusive reports whether the held lease excludes serving processes.
func (lease *MaintenanceLease) Exclusive() bool {
	return lease != nil && lease.mode == LeaseExclusive
}

// Revalidate proves the held inode still names the validated lock path.
func (lease *MaintenanceLease) Revalidate() error {
	if lease == nil {
		return errors.New("policy archive: nil maintenance lease")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.revalidateLocked()
}

func (lease *MaintenanceLease) revalidateLocked() error {
	if lease.closed {
		return errors.New("policy archive: maintenance lease is closed")
	}
	if _, err := validateNamedIdentity(lease.parentFD, lease.name, lease.fd, nodeSpec{kind: unix.S_IFREG, mode: 0o600}); err != nil {
		return fmt.Errorf("policy archive: maintenance lock identity: %w", err)
	}
	return nil
}

// Close releases the flock only after checking for path substitution.
func (lease *MaintenanceLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	identityErr := lease.revalidateLocked()
	lease.closed = true
	unlockErr := unix.Flock(lease.fd, unix.LOCK_UN)
	lockErr := unix.Close(lease.fd)
	parentErr := unix.Close(lease.parentFD)
	return errors.Join(identityErr, unlockErr, lockErr, parentErr)
}
