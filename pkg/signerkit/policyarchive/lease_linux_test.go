//go:build linux

package policyarchive

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMaintenanceLeaseCreatesOwnerOnlyAdjacentLock(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "policy.db")
	lease, err := AcquireMaintenanceLease(databasePath, LeaseShared)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	wantPath := databasePath + maintenanceLockSuffix
	if lease.Path() != wantPath {
		t.Fatalf("Path() = %q; want %q", lease.Path(), wantPath)
	}
	status, err := os.Lstat(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Mode().IsRegular() || status.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v; want regular 0600", status.Mode())
	}
	if err := lease.Revalidate(); err != nil {
		t.Fatalf("Revalidate: %v", err)
	}
}

func TestMaintenanceLeaseFlockModesConflict(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "policy.db")
	lease, err := AcquireMaintenanceLease(databasePath, LeaseShared)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	second, err := unix.Open(lease.Path(), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(second)
	if err := unix.Flock(second, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatalf("second shared flock: %v", err)
	}
	if err := unix.Flock(second, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(second, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("exclusive flock error = %v; want EWOULDBLOCK", err)
	}
}

func TestMaintenanceLeasePostFlockRejectsPathSubstitution(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "policy.db")
	_, err := acquireMaintenanceLease(databasePath, LeaseExclusive, func(lockPath string) error {
		if err := os.Rename(lockPath, lockPath+".displaced"); err != nil {
			return err
		}
		file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		return file.Close()
	})
	if err == nil {
		t.Fatal("acquisition accepted a post-flock pathname substitution")
	}
}

func TestMaintenanceLeaseRevalidationRejectsPathSubstitution(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "policy.db")
	lease, err := AcquireMaintenanceLease(databasePath, LeaseExclusive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(lease.Path(), lease.Path()+".displaced"); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.OpenFile(lease.Path(), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Revalidate(); err == nil {
		t.Fatal("Revalidate accepted a substituted lock inode")
	}
	if err := lease.Close(); err == nil {
		t.Fatal("Close did not report the substituted lock inode")
	}
}

func TestMaintenanceLeaseRejectsUnsafeLockNodes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(string) error
	}{
		{name: "symlink", setup: func(path string) error { return os.Symlink("target", path) }},
		{name: "directory", setup: func(path string) error { return os.Mkdir(path, 0o600) }},
		{name: "wrong mode", setup: func(path string) error {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0o644)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "policy.db")
			if err := test.setup(databasePath + maintenanceLockSuffix); err != nil {
				t.Fatal(err)
			}
			if lease, err := AcquireMaintenanceLease(databasePath, LeaseShared); err == nil {
				_ = lease.Close()
				t.Fatal("AcquireMaintenanceLease accepted an unsafe lock node")
			}
		})
	}
}

func TestMaintenanceLeaseRejectsSymlinkedParentTraversal(t *testing.T) {
	directory := t.TempDir()
	realParent := filepath.Join(directory, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireMaintenanceLease(filepath.Join(alias, "policy.db"), LeaseShared); err == nil {
		_ = lease.Close()
		t.Fatal("AcquireMaintenanceLease traversed a symlinked parent")
	}
}
