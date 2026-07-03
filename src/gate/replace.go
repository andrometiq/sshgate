package gate

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicReplace writes body to path via a same-directory temp file that is
// fsync'd, chmod'd to mode, then renamed over path; the parent directory is
// fsync'd so the rename survives a crash. The rename is atomic because the
// temp file is created in filepath.Dir(path) (same filesystem), and replacing
// a currently-executing binary this way is safe on Linux: the running process
// keeps its old inode while the next exec of path sees the new bytes.
//
// It mirrors the unexported authorized_keys helper (revoke.go) but takes any
// mode and uses a neutral temp prefix, so it can install a 0755 gate binary.
// On any error the temp file is removed and path is left untouched.
func AtomicReplace(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}
