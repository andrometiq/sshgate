package signerkit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadKey reads an Ed25519 private key from path. The file must contain
// the 64-byte raw binary key (the format ed25519.NewKeyFromSeed yields
// when its output is stored verbatim, and what GenerateKeyPair writes).
//
// LoadKey refuses to load if any group or world permission bit is set
// — mask 0o077. This is the stricter sibling of gate.LoadPubKey's
// 0o022 mask: the public key tolerates group/world *read* (because the
// key is public), but the private key must be readable only by its
// owner. Refusing on permissions catches install-time mistakes before
// they become "the master key is world-readable" incidents.
//
// Errors are wrapped with %w; callers may use errors.Is(err, fs.ErrNotExist)
// to detect a missing file specifically.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private key %s is a symbolic link", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reinspect private key: %w", err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, after) {
		return nil, fmt.Errorf("private key %s changed or became a symbolic link during open", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("private key %s is not a regular file", path)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return nil, fmt.Errorf("private key %s has insecure mode %#o (group/world bits must be off)", path, mode)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key %s is %d bytes; want %d (raw Ed25519)", path, len(data), ed25519.PrivateKeySize)
	}
	out := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(out, data)
	return out, nil
}

// GenerateKeyPair generates a fresh Ed25519 keypair and writes:
//
//   - privPath: 64-byte raw private key, mode 0600
//   - pubPath:  32-byte raw public key,  mode 0644
//
// Both files are flushed to disk with fsync, and the parent directory
// of each is fsynced after the rename, per daemon.md §5.1 (atomic file
// rewrite: temp + fsync + rename + fsync(dir)). GenerateKeyPair refuses
// to overwrite either path if it already exists — caller is expected to
// delete or rotate explicitly.
//
// The two paths may share a parent directory (the common case under
// /var/lib/sshgatesigner/keys); the directory-fsync is performed twice in
// that case, which is harmless.
func GenerateKeyPair(privPath, pubPath string) error {
	// Pre-flight gives a useful early error; atomicWriteNoReplace's hard-link
	// publish is the authoritative race-safe refusal.
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %s", p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	if err := atomicWriteNoReplace(privPath, priv, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := atomicWriteNoReplace(pubPath, pub, 0o644); err != nil {
		// Best-effort cleanup: the private exists with no matching
		// public, which would render the daemon unusable. Caller's
		// next attempt will refuse-on-overwrite, so surface that too.
		_ = os.Remove(privPath)
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// atomicWrite writes data to a same-directory temp file with the given mode,
// fsyncs it, renames it over path, and then fsyncs the parent directory.
// This is the normal atomic-replacement primitive used for mutable state such
// as the transfer registry.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	// Sibling temp so rename is atomic on the same filesystem.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// On any non-success path, try to remove the temp.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := os.Chmod(tmpPath, mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	committed = true
	// fsync the parent directory so the rename is durable.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}

// atomicWriteNoReplace writes data to a same-directory temp file, fsyncs it,
// and publishes it with an atomic hard link. Unlike rename, link refuses to
// replace a target created after the caller's preflight check.
func atomicWriteNoReplace(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := os.Chmod(tmpPath, mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("publish temp without overwrite: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("remove published temp link: %w", err)
	}
	committed = true

	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}
