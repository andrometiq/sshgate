package signer_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func writeKeyFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// os.WriteFile honours umask, so force the exact mode we asked for.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func TestLoadKey_ValidPrivateKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "gate.key")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	writeKeyFile(t, path, priv, 0o600)

	got, err := signerkit.LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Errorf("loaded key mismatch")
	}
}

func TestLoadKey_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := signerkit.LoadKey(filepath.Join(t.TempDir(), "nope.key"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadKey_MalformedLength(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	writeKeyFile(t, path, []byte("too short"), 0o600)
	_, err := signerkit.LoadKey(path)
	if err == nil {
		t.Fatal("expected error for malformed key length")
	}
}

func TestLoadKey_RefusesGroupOrWorldPerms(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	cases := []os.FileMode{0o640, 0o644, 0o660, 0o604, 0o666}
	for _, mode := range cases {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, "k_"+mode.String())
			writeKeyFile(t, path, priv, mode)
			_, err := signerkit.LoadKey(path)
			if err == nil {
				t.Fatalf("LoadKey accepted mode %#o; want refusal", mode)
			}
		})
	}
}

func TestGenerateKeyPair_WritesUsableKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "gate.key")
	pubPath := filepath.Join(dir, "gate.pub")

	if err := signerkit.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Modes
	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat priv: %v", err)
	}
	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("priv mode = %#o; want 0600", got)
	}
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat pub: %v", err)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("pub mode = %#o; want 0644", got)
	}

	// Material match
	priv, err := signerkit.LoadKey(privPath)
	if err != nil {
		t.Fatalf("LoadKey after Generate: %v", err)
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("pub file is %d bytes; want %d", len(pubBytes), ed25519.PublicKeySize)
	}
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() not ed25519.PublicKey")
	}
	if !bytes.Equal(derived, pubBytes) {
		t.Errorf("pub on disk does not match priv.Public()")
	}
}

func TestGenerateKeyPair_RefusesOverwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "gate.key")
	pubPath := filepath.Join(dir, "gate.pub")
	if err := signerkit.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	err := signerkit.GenerateKeyPair(privPath, pubPath)
	if err == nil {
		t.Fatal("expected refusal on overwrite")
	}
	// Also: pub-only collision
	dir2 := t.TempDir()
	priv2 := filepath.Join(dir2, "p.key")
	pub2 := filepath.Join(dir2, "p.pub")
	if err := os.WriteFile(pub2, []byte("anything"), 0o644); err != nil {
		t.Fatalf("seed pub: %v", err)
	}
	if err := signerkit.GenerateKeyPair(priv2, pub2); err == nil {
		t.Fatal("expected refusal when pub exists")
	}
}

func TestGenerateKeyPair_MissingParentDir(t *testing.T) {
	t.Parallel()
	// Generate must NOT silently mkdir; the caller is responsible for
	// the directory layout (consistent with daemon.md §5 atomicity).
	bad := filepath.Join(t.TempDir(), "nope", "gate.key")
	err := signerkit.GenerateKeyPair(bad, bad+".pub")
	if err == nil {
		t.Fatal("expected error for missing parent dir")
	}
	if errors.Is(err, os.ErrExist) {
		t.Fatalf("unexpected ErrExist; want ENOENT-style: %v", err)
	}
}
