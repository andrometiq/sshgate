package gate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestAtomicReplace_ReplacesAndSetsMode pins the happy path: the target ends
// up with exactly the new bytes at the requested mode, in place.
func TestAtomicReplace_ReplacesAndSetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gate")
	if err := os.WriteFile(path, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	newBody := []byte("\x7fELF-NEW-BINARY-BYTES")
	if err := AtomicReplace(path, newBody, 0o755); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, newBody) {
		t.Errorf("body = %q; want %q", got, newBody)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v; want 0755", info.Mode().Perm())
	}
}

// TestAtomicReplace_NoTempLeftOnSuccess ensures the temp file is renamed away,
// not left beside the target.
func TestAtomicReplace_NoTempLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gate")
	if err := AtomicReplace(path, []byte("x"), 0o755); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 1 || ents[0].Name() != "gate" {
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = e.Name()
		}
		t.Errorf("dir has %v; want exactly [gate] (no temp left)", names)
	}
}

// TestAtomicReplace_CreatesWhenAbsent covers the create case (no pre-existing
// target) — the gate.new path uses this shape.
func TestAtomicReplace_CreatesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh")
	if err := AtomicReplace(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("target not created: %v", err)
	}
}
