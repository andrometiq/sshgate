package signer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/signer"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// xferKeyTexts generates a fresh box + id keypair and returns their canonical
// PublicText forms, for driving registry Register/Lookup.
func xferKeyTexts(t *testing.T) (boxText, idText string, boxPub *[32]byte) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("gen box key: %v", err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("gen id key: %v", err)
	}
	return bk.PublicText(), ik.PublicText(), bk.Public()
}

// TestXferRegistry_MissingFileIsEmpty: a missing registry file loads as an
// empty registry (no error), and every lookup misses.
func TestXferRegistry_MissingFileIsEmpty(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "xfer-registry.json")
	reg, err := signer.LoadXferRegistry(path)
	if err != nil {
		t.Fatalf("LoadXferRegistry(missing): %v", err)
	}
	if _, _, _, ok := reg.Lookup("SHA256:anything"); ok {
		t.Error("empty registry returned a lookup hit")
	}
}

// TestXferRegistry_RegisterLookupRoundTrip: a registered entry is found and its
// keys round-trip exactly; the file lands at mode 0600.
func TestXferRegistry_RegisterLookupRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "xfer-registry.json")
	reg, err := signer.LoadXferRegistry(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	boxText, idText, boxPub := xferKeyTexts(t)
	fp := "SHA256:host-example-fp-aaaaaaaaaaaaaaaaaaaaaaaa"
	if err := reg.Register(fp, "host-gcp", boxText, idText); err != nil {
		t.Fatalf("Register: %v", err)
	}

	gotBox, gotID, label, ok := reg.Lookup(fp)
	if !ok {
		t.Fatal("Lookup missed a registered fp")
	}
	if *gotBox != *boxPub {
		t.Error("box pub round-trip mismatch")
	}
	if len(gotID) == 0 {
		t.Error("id pub empty")
	}
	if label != "host-gcp" {
		t.Errorf("label = %q; want host-gcp", label)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat registry: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("registry mode = %#o; want 0600", perm)
	}

	// Reload from disk: the persisted entry must survive a fresh load.
	reg2, err := signer.LoadXferRegistry(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, _, _, ok := reg2.Lookup(fp); !ok {
		t.Error("reloaded registry lost the entry")
	}
}

// TestXferRegistry_OverwriteAllowed: re-registering a fp (key rotation) is
// allowed and replaces the entry.
func TestXferRegistry_OverwriteAllowed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "xfer-registry.json")
	reg, _ := signer.LoadXferRegistry(path)
	box1, id1, _ := xferKeyTexts(t)
	box2, id2, want2 := xferKeyTexts(t)
	fp := "SHA256:rotate-me-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := reg.Register(fp, "v1", box1, id1); err != nil {
		t.Fatalf("register v1: %v", err)
	}
	if err := reg.Register(fp, "v2", box2, id2); err != nil {
		t.Fatalf("register v2 (rotation): %v", err)
	}
	gotBox, _, label, ok := reg.Lookup(fp)
	if !ok {
		t.Fatal("lookup after rotation missed")
	}
	if *gotBox != *want2 {
		t.Error("rotation did not replace the box key")
	}
	if label != "v2" {
		t.Errorf("label = %q; want v2 (rotation)", label)
	}
}

// TestXferRegistry_RejectGroupWritable: a present registry file with any
// group/other bit set is refused on load (it is a trust anchor).
func TestXferRegistry_RejectGroupWritable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "xfer-registry.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"servers":{}}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := signer.LoadXferRegistry(path); err == nil {
		t.Error("LoadXferRegistry accepted a group/other-readable registry")
	}
}

// TestXferRegistry_RejectMalformedKey: Register refuses a malformed key text,
// so a bad trust anchor never lands.
func TestXferRegistry_RejectMalformedKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "xfer-registry.json")
	reg, _ := signer.LoadXferRegistry(path)
	_, idText, _ := xferKeyTexts(t)
	if err := reg.Register("SHA256:x", "bad", "not-a-valid-box-key", idText); err == nil {
		t.Error("Register accepted a malformed box key")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("Register persisted a file despite the malformed key")
	}
}
