package xfer_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

func TestBoxKeySaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "box.key")

	k, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("GenerateBoxKey: %v", err)
	}
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Saved private key must be exactly 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved private key mode = %#o, want 0600", info.Mode().Perm())
	}

	loaded, err := xfer.LoadBoxKey(path)
	if err != nil {
		t.Fatalf("LoadBoxKey: %v", err)
	}
	if *loaded.Private() != *k.Private() {
		t.Fatal("loaded box private half differs")
	}
	if *loaded.Public() != *k.Public() {
		t.Fatal("re-derived box public half differs from original")
	}
}

func TestIDKeySaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")

	k, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("GenerateIDKey: %v", err)
	}
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved id key mode = %#o, want 0600", info.Mode().Perm())
	}

	loaded, err := xfer.LoadIDKey(path)
	if err != nil {
		t.Fatalf("LoadIDKey: %v", err)
	}
	if !bytes.Equal(loaded.Private(), k.Private()) {
		t.Fatal("loaded id private half differs")
	}
	if !bytes.Equal(loaded.Public(), k.Public()) {
		t.Fatal("derived id public half differs")
	}
}

func TestLoadBoxKeyRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "box.key")
	k, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("GenerateBoxKey: %v", err)
	}
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o601} {
		t.Run(mode.String(), func(t *testing.T) {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			if _, err := xfer.LoadBoxKey(path); err == nil {
				t.Fatalf("LoadBoxKey accepted mode %#o; want rejection", mode)
			}
		})
	}
}

func TestLoadIDKeyRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	k, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("GenerateIDKey: %v", err)
	}
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := xfer.LoadIDKey(path); err == nil {
		t.Fatal("LoadIDKey accepted mode 0644; want rejection")
	}
}

func TestLoadBoxKeyTightModesAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "box.key")
	k, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("GenerateBoxKey: %v", err)
	}
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := xfer.LoadBoxKey(path); err != nil {
			t.Fatalf("LoadBoxKey rejected tight mode %#o: %v", mode, err)
		}
	}
}

func TestLoadBoxKeyWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "box.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := xfer.LoadBoxKey(path); err == nil {
		t.Fatal("LoadBoxKey accepted a wrong-length key; want error")
	}
}

func TestLoadMissingKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := xfer.LoadBoxKey(filepath.Join(dir, "nope.key")); err == nil {
		t.Fatal("LoadBoxKey on missing file succeeded; want error")
	}
	if _, err := xfer.LoadIDKey(filepath.Join(dir, "nope.key")); err == nil {
		t.Fatal("LoadIDKey on missing file succeeded; want error")
	}
}

func TestBoxPublicTextRoundTrip(t *testing.T) {
	k, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("GenerateBoxKey: %v", err)
	}
	text := k.PublicText()
	parsed, err := xfer.ParseBoxPublicText(text)
	if err != nil {
		t.Fatalf("ParseBoxPublicText: %v", err)
	}
	if *parsed != *k.Public() {
		t.Fatal("box public text did not round-trip")
	}
	// A trailing newline (as a readback file might carry) is tolerated.
	if _, err := xfer.ParseBoxPublicText(text + "\n"); err != nil {
		t.Fatalf("ParseBoxPublicText with trailing newline: %v", err)
	}
}

func TestIDPublicTextRoundTrip(t *testing.T) {
	k, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("GenerateIDKey: %v", err)
	}
	text := k.PublicText()
	parsed, err := xfer.ParseIDPublicText(text)
	if err != nil {
		t.Fatalf("ParseIDPublicText: %v", err)
	}
	if !bytes.Equal(parsed, k.Public()) {
		t.Fatal("id public text did not round-trip")
	}
}

func TestParsePublicTextRejectsMismatch(t *testing.T) {
	box, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("GenerateBoxKey: %v", err)
	}
	id, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("GenerateIDKey: %v", err)
	}

	// Wrong tag: a box line must not parse as an id line and vice versa.
	if _, err := xfer.ParseIDPublicText(box.PublicText()); err == nil {
		t.Fatal("ParseIDPublicText accepted a box public line; want error")
	}
	if _, err := xfer.ParseBoxPublicText(id.PublicText()); err == nil {
		t.Fatal("ParseBoxPublicText accepted an id public line; want error")
	}

	// Structurally broken lines.
	bad := []string{
		"",
		"no-space-single-token",
		"sshgate-xfer-box-x25519 not!valid!base64",
		"sshgate-xfer-box-x25519 " + "AAAA", // right tag, wrong length
	}
	for _, s := range bad {
		if _, err := xfer.ParseBoxPublicText(s); err == nil {
			t.Fatalf("ParseBoxPublicText(%q) succeeded; want error", s)
		}
	}
}
