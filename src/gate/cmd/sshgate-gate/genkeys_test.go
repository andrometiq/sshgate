package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

// This file drives the gate's HUMAN-ONLY `genkeys` ARGV subcommand through the
// gateDirFn seam (t.TempDir), asserting: both key files land at 0600 at the paths
// the RECV/SEND handlers load from; stdout carries ONLY the BEGIN/END block + the
// two tag lines; the two lines round-trip through xfer.Parse*PublicText; and — the
// load-bearing confidentiality property — the PRIVATE bytes never appear in stdout.

// genkeysStdout points gateDirFn at dir and runs `runGenKeys(args)`, returning the
// exit code and captured stdout.
func genkeysStdout(t *testing.T, dir string, args []string) (int, string) {
	t.Helper()
	withGateDir(t, dir)
	var code int
	out := captureStdout(t, func() { code = runGenKeys(args) })
	return code, out
}

// keyLines extracts the box and id tag lines from a genkeys readback.
func keyLines(t *testing.T, stdout string) (boxLine, idLine string) {
	t.Helper()
	for _, l := range strings.Split(stdout, "\n") {
		switch {
		case strings.HasPrefix(l, "sshgate-xfer-box-x25519 "):
			boxLine = l
		case strings.HasPrefix(l, "sshgate-xfer-id-ed25519 "):
			idLine = l
		}
	}
	return boxLine, idLine
}

func TestGenKeys_FreshGenerate(t *testing.T) {
	dir := t.TempDir()
	code, out := genkeysStdout(t, dir, nil)
	if code != exitOK {
		t.Fatalf("runGenKeys rc=%d; want %d", code, exitOK)
	}
	// Both key files exist at 0600.
	for _, name := range []string{"xfer-box.key", "xfer-id.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %#o; want 0600", name, info.Mode().Perm())
		}
	}
	// stdout is exactly the BEGIN/END block + two tag lines (nothing else).
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("stdout has %d lines; want 4 (BEGIN, box, id, END):\n%s", len(lines), out)
	}
	if lines[0] != "SSHGATE_XFER_PUBKEYS_BEGIN" || lines[3] != "SSHGATE_XFER_PUBKEYS_END" {
		t.Errorf("markers wrong:\n%s", out)
	}
	boxLine, idLine := keyLines(t, out)
	if _, err := xfer.ParseBoxPublicText(boxLine); err != nil {
		t.Errorf("box line does not parse: %v", err)
	}
	if _, err := xfer.ParseIDPublicText(idLine); err != nil {
		t.Errorf("id line does not parse: %v", err)
	}

	// CONFIDENTIALITY: the PRIVATE bytes of the saved keys must NOT appear in
	// stdout in any encoding we can check.
	bk, err := xfer.LoadBoxKey(filepath.Join(dir, "xfer-box.key"))
	if err != nil {
		t.Fatal(err)
	}
	ik, err := xfer.LoadIDKey(filepath.Join(dir, "xfer-id.key"))
	if err != nil {
		t.Fatal(err)
	}
	boxPriv := base64.StdEncoding.EncodeToString(bk.Private()[:])
	idPriv := base64.StdEncoding.EncodeToString(ik.Private())
	if strings.Contains(out, boxPriv) {
		t.Error("CONFIDENTIALITY: box PRIVATE key bytes leaked into genkeys stdout")
	}
	if strings.Contains(out, idPriv) {
		t.Error("CONFIDENTIALITY: id PRIVATE key bytes leaked into genkeys stdout")
	}
}

// TestGenKeys_ReadbackIdempotent: a re-run without --rotate returns the SAME
// public lines and leaves the key files byte-for-byte unchanged.
func TestGenKeys_ReadbackIdempotent(t *testing.T) {
	dir := t.TempDir()
	code1, out1 := genkeysStdout(t, dir, nil)
	if code1 != exitOK {
		t.Fatalf("first run rc=%d", code1)
	}
	boxBefore, _ := os.ReadFile(filepath.Join(dir, "xfer-box.key"))
	idBefore, _ := os.ReadFile(filepath.Join(dir, "xfer-id.key"))

	code2, out2 := genkeysStdout(t, dir, nil)
	if code2 != exitOK {
		t.Fatalf("second run rc=%d", code2)
	}
	if out1 != out2 {
		t.Errorf("readback returned different public lines:\n1=%q\n2=%q", out1, out2)
	}
	boxAfter, _ := os.ReadFile(filepath.Join(dir, "xfer-box.key"))
	idAfter, _ := os.ReadFile(filepath.Join(dir, "xfer-id.key"))
	if string(boxBefore) != string(boxAfter) || string(idBefore) != string(idAfter) {
		t.Error("re-run without --rotate clobbered the key files; must be idempotent")
	}
}

// TestGenKeys_Rotate: --rotate regenerates fresh keys — new files, new lines.
func TestGenKeys_Rotate(t *testing.T) {
	dir := t.TempDir()
	_, out1 := genkeysStdout(t, dir, nil)
	boxBefore, _ := os.ReadFile(filepath.Join(dir, "xfer-box.key"))

	code, out2 := genkeysStdout(t, dir, []string{"--rotate"})
	if code != exitOK {
		t.Fatalf("rotate rc=%d", code)
	}
	if out1 == out2 {
		t.Error("--rotate returned the SAME public lines; keys were not regenerated")
	}
	boxAfter, _ := os.ReadFile(filepath.Join(dir, "xfer-box.key"))
	if string(boxBefore) == string(boxAfter) {
		t.Error("--rotate left the box key file unchanged")
	}
}

// TestGenKeys_InsecureModeReadbackFails: an existing key with a group bit is
// refused on readback with a generic error, no key text on stdout.
func TestGenKeys_InsecureModeReadbackFails(t *testing.T) {
	dir := t.TempDir()
	if code, _ := genkeysStdout(t, dir, nil); code != exitOK {
		t.Fatalf("seed run rc=%d", code)
	}
	// Loosen the box key mode to 0640 (group-readable).
	if err := os.Chmod(filepath.Join(dir, "xfer-box.key"), 0o640); err != nil {
		t.Fatal(err)
	}
	code, out := genkeysStdout(t, dir, nil)
	if code != exitSoftware {
		t.Errorf("insecure-mode readback rc=%d; want %d", code, exitSoftware)
	}
	if strings.Contains(out, "SSHGATE_XFER_PUBKEYS_BEGIN") {
		t.Error("a BEGIN block was printed despite the readback failure")
	}
}

// TestGenKeys_WriteFailure: an unwritable gate dir → exitSoftware and no BEGIN
// block (nothing partial advertised).
func TestGenKeys_WriteFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { // read+exec, no write
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	code, out := genkeysStdout(t, dir, []string{"--rotate"})
	if code != exitSoftware {
		t.Errorf("write-failure rc=%d; want %d", code, exitSoftware)
	}
	if strings.Contains(out, "SSHGATE_XFER_PUBKEYS_BEGIN") {
		t.Error("a BEGIN block was printed despite the write failure")
	}
}

// TestGenKeys_ArgvDispatch: runLocalSubcommand rejects an unknown subcommand and
// an extra positional to genkeys with exitDataErr (65), and routes "genkeys".
func TestGenKeys_ArgvDispatch(t *testing.T) {
	if code := runLocalSubcommand([]string{"bogus"}); code != exitDataErr {
		t.Errorf("runLocalSubcommand(bogus) = %d; want %d", code, exitDataErr)
	}
	if code := runLocalSubcommand(nil); code != exitDataErr {
		t.Errorf("runLocalSubcommand(nil) = %d; want %d", code, exitDataErr)
	}
	dir := t.TempDir()
	withGateDir(t, dir)
	_ = captureStdout(t, func() {
		if code := runGenKeys([]string{"--bogus"}); code != exitDataErr {
			t.Errorf("runGenKeys(--bogus) = %d; want %d", code, exitDataErr)
		}
	})
}
