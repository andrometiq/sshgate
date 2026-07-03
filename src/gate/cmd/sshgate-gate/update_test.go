package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runWithStdin mirrors runWith but also feeds stdin bytes to the gate process
// (the SSHGATE_UPDATE binary channel). The writer is closed so the handler
// sees EOF.
func runWithStdin(t *testing.T, cmd string, stdin []byte) (int, string, string) {
	t.Helper()
	withHostFPs(t, testGateHostFP)
	withEnv(t, "SSH_ORIGINAL_COMMAND", cmd)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin; _ = r.Close() })
	go func() {
		_, _ = w.Write(stdin)
		_ = w.Close()
	}()

	var code int
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			code = run()
		})
	})
	return code, out, stderr
}

// readSelfELF returns this test binary's own bytes — a real ELF for the
// current arch, comfortably above minGateBinaryBytes — as the "new gate binary"
// fixture. It skips (rather than fails) if the platform can't provide it.
func readSelfELF(t *testing.T) []byte {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Skipf("read self: %v", err)
	}
	if int64(len(b)) < minGateBinaryBytes {
		t.Skipf("test binary %d bytes < min %d", len(b), minGateBinaryBytes)
	}
	return b
}

func seedGate(t *testing.T, dir string) (binPath string, pubBefore []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, pk := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)
	binPath = filepath.Join(dir, "gate")
	if err := os.WriteFile(binPath, []byte("OLD-GATE-BINARY"), 0o755); err != nil {
		t.Fatalf("seed gate: %v", err)
	}
	pubBefore, _ = os.ReadFile(filepath.Join(dir, "gate.pub"))
	return binPath, pubBefore, pk
}

// TestUpdate_HappyPath: a signed SSHGATE_UPDATE whose hash matches the streamed
// ELF replaces the gate in place, backs up the old binary, leaves gate.pub
// untouched, and prints the success marker.
func TestUpdate_HappyPath(t *testing.T) {
	dir := t.TempDir()
	binPath, pubBefore, priv := seedGate(t, dir)

	newBin := readSelfELF(t)
	sum := sha256.Sum256(newBin)
	hexHash := hex.EncodeToString(sum[:])
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hexHash))

	code, out, stderr := runWithStdin(t, line, newBin)
	if code != exitOK {
		t.Fatalf("exit = %d; want 0 (stderr=%q)", code, stderr)
	}
	if !strings.Contains(out, "SSHGATE_UPDATED sha256="+hexHash) {
		t.Errorf("stdout = %q; want SSHGATE_UPDATED marker with the hash", out)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, newBin) {
		t.Errorf("gate binary was not replaced with the new bytes")
	}
	if bak, err := os.ReadFile(binPath + ".bak"); err != nil || !bytes.Equal(bak, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate.bak = %q err=%v; want the old binary preserved", bak, err)
	}
	if pubAfter, _ := os.ReadFile(filepath.Join(dir, "gate.pub")); !bytes.Equal(pubBefore, pubAfter) {
		t.Errorf("gate.pub changed; the trust anchor must be untouched")
	}
}

// TestUpdate_HashMismatchWritesNothing: streaming bytes that don't match the
// approved hash must refuse (exit 65) and leave the gate + no .bak.
func TestUpdate_HashMismatchWritesNothing(t *testing.T) {
	dir := t.TempDir()
	binPath, _, priv := seedGate(t, dir)

	newBin := readSelfELF(t)
	wrong := sha256.Sum256([]byte("a different binary than what we stream"))
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(wrong[:])))

	code, _, _ := runWithStdin(t, line, newBin)
	if code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on hash mismatch", code)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate binary modified on a hash mismatch — must write nothing")
	}
	if _, err := os.Stat(binPath + ".bak"); err == nil {
		t.Errorf(".bak created for a refused update — nothing should be written")
	}
}

// TestUpdate_NonELFRefused: bytes that match the signed hash but are not an ELF
// must be refused before any write (would brick the gate).
func TestUpdate_NonELFRefused(t *testing.T) {
	dir := t.TempDir()
	binPath, _, priv := seedGate(t, dir)

	body := bytes.Repeat([]byte("A"), int(minGateBinaryBytes)+10) // big enough, not ELF
	sum := sha256.Sum256(body)
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(sum[:])))

	code, _, _ := runWithStdin(t, line, body)
	if code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on non-ELF body", code)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate replaced with a non-ELF body")
	}
}

// TestUpdate_AnchoredParseRejectsTrailing: "SSHGATE_UPDATE <hex>; rm -rf /"
// must be rejected (exit 65) and never install nor exec the suffix.
func TestUpdate_AnchoredParseRejectsTrailing(t *testing.T) {
	dir := t.TempDir()
	binPath, _, priv := seedGate(t, dir)

	newBin := readSelfELF(t)
	sum := sha256.Sum256(newBin)
	cmd := "SSHGATE_UPDATE " + hex.EncodeToString(sum[:]) + "; rm -rf /"
	line := signedLine(t, priv, freshPayload(cmd))

	code, _, _ := runWithStdin(t, line, newBin)
	if code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on trailing bytes", code)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate replaced despite a malformed (trailing) command")
	}
}

// TestUpdate_EmptyStdinRefused: an empty binary stream is refused.
func TestUpdate_EmptyStdinRefused(t *testing.T) {
	dir := t.TempDir()
	_, _, priv := seedGate(t, dir)
	sum := sha256.Sum256(nil)
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(sum[:])))
	if code, _, _ := runWithStdin(t, line, nil); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on empty stdin", code)
	}
}

// TestUpdate_OverCapRefused: a stream larger than the cap is refused via the
// bounded read (no OOM). Shrinks the cap to avoid a 64 MiB fixture.
func TestUpdate_OverCapRefused(t *testing.T) {
	saved := maxGateBinaryBytes
	maxGateBinaryBytes = 128
	t.Cleanup(func() { maxGateBinaryBytes = saved })

	dir := t.TempDir()
	_, _, priv := seedGate(t, dir)
	body := bytes.Repeat([]byte("A"), 512) // > 128-byte cap
	sum := sha256.Sum256(body)
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(sum[:])))
	if code, _, _ := runWithStdin(t, line, body); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 over cap", code)
	}
}

// TestUpdate_WrongArchELFRefused: bytes that match the signed hash and parse as
// a valid ELF, but declare a DIFFERENT machine than the running gate's arch,
// must be refused (exit 65) before any write — a wrong-arch binary passes the
// ELF-magic check yet bricks the gate on its next exec (Finding 3, the whole
// reason checkGateELF compares e_machine to GOARCH).
func TestUpdate_WrongArchELFRefused(t *testing.T) {
	dir := t.TempDir()
	binPath, _, priv := seedGate(t, dir)

	body := append([]byte(nil), readSelfELF(t)...) // copy — we mutate e_machine
	// e_machine is a little-endian uint16 at byte offset 18. Only patch a
	// confirmed little-endian ELF (EI_DATA == ELFDATA2LSB == 1 at offset 5);
	// a big-endian header would place the field differently.
	if body[5] != 1 {
		t.Skip("self ELF is not little-endian (ELFDATA2LSB); wrong-arch patch assumes LE layout")
	}
	// Flip the declared machine to a DIFFERENT architecture so debug/elf still
	// parses a valid ELF but checkGateELF sees the wrong e_machine for this
	// gate's GOARCH and refuses: amd64 (EM_X86_64=62/0x3E) → aarch64
	// (EM_AARCH64=183/0xB7), anything else → amd64.
	const emX8664, emAArch64 = 62, 183
	cur := uint16(body[18]) | uint16(body[19])<<8
	target := uint16(emX8664)
	if cur == emX8664 {
		target = emAArch64
	}
	body[18] = byte(target)
	body[19] = byte(target >> 8)

	sum := sha256.Sum256(body)
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(sum[:])))

	code, _, _ := runWithStdin(t, line, body)
	if code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on a wrong-arch ELF", code)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate replaced with a wrong-arch ELF")
	}
	if _, err := os.Stat(binPath + ".bak"); err == nil {
		t.Errorf(".bak created for a refused wrong-arch update — nothing should be written")
	}
}

// TestUpdate_UndersizeRefused: a real ELF below the minGateBinaryBytes floor is
// refused (exit 65) with the gate untouched. The floor is temporarily RAISED
// above a real ELF's size (restored via t.Cleanup) to exercise the undersize
// guard specifically — mirroring TestUpdate_OverCapRefused's shrink-the-cap
// pattern.
func TestUpdate_UndersizeRefused(t *testing.T) {
	dir := t.TempDir()
	binPath, _, priv := seedGate(t, dir)

	body := readSelfELF(t) // a real ELF, normally comfortably above the floor

	saved := minGateBinaryBytes
	minGateBinaryBytes = int64(len(body)) + 1 // now our real ELF is "undersize"
	t.Cleanup(func() { minGateBinaryBytes = saved })

	sum := sha256.Sum256(body)
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(sum[:])))

	code, _, _ := runWithStdin(t, line, body)
	if code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on an undersize binary", code)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate replaced with an undersize binary")
	}
	if _, err := os.Stat(binPath + ".bak"); err == nil {
		t.Errorf(".bak created for a refused undersize update — nothing should be written")
	}
}

// TestUpdate_Tier1RefusesBeforeHandler: on a read-only gate (no gate.pub) the
// signed update line is denied at exit 77 upstream — handleUpdate never runs,
// and the gate is untouched.
func TestUpdate_Tier1RefusesBeforeHandler(t *testing.T) {
	dir := t.TempDir()
	_, priv := genKey(t)
	withGateDir(t, dir) // NO seedPub → Tier-1
	binPath := filepath.Join(dir, "gate")
	if err := os.WriteFile(binPath, []byte("OLD-GATE-BINARY"), 0o755); err != nil {
		t.Fatalf("seed gate: %v", err)
	}
	newBin := readSelfELF(t)
	sum := sha256.Sum256(newBin)
	line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE "+hex.EncodeToString(sum[:])))

	code, _, stderr := runWithStdin(t, line, newBin)
	if code != exitNoPermVal {
		t.Fatalf("exit = %d; want 77 (Tier-1 denies signed lines)", code)
	}
	if !strings.Contains(stderr, "no signing key configured") {
		t.Errorf("stderr = %q; want the read-only denial", stderr)
	}
	if got, _ := os.ReadFile(binPath); !bytes.Equal(got, []byte("OLD-GATE-BINARY")) {
		t.Errorf("gate modified on a Tier-1 box")
	}
}

// TestSSHGateVersion: the unsigned SSHGATE_VERSION probe prints the running
// gate's build VERSION (from the compiled-in marker, not vcs) and exits 0. The
// test binary carries no -X override, so it reports the default marker's token
// "dev" — proving runningGateVersion reads versionMarker (spec §11.2), because
// the old vcs path would have yielded a git sha or "unknown". The rev= key stays
// frozen (HIGH-2).
func TestSSHGateVersion(t *testing.T) {
	code, out, _ := runWith(t, "SSHGATE_VERSION")
	if code != exitOK {
		t.Fatalf("exit = %d; want 0", code)
	}
	if got := strings.TrimSpace(out); got != "SSHGATE_VERSION rev=dev" {
		t.Errorf("stdout = %q; want %q (default marker token, proves the marker is read not vcs)", got, "SSHGATE_VERSION rev=dev")
	}
}
