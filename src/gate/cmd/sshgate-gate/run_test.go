package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// This file drives run() and doRevoke() end-to-end through the
// test-only gateDirFn / homeDirFn package-var seams (see main.go). The
// seams let a same-package test point gate.pub resolution and the
// revoke home directory at t.TempDirs without re-exec'ing the binary —
// they are NOT environment-driven, so production attack surface is
// unchanged (an env override of where gate.pub is read would be a
// signature-forgery surface).
//
// Helpers withEnv and captureStderr live in main_test.go (same
// package) and are reused here. captureStdout, genKey, signedLine,
// withGateDir, withHomeDir, seedPub are defined below.

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns
// everything written. Mirror of captureStderr in main_test.go.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fn()
	_ = w.Close()
	<-done
	os.Stdout = orig
	_ = r.Close()
	return buf.String()
}

// genKey returns a fresh Ed25519 keypair from crypto/rand.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// signedLine signs payload p with priv and returns the SSHGATE_SIG wire
// string. Mirrors the gate package's verify_test helper.
func signedLine(t *testing.T, priv ed25519.PrivateKey, p sigwire.SigPayload) string {
	t.Helper()
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, pb)
	line, err := sigwire.EncodeSigned(sig, p)
	if err != nil {
		t.Fatalf("encode signed: %v", err)
	}
	return line
}

// testGateHostFP is the canonical host-key fingerprint the test gate
// self-derives (via the hostKeyFPsFn seam installed by runWith). freshPayload
// binds to it so a signed write that reaches the host check matches; tests
// that exercise cross-host rejection override the payload Host explicitly.
const testGateHostFP = "SHA256:testGateHostKeyFingerprintAAAAAAAAAAAAAAAAAA"

// freshPayload returns a payload that is valid against the real wall
// clock for the next 5 minutes (ts a second in the past, exp inside the
// MaxSigValidity window) and bound to the test gate's host key. run() reads
// time.Now(), so the window must cover actual test execution time.
func freshPayload(cmd string) sigwire.SigPayload {
	now := time.Now()
	return sigwire.SigPayload{
		Cmd:   cmd,
		TS:    now.Add(-1 * time.Second).Unix(),
		Exp:   now.Add(4 * time.Minute).Unix(),
		Nonce: "nonce-run-test",
		Host:  testGateHostFP,
	}
}

// withHostFPs points the hostKeyFPsFn seam at a fixed fingerprint set for the
// test, restoring the production loader on cleanup. The signed-write path in
// run() consults this to enforce the per-server host-key binding; without the
// seam a test would read the real /etc/ssh and fail closed.
func withHostFPs(t *testing.T, fps ...string) {
	t.Helper()
	prev := hostKeyFPsFn
	hostKeyFPsFn = func() ([]string, error) { return fps, nil }
	t.Cleanup(func() { hostKeyFPsFn = prev })
}

// withGateDir points the gateDirFn seam at dir (with binaryPath
// dir/gate) for the duration of the test, restoring the production
// default on cleanup.
func withGateDir(t *testing.T, dir string) {
	t.Helper()
	prev := gateDirFn
	binPath := filepath.Join(dir, "gate")
	gateDirFn = func() (string, string, error) {
		return dir, binPath, nil
	}
	t.Cleanup(func() { gateDirFn = prev })
}

// withGateDirErr points gateDirFn at a function that always fails, to
// exercise the os.Executable()-failure branch now reachable via the
// seam.
func withGateDirErr(t *testing.T, err error) {
	t.Helper()
	prev := gateDirFn
	gateDirFn = func() (string, string, error) {
		return "", "", err
	}
	t.Cleanup(func() { gateDirFn = prev })
}

// withHomeDir points the homeDirFn seam at dir for the test.
func withHomeDir(t *testing.T, dir string) {
	t.Helper()
	prev := homeDirFn
	homeDirFn = func() (string, error) { return dir, nil }
	t.Cleanup(func() { homeDirFn = prev })
}

// seedPub writes pub as a raw 32-byte gate.pub into dir at mode 0644
// (the secure default LoadPubKey accepts) and returns its path.
func seedPub(t *testing.T, dir string, pub ed25519.PublicKey, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "gate.pub")
	if err := os.WriteFile(path, pub, mode); err != nil {
		t.Fatalf("write gate.pub: %v", err)
	}
	// WriteFile honours umask; force the exact mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod gate.pub: %v", err)
	}
	return path
}

// runWith sets SSH_ORIGINAL_COMMAND and runs run(), capturing both
// stdout and stderr. Returns (exitCode, stdout, stderr).
func runWith(t *testing.T, cmd string) (int, string, string) {
	t.Helper()
	// Install a deterministic host-key fingerprint set so the signed-write
	// host-binding check resolves against testGateHostFP rather than the real
	// /etc/ssh on the build box. Tests that assert cross-host rejection install
	// their own narrower set AFTER calling this (Cleanup restores in reverse).
	withHostFPs(t, testGateHostFP)
	withEnv(t, "SSH_ORIGINAL_COMMAND", cmd)
	var code int
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			code = run()
		})
	})
	return code, out, stderr
}

// TestRunVerifiedPaths covers the signature-verification decision tree
// when gate.pub is present (Tier-2 install). Each subtest seeds a fresh
// gate.pub and points the gateDirFn seam at a TempDir.
func TestRunVerifiedPaths(t *testing.T) {
	t.Run("valid signed read execs and exits 0", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// A read command (cat) over a file we control. cat classifies
		// as KindRead, so even though it is signed it takes the read
		// path; it must exec and exit 0, streaming the file to stdout.
		f := filepath.Join(dir, "payload.txt")
		if err := os.WriteFile(f, []byte("hello-from-cat\n"), 0o644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		line := signedLine(t, priv, freshPayload("cat "+f))
		code, out, _ := runWith(t, line)
		if code != exitOK {
			t.Errorf("exit = %d, want %d", code, exitOK)
		}
		if !strings.Contains(out, "hello-from-cat") {
			t.Errorf("stdout = %q, want child output", out)
		}
	})

	t.Run("bad signature exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		_, wrongPriv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// Signed by the WRONG key; verifies against gate.pub -> fails.
		line := signedLine(t, wrongPriv, freshPayload("cat /etc/hostname"))
		code, _, stderr := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d; stderr=%q", code, exitDataErr, stderr)
		}
	})

	t.Run("wrong key entirely exits 65", func(t *testing.T) {
		dir := t.TempDir()
		// gate.pub holds otherPub; line is signed by priv (a different
		// key). Verification anchors on the file, so it fails.
		otherPub, _ := genKey(t)
		_, priv := genKey(t)
		seedPub(t, dir, otherPub, 0o644)
		withGateDir(t, dir)

		line := signedLine(t, priv, freshPayload("cat /etc/hostname"))
		code, _, _ := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d", code, exitDataErr)
		}
	})

	t.Run("tampered cmd exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// Sign one payload, then re-encode the SAME sig over a payload
		// whose cmd changed. The signature no longer matches the bytes.
		p := freshPayload("cat /etc/hostname")
		pb, _ := json.Marshal(p)
		sig := ed25519.Sign(priv, pb)
		tampered := p
		tampered.Cmd = "rm -rf /"
		line, err := sigwire.EncodeSigned(sig, tampered)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		code, _, _ := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d", code, exitDataErr)
		}
	})

	t.Run("expired signature exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		now := time.Now()
		p := sigwire.SigPayload{
			Cmd:   "cat /etc/hostname",
			TS:    now.Add(-120 * time.Second).Unix(),
			Exp:   now.Add(-1 * time.Second).Unix(), // already past
			Nonce: "n",
		}
		line := signedLine(t, priv, p)
		code, _, _ := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d", code, exitDataErr)
		}
	})

	t.Run("validity window over 5m exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		now := time.Now()
		p := sigwire.SigPayload{
			Cmd: "cat /etc/hostname",
			TS:  now.Add(-1 * time.Second).Unix(),
			// exp-ts exceeds MaxSigValidity (5m) -> rejected even though
			// the signature itself is valid and not yet expired.
			Exp:   now.Add(sigwire.MaxSigValidity + 1*time.Minute).Unix(),
			Nonce: "n",
		}
		line := signedLine(t, priv, p)
		code, _, _ := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d", code, exitDataErr)
		}
	})

	t.Run("malformed envelope exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// Correct prefix so IsSigned() routes it to VerifySigned, but
		// the body is junk: bad base64 / no payload separator.
		for _, bad := range []string{
			"SSHGATE_SIG:not-base64::also-not",      // bad base64
			"SSHGATE_SIG:" + strings.Repeat("A", 8), // no payload separator
			"SSHGATE_SIG:QQ:" + "!!!notbase64!!!",   // bad payload base64
		} {
			code, _, _ := runWith(t, bad)
			if code != exitDataErr {
				t.Errorf("cmd %q: exit = %d, want %d", bad, code, exitDataErr)
			}
		}
	})

	t.Run("bad JSON payload exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// Valid base64 in both fields but the payload base64 decodes to
		// non-JSON bytes -> DecodeSigned -> ErrBadFormat -> 65.
		line := "SSHGATE_SIG:QUFBQQ:" + base64URL("this is not json")
		code, _, _ := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d", code, exitDataErr)
		}
	})

	t.Run("signature bound to a different host exits 65", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// A perfectly valid, in-window signature — but its Host names ANOTHER
		// server. Replayed against this gate (whose host key is testGateHostFP
		// via runWith's seam), it must be refused at the binding check. This
		// is the end-to-end cross-host replay guard.
		p := freshPayload("cat /etc/hostname")
		p.Host = "SHA256:someOtherServerHostKeyFingerprintZZZZZZZZZZ"
		line := signedLine(t, priv, p)
		code, _, stderr := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d; stderr=%q", code, exitDataErr, stderr)
		}
	})

	t.Run("signature with no host binding exits 65 (fail closed)", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// Valid signature, valid window, but NO Host binding at all. The
		// signed path is binding-mandatory: must be refused.
		p := freshPayload("cat /etc/hostname")
		p.Host = ""
		line := signedLine(t, priv, p)
		code, _, stderr := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d; stderr=%q", code, exitDataErr, stderr)
		}
	})
}

// base64URL encodes s with the same URL-safe, unpadded alphabet the
// wire format uses, so the gate's DecodeSigned will successfully
// base64-decode it (and then fail on the JSON shape).
func base64URL(s string) string {
	// Reuse sigwire's encoder indirectly by round-tripping a payload is
	// overkill; build the encoding inline to keep the test honest about
	// what bytes reach DecodeSigned.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		out.WriteByte(alphabet[chunk[0]>>2])
		out.WriteByte(alphabet[(chunk[0]&0x03)<<4|chunk[1]>>4])
		if n > 1 {
			out.WriteByte(alphabet[(chunk[1]&0x0f)<<2|chunk[2]>>6])
		}
		if n > 2 {
			out.WriteByte(alphabet[chunk[2]&0x3f])
		}
	}
	return out.String()
}

// TestRunPubkeyFailures covers the EX_SOFTWARE (70) paths where gate.pub
// itself is unusable.
func TestRunPubkeyFailures(t *testing.T) {
	t.Run("corrupt gate.pub exits 70", func(t *testing.T) {
		dir := t.TempDir()
		// Garbage that is neither a 32-byte raw key nor a PEM block.
		if err := os.WriteFile(filepath.Join(dir, "gate.pub"), []byte("not a key at all"), 0o644); err != nil {
			t.Fatalf("seed corrupt pub: %v", err)
		}
		withGateDir(t, dir)
		code, _, stderr := runWith(t, "cat /etc/hostname")
		if code != exitSoftware {
			t.Errorf("exit = %d, want %d; stderr=%q", code, exitSoftware, stderr)
		}
	})

	for _, mode := range []os.FileMode{0o664, 0o666} {
		mode := mode
		t.Run("insecure gate.pub mode "+mode.String()+" exits 70", func(t *testing.T) {
			dir := t.TempDir()
			pub, _ := genKey(t)
			seedPub(t, dir, pub, mode) // group/world writable -> rejected
			withGateDir(t, dir)
			code, _, _ := runWith(t, "cat /etc/hostname")
			if code != exitSoftware {
				t.Errorf("exit = %d, want %d", code, exitSoftware)
			}
		})
	}

	t.Run("gateDirFn failure exits 70", func(t *testing.T) {
		// os.Executable()-style failure is now reachable through the
		// seam. pubKeyPath() bubbles the error and run() maps it to
		// EX_SOFTWARE.
		withGateDirErr(t, errFake)
		code, _, stderr := runWith(t, "cat /etc/hostname")
		if code != exitSoftware {
			t.Errorf("exit = %d, want %d; stderr=%q", code, exitSoftware, stderr)
		}
		if !strings.Contains(stderr, "locate pubkey") {
			t.Errorf("stderr = %q, want 'locate pubkey'", stderr)
		}
	})
}

// errFake is a stable sentinel for the gateDirFn-failure case.
var errFake = &fakeErr{}

type fakeErr struct{}

func (*fakeErr) Error() string { return "fake os.Executable failure" }

// TestRunWriteDenial covers the write-vs-read authorization edges with a
// key present.
func TestRunWriteDenial(t *testing.T) {
	t.Run("unsigned write exits 77 with SSHGATE_SIG-prefix message", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// rm classifies as KindWrite; unsigned -> 77 with the distinct
		// "requires a SSHGATE_SIG prefix" message (NOT the read-only
		// "no signing key configured" message).
		code, _, stderr := runWith(t, "rm -rf /tmp/whatever")
		if code != exitNoPermVal {
			t.Errorf("exit = %d, want %d", code, exitNoPermVal)
		}
		if !strings.Contains(stderr, "require a SSHGATE_SIG prefix") {
			t.Errorf("stderr = %q, want 'require a SSHGATE_SIG prefix'", stderr)
		}
		// Must be distinct from the read-only-mode messaging.
		if strings.Contains(stderr, "no signing key configured") {
			t.Errorf("stderr leaked read-only-mode message: %q", stderr)
		}
	})

	t.Run("unsigned KindUnknown inner is denied as write (77)", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// A whitespace-only command is non-empty (so not the probe) but
		// classifies as KindUnknown; unsigned, it falls into the
		// write/unknown branch and is denied with 77 — never executed.
		code, _, stderr := runWith(t, "   ")
		if code != exitNoPermVal {
			t.Errorf("exit = %d, want %d; stderr=%q", code, exitNoPermVal, stderr)
		}
	})
}

// TestRunReadOnlyExecsRealChild covers the Tier-1 (no gate.pub) read
// path actually exec'ing a child — complementing the existing
// TestRunReadOnlyMode which only asserts the denial messaging. Here we
// point gateDirFn at an empty TempDir (no gate.pub) so LoadPubKey
// returns (nil, nil) and an unsigned read runs.
func TestRunReadOnlyExecsRealChild(t *testing.T) {
	dir := t.TempDir() // no gate.pub seeded -> read-only mode
	withGateDir(t, dir)

	f := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(f, []byte("readonly-child-output\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	code, out, _ := runWith(t, "cat "+f)
	if code != exitOK {
		t.Errorf("exit = %d, want %d (child cat exits 0)", code, exitOK)
	}
	if !strings.Contains(out, "readonly-child-output") {
		t.Errorf("stdout = %q, want child output", out)
	}
}

// TestRunSignedWritePassthrough covers a signed write actually exec'ing
// and the child's exit code passing through run() verbatim.
func TestRunSignedWritePassthrough(t *testing.T) {
	t.Run("signed write child exit passes through", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// `exit 42` classifies as a write; signed -> exec'd via
		// /bin/sh -c 'exit 42'; run() must return 42 unchanged.
		line := signedLine(t, priv, freshPayload("exit 42"))
		code, _, _ := runWith(t, line)
		if code != 42 {
			t.Errorf("exit = %d, want 42 (child exit must pass through)", code)
		}
	})

	t.Run("signed write child killed by signal -> 128+signum", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// The child kills its own process group with SIGTERM(15);
		// gate's executor reports 128+15 = 143, which run() passes up.
		line := signedLine(t, priv, freshPayload("sh -c 'kill -TERM $$'"))
		code, _, _ := runWith(t, line)
		if code != 128+15 {
			t.Errorf("exit = %d, want %d (128+SIGTERM)", code, 128+15)
		}
	})

	t.Run("signed write empty inner -> exec start-failure -> exit 1", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		// A signed whitespace cmd survives DecodeSigned (only empty is
		// rejected) and verifies; classify(" ") = KindUnknown -> signed
		// write branch -> execChild(" "); ExecWithRedaction rejects the
		// empty command, returning exit<0, which execChild maps to
		// exitGeneric (1).
		line := signedLine(t, priv, freshPayload(" "))
		code, _, _ := runWith(t, line)
		if code != exitGeneric {
			t.Errorf("exit = %d, want %d (exec start-failure)", code, exitGeneric)
		}
	})
}

// TestRunAdminCommands covers the signed administrative verbs and the
// security regression pin that UNSIGNED admin verbs are never honored.
func TestRunAdminCommands(t *testing.T) {
	t.Run("signed SSHGATE_REVOKE runs doRevoke and prints SSHGATE_REVOKED", func(t *testing.T) {
		dir := t.TempDir()
		home := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		withHomeDir(t, home)

		// Seed an authorized_keys with the gate's restricted line so the
		// revoke has something to strip. binaryPath the seam reports is
		// <dir>/gate.
		sshDir := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			t.Fatalf("mkdir .ssh: %v", err)
		}
		binPath := filepath.Join(dir, "gate")
		authLine := `command="` + binPath + `",no-pty ssh-ed25519 AAAAtest sshgate@laptop`
		if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(authLine+"\n"), 0o600); err != nil {
			t.Fatalf("seed authorized_keys: %v", err)
		}

		line := signedLine(t, priv, freshPayload("SSHGATE_REVOKE"))
		code, out, _ := runWith(t, line)
		if code != exitOK {
			t.Errorf("exit = %d, want %d", code, exitOK)
		}
		if !strings.Contains(out, "SSHGATE_REVOKED") {
			t.Errorf("stdout = %q, want SSHGATE_REVOKED", out)
		}
		// The restricted line must be gone from authorized_keys.
		got, _ := os.ReadFile(filepath.Join(sshDir, "authorized_keys"))
		if strings.Contains(string(got), "AAAAtest") {
			t.Errorf("authorized_keys still has the gate line:\n%s", got)
		}
	})

	t.Run("signed SSHGATE_UPDATE with a malformed hash arg -> exit 65", func(t *testing.T) {
		// The verb is implemented (see update_test.go for the full matrix);
		// this pins the run()->handleUpdate integration for a non-hash arg:
		// "v1.1.0" is not 64 lowercase hex, so it is rejected with EX_DATAERR
		// and nothing is installed. (runWith sends no stdin, so even a valid
		// hash would then hit the empty-stdin refusal — also 65.)
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		line := signedLine(t, priv, freshPayload("SSHGATE_UPDATE v1.1.0"))
		code, _, stderr := runWith(t, line)
		if code != exitDataErr {
			t.Errorf("exit = %d, want %d", code, exitDataErr)
		}
		if !strings.Contains(stderr, "malformed hash") {
			t.Errorf("stderr = %q, want 'malformed hash'", stderr)
		}
	})

	// SECURITY REGRESSION PIN: an UNSIGNED SSHGATE_REVOKE / SSHGATE_UPDATE
	// must NOT be treated as an admin command. Both tokens classify as
	// KindWrite (unknown binary), so without a signature they fall into
	// the write-denied branch (77) — they never reach doRevoke or the
	// update stub, and they leave authorized_keys untouched. If this
	// ever regresses to honoring unsigned admin verbs, an attacker who
	// merely reaches the gate (no master key) could self-revoke or
	// trigger an update.
	for _, verb := range []string{"SSHGATE_REVOKE", "SSHGATE_UPDATE v9"} {
		verb := verb
		t.Run("unsigned admin verb is denied not honored: "+verb, func(t *testing.T) {
			dir := t.TempDir()
			home := t.TempDir()
			pub, _ := genKey(t)
			seedPub(t, dir, pub, 0o644)
			withGateDir(t, dir)
			withHomeDir(t, home)

			// Seed authorized_keys so we can prove it is left intact.
			sshDir := filepath.Join(home, ".ssh")
			if err := os.MkdirAll(sshDir, 0o700); err != nil {
				t.Fatalf("mkdir .ssh: %v", err)
			}
			binPath := filepath.Join(dir, "gate")
			authLine := `command="` + binPath + `",no-pty ssh-ed25519 AAAAtest sshgate@laptop`
			authPath := filepath.Join(sshDir, "authorized_keys")
			if err := os.WriteFile(authPath, []byte(authLine+"\n"), 0o600); err != nil {
				t.Fatalf("seed authorized_keys: %v", err)
			}

			code, out, _ := runWith(t, verb)
			if code != exitNoPermVal {
				t.Errorf("exit = %d, want %d (unsigned admin must be write-denied)", code, exitNoPermVal)
			}
			if strings.Contains(out, "SSHGATE_REVOKED") {
				t.Errorf("unsigned admin verb produced revoke output: %q", out)
			}
			// authorized_keys must be untouched.
			got, _ := os.ReadFile(authPath)
			if !strings.Contains(string(got), "AAAAtest") {
				t.Errorf("unsigned admin verb mutated authorized_keys:\n%s", got)
			}
		})
	}
}

// TestRunReplayWithinWindow pins the INTENDED behavior that there is no
// server-side nonce cache: the same valid envelope replayed twice within
// its validity window succeeds BOTH times. This is by design — the
// defense against replay is the short (<=5m) validity window plus the
// human Telegram approval that gates issuance of any signature, not a
// per-nonce ledger on the gate. If a nonce cache is ever added, this
// test should be updated deliberately (not silently weakened).
func TestRunReplayWithinWindow(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	f := filepath.Join(dir, "replay.txt")
	if err := os.WriteFile(f, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	line := signedLine(t, priv, freshPayload("cat "+f))

	for i := 0; i < 2; i++ {
		code, out, _ := runWith(t, line)
		if code != exitOK {
			t.Errorf("replay %d: exit = %d, want %d (no nonce cache: replay succeeds)", i, code, exitOK)
		}
		if !strings.Contains(out, "ok") {
			t.Errorf("replay %d: stdout = %q, want child output", i, out)
		}
	}
}

// TestRunProbeWithKeyPresent pins that the empty-command post-install
// probe short-circuits to SSHGATE_OK BEFORE any pubkey resolution, even
// when a gate.pub exists.
func TestRunProbeWithKeyPresent(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	code, out, _ := runWith(t, "")
	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out, "SSHGATE_OK") {
		t.Errorf("stdout = %q, want SSHGATE_OK", out)
	}
}

// TestDoRevokeUnwritableSSHDir covers the permission-denied branch of
// doRevoke: when ~/.ssh is mode 0500, the atomic rewrite (and backup
// write) of authorized_keys cannot create files in it, so gate.Revoke
// returns an error and doRevoke returns exitGeneric (1). Skipped if the
// process can write through the mode bits anyway (e.g. running as root).
func TestDoRevokeUnwritableSSHDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file modes do not deny writes")
	}
	dir := t.TempDir()
	home := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)
	withHomeDir(t, home)

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	binPath := filepath.Join(dir, "gate")
	// A MATCHING line so Revoke attempts a rewrite (which needs to
	// create a temp file + backup inside .ssh).
	authLine := `command="` + binPath + `",no-pty ssh-ed25519 AAAAtest sshgate@laptop`
	authPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(authPath, []byte(authLine+"\n"), 0o600); err != nil {
		t.Fatalf("seed authorized_keys: %v", err)
	}
	// Make .ssh non-writable (r-x). Restore before cleanup so t.TempDir
	// can delete it.
	if err := os.Chmod(sshDir, 0o500); err != nil {
		t.Fatalf("chmod .ssh: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sshDir, 0o700) })

	line := signedLine(t, priv, freshPayload("SSHGATE_REVOKE"))
	code, out, stderr := runWith(t, line)
	if code != exitGeneric {
		t.Errorf("exit = %d, want %d (permission-denied rewrite)", code, exitGeneric)
	}
	if strings.Contains(out, "SSHGATE_REVOKED") {
		t.Errorf("revoke wrongly reported success: %q", out)
	}
	if !strings.Contains(stderr, "revoke:") {
		t.Errorf("stderr = %q, want a 'revoke:' error line", stderr)
	}
}
