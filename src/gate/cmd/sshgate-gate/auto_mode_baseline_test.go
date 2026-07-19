package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// TestAutoModeBaseline freezes the pre-policy gate contract. Policy-aware
// integration must preserve these routes when the effective mode is auto:
// classifier-proven reads execute unsigned, writes need a valid host-bound
// signature, and reveal/admin capabilities retain their signed-only special
// dispatch rather than becoming ordinary policy entries.
func TestAutoModeBaseline(t *testing.T) {
	t.Run("unsigned proven read executes directly", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		path := filepath.Join(dir, "read.txt")
		if err := os.WriteFile(path, []byte("auto-read-ok\n"), 0o600); err != nil {
			t.Fatalf("seed read fixture: %v", err)
		}

		code, out, stderr := runWith(t, "cat "+path)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d; stderr=%q", code, exitOK, stderr)
		}
		if out != "auto-read-ok\n" {
			t.Fatalf("stdout = %q, want direct child output", out)
		}
	})

	t.Run("unsigned write is denied without side effects", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		target := filepath.Join(dir, "unsigned-write-must-not-exist")
		code, _, stderr := runWith(t, "touch "+target)
		if code != exitNoPermVal {
			t.Fatalf("exit = %d, want %d; stderr=%q", code, exitNoPermVal, stderr)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("unsigned write produced a side effect: stat err=%v", err)
		}
	})

	t.Run("valid host-bound signed write executes", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		target := filepath.Join(dir, "signed-write-executed")
		payload := freshPayload("touch " + target)
		if payload.Host != testGateHostFP {
			t.Fatalf("test payload host = %q, want %q", payload.Host, testGateHostFP)
		}
		code, _, stderr := runWith(t, signedLine(t, priv, payload))
		if code != exitOK {
			t.Fatalf("exit = %d, want %d; stderr=%q", code, exitOK, stderr)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("signed write did not execute: %v", err)
		}
	})

	t.Run("reveal stays a signed-only capability", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		cmd := "echo " + awsKey
		code, out, stderr := runWith(t, cmd)
		if code != exitOK {
			t.Fatalf("unsigned read exit = %d, want %d; stderr=%q", code, exitOK, stderr)
		}
		if strings.Contains(out, awsKey) || !strings.Contains(out, redact.MarkerPrefix) {
			t.Fatalf("unsigned read must remain redacted; stdout=%q", out)
		}

		payload := freshPayload(cmd)
		payload.Reveal = true
		code, out, stderr = runWith(t, signedLine(t, priv, payload))
		if code != exitOK {
			t.Fatalf("signed reveal exit = %d, want %d; stderr=%q", code, exitOK, stderr)
		}
		if !strings.Contains(out, awsKey) || strings.Contains(out, redact.MarkerPrefix) {
			t.Fatalf("signed reveal must return raw output; stdout=%q", out)
		}
	})

	t.Run("admin stays signed-only special dispatch", func(t *testing.T) {
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
		authPath := filepath.Join(sshDir, "authorized_keys")
		authLine := `command="` + filepath.Join(dir, "gate") + `",no-pty ssh-ed25519 AAAAtest sshgate@laptop`
		if err := os.WriteFile(authPath, []byte(authLine+"\n"), 0o600); err != nil {
			t.Fatalf("seed authorized_keys: %v", err)
		}

		code, out, stderr := runWith(t, "SSHGATE_REVOKE")
		if code != exitNoPermVal {
			t.Fatalf("unsigned revoke exit = %d, want %d; stderr=%q", code, exitNoPermVal, stderr)
		}
		if strings.Contains(out, "SSHGATE_REVOKED") {
			t.Fatalf("unsigned revoke reached admin dispatch: stdout=%q", out)
		}
		if got, err := os.ReadFile(authPath); err != nil || !strings.Contains(string(got), "AAAAtest") {
			t.Fatalf("unsigned revoke changed authorized_keys: contents=%q err=%v", got, err)
		}

		code, out, stderr = runWith(t, signedLine(t, priv, freshPayload("SSHGATE_REVOKE")))
		if code != exitOK {
			t.Fatalf("signed revoke exit = %d, want %d; stderr=%q", code, exitOK, stderr)
		}
		if !strings.Contains(out, "SSHGATE_REVOKED") {
			t.Fatalf("signed revoke did not reach admin dispatch: stdout=%q", out)
		}
		if got, err := os.ReadFile(authPath); err != nil || strings.Contains(string(got), "AAAAtest") {
			t.Fatalf("signed revoke did not remove restricted key: contents=%q err=%v", got, err)
		}
	})
}
