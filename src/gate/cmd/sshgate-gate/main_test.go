package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// withEnv sets SSH_ORIGINAL_COMMAND for the duration of the test and
// restores the previous value (or unset state) on cleanup.
func withEnv(t *testing.T, key, val string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Setenv(key, val); err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// captureStderr swaps os.Stderr for a pipe, runs fn, and returns
// everything written. The pipe is restored on return so subsequent
// tests are unaffected.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fn()
	_ = w.Close()
	<-done
	os.Stderr = orig
	_ = r.Close()
	return buf.String()
}

// TestRunReadOnlyMode covers the tier-1 install where gate.pub is
// absent. The binary lives in an empty TempDir so pubKeyPath() resolves
// to a non-existent file and LoadPubKey returns (nil, nil).
//
// We can't easily redirect os.Executable() to a TempDir without
// re-exec'ing, so we exercise the keystore + classify decision tree
// indirectly by asserting the documented exit codes / stderr lines on
// the run() entry point. Read commands need to actually exec, which we
// avoid by checking against the documented EX_NOPERM denial messaging
// on write/signed paths — the read path is covered by the existing
// executor_test.
//
// The pubkey-missing branch only triggers if gate's pubKeyPath()
// (sibling-of-binary) does not exist. For the unit test binary, the
// sibling is the test binary's own directory, which won't contain a
// "gate.pub" — so the read-only branch is exactly what we hit.
func TestRunReadOnlyMode(t *testing.T) {
	// Sanity: ensure the test binary's sibling gate.pub really is
	// absent before we run. If a previous failed test left one behind,
	// remove it so we get a clean run.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	pub := filepath.Join(filepath.Dir(exe), "gate.pub")
	if _, err := os.Stat(pub); err == nil {
		t.Skipf("gate.pub present at %s; skipping read-only test", pub)
	}

	t.Run("signed command exits 77 with descriptive stderr", func(t *testing.T) {
		// A SIG-prefixed line — verification would normally fail, but
		// the read-only branch short-circuits before VerifySigned runs.
		withEnv(t, "SSH_ORIGINAL_COMMAND", "SSHGATE_SIG:abc:0:0:dummy ls")
		var code int
		stderr := captureStderr(t, func() {
			code = run()
		})
		if code != exitNoPermVal {
			t.Errorf("exit = %d, want %d", code, exitNoPermVal)
		}
		if want := "no signing key configured"; !bytes.Contains([]byte(stderr), []byte(want)) {
			t.Errorf("stderr = %q, want substring %q", stderr, want)
		}
	})

	t.Run("write command exits 77 with re-run /sshgate:setup hint", func(t *testing.T) {
		// `rm` classifies as KindWrite.
		withEnv(t, "SSH_ORIGINAL_COMMAND", "rm -rf /tmp/whatever")
		var code int
		stderr := captureStderr(t, func() {
			code = run()
		})
		if code != exitNoPermVal {
			t.Errorf("exit = %d, want %d", code, exitNoPermVal)
		}
		if want := "read-only install"; !bytes.Contains([]byte(stderr), []byte(want)) {
			t.Errorf("stderr = %q, want substring %q", stderr, want)
		}
		if want := "/sshgate:setup"; !bytes.Contains([]byte(stderr), []byte(want)) {
			t.Errorf("stderr = %q, want substring %q", stderr, want)
		}
	})

	t.Run("empty command is the probe path and prints SSHGATE_OK", func(t *testing.T) {
		withEnv(t, "SSH_ORIGINAL_COMMAND", "")
		// Capture stdout for the probe assertion.
		origOut := os.Stdout
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
		code := run()
		_ = w.Close()
		<-done
		os.Stdout = origOut
		_ = r.Close()
		if code != exitOK {
			t.Errorf("exit = %d, want 0", code)
		}
		if !bytes.Contains(buf.Bytes(), []byte("SSHGATE_OK")) {
			t.Errorf("stdout = %q, want SSHGATE_OK", buf.String())
		}
	})
}

// TestGateSentinelsAreJailOnly: the real binary dispatches only the jail's
// shim and worker sentinels and the jailed selftest. Run unjailed, with its
// own namespaces declared as the outer ones, the selftest refuses (77) and
// touches nothing. The retired probe sentinel and the test binary's capless
// reader reach the operator subcommands and are refused like any unknown one.
func TestGateSentinelsAreJailOnly(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, out)
	}
	for _, sentinel := range []string{"__jailprobe", sentinelCaplessReader} {
		out, err := exec.Command(bin, sentinel, "{}").CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != exitDataErr || string(out) != "gate: unknown subcommand\n" {
			t.Fatalf("%s: %v, output %q; want exit %d as an unknown subcommand", sentinel, err, out, exitDataErr)
		}
	}
	canary := filepath.Join(dir, "canary")
	if err := os.WriteFile(canary, []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	own, err := ownNamespaces()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{sentinelSelftest, fmt.Sprintf("--outer-ns=%d:%d", own[0], own[1]), "--canary=" + canary, "--fifo=" + filepath.Join(dir, "fifo"),
		"--unix=" + filepath.Join(dir, "sock"), "--abstract=sshgate-doctor-test", "--tcp4=127.0.0.1:9", "--pid=" + strconv.Itoa(os.Getpid()),
		"--tmp=" + canary, "--shm=sshgate-doctor-test", "--nonce=" + strings.Repeat("a", 32), "--net=deny"}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != exitNoPermVal || len(out) != 0 {
		t.Fatalf("unjailed selftest: %v, output %q; want exit %d and no output", err, out, exitNoPermVal)
	}
	if data, _ := os.ReadFile(canary); string(data) != "orig\n" {
		t.Fatalf("the unjailed selftest changed the canary: %q", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("the unjailed selftest created files: %v", entries)
	}
}
