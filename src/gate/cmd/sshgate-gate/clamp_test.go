//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireClampHost skips unless Ubuntu's AppArmor userns restriction is on.
// SSHGATE_REQUIRE_CLAMP_TEST=1 (a test-only switch; the gate reads no policy
// from the environment) turns the skip into a failure, so the CI step that
// runs on a clamp host cannot pass by skipping.
func requireClampHost(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		return
	}
	if os.Getenv("SSHGATE_REQUIRE_CLAMP_TEST") == "1" {
		t.Fatalf("the AppArmor userns restriction is not on (%q, %v)", b, err)
	}
	t.Skip("the AppArmor userns restriction is not on")
}

// checkClampRead asserts an unsigned read on an unpinned clamp host: it ran
// classifier-only after the jail's clone was refused, quietly.
func checkClampRead(t *testing.T, dir string, code int, out, stderr, want string) {
	t.Helper()
	if code != exitOK || out != want || stderr != "" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["enforcement"] != "classifier" || recs[0]["net"] != true || recs[0]["jail_absent"] != "clone:EACCES" {
		t.Fatalf("audit = %v, want one classifier-only read after clone:EACCES", recs)
	}
}

// TestRunReadClampHostRunsClassifierOnly runs on stock Ubuntu 24.04 with no
// seams: the real executor and the real host facts.
func TestRunReadClampHostRunsClassifierOnly(t *testing.T) {
	requireClampHost(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("clamp fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runWith(t, "cat "+fixture)
	checkClampRead(t, dir, code, out, stderr, "clamp fixture\n")
}

// TestGateBinaryClampHostClassifierOnly drives the real gate binary the way
// sshd does on a Tier-1 clamp host.
func TestGateBinaryClampHostClassifierOnly(t *testing.T) {
	requireClampHost(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, out)
	}
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("clamp fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gate := exec.Command(bin) // no argv: the forced-command shape
	gate.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=cat "+fixture)
	var stdout, stderr bytes.Buffer
	gate.Stdout, gate.Stderr = &stdout, &stderr
	code := 0
	if err := gate.Run(); err != nil {
		code = -1
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
	}
	checkClampRead(t, dir, code, stdout.String(), stderr.String(), "clamp fixture\n")
}
