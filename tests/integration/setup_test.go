//go:build integration

// Setup-script syntax test (task 2.4; updated in v1.1 Task A — the
// install/user-provisioning scripts collapsed into a single install.sh).
//
// Privileged-container integration smoke (boot Ubuntu, run install.sh,
// assert systemctl active) is still deferred — running systemd inside
// docker on a dev box is fiddly and not worth the complexity for an
// idempotent shell-script chain that's read by humans before it runs.
// Revisit when a CI runner with privileged containers is available.
//
// What this test DOES do: lint every shell script under scripts/ with
// `bash -n` (syntax check) and `shellcheck` (when installed). It's
// cheap, it runs in CI, and it catches the easy-to-miss class of bugs
// (unquoted vars, mismatched quotes, accidental `$1` typos).
package integration_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// scriptsDir resolves to <repo-root>/scripts based on this file's
// location. We can't rely on the test's cwd — `go test` runs each
// package in its own directory.
func scriptsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// tests/integration/setup_test.go -> tests/integration -> tests -> <repo-root>
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts")
}

func TestSetupScripts_Syntax(t *testing.T) {
	dir := scriptsDir(t)
	scripts := []string{
		"install.sh",
		"uninstall.sh",
		"install-executor.sh",
		"uninstall-executor.sh",
	}

	for _, name := range scripts {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			cmd := exec.Command("bash", "-n", path)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("bash -n %s failed: %v\n%s", path, err, out)
			}
		})
	}
}

func TestSetupScripts_Shellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed; skipping lint")
	}
	dir := scriptsDir(t)
	scripts := []string{
		"install.sh",
		"uninstall.sh",
		"install-executor.sh",
		"uninstall-executor.sh",
	}
	args := append([]string{"--severity=warning"}, func() []string {
		paths := make([]string, 0, len(scripts))
		for _, n := range scripts {
			paths = append(paths, filepath.Join(dir, n))
		}
		return paths
	}()...)
	cmd := exec.Command("shellcheck", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shellcheck failed:\n%s", out)
	}
}
