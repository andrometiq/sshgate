//go:build integration

// Setup-script syntax test (task 2.4; updated in v1.1 Task A — the
// install/user-provisioning scripts collapsed into a single install.sh).
//
// Real systemd lifecycle coverage lives in tests/install-smoke.
//
// What this test DOES do: lint every shell script under scripts/ with
// `bash -n` (syntax check) and `shellcheck` (when installed). It's
// cheap, it runs in CI, and it catches the easy-to-miss class of bugs
// (unquoted vars, mismatched quotes, accidental `$1` typos).
package integration_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// This stub checks arguments and ordering, not systemd semantics.
func TestExecutorInstallerFlow(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("installer requires a Linux login user")
	}
	for _, scenario := range []string{"install", "reinstall", "install-conflict", "uninstall-conflict", "missing-directory", "rollback", "uninstall", "missing-unit", "stop-failure", "restart-failure", "removed-flag", "dry-run", "uninstall-dry-run", "destination-symlink", "escaped-path", "uninstall-escaped-path", "single-quote-path", "unbalanced-quote", "partial-parse"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			manager := filepath.Join(root, "manager dir/systemd/user") // systemd quotes UnitPath entries with spaces
			unit := filepath.Join(manager, "sshgate-executor.service")
			binary := filepath.Join(root, "executor")
			write := func(path, contents string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write(binary, "#!/bin/sh\nexit 0\n")
			type call struct {
				args, output string
				status       int
			}
			calls := []call{{"show -p UnitPath --value", `"` + manager + `.control" /run/user/1000/systemd/user.control`, 0}, {"daemon-reload", "", 0}, {"show --property=FragmentPath --value sshgate-executor.service", "", 0}}
			script := "install-executor.sh"
			args := []string{"--binary", binary}
			wantError := false
			switch scenario {
			case "removed-flag", "dry-run", "uninstall-dry-run":
				calls = nil
				if scenario == "removed-flag" {
					args = append(args, "--restart")
					wantError = true
				} else {
					args = append(args, "--dry-run")
					if scenario == "uninstall-dry-run" {
						script = "uninstall-executor.sh"
						args = []string{"--dry-run"}
					}
				}
			case "destination-symlink":
				write(unit, "previous unit\n")
				if err := os.Remove(unit); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(binary, unit); err != nil {
					t.Fatal(err)
				}
				calls = calls[:2]
				wantError = true
			case "escaped-path", "uninstall-escaped-path", "single-quote-path", "unbalanced-quote", "partial-parse":
				// Escapes are refused, and a parse failure never leaves a partial path list in use.
				calls[0].output = map[string]string{
					"escaped-path":           `"` + manager + `\\x.control"`,
					"uninstall-escaped-path": `"` + manager + `\".control"`,
					"single-quote-path":      `"` + manager + `'s.control"`,
					"unbalanced-quote":       `"` + manager + `.control`,
					"partial-parse":          `"` + manager + `.control" "/broken`,
				}[scenario]
				calls = calls[:1]
				wantError = true
				if scenario == "uninstall-escaped-path" {
					script = "uninstall-executor.sh"
					args = nil
				}
			case "missing-directory":
				calls = []call{{"show -p UnitPath --value", "/run/user/1000/systemd/user.control /usr/lib/systemd/user", 0}}
				wantError = true
			case "install-conflict", "uninstall-conflict":
				calls[2].output = filepath.Join(root, "other/sshgate-executor.service")
				wantError = true
				if scenario == "uninstall-conflict" {
					script = "uninstall-executor.sh"
					args = nil
				}
			case "uninstall", "missing-unit", "stop-failure":
				script = "uninstall-executor.sh"
				args = nil
				calls[2].output = manager + "/../user/sshgate-executor.service"
				if scenario != "missing-unit" {
					write(unit, "previous unit\n")
				}
				calls = append(calls, call{"stop sshgate-executor.service", "", 0})
				if scenario != "uninstall" {
					calls[len(calls)-1].status = 1
					state := "inactive"
					if scenario == "stop-failure" {
						state = "active"
						wantError = true
					}
					calls = append(calls, call{"show --property=LoadState --value sshgate-executor.service", "not-found", 0}, call{"show --property=ActiveState --value sshgate-executor.service", state, 0})
				}
				if !wantError {
					calls = append(calls, call{"disable sshgate-executor.service", "", 1}, call{"daemon-reload", "", 0}, call{"reset-failed sshgate-executor.service", "", 1})
				}
			default:
				if scenario == "reinstall" || scenario == "rollback" {
					write(unit, "previous unit\n")
					calls[2].output = unit
				}
				fragment := unit
				if scenario == "rollback" {
					fragment = ""
					wantError = true
				}
				calls = append(calls, call{"daemon-reload", "", 0}, call{"show --property=FragmentPath --value sshgate-executor.service", fragment, 0})
				if scenario == "rollback" {
					calls = append(calls, call{"daemon-reload", "", 0})
				} else {
					status := 0
					if scenario == "restart-failure" {
						status = 1
						wantError = true
					}
					calls = append(calls, call{"enable sshgate-executor.service", "", 0}, call{"restart sshgate-executor.service", "", status})
				}
			}
			quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
			stub := "#!/bin/bash\nset -eu\nprintf '%s\\n' \"$*\" >> \"$CALL_COUNT.args\"\nn=$(cat \"$CALL_COUNT\")\necho $((n+1)) > \"$CALL_COUNT\"\ncase $n in\n"
			for i, c := range calls {
				stub += fmt.Sprintf("%d) [[ \"$*\" == %s ]] || exit 99; printf '%%s\\n' %s; exit %d ;;\n", i, quote("--user "+c.args), quote(c.output), c.status)
			}
			stub += "*) exit 99 ;;\nesac\n"
			write(filepath.Join(root, "systemctl"), stub)
			counter := filepath.Join(root, "count")
			write(counter, "0\n")
			cmd := exec.Command("bash", append([]string{filepath.Join(scriptsDir(t), script)}, args...)...)
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "CALL_COUNT="+counter, "XDG_CONFIG_HOME="+filepath.Join(root, "data root"))
			out, err := cmd.CombinedOutput()
			if (err != nil) != wantError {
				t.Fatalf("error=%v, wantError=%v\n%s", err, wantError, out)
			}
			count, err := os.ReadFile(counter)
			if err != nil || string(count) != fmt.Sprintf("%d\n", len(calls)) {
				t.Fatalf("calls=%s, want %d: %v\n%s", count, len(calls), err, out)
			}
			var expected strings.Builder
			for _, c := range calls {
				fmt.Fprintln(&expected, "--user "+c.args)
			}
			actual, readErr := os.ReadFile(counter + ".args")
			if (readErr != nil && !os.IsNotExist(readErr)) || string(actual) != expected.String() {
				t.Fatalf("arguments=%q, expected=%q: %v", actual, expected.String(), readErr)
			}
			if strings.HasSuffix(scenario, "-path") || scenario == "unbalanced-quote" || scenario == "partial-parse" {
				if !strings.Contains(string(out), "unit path") {
					t.Fatalf("missing unit path error:\n%s", out)
				}
				if _, err := os.Stat(unit); !os.IsNotExist(err) {
					t.Fatalf("unit written despite parse refusal: %v", err)
				}
			}
			if scenario == "rollback" || scenario == "stop-failure" {
				content, err := os.ReadFile(unit)
				if err != nil || string(content) != "previous unit\n" {
					t.Fatalf("previous unit lost: %s %v", content, err)
				}
			}
			if scenario == "uninstall" || scenario == "missing-unit" {
				if _, err := os.Stat(unit); !os.IsNotExist(err) {
					t.Fatalf("unit remains: %v", err)
				}
			}
		})
	}
}
