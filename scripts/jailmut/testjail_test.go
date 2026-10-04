package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestJailStatusCapture(t *testing.T) {
	shell := os.Getenv("TESTJAIL_SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"test-jail", "test-jail-root", "test-jail-mutate"} {
		for _, mode := range []string{"ok", "go-failure", "first-failure", "tee-failure", "truncated", "mktemp-failure", "ci-control"} {
			if target == "test-jail-mutate" && (mode == "truncated" || mode == "ci-control" || mode == "first-failure") {
				continue
			}
			t.Run(target+"/"+mode, func(t *testing.T) {
				directory := t.TempDir()
				commands := map[string]string{
					"go": `#!/bin/sh
case "$1" in
run) echo 'test-jail-mutate: fixture harness'; [ "$FIXTURE_MODE" != go-failure ]; exit $?;;
esac
if [ "$FIXTURE_MODE" = truncated ]; then echo '=== RUN   TestJailMatrix'; exit 0; fi
for name in TestJailMatrix TestJailMatrixP12 TestJailMatrixP14 TestJailMatrixP15 TestJailMatrixP15c TestROFallbackParent TestDetectUsernsCountUsedUpDenies TestExecWithRedactionConfinedNamespace TestExecWithRedactionConfineLifecycle TestExecWithRedactionConfinedEROFS TestExecWithRedactionConfineFailClosed TestExecWithRedactionConfineClosesInheritedFDs TestRunReadJailedRealEffect TestGateBinaryJailedRead TestRunReadJailSetupFailureDenies; do
 echo "--- PASS: $name (0.00s)"
done
if [ "$FIXTURE_MODE" = ci-control ]; then echo 'CONTROL-SKIPPED(ci-only): fixture'; fi
if [ "$FIXTURE_MODE" = go-failure ]; then exit 1; fi
if [ "$FIXTURE_MODE" = first-failure ] && [ ! -f "$FIXTURE_COUNTER" ]; then : > "$FIXTURE_COUNTER"; exit 1; fi
`,
					"id": "#!/bin/sh\necho 0\n",
				}
				if mode == "tee-failure" {
					commands["tee"] = "#!/bin/sh\n/usr/bin/tee \"$@\"\nexit 23\n"
				}
				if mode == "mktemp-failure" {
					commands["mktemp"] = "#!/bin/sh\nexit 9\n"
				}
				for name, body := range commands {
					if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0755); err != nil {
						t.Fatal(err)
					}
				}
				command := exec.Command("make", "--no-print-directory", target, "SHELL="+shell)
				command.Dir = root
				command.Env = append(os.Environ(), "PATH="+directory+":"+os.Getenv("PATH"), "FIXTURE_MODE="+mode, "FIXTURE_COUNTER="+filepath.Join(directory, "counter"), "SSHGATE_JAIL_CI=1")
				output, err := command.CombinedOutput()
				if mode == "ok" {
					if err != nil {
						t.Fatalf("%v\n%s", err, output)
					}
				} else if err == nil {
					t.Fatalf("accepted %s\n%s", mode, output)
				}
				if strings.Contains(string(output), "Syntax error") {
					t.Fatalf("shell incompatibility: %s", output)
				}
			})
		}
	}
}
