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
		for _, mode := range []string{"ok", "go-failure", "first-failure", "tee-failure", "truncated", "mktemp-failure", "ci-control", "render-failure"} {
			if target == "test-jail-mutate" && (mode == "truncated" || mode == "ci-control" || mode == "first-failure" || mode == "render-failure") {
				continue
			}
			t.Run(target+"/"+mode, func(t *testing.T) {
				directory := t.TempDir()
				commands := map[string]string{
					"go": `#!/bin/sh
case "$1" in
run)
 if [ "$3" = -render-json ]; then
  [ "$FIXTURE_MODE" != render-failure ] || exit 19
  sed -n 's/.*"Output":"\(.*\)".*/\1/p' "$4" | sed 's/\\n$//'
  exit $?
 fi
 echo 'test-jail-mutate: fixture harness'; [ "$FIXTURE_MODE" != go-failure ]; exit $?;;
esac
if [ "$FIXTURE_MODE" = truncated ]; then printf '%s\n' '{"Action":"output","Output":"=== RUN   TestJailMatrix\n"}' ; exit 0; fi
for name in TestPhase1Tables TestFilterTables TestHostPIDFilters TestSyscallRowDecisions TestStrictSpecDecode TestStatusMutation TestCatalogueControls TestCatalogueRouting TestJailMatrix TestJailMatrixP12 TestJailMatrixPhase1 TestJailMatrixP14 TestJailMatrixP15 TestJailMatrixP15c TestJailMatrixCovers TestJailMatrixCredentials TestJailMatrixCatalogue TestJailMatrixWrite TestJailMatrixSyscallSweep TestROFallbackParent TestDetectUsernsCountUsedUpDenies TestExecWithRedactionConfinedNamespace TestExecWithRedactionConfineLifecycle TestExecWithRedactionConfinedEROFS TestExecWithRedactionConfineFailClosed TestExecWithRedactionConfineClosesInheritedFDs TestRunReadJailedRealEffect TestGateBinaryJailedRead TestRunReadJailSetupFailureDenies; do
 printf '{"Action":"output","Output":"--- PASS: %s (0.00s)\\n"}\n' "$name"
done
if [ "$FIXTURE_MODE" = ci-control ]; then printf '%s\n' '{"Action":"output","Output":"CONTROL-SKIPPED(ci-only): fixture\n"}' ; fi
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
