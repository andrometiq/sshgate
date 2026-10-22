package install_test

import (
	_ "embed"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed deploy.sh
var deployScript string

func TestDeployRefusesAdminBeforePreflight(t *testing.T) {
	for _, name := range []string{"administrator", " "} {
		cmd := exec.Command("bash", "-s")
		// No external command is available if a mutant bypasses the early refusal.
		cmd.Env = []string{"PATH=" + filepath.Join(t.TempDir(), "empty"), "SIGNER_SERVER_BOOTSTRAP_ADMIN=" + name}
		cmd.Stdin = strings.NewReader(deployScript)
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "SIGNER_SERVER_BOOTSTRAP_ADMIN is disabled") || !strings.Contains(string(output), "README.md") {
			t.Fatalf("admin not refused before preflight: %v %s", err, output)
		}
	}
}
