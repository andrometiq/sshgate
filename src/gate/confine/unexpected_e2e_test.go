//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func unexpected(t *testing.T, format string, args ...any) {
	t.Helper()
	harness.Unexpected(t, format, args...)
}

// The child diagnostics were forwarded; only a completed test failure is expected.
func propagateFixtureFailure(t *testing.T, output []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Errorf("SETUP: fixture process: %v", err)
		return
	}
	terminals := 0
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "--- FAIL: ") || !strings.HasSuffix(line, "s)") {
			continue
		}
		name, _, ok := strings.Cut(strings.TrimPrefix(line, "--- FAIL: "), " (")
		if !ok || name != t.Name() && !strings.HasPrefix(t.Name(), name+"/") && !strings.HasPrefix(name, t.Name()+"/") {
			unexpected(t, "unrelated fixture failure: %s", line)
			return
		}
		if name == t.Name() {
			terminals++
		}
	}
	if exit.ExitCode() != 1 || terminals != 1 || !bytes.HasSuffix(output, []byte("\nFAIL\n")) {
		unexpected(t, "incomplete fixture process: %v", err)
		return
	}
	t.Fail()
}
