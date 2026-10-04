//go:build linux

package gate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

func TestExecutorCleanupErrorStatus(t *testing.T) {
	// Isolate subreaper ownership from other tests' children.
	if os.Getenv("SSHGATE_TEST_CLEANUP_REPORT") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutorCleanupErrorStatus$")
		command.Env = append(os.Environ(), "SSHGATE_TEST_CLEANUP_REPORT=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("cleanup fixture: %v\n%s", err, output)
		}
		return
	}
	original := confinedCommand
	defer func() { confinedCommand = original }()
	for _, code := range []int{0, 23} {
		confinedCommand = func(spec *confine.Spec, ctx context.Context, command string) (*confine.Jailed, error) {
			jailed, err := original(spec, ctx, command)
			if err != nil {
				return nil, err
			}
			jailed.Cmd.Path = "/bin/sh"
			jailed.Cmd.Args = []string{"sh", "-c", fmt.Sprintf("cat <&3 >/dev/null; printf 'I{\"profile\":\"ro-v1\",\"abi\":1,\"net\":false,\"lane2\":false}\\nX\\nCinjected cleanup error\\n' >&4; printf 'gate-jail: cleanup: injected cleanup error\\n' >&2; exit %d", code)}
			jailed.Cmd.SysProcAttr = nil
			return jailed, nil
		}
		result, err := ExecWithRedaction(context.Background(), "true", ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, CaptureLimit: 4096})
		if err != nil || result.ExitCode != code || result.CleanupError != "injected cleanup error" || result.Stderr != "gate-jail: cleanup: injected cleanup error\n" || strings.Count(result.Stderr, "gate-jail: cleanup:") != 1 {
			t.Fatalf("status %d: %+v, %v", code, result, err)
		}
	}
}
