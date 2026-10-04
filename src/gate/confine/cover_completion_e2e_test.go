//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverProbeCompletionFixture(t *testing.T) {
	const good = "COVER-BEGIN fuse-ioctl\nopen=ok\nioctl=ok\nCOVER-END 0\n"
	for _, tc := range []struct {
		name   string
		result jailResult
		count  int
		bad    bool
	}{
		{"effect", jailResult{stdout: good}, 1, false},
		{"denied", jailResult{stdout: "COVER-BEGIN fuse-ioctl\nopen=2\nCOVER-END 1\n"}, 1, false},
		{"crashed-after-effect", jailResult{stdout: strings.Replace(good, "END 0", "END 139", 1)}, 1, true},
		{"killed-before-later-success", jailResult{stdout: strings.Replace(good, "END 0", "END 137", 1) + good}, 2, true},
		{"missing-ioctl", jailResult{stdout: strings.Replace(good, "ioctl=ok\n", "", 1)}, 1, true},
		{"unterminated-report", jailResult{stdout: strings.Replace(good, "ioctl=ok\n", "ioctl=ok", 1)}, 1, true},
		{"missing-completion", jailResult{stdout: "COVER-BEGIN fuse-ioctl\nopen=ok\nioctl=ok\n"}, 1, true},
		{"missing-probe", jailResult{stdout: good}, 2, true},
		{"wrong-status", jailResult{stdout: strings.Replace(good, "END 0", "END 1", 1)}, 1, true},
		{"stderr", jailResult{stdout: good, stderr: "diagnostic\n"}, 1, true},
		{"setup", jailResult{stdout: good, setupErr: errors.New("setup")}, 1, true},
		{"shell-killed", jailResult{stdout: good, exit: -1}, 1, true},
		{"empty-listing", jailResult{}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCoverReports(tc.result, tc.count)
			if (err != nil) != tc.bad {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestCoverProbeFramingFixture(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("#!/bin/sh\nprintf 'open=ok\\nioctl=ok\\n'\nexit \"$2\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHGATE_COVER_PROBE", probe)
	for _, status := range []string{"0", "139"} {
		command := exec.Command("/bin/sh", "-c", coverProbeCommand("fuse-ioctl", status)+"; "+coverProbeCommand("fuse-ioctl", "0"))
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		result := jailResult{stdout: stdout.String(), stderr: stderr.String(), exit: exitCodeOf(err)}
		output, err := validateCoverReports(result, 2)
		if (err != nil) != (status != "0") {
			t.Fatalf("status %s: validation %v, result %+v", status, err, result)
		}
		if err == nil && output != "open=ok\nioctl=ok\nopen=ok\nioctl=ok\n" {
			t.Fatalf("stripped output: %q", output)
		}
	}
}
