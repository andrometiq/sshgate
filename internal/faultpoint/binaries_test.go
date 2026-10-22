package faultpoint_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Inspect unstripped release builds: stripping would hide a linked fault hook.
func TestReleaseBinariesExcludeFaultpoints(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("executor is Linux-only")
	}
	for _, target := range []string{"src/signer/cmd/sshgate-signer-telegram", "src/executor/cmd/sshgate-executor"} {
		t.Run(filepath.Base(target), func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "release")
			build := exec.Command("go", "build", "-tags=", "-ldflags=", "-o", binary, "./"+target)
			build.Dir = "../.."
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build: %v: %s", err, out)
			}
			out, err := exec.Command("go", "tool", "nm", binary).CombinedOutput()
			if err != nil {
				t.Fatalf("nm: %v: %s", err, out)
			}
			if strings.Contains(string(out), "/internal/faultpoint.") {
				t.Fatal("release binary contains faultpoint symbols")
			}
		})
	}
}
