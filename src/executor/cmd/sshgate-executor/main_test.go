package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainFailureExit(t *testing.T) {
	if os.Getenv("EXECUTOR_TEST_MAIN_FAILURE") == "1" {
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainFailureExit$", "-test.timeout=30m")
	cmd.Env = append(os.Environ(), "EXECUTOR_TEST_MAIN_FAILURE=1", "XDG_RUNTIME_DIR=", "XDG_CONFIG_HOME="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("startup failure exited zero")
	}
	if !strings.Contains(string(output), "executor:") {
		t.Fatalf("missing diagnostic: %s", output)
	}
}
