//go:build sshgate_faults

package faultpoint

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestFaultSelection(t *testing.T) {
	injected := errors.New("injected")
	t.Setenv("SSHGATE_TEST_FAULT", "selected")
	if Error("selected", injected) != injected {
		t.Fatal("selected error not returned")
	}
	if Error("other", injected) != nil {
		t.Fatal("unselected error returned")
	}
	Exit("other")
	t.Setenv("SSHGATE_TEST_FAULT", "")
	if Error("selected", injected) != nil || Error("", injected) != nil {
		t.Fatal("unset fault activated")
	}
	Exit("")
}

func TestFaultExit(t *testing.T) {
	if os.Getenv("SSHGATE_FAULT_CHILD") == "1" {
		Exit("exit-test")
		t.Fatal("selected exit returned")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFaultExit$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "SSHGATE_FAULT_CHILD=1", "SSHGATE_TEST_FAULT=exit-test")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatalf("exit: %v: %s", err, out)
	}
}
