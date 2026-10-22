//go:build !sshgate_faults

package faultpoint

import (
	"errors"
	"testing"
)

func TestReleaseIgnoresFaultEnvironment(t *testing.T) {
	t.Setenv("SSHGATE_TEST_FAULT", "release-test")
	Exit("release-test")
	if err := Error("release-test", errors.New("injected")); err != nil {
		t.Fatalf("release fault enabled: %v", err)
	}
}
