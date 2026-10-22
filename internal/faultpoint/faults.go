//go:build sshgate_faults

// Package faultpoint provides process fault injection for tagged test builds.
// SSHGATE_TEST_FAULT selects one exact cutpoint. Exit cuts terminate with 86;
// error cuts return the supplied error. Release builds ignore the environment.
package faultpoint

import "os"

// Exit terminates the process without running deferred cleanup at the selected cut.
func Exit(point string) {
	if selected := os.Getenv("SSHGATE_TEST_FAULT"); selected != "" && selected == point {
		os.Exit(86)
	}
}

// Error returns err only at the selected cut.
func Error(point string, err error) error {
	if selected := os.Getenv("SSHGATE_TEST_FAULT"); selected != "" && selected == point {
		return err
	}
	return nil
}
