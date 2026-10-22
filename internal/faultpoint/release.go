//go:build !sshgate_faults

package faultpoint

// Exit is compiled away in release builds.
func Exit(string) {}

// Error is compiled away in release builds.
func Error(string, error) error { return nil }
