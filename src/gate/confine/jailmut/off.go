//go:build !jail_mutation

// Package jailmut supplies compiled-out protection mutations for jail tests.
package jailmut

func On(string) bool { return false }

// BuildFlags are the go build flags of a binary with the same hooks: none.
func BuildFlags() []string { return nil }
