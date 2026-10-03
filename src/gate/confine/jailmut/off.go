//go:build !jail_mutation

// Package jailmut supplies compiled-out protection mutations for jail tests.
package jailmut

func On(string) bool { return false }
