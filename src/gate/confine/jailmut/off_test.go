//go:build !jail_mutation

package jailmut

import "testing"

func TestHarnessHooksOff(t *testing.T) {
	if On("P-FIXTURE") || On("") || BuildFlags() != nil {
		t.Fatal("mutation enabled without build tag")
	}
}
