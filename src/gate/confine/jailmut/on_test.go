//go:build jail_mutation

package jailmut

import "testing"

func TestHarnessHooksOn(t *testing.T) {
	previous := IDs
	t.Cleanup(func() { IDs = previous })
	IDs = "P-FIRST,P-SECOND"
	for _, id := range []string{"P-FIRST", "P-SECOND"} {
		if !On(id) {
			t.Errorf("missing exact ID %q", id)
		}
	}
	for _, id := range []string{"", "P-FIR", "P-FIRST,P-SECOND", " P-FIRST"} {
		if On(id) {
			t.Errorf("accepted non-ID %q", id)
		}
	}
}
