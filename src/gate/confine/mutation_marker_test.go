package confine

import "testing"

// mutationEffect and mutationAbort deliberately continue to later assertions.
func mutationEffect(t *testing.T, leg, assertion string, observed bool) {
	t.Helper()
	if observed {
		t.Errorf("MUTATION-EFFECT %s %s", leg, assertion)
	}
}
func mutationAbort(t *testing.T, leg, stage string, observed bool) {
	t.Helper()
	if observed {
		t.Errorf("MUTATION-ABORT %s %s", leg, stage)
	}
}
func mutationSetup(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("SETUP: %v", err)
	}
}
