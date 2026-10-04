package confine

import "testing"

// Migrated legs record evidence; pending legs retain their old failing markers.
func mutationEffect(t *testing.T, leg, assertion string, observed bool) {
	t.Helper()
	if observed {
		if active, ok := activeProofs.Load(t); ok {
			active.(*proof).record("EFFECT", leg, assertion)
		} else {
			t.Errorf("MUTATION-EFFECT %s %s", leg, assertion)
		}
	}
}
func mutationAbort(t *testing.T, leg, stage string, observed bool) {
	t.Helper()
	if observed {
		if active, ok := activeProofs.Load(t); ok {
			active.(*proof).record("ABORT", leg, stage)
		} else {
			t.Errorf("MUTATION-ABORT %s %s", leg, stage)
		}
	}
}
func mutationSetup(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("SETUP: %v", err)
	}
}
