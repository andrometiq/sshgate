package statetest

import (
	"os"
	"strconv"
	"testing"
)

// TestModel drives random schedules through the pure core with crash
// injection and checks SA-11's properties after every commit and at
// quiescence. STATETEST_SEEDS widens the sweep.
func TestModel(t *testing.T) {
	seeds := 25
	if n, err := strconv.Atoi(os.Getenv("STATETEST_SEEDS")); err == nil {
		seeds = n
	}
	if seeds < 1 {
		t.Fatal("STATETEST_SEEDS must be positive")
	}
	releases, dispatches, cuts, gateChecks := 0, 0, 0, 0
	for seed := range uint64(seeds) {
		m := NewModel(seed)
		if err := m.Run(250); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		releases += len(m.Signer.Released)
		dispatches += len(m.Exec.Gate.Dispatches)
		cuts += m.dispatchCuts
		gateChecks += m.Exec.Gate.Checked
	}
	t.Logf("%d seeds: releases=%d dispatches=%d dispatch cuts=%d gate checks=%d; %d runs without wall steps", seeds, releases, dispatches, cuts, gateChecks, (seeds+1)/2)
}
