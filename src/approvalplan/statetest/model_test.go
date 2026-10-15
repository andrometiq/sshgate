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
	for seed := range uint64(seeds) {
		if err := NewModel(seed).Run(250); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
	}
}
