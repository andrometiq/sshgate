// Package elapsed is the two-clock reading every holder of time-bounded
// authority uses (SA-1 rule 3.4): the wall clock, and an elapsed clock that
// never steps. On Linux the elapsed clock is CLOCK_BOOTTIME, which also counts
// suspend; Go's own monotonic reading there is CLOCK_MONOTONIC, which stops
// during suspend, so it is not used. Elsewhere it is Go's monotonic reading.
//
// Holders read time only through Clock, so tests can move the two halves
// independently (elapsedtest.Fake).
package elapsed

import "time"

// Clock is the one injectable time source of a holder.
type Clock interface {
	// Wall is the wall clock in UTC with no monotonic reading, so every
	// comparison with it is a wall-clock comparison.
	Wall() time.Time
	// Elapsed is a reading of the elapsed clock. Only differences between
	// two readings in one process mean anything.
	Elapsed() time.Duration
}

// Real returns the process's real clock.
func Real() Clock { return realClock{} }

type realClock struct{}

func (realClock) Wall() time.Time { return time.Now().UTC().Round(0) }

func (realClock) Elapsed() time.Duration { return elapsedNow() }
