// Package elapsedtest is test support for elapsed: a fake two-clock source and
// the static check that a holder never reads time directly. Only _test.go
// files import it.
package elapsedtest

import (
	"sync"
	"time"
)

// Fake is a Clock whose wall and elapsed halves tests move independently. It
// models Linux, where the elapsed clock is CLOCK_BOOTTIME.
type Fake struct {
	mu      sync.Mutex
	wall    time.Time
	elapsed time.Duration
}

// NewFake starts a fake at wall (normalized to UTC) with elapsed zero.
func NewFake(wall time.Time) *Fake {
	return &Fake{wall: wall.UTC().Round(0)}
}

// Wall returns the fake wall clock.
func (f *Fake) Wall() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wall
}

// Elapsed returns the fake elapsed reading.
func (f *Fake) Elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elapsed
}

// StepWall moves only the wall clock, by d of either sign: an NTP step or an
// operator's date change.
func (f *Fake) StepWall(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
}

// Advance lets d of real time pass: both clocks move.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
	f.elapsed += d
}

// Suspend models a machine asleep for d. The wall clock and CLOCK_BOOTTIME
// both count it; Go's monotonic reading, and so Go's timers, would not.
func (f *Fake) Suspend(d time.Duration) {
	f.Advance(d)
}
