package elapsedtest

import (
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
)

var _ elapsed.Clock = (*Fake)(nil)

func TestFakeHalvesMoveIndependently(t *testing.T) {
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	f := NewFake(start)

	f.StepWall(-time.Hour)
	if got := f.Elapsed(); got != 0 {
		t.Fatalf("StepWall moved elapsed to %v", got)
	}
	if got := f.Wall(); !got.Equal(start.Add(-time.Hour)) {
		t.Fatalf("StepWall(-1h): wall = %v", got)
	}

	f.Suspend(8 * time.Hour)
	if got := f.Elapsed(); got != 8*time.Hour {
		t.Fatalf("Suspend(8h): elapsed = %v", got)
	}
	if got := f.Wall(); !got.Equal(start.Add(7 * time.Hour)) {
		t.Fatalf("Suspend(8h): wall = %v", got)
	}

	f.Advance(time.Second)
	if got := f.Elapsed(); got != 8*time.Hour+time.Second {
		t.Fatalf("Advance: elapsed = %v", got)
	}
}
