package elapsed

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRealElapsedIsNonDecreasing(t *testing.T) {
	c := Real()
	prev := c.Elapsed()
	for i := 0; i < 100000; i++ {
		now := c.Elapsed()
		if now < prev {
			t.Fatalf("read %d: elapsed went back from %v to %v", i, prev, now)
		}
		prev = now
	}
}

func TestRealElapsedIsBoottime(t *testing.T) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	direct := time.Duration(ts.Nano())
	got := Real().Elapsed()
	if d := got - direct; d < 0 || d > time.Millisecond {
		t.Fatalf("Elapsed() = %v, CLOCK_BOOTTIME read just before = %v (diff %v)", got, direct, d)
	}
}

func TestRealWallIsUTCWithoutMonotonic(t *testing.T) {
	w := Real().Wall()
	if w.Location() != time.UTC {
		t.Fatalf("Wall() location = %v, want UTC", w.Location())
	}
	if w != w.Round(0) {
		t.Fatal("Wall() carries a monotonic reading")
	}
	if d := time.Since(w); d < 0 || d > time.Second {
		t.Fatalf("Wall() is %v away from time.Now()", d)
	}
}
