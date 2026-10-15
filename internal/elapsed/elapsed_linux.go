package elapsed

import (
	"time"

	"golang.org/x/sys/unix"
)

// elapsedNow reads CLOCK_BOOTTIME. The call cannot fail for a valid clock ID
// on any kernel Go supports, so a failure is a broken process.
func elapsedNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		panic("elapsed: clock_gettime(CLOCK_BOOTTIME): " + err.Error())
	}
	return time.Duration(ts.Nano())
}
