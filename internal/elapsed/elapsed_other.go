//go:build !linux

package elapsed

import "time"

var start = time.Now()

// elapsedNow is Go's monotonic reading, measured from package start.
func elapsedNow() time.Duration { return time.Since(start) }
