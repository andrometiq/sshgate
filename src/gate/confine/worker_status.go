package confine

import "syscall"

// WorkerStatus is the worker's wait status as the shim reaped it, published on
// fd 4 as a W record before descendant cleanup (BUILD-22-P2 §27, redesign E12).
type WorkerStatus struct {
	// Known is true when a W record carried an exit code or signal.
	Known  bool
	Exited bool
	Code   int
	Signal syscall.Signal
	Core   bool
	// Unavailable names why no status exists (no W record, or the shim's
	// W{"unavailable":...}); empty when Known.
	Unavailable string
}

// WorkerStatus returns the worker status parsed by Status. Until the shim
// publishes W records it always reports an unavailable status.
func (j *Jailed) WorkerStatus() WorkerStatus {
	return WorkerStatus{Unavailable: "not published"}
}
