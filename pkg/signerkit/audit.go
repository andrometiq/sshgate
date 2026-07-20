package signerkit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEvent is the on-disk shape of a single audit record. The shape is
// deliberately flat and string-y so a `grep "request_id"` over the log
// file is still useful when the operator has no JSON tooling handy.
//
// Status is one of "approved", "approved-undelivered", "denied",
// "timeout", "error" — the same strings ResultStatus.String()
// emits, plus "error" for protocol-level failures where no approval
// channel was even consulted, plus "approved-undelivered" when an
// approved request was signed but the response write to the MCP
// failed (so the operator-visible decision did not reach the caller).
//
// ApprovedBy is the human-readable identifier of the actor the backend
// associates with the verdict (Telegram populates it with the tapping user's
// name). It is NOT a proxy for "was authorised": the real Telegram backend
// records the DENIER's name on a DENY too, so a non-empty approved_by can
// accompany a denied/timeout outcome. Empty when the backend doesn't track
// identity (stub).
//
// AuthMode records HOW the request was authorised — and ONLY when it was.
// Decoupled from approved_by so the log carries both WHO ("approved_by") and
// HOW ("auth_mode"): "human" = a real-time human approval; "grant:<id>" = a
// standing-grant auto-sign; empty for a denied/timeout/error/read where
// nothing was authorised. It is set via the authMode helper — the SAME helper
// the socket response uses, gated on the approval state — so the audit and the
// wire never drift, and a DENY never reads as "human".
type AuditEvent struct {
	TS         time.Time `json:"ts"`
	RequestID  string    `json:"request_id"`
	Status     string    `json:"status"`
	Commands   []string  `json:"commands"`
	Servers    []string  `json:"servers"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	AuthMode   string    `json:"auth_mode,omitempty"`
	// Policy is nil for every frozen ordinary audit row. Dedicated policy
	// events populate it without changing ordinary JSON bytes.
	Policy *PolicyAuditMetadata `json:"policy,omitempty"`
}

// AuditLog is an append-only JSON-Lines file with fsync per record.
// Concurrent Write calls are serialised by an internal mutex; the file
// itself is opened O_APPEND so atomic-write guarantees from the kernel
// also hold (PIPE_BUF-sized writes are atomic on POSIX, and our records
// fit well under that), but we keep the mutex for clarity and to bound
// any future record-size growth.
//
// The zero value is not usable — call OpenAuditLog or
// NewMemAuditLog. nil is never an acceptable value to Daemon.Audit;
// pass NewMemAuditLog() in tests that want to throw away records.
type AuditLog struct {
	mu       sync.Mutex
	f        *os.File
	skipSync bool // for in-memory pipes where Sync is a no-op / errors
}

// OpenAuditLog opens (or creates) path for append-only JSON-Lines
// writes. The file is opened with mode 0600 (owner-only): it carries the
// command text of every approval request, so it must not be group- or
// world-readable. (A tighter umask can only restrict further.)
func OpenAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &AuditLog{f: f}, nil
}

// NewMemAuditLog returns a writable AuditLog backed by an os.Pipe.
// Records written to it are drained by an internal goroutine and
// discarded; the pipe is closed when Close() is called. Intended for
// unit tests that want to exercise the daemon's audit code path
// without persisting to disk. Production callers should use
// OpenAuditLog.
//
// The returned *AuditLog has skipSync=true so Write does not call
// Sync on the pipe FD (the pipe is non-syncable on Linux and would
// surface EINVAL).
func NewMemAuditLog() (*AuditLog, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("pipe: %w", err)
	}
	// Drain the read end so the writer never blocks on a full pipe
	// buffer (kernel default: 64KB on Linux). The goroutine exits
	// when the write end is closed (i.e. when Close() runs).
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	}()
	return &AuditLog{f: w, skipSync: true}, nil
}

// Write appends one event to the log as a single JSON line. The line is
// flushed to disk with fsync before Write returns, so a kill -9 on the
// daemon (or a power loss) does not lose records that have already
// reported success to their caller.
//
// Write is safe to call concurrently; an internal mutex serialises the
// (encode → write → fsync) sequence so partial encodings cannot
// interleave on disk.
func (a *AuditLog) Write(e AuditEvent) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	b = append(b, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.f.Write(b); err != nil {
		return fmt.Errorf("write audit line: %w", err)
	}
	if !a.skipSync {
		if err := a.f.Sync(); err != nil {
			return fmt.Errorf("fsync audit line: %w", err)
		}
	}
	return nil
}

// Close releases the underlying file handle. After Close, Write will
// return an error from the kernel; the daemon is expected to call Close
// only during shutdown.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	if err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}
