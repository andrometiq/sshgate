package lifecycle

import (
	"log/slog"
	"strconv"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

const legacyAuditInterval = time.Minute

type legacyAuditCall struct {
	metadata *ap.AuditMetadata
	done     chan struct{}
}

// The legacy owner keeps this worker across v2 recovery. Its counters use
// Engine.mu; only the worker writes to the sink.
type legacyAuditWorker struct {
	calls     chan legacyAuditCall
	dropped   uint64
	lastAudit time.Duration
}

func (e *Engine) startLegacyAuditLocked() {
	if e.legacy.audit != nil {
		return
	}
	e.legacy.audit = &legacyAuditWorker{calls: make(chan legacyAuditCall)}
	e.legacy.joined.Add(1)
	go e.runLegacyAudit(e.legacy.audit)
}

func (e *Engine) runLegacyAudit(worker *legacyAuditWorker) {
	defer e.legacy.joined.Done()
	ticker := newReconcileTicker()
	defer ticker.Stop()
	for {
		select {
		case <-e.legacy.ctx.Done():
			return
		case call := <-worker.calls:
			e.attemptLegacyAudit(worker, call.metadata)
			close(call.done)
		case <-ticker.C:
			e.attemptLegacyAudit(worker, nil)
		}
	}
}

func (e *Engine) writeLegacyAudit(metadata ap.AuditMetadata) {
	e.callLegacyAudit(&metadata)
}

func (e *Engine) flushLegacyAudit() { e.callLegacyAudit(nil) }

func (e *Engine) callLegacyAudit(metadata *ap.AuditMetadata) {
	e.mu.Lock()
	if e.legacy.closed {
		e.mu.Unlock()
		return
	}
	e.startLegacyAuditLocked()
	worker := e.legacy.audit
	e.mu.Unlock()
	call := legacyAuditCall{metadata: metadata, done: make(chan struct{})}
	select {
	case <-e.legacy.ctx.Done():
		return
	case worker.calls <- call:
	}
	select {
	case <-e.legacy.ctx.Done():
	case <-call.done:
	}
}

// Fail-open lines are never retried or put in the durable outbox.
func (e *Engine) attemptLegacyAudit(worker *legacyAuditWorker, metadata *ap.AuditMetadata) {
	e.mu.Lock()
	if e.legacy.closed || e.config.AuditWriter == nil {
		e.mu.Unlock()
		return
	}
	now := e.config.Clock.Elapsed()
	if metadata == nil {
		if worker.dropped == 0 || now-worker.lastAudit < legacyAuditInterval {
			e.mu.Unlock()
			return
		}
		metadata = &ap.AuditMetadata{Transition: "legacy_audit_dropped{" + strconv.FormatUint(worker.dropped, 10) + "}", Replay: true}
	} else if worker.dropped != 0 {
		metadata.Transition += "{noise_dropped:" + strconv.FormatUint(worker.dropped, 10) + "}"
	}
	worker.dropped = 0
	worker.lastAudit = now
	writer := e.config.AuditWriter
	e.mu.Unlock()
	if err := writer.WriteApproval(e.legacy.ctx, *metadata); err != nil {
		slog.Warn("lifecycle: legacy audit write failed")
	}
}
