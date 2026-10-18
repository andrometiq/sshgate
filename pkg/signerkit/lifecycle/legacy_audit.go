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
// LegacyService.mu; only the worker writes to the sink.
type legacyAuditWorker struct {
	calls     chan legacyAuditCall
	dropped   uint64
	lastAudit time.Duration
}

func (e *LegacyService) startLegacyAuditLocked() {
	if e.audit != nil {
		return
	}
	e.audit = &legacyAuditWorker{calls: make(chan legacyAuditCall)}
	e.joined.Add(1)
	go e.runLegacyAudit(e.audit)
}

func (e *LegacyService) runLegacyAudit(worker *legacyAuditWorker) {
	defer e.joined.Done()
	ticker := newReconcileTicker()
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case call := <-worker.calls:
			e.attemptLegacyAudit(worker, call.metadata)
			close(call.done)
		case <-ticker.C:
			e.attemptLegacyAudit(worker, nil)
		}
	}
}

func (e *LegacyService) writeLegacyAudit(metadata ap.AuditMetadata) {
	e.callLegacyAudit(&metadata)
}

func (e *LegacyService) flushLegacyAudit() { e.callLegacyAudit(nil) }

func (e *LegacyService) callLegacyAudit(metadata *ap.AuditMetadata) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.startLegacyAuditLocked()
	worker := e.audit
	e.mu.Unlock()
	call := legacyAuditCall{metadata: metadata, done: make(chan struct{})}
	select {
	case <-e.ctx.Done():
		return
	case worker.calls <- call:
	}
	select {
	case <-e.ctx.Done():
	case <-call.done:
	}
}

// Fail-open lines are never retried or put in the durable outbox.
func (e *LegacyService) attemptLegacyAudit(worker *legacyAuditWorker, metadata *ap.AuditMetadata) {
	e.mu.Lock()
	if e.closed || e.config.AuditWriter == nil {
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
	if err := writer.WriteApproval(e.ctx, *metadata); err != nil {
		slog.Warn("lifecycle: legacy audit write failed")
	}
}
