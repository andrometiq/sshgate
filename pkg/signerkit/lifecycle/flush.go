package lifecycle

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

type flushWaiter struct {
	ready chan struct{}
	users int
}

func (e *Engine) nudgeFlush() {
	select {
	case e.flushNudge <- struct{}{}:
	default:
	}
}

func (e *Engine) runFlusher(ctx context.Context) error {
	ticker := newReconcileTicker()
	defer ticker.Stop()
	e.nudgeFlush() // Startup may have recovered an outbox without appending to it.
	failed := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			failed = false
		case <-e.flushNudge:
			if failed {
				continue
			}
		}
		var err error
		failed, err = e.flushPass(ctx)
		if err != nil {
			return err
		}
	}
}

// flushPass is called only by the flusher. Sink failures stop this pass;
// storage failures stop the driver. Neither acknowledges unwritten events.
func (e *Engine) flushPass(ctx context.Context) (bool, error) {
	if e.config.AuditWriter == nil {
		return true, nil
	}
	e.mu.Lock()
	keys := make([]string, 0, len(e.projections.unflushed))
	for key := range e.projections.unflushed {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int {
		x, y := e.projections.due[a], e.projections.due[b]
		if x.IsZero() != y.IsZero() {
			if x.IsZero() {
				return 1
			}
			return -1
		}
		if order := x.Compare(y); order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
	if len(keys) > ap.FlushBatch {
		keys = keys[:ap.FlushBatch]
	}
	e.mu.Unlock()
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		e.mu.Lock()
		rec, err := e.load(key)
		e.mu.Unlock()
		if err != nil {
			return false, err
		}
		if rec == nil {
			continue
		} // A fully audited record may have been deleted.
		for _, event := range rec.Header.Outbox {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if err := e.config.AuditWriter.WriteApproval(ctx, auditMetadata(key, rec.Header, event)); err != nil {
				return true, nil
			}
		}
		e.mu.Lock()
		err = e.flushThroughLocked(ctx, key, rec.Header.OutboxSeq)
		e.mu.Unlock()
		if err != nil {
			return false, err
		}
	}
	return false, nil
}

func (e *Engine) flushThroughLocked(ctx context.Context, key string, through uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, err := e.load(key)
	if err != nil || rec == nil {
		return err
	}
	_, answer, err := e.commitLocked(key, rec, ap.Flush{Through: through}, e.now(), ap.Inputs{})
	if err != nil {
		return err
	}
	return answerError(answer)
}

func auditMetadata(key string, h ap.R1Header, event ap.OutboxEvent) ap.AuditMetadata {
	transition := event.Kind
	if event.Detail != "" {
		transition += "{" + event.Detail + "}"
	}
	if event.Operator != "" {
		transition += "{operator:" + event.Operator + "}"
	}
	if event.NoiseDropped != 0 {
		transition += "{noise_dropped:" + strconv.FormatUint(event.NoiseDropped, 10) + "}"
	}
	metadata := ap.AuditMetadata{
		Kind: h.Kind, RequestID: h.RequestID, Principal: h.Principal,
		PlanHash: h.PlanHash, RationaleRedacted: h.RationaleRedacted, RationaleOrigin: h.RationaleOrigin,
		Transition: transition, Decision: event.Decision, Assist: event.Assist,
		DecidedBy: event.DecidedBy, Replay: event.Replay, EventKey: ap.EventKey(key, event.Seq),
	}
	if event.Kind == ap.EventDecision && h.Decision != nil {
		at := h.Decision.DecidedAt
		metadata.DecidedAt = &at
	}
	if event.Kind == ap.EventFinalReport && h.FinalReport != nil {
		metadata.Execution = &ap.AuditExecution{State: ap.ExecutionFinal, Class: h.FinalReport.Class, ClientReported: true}
	}
	return metadata
}

// The timer bounds waiting only; Claim rechecks authority through Apply.
func newClaimFlushTimer() *time.Timer { return time.NewTimer(2 * time.Second) }
