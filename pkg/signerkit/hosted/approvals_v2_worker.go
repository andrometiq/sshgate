package hosted

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

type approvalGrantOwner struct{ principal, alias string }

// Marks advance in confirmed commit order, never on Revoke, Shed or Delete.
func (e *ApprovalV2Engine) updateGrant(before *ap.R1, after ap.R1, removed bool, now ap.Now) {
	e.grantsMu.Lock()
	defer e.grantsMu.Unlock()
	h := after.Header
	if removed && before != nil {
		h = before.Header
	}
	key := sqlitestore.V2Key{ClientID: h.Principal, SubPrincipal: h.SubPrincipal, RequestID: h.RequestID}
	for k, held := range e.grants {
		if held.Passed(now) {
			delete(e.grants, k)
		}
	}
	if removed || h.RevokedAt != nil {
		delete(e.grants, key)
		return
	}
	if h.Kind != ap.KindStandingGrant || h.Decision == nil || h.Decision.Status != ap.ApprovalApproved || h.Decision.Epoch != e.epoch || (before != nil && before.Header.Decision != nil) {
		return
	}
	owner := approvalGrantOwner{h.Principal, h.GrantAlias}
	delete(e.grants, e.newest[owner])
	e.newest[owner] = key
	held := ap.AcquireGrant(after, now)
	if !held.Passed(now) {
		e.grants[key] = held
	}
}

func (e *ApprovalV2Engine) expireGrants(now ap.Now) {
	e.grantsMu.Lock()
	defer e.grantsMu.Unlock()
	for key, held := range e.grants {
		if held.Passed(now) {
			delete(e.grants, key)
		}
	}
}

func (e *ApprovalV2Engine) grantLive(rec ap.R1) bool {
	e.grantsMu.Lock()
	defer e.grantsMu.Unlock()
	h := rec.Header
	key := sqlitestore.V2Key{ClientID: h.Principal, SubPrincipal: h.SubPrincipal, RequestID: h.RequestID}
	_, live := e.grants[key]
	return live && h.RevokedAt == nil && e.newest[approvalGrantOwner{h.Principal, h.GrantAlias}] == key
}

// Run owns exactly one flusher and one due-row loop. Cancellation joins both;
// Server's ordinary-worker owner can therefore join Run before closing SQLite.
func (e *ApprovalV2Engine) Run(ctx context.Context) error {
	e.runMu.Lock()
	if e.running {
		e.runMu.Unlock()
		return errors.New("hosted: approval worker already running")
	}
	e.running = true
	e.runMu.Unlock()
	defer func() { e.runMu.Lock(); e.running = false; e.runMu.Unlock() }()
	joined := make(chan struct{})
	go func() { defer close(joined); e.runFlusher(ctx) }()
	defer func() { <-joined }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	startup := true
	var previous ap.Now
	var warned time.Duration
	hasWarned := false
	for {
		now := e.now()
		if !previous.Wall.IsZero() {
			drift := now.Wall.Sub(previous.Wall) - (now.Elapsed - previous.Elapsed)
			if drift > time.Second || drift < -time.Second {
				e.config.Logger.Printf("approval clock wall step: %s", drift)
			}
		}
		previous = now
		if startup {
			if err := e.reconcileStartup(ctx); err != nil {
				e.config.Logger.Printf("approval startup: %v", err)
			} else {
				startup = false
			}
		}
		if err := e.reconcile(ctx); err != nil && ctx.Err() == nil {
			e.config.Logger.Printf("approval worker: %v", err)
		}
		if e.config.Settings.MaxAge == 0 && (!hasWarned || now.Elapsed-warned >= time.Hour) {
			full, err := e.rowCeiling(ctx)
			if err != nil && ctx.Err() == nil {
				e.config.Logger.Printf("approval ceiling check: %v", err)
			}
			if err == nil && full {
				e.config.Logger.Print("approval row ceiling: raise --approval-max-rows or set --approval-max-age")
				warned = now.Elapsed
				hasWarned = true
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (e *ApprovalV2Engine) rowCeiling(ctx context.Context) (bool, error) {
	counts, err := e.approvalCounts(ctx)
	return counts.All >= e.config.MaxRows, err
}

func (e *ApprovalV2Engine) reconcile(ctx context.Context) error {
	e.expireGrants(e.now())
	rows, err := e.config.Store.DueV2(ctx, e.now().Wall, ap.FlushBatch)
	if err != nil {
		return approvalReadError(err)
	}
	var result error
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.reconcileRow(ctx, row.Key, false, false); err != nil {
			result = errors.Join(result, err)
		}
	}
	if err := e.expireLegacy(ctx); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func (e *ApprovalV2Engine) reconcileRow(ctx context.Context, key sqlitestore.V2Key, pressureFull, pressureRows bool) error {
	// Tick also refreshes time-derived columns when no slot changes (report horizon).
	rec, answer, err := e.transact(ctx, key, func(_ *sql.Tx, before *ap.R1, now ap.Now) (ap.Command, ap.Inputs, error) {
		if before != nil {
			work := ap.Next(*before, now, e.epoch, e.config.Settings, e.grantLive(*before))
			if !work.Clock {
				if work.Delete {
					return ap.Delete{}, ap.Inputs{}, nil
				}
				if work.Shed {
					return ap.ShedRecord{}, ap.Inputs{}, nil
				}
			}
		}
		return ap.Tick{}, ap.Inputs{}, nil
	})
	if err != nil || answer.Removed {
		return err
	}
	work := ap.Next(rec, e.now(), e.epoch, e.config.Settings, e.grantLive(rec))
	if work.Delete || pressureRows {
		_, answer, err := e.reclaim(ctx, key, true, pressureRows)
		if err != nil || answer.Removed {
			return err
		}
	}
	if work.Shed || pressureFull {
		_, _, err = e.reclaim(ctx, key, false, pressureFull)
	}
	return err
}

// A concurrent reclaimer may already have made room. Judge pressure under the
// same writer lock as the deletion/shedding, rather than using the earlier count.
func (e *ApprovalV2Engine) reclaim(ctx context.Context, key sqlitestore.V2Key, remove, pressure bool) (ap.R1, ap.Answer, error) {
	return e.transact(ctx, key, func(tx *sql.Tx, _ *ap.R1, _ ap.Now) (ap.Command, ap.Inputs, error) {
		if pressure {
			counts, err := e.config.Store.CountV2(ctx, tx)
			if err != nil {
				return nil, ap.Inputs{}, approvalTransactionError(err)
			}
			pressure = counts.Full >= e.config.MaxFullRows
			if remove {
				pressure = counts.All >= e.config.MaxRows
			}
		}
		if remove {
			return ap.Delete{Pressure: pressure}, ap.Inputs{}, nil
		}
		return ap.ShedRecord{Pressure: pressure}, ap.Inputs{}, nil
	})
}

// X5 applies due Clock facts before the final quota count. Pressure candidates
// are oldest first; every candidate is re-read and judged by Apply in its own tx.
func (e *ApprovalV2Engine) reclaimForSubmit(ctx context.Context) error {
	due, err := e.approvalKeys(ctx, `SELECT client_id,sub_principal,request_id FROM approvals_v2 WHERE next_due_at<=? ORDER BY client_id,sub_principal,request_id`, e.now().Wall.Unix())
	if err != nil {
		return err
	}
	// Complete X5 before selecting history: Clock may create a new decision.
	for _, key := range due {
		if err := e.reconcileRow(ctx, key, false, false); err != nil && !isMissingApproval(err) {
			return err
		}
	}
	counts, err := e.approvalCounts(ctx)
	if err != nil {
		return err
	}
	full, all := counts.Full >= e.config.MaxFullRows, counts.All >= e.config.MaxRows
	if !full && !all {
		return nil
	}
	keys, err := e.approvalKeys(ctx, `SELECT client_id,sub_principal,request_id FROM approvals_v2 WHERE decided_at IS NOT NULL AND ((? AND shed=0) OR ?) ORDER BY decided_at,client_id,sub_principal,request_id`, full, all && e.config.Settings.MaxAge > 0)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if !full && !all {
			break
		}
		if err := e.reconcileRow(ctx, key, full, all); err != nil && !isMissingApproval(err) {
			return err
		}
		counts, err = e.approvalCounts(ctx)
		if err != nil {
			return err
		}
		full, all = counts.Full >= e.config.MaxFullRows, counts.All >= e.config.MaxRows
	}
	return nil
}

func isMissingApproval(err error) bool {
	var coded *ap.CodeError
	return errors.As(err, &coded) && coded.Code == ap.CodeNotFound
}

func (e *ApprovalV2Engine) approvalCounts(ctx context.Context) (sqlitestore.V2Counts, error) {
	tx, err := e.config.Store.BeginV2(ctx)
	if err != nil {
		return sqlitestore.V2Counts{}, approvalReadError(err)
	}
	defer tx.Rollback()
	counts, err := e.config.Store.CountV2(ctx, tx)
	if err != nil {
		return counts, approvalTransactionError(err)
	}
	return counts, nil
}

func (e *ApprovalV2Engine) runFlusher(ctx context.Context) {
	for {
		if e.flushPass(ctx) {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-e.flushNudge:
			timer.Stop()
		}
	}
}

// Only runFlusher calls this in production. Sink I/O never holds a transaction.
// A failed pass waits a full second; nudges cannot shorten that backoff.
func (e *ApprovalV2Engine) flushPass(ctx context.Context) bool {
	if e.config.AuditSink == nil {
		return true
	}
	rows, err := e.config.Store.UnflushedV2(ctx, ap.FlushBatch)
	if err != nil {
		e.config.Logger.Printf("approval flush list: %v", approvalReadError(err))
		return true
	}
	for _, listed := range rows {
		if ctx.Err() != nil {
			return true
		}
		row, err := e.config.Store.ReadV2(ctx, listed.Key)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				e.config.Logger.Printf("approval flush read: %v", approvalReadError(err))
			}
			continue
		}
		h := row.Record.Header
		for _, event := range h.Outbox {
			if ctx.Err() != nil {
				return true
			}
			metadata := hostedApprovalMetadata(listed.Key, h, event)
			if err := e.config.AuditSink.Call(ctx, signerkit.AuditCall{Time: e.now().Wall, Lifecycle: "approval-" + metadata.Transition, Approval: &metadata}); err != nil {
				e.config.Logger.Print("approval audit sink unavailable")
				return true
			}
		}
		if len(h.Outbox) == 0 {
			continue
		}
		if _, _, err := e.mutate(ctx, listed.Key, ap.Flush{Through: h.OutboxSeq}, ap.Inputs{}); err != nil {
			e.config.Logger.Printf("approval Flush: %v", err)
			return true
		}
	}
	if err := e.flushLegacyAudit(ctx); err != nil {
		e.config.Logger.Print("legacy audit delivery failed")
		return true
	}
	return false
}

func hostedApprovalMetadata(key sqlitestore.V2Key, h ap.R1Header, event ap.OutboxEvent) ap.AuditMetadata {
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
	recordKey := ap.HostedRecordKey(key.ClientID, key.SubPrincipal, key.RequestID)
	metadata := ap.AuditMetadata{
		Kind: h.Kind, RequestID: h.RequestID, Principal: h.Principal, PlanHash: h.PlanHash,
		RationaleRedacted: h.RationaleRedacted, RationaleOrigin: h.RationaleOrigin,
		Transition: transition, Decision: event.Decision, Assist: event.Assist,
		DecidedBy: event.DecidedBy, Replay: event.Replay, EventKey: ap.EventKey(recordKey, event.Seq),
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

// Cached deadlines belong to the previous settings and cannot select startup work.
func (e *ApprovalV2Engine) reconcileStartup(ctx context.Context) error {
	var cursor *sqlitestore.V2Key
	var result error
	for {
		rows, err := e.startupRows(ctx, cursor)
		if err != nil {
			return errors.Join(result, err)
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			rec, err := ap.DecodeR1(row.RecordJSON)
			row.RecordJSON = nil
			if err != nil || row.Key != (sqlitestore.V2Key{ClientID: rec.Header.Principal, SubPrincipal: rec.Header.SubPrincipal, RequestID: rec.Header.RequestID}) {
				result = errors.Join(result, &ap.CodeError{Code: ap.CodeRecordCorrupt})
				continue
			}
			now := e.now()
			work := ap.Next(rec, now, e.epoch, e.config.Settings, e.grantLive(rec))
			if !work.Clock && !work.Shed && !work.Delete && !approvalProjectionChanged(row, e.view(rec, now), work.DueAt) {
				continue
			}
			if err := e.reconcileRow(ctx, row.Key, false, false); err != nil && !isMissingApproval(err) {
				result = errors.Join(result, err)
			}
		}
		if len(rows) < ap.FlushBatch {
			return result
		}
		next := rows[len(rows)-1].Key
		cursor = &next
	}
}

// Release the connection before decoding: startup must not monopolize the
// single-connection store while the flusher and ordinary readers make progress.
func (e *ApprovalV2Engine) startupRows(ctx context.Context, cursor *sqlitestore.V2Key) ([]*sqlitestore.V2Row, error) {
	tx, err := e.config.Store.BeginV2(ctx)
	if err != nil {
		return nil, approvalReadError(err)
	}
	defer tx.Rollback()
	query := `SELECT client_id,sub_principal,request_id,record_json,view_status,class,next_due_at FROM approvals_v2`
	var args []any
	if cursor != nil {
		query += ` WHERE (client_id,sub_principal,request_id)>(?,?,?)`
		args = append(args, cursor.ClientID, cursor.SubPrincipal, cursor.RequestID)
	}
	query += ` ORDER BY client_id,sub_principal,request_id LIMIT ?`
	args = append(args, ap.FlushBatch)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, approvalTransactionError(err)
	}
	defer rows.Close()
	var result []*sqlitestore.V2Row
	for rows.Next() {
		row := new(sqlitestore.V2Row)
		var due sql.NullInt64
		if err := rows.Scan(&row.Key.ClientID, &row.Key.SubPrincipal, &row.Key.RequestID, &row.RecordJSON, &row.ViewStatus, &row.Class, &due); err != nil {
			return nil, approvalTransactionError(err)
		}
		if due.Valid {
			at := time.Unix(due.Int64, 0).UTC()
			row.NextDueAt = &at
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, approvalTransactionError(err)
	}
	return result, nil
}

func (e *ApprovalV2Engine) approvalKeys(ctx context.Context, query string, args ...any) ([]sqlitestore.V2Key, error) {
	tx, err := e.config.Store.BeginV2(ctx)
	if err != nil {
		return nil, approvalReadError(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, approvalTransactionError(err)
	}
	defer rows.Close()
	var keys []sqlitestore.V2Key
	for rows.Next() {
		var key sqlitestore.V2Key
		if err := rows.Scan(&key.ClientID, &key.SubPrincipal, &key.RequestID); err != nil {
			return nil, approvalTransactionError(err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, approvalTransactionError(err)
	}
	return keys, nil
}

// StartOrdinaryWorkers transfers ownership of engine and its assist pool to the
// server. Call before serving; Close joins them before the caller closes SQLite.
// Effects use an independent context so HTTP shutdown cannot look like failure.
func (s *Server) StartOrdinaryWorkers(engine *ApprovalV2Engine) error {
	s.ordinaryMu.Lock()
	defer s.ordinaryMu.Unlock()
	if engine == nil {
		return errors.New("hosted: approval engine is required")
	}
	if s.ordinaryClosed {
		return errors.New("hosted: ordinary workers are closed")
	}
	if s.ordinaryEngine != nil {
		return errors.New("hosted: ordinary workers already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.ordinaryEngine, s.ordinaryCancel, s.ordinaryJoined = engine, cancel, make(chan struct{})
	go func() {
		defer close(s.ordinaryJoined)
		if err := engine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.Logger.Printf("approval worker stopped: %v", err)
		}
	}()
	return nil
}

// currentOrdinaryEngine takes a snapshot without holding the server lock during I/O.
func (s *Server) currentOrdinaryEngine() *ApprovalV2Engine {
	s.ordinaryMu.Lock()
	defer s.ordinaryMu.Unlock()
	if s.ordinaryClosed || s.ordinaryEngine == nil {
		return nil
	}
	select {
	case <-s.ordinaryJoined:
		return nil
	default:
		return s.ordinaryEngine
	}
}

func (s *Server) closeOrdinaryWorkers() {
	s.ordinaryClose.Do(func() {
		s.ordinaryMu.Lock()
		s.ordinaryClosed = true
		engine, cancel, joined := s.ordinaryEngine, s.ordinaryCancel, s.ordinaryJoined
		s.ordinaryMu.Unlock()
		if engine == nil {
			return
		}
		// Cancel callbacks as well as providers: a callback may be retrying busy BEGIN.
		engine.assistMu.Lock()
		engine.assistCancel()
		engine.assistMu.Unlock()
		cancel()
		if engine.config.AssistPool != nil {
			engine.config.AssistPool.Close()
		}
		engine.assistJobs.Wait()
		<-joined
	})
}

func (e *ApprovalV2Engine) startAssist(key sqlitestore.V2Key, rec ap.R1) {
	if e.config.AssistPool == nil || rec.Header.Assist != nil || rec.Payload == nil {
		return
	}
	e.assistMu.Lock()
	if e.assistContext.Err() != nil {
		e.assistMu.Unlock()
		return
	}
	e.assistJobs.Add(1)
	e.assistMu.Unlock()
	defer e.assistJobs.Done()
	input, inputErr := e.config.AssistInputBuilder.BuildAssistInput(rec.Payload.Plan)
	assessor := e.config.Assessor
	if inputErr != nil {
		assessor = nil
		input = assist.Input{}
	}
	outcome := e.config.AssistPool.TrySubmit(e.assistContext, assessor, input, rec.Header.AssistDeadline, func(snapshot assist.Snapshot) {
		if inputErr != nil && snapshot.Reason == assist.ReasonFailed {
			snapshot.Reason = assist.ReasonRedaction
		}
		e.finishAssist(key, rec.Header.AssistDeadline, snapshot)
	})
	if outcome == assist.Full {
		e.finishAssist(key, rec.Header.AssistDeadline, assist.Snapshot{Reason: assist.ReasonBusy})
	}
}

// Retry only a definite busy BEGIN, retaining the single provider result.
func (e *ApprovalV2Engine) finishAssist(key sqlitestore.V2Key, deadline time.Time, snapshot assist.Snapshot) {
	for backoff := 250 * time.Millisecond; e.assistContext.Err() == nil && e.now().Wall.Before(deadline); backoff = min(backoff*2, 2*time.Second) {
		_, _, err := e.mutate(e.assistContext, key, ap.AssistDone{Result: snapshot.Result, Unavailable: snapshot.Reason}, ap.Inputs{})
		if err == nil || e.assistContext.Err() != nil {
			return
		}
		var coded *ap.CodeError
		if !errors.As(err, &coded) || coded.Code != ap.CodeBusy {
			e.config.Logger.Printf("approval assist commit: %v", err)
			return
		}
		timer := time.NewTimer(min(backoff, deadline.Sub(e.now().Wall)))
		select {
		case <-e.assistContext.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Drain waits for queued process diagnostics before exit, bounded by ctx.
// It never closes the process writer or interrupts a blocking write.
func (s *ProcessAuditSink) Drain(ctx context.Context) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		busy := s.busy
		s.mu.Unlock()
		if !busy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
