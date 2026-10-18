package hosted

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// ApprovalV2Store separates plain committed reads from BEGIN IMMEDIATE mutations.
// Implementations must use the supplied transaction for every transactional call.
type ApprovalV2Store interface {
	BeginV2(context.Context) (*sql.Tx, error)
	GetV2(context.Context, *sql.Tx, sqlitestore.V2Key) (*sqlitestore.V2Row, error)
	PutV2(context.Context, *sql.Tx, sqlitestore.V2Key, ap.R1, sqlitestore.V2Projection) error
	DeleteV2(context.Context, *sql.Tx, sqlitestore.V2Key) error
	CountV2(context.Context, *sql.Tx) (sqlitestore.V2Counts, error)
	ReadV2(context.Context, sqlitestore.V2Key) (*sqlitestore.V2Row, error)
	ListV2(context.Context, string, string, *sqlitestore.V2Cursor, int) ([]*sqlitestore.V2Row, error)
}

// ApprovalV2Config contains only signer-owned inputs. Freezer and SnapshotBuilder
// run inside Submit's transaction and must not query the database outside it.
type ApprovalV2Config struct {
	Store             ApprovalV2Store
	Clock             elapsed.Clock
	Freezer           lifecycle.Freezer
	SnapshotBuilder   lifecycle.SnapshotBuilder
	Settings          ap.Settings
	RequiredApprovals int
	AssistTimeout     time.Duration
	MaxFullRows       int64
	MaxRows           int64
}

// ApprovalV2Engine has no record cache or local-engine recovery latch. After an
// uncertain commit, the next request re-reads SQLite's committed state.
type ApprovalV2Engine struct {
	config     ApprovalV2Config
	epoch      string
	commit     func(*sql.Tx) error
	mu         sync.Mutex // waiter registration only; never held during database I/O
	waiters    map[sqlitestore.V2Key]map[chan struct{}]struct{}
	flushNudge chan struct{}
}

func NewApprovalV2Engine(c ApprovalV2Config) (*ApprovalV2Engine, error) {
	if c.Store == nil || c.Clock == nil || c.Freezer == nil || c.SnapshotBuilder == nil {
		return nil, errors.New("hosted: approval store, clock, freezer and snapshot builder are required")
	}
	if c.RequiredApprovals > ap.MaxRequiredApprovals {
		return nil, ErrInvalidRequiredApprovals
	}
	c.RequiredApprovals = max(c.RequiredApprovals, 1)
	if c.AssistTimeout < 0 || c.MaxFullRows < 0 || c.MaxRows < 0 || c.Settings.Retention < 0 || c.Settings.MaxAge < 0 || c.Settings.ReportHorizon < 0 {
		return nil, errors.New("hosted: negative approval limit")
	}
	if c.AssistTimeout == 0 || c.AssistTimeout > 5*time.Second {
		c.AssistTimeout = 5 * time.Second
	}
	if c.MaxFullRows == 0 {
		c.MaxFullRows = ap.HostedFullRows
	}
	if c.MaxRows == 0 {
		c.MaxRows = ap.HostedRows
	}
	if c.Settings.ReportHorizon == 0 {
		c.Settings.ReportHorizon = ap.ReportHorizonDefault
	}
	if c.Settings.ReportHorizon < ap.ReportHorizonMin || c.Settings.ReportHorizon > ap.ReportHorizonMax {
		return nil, errors.New("hosted: approval report horizon must be between 1 hour and 7 days")
	}
	if c.Settings.Retention == 0 {
		c.Settings.Retention = 7 * 24 * time.Hour
	}
	c.Settings.Hosted = true
	epoch, err := ap.NewEpoch(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ApprovalV2Engine{config: c, epoch: epoch, commit: func(tx *sql.Tx) error { return tx.Commit() }, waiters: make(map[sqlitestore.V2Key]map[chan struct{}]struct{}), flushNudge: make(chan struct{}, 1)}, nil
}

// IsApprovalBusy recognizes SQLite primary and extended BUSY codes through
// wrappers. Use only at BEGIN or a plain read; write/COMMIT errors are uncertain.
func IsApprovalBusy(err error) bool {
	var coded interface{ Code() int }
	return errors.As(err, &coded) && coded.Code()&0xff == 5
}

func approvalReadError(err error) error {
	if err == nil {
		return nil
	}
	if IsApprovalBusy(err) {
		return &ap.CodeError{Code: ap.CodeBusy}
	}
	if errors.Is(err, store.ErrNotFound) {
		return &ap.CodeError{Code: ap.CodeNotFound}
	}
	var coded *ap.CodeError
	if errors.As(err, &coded) {
		return err
	}
	return &ap.CodeError{Code: ap.CodeStorageUncertain}
}

func approvalAnswerError(answer ap.Answer) error {
	if answer.Code == "" {
		return nil
	}
	return &ap.CodeError{Code: answer.Code, Msg: answer.Reason}
}

func (e *ApprovalV2Engine) now() ap.Now {
	return ap.Now{Wall: e.config.Clock.Wall().UTC().Round(0), Elapsed: e.config.Clock.Elapsed()}
}

func (e *ApprovalV2Engine) view(rec ap.R1, now ap.Now) ap.Summary {
	return ap.View(rec, now, e.epoch, e.config.Settings, false)
}

// transact is the sole mutation path. Preparation resolves inputs using tx;
// Apply owns Clock ordering, including Delete's exception. Effects follow COMMIT.
func (e *ApprovalV2Engine) transact(ctx context.Context, key sqlitestore.V2Key, prepare func(*sql.Tx, *ap.R1, ap.Now) (ap.Command, ap.Inputs, error)) (ap.R1, ap.Answer, error) {
	tx, err := e.config.Store.BeginV2(ctx)
	if err != nil {
		return ap.R1{}, ap.Answer{}, approvalReadError(err)
	}
	defer tx.Rollback()
	row, readErr := e.config.Store.GetV2(ctx, tx, key)
	if readErr != nil && !errors.Is(readErr, store.ErrNotFound) {
		return ap.R1{}, ap.Answer{}, approvalTransactionError(readErr)
	}
	var before *ap.R1
	if row != nil {
		before = &row.Record
	}
	now := e.now()
	command, inputs, err := prepare(tx, before, now)
	if err != nil {
		return ap.R1{}, ap.Answer{}, err
	}
	inputs.Epoch, inputs.Settings = e.epoch, e.config.Settings
	after, answer := ap.Apply(before, command, now, inputs)
	if answer.Code == ap.CodeRecordCorrupt {
		return ap.R1{}, ap.Answer{}, approvalAnswerError(answer)
	}
	if answer.MintRequired {
		return ap.R1{}, ap.Answer{}, errors.New("hosted: missing mint input")
	}
	if !answer.Changed && !answer.Removed {
		return after, answer, approvalAnswerError(answer)
	}
	if answer.Removed {
		err = e.config.Store.DeleteV2(ctx, tx, key)
	} else {
		err = e.config.Store.PutV2(ctx, tx, key, after, sqlitestore.V2Projection{Now: now, Epoch: e.epoch, Settings: e.config.Settings})
	}
	if err != nil {
		return ap.R1{}, ap.Answer{}, approvalTransactionError(err)
	}
	if err := e.commit(tx); err != nil {
		return ap.R1{}, ap.Answer{}, &ap.CodeError{Code: ap.CodeStorageUncertain}
	}
	e.mu.Lock()
	for ready := range e.waiters[key] {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	e.mu.Unlock()
	if !answer.Removed && ap.Unflushed(after) {
		select {
		case e.flushNudge <- struct{}{}:
		default:
		}
	}
	return after, answer, approvalAnswerError(answer)
}

func approvalTransactionError(err error) error {
	var coded *ap.CodeError
	if errors.As(err, &coded) {
		switch coded.Code {
		case ap.CodeRecordCorrupt, ap.CodeInvalidRequest, ap.CodeRequestTooLarge:
			return err
		}
	}
	return &ap.CodeError{Code: ap.CodeStorageUncertain}
}

// mutate is shared by later Vote, Claim, Report, worker and flusher adapters.
func (e *ApprovalV2Engine) mutate(ctx context.Context, key sqlitestore.V2Key, command ap.Command, inputs ap.Inputs) (ap.R1, ap.Answer, error) {
	return e.transact(ctx, key, func(_ *sql.Tx, _ *ap.R1, _ ap.Now) (ap.Command, ap.Inputs, error) { return command, inputs, nil })
}

func (e *ApprovalV2Engine) Submit(ctx context.Context, client, sub string, draft ap.ApprovalDraft) (ap.Summary, error) {
	// Validate reserved verbs and the mandatory claim hash even for a replay.
	if err := draft.Validate(); err != nil {
		return ap.Summary{}, err
	}
	key := sqlitestore.V2Key{ClientID: client, SubPrincipal: sub, RequestID: draft.RequestID}
	after, _, err := e.transact(ctx, key, func(tx *sql.Tx, before *ap.R1, now ap.Now) (ap.Command, ap.Inputs, error) {
		command := ap.Submit{Draft: draft, Allowance: ap.HostedSkew}
		if before != nil {
			return command, ap.Inputs{}, nil
		}
		if err := ap.CheckSubmitWindow(now.Wall, draft.SubmitNotAfter, ap.HostedSkew); err != nil {
			return nil, ap.Inputs{}, err
		}
		if err := e.admit(ctx, tx, client); err != nil {
			return nil, ap.Inputs{}, err
		}
		plan, err := e.config.Freezer.Freeze(ctx, draft, client, sub, now.Wall)
		if err != nil {
			return nil, ap.Inputs{}, err
		}
		if plan.RequesterPrincipal != client || plan.RequesterSub != sub {
			return nil, ap.Inputs{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		snapshot, reason, err := e.config.SnapshotBuilder.BuildSnapshot(ctx, plan)
		if err != nil {
			return nil, ap.Inputs{}, err
		}
		command.Plan, command.ReviewSnapshot, command.RationaleRedacted = plan, snapshot, reason
		command.RequiredApprovals, command.AssistDeadline = e.config.RequiredApprovals, now.Wall.Add(e.config.AssistTimeout)
		return command, ap.Inputs{}, nil
	})
	if err != nil {
		return ap.Summary{}, err
	}
	return e.view(after, e.now()), nil
}

func (e *ApprovalV2Engine) admit(ctx context.Context, tx *sql.Tx, client string) error {
	// A9 exposes row counts but no transactional mixed-quota reader. This is
	// E52's slot predicate, shared in meaning with v1 Insert (never cached class).
	const live = `(decision_status IS NULL OR (decision_status='approved' AND mint_state IN ('none','bytes') AND final_class IS NULL))`
	var global, principal int64
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM requests WHERE status='pending') + (SELECT count(*) FROM approvals_v2 WHERE `+live+`),
 (SELECT count(*) FROM requests WHERE status='pending' AND client_id=?) + (SELECT count(*) FROM approvals_v2 WHERE client_id=? AND `+live+`)`, client, client).Scan(&global, &principal)
	if err != nil {
		return approvalTransactionError(err)
	}
	if global >= 1000 || principal >= 100 {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	counts, err := e.config.Store.CountV2(ctx, tx)
	if err != nil {
		return approvalTransactionError(err)
	}
	if counts.Full >= e.config.MaxFullRows || counts.All >= e.config.MaxRows {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	return nil
}

// Get and List observe committed slots; neither runs Clock or takes a writer lock.
func (e *ApprovalV2Engine) Get(ctx context.Context, key sqlitestore.V2Key) (ap.Summary, error) {
	row, err := e.config.Store.ReadV2(ctx, key)
	if err != nil {
		return ap.Summary{}, approvalReadError(err)
	}
	return e.view(row.Record, e.now()), nil
}

func (e *ApprovalV2Engine) List(ctx context.Context, client, sub string, cursor *sqlitestore.V2Cursor, limit int) ([]ap.Summary, error) {
	rows, err := e.config.Store.ListV2(ctx, client, sub, cursor, limit)
	if err != nil {
		return nil, approvalReadError(err)
	}
	result := make([]ap.Summary, 0, len(rows))
	now := e.now()
	for _, row := range rows {
		result = append(result, e.view(row.Record, now))
	}
	return result, nil
}

// WaitMany registers before reading, closing the read/subscribe race without
// holding a transaction or blocking writers while it waits.
func (e *ApprovalV2Engine) WaitMany(ctx context.Context, client, sub string, ids []string, wait time.Duration) (lifecycle.WaitResult, error) {
	if len(ids) == 0 || len(ids) > ap.AwaitMaxIDs || wait < 0 || wait > ap.AwaitMaxWait {
		return lifecycle.WaitResult{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	keys := make([]sqlitestore.V2Key, len(ids))
	seen := make(map[string]bool, len(ids))
	for i, id := range ids {
		if !ap.ValidRequestID(id) || seen[id] {
			return lifecycle.WaitResult{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		seen[id] = true
		keys[i] = sqlitestore.V2Key{ClientID: client, SubPrincipal: sub, RequestID: id}
	}
	ready := make(chan struct{}, 1)
	e.mu.Lock()
	for _, key := range keys {
		if e.waiters[key] == nil {
			e.waiters[key] = make(map[chan struct{}]struct{})
		}
		e.waiters[key][ready] = struct{}{}
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, key := range keys {
			delete(e.waiters[key], ready)
			if len(e.waiters[key]) == 0 {
				delete(e.waiters, key)
			}
		}
	}()
	read := func() (lifecycle.WaitResult, error) {
		result := lifecycle.WaitResult{Summaries: make([]ap.Summary, 0, len(keys))}
		for _, key := range keys {
			summary, err := e.Get(ctx, key)
			if err != nil {
				return lifecycle.WaitResult{}, err
			}
			result.Summaries = append(result.Summaries, summary)
		}
		return result, nil
	}
	result, err := read()
	if err != nil {
		return lifecycle.WaitResult{}, err
	}
	for _, summary := range result.Summaries {
		if summary.ApprovalStatus != ap.ApprovalPending {
			return result, nil
		}
	}
	if wait == 0 {
		result.WaitElapsed = true
		return result, nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	expired := false
	select {
	case <-ctx.Done():
		return lifecycle.WaitResult{}, ctx.Err()
	case <-ready:
	case <-timer.C:
		expired = true
	}
	select {
	case <-ready:
		expired = false
	default:
	}
	result, err = read()
	result.WaitElapsed = expired
	return result, err
}
