package hosted

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
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
	DueV2(context.Context, time.Time, int) ([]*sqlitestore.V2Row, error)
	UnflushedV2(context.Context, int) ([]*sqlitestore.V2Row, error)
}

// ApprovalV2Config contains only signer-owned inputs. Freezer and SnapshotBuilder
// run inside Submit's transaction and must not query the database outside it.
type ApprovalV2Config struct {
	Store             ApprovalV2Store
	Minter            lifecycle.Minter
	Clock             elapsed.Clock
	Freezer           lifecycle.Freezer
	SnapshotBuilder   lifecycle.SnapshotBuilder
	Settings          ap.Settings
	RequiredApprovals int
	AssistTimeout     time.Duration
	MaxFullRows       int64
	MaxRows           int64
	// Use ProcessAuditSink for file output; custom sinks must honor cancellation.
	AuditSink signerkit.AuditSink
	Logger    *log.Logger
	// LegacyStore must share Store's database; the hosted expiry outbox is atomic with its transitions.
	LegacyStore interface {
		ListPending(context.Context) ([]*store.Request, error)
		ExpireLegacy(context.Context, string, time.Time) (bool, []*store.Vote, error)
	}
}

// ApprovalV2Engine has no record cache or local-engine recovery latch. After an
// uncertain commit, the next request re-reads SQLite's committed state.
type ApprovalV2Engine struct {
	config            ApprovalV2Config
	epoch             string
	commit            func(*sql.Tx) error
	mu                sync.Mutex // waiter registration only; never held during database I/O
	waiters           map[sqlitestore.V2Key]map[chan struct{}]struct{}
	flushNudge        chan struct{}
	writerAdmission   chan struct{}
	grantsMu          sync.Mutex
	newest            map[approvalGrantOwner]sqlitestore.V2Key
	grants            map[sqlitestore.V2Key]ap.Held
	runMu             sync.Mutex
	running           bool
	legacyAuditCursor string
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
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	epoch, err := ap.NewEpoch(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ApprovalV2Engine{
		config: c, epoch: epoch, writerAdmission: make(chan struct{}, 1), commit: func(tx *sql.Tx) error { return tx.Commit() },
		waiters: make(map[sqlitestore.V2Key]map[chan struct{}]struct{}), flushNudge: make(chan struct{}, 1),
		newest: make(map[approvalGrantOwner]sqlitestore.V2Key), grants: make(map[sqlitestore.V2Key]ap.Held),
	}, nil
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
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(&ap.CodeError{Code: ap.CodeStorageUncertain}, err)
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
	return ap.View(rec, now, e.epoch, e.config.Settings, e.grantLive(rec))
}

// transact is the sole mutation path. Preparation resolves inputs using tx;
// Apply owns Clock ordering, including Delete's exception. Effects follow COMMIT.
func (e *ApprovalV2Engine) transact(ctx context.Context, key sqlitestore.V2Key, prepare func(*sql.Tx, *ap.R1, ap.Now) (ap.Command, ap.Inputs, error)) (ap.R1, ap.Answer, error) {
	select {
	case e.writerAdmission <- struct{}{}:
		defer func() { <-e.writerAdmission }()
	case <-ctx.Done():
		return ap.R1{}, ap.Answer{}, approvalReadError(ctx.Err())
	}
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
	e.expireGrants(now)
	command, inputs, err := prepare(tx, before, now)
	if err != nil {
		return ap.R1{}, ap.Answer{}, err
	}
	inputs.Epoch, inputs.Settings = e.epoch, e.config.Settings
	if before != nil {
		inputs.GrantLive = e.grantLive(*before)
	}
	after, answer := ap.Apply(before, command, now, inputs)
	if answer.Code == ap.CodeRecordCorrupt {
		return ap.R1{}, ap.Answer{}, approvalAnswerError(answer)
	}
	// Approval or its audit flush may have landed after Claim's plain read.
	// No mint input means the caller retries; custody never runs under tx.
	if answer.MintRequired {
		return after, ap.Answer{Claim: ap.ClaimNotReady}, nil
	}
	// Settings can invalidate projections without changing an R1 slot.
	_, refresh := command.(ap.Tick)
	refresh = refresh && row != nil
	if refresh && !answer.Changed && !answer.Removed {
		view := e.view(after, now)
		due := ap.Next(after, now, e.epoch, e.config.Settings, inputs.GrantLive).DueAt
		refresh = approvalProjectionChanged(row, view, due)
	}
	if !answer.Changed && !answer.Removed && !refresh {
		return after, answer, approvalAnswerError(answer)
	}
	if answer.Removed {
		err = e.config.Store.DeleteV2(ctx, tx, key)
	} else {
		err = e.config.Store.PutV2(ctx, tx, key, after, sqlitestore.V2Projection{Now: now, Epoch: e.epoch, Settings: e.config.Settings, GrantLive: inputs.GrantLive || (after.Header.Kind == ap.KindStandingGrant && (before == nil || before.Header.Decision == nil) && ap.GrantLive(after, now, e.epoch, true))})
	}
	if err != nil {
		return ap.R1{}, ap.Answer{}, approvalTransactionError(err)
	}
	if err := e.commit(tx); err != nil {
		e.grantsMu.Lock()
		clear(e.grants)
		e.grantsMu.Unlock()
		return ap.R1{}, ap.Answer{}, &ap.CodeError{Code: ap.CodeStorageUncertain}
	}
	e.updateGrant(before, after, answer.Removed, now)
	e.mu.Lock()
	for ready := range e.waiters[key] {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	e.mu.Unlock()
	if !answer.Removed && ap.Unflushed(after) && (before == nil || after.Header.OutboxSeq > before.Header.OutboxSeq) {
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
	// Reclamation is outside the admission transaction. Recheck all caps inside it.
	if _, err := e.config.Store.ReadV2(ctx, key); errors.Is(err, store.ErrNotFound) {
		if err := ap.CheckSubmitWindow(e.now().Wall, draft.SubmitNotAfter, ap.HostedSkew); err != nil {
			return ap.Summary{}, err
		}
		if err := e.reclaimForSubmit(ctx); err != nil {
			return ap.Summary{}, err
		}
	} else if err != nil {
		return ap.Summary{}, approvalReadError(err)
	}
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

func (e *ApprovalV2Engine) registerWaiter(keys []sqlitestore.V2Key) (<-chan struct{}, func()) {
	ready := make(chan struct{}, 1)
	e.mu.Lock()
	for _, key := range keys {
		if e.waiters[key] == nil {
			e.waiters[key] = make(map[chan struct{}]struct{})
		}
		e.waiters[key][ready] = struct{}{}
	}
	e.mu.Unlock()
	return ready, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, key := range keys {
			delete(e.waiters[key], ready)
			if len(e.waiters[key]) == 0 {
				delete(e.waiters, key)
			}
		}
	}
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
	ready, unregister := e.registerWaiter(keys)
	defer unregister()
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

// Vote accepts a verified hosted challenge from the human adapter, which owns
// role and step-up checks. Apply derives policy from the row inside this commit.
func (e *ApprovalV2Engine) Vote(ctx context.Context, key sqlitestore.V2Key, vote ap.CastVote) (ap.Answer, error) {
	if vote.Hosted == nil || vote.Card != nil {
		return ap.Answer{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	_, answer, err := e.mutate(ctx, key, vote, ap.Inputs{})
	return answer, err
}

// Report acknowledges only a confirmed commit, including token refusals.
func (e *ApprovalV2Engine) Report(ctx context.Context, key sqlitestore.V2Key, report ap.Report) (ap.Answer, error) {
	_, answer, err := e.mutate(ctx, key, report, ap.Inputs{})
	return answer, err
}

// Claim waits up to two seconds for the decision audit, then retries once.
// Waiting and custody I/O hold no transaction; Apply rechecks guards under the
// writer lock and returns the winning persisted signature set. Cancellation and
// deadline errors map to storage_uncertain, as store reads do, retaining the
// context error for errors.Is. They never commit a permanent mint failure.
func (e *ApprovalV2Engine) Claim(ctx context.Context, key sqlitestore.V2Key, claim ap.Claim) (ap.Answer, error) {
	answer, err := e.claimOnce(ctx, key, claim)
	if err != nil || answer.Claim != ap.ClaimNotReady {
		return answer, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ready, unregister := e.registerWaiter([]sqlitestore.V2Key{key})
	defer unregister()
	for {
		if err := ctx.Err(); err != nil {
			return ap.Answer{}, approvalReadError(err)
		}
		if waitCtx.Err() != nil {
			break
		}
		// Register before rechecking so a concurrent Flush cannot be missed.
		row, err := e.config.Store.ReadV2(waitCtx, key)
		if err != nil {
			if ctx.Err() != nil {
				return ap.Answer{}, approvalReadError(ctx.Err())
			}
			if waitCtx.Err() != nil {
				break
			}
			return ap.Answer{}, approvalReadError(err)
		}
		if row.Record.Header.Decision == nil {
			return answer, nil
		}
		_, probe := ap.Apply(&row.Record, claim, e.now(), ap.Inputs{Epoch: e.epoch, Settings: e.config.Settings})
		if probe.Claim != ap.ClaimNotReady {
			break
		}
		select {
		case <-waitCtx.Done():
		case <-ready:
		}
	}
	return e.claimOnce(ctx, key, claim)
}

func (e *ApprovalV2Engine) claimOnce(ctx context.Context, key sqlitestore.V2Key, claim ap.Claim) (ap.Answer, error) {
	row, err := e.config.Store.ReadV2(ctx, key)
	if err != nil {
		return ap.Answer{}, approvalReadError(err)
	}
	inputs := ap.Inputs{Epoch: e.epoch, Settings: e.config.Settings}
	_, probe := ap.Apply(&row.Record, claim, e.now(), inputs)
	if probe.Code == ap.CodeRecordCorrupt {
		return ap.Answer{}, approvalAnswerError(probe)
	}
	if probe.MintRequired {
		if e.config.Minter == nil {
			return ap.Answer{}, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
		}
		inputs.Minted, err = e.config.Minter.Mint(ctx, row.Record.Payload.Plan, row.Record.Header.Decision.DecidedAt)
		if ctx.Err() != nil {
			return ap.Answer{}, approvalReadError(ctx.Err())
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ap.Answer{}, approvalReadError(err)
		}
		var coded *ap.CodeError
		if errors.As(err, &coded) && (coded.Code == ap.CodeRecordCorrupt || coded.Code == ap.CodeLifecycleUnavailable) {
			return ap.Answer{}, err
		}
		inputs.MintFailed = err != nil
		if inputs.Minted == nil && !inputs.MintFailed {
			inputs.Minted = []string{}
		}
	}
	_, answer, err := e.transact(ctx, key, func(_ *sql.Tx, current *ap.R1, _ ap.Now) (ap.Command, ap.Inputs, error) {
		// Never apply material from a replaced record to a different approval.
		if probe.MintRequired && current != nil && (current.Header.PlanHash != row.Record.Header.PlanHash ||
			current.Header.Decision == nil || *current.Header.Decision != *row.Record.Header.Decision) {
			return claim, ap.Inputs{}, nil
		}
		return claim, inputs, nil
	})
	return answer, err
}

// ApprovalV2Minter adapts the hosted custody choke point without altering v1.
// Validate the entire plan before signing any leg, including E71's byte checks.
type ApprovalV2Minter struct{ Core HostedCore }

func (m ApprovalV2Minter) Mint(ctx context.Context, plan ap.ApprovalPlanV1, decidedAt time.Time) ([]string, error) {
	if err := plan.Validate(); err != nil {
		return nil, &ap.CodeError{Code: ap.CodeRecordCorrupt}
	}
	if plan.CommandJob == nil {
		return nil, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	commands := make([]signerkit.HostedSignCommand, 0, len(plan.CommandJob.Steps))
	for _, step := range plan.CommandJob.Steps {
		switch step.Route {
		case ap.RouteUnsignedRead:
			continue
		case ap.RouteSignedWrite, ap.RouteSignedAdmin:
			commands = append(commands, signerkit.HostedSignCommand{Cmd: step.ExactCommand, HostKeyFP: step.Target.TrustedHostFingerprint, TTLSeconds: int64(step.SignatureTTLSeconds)})
		default:
			return nil, &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.Core == nil {
		return nil, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
	}
	if len(commands) == 0 {
		return []string{}, nil
	}
	results, err := m.Core.SignApproved(commands, decidedAt)
	if err != nil {
		return nil, err
	}
	if len(results) != len(commands) {
		return nil, errors.New("hosted: signer returned wrong signature count")
	}
	signatures := make([]string, len(results))
	for i, result := range results {
		if result.Cmd != commands[i].Cmd || result.Sig == "" {
			return nil, errors.New("hosted: signer returned invalid signature result")
		}
		signatures[i] = result.Sig
	}
	return signatures, nil
}

func approvalProjectionChanged(row *sqlitestore.V2Row, view ap.Summary, due time.Time) bool {
	status := string(view.ApprovalStatus)
	if view.ExecutionStatus != ap.ExecutionNone && view.ExecutionStatus != ap.ExecutionNotApplicable {
		status = string(view.ExecutionStatus)
	}
	sameDue := row.NextDueAt == nil && due.IsZero()
	if row.NextDueAt != nil && !due.IsZero() {
		sameDue = row.NextDueAt.Unix() == due.Unix()
	}
	return row.Class != view.Class || row.ViewStatus != status || !sameDue
}
