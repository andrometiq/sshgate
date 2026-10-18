package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Config supplies the local engine's authoritative adapters and clock.
type Config struct {
	Store              Store
	Clock              elapsed.Clock
	Freezer            Freezer
	SnapshotBuilder    SnapshotBuilder
	Minter             Minter
	Notifier           Notifier
	LegacyNotifier     LegacyNotifier
	AuditWriter        AuditWriter // nil leaves the outbox unflushed and Claim gated.
	XferDigests        XferDigests
	Caps               Caps // Zero fields use the local defaults.
	Settings           ap.Settings
	AssistTimeout      time.Duration
	AssistPool         *assist.Pool // Owned by Engine; nil leaves the slot for Clock.
	Assessor           assist.Assessor
	AssistInputBuilder AssistInputBuilder
}

// Engine serializes all record mutations. Its Store must not have another writer.
// Run drives effects; Close cancels and joins them before the store may be closed.
type Engine struct {
	mu            sync.Mutex
	running       bool
	stopping      bool
	effectContext context.Context
	cancelEffects context.CancelFunc
	runDone       chan struct{}
	waitJoined    sync.WaitGroup
	notifyContext context.Context
	notifyActors  map[string]*notifyActor
	notifyJoined  sync.WaitGroup
	effectErrors  chan error
	flushNudge    chan struct{}
	flushWaiters  map[string]*flushWaiter
	waiters       map[string]map[chan struct{}]struct{}
	config        Config
	epoch         string
	projections   projections

	legacyContext      context.Context
	cancelLegacy       context.CancelFunc
	legacyClosed       bool
	legacyJoined       sync.WaitGroup
	legacy             legacyTable
	legacyAudit        *legacyAuditWorker
	legacyUnknownEnd   time.Duration
	legacyUnknownCount int
}

// New recovers the store before exposing the engine. The caller owns running Run.
func New(c Config) (*Engine, error) {
	if c.Store == nil || c.Clock == nil || c.Freezer == nil || c.SnapshotBuilder == nil {
		return nil, errors.New("lifecycle: store, clock, freezer and snapshot builder are required")
	}
	if c.AssistPool != nil && c.AssistInputBuilder == nil {
		return nil, errors.New("lifecycle: assist input builder is required with pool")
	}
	if c.Settings.Hosted {
		return nil, errors.New("lifecycle: hosted settings are not supported")
	}
	if c.Settings == (ap.Settings{}) {
		c.Settings = ap.LocalSettings
	}
	if c.Settings.ReportHorizon < 0 || c.Settings.Retention < 0 || c.Settings.MaxAge < 0 || c.AssistTimeout < 0 {
		return nil, errors.New("lifecycle: negative duration")
	}
	if c.AssistTimeout == 0 || c.AssistTimeout > 5*time.Second {
		c.AssistTimeout = 5 * time.Second
	}
	if err := c.Caps.defaults(); err != nil {
		return nil, err
	}
	e := &Engine{config: c, effectErrors: make(chan error, 1), projections: newProjections(), flushNudge: make(chan struct{}, 1), flushWaiters: make(map[string]*flushWaiter)}
	e.effectContext, e.cancelEffects = context.WithCancel(context.Background())
	if err := e.startup(); err != nil {
		e.cancelEffects()
		return nil, err
	}
	e.legacyContext, e.cancelLegacy = context.WithCancel(context.Background())
	return e, nil
}

func (e *Engine) now() ap.Now {
	return ap.Now{Wall: e.config.Clock.Wall().UTC().Round(0), Elapsed: e.config.Clock.Elapsed()}
}

func (e *Engine) load(key string) (*ap.R1, error) {
	rec, err := e.config.Store.Load(key)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ap.RecordKey(rec.Header.Principal, rec.Header.RequestID) != key {
		return nil, keyError()
	}
	return &rec, nil
}

// commitLocked is the only record writer. Callers hold mu from the owner-scoped
// load through impure input resolution and this confirmed projection update.
func (e *Engine) commitLocked(key string, before *ap.R1, cmd ap.Command, now ap.Now, in ap.Inputs) (ap.R1, ap.Answer, error) {
	if e.stopping {
		return ap.R1{}, ap.Answer{}, unavailable()
	}
	// Apply's Delete checks the stored record without Clock. Persist any due
	// slots first so deletion cannot bypass their outbox's flush gate.
	if _, deleting := cmd.(ap.Delete); deleting && before != nil {
		after, answer, err := e.commitLocked(key, before, ap.Tick{}, now, in)
		if err != nil {
			return ap.R1{}, ap.Answer{}, err
		}
		if err := answerError(answer); err != nil {
			return ap.R1{}, ap.Answer{}, err
		}
		before = &after
	}
	in.Epoch, in.Settings = e.epoch, e.config.Settings
	in.GrantLive = e.projections.grants[key] != nil
	after, answer := ap.Apply(before, cmd, now, in)
	if answer.Removed {
		if err := e.config.Store.Remove(key); err != nil {
			return ap.R1{}, ap.Answer{}, err
		}
		e.projections.remove(key)
	} else if answer.Changed {
		if err := e.config.Store.Commit(key, after); err != nil {
			return ap.R1{}, ap.Answer{}, err
		}
		e.projections.update(key, before, after, now, e.epoch, e.config.Settings)
		e.nudgeNotifyLocked(key)
		if before == nil || after.Header.OutboxSeq > before.Header.OutboxSeq {
			e.nudgeFlush()
		}
		if before != nil && after.Header.AuditedThrough > before.Header.AuditedThrough &&
			!slices.ContainsFunc(after.Header.Outbox, func(event ap.OutboxEvent) bool { return event.Kind == ap.EventDecision }) {
			if waiter := e.flushWaiters[key]; waiter != nil {
				close(waiter.ready)
				delete(e.flushWaiters, key)
			}
		}
	}
	if answer.Changed || answer.Removed {
		e.wakeWaitersLocked(key)
	}
	return after, answer, nil
}

func answerError(answer ap.Answer) error {
	if answer.Code == "" {
		return nil
	}
	return &ap.CodeError{Code: answer.Code, Msg: answer.Reason}
}

// Submit freezes only a new owner-scoped ID. Replays use their original record
// even when the registry or submit window has since changed.
func (e *Engine) Submit(ctx context.Context, principal string, draft ap.ApprovalDraft) (ap.Summary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return ap.Summary{}, unavailable()
	}
	key := ap.RecordKey(principal, draft.RequestID)
	before, err := e.load(key)
	if err != nil {
		return ap.Summary{}, err
	}
	now := e.now()
	command := ap.Submit{Draft: draft, Allowance: ap.LocalSkew}
	in := ap.Inputs{}
	if before == nil {
		if err := draft.Validate(); err != nil {
			return ap.Summary{}, err
		}
		if err := ap.CheckSubmitWindow(now.Wall, draft.SubmitNotAfter, ap.LocalSkew); err != nil {
			return ap.Summary{}, err
		}
		plan, err := e.config.Freezer.Freeze(ctx, draft, principal, "", now.Wall)
		if err != nil {
			return ap.Summary{}, err
		}
		if plan.RequesterPrincipal != principal || plan.RequesterSub != "" {
			return ap.Summary{}, fmt.Errorf("lifecycle: freezer changed owner")
		}
		snapshot, reason, err := e.config.SnapshotBuilder.BuildSnapshot(ctx, plan)
		if err != nil {
			return ap.Summary{}, err
		}
		command.Plan, command.ReviewSnapshot, command.RationaleRedacted = plan, snapshot, reason
		command.RequiredApprovals, command.AssistDeadline = 1, now.Wall.Add(e.config.AssistTimeout)
		e.projections.expireGrants(now)
		in.Grant, err = e.matchGrant(plan)
		if err != nil {
			return ap.Summary{}, err
		}
		previewInputs := in
		previewInputs.Epoch, previewInputs.Settings = e.epoch, e.config.Settings
		candidate, answer := ap.Apply(nil, command, now, previewInputs)
		if err := answerError(answer); err != nil {
			return ap.Summary{}, err
		}
		if err := e.admitLocked(candidate, now); err != nil {
			return ap.Summary{}, err
		}
	}
	after, answer, err := e.commitLocked(key, before, command, now, in)
	if err != nil {
		return ap.Summary{}, err
	}
	if err := answerError(answer); err != nil {
		return ap.Summary{}, err
	}
	if before == nil && answer.Changed {
		after, err = e.startAssistLocked(key, after)
		if err != nil {
			return ap.Summary{}, err
		}
	}
	return e.view(key, after, now), nil
}

func (e *Engine) matchGrant(plan ap.ApprovalPlanV1) (*ap.GrantRef, error) {
	// Sorting makes unsigned-only plans covered by several grants deterministic.
	keys := make([]string, 0, len(e.projections.grants))
	for key := range e.projections.grants {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	candidate := ap.R1{Header: ap.R1Header{Kind: plan.Kind, Principal: plan.RequesterPrincipal, SubPrincipal: plan.RequesterSub}, Payload: &ap.R1Payload{Plan: plan}}
	for _, key := range keys {
		grant, err := e.load(key)
		if err != nil {
			return nil, err
		}
		if grant == nil {
			return nil, keyError()
		}
		if ap.GrantCovers(*grant, candidate) {
			return &ap.GrantRef{Record: *grant, Live: true}, nil
		}
	}
	return nil, nil
}

func (e *Engine) view(key string, rec ap.R1, now ap.Now) ap.Summary {
	return ap.View(rec, now, e.epoch, e.config.Settings, e.projections.grants[key] != nil)
}

// Get reads committed slots only; it never advances Clock or grant expiry.
func (e *Engine) Get(principal, requestID string) (ap.Summary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return ap.Summary{}, unavailable()
	}
	key := ap.RecordKey(principal, requestID)
	rec, err := e.load(key)
	if err != nil {
		return ap.Summary{}, err
	}
	if rec == nil {
		return ap.Summary{}, &ap.CodeError{Code: ap.CodeNotFound}
	}
	return e.view(key, *rec, e.now()), nil
}

// List returns the caller's committed records in record-key order.
func (e *Engine) List(principal string) ([]ap.Summary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return nil, unavailable()
	}
	now := e.now()
	keys := make([]string, 0)
	for key, charge := range e.projections.records {
		if charge.principal == principal {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	out := make([]ap.Summary, 0, len(keys))
	for _, key := range keys {
		rec, err := e.load(key)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			return nil, keyError()
		}
		out = append(out, e.view(key, *rec, now))
	}
	return out, nil
}
