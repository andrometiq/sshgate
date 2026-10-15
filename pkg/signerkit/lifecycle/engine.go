package lifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Config supplies the local engine's authoritative adapters and clock.
type Config struct {
	Store           Store
	Clock           elapsed.Clock
	Freezer         Freezer
	SnapshotBuilder SnapshotBuilder
	Minter          Minter
	XferDigests     XferDigests
	Settings        ap.Settings
	AssistTimeout   time.Duration
}

// Engine serializes all record mutations. Its Store must not have another writer.
// Background effects and recovery are installed separately from this core.
type Engine struct {
	mu          sync.Mutex
	config      Config
	epoch       string
	projections projections
}

// New constructs a core over an empty store. Recovery of existing stores belongs
// to Startup; refusing them here prevents serving incomplete projections.
func New(c Config) (*Engine, error) {
	if c.Store == nil || c.Clock == nil || c.Freezer == nil || c.SnapshotBuilder == nil {
		return nil, errors.New("lifecycle: store, clock, freezer and snapshot builder are required")
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
	entries, err := c.Store.List()
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, errors.New("lifecycle: nonempty store requires Startup")
	}
	epoch, err := ap.NewEpoch(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Engine{config: c, epoch: epoch, projections: newProjections()}, nil
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
	}
	after, answer, err := e.commitLocked(key, before, command, now, in)
	if err != nil {
		return ap.Summary{}, err
	}
	if err := answerError(answer); err != nil {
		return ap.Summary{}, err
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
