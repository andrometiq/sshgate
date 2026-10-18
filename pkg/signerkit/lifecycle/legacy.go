package lifecycle

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

const LegacyTapRefused = "expired or already resolved"

// LegacyResult is the single v1 resolution. Signing and the ordinary v1 audit
// remain the caller's responsibility, at response time.
type LegacyResult struct {
	Status     string
	ResolvedBy string
}

// LegacyRequest is memory-only. All mutable fields belong to LegacyService.mu.
// The prepared artifact is the sole owner of display and delivery material.
type LegacyRequest struct {
	owner                 legacyOwner
	instance              string
	delivering            bool
	handle, challengeHash string
	artifact              *PreparedLegacyApproval
	live                  bool
	ctx                   context.Context
	cancel                context.CancelFunc
	deadline              time.Duration
	done                  chan struct{}
	result                LegacyResult
	noise                 int
}

type legacyOwner struct {
	uid       uint32
	requestID string
}
type legacyTombstone struct {
	owner         legacyOwner
	challengeHash string
	result        LegacyResult
	noise         int
}

// LegacyService owns v1 work independently of replaceable v2 engines.
// The runtime must close it separately at process shutdown.
type LegacyService struct {
	mu           sync.Mutex
	config       LegacyConfig
	ctx          context.Context
	cancel       context.CancelFunc
	closed       bool
	joined       sync.WaitGroup
	assistPool   *assist.Pool
	audit        *legacyAuditWorker
	unknownEnd   time.Duration
	unknownCount int
	requests     map[string]*LegacyRequest
	owners       map[legacyOwner]*LegacyRequest
	tombstones   map[string]*legacyTombstone
	order        []string
}

// LegacyConfig supplies dependencies that survive v2 storage recovery.
type LegacyConfig struct {
	Clock          elapsed.Clock
	LegacyNotifier LegacyNotifier
	AuditWriter    AuditWriter
	Assessor       assist.Assessor
	AssistTimeout  time.Duration
}

func NewLegacyService(c LegacyConfig) (*LegacyService, error) {
	if c.Clock == nil {
		return nil, errors.New("lifecycle: legacy clock is required")
	}
	if c.AssistTimeout < 0 {
		return nil, errors.New("lifecycle: negative assist timeout")
	}
	if c.AssistTimeout == 0 || c.AssistTimeout > 5*time.Second {
		c.AssistTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &LegacyService{config: c, ctx: ctx, cancel: cancel, assistPool: assist.NewPool(1, assist.Timers{Now: c.Clock.Wall})}, nil
}

func (e *LegacyService) now() ap.Now {
	return ap.Now{Wall: e.config.Clock.Wall().UTC().Round(0), Elapsed: e.config.Clock.Elapsed()}
}

// Close cancels and joins preparation, delivery, deadlines and audit work.
// It must not be called by a legacy adapter.
func (e *LegacyService) Close() error {
	e.mu.Lock()
	e.closed = true
	e.cancel()
	for _, r := range e.requests {
		e.resolveLegacyLocked(r, LegacyResult{Status: "timeout"})
	}
	e.mu.Unlock()
	e.assistPool.Close()
	e.joined.Wait()
	return nil
}

// HasHandle includes tombstones so a resolved legacy card retains its owner.
func (e *LegacyService) HasHandle(handle string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests[handle] != nil || e.tombstones[handle] != nil
}

// reserveLegacyLocked is the admission primitive for prepared legacy delivery.
// The preparation layer supplies freshly minted callback material; no public
// entry point can mark an undelivered request live.
func (e *LegacyService) reserveLegacyLocked(ctx context.Context, uid uint32, requestID, handle, challenge string) (*LegacyRequest, error) {
	if e.closed {
		return nil, unavailable()
	}
	if requestID == "" || !ap.ValidCardHandle(handle) || !ap.ValidChallenge(challenge) {
		return nil, errors.New("lifecycle: invalid legacy reservation")
	}
	if e.requests == nil {
		e.requests = make(map[string]*LegacyRequest)
		e.owners = make(map[legacyOwner]*LegacyRequest)
		e.tombstones = make(map[string]*legacyTombstone)
	}
	owner := legacyOwner{uid, requestID}
	if e.owners[owner] != nil {
		return nil, errors.New("telegram: request_id already pending — refusing duplicate")
	}
	if e.requests[handle] != nil || e.tombstones[handle] != nil {
		return nil, errors.New("lifecycle: legacy handle collision")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := e.now()
	requestCtx, cancel := context.WithCancel(ctx)
	r := &LegacyRequest{owner: owner, handle: handle, challengeHash: ap.ChallengeHash(challenge), ctx: requestCtx, cancel: cancel, deadline: now.Elapsed + sigwire.ApprovalWindow, done: make(chan struct{})}
	e.requests[handle], e.owners[owner] = r, r
	e.joined.Add(1)
	go func() {
		defer e.joined.Done()
		ticker := newReconcileTicker()
		defer ticker.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-ctx.Done():
			case <-ticker.C:
			}
			e.mu.Lock()
			if ctx.Err() != nil || e.config.Clock.Elapsed() >= r.deadline {
				e.resolveLegacyLocked(r, LegacyResult{Status: "timeout"})
			}
			e.mu.Unlock()
		}
	}()
	return r, nil
}

// Wait returns the one resolution; the request watches its deadline independently
// of v2 recovery. Close and caller disconnect resolve outstanding requests as timeout.
func (r *LegacyRequest) Wait() LegacyResult {
	<-r.done
	return r.result // Published before done is closed; never changed afterward.
}

func (e *LegacyService) resolveLegacyLocked(r *LegacyRequest, result LegacyResult) {
	if r.result.Status != "" {
		return
	}
	r.result = result
	r.cancel()
	delete(e.requests, r.handle)
	delete(e.owners, r.owner)
	e.tombstones[r.handle] = &legacyTombstone{owner: r.owner, challengeHash: r.challengeHash, result: result, noise: r.noise}
	e.order = append(e.order, r.handle)
	if len(e.order) > 256 {
		delete(e.tombstones, e.order[0])
		e.order = e.order[1:]
	}
	close(r.done)
}

func (e *LegacyService) expireLegacyLocked(now ap.Now) {
	for _, r := range e.requests {
		if r.ctx.Err() != nil || now.Elapsed >= r.deadline {
			e.resolveLegacyLocked(r, LegacyResult{Status: "timeout"})
		}
	}
}

// LegacyTapResult lets the adapter edit only for the winning tap. Handled=false
// routes a known v2 card to Vote without a legacy answer or audit.
type LegacyTapResult struct {
	Handled  bool
	Resolved bool
	Answer   string
}

// VoteLegacy accepts an authenticated operator's tap. answer must acknowledge
// the callback (best effort); only afterward is its inert audit written. The
// runtime routes v2 handles and refuses cross-service collisions before calling. The
// adapter must not call Close from answer. Audit failures never change a result.
func (e *LegacyService) VoteLegacy(vote ap.CastVote, answer func(LegacyTapResult)) (LegacyTapResult, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return LegacyTapResult{}, unavailable()
	}
	if vote.Card == nil || vote.Hosted != nil || !ap.ValidOperatorID(vote.Operator) || (vote.Decision != ap.VoteApprove && vote.Decision != ap.VoteDeny) || answer == nil {
		e.mu.Unlock()
		return LegacyTapResult{}, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	e.startLegacyAuditLocked()
	now := e.now()
	e.expireLegacyLocked(now)
	result, metadata := e.legacyVoteLocked(vote, now)
	e.joined.Add(1)
	e.mu.Unlock()
	defer e.joined.Done()
	answer(result)
	if metadata != nil {
		e.writeLegacyAudit(*metadata)
	}
	return result, nil
}

func (e *LegacyService) legacyVoteLocked(vote ap.CastVote, now ap.Now) (LegacyTapResult, *ap.AuditMetadata) {
	result := LegacyTapResult{Handled: true, Answer: LegacyTapRefused}
	handle := vote.Card.Handle
	r, tomb := e.requests[handle], e.tombstones[handle]
	transition := "legacy_vote_refused{unknown_card}"
	var owner legacyOwner
	var noise *int
	hash := ap.ChallengeHash(vote.Card.Challenge)
	if r != nil {
		owner, noise = r.owner, &r.noise
		if !r.live || subtle.ConstantTimeCompare([]byte(hash), []byte(r.challengeHash)) != 1 {
			transition = "legacy_vote_refused{stale_challenge}"
		} else {
			status := "approved"
			if vote.Decision == ap.VoteDeny {
				status = "denied"
			}
			e.resolveLegacyLocked(r, LegacyResult{Status: status, ResolvedBy: vote.Operator})
			return LegacyTapResult{Handled: true, Resolved: true, Answer: status}, nil
		}
	} else if tomb != nil {
		owner, noise = tomb.owner, &tomb.noise
		switch {
		case subtle.ConstantTimeCompare([]byte(hash), []byte(tomb.challengeHash)) != 1:
			transition = "legacy_vote_refused{stale_challenge}"
		case tomb.result.Status == "timeout":
			transition = "legacy_vote_refused{expired}"
		default:
			transition = "legacy_vote_replay"
		}
	}
	if noise == nil {
		if now.Elapsed >= e.unknownEnd {
			e.unknownCount = 0
			e.unknownEnd = now.Elapsed + legacyAuditInterval
		}
		noise = &e.unknownCount
	}
	if *noise >= 32 {
		e.audit.dropped++
		return result, nil
	}
	*noise++
	metadata := &ap.AuditMetadata{Transition: transition, Decision: vote.Decision, Replay: true}
	if r != nil || tomb != nil {
		metadata.RequestID = owner.requestID
		metadata.Principal = "local-uid:" + strconv.FormatUint(uint64(owner.uid), 10)
	}
	return result, metadata
}
