package lifecycle

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"sync"
	"time"

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

// LegacyRequest is memory-only. All mutable fields belong to Engine.mu.
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

// legacyService is created once by New and stopped only by Close. Engine.mu
// guards its state; v2 stop and recovery own none of these resources.
type legacyService struct {
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

func newLegacyService(now func() time.Time) *legacyService {
	ctx, cancel := context.WithCancel(context.Background())
	return &legacyService{ctx: ctx, cancel: cancel, assistPool: assist.NewPool(1, assist.Timers{Now: now})}
}

// reserveLegacyLocked is the admission primitive for prepared legacy delivery.
// The preparation layer supplies freshly minted callback material; no public
// entry point can mark an undelivered request live.
func (e *Engine) reserveLegacyLocked(ctx context.Context, uid uint32, requestID, handle, challenge string) (*LegacyRequest, error) {
	if e.legacy.closed {
		return nil, unavailable()
	}
	if requestID == "" || !ap.ValidCardHandle(handle) || !ap.ValidChallenge(challenge) {
		return nil, errors.New("lifecycle: invalid legacy reservation")
	}
	if e.legacy.requests == nil {
		e.legacy.requests = make(map[string]*LegacyRequest)
		e.legacy.owners = make(map[legacyOwner]*LegacyRequest)
		e.legacy.tombstones = make(map[string]*legacyTombstone)
	}
	owner := legacyOwner{uid, requestID}
	if e.legacy.owners[owner] != nil {
		return nil, errors.New("telegram: request_id already pending — refusing duplicate")
	}
	if e.legacy.requests[handle] != nil || e.legacy.tombstones[handle] != nil || len(e.projections.cards[handle]) != 0 {
		return nil, errors.New("lifecycle: legacy handle collision")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := e.now()
	requestCtx, cancel := context.WithCancel(ctx)
	r := &LegacyRequest{owner: owner, handle: handle, challengeHash: ap.ChallengeHash(challenge), ctx: requestCtx, cancel: cancel, deadline: now.Elapsed + sigwire.ApprovalWindow, done: make(chan struct{})}
	e.legacy.requests[handle], e.legacy.owners[owner] = r, r
	e.legacy.joined.Add(1)
	go func() {
		defer e.legacy.joined.Done()
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

func (e *Engine) resolveLegacyLocked(r *LegacyRequest, result LegacyResult) {
	if r.result.Status != "" {
		return
	}
	r.result = result
	r.cancel()
	delete(e.legacy.requests, r.handle)
	delete(e.legacy.owners, r.owner)
	e.legacy.tombstones[r.handle] = &legacyTombstone{owner: r.owner, challengeHash: r.challengeHash, result: result, noise: r.noise}
	e.legacy.order = append(e.legacy.order, r.handle)
	if len(e.legacy.order) > 256 {
		delete(e.legacy.tombstones, e.legacy.order[0])
		e.legacy.order = e.legacy.order[1:]
	}
	close(r.done)
}

func (e *Engine) expireLegacyLocked(now ap.Now) {
	for _, r := range e.legacy.requests {
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
// adapter must not call Close from answer. Audit failures never change a result.
func (e *Engine) VoteLegacy(vote ap.CastVote, answer func(LegacyTapResult)) (LegacyTapResult, error) {
	e.mu.Lock()
	if e.legacy.closed {
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
	if !result.Handled {
		e.mu.Unlock()
		return result, nil
	}
	e.legacy.joined.Add(1)
	e.mu.Unlock()
	defer e.legacy.joined.Done()
	answer(result)
	if metadata != nil {
		e.writeLegacyAudit(*metadata)
	}
	return result, nil
}

func (e *Engine) legacyVoteLocked(vote ap.CastVote, now ap.Now) (LegacyTapResult, *ap.AuditMetadata) {
	result := LegacyTapResult{Handled: true, Answer: LegacyTapRefused}
	handle := vote.Card.Handle
	r, tomb := e.legacy.requests[handle], e.legacy.tombstones[handle]
	if r == nil && tomb == nil && len(e.projections.cards[handle]) != 0 {
		return LegacyTapResult{}, nil
	}
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
		if now.Elapsed >= e.legacy.unknownEnd {
			e.legacy.unknownCount = 0
			e.legacy.unknownEnd = now.Elapsed + legacyAuditInterval
		}
		noise = &e.legacy.unknownCount
	}
	if *noise >= 32 {
		e.legacy.audit.dropped++
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
