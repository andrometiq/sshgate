package approvalplan

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// Outbox event kinds. A store's flusher writes each as transition
// "approval-<kind>". The four noise kinds carry Replay and may be folded.
const (
	EventSubmitted     = "submitted"
	EventAssist        = "assist"
	EventVote          = "vote"
	EventDecision      = "decision"
	EventMint          = "mint"
	EventErase         = "erase"
	EventFinalReport   = "final_report"
	EventRevoked       = "revoked"
	EventBurst         = "burst"
	EventBurstOutcome  = "burst_outcome"
	EventCard          = "card"
	EventCardOutcome   = "card_outcome"
	EventCardConfirmed = "card_confirmed"
	EventCardRetired   = "card_retired"
	EventStatusEdit    = "status_edit"
	EventRenotify      = "renotify"

	EventVoteReplay    = "vote_replay"
	EventVoteRefused   = "vote_refused"
	EventInvalidClaim  = "invalid_claim"
	EventInvalidReport = "invalid_report"
)

// decided_by forms other than an operator list.
const (
	DecidedByClock     = "clock"
	DecidedByNotifier  = "notifier"
	GrantDecidedPrefix = "grant:"
)

// Terminal reasons the core writes.
const (
	ReasonNotificationFailed = "notification_failed"
	ReasonNotificationLimit  = "notification_limit"
)

// Command is one SA-4 command on an R1 record. Each is exactly one commit.
type Command interface{ isCommand() }

// Submit freezes a new record, or returns the existing one for the same
// draft. The caller has frozen Plan from Draft at the same wall reading it
// passes to Apply, and built the review snapshot and redacted reason.
type Submit struct {
	Draft             ApprovalDraft
	Plan              ApprovalPlanV1
	ReviewSnapshot    json.RawMessage
	RationaleRedacted string
	// RequiredApprovals is the server's configured quorum, frozen into the
	// header; a value ≤ 0 freezes as 1. Local is always 1 (E6).
	RequiredApprovals int
	// AssistDeadline is freeze + min(timeout, 5 s) (E68).
	AssistDeadline time.Time
	// Allowance is the submit window's skew allowance: LocalSkew or HostedSkew.
	Allowance time.Duration
}

// AssistDone commits the one assist attempt's result: a validated provider
// result, or an unavailable reason ("assist busy", a provider failure).
type AssistDone struct {
	Result      *AssistResult
	Unavailable string
}

// CastVote is one operator's tap or POST. The caller has checked the role and
// step-up; Card or Hosted carries the challenge the core judges against the
// view after Clock (SA-6.1).
type CastVote struct {
	Operator string
	Decision string
	Authn    string
	Flags    VoteFlags
	Card     *CardTap
	Hosted   *HostedTap
}

// CardTap is a local Telegram callback: the card handle, the raw challenge it
// carries and the message it was pressed on.
type CardTap struct {
	Handle    string
	Challenge string
	MsgID     int64
}

// HostedTap is a hosted vote POST whose MAC the handler has verified.
// Refusal is a MAC-side refusal the handler already found (expired_challenge,
// session_mismatch, stale_challenge); the core records it as noise. The other
// fields are the challenge's binding, compared with the view after Clock.
type HostedTap struct {
	Refusal  string
	PlanHash string
	Revision int
	Digest   string
	Actions  []string
}

// AdminCancel cancels a pending record whose plan_hash the admin saw.
type AdminCancel struct {
	PlanHash string
	Admin    string
}

// Revoke ends an approved grant record.
type Revoke struct{}

// Tick applies Clock alone.
type Tick struct{}

// Flush records that the sink holds every event through Through.
type Flush struct{ Through uint64 }

// ShedRecord drops the payload of a settled, fully audited record (SA-9).
type ShedRecord struct{ Pressure bool }

// Delete removes a settled, fully audited record past its ages. It is the one
// command that skips Clock.
type Delete struct{ Pressure bool }

func (Submit) isCommand()       {}
func (AssistDone) isCommand()   {}
func (CastVote) isCommand()     {}
func (AdminCancel) isCommand()  {}
func (Revoke) isCommand()       {}
func (Tick) isCommand()         {}
func (Flush) isCommand()        {}
func (ShedRecord) isCommand()   {}
func (Delete) isCommand()       {}
func (Claim) isCommand()        {}
func (Report) isCommand()       {}
func (Renotify) isCommand()     {}
func (BurstStart) isCommand()   {}
func (BurstDone) isCommand()    {}
func (CardStart) isCommand()    {}
func (CardDone) isCommand()     {}
func (EditStart) isCommand()    {}
func (EditDone) isCommand()     {}
func (StatusEdited) isCommand() {}

// Inputs are a command's impure inputs, read by the caller inside the same
// critical section (SA-1 rule 4).
type Inputs struct {
	Epoch    string
	Settings Settings
	// GrantLive is the grant projection's membership for this record, used
	// by the class that Shed and Delete judge.
	GrantLive bool
	// Grant is the live grant a Submit's freeze or a grant-decided first
	// Claim is judged against.
	Grant *GrantRef
	// Minted is the signature set for a first Claim, signed at decided_at;
	// MintFailed reports that the minter failed.
	Minted     []string
	MintFailed bool
	// XferDigests are the transfer registry's current entry digests.
	XferDigests *XferDigests
}

// GrantRef is a grant record and the caller's projection verdict on it: the
// newest grant for its alias in this epoch, with neither held end found
// passed (SA-6.4).
type GrantRef struct {
	Record R1
	Live   bool
}

// XferDigests are the current key-entry digests of a transfer's endpoints.
type XferDigests struct{ Source, Destination string }

// Answer is a command's answer. Changed says the store must commit the
// returned record; nothing else may be committed.
type Answer struct {
	// Code is set for a refusal on the wire's closed set.
	Code Code
	// Reason details a refusal, a noise event, a materialization error, or
	// an inert outcome such as "already_resolved".
	Reason string
	// Noise says the command was recorded only as a noise event.
	Noise bool
	// Claim answers.
	Claim      ClaimStatus
	Signatures []string
	DecidedAt  time.Time
	Windows    []time.Time
	Class      JobClass
	// MintRequired asks the caller to supply the mint inputs and apply the
	// same Claim again; nothing is to be committed.
	MintRequired bool
	Changed      bool
	// Removed says Delete's record is to be removed from the store.
	Removed bool
}

// change is one evaluation of a command on a private copy of the record.
type change struct {
	rec     R1
	now     Now
	epoch   string
	changed bool
	events  []OutboxEvent
}

func begin(rec R1, now Now, epoch string) *change {
	return &change{rec: cloneR1(rec), now: now.norm(), epoch: epoch}
}

// cloneR1 copies every slice and pointer the core may replace, so a command
// never writes through to the caller's record. Pointees are never mutated in
// place: the core always assigns fresh values.
func cloneR1(rec R1) R1 {
	h := &rec.Header
	h.Votes = slices.Clone(h.Votes)
	h.Outbox = slices.Clone(h.Outbox)
	if rec.Payload != nil {
		p := *rec.Payload
		p.Signatures = slices.Clone(p.Signatures)
		p.CardEntries = slices.Clone(p.CardEntries)
		p.Bursts = slices.Clone(p.Bursts)
		p.StatusEdits = slices.Clone(p.StatusEdits)
		rec.Payload = &p
	}
	return rec
}

// emit appends one event to the outbox with the next sequence number. A noise
// event beyond the fold only raises noise_dropped (SA-7).
func (c *change) emit(e OutboxEvent) {
	h := &c.rec.Header
	c.changed = true
	if e.Replay {
		fold := NoiseFold
		if h.Shed {
			fold = ShedNoiseFold
		}
		if unflushedNoise(*h) >= fold {
			h.NoiseDropped++
			return
		}
	}
	h.OutboxSeq++
	e.Seq = h.OutboxSeq
	e.NoiseDropped = h.NoiseDropped
	h.Outbox = append(h.Outbox, e)
	c.events = append(c.events, e)
}

func unflushedNoise(h R1Header) int {
	n := 0
	for _, e := range h.Outbox {
		if e.Replay {
			n++
		}
	}
	return n
}

func (c *change) noise(kind, operator, decision, reason string) Answer {
	c.emit(OutboxEvent{Kind: kind, Replay: true, Operator: operator, Decision: decision, Detail: reason})
	return Answer{Noise: true, Reason: reason}
}

// decide writes the decision slot with the assist the view shows at this
// commit (K8), and its event.
func (c *change) decide(status ApprovalStatus, at time.Time, by, reason string) {
	bound := assistBound(c.rec)
	if strings.HasPrefix(by, GrantDecidedPrefix) {
		bound = AssistBound{State: AssistNotApplicable}
	}
	c.rec.Header.Decision = &Decision{
		Status: status, DecidedAt: at, DecidedBy: by, TerminalReason: reason, Epoch: c.epoch, AssistBound: bound,
	}
	c.emit(OutboxEvent{Kind: EventDecision, Decision: string(status), DecidedBy: by, Assist: &bound, Detail: reason})
}

// Apply is the one commit function (SA-1 rule 4): cmd applied to Clock(rec,
// now). rec is nil when the owner-scoped load found nothing, so a foreign and
// an absent ID answer identically (SA-6.6). The returned record is committed
// exactly when Answer.Changed; when Answer.Removed the record is deleted.
func Apply(rec *R1, cmd Command, now Now, in Inputs) (R1, Answer) {
	if rec == nil {
		if s, ok := cmd.(Submit); ok {
			return submitNew(s, now.norm(), in)
		}
		return R1{}, Answer{Code: CodeNotFound}
	}
	if d, ok := cmd.(Delete); ok {
		if deleteAllowed(*rec, now.norm(), in.Settings, in.GrantLive, d.Pressure) {
			return R1{}, Answer{Removed: true}
		}
		return *rec, Answer{Reason: "protected"}
	}
	c := begin(*rec, now, in.Epoch)
	c.clock()
	clocked := begin(c.rec, c.now, c.epoch)
	clocked.changed = c.changed
	ans := c.apply(cmd, in)
	if ans.Code != "" && !ans.Noise {
		c = clocked
	}
	if ans.MintRequired {
		return *rec, Answer{MintRequired: true}
	}
	if c.changed {
		if err := c.rec.validate(); err != nil {
			return *rec, refusal(err)
		}
	}
	ans.Changed = c.changed
	return c.rec, ans
}

func (c *change) apply(cmd Command, in Inputs) Answer {
	switch cmd := cmd.(type) {
	case Submit:
		return c.resubmit(cmd)
	case AssistDone:
		return c.assistDone(cmd)
	case CastVote:
		return c.vote(cmd, in.Settings.Hosted)
	case AdminCancel:
		return c.adminCancel(cmd)
	case Revoke:
		return c.revoke()
	case Tick:
		return Answer{}
	case Flush:
		return c.flush(cmd)
	case ShedRecord:
		if !shedAllowed(c.rec, c.now, in.Settings, in.GrantLive, cmd.Pressure) {
			return Answer{Reason: "protected"}
		}
		c.rec, c.changed = Shed(c.rec), true
		return Answer{}
	case Claim:
		return c.claim(cmd, in)
	case Report:
		return c.report(cmd)
	case Renotify:
		return c.renotify(in.Settings)
	case BurstStart, BurstDone, CardStart, CardDone, EditStart, EditDone, StatusEdited:
		return c.notify(cmd, in.Settings)
	}
	return Answer{Code: CodeInvalidRequest, Reason: "unknown command"}
}

func refusal(err error) Answer {
	var ce *CodeError
	if errors.As(err, &ce) {
		return Answer{Code: ce.Code, Reason: strings.TrimPrefix(ce.Field+": "+ce.Msg, ": ")}
	}
	return Answer{Code: CodeInvalidRequest, Reason: err.Error()}
}

// submitNew validates and freezes a new record (SA-4 Submit). The caller has
// already run admission; the window is judged here at the wall clock.
func submitNew(s Submit, now Now, in Inputs) (R1, Answer) {
	if err := s.Draft.Validate(); err != nil {
		return R1{}, refusal(err)
	}
	if err := CheckSubmitWindow(now.Wall, s.Draft.SubmitNotAfter, s.Allowance); err != nil {
		return R1{}, refusal(err)
	}
	if err := planMatchesDraft(s.Plan, s.Draft, now.Wall); err != nil {
		return R1{}, refusal(err)
	}
	if s.AssistDeadline.Before(now.Wall) || s.AssistDeadline.After(now.Wall.Add(5*time.Second)) {
		return R1{}, Answer{Code: CodeInvalidRequest, Reason: "assist_deadline: must be within 5 s of freeze"}
	}
	draftHash, err := DraftHash(s.Draft)
	if err != nil {
		return R1{}, refusal(err)
	}
	planHash, err := PlanHash(s.Plan)
	if err != nil {
		return R1{}, refusal(err)
	}
	p := s.Plan
	h := R1Header{
		Version: R1Version, Principal: p.RequesterPrincipal, SubPrincipal: p.RequesterSub, RequestID: p.RequestID,
		Kind: p.Kind, DraftHash: draftHash, PlanHash: planHash, RationaleOrigin: p.RationaleOrigin,
		RationaleRedacted: s.RationaleRedacted, ClaimTokenHash: p.ExecutorClaimTokenHash, Coordinator: p.Coordinator,
		RequiredApprovals: max(s.RequiredApprovals, 1), CreatedAt: now.Wall, RequestExpiresAt: p.RequestExpiresAt,
		AssistDeadline: s.AssistDeadline.UTC(), SubmitNotAfter: p.SubmitNotAfter, StepTTLs: stepTTLs(p),
	}
	h.StepCount = len(h.StepTTLs)
	if g := p.StandingGrant; g != nil {
		h.GrantAlias, h.DurationSeconds, h.GrantHostFP = g.Alias, g.DurationSeconds, g.TrustedHostFingerprint
	}
	c := &change{rec: R1{Header: h, Payload: &R1Payload{Plan: p, ReviewSnapshot: s.ReviewSnapshot}}, now: now, epoch: in.Epoch}
	c.emit(OutboxEvent{Kind: EventSubmitted})
	if g := in.Grant; g != nil && g.Live && GrantLive(g.Record, now, in.Epoch, true) && GrantCovers(g.Record, c.rec) {
		c.decide(ApprovalApproved, now.Wall, GrantDecidedPrefix+g.Record.Header.RequestID, "")
		if by := g.Record.Header.Decision.DecidedBy; ValidOperatorID(by) {
			c.rec.Header.Outbox[len(c.rec.Header.Outbox)-1].Operator = by
		}
	}
	c.clock()
	if err := c.rec.validate(); err != nil {
		return R1{}, refusal(err)
	}
	return c.rec, Answer{Changed: true}
}

// planMatchesDraft checks that the frozen plan is the draft plus only what
// the signer resolves at freeze, frozen at this evaluation's wall reading.
func planMatchesDraft(p ApprovalPlanV1, d ApprovalDraft, now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Kind != d.Kind || p.RequestID != d.RequestID || p.Rationale != d.Rationale ||
		p.ExecutorClaimTokenHash != d.ExecutorClaimTokenHash || p.Coordinator != d.Coordinator ||
		!p.SubmitNotAfter.Equal(d.SubmitNotAfter) || !p.SubmittedAt.Equal(now) {
		return invalid("plan", "does not freeze this draft at this evaluation")
	}
	var planPart, draftPart any
	switch p.Kind {
	case KindCommandJob:
		planPart, draftPart = p.CommandJob, d.CommandJob
	case KindStandingGrant:
		planPart, draftPart = p.StandingGrant, d.StandingGrant
	case KindTransfer:
		t := *p.Transfer
		t.TransferID, t.SendCommand, t.SendCommandSHA256, t.RecvCommand, t.RecvCommandSHA256 = "", "", "", "", ""
		for _, e := range []*TransferEndpoint{&t.Source, &t.Destination} {
			e.KeyLabel, e.PublicKey, e.PublicKeySHA256, e.KeyEntryDigest = "", "", "", ""
		}
		planPart, draftPart = &t, d.Transfer
	}
	a, errA := Canonical(planPart)
	b, errB := Canonical(draftPart)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return invalid("plan", "payload differs from the draft's")
	}
	return nil
}

func (c *change) resubmit(s Submit) Answer {
	sum, err := DraftHash(s.Draft)
	if err != nil {
		return refusal(err)
	}
	if sum != c.rec.Header.DraftHash {
		return Answer{Code: CodeConflict, Reason: "request_id: already used with another draft"}
	}
	return Answer{}
}

func (c *change) assistDone(a AssistDone) Answer {
	h := &c.rec.Header
	if h.Assist != nil || c.rec.Payload == nil {
		return Answer{Reason: "dropped"}
	}
	switch {
	case a.Result != nil && a.Unavailable == "":
		if err := ValidateAssist(*a.Result); err != nil {
			return refusal(err)
		}
		r := *a.Result
		h.Assist = &AssistSlot{State: AssistReady, GeneratedAt: r.GeneratedAt, Digest: AssistDigest(r)}
		c.rec.Payload.AssistResult = &r
	case a.Result == nil && isRouteTokenOrSpaced(a.Unavailable, MaxAssistReasonBytes):
		h.Assist = &AssistSlot{
			State: AssistUnavailable, Reason: a.Unavailable, GeneratedAt: c.now.Wall,
			Digest: UnavailableAssistDigest(a.Unavailable, c.now.Wall),
		}
	default:
		return Answer{Code: CodeInvalidRequest, Reason: "assist: exactly one of a result or an unavailable reason"}
	}
	c.emit(OutboxEvent{Kind: EventAssist, Assist: boundPtr(assistBound(c.rec))})
	return Answer{}
}

// vote applies one tap or POST (SA-4 Vote). Every guard is judged after
// Clock; a vote that fails one is recorded as exactly one noise event.
func (c *change) vote(v CastVote, hosted bool) Answer {
	if !ValidOperatorID(v.Operator) || (v.Decision != VoteApprove && v.Decision != VoteDeny) ||
		!isEventToken(v.Authn, MaxAuthnBytes) || (v.Card == nil) == (v.Hosted == nil) {
		return Answer{Code: CodeInvalidRequest, Reason: "vote: operator, decision, authn and exactly one challenge are required"}
	}
	h := &c.rec.Header
	voted := slices.ContainsFunc(h.Votes, func(x Vote) bool { return x.Operator == v.Operator })
	if h.Decision != nil {
		if voted {
			return c.noise(EventVoteReplay, v.Operator, v.Decision, "")
		}
		return c.noise(EventVoteRefused, v.Operator, v.Decision, resolvedReason(h.Decision.Status))
	}
	if reason := c.challengeRefusal(v, hosted); reason != "" {
		return c.noise(EventVoteRefused, v.Operator, v.Decision, reason)
	}
	if voted {
		return c.noise(EventVoteReplay, v.Operator, v.Decision, "")
	}
	vote := Vote{Operator: v.Operator, Decision: v.Decision, TS: c.now.Wall, Authn: v.Authn}
	if !VoteRoom(c.rec, v.Flags, vote) {
		return c.noise(EventVoteRefused, v.Operator, v.Decision, "set_full")
	}
	h.Votes = append(h.Votes, vote)
	c.emit(OutboxEvent{Kind: EventVote, Operator: v.Operator, Decision: v.Decision})
	p := EffectivePolicy(c.rec, v.Flags)
	switch Decide(p, h.Votes) {
	case ApprovalApproved:
		c.decide(ApprovalApproved, vote.TS, strings.Join(ApprovingOperators(p, h.Votes), ","), "")
	case ApprovalDenied:
		c.decide(ApprovalDenied, vote.TS, firstEligibleDeny(p, h.Votes), "")
	}
	return Answer{}
}

func firstEligibleDeny(p Policy, votes []Vote) string {
	for _, v := range votes {
		if v.Decision == VoteDeny && (p.AllowSelfApprove || v.Operator != p.Requester) {
			return v.Operator
		}
	}
	return ""
}

func resolvedReason(s ApprovalStatus) string {
	if s == ApprovalExpired || s == ApprovalCanceled {
		return string(s)
	}
	return "resolved"
}

// challengeRefusal judges a tap's challenge against the record after Clock
// (SA-6.1); "" means valid.
func (c *change) challengeRefusal(v CastVote, hosted bool) string {
	_, rev, digest := assistView(c.rec.Header)
	if t := v.Hosted; t != nil {
		if !hosted {
			return "stale_challenge"
		}
		switch {
		case t.Refusal != "":
			if !isEventToken(t.Refusal, MaxDetailBytes) {
				return "stale_challenge"
			}
			return t.Refusal
		case t.PlanHash != c.rec.Header.PlanHash || t.Revision != rev || t.Digest != digest || !slices.Equal(t.Actions, ActionsAt(rev)):
			return "stale_challenge"
		case !slices.Contains(t.Actions, v.Decision):
			return "action_not_allowed"
		}
		return ""
	}
	t := v.Card
	if c.rec.Payload == nil {
		return "unknown_card"
	}
	entries := c.rec.Payload.CardEntries
	i := slices.IndexFunc(entries, func(e CardEntry) bool { return e.Handle == t.Handle })
	switch {
	case i < 0:
		return "unknown_card"
	case i != latestUnretired(entries):
		return "retired"
	case entries[i].Rev != rev:
		return "stale_revision"
	case !delivered(entries[i]):
		return "undelivered"
	case *entries[i].MsgID != t.MsgID ||
		subtle.ConstantTimeCompare([]byte(ChallengeHash(t.Challenge)), []byte(entries[i].ChalHash)) != 1:
		return "stale_challenge"
	case !slices.Contains(entries[i].Actions, v.Decision):
		return "action_not_allowed"
	}
	return ""
}

// ActionsAt is the action set a card or challenge offers at an assist
// revision: Deny only while assist is preparing (K6), both once it is final.
func ActionsAt(revision int) []string {
	if revision == 0 {
		return []string{ActionDeny}
	}
	return []string{ActionApprove, ActionDeny}
}

func (c *change) adminCancel(a AdminCancel) Answer {
	if !ValidOperatorID(a.Admin) {
		return Answer{Code: CodeInvalidRequest, Reason: "admin: is not an operator ID"}
	}
	h := &c.rec.Header
	if h.Decision != nil {
		return Answer{Reason: "already_resolved"}
	}
	if a.PlanHash != h.PlanHash {
		return Answer{Code: CodeConflict, Reason: "plan_hash: the record changed since the snapshot"}
	}
	c.decide(ApprovalCanceled, c.now.Wall, a.Admin, "")
	return Answer{}
}

func (c *change) revoke() Answer {
	h := &c.rec.Header
	if h.Kind != KindStandingGrant {
		return Answer{Code: CodeInvalidRequest, Reason: "kind: only a grant is revoked"}
	}
	if h.Decision == nil || h.Decision.Status != ApprovalApproved || h.RevokedAt != nil {
		return Answer{Reason: "not_live"}
	}
	at := c.now.Wall
	h.RevokedAt = &at
	c.emit(OutboxEvent{Kind: EventRevoked})
	return Answer{}
}

func (c *change) flush(f Flush) Answer {
	h := &c.rec.Header
	if f.Through > h.OutboxSeq {
		return Answer{Code: CodeInvalidRequest, Reason: "through: past outbox_seq"}
	}
	if f.Through <= h.AuditedThrough {
		return Answer{}
	}
	h.AuditedThrough = f.Through
	h.Outbox = slices.DeleteFunc(h.Outbox, func(e OutboxEvent) bool { return e.Seq <= f.Through })
	if len(h.Outbox) == 0 {
		h.Outbox = nil
	}
	c.changed = true
	return Answer{}
}

func fullyAudited(h R1Header) bool { return h.AuditedThrough == h.OutboxSeq }

// shedAllowed is SA-9's Shed rule: settled and fully audited at its age or
// under payload pressure, or a fully audited awaiting_report record under
// pressure. All Clock writes must be committed and flushed first.
func shedAllowed(rec R1, now Now, s Settings, grantLive, pressure bool) bool {
	h := rec.Header
	if h.Shed || h.Decision == nil || h.Assist == nil || !fullyAudited(h) || bytesHeld(rec) {
		return false
	}
	if _, ok := ClaimEnd(rec); ok && h.Mint == nil {
		return false
	}
	switch Class(rec, now, s, grantLive) {
	case ClassSettled:
		return pressure || !now.Wall.Before(shedAt(h, s))
	case ClassAwaitingReport:
		return pressure
	}
	return false
}

// deleteAllowed is SA-9's Delete rule: settled, fully audited, past
// submit_not_after + 24 h, and past its age limit or under count pressure.
func deleteAllowed(rec R1, now Now, s Settings, grantLive, pressure bool) bool {
	h := rec.Header
	if h.Decision == nil || !fullyAudited(h) || Class(rec, now, s, grantLive) != ClassSettled ||
		now.Wall.Before(h.SubmitNotAfter.Add(DeleteFloor)) {
		return false
	}
	if pressure {
		return !s.Hosted || s.MaxAge > 0
	}
	at, ok := deleteAt(h, s)
	return ok && !now.Wall.Before(at)
}

func grantDecided(h R1Header) bool {
	return h.Decision != nil && strings.HasPrefix(h.Decision.DecidedBy, GrantDecidedPrefix)
}

// assistView is the approval view's assist (SA-6.1): the slot, or preparing
// at revision 0; not_applicable for a grant-decided record.
func assistView(h R1Header) (AssistState, int, string) {
	switch {
	case grantDecided(h):
		return AssistNotApplicable, 0, ""
	case h.Assist == nil:
		return AssistPreparing, 0, ""
	}
	return h.Assist.State, 1, h.Assist.Digest
}

func assistBound(rec R1) AssistBound {
	state, rev, digest := assistView(rec.Header)
	return AssistBound{State: state, Revision: rev, Digest: digest}
}

func boundPtr(b AssistBound) *AssistBound { return &b }
