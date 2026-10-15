package approvalplan

import "time"

// Now is one evaluation's two clock readings (SA-1 rule 3.1): the wall clock
// for every stamp, guard and Clock pass, and the elapsed clock that held
// authority is measured on (rule 3.4). The core never reads a clock; callers
// pass the reading they took inside their critical section.
type Now struct {
	Wall    time.Time
	Elapsed time.Duration
}

// norm drops any monotonic reading and zone, so stamps encode canonically.
func (n Now) norm() Now {
	n.Wall = n.Wall.UTC().Round(0)
	return n
}

// ReleaseSkew is SA-1 rule 3.2's bound: signature bytes leave only while
// decided_at ≤ now + ReleaseSkew.
const ReleaseSkew = 5 * time.Second

// Settings is the store configuration the views, the reconciler and the
// retention commands read (SA-6.2, SA-9). The record holds none of it.
type Settings struct {
	// Hosted selects the hosted record key and turns the Telegram
	// notification view off (SA-6.3).
	Hosted bool
	// ReportHorizon is [approvals] report_horizon or
	// --approval-report-horizon.
	ReportHorizon time.Duration
	// Retention is the Shed age, counted from decided_at.
	Retention time.Duration
	// MaxAge is the Delete age, counted from decided_at; 0 means never (the
	// hosted default, E23).
	MaxAge time.Duration
}

// LocalSettings is the local signer's default configuration.
var LocalSettings = Settings{ReportHorizon: ReportHorizonDefault, Retention: 7 * 24 * time.Hour, MaxAge: 7 * 24 * time.Hour}

// DeleteFloor is how long past submit_not_after a record is kept whatever its
// age limit, so a retried draft can never become a second approval (E73).
const DeleteFloor = 24 * time.Hour

// windowEnd is a signed step's window end in whole seconds: exactly the gate
// Exp of a signature minted at decidedAt (SA-1 rule 3.3).
func windowEnd(decidedAt time.Time, ttl int) time.Time {
	return time.Unix(decidedAt.Unix()+int64(ttl), 0).UTC()
}

// StepWindows returns each step's window end for an approved record: one per
// step, zero for an unsigned step. A transfer's one step covers both legs.
func StepWindows(rec R1) []time.Time {
	d := rec.Header.Decision
	if d == nil || d.Status != ApprovalApproved || !rec.Header.Kind.ExecutionApplicable() {
		return nil
	}
	out := make([]time.Time, len(rec.Header.StepTTLs))
	for i, ttl := range rec.Header.StepTTLs {
		if ttl > 0 {
			out[i] = windowEnd(d.DecidedAt, ttl)
		}
	}
	return out
}

// windows returns first_end and last_end over the signed steps.
func windows(rec R1) (first, last time.Time, ok bool) {
	for _, end := range StepWindows(rec) {
		if end.IsZero() {
			continue
		}
		if !ok || end.Before(first) {
			first = end
		}
		if !ok || end.After(last) {
			last = end
		}
		ok = true
	}
	return first, last, ok
}

// SyncClaimDeadline is created_at + 310 s, after which an in_process_sync
// record can no longer be claimed (E25).
func SyncClaimDeadline(h R1Header) time.Time { return h.CreatedAt.Add(SyncClaimWindow) }

// ClaimEnd is the one window function's claim_end (SA-1 rule 3.3): first_end
// while unclaimed, last_end once claimed, never later than the sync claim
// deadline for an in_process_sync record. ok is false unless the record is
// approved and execution-applicable.
func ClaimEnd(rec R1) (time.Time, bool) {
	first, last, ok := windows(rec)
	if !ok {
		return time.Time{}, false
	}
	end := first
	if rec.Header.ClaimCount > 0 {
		end = last
	}
	if rec.Header.Coordinator == CoordinatorInProcessSync {
		if sync := SyncClaimDeadline(rec.Header); sync.Before(end) {
			end = sync
		}
	}
	return end, true
}

// LastEnd is last_end, the report horizon's base.
func LastEnd(rec R1) (time.Time, bool) {
	_, last, ok := windows(rec)
	return last, ok
}

// Clock fills, in order, exactly the empty slots whose deadline is at or
// before now (SA-1 rule 3.3): the assist deadline's unavailable snapshot, the
// expiry decision, and at claim_end either window_closed or the Erase. It
// writes no stamp, never overwrites a slot, and is idempotent. epoch is the
// owner's current epoch, recorded in an expiry decision. It returns the record
// and the events it appended.
func Clock(rec R1, now Now, epoch string) (R1, []OutboxEvent) {
	c := begin(rec, now, epoch)
	c.clock()
	return c.rec, c.events
}

func (c *change) clock() {
	h := &c.rec.Header
	if h.Assist == nil && !c.now.Wall.Before(h.AssistDeadline) {
		h.Assist = unavailableSlot(h.AssistDeadline)
		c.emit(OutboxEvent{Kind: EventAssist, Assist: boundPtr(assistBound(c.rec))})
	}
	if h.Decision == nil && !c.now.Wall.Before(h.RequestExpiresAt) {
		c.decide(ApprovalExpired, h.RequestExpiresAt, DecidedByClock, "")
	}
	end, ok := ClaimEnd(c.rec)
	if !ok || c.now.Wall.Before(end) {
		return
	}
	switch {
	case h.ClaimCount == 0 && h.Mint == nil:
		h.Mint = &MintSlot{State: MintError, Reason: MintReasonWindowClosed}
		c.emit(OutboxEvent{Kind: EventMint, Detail: MintReasonWindowClosed})
	case bytesHeld(c.rec):
		c.erase()
	}
}

// unavailableSlot is Clock's assist snapshot: a pure function of the header,
// so every Clock pass past the deadline writes the same bytes and digest
// (K8, E68).
func unavailableSlot(deadline time.Time) *AssistSlot {
	return &AssistSlot{
		State: AssistUnavailable, Reason: AssistDeadlineReason, GeneratedAt: deadline,
		Digest: UnavailableAssistDigest(AssistDeadlineReason, deadline),
	}
}

// bytesHeld reports whether the record still holds minted signature bytes.
func bytesHeld(rec R1) bool {
	return rec.Payload != nil && len(rec.Payload.Signatures) > 0
}

func (c *change) erase() {
	c.rec.Payload.Signatures = nil
	c.emit(OutboxEvent{Kind: EventErase})
}

// NextDueAt is the record's next_due_at (SA-1 rule 3.3): the earliest instant
// at which Next has time-driven work, or the zero time when none is left. A
// term that has passed and has nothing to commit (the report horizon, an age
// a guard still blocks) is dropped, so a due pass that commits nothing still
// advances it. An unflushed outbox is never a term (SA-7).
func NextDueAt(rec R1, now Now, s Settings) time.Time {
	h := rec.Header
	var due time.Time
	add := func(t time.Time) {
		if !t.IsZero() && (due.IsZero() || t.Before(due)) {
			due = t
		}
	}
	if h.Assist == nil {
		add(h.AssistDeadline)
	}
	if h.Decision == nil {
		add(h.RequestExpiresAt)
		return due
	}
	if end, ok := ClaimEnd(rec); ok && (h.Mint == nil || bytesHeld(rec)) {
		add(end)
	}
	if last, ok := LastEnd(rec); ok && h.ClaimCount > 0 && h.FinalReport == nil {
		if horizon := last.Add(s.ReportHorizon); now.Wall.Before(horizon) {
			add(horizon)
		}
	}
	if at := shedAt(h, s); !h.Shed && (now.Wall.Before(at) || shedAllowed(rec, now, s, false, false)) {
		add(at)
	}
	if at, ok := deleteAt(h, s); ok && (now.Wall.Before(at) || deleteAllowed(rec, now, s, false, false)) {
		add(at)
	}
	return due
}

func shedAt(h R1Header, s Settings) time.Time { return h.Decision.DecidedAt.Add(s.Retention) }

// deleteAt is max(submit_not_after + 24 h, decided_at + age limit); ok is
// false while no age limit is set.
func deleteAt(h R1Header, s Settings) (time.Time, bool) {
	if s.MaxAge <= 0 || h.Decision == nil {
		return time.Time{}, false
	}
	at := h.Decision.DecidedAt.Add(s.MaxAge)
	if floor := h.SubmitNotAfter.Add(DeleteFloor); floor.After(at) {
		at = floor
	}
	return at, true
}
