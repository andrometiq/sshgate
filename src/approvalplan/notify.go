package approvalplan

import (
	"slices"
)

// NotifyKind names the notify step a record's actor runs next (SA-4).
type NotifyKind string

const (
	NotifyNone NotifyKind = ""
	// NotifyBurst: commit BurstStart, send the review parts, commit BurstDone.
	NotifyBurst NotifyKind = "burst"
	// NotifyCard: commit CardStart, send the card, commit CardDone.
	NotifyCard NotifyKind = "card"
	// NotifyEdit: commit EditStart (it supersedes an unconfirmed edit from
	// another epoch), edit the card, commit EditDone.
	NotifyEdit NotifyKind = "edit"
	// NotifyEditRetry: re-send this epoch's unconfirmed edit from the
	// challenge the actor holds in memory, then commit EditDone.
	NotifyEditRetry NotifyKind = "edit_retry"
	// NotifyStatus: edit the card to the display state, then commit
	// StatusEdited (best effort).
	NotifyStatus NotifyKind = "status"
)

// NotifyStep is the notify planner's answer.
type NotifyStep struct {
	Kind NotifyKind
	// CardKind is first or replacement for NotifyCard.
	CardKind string
	// Revision is the assist revision a new card or edit carries.
	Revision int
	// MsgID is the card message an edit or status edit targets.
	MsgID int64
	// Handle is the entry NotifyEditRetry re-sends.
	Handle string
	// State is NotifyStatus's display state.
	State string
}

// BurstStart appends the burst write-ahead entry (notify step 1).
type BurstStart struct{}

// BurstDone records the burst's outcome. A live failure also decides error
// (K19); a send the owner's stop interrupted is never reported here.
type BurstDone struct {
	PartMsgIDs []int64
	Failed     bool
}

// CardStart appends a card entry (notify step 2) with a fresh handle and the
// hash of a fresh challenge. A full card set decides error{notification_limit}.
type CardStart struct{ Handle, ChalHash string }

// CardDone records a card send's msg_id and outcome together, or its live
// failure, which decides error.
type CardDone struct {
	Handle string
	MsgID  int64
	Failed bool
}

// EditStart appends an edit entry at the view's revision (notify step 3),
// retiring an unconfirmed edit from another epoch in the same commit.
type EditStart struct{ Handle, ChalHash string }

// EditDone confirms an edit, or on a known edit failure retires the card so
// step 2 sends a replacement (E48).
type EditDone struct {
	Handle string
	Failed bool
}

// StatusEdited records that the display state's one best-effort edit was
// made (notify step 4, E49).
type StatusEdited struct{ State string }

// Renotify is /renotify (notify step 5): raise renotify_gen and retire every
// unretired card entry, authorizing exactly one more burst and card.
type Renotify struct{}

func notifies(h R1Header, s Settings) bool { return !s.Hosted && !grantDecided(h) }

func lastBurst(p *R1Payload) *Burst {
	if len(p.Bursts) == 0 {
		return nil
	}
	return &p.Bursts[len(p.Bursts)-1]
}

// resendDue: no burst carries the current renotify_gen.
func resendDue(rec R1) bool {
	return !slices.ContainsFunc(rec.Payload.Bursts, func(b Burst) bool { return b.Gen == rec.Header.RenotifyGen })
}

func isSendEntry(e CardEntry) bool { return e.Kind == CardFirst || e.Kind == CardReplacement }

// latestUnretired is the index of the latest unretired card entry, or -1.
func latestUnretired(entries []CardEntry) int {
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].Retired {
			return i
		}
	}
	return -1
}

func latestUnretiredSend(p *R1Payload) *CardEntry {
	for i := len(p.CardEntries) - 1; i >= 0; i-- {
		if e := &p.CardEntries[i]; !e.Retired && isSendEntry(*e) {
			return e
		}
	}
	return nil
}

// delivered: a send entry with its message recorded, or a confirmed edit.
func delivered(e CardEntry) bool {
	if e.MsgID == nil {
		return false
	}
	if e.Kind == CardEdit {
		return e.Confirmed
	}
	return e.Outcome == OutcomeSent
}

// cardDue is step 2's guard: the current burst was sent and no unretired card
// entry exists.
func cardDue(rec R1) bool {
	b := lastBurst(rec.Payload)
	return !resendDue(rec) && b != nil && b.Gen == rec.Header.RenotifyGen && b.Outcome == OutcomeSent &&
		latestUnretired(rec.Payload.CardEntries) < 0
}

// NotifyNext is the notify-step planner: the one step of SA-4 that is due for
// a record, judged on the committed record. Steps 1-3 run only while it is
// pending; step 4 only once it is decided.
func NotifyNext(rec R1, now Now, epoch string, s Settings) NotifyStep {
	h, p := rec.Header, rec.Payload
	if p == nil || !notifies(h, s) {
		return NotifyStep{}
	}
	if h.Decision != nil {
		return statusStep(rec, now, s)
	}
	_, rev, _ := assistView(h)
	switch {
	case resendDue(rec):
		return NotifyStep{Kind: NotifyBurst}
	case cardDue(rec):
		kind := CardReplacement
		if len(p.CardEntries) == 0 {
			kind = CardFirst
		}
		return NotifyStep{Kind: NotifyCard, CardKind: kind, Revision: rev}
	}
	i := latestUnretired(p.CardEntries)
	if i < 0 {
		return NotifyStep{}
	}
	e := p.CardEntries[i]
	switch {
	case e.Kind == CardEdit && !e.Confirmed && e.Epoch == epoch:
		return NotifyStep{Kind: NotifyEditRetry, Handle: e.Handle, MsgID: *e.MsgID, Revision: e.Rev}
	case e.Kind == CardEdit && !e.Confirmed:
		return NotifyStep{Kind: NotifyEdit, MsgID: *e.MsgID, Revision: rev}
	case delivered(e) && e.Rev < rev:
		return NotifyStep{Kind: NotifyEdit, MsgID: *e.MsgID, Revision: rev}
	}
	return NotifyStep{}
}

func statusStep(rec R1, now Now, s Settings) NotifyStep {
	msg := cardMessage(rec.Payload)
	state := DisplayState(rec, now, s)
	edits := rec.Payload.StatusEdits
	if msg == 0 || state == "" || len(edits) >= MaxStatusEdits ||
		slices.ContainsFunc(edits, func(e StatusEdit) bool { return e.State == state }) {
		return NotifyStep{}
	}
	return NotifyStep{Kind: NotifyStatus, State: state, MsgID: msg}
}

// cardMessage is the latest delivered card message, or 0.
func cardMessage(p *R1Payload) int64 {
	for i := len(p.CardEntries) - 1; i >= 0; i-- {
		if e := p.CardEntries[i]; delivered(e) {
			return *e.MsgID
		}
	}
	return 0
}

// DisplayState is the E49 display state of a decided record: the approval
// terminal, or for an approved execution-applicable record its execution
// view (a final view shows its class). "" while pending.
func DisplayState(rec R1, now Now, s Settings) string {
	d := rec.Header.Decision
	switch {
	case d == nil:
		return ""
	case d.Status != ApprovalApproved || !rec.Header.Kind.ExecutionApplicable():
		return string(d.Status)
	}
	status, final, _ := executionView(rec, now, s)
	switch status {
	case ExecutionNone:
		return string(ApprovalApproved)
	case ExecutionFinal:
		return string(final.Class)
	}
	return string(status)
}

// notify applies the actor's commits. Each re-checks its step's guard on the
// committed record, so a stale actor can never send twice.
func (c *change) notify(cmd Command, s Settings) Answer {
	h, p := &c.rec.Header, c.rec.Payload
	if p == nil || !notifies(*h, s) {
		return Answer{Reason: "not_applicable"}
	}
	switch cmd := cmd.(type) {
	case BurstStart:
		if h.Decision != nil || !resendDue(c.rec) || len(p.Bursts) >= MaxBursts {
			return Answer{Reason: "not_due"}
		}
		p.Bursts = append(p.Bursts, Burst{Epoch: c.epoch, Gen: h.RenotifyGen, StartedAt: c.now.Wall})
		c.emit(OutboxEvent{Kind: EventBurst})
	case BurstDone:
		b := lastBurst(p)
		if b == nil || b.Epoch != c.epoch || b.Outcome != "" {
			return Answer{Reason: "not_in_flight"}
		}
		b.PartMsgIDs = slices.Clone(cmd.PartMsgIDs)
		b.Outcome = OutcomeSent
		if cmd.Failed {
			b.Outcome = OutcomeError
		}
		c.emit(OutboxEvent{Kind: EventBurstOutcome, Detail: b.Outcome})
		c.failLive(cmd.Failed)
	case CardStart:
		if h.Decision != nil || !cardDue(c.rec) {
			return Answer{Reason: "not_due"}
		}
		kind := CardReplacement
		if len(p.CardEntries) == 0 {
			kind = CardFirst
		}
		return c.appendEntry(cmd.Handle, cmd.ChalHash, kind, nil)
	case CardDone:
		i := slices.IndexFunc(p.CardEntries, func(e CardEntry) bool { return e.Handle == cmd.Handle })
		if i < 0 || !isSendEntry(p.CardEntries[i]) || p.CardEntries[i].Epoch != c.epoch || p.CardEntries[i].Outcome != "" {
			return Answer{Reason: "not_in_flight"}
		}
		e := &p.CardEntries[i]
		e.Outcome = OutcomeError
		if !cmd.Failed {
			if cmd.MsgID < 1 {
				return Answer{Code: CodeInvalidRequest, Reason: "msg_id: must be positive"}
			}
			e.MsgID, e.Outcome = &cmd.MsgID, OutcomeSent
		}
		c.emit(OutboxEvent{Kind: EventCardOutcome, Detail: e.Outcome})
		c.failLive(cmd.Failed)
	case EditStart:
		return c.editStart(cmd)
	case EditDone:
		i := slices.IndexFunc(p.CardEntries, func(e CardEntry) bool { return e.Handle == cmd.Handle })
		if i < 0 || p.CardEntries[i].Kind != CardEdit || p.CardEntries[i].Confirmed || p.CardEntries[i].Retired ||
			p.CardEntries[i].Epoch != c.epoch {
			return Answer{Reason: "not_in_flight"}
		}
		if cmd.Failed {
			c.retireAll()
			return Answer{}
		}
		p.CardEntries[i].Confirmed = true
		c.emit(OutboxEvent{Kind: EventCardConfirmed})
	case StatusEdited:
		step := statusStep(c.rec, c.now, s)
		if step.Kind != NotifyStatus || step.State != cmd.State {
			return Answer{Reason: "not_due"}
		}
		p.StatusEdits = append(p.StatusEdits, StatusEdit{State: cmd.State})
		c.emit(OutboxEvent{Kind: EventStatusEdit, Detail: cmd.State})
	}
	return Answer{}
}

// failLive decides error after a live send failure, if still pending (K19).
func (c *change) failLive(failed bool) {
	if failed && c.rec.Header.Decision == nil {
		c.decide(ApprovalError, c.now.Wall, DecidedByNotifier, ReasonNotificationFailed)
	}
}

func (c *change) editStart(cmd EditStart) Answer {
	h, p := &c.rec.Header, c.rec.Payload
	i := latestUnretired(p.CardEntries)
	_, rev, _ := assistView(*h)
	if h.Decision != nil || i < 0 {
		return Answer{Reason: "not_due"}
	}
	e := p.CardEntries[i]
	supersede := e.Kind == CardEdit && !e.Confirmed && e.Epoch != c.epoch
	if !supersede && !(delivered(e) && e.Rev < rev) {
		return Answer{Reason: "not_due"}
	}
	msg := *e.MsgID
	if supersede {
		p.CardEntries[i].Retired = true
		c.emit(OutboxEvent{Kind: EventCardRetired})
	}
	return c.appendEntry(cmd.Handle, cmd.ChalHash, CardEdit, &msg)
}

// appendEntry adds a card entry at the view's revision, or on a full set
// decides error{notification_limit} (SA-3).
func (c *change) appendEntry(handle, chalHash, kind string, msgID *int64) Answer {
	p := c.rec.Payload
	if !ValidCardHandle(handle) || !ValidSHA256Hex(chalHash) ||
		slices.ContainsFunc(p.CardEntries, func(e CardEntry) bool { return e.Handle == handle }) {
		return Answer{Code: CodeInvalidRequest, Reason: "handle: a fresh card handle and challenge hash are required"}
	}
	if len(p.CardEntries) >= MaxCardEntries {
		c.decide(ApprovalError, c.now.Wall, DecidedByNotifier, ReasonNotificationLimit)
		return Answer{Reason: ReasonNotificationLimit}
	}
	_, rev, _ := assistView(c.rec.Header)
	p.CardEntries = append(p.CardEntries, CardEntry{
		Handle: handle, Rev: rev, ChalHash: chalHash, Actions: ActionsAt(rev), Kind: kind, Epoch: c.epoch, MsgID: msgID,
	})
	c.emit(OutboxEvent{Kind: EventCard, Detail: kind})
	return Answer{}
}

func (c *change) retireAll() {
	for i := range c.rec.Payload.CardEntries {
		if e := &c.rec.Payload.CardEntries[i]; !e.Retired {
			e.Retired = true
			c.emit(OutboxEvent{Kind: EventCardRetired})
		}
	}
}

// renotify is SA-4 step 5, judged after Clock.
func (c *change) renotify(s Settings) Answer {
	h, p := &c.rec.Header, c.rec.Payload
	switch {
	case h.Decision != nil:
		return Answer{Code: CodeConflict, Reason: "not_pending"}
	case p == nil || !notifies(*h, s):
		return Answer{Code: CodeConflict, Reason: "not_applicable"}
	case resendDue(c.rec):
		return Answer{Reason: "already_pending"}
	case sendInFlight(c.rec, c.epoch):
		return Answer{Code: CodeConflict, Reason: "in_progress"}
	case len(p.Bursts) >= MaxBursts:
		return Answer{Code: CodeConflict, Reason: ReasonNotificationLimit}
	}
	h.RenotifyGen++
	c.emit(OutboxEvent{Kind: EventRenotify})
	c.retireAll()
	return Answer{}
}

// sendInFlight: the latest burst or unretired send entry is this epoch's and
// has no outcome yet, so the actor is mid-send.
func sendInFlight(rec R1, epoch string) bool {
	if b := lastBurst(rec.Payload); b != nil && b.Outcome == "" && b.Epoch == epoch {
		return true
	}
	e := latestUnretiredSend(rec.Payload)
	return e != nil && e.Outcome == "" && e.Epoch == epoch
}
