package approvalplan_test

import (
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func (r *rig) bursts(key string) int {
	n := 0
	for k, v := range r.s.TG.BurstSends {
		if len(k) > len(key) && k[:len(key)] == key {
			n += v
		}
	}
	return n
}

func (r *rig) notification(key string) ap.NotificationStatus { return r.view(key).NotificationStatus }

func (r *rig) entries(key string) []ap.CardEntry { return r.rec(key).Payload.CardEntries }

// K19: a live send failure on a part or on the card decides error; only a
// send cut by a crash (another epoch, no outcome) is uncertain.
func TestLiveSendFailureIsError(t *testing.T) {
	r := newRig(t)
	part := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.TG.Fail = true
	r.s.Reconcile(part)
	if d := r.rec(part).Header.Decision; d == nil || d.Status != ap.ApprovalError || r.notification(part) != ap.NotificationError {
		t.Fatalf("part failure: %+v %s", d, r.notification(part))
	}
	r.s.TG.Fail = false
	card := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Do(card, ap.BurstStart{})
	r.s.Do(card, ap.BurstDone{PartMsgIDs: []int64{7}})
	h, c := r.s.NewCard()
	r.s.Do(card, ap.CardStart{Handle: h, ChalHash: c})
	r.s.Do(card, ap.CardDone{Handle: h, Failed: true})
	if d := r.rec(card).Header.Decision; d == nil || d.Status != ap.ApprovalError || r.notification(card) != ap.NotificationError {
		t.Fatalf("card failure: %+v %s", d, r.notification(card))
	}
	cut := r.submit(st.ID(3), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Do(cut, ap.BurstStart{})
	if v := r.notification(cut); v != ap.NotificationSending {
		t.Fatalf("in flight in this epoch: %s", v)
	}
	r.s.Restart()
	if v := r.notification(cut); v != ap.NotificationUncertain || r.bursts(cut) != 0 {
		t.Fatalf("after a crash: %s, %d bursts", v, r.bursts(cut))
	}
}

// Re-notify is a durable authorization (r5.4): the crash-prefix walk.
func TestRenotifyAuthorization(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Do(key, ap.BurstStart{})
	r.s.Restart()
	r.s.Reconcile(key)
	if r.bursts(key) != 0 || r.notification(key) != ap.NotificationUncertain {
		t.Fatal("Startup resent a cut burst")
	}
	if ans := r.s.Renotify(key); ans.Code != "" || r.rec(key).Header.RenotifyGen != 1 {
		t.Fatalf("renotify %+v", ans)
	}
	if v := r.notification(key); v != ap.NotificationSending {
		t.Fatalf("after renotify: %s", v)
	}
	if ans := r.s.Renotify(key); ans.Reason != "already_pending" || ans.Changed {
		t.Fatalf("second renotify before the burst: %+v", ans)
	}
	r.s.Restart()
	r.s.Reconcile(key)
	es := r.entries(key)
	if r.bursts(key) != 1 || len(es) != 1 || es[0].Kind != ap.CardFirst || r.rec(key).Payload.Bursts[1].Gen != 1 {
		t.Fatalf("after Startup: %d bursts, entries %+v", r.bursts(key), es)
	}

	cut := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Do(cut, ap.BurstStart{})
	if ans := r.s.Renotify(cut); ans.Reason != "in_progress" {
		t.Fatalf("renotify mid-burst: %+v", ans)
	}
	r.s.Restart()
	r.s.Renotify(cut)
	r.s.Do(cut, ap.BurstStart{})
	r.s.Restart()
	r.s.Reconcile(cut)
	if r.bursts(cut) != 0 || r.notification(cut) != ap.NotificationUncertain {
		t.Fatal("a cut gen-1 burst was resent")
	}
}

// (i) Renotify on a delivered card retires it; the gen-1 burst's parts come
// first, then exactly one replacement. (ii) A Renotify between a burst's
// outcome and its card's append sends the new burst and then one card.
func TestRenotifyReplacesCard(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	r.s.Renotify(key)
	r.s.Reconcile(key)
	es := r.entries(key)
	if r.bursts(key) != 2 || len(es) != 2 || !es[0].Retired || es[1].Kind != ap.CardReplacement || r.notification(key) != ap.NotificationSent {
		t.Fatalf("entries %+v, %d bursts", es, r.bursts(key))
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Do(key2, ap.BurstStart{})
	r.s.Do(key2, ap.BurstDone{PartMsgIDs: []int64{9}})
	if v := r.notification(key2); v != ap.NotificationSending {
		t.Fatalf("between a burst and its card: %s", v)
	}
	r.s.Renotify(key2)
	h, c := r.s.NewCard()
	if ans := r.s.Do(key2, ap.CardStart{Handle: h, ChalHash: c}); ans.Changed {
		t.Fatal("a card for the old burst was appended after Renotify")
	}
	r.s.Reconcile(key2)
	if es := r.entries(key2); len(es) != 1 || es[0].Kind != ap.CardFirst || r.rec(key2).Payload.Bursts[1].Gen != 1 {
		t.Fatalf("entries %+v", es)
	}
}

// (iii) An authorization that never went out reads the last settled outcome,
// never sending. (iv) After a renotified burst, before the replacement, the
// view reads sending, not uncertain; a full card set ends in error.
func TestRenotifyViews(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	r.s.Renotify(key)
	r.s.Cancel(key)
	if v := r.notification(key); v != ap.NotificationSent {
		t.Fatalf("renotify then cancel: %s", v)
	}

	key2 := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Do(key2, ap.BurstStart{})
	r.s.Do(key2, ap.BurstDone{PartMsgIDs: []int64{9}})
	h, c := r.s.NewCard()
	r.s.Do(key2, ap.CardStart{Handle: h, ChalHash: c})
	r.s.Restart()
	if v := r.notification(key2); v != ap.NotificationUncertain {
		t.Fatalf("cut card: %s", v)
	}
	r.s.Renotify(key2)
	r.s.Do(key2, ap.BurstStart{})
	r.s.Do(key2, ap.BurstDone{PartMsgIDs: []int64{10}})
	if v := r.notification(key2); v != ap.NotificationSending {
		t.Fatalf("after the gen-1 burst, before the replacement: %s", v)
	}

	full := r.submit(st.ID(3), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(full)
	for range 7 {
		r.s.Renotify(full)
		r.s.Reconcile(full)
	}
	if ans := r.s.Renotify(full); ans.Reason != ap.ReasonNotificationLimit {
		t.Fatalf("renotify with a full burst set: %+v", ans)
	}
	cards := r.submit(st.ID(4), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(cards)
	r.s.AssistArrives(cards, false)
	for len(r.entries(cards)) < ap.MaxCardEntries {
		h, c := r.s.NewCard()
		r.s.Do(cards, ap.EditStart{Handle: h, ChalHash: c})
		r.s.NewEpoch()
	}
	h3, c3 := r.s.NewCard()
	if ans := r.s.Do(cards, ap.EditStart{Handle: h3, ChalHash: c3}); ans.Reason != ap.ReasonNotificationLimit {
		t.Fatalf("edit with a full card set: %+v", ans)
	}
	full = cards
	if d := r.rec(full).Header.Decision; d == nil || d.TerminalReason != ap.ReasonNotificationLimit || r.notification(full) != ap.NotificationError {
		t.Fatalf("full card set: %+v", d)
	}
}

// A delivered card commits msg_id and outcome together and reads sent in its
// epoch and after a restart; an unconfirmed edit from another epoch never
// makes the view uncertain, a replacement with no outcome does.
func TestCardOutcome(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	if e := r.entries(key)[0]; e.MsgID == nil || e.Outcome != ap.OutcomeSent || r.notification(key) != ap.NotificationSent {
		t.Fatalf("entry %+v", e)
	}
	r.s.AssistArrives(key, false)
	h, c := r.s.NewCard()
	r.s.Do(key, ap.EditStart{Handle: h, ChalHash: c})
	r.s.NewEpoch()
	if v := r.notification(key); v != ap.NotificationSent {
		t.Fatalf("unconfirmed edit from another epoch: %s", v)
	}
	r.s.Renotify(key)
	r.s.Do(key, ap.BurstStart{})
	r.s.Do(key, ap.BurstDone{PartMsgIDs: []int64{3}})
	h, c = r.s.NewCard()
	r.s.Do(key, ap.CardStart{Handle: h, ChalHash: c})
	r.s.Restart()
	if v := r.notification(key); v != ap.NotificationUncertain {
		t.Fatalf("replacement with no outcome from another epoch: %s", v)
	}
}

// Edit supersession (r5.2) and challenge validity across each cut.
func TestEditSupersession(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	rev0 := r.entries(key)[0]
	r.s.AssistArrives(key, false)
	h, c := r.s.NewCard()
	r.s.Do(key, ap.EditStart{Handle: h, ChalHash: c})
	if step := ap.NotifyNext(r.rec(key), r.now(), r.s.Epoch, r.s.Settings); step.Kind != ap.NotifyEditRetry || step.Handle != h {
		t.Fatalf("same epoch: %+v", step)
	}
	interrupted := r.entries(key)[1]
	r.s.NewEpoch()
	if step := ap.NotifyNext(r.rec(key), r.now(), r.s.Epoch, r.s.Settings); step.Kind != ap.NotifyEdit {
		t.Fatalf("another epoch: %+v", step)
	}
	before := r.s.Commits
	h2, c2 := r.s.NewCard()
	r.s.Do(key, ap.EditStart{Handle: h2, ChalHash: c2})
	es := r.entries(key)
	if r.s.Commits != before+1 || !es[1].Retired || es[2].Kind != ap.CardEdit || es[2].Confirmed {
		t.Fatalf("supersede: %+v", es)
	}
	for _, e := range []ap.CardEntry{rev0, interrupted, es[2]} {
		if ans := r.s.TapEntry(key, e, ap.VoteDeny, st.Operator); !ans.Noise {
			t.Fatalf("tap on %s before confirmation counted: %+v", e.Handle, ans)
		}
	}
	r.s.Do(key, ap.EditDone{Handle: h2})
	if ans := r.s.TapEntry(key, r.entries(key)[2], ap.VoteApprove, st.Operator); ans.Noise {
		t.Fatalf("tap on the confirmed edit: %+v", ans)
	}
}

// X1 (OA-5): once the assist slot commits, a tap on the revision-0 card is
// refused stale_revision, Deny included, until the revision-1 edit is
// confirmed; then a tap counts and binds revision 1.
func TestRevisionBinding(t *testing.T) {
	for _, viaClock := range []bool{false, true} {
		r := newRig(t)
		key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
		r.s.Reconcile(key)
		rev0 := r.entries(key)[0]
		if viaClock {
			r.clock.Advance(st.AssistTimeout)
		} else {
			r.s.AssistArrives(key, false)
		}
		for _, d := range []string{ap.VoteDeny, ap.VoteApprove} {
			if ans := r.s.TapEntry(key, rev0, d, st.Operator); ans.Reason != "stale_revision" {
				t.Fatalf("viaClock=%v %s on rev 0: %+v", viaClock, d, ans)
			}
		}
		r.s.Reconcile(key)
		if ans := r.s.Tap(key, ap.VoteApprove, st.Operator, true); ans.Noise {
			t.Fatalf("tap on the confirmed edit: %+v", ans)
		}
		if b := r.rec(key).Header.Decision.AssistBound; b.Revision != 1 {
			t.Fatalf("assist_bound %+v", b)
		}
	}
	// A Deny on a still-current revision-0 challenge is never refused.
	r := newRig(t)
	key := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.Reconcile(key)
	if ans := r.s.Tap(key, ap.VoteDeny, st.Operator, true); ans.Noise || r.rec(key).Header.Decision.Status != ap.ApprovalDenied {
		t.Fatalf("deny at rev 0: %+v", ans)
	}
}

// Duplicates (r5.1): a same-decision re-send, an opposite re-send and a tap
// on a resolved record each append exactly one noise event, nothing else.
func TestDuplicateTapsAreNoise(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.approve(key)
	for _, tap := range []struct{ decision, operator, kind string }{
		{ap.VoteApprove, st.Operator, ap.EventVoteReplay},
		{ap.VoteDeny, st.Operator, ap.EventVoteReplay},
		{ap.VoteApprove, "telegram:7", ap.EventVoteRefused},
	} {
		before := r.rec(key)
		ans := r.s.Tap(key, tap.decision, tap.operator, true)
		after := r.rec(key)
		if !ans.Noise || after.Header.OutboxSeq != before.Header.OutboxSeq+1 || len(after.Header.Votes) != 1 ||
			after.Header.Outbox[len(after.Header.Outbox)-1].Kind != tap.kind {
			t.Fatalf("%+v: %+v", tap, ans)
		}
	}
	for range ap.NoiseFold + 3 {
		r.s.Tap(key, ap.VoteApprove, st.Operator, true)
	}
	if h := r.rec(key).Header; h.NoiseDropped == 0 {
		t.Fatal("noise beyond the fold was not folded")
	}
	r.clock.Advance(time.Second)
}

func TestRefusedNotifyPreservesOnlyClock(t *testing.T) {
	t.Run("card outcome", func(t *testing.T) {
		r := newRig(t)
		key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
		r.apply(key, ap.BurstStart{})
		r.apply(key, ap.BurstDone{PartMsgIDs: []int64{1}})
		h, c := r.s.NewCard()
		r.apply(key, ap.CardStart{Handle: h, ChalHash: c})
		r.clock.Advance(st.AssistTimeout)
		before := r.rec(key)
		want, _ := ap.Clock(before, r.now(), r.s.Epoch)
		after, a := ap.Apply(&before, ap.CardDone{Handle: h, MsgID: 0}, r.now(), ap.Inputs{Epoch: r.s.Epoch, Settings: r.s.Settings})
		gotBytes, _ := ap.EncodeR1(after)
		wantBytes, _ := ap.EncodeR1(want)
		if a.Code != ap.CodeInvalidRequest || !a.Changed || string(gotBytes) != string(wantBytes) {
			t.Fatalf("refusal changed card or lost Clock: %+v", a)
		}
	})
	t.Run("edit supersession", func(t *testing.T) {
		r := newRig(t)
		key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
		r.s.Reconcile(key)
		r.s.AssistArrives(key, false)
		h, c := r.s.NewCard()
		r.apply(key, ap.EditStart{Handle: h, ChalHash: c})
		r.s.NewEpoch()
		before := r.rec(key)
		after, a := ap.Apply(&before, ap.EditStart{Handle: "bad"}, r.now(), ap.Inputs{Epoch: r.s.Epoch, Settings: r.s.Settings})
		x, _ := ap.EncodeR1(before)
		y, _ := ap.EncodeR1(after)
		if a.Code != ap.CodeInvalidRequest || a.Changed || string(x) != string(y) {
			t.Fatalf("refused edit retired entry: %+v", a)
		}
	})
}

func TestHostedTapRefusedLocally(t *testing.T) {
	r := newRig(t)
	key := r.submit(st.ID(1), ap.CoordinatorExecutor, st.Write("w", 60))
	r.s.AssistArrives(key, false)
	rec := r.rec(key)
	a := r.apply(key, ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "hosted", Flags: ap.LocalVoteFlags, Hosted: &ap.HostedTap{PlanHash: rec.Header.PlanHash, Revision: 1, Digest: rec.Header.Assist.Digest, Actions: ap.ActionsAt(1)}})
	if !a.Noise || r.rec(key).Header.Decision != nil || len(r.rec(key).Header.Votes) != 0 {
		t.Fatal(a)
	}
}
