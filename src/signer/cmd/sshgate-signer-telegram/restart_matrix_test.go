//go:build linux

package main

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

const renotifyAccepted = "re-notify accepted: a new review and card follow"

func latest(card, edit botCall) botCall {
	if edit.id != 0 {
		return edit
	}
	return card
}

func lastCard(t *testing.T, calls []botCall) botCall {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if isCard(calls[i]) {
			return calls[i]
		}
	}
	t.Fatal("no card")
	return botCall{}
}

func lastEntry(r ap.R1) ap.CardEntry {
	if r.Payload == nil || len(r.Payload.CardEntries) == 0 {
		return ap.CardEntry{}
	}
	return r.Payload.CardEntries[len(r.Payload.CardEntries)-1]
}

// No reattach: a delivered card stays sent and votable through itself, and
// /renotify is the only resend.
func TestRestartDeliveredCardStaysVotable(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	a, b := m.submit(1), m.submit(2)
	cardA, editA := m.delivered(a)
	cardB, editB := m.delivered(b)
	for _, id := range []string{a, b} {
		if s := m.get(id); s.NotificationStatus != ap.NotificationSent {
			t.Fatalf("%s before restart: %s", id, s.NotificationStatus)
		}
	}
	m.kill()

	m.restart()
	m.quiet(a, time.Second)
	m.quiet(b, 0)
	for _, id := range []string{a, b} {
		if s := m.get(id); s.NotificationStatus != ap.NotificationSent || s.ApprovalStatus != ap.ApprovalPending {
			t.Fatalf("%s after restart: %+v", id, s)
		}
	}
	tap := m.bot.tap(button(t, latest(cardA, editA), "v:d:"), cardA.id)
	if answer := m.answered(tap); answer != "denied" {
		t.Fatalf("tap through the pre-restart card: %q", answer)
	}
	if rec := m.record(a); rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalDenied {
		t.Fatalf("decision %+v", rec.Header.Decision)
	}

	before := len(forRecord(m.bot.snapshot(), b))
	m.bot.command("/renotify " + m.handle(b))
	m.reply(renotifyAccepted)
	rec := m.waitRecord(b, "the replacement card", func(r ap.R1) bool {
		e := lastEntry(r)
		return r.Header.RenotifyGen == 1 && e.Kind == ap.CardReplacement && e.Outcome == ap.OutcomeSent
	})
	if !rec.Payload.CardEntries[0].Retired {
		t.Fatal("renotify left the old card valid")
	}
	m.settled(b)
	sent := forRecord(m.bot.snapshot(), b)[before:]
	if count(sent, isPart) == 0 || count(sent, isCard) != 1 || !isCard(sent[len(sent)-1]) {
		t.Fatalf("renotify sends, want parts then one card: %+v", sent)
	}
	tap = m.bot.tap(button(t, latest(cardB, editB), "v:d:"), cardB.id)
	if answer := m.answered(tap); answer != "card updated — tap again" {
		t.Fatalf("retired card tap: %q", answer)
	}
	if rec := m.record(b); rec.Header.Decision != nil {
		t.Fatal("retired card decided")
	}
	replacement := lastCard(t, sent)
	tap = m.bot.tap(button(t, replacement, "v:a:"), replacement.id)
	if answer := m.answered(tap); answer != "approved" {
		t.Fatalf("replacement card tap: %q", answer)
	}
	m.proc.terminate(t)
}

func fault(point string) string { return "SSHGATE_TEST_FAULT=" + point }

func cardHandle(data string) string {
	if len(data) < 5+ap.CardHandleLen {
		return ""
	}
	return data[4 : 4+ap.CardHandleLen]
}

// An interrupted edit, at both cuts: one commit supersedes it and exactly one
// fresh edit follows; the old challenges answer "card updated — tap again".
func TestRestartInterruptedEdit(t *testing.T) {
	for _, cut := range []string{"before_call", "accepted_unconfirmed"} {
		t.Run(cut, func(t *testing.T) {
			m := newMatrix(t, matrixOptions{explainer: true})
			if cut == "before_call" {
				m.start(fault("notify.before-edit"))
				m.ready()
			} else {
				held := make(chan struct{}, 1)
				m.bot.setIntercept(func(_ context.Context, call botCall) botReply {
					if isCardEdit(call) {
						held <- struct{}{}
						return replyHang
					}
					return replyOK
				})
				m.restart()
			}
			id := m.submit(1)
			if cut == "before_call" {
				m.crashed()
			} else {
				m.waitRecord(id, "the edit entry", func(r ap.R1) bool { return lastEntry(r).Kind == ap.CardEdit })
				eventually(t, 10*time.Second, "the held edit", func() bool { return count(m.bot.snapshot(), isCardEdit) == 1 })
				m.kill()
				m.bot.setIntercept(nil)
			}
			interrupted := lastEntry(m.record(id))
			if interrupted.Kind != ap.CardEdit || interrupted.Confirmed || len(m.record(id).Payload.CardEntries) != 2 {
				t.Fatalf("interrupted entry %+v", m.record(id).Payload.CardEntries)
			}
			calls := m.bot.snapshot()
			card := lastCard(t, calls)
			oldEdits := count(calls, isCardEdit)

			m.restart()
			if s := m.get(id); s.NotificationStatus != ap.NotificationSent {
				t.Fatalf("superseded edit shows %s", s.NotificationStatus)
			}
			rec := m.waitRecord(id, "the fresh edit", func(r ap.R1) bool {
				return len(r.Payload.CardEntries) == 3 && r.Payload.CardEntries[2].Confirmed
			})
			fresh := rec.Payload.CardEntries[2]
			if !rec.Payload.CardEntries[1].Retired || fresh.Kind != ap.CardEdit || fresh.Handle == interrupted.Handle || fresh.ChalHash == interrupted.ChalHash {
				t.Fatalf("supersession %+v", rec.Payload.CardEntries)
			}
			m.settled(id)
			edits := []botCall{}
			for _, call := range m.bot.snapshot() {
				if isCardEdit(call) {
					edits = append(edits, call)
					if cardHandle(button(t, call, "v:d:")) == interrupted.Handle && cut == "before_call" {
						t.Fatal("the fake received the interrupted entry's edit")
					}
				}
			}
			if len(edits) != oldEdits+1 || cardHandle(button(t, edits[len(edits)-1], "v:a:")) != fresh.Handle {
				t.Fatalf("edits after restart: %d new (want 1)", len(edits)-oldEdits)
			}
			if s := m.get(id); s.NotificationStatus != ap.NotificationSent {
				t.Fatalf("after the fresh edit: %s", s.NotificationStatus)
			}
			stale := []string{button(t, card, "v:d:")}
			if cut == "accepted_unconfirmed" {
				stale = append(stale, button(t, edits[0], "v:a:"))
			}
			for _, data := range stale {
				if answer := m.answered(m.bot.tap(data, card.id)); answer != "card updated — tap again" {
					t.Fatalf("stale tap %s: %q", data[:4], answer)
				}
			}
			if rec := m.record(id); rec.Header.Decision != nil {
				t.Fatal("stale tap decided")
			}
			if answer := m.answered(m.bot.tap(button(t, edits[len(edits)-1], "v:a:"), card.id)); answer != "approved" {
				t.Fatalf("fresh challenge: %q", answer)
			}
			m.proc.terminate(t)
		})
	}
}

// Repeated crashes at the before-call cut use one card entry each; the entry
// limit then ends the request as error{notification_limit}.
func TestRestartRepeatedEditCrashesReachNotificationLimit(t *testing.T) {
	m := newMatrix(t, matrixOptions{explainer: true})
	m.start(fault("notify.before-edit"))
	m.ready()
	id := m.submit(1)
	m.crashed()
	crashes := 1
	for entries := len(m.record(id).Payload.CardEntries); entries < ap.MaxCardEntries; crashes++ {
		m.start(fault("notify.before-edit"))
		m.crashed()
		next := len(m.record(id).Payload.CardEntries)
		if next != entries+1 {
			t.Fatalf("crash %d used %d card entries", crashes, next-entries)
		}
		entries = next
	}
	m.start(fault("notify.before-edit"))
	rec := m.waitRecord(id, "the notification limit", func(r ap.R1) bool { return r.Header.Decision != nil })
	if rec.Header.Decision.Status != ap.ApprovalError || rec.Header.Decision.TerminalReason != ap.ReasonNotificationLimit || crashes != ap.MaxCardEntries-1 {
		t.Fatalf("after %d crashes: %+v", crashes, rec.Header.Decision)
	}
	// Every review part and the card are marked INCOMPLETE.
	want := map[int]bool{}
	for _, id := range rec.Payload.Bursts[len(rec.Payload.Bursts)-1].PartMsgIDs {
		want[int(id)] = true
	}
	for _, entry := range rec.Payload.CardEntries {
		if entry.MsgID != nil {
			want[int(*entry.MsgID)] = true
		}
	}
	eventually(t, 10*time.Second, "INCOMPLETE edits on every part and the card", func() bool {
		marked := map[int]bool{}
		for _, call := range m.bot.snapshot() {
			if isIncomplete(call) {
				marked[call.id] = true
			}
		}
		return len(want) >= 2 && reflect.DeepEqual(marked, want)
	})
	if edits := count(m.bot.snapshot(), isCardEdit); edits != 0 {
		t.Fatalf("%d card edits reached the fake", edits)
	}
	m.proc.terminate(t)
}

// A restart while assist is preparing: Clock commits unavailable at the
// deadline, the card is edited to revision 1, and the provider is not called again.
func TestRestartWhileAssistPreparing(t *testing.T) {
	m := newMatrix(t, matrixOptions{explainer: true})
	m.restart()
	id := m.submit(1)
	m.waitRecord(id, "the revision-0 card", func(r ap.R1) bool { e := lastEntry(r); return e.Outcome == ap.OutcomeSent && e.Rev == 0 })
	if rec := m.record(id); rec.Header.Assist != nil {
		t.Fatalf("assist already settled: %+v", rec.Header.Assist)
	}
	m.kill()
	providerCalls := m.bot.explainerCalls()
	m.restart()
	restarted := time.Now()
	rec := m.waitRecord(id, "assist unavailable", func(r ap.R1) bool { return r.Header.Assist != nil })
	observed := time.Now()
	if rec.Header.Assist.State != ap.AssistUnavailable {
		t.Fatalf("assist %+v", rec.Header.Assist)
	}
	due := rec.Header.AssistDeadline
	if restarted.After(due) {
		due = restarted
	}
	if late := observed.Sub(due); late > 2*time.Second {
		t.Fatalf("unavailable committed %v after it was due", late)
	}
	rec = m.waitRecord(id, "the revision-1 edit", func(r ap.R1) bool { e := lastEntry(r); return e.Kind == ap.CardEdit && e.Confirmed && e.Rev == 1 })
	m.settled(id)
	if edits := count(m.bot.snapshot(), isCardEdit); edits != 1 {
		t.Fatalf("%d card edits", edits)
	}
	if calls := m.bot.explainerCalls(); calls != providerCalls || calls != 1 {
		t.Fatalf("provider calls %d before restart, %d after", providerCalls, calls)
	}
	m.proc.terminate(t)
}

// uncertain kills the signer while the first burst's first part is held and
// restarts it: the burst is from the old epoch with no outcome.
func (m *matrix) uncertain(n int) string {
	m.t.Helper()
	held := m.hold(isPart, replyHang, nil)
	id := m.submit(n)
	receive(m.t, held)
	m.kill()
	m.bot.setIntercept(nil)
	m.restart()
	m.quiet(id, time.Second)
	if s := m.get(id); s.NotificationStatus != ap.NotificationUncertain || s.ApprovalStatus != ap.ApprovalPending {
		m.t.Fatalf("after the interrupted burst: %+v", s)
	}
	return id
}

// The cut after /renotify commits and before its burst is appended, with an
// empty card set; redelivered /renotify commands are dropped by the drain.
func TestRestartRenotifyCommitCuts(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	id := m.uncertain(1)
	m.kill()

	m.start(fault("renotify.before-commit"))
	m.ready()
	m.bot.command("/renotify " + m.handle(id))
	m.crashed()
	if rec := m.record(id); rec.Header.RenotifyGen != 0 {
		t.Fatalf("unlanded renotify committed gen %d", rec.Header.RenotifyGen)
	}
	m.restart()
	m.quiet(id, time.Second)
	if s := m.get(id); s.NotificationStatus != ap.NotificationUncertain {
		t.Fatalf("not landed: %s", s.NotificationStatus)
	}
	m.kill()

	m.start(fault("renotify.after-commit"))
	m.ready()
	m.bot.command("/renotify " + m.handle(id))
	m.crashed()
	if rec := m.record(id); rec.Header.RenotifyGen != 1 || len(rec.Payload.Bursts) != 1 || len(rec.Payload.CardEntries) != 0 {
		t.Fatalf("landed renotify: gen=%d bursts=%d cards=%d", rec.Header.RenotifyGen, len(rec.Payload.Bursts), len(rec.Payload.CardEntries))
	}
	before := len(forRecord(m.bot.snapshot(), id))
	m.restart()
	rec := m.waitRecord(id, "the gen-1 burst and card", func(r ap.R1) bool { return lastEntry(r).Outcome == ap.OutcomeSent })
	if len(rec.Payload.Bursts) != 2 || rec.Payload.Bursts[1].Gen != 1 || rec.Payload.Bursts[1].Outcome != ap.OutcomeSent || len(rec.Payload.CardEntries) != 1 || rec.Payload.CardEntries[0].Kind != ap.CardFirst {
		t.Fatalf("after the landed cut: bursts=%+v cards=%+v", rec.Payload.Bursts, rec.Payload.CardEntries)
	}
	m.settled(id)
	sent := forRecord(m.bot.snapshot(), id)[before:]
	if count(sent, isPart) == 0 || count(sent, isCard) != 1 || !isCard(sent[len(sent)-1]) {
		t.Fatalf("sends after the landed cut: %+v", sent)
	}
	if rec.Header.RenotifyGen != 1 {
		t.Fatalf("a redelivered /renotify was applied: gen %d", rec.Header.RenotifyGen)
	}
	card := lastCard(t, sent)
	if answer := m.answered(m.bot.tap(button(t, card, "v:a:"), card.id)); answer != "approved" {
		t.Fatalf("new card tap: %q", answer)
	}
	m.proc.terminate(t)
}

// A kill after the gen-1 burst's append leaves it uncertain again, with no
// automatic third burst.
func TestRestartKillAfterRenotifyBurstAppend(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	id := m.uncertain(1)
	held := m.hold(isPart, replyHang, nil)
	m.bot.command("/renotify " + m.handle(id))
	receive(t, held)
	m.kill()
	m.bot.setIntercept(nil)
	m.restart()
	m.quiet(id, 2*time.Second)
	rec := m.record(id)
	if s := m.get(id); s.NotificationStatus != ap.NotificationUncertain || len(rec.Payload.Bursts) != 2 || rec.Payload.Bursts[1].Gen != 1 {
		t.Fatalf("status %s bursts %+v", s.NotificationStatus, rec.Payload.Bursts)
	}
	m.proc.terminate(t)
}

// A crash after a card was sent and before its message ID committed: the
// card's taps are refused and /renotify sends parts, then one replacement.
func TestRestartCardSentBeforeMessageIDCommitted(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	held := m.hold(isCard, replyHang, nil)
	id := m.submit(1)
	card := receive(t, held)
	m.kill()
	m.bot.setIntercept(nil)
	m.restart()
	m.quiet(id, time.Second)
	if s := m.get(id); s.NotificationStatus != ap.NotificationUncertain {
		t.Fatalf("status %s", s.NotificationStatus)
	}
	if answer := m.answered(m.bot.tap(button(t, card, "v:d:"), card.id)); answer != lifecycle.LegacyTapRefused {
		t.Fatalf("unrecorded card tap: %q", answer)
	}
	if rec := m.record(id); rec.Header.Decision != nil {
		t.Fatal("unrecorded card decided")
	}
	before := len(forRecord(m.bot.snapshot(), id))
	m.bot.command("/renotify " + m.handle(id))
	m.reply(renotifyAccepted)
	rec := m.waitRecord(id, "the replacement", func(r ap.R1) bool {
		e := lastEntry(r)
		return e.Kind == ap.CardReplacement && e.Outcome == ap.OutcomeSent
	})
	if !rec.Payload.CardEntries[0].Retired {
		t.Fatal("unrecorded card not retired")
	}
	m.settled(id)
	sent := forRecord(m.bot.snapshot(), id)[before:]
	if count(sent, isPart) == 0 || count(sent, isCard) != 1 || !isCard(sent[len(sent)-1]) || !isPart(sent[0]) {
		t.Fatalf("renotify sends: %+v", sent)
	}
	m.proc.terminate(t)
}

// By contrast, a transport error on the same send while the signer keeps
// running ends the request as error with INCOMPLETE edits.
func TestRunningCardTransportErrorIsError(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	m.hold(isCard, replyReset, nil)
	id := m.submit(1)
	rec := m.waitRecord(id, "the error decision", func(r ap.R1) bool { return r.Header.Decision != nil })
	if rec.Header.Decision.Status != ap.ApprovalError {
		t.Fatalf("decision %+v", rec.Header.Decision)
	}
	eventually(t, 10*time.Second, "INCOMPLETE edits", func() bool {
		return count(forRecord(m.bot.snapshot(), id), isIncomplete) == len(rec.Payload.Bursts[0].PartMsgIDs)
	})
	if s := m.get(id); s.NotificationStatus != ap.NotificationError {
		t.Fatalf("status %s", s.NotificationStatus)
	}
	m.proc.terminate(t)
}

// A crash right after the Submit commit: exactly one burst after the restart.
func TestRestartAfterSubmitCommit(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.start(fault("notify.before-burst"))
	m.ready()
	data := m.encode(m.fixture("request-submit-write.json", 1))
	conn, err := net.Dial("unix", m.socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(append(data, '\n'))
	m.crashed()
	conn.Close()
	id := st.ID(1)
	if rec := m.record(id); len(rec.Payload.Bursts) != 0 {
		t.Fatalf("burst before the cut: %+v", rec.Payload.Bursts)
	}
	m.restart()
	m.delivered(id)
	rec := m.record(id)
	sent := forRecord(m.bot.snapshot(), id)
	if len(rec.Payload.Bursts) != 1 || count(sent, isCard) != 1 || count(sent, isPart) != len(rec.Payload.Bursts[0].PartMsgIDs) {
		t.Fatalf("bursts %+v sends %+v", rec.Payload.Bursts, sent)
	}
	m.proc.terminate(t)
}

// Telegram redelivery from offset 0, and a vote committed before a crash
// that lost its callback answer.
func TestRestartTelegramRedelivery(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	a, b, c := m.submit(1), m.submit(2), m.submit(3)
	cardA, editA := m.delivered(a)
	cardB, editB := m.delivered(b)
	cardC, editC := m.delivered(c)
	m.bot.command("/renotify " + m.handle(c))
	m.waitRecord(c, "the replacement", func(r ap.R1) bool {
		return lastEntry(r).Kind == ap.CardReplacement && lastEntry(r).Outcome == ap.OutcomeSent
	})

	answered := m.hold(func(call botCall) bool { return call.method == "answerCallbackQuery" }, replyHang, nil)
	tapA := m.bot.tap(button(t, latest(cardA, editA), "v:d:"), cardA.id)
	m.waitRecord(a, "the committed vote", func(r ap.R1) bool { return r.Header.Decision != nil })
	receive(t, answered)
	m.kill()
	m.bot.setIntercept(nil)
	decided := m.record(a).Header.Decision

	tapB := m.bot.tap(button(t, latest(cardB, editB), "v:d:"), cardB.id)
	tapC := m.bot.tap(button(t, latest(cardC, editC), "v:d:"), cardC.id)
	m.restart()
	eventually(t, 10*time.Second, "the redelivered tap's answer", func() bool { return len(m.bot.answers(tapA)) == 2 })
	if answers := m.bot.answers(tapA); answers[1] != "denied" {
		t.Fatalf("redelivered applied tap: %q", answers)
	}
	if rec := m.record(a); !reflect.DeepEqual(rec.Header.Decision, decided) {
		t.Fatalf("redelivered tap changed the decision: %+v", rec.Header.Decision)
	}
	if answer := m.answered(tapB); answer != "denied" {
		t.Fatalf("downtime tap: %q", answer)
	}
	if answer := m.answered(tapC); answer != "card updated — tap again" {
		t.Fatalf("retired card tap: %q", answer)
	}
	if rec := m.record(c); rec.Header.Decision != nil {
		t.Fatal("retired card decided")
	}
	decidedB := m.record(b).Header.Decision
	if decidedB == nil || decidedB.Status != ap.ApprovalDenied {
		t.Fatalf("downtime tap decision %+v", decidedB)
	}
	again := m.bot.tap(button(t, latest(cardB, editB), "v:d:"), cardB.id)
	if answer := m.answered(again); answer != "denied" {
		t.Fatalf("repeated tap: %q", answer)
	}
	if rec := m.record(b); !reflect.DeepEqual(rec.Header.Decision, decidedB) {
		t.Fatal("repeated tap counted twice")
	}
	m.proc.terminate(t)
}

// SIGTERM while pending and idle leaves the record unchanged across the
// restart; a standing grant is dead after any restart.
func TestSIGTERMPendingIdleAndGrantRestart(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	id := m.submit(1)
	m.delivered(id)
	idle := m.settled(id)
	m.proc.terminate(t)
	if !bytes.Equal(m.raw(id), idle) {
		t.Fatal("SIGTERM changed the idle record")
	}
	m.restart()
	if !bytes.Equal(m.settled(id), idle) {
		t.Fatal("restart changed the idle record")
	}
	if s := m.get(id); s.ApprovalStatus != ap.ApprovalPending || s.NotificationStatus != ap.NotificationSent {
		t.Fatalf("after restart %+v", s)
	}

	grant := m.submitGrant(2)
	card, edit := m.delivered(grant)
	if answer := m.answered(m.bot.tap(button(t, latest(card, edit), "v:a:"), card.id)); answer != "approved" {
		t.Fatalf("grant approval: %q", answer)
	}
	covered := m.submitCommands(3, "systemctl restart worker")
	if s := m.get(covered); s.ApprovalStatus != ap.ApprovalApproved {
		t.Fatalf("live grant did not cover: %+v", s)
	}
	m.proc.terminate(t)
	m.restart()
	after := m.submitCommands(4, "systemctl restart worker")
	if s := m.get(after); s.ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("grant survived the restart: %+v", s)
	}
	m.proc.terminate(t)
}

func isStatusEdit(call botCall) bool {
	return call.method == "editMessageText" && strings.HasPrefix(call.form.Get("text"), "Approval: ")
}

// effects lists every Bot API call except polling.
func effects(calls []botCall) []botCall {
	var out []botCall
	for _, call := range calls {
		if call.method != "getUpdates" {
			out = append(out, call)
		}
	}
	return out
}

var longCommands = []string{"echo " + strings.Repeat("a", 3400), "echo " + strings.Repeat("b", 3400), "echo " + strings.Repeat("c", 3400)}

// SIGTERM is SA-8's owner stop during each kind of notification call: the
// process exits 0, nothing commits after the latch, and no call follows.
func TestSIGTERMDuringNotificationCall(t *testing.T) {
	type stopCase struct {
		name  string
		match func(*matrix, string) func(botCall) bool
		reply botReply
	}
	part := func(index int) func(*matrix, string) func(botCall) bool {
		return func(m *matrix, _ string) func(botCall) bool {
			seen := 0
			return func(call botCall) bool {
				if !isPart(call) {
					return false
				}
				seen++
				return seen == index
			}
		}
	}
	matchAll := func(match func(botCall) bool) func(*matrix, string) func(botCall) bool {
		return func(*matrix, string) func(botCall) bool { return match }
	}
	var cases []stopCase
	for _, reply := range []botReply{replyReset, replyHang} {
		mode := map[botReply]string{replyReset: "reset", replyHang: "applied_dropped"}[reply]
		cases = append(cases,
			stopCase{"part2/" + mode, part(2), reply},
			stopCase{"card/" + mode, matchAll(isCard), reply},
			stopCase{"assist_edit/" + mode, matchAll(isCardEdit), reply},
			stopCase{"status_edit/" + mode, matchAll(isStatusEdit), reply},
		)
	}
	cases = append(cases, stopCase{"part2_429_wait", part(2), reply429})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind := strings.Split(tc.name, "/")[0]
			m := newMatrix(t, matrixOptions{explainer: kind == "assist_edit"})
			m.restart()
			release := make(chan struct{})
			if tc.reply == reply429 {
				release = nil
			}
			held := m.hold(tc.match(m, ""), tc.reply, release)
			var id string
			switch kind {
			case "status_edit":
				id = m.submit(1)
				card, edit := m.delivered(id)
				m.bot.tap(button(t, latest(card, edit), "v:d:"), card.id)
			case "assist_edit":
				id = m.submit(1)
			default:
				id = m.submitCommands(1, longCommands...)
			}
			heldCall := receive(t, held)
			if tc.reply == reply429 {
				time.Sleep(200 * time.Millisecond) // the client is now in its retry wait
			}
			committed := m.settled(id)
			calls := effects(m.bot.snapshot())
			if err := m.proc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			stopped := time.Now()
			if release != nil {
				time.AfterFunc(200*time.Millisecond, func() { close(release) })
			}
			if code := m.proc.exitCode(t); code != 0 {
				t.Fatalf("SIGTERM exit %d; stderr:\n%s", code, m.proc.stderr.String())
			}
			if took := time.Since(stopped); took > 10*time.Second {
				t.Fatalf("stop took %v", took)
			}
			if !bytes.Equal(m.raw(id), committed) {
				t.Fatalf("a commit followed the latch:\nbefore %s\nafter  %s", committed, m.raw(id))
			}
			if after := effects(m.bot.snapshot()); len(after) != len(calls) {
				t.Fatalf("calls after the held one: %+v", after[len(calls):])
			}
			if count(calls, isIncomplete) != 0 {
				t.Fatal("INCOMPLETE edit before the stop")
			}
			rec := m.record(id)
			if kind == "status_edit" {
				if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalDenied || len(rec.Payload.StatusEdits) != 0 {
					t.Fatalf("decision %+v status edits %+v", rec.Header.Decision, rec.Payload.StatusEdits)
				}
			} else if rec.Header.Decision != nil {
				t.Fatalf("decision slot filled: %+v", rec.Header.Decision)
			}
			m.bot.setIntercept(nil)

			before := len(effects(m.bot.snapshot()))
			m.restart()
			switch kind {
			case "assist_edit":
				rec := m.waitRecord(id, "the fresh edit", func(r ap.R1) bool { e := lastEntry(r); return e.Kind == ap.CardEdit && e.Confirmed })
				m.settled(id)
				if n := len(rec.Payload.CardEntries); n != 3 || !rec.Payload.CardEntries[1].Retired {
					t.Fatalf("supersession %+v", rec.Payload.CardEntries)
				}
				if edits := count(effects(m.bot.snapshot())[before:], isCardEdit); edits != 1 {
					t.Fatalf("%d edits after restart", edits)
				}
			case "status_edit":
				m.waitRecord(id, "the status edit", func(r ap.R1) bool { return len(r.Payload.StatusEdits) == 1 })
				m.settled(id)
				if edits := count(effects(m.bot.snapshot())[before:], isStatusEdit); edits != 1 {
					t.Fatalf("%d status edits after restart", edits)
				}
			default:
				m.quiet(id, time.Second)
				if s := m.get(id); s.NotificationStatus != ap.NotificationUncertain || s.ApprovalStatus != ap.ApprovalPending {
					t.Fatalf("after restart %+v", s)
				}
				hadCard := len(m.record(id).Payload.CardEntries) != 0
				if kind == "card" && tc.reply == replyHang {
					if answer := m.answered(m.bot.tap(button(t, heldCall, "v:d:"), heldCall.id)); answer != lifecycle.LegacyTapRefused {
						t.Fatalf("tap on the dropped-response card: %q", answer)
					}
				}
				before = len(forRecord(m.bot.snapshot(), id))
				m.bot.command("/renotify " + m.handle(id))
				rec := m.waitRecord(id, "the renotified card", func(r ap.R1) bool { return r.Header.RenotifyGen == 1 && lastEntry(r).Outcome == ap.OutcomeSent })
				want := ap.CardFirst
				if hadCard {
					want = ap.CardReplacement
				}
				m.settled(id)
				sent := forRecord(m.bot.snapshot(), id)[before:]
				parts := len(rec.Payload.Bursts[len(rec.Payload.Bursts)-1].PartMsgIDs)
				if lastEntry(rec).Kind != want || count(sent, isCard) != 1 || count(sent, isPart) != parts || parts < 3 {
					t.Fatalf("renotify: kind %s sends %d parts %d cards", lastEntry(rec).Kind, count(sent, isPart), count(sent, isCard))
				}
				card := lastCard(t, sent)
				if answer := m.answered(m.bot.tap(button(t, card, "v:a:"), card.id)); answer != "approved" {
					t.Fatalf("approve after renotify: %q", answer)
				}
			}
			m.proc.terminate(t)
		})
	}
}

// The contrast: a connection reset on part 2 with no SIGTERM gives error with
// INCOMPLETE edits.
func TestRunningPartResetIsError(t *testing.T) {
	m := newMatrix(t, matrixOptions{})
	m.restart()
	seen := 0
	m.hold(func(call botCall) bool {
		if isPart(call) {
			seen++
		}
		return isPart(call) && seen == 2
	}, replyReset, nil)
	id := m.submitCommands(1, longCommands...)
	rec := m.waitRecord(id, "the error decision", func(r ap.R1) bool { return r.Header.Decision != nil })
	if rec.Header.Decision.Status != ap.ApprovalError {
		t.Fatalf("decision %+v", rec.Header.Decision)
	}
	eventually(t, 10*time.Second, "INCOMPLETE edits", func() bool { return count(m.bot.snapshot(), isIncomplete) == 1 })
	m.proc.terminate(t)
}
