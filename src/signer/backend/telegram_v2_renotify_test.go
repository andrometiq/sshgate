package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func renotifyHandle(principal string) string {
	return ap.RecordHandle(ap.RecordKey(principal, st.ID(1)))
}

// replies drains queued sends and returns the texts sent without a keyboard.
func (f *callbackFixture) replies() []string {
	for len(f.backend.notifications) > 0 {
		(<-f.backend.notifications)()
	}
	var texts []string
	for _, c := range f.api.snapshot() {
		if c.method == "sendMessage" && c.form.Get("reply_markup") == "" && !strings.HasPrefix(c.form.Get("text"), "🔐 SSHGate approval review") {
			texts = append(texts, c.form.Get("text"))
		}
	}
	return texts
}

func sentCards(calls []approvalAPICall) (parts, cards int) {
	for _, c := range calls {
		switch {
		case c.method != "sendMessage":
		case c.form.Get("reply_markup") != "":
			cards++
		case strings.HasPrefix(c.form.Get("text"), "🔐 SSHGate approval review"):
			parts++
		}
	}
	return parts, cards
}

func TestRenotifyCommandRetiresCardAndSendsReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		a := &commandAudit{}
		f.backend.CommandAudit = a
		f.start(t)
		old := f.card(t)
		if rec := f.record(t); len(rec.Payload.CardEntries) != 1 || rec.Payload.CardEntries[0].Outcome != ap.OutcomeSent {
			t.Fatalf("no delivered card: %+v", rec.Payload.CardEntries)
		}
		f.api.reset()
		f.backend.dispatch(commandUpdate(10, "/renotify "+renotifyHandle(st.PrincipalA)))
		synctest.Wait()
		rec := f.record(t)
		entries := rec.Payload.CardEntries
		if rec.Header.RenotifyGen != 1 || len(entries) != 2 || !entries[0].Retired || entries[1].Kind != ap.CardReplacement || entries[1].Outcome != ap.OutcomeSent {
			t.Fatalf("renotify gen=%d entries=%+v", rec.Header.RenotifyGen, entries)
		}
		calls := f.api.snapshot()
		if parts, cards := sentCards(calls); parts == 0 || cards != 1 || calls[len(calls)-1].form.Get("reply_markup") == "" {
			t.Fatalf("new burst: parts=%d cards=%d calls=%+v", parts, cards, calls)
		}
		if replies := f.replies(); !reflect.DeepEqual(replies, []string{"re-notify accepted: a new review and card follow"}) {
			t.Fatalf("replies %q", replies)
		}
		if len(a.events) != 0 {
			t.Fatalf("accepted renotify audited as a refusal: %+v", a.events)
		}
		f.api.reset()
		f.backend.handleCallback(old)
		synctest.Wait()
		if answers := f.answers(); len(answers) != 1 || answers[0] != "card updated — tap again" {
			t.Fatalf("retired card tap: %q", answers)
		}
		if after := f.record(t); after.Header.Decision != nil {
			t.Fatal("retired card decided the record")
		}
	})
}

func TestRenotifyCommandGateChangesNothingAndAudits(t *testing.T) {
	for _, tt := range []struct {
		name, reason string
		change       func(*TelegramBackend, *tgbotapi.Message)
	}{
		{"wrong user", "wrong_user", func(_ *TelegramBackend, m *tgbotapi.Message) { m.From.ID = 99 }},
		{"group", "not_private", func(_ *TelegramBackend, m *tgbotapi.Message) { m.Chat.Type = "group"; m.Chat.ID = -42 }},
		{"forwarded", "forwarded", func(_ *TelegramBackend, m *tgbotapi.Message) { m.ForwardFrom = &tgbotapi.User{ID: 42} }},
		{"redelivered", "redelivered", func(b *TelegramBackend, _ *tgbotapi.Message) { b.commandDrain = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				a := &commandAudit{}
				f.backend.CommandAudit = a
				f.start(t)
				before := f.record(t)
				f.api.reset()
				u := commandUpdate(10, "/renotify "+renotifyHandle(st.PrincipalA))
				tt.change(f.backend, u.Message)
				f.backend.dispatch(u)
				synctest.Wait()
				if after := f.record(t); !reflect.DeepEqual(after, before) {
					t.Fatalf("gate refusal changed the record:\n%+v\n%+v", before.Header, after.Header)
				}
				f.clock.Advance(commandRefusalInterval)
				f.backend.flushCommandRefusals()
				transition := "command_refused{" + tt.reason + "}"
				if tt.reason == "wrong_user" || tt.reason == "not_private" {
					transition = "command_refused{count=1,wrong_user=" + map[bool]string{true: "1", false: "0"}[tt.reason == "wrong_user"] + ",not_private=" + map[bool]string{true: "1", false: "0"}[tt.reason == "not_private"] + "}"
				}
				if len(a.events) != 1 || a.events[0].Approval == nil || a.events[0].Approval.Transition != transition {
					t.Fatalf("audit %+v, want %s", a.events, transition)
				}
				for _, c := range f.api.snapshot() {
					if c.method == "sendMessage" && c.form.Get("chat_id") != "42" {
						t.Fatalf("reply escaped the linked DM: %+v", c)
					}
				}
			})
		})
	}
}

func TestRenotifyCommandAmbiguousRequestID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		a := &commandAudit{}
		f.backend.CommandAudit = a
		if _, err := f.engine.Submit(context.Background(), st.PrincipalB, approvalDraft()); err != nil {
			t.Fatal(err)
		}
		f.start(t)
		keyB := ap.RecordKey(st.PrincipalB, st.ID(1))
		loadB := func() ap.R1 {
			rec, err := f.store.Load(keyB)
			if err != nil {
				t.Fatal(err)
			}
			return rec
		}
		beforeA, beforeB := f.record(t), loadB()
		f.api.reset()
		f.backend.dispatch(commandUpdate(10, "/renotify "+st.ID(1)))
		synctest.Wait()
		if !reflect.DeepEqual(f.record(t), beforeA) || !reflect.DeepEqual(loadB(), beforeB) {
			t.Fatal("ambiguous renotify changed a record")
		}
		if replies := f.replies(); !reflect.DeepEqual(replies, []string{"ambiguous id — use the handle from /pending"}) {
			t.Fatalf("replies %q", replies)
		}
		if len(a.events) != 1 || a.events[0].Status != "approval-command_refused{ambiguous_id}" || a.events[0].Approval.Transition != "command_refused{ambiguous_id}" || a.events[0].Approval.Replay || strings.Contains(a.events[0].Status, st.ID(1)) {
			t.Fatalf("audit %+v", a.events)
		}
		f.backend.dispatch(commandUpdate(11, "/renotify "+renotifyHandle(st.PrincipalB)))
		synctest.Wait()
		if rec := loadB(); rec.Header.RenotifyGen != 1 {
			t.Fatalf("handle renotify gen=%d", rec.Header.RenotifyGen)
		}
		if !reflect.DeepEqual(f.record(t), beforeA) {
			t.Fatal("handle renotify touched the other principal's record")
		}
	})
}

func TestRenotifyCommandWhileRecovering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		a := &commandAudit{}
		f.backend.CommandAudit = a
		f.start(t)
		before := f.record(t)
		f.api.reset()
		f.runtime.currentErr = &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
		for i, arg := range []string{renotifyHandle(st.PrincipalA), st.ID(1), st.ID(9)} {
			f.backend.dispatch(commandUpdate(10+i, "/renotify "+arg))
		}
		synctest.Wait()
		if !reflect.DeepEqual(f.record(t), before) {
			t.Fatal("renotify while recovering changed the record")
		}
		want := []string{"signer recovering — try again", "signer recovering — try again", "signer recovering — try again"}
		if replies := f.replies(); !reflect.DeepEqual(replies, want) {
			t.Fatalf("replies %q", replies)
		}
		if len(a.events) != 3 || a.events[2].Approval.Transition != "renotify_refused{recovering}" {
			t.Fatalf("audit %+v", a.events)
		}
	})
}

// E64 without a clock: the update_id cut, not the wall clock, drops the
// redelivered /renotify; a later one on an uncertain record is accepted.
func TestRenotifyCommandUncertainRecordClockCorrection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		a := &commandAudit{}
		f.backend.CommandAudit = a
		f.api.hook = func(r *http.Request, i int) (string, error) {
			if strings.HasSuffix(r.URL.Path, "sendMessage") {
				<-r.Context().Done() // the stop cancels the burst's first part
				return "", r.Context().Err()
			}
			return `{"ok":true,"result":{"message_id":1}}`, nil
		}
		f.start(t)
		f.engine.Close()
		if rec := f.record(t); len(rec.Payload.Bursts) != 1 || rec.Payload.Bursts[0].Outcome != "" {
			t.Fatalf("no interrupted burst: %+v", rec.Payload.Bursts)
		}
		recovered, err := lc.New(lc.Config{Store: f.fault, Clock: f.clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}, Notifier: f.backend})
		if err != nil {
			t.Fatal(err)
		}
		f.runtime.engine = recovered
		done := make(chan error, 1)
		go func() { done <- recovered.Run(context.Background()) }()
		t.Cleanup(func() { recovered.Close(); <-done })
		f.api.reset()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.backend.runDone = make(chan struct{})
		defer close(f.backend.runDone)
		const skew = 10 * time.Minute
		f.clock.StepWall(skew)
		batch := 0
		command := "/renotify " + renotifyHandle(st.PrincipalA)
		f.api.hook = func(r *http.Request, i int) (string, error) {
			if !strings.HasSuffix(r.URL.Path, "getUpdates") {
				return `{"ok":true,"result":{"message_id":` + strconv.Itoa(i) + `}}`, nil
			}
			batch++
			switch batch {
			case 1:
			case 2:
				if gen := f.record(t).Header.RenotifyGen; gen != 0 || len(f.record(t).Payload.Bursts) != 1 {
					t.Errorf("redelivered renotify was applied: gen=%d", gen)
				}
				f.clock.StepWall(-skew)
			default:
				cancel()
				synctest.Wait()
				return `{"ok":true,"result":[]}`, nil
			}
			u := commandUpdate(batch, command)
			u.Message.MessageID = batch
			body, err := json.Marshal(struct {
				OK     bool              `json:"ok"`
				Result []tgbotapi.Update `json:"result"`
			}{true, []tgbotapi.Update{u}})
			return string(body), err
		}
		f.backend.pollLoop(ctx)
		synctest.Wait()
		rec := f.record(t)
		if rec.Header.RenotifyGen != 1 || len(rec.Payload.Bursts) != 2 || rec.Payload.Bursts[1].Gen != 1 || rec.Payload.Bursts[1].Outcome != ap.OutcomeSent {
			t.Fatalf("post-drain renotify: gen=%d bursts=%+v", rec.Header.RenotifyGen, rec.Payload.Bursts)
		}
		if len(a.events) != 1 || a.events[0].Status != "approval-command_refused{redelivered}" {
			t.Fatalf("audit %+v", a.events)
		}
	})
}
