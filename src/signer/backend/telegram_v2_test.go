package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	ar "github.com/karthikeyan5/sshgate/src/approvalreview"
)

type approvalAPICall struct {
	method string
	form   url.Values
}
type approvalAPI struct {
	mu    sync.Mutex
	calls []approvalAPICall
	hook  func(http.ResponseWriter, *http.Request, int) bool
}

const approvalTestToken = "123456789:AA_DummyTokenForTests-0123456789"

func newApprovalAPI(t *testing.T) (*TelegramBackend, *approvalAPI) {
	t.Helper()
	api := &approvalAPI{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getMe") {
			fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"test"}}`)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		api.mu.Lock()
		api.calls = append(api.calls, approvalAPICall{method, r.Form})
		number := len(api.calls)
		hook := api.hook
		api.mu.Unlock()
		if hook != nil && hook(w, r, number) {
			return
		}
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"chat":{"id":42,"type":"private"}}}`, number)
	}))
	t.Cleanup(server.Close)
	chat := &MemChatStore{}
	_ = chat.Save(42)
	backend, err := NewTelegramBackend(TelegramOptions{BotToken: approvalTestToken, AllowedUserID: 42, ChatStore: chat, APIEndpoint: server.URL + "/bot%s/%s", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return backend, api
}
func (a *approvalAPI) snapshot() []approvalAPICall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approvalAPICall(nil), a.calls...)
}
func approvalDraft() ap.ApprovalDraft {
	draft := st.JobDraft(st.ID(1), ap.CoordinatorInProcessSync, st.T0, st.Write(strings.Repeat("x", 3500), 60), st.Write(strings.Repeat("y", 3500), 60))
	for i := range draft.CommandJob.Steps {
		step := &draft.CommandJob.Steps[i]
		step.Target.TrustedHostFingerprint = "SHA256:" + strings.Repeat("A", 43)
		step.RegistryEntryDigest = step.Target.Digest()
	}
	return draft
}

func notificationFixture(t *testing.T, revision int) lifecycle.Notification {
	t.Helper()
	draft := approvalDraft()
	plan := st.Freeze(draft, st.PrincipalA, st.T0, time.Hour)
	snapshot, err := ar.BuildSnapshot(plan, &[32]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := snapshot.Encode()
	if err != nil {
		t.Fatal(err)
	}
	state := ap.AssistPreparing
	if revision == 1 {
		state = ap.AssistUnavailable
	}
	handle := ap.CardHandleFor(ap.RecordKey(st.PrincipalA, st.ID(1)), 0)
	return lifecycle.Notification{Snapshot: raw, Handle: handle, PartsHandle: handle, Challenge: "0123456789abcdef", AssistState: state, Revision: revision}
}
func TestApprovalNotifierPartsAndCard(t *testing.T) {
	for _, revision := range []int{0, 1} {
		t.Run(fmt.Sprint(revision), func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			n := notificationFixture(t, revision)
			err := backend.Burst(context.Background(), func(session lifecycle.BurstSession) error {
				ids, err := session.SendParts(context.Background(), n)
				if err != nil {
					return err
				}
				n.PartMessageIDs = ids
				_, err = session.SendCard(context.Background(), n)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			calls := api.snapshot()
			if len(calls) < 3 {
				t.Fatal("not multipart")
			}
			view, err := approvalView(n)
			if err != nil {
				t.Fatal(err)
			}
			parts, err := ar.PackParts(view, n.Handle)
			if err != nil {
				t.Fatal(err)
			}
			for i, call := range calls {
				if call.method != "sendMessage" || !strings.Contains(call.form.Get("text"), "Card: "+n.Handle) {
					t.Fatalf("call %d: %+v", i, call)
				}
				if i < len(calls)-1 {
					if call.form.Get("text") != parts[i] || call.form.Get("reply_markup") != "" {
						t.Fatal("part differs from renderer or has buttons")
					}
				}
			}
			card := calls[len(calls)-1]
			want, err := ar.DecisionCard(view, n.Handle, len(parts))
			if err != nil {
				t.Fatal(err)
			}
			if card.form.Get("text") != want {
				t.Fatal("card differs from renderer")
			}
			keyboard := card.form.Get("reply_markup")
			if !strings.Contains(keyboard, "v:d:"+n.Handle+":"+n.Challenge) || strings.Contains(keyboard, "v:a:") != (revision == 1) {
				t.Fatal(keyboard)
			}
		})
	}
}
func TestApprovalNotifierRejectsBeforeIO(t *testing.T) {
	for _, bad := range []string{"snapshot", "handle", "revision", "group"} {
		t.Run(bad, func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			n := notificationFixture(t, 0)
			switch bad {
			case "snapshot":
				n.Snapshot = []byte(`{}`)
			case "handle":
				n.Handle = ""
			case "revision":
				n.Revision = 1
			case "group":
				_ = backend.chatStore.Save(-42)
			}
			err := backend.Burst(context.Background(), func(s lifecycle.BurstSession) error { _, err := s.SendParts(context.Background(), n); return err })
			if err == nil || len(api.snapshot()) != 0 {
				t.Fatal("bad notification reached API")
			}
		})
	}
}
func TestApprovalNotifierPartialAndCardFailure(t *testing.T) {
	for _, failure := range []string{"part_400", "part_transport", "card_transport"} {
		t.Run(failure, func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			n := notificationFixture(t, 1)
			api.hook = func(w http.ResponseWriter, r *http.Request, i int) bool {
				fail := i == 2
				if failure == "card_transport" {
					fail = r.Form.Get("reply_markup") != ""
				}
				if !fail {
					return false
				}
				if failure == "part_400" {
					fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"bad request"}`)
				} else {
					h := w.(http.Hijacker)
					conn, _, err := h.Hijack()
					if err != nil {
						t.Error(err)
					} else {
						conn.Close()
					}
				}
				return true
			}
			var ids []int64
			err := backend.Burst(context.Background(), func(s lifecycle.BurstSession) error {
				var err error
				ids, err = s.SendParts(context.Background(), n)
				if err != nil {
					return err
				}
				n.PartMessageIDs = ids
				_, err = s.SendCard(context.Background(), n)
				return err
			})
			if err == nil || len(ids) == 0 || strings.Contains(err.Error(), approvalTestToken) {
				t.Fatalf("ids=%v err=%v", ids, err)
			}
			if failure != "part_400" && !strings.Contains(err.Error(), "bot<REDACTED>") {
				t.Fatalf("transport error did not redact the bot URL: %v", err)
			}
			if failure != "card_transport" && len(ids) != 1 {
				t.Fatal(ids)
			}
		})
	}
}
func TestApprovalNotifierRetryBudgetAndCancellation(t *testing.T) {
	for _, mode := range []string{"retry", "cancel", "budget"} {
		t.Run(mode, func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			n := notificationFixture(t, 1)
			waiting := make(chan struct{})
			retryAfter := 30
			if mode == "budget" {
				retryAfter = 61
			}
			api.hook = func(w http.ResponseWriter, r *http.Request, i int) bool {
				if i != 2 {
					return false
				}
				fmt.Fprintf(w, `{"ok":false,"error_code":429,"description":"retry","parameters":{"retry_after":%d}}`, retryAfter)
				close(waiting)
				return true
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			// A short deadline exercises the same 60-second budget path without sleeping a minute.
			deadline := time.Now().Add(60 * time.Second)
			if mode == "budget" {
				deadline = time.Now().Add(100 * time.Millisecond)
			}
			started := time.Now()
			go func() {
				_, err := (&approvalBurst{backend: backend, deadline: deadline}).SendParts(ctx, n)
				done <- err
			}()
			select {
			case <-waiting:
			case <-time.After(5 * time.Second):
				t.Fatal("429 was not reached")
			}
			if mode == "cancel" {
				started = time.Now()
				cancel()
			}
			select {
			case err := <-done:
				switch mode {
				case "cancel":
					if !errors.Is(err, context.Canceled) || time.Since(started) > 100*time.Millisecond {
						t.Fatalf("cancellation %v %s", err, time.Since(started))
					}
				case "budget":
					if !errors.Is(err, errApprovalSendBudget) || errors.Is(err, context.DeadlineExceeded) {
						t.Fatal(err)
					}
				case "retry":
					if err != nil || time.Since(started) < 30*time.Second {
						t.Fatalf("retry %v %s", err, time.Since(started))
					}
				}
			case <-time.After(35 * time.Second):
				t.Fatal("retry did not stop")
			}
			if mode != "retry" && len(api.snapshot()) != 2 {
				t.Fatal("sent after failure")
			}
		})
	}
}
func TestApprovalNotifierEditOutcomes(t *testing.T) {
	for _, test := range []struct {
		name        string
		code        int
		description string
		want        lifecycle.EditOutcome
	}{{"success", 0, "", lifecycle.EditConfirmed}, {"unchanged", 400, "Bad Request: message is not modified", lifecycle.EditConfirmed}, {"missing", 400, "message to edit not found", lifecycle.EditFailed}, {"server", 500, "server failure", lifecycle.EditPossible}, {"rate", 429, "retry", lifecycle.EditPossible}} {
		t.Run(test.name, func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			n := notificationFixture(t, 1)
			n.PartMessageIDs = []int64{1, 2}
			api.hook = func(w http.ResponseWriter, r *http.Request, i int) bool {
				if test.code == 0 {
					return false
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": test.code, "description": test.description})
				return true
			}
			outcome, _ := backend.EditCard(context.Background(), 3, n)
			if outcome != test.want || len(api.snapshot()) != 1 {
				t.Fatalf("outcome %v", outcome)
			}
		})
	}
}
func TestApprovalNotifierBurstSerializesCommits(t *testing.T) {
	backend, api := newApprovalAPI(t)
	entered, release := make(chan struct{}), make(chan struct{})
	second := make(chan error, 1)
	first := make(chan error, 1)
	go func() {
		first <- backend.Burst(context.Background(), func(s lifecycle.BurstSession) error {
			n := notificationFixture(t, 1)
			ids, err := s.SendParts(context.Background(), n)
			if err != nil {
				return err
			}
			close(entered)
			<-release
			n.PartMessageIDs = ids
			_, err = s.SendCard(context.Background(), n)
			return err
		})
	}()
	<-entered
	before := len(api.snapshot())
	go func() {
		second <- backend.Burst(context.Background(), func(s lifecycle.BurstSession) error {
			n := notificationFixture(t, 1)
			_, err := s.SendParts(context.Background(), n)
			return err
		})
	}()
	// Policy uses this exact mutex, including the gap in which the actor commits.
	if backend.policyNotifyMu.TryLock() {
		backend.policyNotifyMu.Unlock()
		t.Error("burst released policy lock during commit")
	}
	if len(api.snapshot()) != before {
		t.Error("second burst interleaved")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	calls := api.snapshot()
	if calls[before].form.Get("reply_markup") == "" {
		t.Fatal("second parts preceded first card")
	}
}

type approvalTestFreezer struct{}

func (approvalTestFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	return st.Freeze(d, principal, now, time.Hour), nil
}

type approvalTestSnapshotter struct{}

func (approvalTestSnapshotter) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	s, err := ar.BuildSnapshot(p, &[32]byte{}, nil)
	if err != nil {
		return nil, "", err
	}
	raw, err := s.Encode()
	return raw, p.Rationale, err
}

func TestApprovalNotifierActorRendererAndTap(t *testing.T) {
	backend, api := newApprovalAPI(t)
	store := &lifecycle.MemStore{}
	clock := elapsedtest.NewFake(st.T0)
	engine, err := lifecycle.New(lifecycle.Config{Store: store, Clock: clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}, Notifier: backend})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	id := st.ID(1)
	key := ap.RecordKey(st.PrincipalA, id)
	_, err = engine.Submit(context.Background(), st.PrincipalA, approvalDraft())
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	api.hook = func(w http.ResponseWriter, r *http.Request, i int) bool {
		rec, err := store.Load(key)
		if err != nil {
			t.Error(err)
			return false
		}
		if len(rec.Payload.Bursts) != 1 {
			t.Error("I/O before BurstStart")
		}
		if r.Form.Get("reply_markup") != "" && (rec.Payload.Bursts[0].Outcome != ap.OutcomeSent || len(rec.Payload.CardEntries) != 1) {
			t.Error("card before BurstDone/CardStart")
		}
		return false
	}
	done := make(chan error, 1)
	go func() { done <- engine.Run(context.Background()) }()
	t.Cleanup(func() { engine.Close(); <-done })
	rec := waitApprovalRecord(t, store, key, func(r ap.R1) bool {
		return len(r.Payload.CardEntries) == 1 && r.Payload.CardEntries[0].Outcome == ap.OutcomeSent
	})
	calls := api.snapshot()
	card := calls[len(calls)-1]
	want := ap.CardHandleFor(key, 0)
	for _, call := range calls {
		if !strings.Contains(call.form.Get("text"), "Card: "+want) {
			t.Fatal("parts and card differ")
		}
	}
	var keyboard struct {
		Rows [][]struct {
			Data string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if err := json.Unmarshal([]byte(card.form.Get("reply_markup")), &keyboard); err != nil {
		t.Fatal(err)
	}
	data := keyboard.Rows[0][0].Data
	if !strings.HasPrefix(data, "v:a:"+want+":") {
		t.Fatal(data)
	}
	fields := strings.Split(data, ":")
	answer, err := engine.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: fields[2], Challenge: fields[3], MsgID: *rec.Payload.CardEntries[0].MsgID}})
	if err != nil || answer.Code != "" {
		t.Fatalf("tap: %+v %v", answer, err)
	}
	rec, err = store.Load(key)
	if err != nil || rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalApproved {
		t.Fatal("callback did not decide")
	}
}
func waitApprovalRecord(t *testing.T, store lifecycle.Store, key string, ready func(ap.R1) bool) ap.R1 {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		rec, err := store.Load(key)
		if err == nil && ready(rec) {
			return rec
		}
		select {
		case <-deadline:
			t.Fatal("record did not settle")
		case <-tick.C:
		}
	}
}

func TestApprovalNotifierActorLiveFailures(t *testing.T) {
	for _, failure := range []string{"part_400", "part_transport", "card_transport", "budget"} {
		t.Run(failure, func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			store := &lifecycle.MemStore{}
			clock := elapsedtest.NewFake(st.T0)
			engine, err := lifecycle.New(lifecycle.Config{Store: store, Clock: clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}, Notifier: backend})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			api.hook = func(w http.ResponseWriter, r *http.Request, i int) bool {
				fail := i == 2
				if failure == "card_transport" {
					fail = strings.Contains(r.Form.Get("text"), "DECISION CARD")
				}
				if !fail || !strings.HasSuffix(r.URL.Path, "/sendMessage") {
					return false
				}
				switch failure {
				case "part_400":
					fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"bad request"}`)
				case "budget":
					fmt.Fprint(w, `{"ok":false,"error_code":429,"description":"retry","parameters":{"retry_after":61}}`)
				default:
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
					} else {
						conn.Close()
					}
				}
				return true
			}
			id := st.ID(1)
			key := ap.RecordKey(st.PrincipalA, id)
			_, err = engine.Submit(context.Background(), st.PrincipalA, approvalDraft())
			if err != nil {
				t.Fatal(err)
			}
			clock.Advance(5 * time.Second)
			done := make(chan error, 1)
			go func() { done <- engine.Run(context.Background()) }()
			defer func() { engine.Close(); <-done }()
			deadline := time.After(65 * time.Second)
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				rec, err := store.Load(key)
				if err != nil {
					t.Fatal(err)
				}
				if rec.Header.Decision != nil {
					if rec.Header.Decision.Status != ap.ApprovalError {
						t.Fatal(rec.Header.Decision)
					}
					incomplete := 0
					for _, call := range api.snapshot() {
						if call.form.Get("text") == "INCOMPLETE — NOT APPROVABLE" {
							incomplete++
						}
					}
					if incomplete == len(rec.Payload.Bursts[0].PartMsgIDs) && incomplete > 0 {
						break
					}
				}
				select {
				case <-deadline:
					t.Fatal("live failure did not error and mark delivered parts")
				case <-tick.C:
				}
			}
		})
	}
}

func TestApprovalReplacementNote(t *testing.T) {
	n := notificationFixture(t, 1)
	text, _, err := approvalCard(n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "Review parts were sent under card") {
		t.Fatal("first card has a replacement note")
	}
	replacement := "abcdefghijkl"
	n.Handle, n.PartMessageIDs = replacement, []int64{1, 2}
	text, _, err = approvalCard(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Review parts were sent under card "+n.PartsHandle) || !strings.Contains(text, "Card: "+replacement) {
		t.Fatal("replacement identities missing")
	}
	if len(text) >= ar.PartBytes {
		t.Fatal("note exceeded card budget")
	}
	n.PartsHandle = "invalid"
	if _, _, err = approvalCard(n); err == nil {
		t.Fatal("invalid original handle accepted")
	}
}

func TestApprovalReplacementDelivery(t *testing.T) {
	backend, api := newApprovalAPI(t)
	n := notificationFixture(t, 1)
	n.Handle, n.PartMessageIDs = "abcdefghijkl", []int64{1, 2}
	if outcome, err := backend.EditCard(context.Background(), 3, n); err != nil || outcome != lifecycle.EditConfirmed {
		t.Fatalf("edit: %v, %v", outcome, err)
	}
	n.Handle = "mnopqrstuvwx"
	if err := backend.Burst(context.Background(), func(session lifecycle.BurstSession) error {
		_, err := session.SendCard(context.Background(), n)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	calls := api.snapshot()
	if len(calls) != 2 || calls[0].method != "editMessageText" || calls[1].method != "sendMessage" {
		t.Fatalf("unexpected delivery calls: %+v", calls)
	}
	for i, handle := range []string{"abcdefghijkl", "mnopqrstuvwx"} {
		text := calls[i].form.Get("text")
		if !strings.Contains(text, "Card: "+handle) || !strings.Contains(text, "Review parts were sent under card "+n.PartsHandle) {
			t.Fatalf("delivery %d lost card identities: %s", i, text)
		}
	}
}

func TestApprovalNotExecutableStatusText(t *testing.T) {
	for _, reason := range []string{ap.MintReasonGrantNotLive, ap.MintReasonStaleTransferKey, ap.MintReasonReservedVerb, ap.MintReasonClockSkew, ap.MintReasonSigningFailed} {
		text, err := approvalStatusText(lifecycle.StatusDisplay{State: "not_executable", Reason: reason})
		if err != nil || !strings.Contains(text, "signer-derived: not_executable: "+reason) {
			t.Fatalf("reason %q: %q, %v", reason, text, err)
		}
		if reason == ap.MintReasonGrantNotLive && !strings.Contains(text, "approved by a standing grant that was revoked, replaced or lost before execution") {
			t.Fatal("grant failure explanation missing")
		}
	}
	for _, reason := range []string{"", "unknown", ap.MintReasonWindowClosed} {
		if _, err := approvalStatusText(lifecycle.StatusDisplay{State: "not_executable", Reason: reason}); err == nil {
			t.Fatalf("invalid reason %q accepted", reason)
		}
	}
}

func TestApprovalNotifierStatusReasonActorToAPI(t *testing.T) {
	for _, reason := range []string{ap.MintReasonGrantNotLive, ap.MintReasonStaleTransferKey, ap.MintReasonReservedVerb, ap.MintReasonClockSkew, ap.MintReasonSigningFailed} {
		t.Run(reason, func(t *testing.T) {
			backend, api := newApprovalAPI(t)
			submit := st.SubmitOf(approvalDraft(), st.PrincipalA, st.T0, time.Hour)
			submit.ReviewSnapshot = notificationFixture(t, 1).Snapshot
			handle, challenge := "abcdefghijkl", "0123456789abcdef"
			var rec *ap.R1
			for _, cmd := range []ap.Command{
				submit,
				ap.AssistDone{Unavailable: "test"},
				ap.BurstStart{},
				ap.BurstDone{PartMsgIDs: []int64{1, 2}},
				ap.CardStart{Handle: handle, ChalHash: ap.ChallengeHash(challenge)},
				ap.CardDone{Handle: handle, MsgID: 3},
				ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags,
					Card: &ap.CardTap{Handle: handle, Challenge: challenge, MsgID: 3}},
			} {
				next, answer := ap.Apply(rec, cmd, ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
				if answer.Code != "" || !answer.Changed {
					t.Fatalf("fixture %T: %+v", cmd, answer)
				}
				rec = &next
			}
			// Recover a committed materialization failure with an already delivered card.
			rec.Header.Mint = &ap.MintSlot{State: ap.MintError, Reason: reason}
			store := &lifecycle.MemStore{}
			key := ap.RecordKey(st.PrincipalA, st.ID(1))
			if err := store.Commit(key, *rec); err != nil {
				t.Fatal(err)
			}
			engine, err := lifecycle.New(lifecycle.Config{Store: store, Clock: elapsedtest.NewFake(st.T0), Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}, Notifier: backend})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- engine.Run(context.Background()) }()
			t.Cleanup(func() { engine.Close(); <-done })
			after := waitApprovalRecord(t, store, key, func(r ap.R1) bool { return len(r.Payload.StatusEdits) == 1 })
			calls := api.snapshot()
			if len(calls) != 1 || calls[0].method != "editMessageText" || calls[0].form.Get("message_id") != "3" {
				t.Fatalf("status delivery: %+v", calls)
			}
			text := calls[0].form.Get("text")
			if !strings.Contains(text, "signer-derived: not_executable: "+reason) {
				t.Fatalf("lost reason: %q", text)
			}
			if reason == ap.MintReasonGrantNotLive && !strings.Contains(text, "approved by a standing grant that was revoked, replaced or lost before execution") {
				t.Fatal("grant explanation missing from API text")
			}
			if after.Payload.StatusEdits[0].State != "not_executable" {
				t.Fatal("changed durable status-edit key")
			}
		})
	}
}
