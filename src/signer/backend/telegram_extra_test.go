package backend_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// failingSaveStore is a ChatStore whose Save always errors. Load behaves
// like MemChatStore (always "no chat_id yet") so /start's Save failure
// path is exercised in isolation. ~5-line fixture noted in the brief.
type failingSaveStore struct{}

func (failingSaveStore) Load() (int64, bool, error) { return 0, false, nil }

func (failingSaveStore) Save(int64) error { return errors.New("disk full") }

// TestTelegram_StartSaveFailsStillReplies asserts that when ChatStore.Save
// fails during /start, the operator STILL gets the "Linked" confirmation
// (so the bot isn't silently dead) and the chat_id is NOT persisted —
// the failure surfaces later on the next approval request rather than
// here. handleStart logs the save error and replies anyway.
func TestTelegram_StartSaveFailsStillReplies(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := failingSaveStore{}
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	fake.pushMessage(allowedUserID, allowedChatID, "/start")

	// The "Linked" confirmation should still fly out despite Save failing.
	waitFor(t, time.Second, func() bool { return len(fake.sentSnapshot()) >= 1 })
	sent := fake.sentSnapshot()[0]
	if sent.ChatID != allowedChatID {
		t.Errorf("confirmation ChatID = %d; want %d", sent.ChatID, allowedChatID)
	}
	if !strings.Contains(strings.ToLower(sent.Text), "linked") {
		t.Errorf("confirmation text = %q; want a 'Linked' message even though Save failed", sent.Text)
	}

	// chat_id must NOT be persisted (Save errored).
	if _, ok, _ := store.Load(); ok {
		t.Error("store reports a captured chat_id; Save failed so it must remain absent")
	}
	// No panic — this is a logged-and-continue path, not a crash.
	if tb.PanicsTotal() != 0 {
		t.Errorf("PanicsTotal = %d; want 0 (Save failure is logged, not a panic)", tb.PanicsTotal())
	}
}

// TestTelegram_SendMessage5xxNoPendingEntry asserts that when the
// sendMessage call fails (upstream 5xx) inside Request, Request returns a
// "telegram send" error and registers NO pending entry — so there's no
// leaked timer/ctx-watcher goroutine and no phantom request. We verify
// "no pending entry" behaviourally: a later callback for that RequestID
// is answered "expired or already resolved" (the unknown-reqid path),
// proving nothing was registered. goleak (TestMain) catches a leaked
// goroutine if one were spawned.
func TestTelegram_SendMessage5xxNoPendingEntry(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	fake.mu.Lock()
	fake.sendMessageFailCode = 502 // Bad Gateway
	fake.mu.Unlock()
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	ch, err := tb.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_send5xx",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo hi", TTLSec: 60}},
	})
	if err == nil {
		t.Fatal("Request returned nil err on sendMessage 5xx; want a 'telegram send' error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "telegram send") {
		t.Errorf("err = %v; want it to mention 'telegram send'", err)
	}
	if ch != nil {
		t.Errorf("Request returned a non-nil channel alongside the error; contract is (nil, err)")
	}

	// Prove no pending entry leaked: a callback for that reqID hits the
	// unknown-reqid branch ("expired or already resolved").
	fake.pushCallback(allowedUserID, "karthi", "approve:r_send5xx", 1000, allowedChatID)
	waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 1 })
	ans := fake.callbackAnswersSnapshot()
	if !strings.Contains(strings.ToLower(ans[0].Text), "expired") {
		t.Errorf("callback answer = %q; want 'expired or already resolved' (no pending entry registered)", ans[0].Text)
	}
}

// TestTelegram_MalformedCallbackData asserts the parseCallbackData reject
// paths: "garbage" (no colon), "approve:" (empty reqID), and ":reqid"
// (empty action) all yield an "invalid request" answer with NO panic and
// NO resolution of any pending request. Callbacks come from the allowed
// user so we exercise the data-validation branch, not the auth branch.
func TestTelegram_MalformedCallbackData(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
	}{
		{"no_colon", "garbage"},
		{"empty_reqid", "approve:"},
		{"empty_action", ":reqid"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeTelegram(t)
			store := &backend.MemChatStore{}
			_ = store.Save(allowedChatID)
			tb := newTestBackend(t, fake, store, 5*time.Second)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := tb.Run(ctx); err != nil {
				t.Fatal(err)
			}

			fake.pushCallback(allowedUserID, "karthi", tc.data, 1000, allowedChatID)

			waitFor(t, time.Second, func() bool { return len(fake.callbackAnswersSnapshot()) >= 1 })
			ans := fake.callbackAnswersSnapshot()
			if !strings.Contains(strings.ToLower(ans[0].Text), "invalid request") {
				t.Errorf("callback answer = %q; want 'invalid request' for data %q", ans[0].Text, tc.data)
			}
			if tb.PanicsTotal() != 0 {
				t.Errorf("PanicsTotal = %d; want 0 (malformed data is rejected, not a crash)", tb.PanicsTotal())
			}
		})
	}
}

// TestTelegram_PoisonUpdatePanicsLoopSurvives pushes a /start update with
// nil Chat AND nil From. handleStart takes the unauthorized branch
// (From == nil) and dereferences m.Chat.ID → panic, which dispatch's
// recover catches: PanicsTotal increments and the poll loop survives.
// We prove survival by pushing a well-formed /start afterward and seeing
// it processed (chat_id captured).
func TestTelegram_PoisonUpdatePanicsLoopSurvives(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	// A /start command message with neither "from" nor "chat". The
	// bot_command entity makes IsCommand()+Command()=="start" true so
	// dispatch routes it to handleStart, which then dereferences the nil
	// Chat.
	poison := `{"message_id":1,"date":1,"text":"/start","entities":[{"type":"bot_command","offset":0,"length":6}]}`
	fake.pushRawMessage(poison)

	waitFor(t, 2*time.Second, func() bool { return tb.PanicsTotal() >= 1 })
	if tb.PanicsTotal() < 1 {
		t.Fatalf("PanicsTotal = %d; want >= 1 after poison update", tb.PanicsTotal())
	}

	// Loop survived: a valid /start is still processed.
	fake.pushMessage(allowedUserID, allowedChatID, "/start")
	waitFor(t, 2*time.Second, func() bool {
		_, ok, _ := store.Load()
		return ok
	})
	id, ok, _ := store.Load()
	if !ok || id != allowedChatID {
		t.Errorf("after poison, Load() = (%d, %v); want (%d, true) — poll loop should still be alive", id, ok, allowedChatID)
	}
}

// TestTelegram_StartNilFromNilChatRecovers is the targeted nil-Chat /
// nil-From variant from the brief: same mechanism as the poison test but
// asserted as a focused recover (no follow-up valid update). PanicsTotal
// increments and Run does not die.
func TestTelegram_StartNilFromNilChatRecovers(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	tb := newTestBackend(t, fake, &backend.MemChatStore{}, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	// nil From, nil Chat → handleStart panics on m.Chat.ID → recovered.
	fake.pushRawMessage(`{"message_id":9,"date":1,"text":"/start","entities":[{"type":"bot_command","offset":0,"length":6}]}`)

	waitFor(t, 2*time.Second, func() bool { return tb.PanicsTotal() >= 1 })

	// The recover must keep getUpdates being called (loop alive). Capture
	// the count, push a benign valid update, and confirm it advances.
	before := fake.getUpdatesCalled.Load()
	fake.pushMessage(allowedUserID, allowedChatID, "/start")
	waitFor(t, 2*time.Second, func() bool { return fake.getUpdatesCalled.Load() > before })
}

// TestTelegram_GetUpdates4xx5xxThenRecovers scripts a getUpdates failure
// sequence — 429 (4xx) → 500 (5xx) → success — and asserts the poll loop
// backs off, recovers, and goes on to process a real update. This
// exercises pollLoop's classifyAndLog + backoff branch end-to-end.
func TestTelegram_GetUpdates4xx5xxThenRecovers(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	fake.mu.Lock()
	fake.getUpdatesFailCodes = []int{429, 500} // 4xx then 5xx, then normal
	fake.mu.Unlock()
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	// Drop a valid /start in. The first two getUpdates calls fail (429,
	// 500); the loop backs off (100ms, 200ms) then recovers and on the
	// next success drains the update.
	fake.pushMessage(allowedUserID, allowedChatID, "/start")

	waitFor(t, 3*time.Second, func() bool {
		_, ok, _ := store.Load()
		return ok
	})
	id, ok, _ := store.Load()
	if !ok || id != allowedChatID {
		t.Errorf("Load() = (%d, %v); want (%d, true) after 4xx→5xx→success recovery", id, ok, allowedChatID)
	}
	// We scripted exactly two failures, so at least 3 getUpdates calls
	// occurred (2 failed + ≥1 success that drained the update).
	if got := fake.getUpdatesCalled.Load(); got < 3 {
		t.Errorf("getUpdatesCalled = %d; want >= 3 (2 scripted failures + recovery)", got)
	}
	if tb.PanicsTotal() != 0 {
		t.Errorf("PanicsTotal = %d; want 0 (API errors are not panics)", tb.PanicsTotal())
	}
}

// TestTelegram_ConcurrentRequestsResolvedOutOfOrder submits several
// concurrent approval requests and approves them in REVERSE submission
// order. Each request's channel must receive exactly its own Result —
// proving the pending map keys correctly and the per-request once guards
// resolution. Run under -race to catch any data race in the pending map
// or pendingState fields.
func TestTelegram_ConcurrentRequestsResolvedOutOfOrder(t *testing.T) {
	t.Parallel()
	fake := newFakeTelegram(t)
	store := &backend.MemChatStore{}
	_ = store.Save(allowedChatID)
	tb := newTestBackend(t, fake, store, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tb.Run(ctx); err != nil {
		t.Fatal(err)
	}

	const n = 3
	reqIDs := make([]string, n)
	chans := make([]<-chan signerkit.Result, n)
	for i := 0; i < n; i++ {
		reqIDs[i] = fmt.Sprintf("r_conc_%d", i)
		ch, err := tb.Request(ctx, signerkit.ApprovalRequest{
			RequestID: reqIDs[i],
			Commands:  []signerkit.CommandReq{{Server: "x", Cmd: fmt.Sprintf("echo %d", i), TTLSec: 60}},
		})
		if err != nil {
			t.Fatalf("Request[%d]: %v", i, err)
		}
		chans[i] = ch
	}

	// All n approval messages should have been sent.
	waitFor(t, 2*time.Second, func() bool { return len(fake.sentSnapshot()) == n })

	// Approve in reverse order: r_conc_2, r_conc_1, r_conc_0. The
	// message_id for each send is 1000+i (nextMessageID starts at 1000).
	for i := n - 1; i >= 0; i-- {
		fake.pushCallback(allowedUserID, "karthi", "approve:"+reqIDs[i], 1000+i, allowedChatID)
	}

	// Each channel must yield exactly one StatusApproved. We don't assert
	// ordering across channels — only that each gets its own resolution.
	for i := 0; i < n; i++ {
		select {
		case got, ok := <-chans[i]:
			if !ok {
				t.Fatalf("chan[%d] (%s) closed without a result", i, reqIDs[i])
			}
			if got.Status != signerkit.StatusApproved {
				t.Errorf("chan[%d] (%s) Status = %v; want Approved", i, reqIDs[i], got.Status)
			}
			if got.ApprovedBy != "@karthi" {
				t.Errorf("chan[%d] ApprovedBy = %q; want @karthi", i, got.ApprovedBy)
			}
			// The channel must be closed after exactly one Result.
			if second, stillOpen := <-chans[i]; stillOpen {
				t.Errorf("chan[%d] (%s) yielded a second Result %+v; want closed after one", i, reqIDs[i], second)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("chan[%d] (%s) did not resolve within 3s", i, reqIDs[i])
		}
	}
}
