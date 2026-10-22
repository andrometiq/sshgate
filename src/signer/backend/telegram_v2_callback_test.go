package backend

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	lt "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

type callbackRuntime struct {
	current    func() (*lc.Engine, error)
	currentErr error
	engine     *lc.Engine
	legacy     *lc.LegacyService
}

func (r *callbackRuntime) Current() (*lc.Engine, error) {
	if r.current != nil {
		return r.current()
	}
	if r.currentErr != nil {
		return nil, r.currentErr
	}
	return r.engine, nil
}
func (r *callbackRuntime) Legacy() *lc.LegacyService { return r.legacy }

type callbackAudit struct {
	mu     sync.Mutex
	events []ap.AuditMetadata
}

func (a *callbackAudit) WriteApproval(_ context.Context, event ap.AuditMetadata) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

type callbackFixture struct {
	fault   *lt.FaultStore
	audit   *callbackAudit
	backend *TelegramBackend
	api     *legacyBotAPI
	engine  *lc.Engine
	store   *lc.MemStore
	clock   *elapsedtest.Fake
	runtime *callbackRuntime
}

func newCallbackFixture(t *testing.T) *callbackFixture {
	t.Helper()
	notifier, api, _ := legacyNotifierFixture(t)
	backend := notifier.backend
	backend.logger = log.New(io.Discard, "", 0)
	backend.notifications = make(chan func(), 256)
	if err := backend.chatStore.Save(42); err != nil {
		t.Fatal(err)
	}
	clock := elapsedtest.NewFake(st.T0)
	store := &lc.MemStore{}
	fault := &lt.FaultStore{Store: store}
	engine, err := lc.New(lc.Config{Store: fault, Clock: clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}, Notifier: backend})
	if err != nil {
		t.Fatal(err)
	}
	audit := &callbackAudit{}
	legacy, err := lc.NewLegacyService(lc.LegacyConfig{Clock: clock, LegacyNotifier: notifier, AuditWriter: audit})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &callbackRuntime{engine: engine, legacy: legacy}
	if err := backend.AttachApprovalCallbacks(runtime, notifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.CloseApprovalCallbacks(); engine.Close(); legacy.Close() })
	return &callbackFixture{fault, audit, backend, api, engine, store, clock, runtime}
}
func (f *callbackFixture) start(t *testing.T) {
	t.Helper()
	if _, err := f.engine.Submit(context.Background(), st.PrincipalA, approvalDraft()); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(5 * time.Second)
	done := make(chan error, 1)
	go func() { done <- f.engine.Run(context.Background()) }()
	t.Cleanup(func() { f.engine.Close(); <-done })
	synctest.Wait()
}
func (f *callbackFixture) record(t *testing.T) ap.R1 {
	t.Helper()
	r, e := f.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func callbackFromCall(call approvalAPICall, id int) *tgbotapi.CallbackQuery {
	markup := call.form.Get("reply_markup")
	start := strings.Index(markup, "v:a:")
	if start < 0 {
		start = strings.Index(markup, "v:d:")
	}
	data := markup[start:]
	data = data[:strings.Index(data, "\"")]
	return &tgbotapi.CallbackQuery{ID: strconv.Itoa(id), From: &tgbotapi.User{ID: 42}, Message: &tgbotapi.Message{MessageID: id, Chat: &tgbotapi.Chat{ID: 42, Type: "private"}}, Data: data}
}
func (f *callbackFixture) card(t *testing.T) *tgbotapi.CallbackQuery {
	t.Helper()
	for i, c := range f.api.snapshot() {
		if c.method == "sendMessage" && c.form.Get("reply_markup") != "" {
			return callbackFromCall(c, i+1)
		}
	}
	t.Fatal("no decision card")
	return nil
}
func (f *callbackFixture) answers() []string {
	for len(f.backend.notifications) > 0 {
		(<-f.backend.notifications)()
	}
	var answers []string
	for _, c := range f.api.snapshot() {
		if c.method == "answerCallbackQuery" {
			answers = append(answers, c.form.Get("text"))
		}
	}
	return answers
}
func TestApprovalCallbackBindings(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	for _, mode := range []string{"approve", "deny", "malformed", "extra_field", "decision", "challenge", "handle", "user", "nil_user", "chat", "group", "message", "nil_message", "nil_chat", "closed"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				f.start(t)
				cb := f.card(t)
				switch mode {
				case "closed":
					f.backend.CloseApprovalCallbacks()
				case "deny":
					cb.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
				case "malformed":
					cb.Data = "v:a:bad"
				case "extra_field":
					cb.Data += ":extra"
				case "decision":
					cb.Data = strings.Replace(cb.Data, "v:a:", "v:x:", 1)
				case "challenge":
					cb.Data = cb.Data[:len(cb.Data)-16] + "fedcba9876543210"
				case "handle":
					p := strings.Split(cb.Data, ":")
					p[2] = "abcdefghijkl"
					cb.Data = strings.Join(p, ":")
				case "user":
					cb.From.ID++
				case "nil_user":
					cb.From = nil
				case "chat":
					cb.Message.Chat.ID++
				case "group":
					cb.Message.Chat.Type = "group"
				case "message":
					cb.Message.MessageID++
				case "nil_message":
					cb.Message = nil
				case "nil_chat":
					cb.Message.Chat = nil
				}
				f.backend.handleCallback(cb)
				synctest.Wait()
				rec := f.record(t)
				if mode == "approve" || mode == "deny" {
					want := ap.ApprovalApproved
					if mode == "deny" {
						want = ap.ApprovalDenied
					}
					if rec.Header.Decision == nil || rec.Header.Decision.Status != want {
						t.Fatalf("decision: %+v", rec.Header.Decision)
					}
					f.backend.handleCallback(cb)
					synctest.Wait()
					answers := f.answers()
					wantAnswer := "approved"
					if mode == "deny" {
						wantAnswer = "denied"
					}
					if len(answers) != 2 || answers[1] != wantAnswer {
						t.Fatalf("replay answers: %v", answers)
					}
				} else {
					if rec.Header.Decision != nil {
						t.Fatalf("invalid callback voted: %+v", rec.Header.Decision)
					}
					answers := f.answers()
					if len(answers) != 1 || answers[0] == "approved" {
						t.Fatalf("answers: %v", answers)
					}
				}
			})
		})
	}
}
func TestApprovalCallbackEarlyCardFIFO(t *testing.T) {
	for _, mode := range []string{"success", "deny_first", "failure", "timeout", "close", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				entered, release := make(chan struct{}), make(chan struct{})
				f.api.hook = func(r *http.Request, i int) (string, error) {
					if r.Form.Get("reply_markup") != "" && strings.HasSuffix(r.URL.Path, "/sendMessage") {
						cb := callbackFromCall(approvalAPICall{form: r.Form}, i)
						if mode == "deny_first" {
							cb.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
						}
						f.backend.handleCallback(cb)
						deny := *cb
						deny.ID = "deny"
						deny.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
						if mode == "deny_first" {
							deny.Data = strings.Replace(cb.Data, "v:d:", "v:a:", 1)
						}
						f.backend.handleCallback(&deny)
						if mode == "overflow" {
							for j := 0; j < 4; j++ {
								f.backend.handleCallback(&deny)
							}
						}
						close(entered)
						select {
						case <-release:
						case <-r.Context().Done():
							return "", r.Context().Err()
						}
						if mode == "failure" {
							return `{"ok":false,"error_code":400,"description":"failed"}`, nil
						}
					}
					return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
				}
				f.start(t)
				<-entered
				if f.record(t).Header.Decision != nil {
					t.Fatal("tap voted before card commit")
				}
				if mode == "timeout" {
					f.clock.Advance(10 * time.Second)
					time.Sleep(10 * time.Second)
					synctest.Wait()
				}
				if mode == "close" {
					f.backend.CloseApprovalCallbacks()
				}
				if mode == "overflow" {
					f.backend.approvalCallbacks.mu.Lock()
					count := f.backend.approvalCallbacks.count
					f.backend.approvalCallbacks.mu.Unlock()
					if count != 4 {
						t.Fatalf("queue count %d", count)
					}
				}
				close(release)
				synctest.Wait()
				rec := f.record(t)
				switch mode {
				case "success", "overflow", "deny_first":
					want := ap.ApprovalApproved
					if mode == "deny_first" {
						want = ap.ApprovalDenied
					}
					if rec.Header.Decision == nil || rec.Header.Decision.Status != want {
						t.Fatalf("FIFO decision: %+v", rec.Header.Decision)
					}
				case "failure":
					if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalError {
						t.Fatalf("failure decision: %+v", rec.Header.Decision)
					}
				default:
					if rec.Header.Decision != nil {
						t.Fatalf("late callback voted: %+v", rec.Header.Decision)
					}
				}
				answers := f.answers()
				if len(answers) < 2 {
					t.Fatalf("answers %v", answers)
				}
				if mode == "success" && (answers[0] != "approved" || answers[1] != "approved") {
					t.Fatalf("FIFO answers %v", answers)
				}
			})
		})
	}
}

func (f *callbackFixture) prepareLegacy(t *testing.T, number int) (*lc.LegacyReservation, *lc.PreparedLegacyApproval) {
	t.Helper()
	instance := fmt.Sprintf("%032x", number)
	_, _, seed := legacyNotifierFixture(t)
	reservation, err := f.runtime.legacy.ReserveLegacy(context.Background(), lc.LegacyInstance{ID: instance, UID: 1000, RequestID: fmt.Sprintf("request-%d", number), RedactionFailed: true}, seed.Data().Snapshot, assist.Input{})
	if err != nil {
		t.Fatal(err)
	}
	data := seed.Data()
	data.Instance = instance
	data.Context = reservation.RenderContext()
	artifact, err := lc.NewPreparedLegacyApproval(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.backend.approvalCallbacks.legacy.Prepare(artifact); err != nil {
		t.Fatal(err)
	}
	return reservation, artifact
}
func TestApprovalCallbackLegacyEarlyAndBindings(t *testing.T) {
	for _, mode := range []string{"fifo", "deny_first", "chat", "message", "instance", "failure", "recovery", "recovery_approve", "recovery_deny", "uncertain_approve", "uncertain_deny"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				reservation, artifact := f.prepareLegacy(t, 1)
				var old *tgbotapi.CallbackQuery
				f.api.hook = func(r *http.Request, i int) (string, error) {
					if r.Form.Get("reply_markup") != "" && strings.HasSuffix(r.URL.Path, "/sendMessage") {
						cb := callbackFromCall(approvalAPICall{form: r.Form}, i)
						cb.Message.Chat = &tgbotapi.Chat{ID: -42, Type: "supergroup"}
						old = cb
						switch mode {
						case "chat":
							cb.Message.Chat.ID--
						case "message":
							cb.Message.MessageID++
						case "instance":
							other, _ := f.prepareLegacy(t, 2)
							cb.Data = "v:a:" + other.RenderContext().Handle + ":" + artifact.Data().Context.Challenge
						}
						if mode == "deny_first" || strings.HasSuffix(mode, "_deny") {
							cb.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
						}
						f.backend.handleCallback(cb)
						deny := *cb
						deny.ID = "deny"
						deny.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
						if mode == "deny_first" || strings.HasSuffix(mode, "_deny") {
							deny.Data = strings.Replace(cb.Data, "v:d:", "v:a:", 1)
						}
						f.backend.handleCallback(&deny)
						synctest.Wait()
						if mode == "failure" {
							return `{"ok":false,"error_code":400,"description":"failed"}`, nil
						}
					}
					return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
				}
				if mode == "recovery" {
					f.engine.Close()
				}
				if strings.HasPrefix(mode, "recovery_") {
					f.runtime.currentErr = &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
				}
				if strings.HasPrefix(mode, "uncertain_") {
					f.runtime.currentErr = &ap.CodeError{Code: ap.CodeStorageUncertain}
				}
				err := f.runtime.legacy.DeliverLegacy(reservation, artifact)
				if (err != nil) != (mode == "failure") {
					t.Fatal(err)
				}
				synctest.Wait()
				answers := f.answers()
				if mode == "fifo" || mode == "recovery" || mode == "deny_first" || strings.HasPrefix(mode, "recovery_") || strings.HasPrefix(mode, "uncertain_") {
					want := "approved"
					if mode == "deny_first" || strings.HasSuffix(mode, "_deny") {
						want = "denied"
					}
					if len(answers) != 2 || answers[0] != want || answers[1] != lc.LegacyTapRefused {
						t.Fatalf("answers: %v", answers)
					}
					if result := reservation.Request().Wait(); result.Status != want {
						t.Fatalf("FIFO result: %+v", result)
					}
					f.backend.handleCallback(old)
					synctest.Wait()
					answers = f.answers()
					if answers[len(answers)-1] != lc.LegacyTapRefused {
						t.Fatal("replay accepted")
					}
				} else {
					for _, answer := range answers {
						if answer == "approved" || answer == "denied" {
							t.Fatalf("invalid callback voted: %v", answers)
						}
					}
					f.runtime.legacy.Close()
					result := reservation.Request().Wait()
					if result.Status == "approved" || result.Status == "denied" {
						t.Fatalf("invalid result: %+v", result)
					}
				}
			})
		})
	}
}

type blockedCallbackLegacyNotifier struct {
	*TelegramLegacyNotifier
	release <-chan struct{}
}

func (n *blockedCallbackLegacyNotifier) Deliver(ctx context.Context, artifact *lc.PreparedLegacyApproval) (lc.LegacyDelivery, error) {
	select {
	case <-n.release:
		return n.TelegramLegacyNotifier.Deliver(ctx, artifact)
	case <-ctx.Done():
		return lc.LegacyDelivery{}, ctx.Err()
	}
}

func TestApprovalCallbackGlobalQueueBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		release := make(chan struct{})
		f.runtime.legacy.Close()
		legacy, err := lc.NewLegacyService(lc.LegacyConfig{Clock: f.clock, LegacyNotifier: &blockedCallbackLegacyNotifier{TelegramLegacyNotifier: f.backend.approvalCallbacks.legacy, release: release}, AuditWriter: f.audit})
		if err != nil {
			t.Fatal(err)
		}
		f.runtime.legacy = legacy
		t.Cleanup(func() { legacy.Close() })

		done := make(chan error, 17)
		var callbacks []*tgbotapi.CallbackQuery
		for i := 1; i <= 17; i++ {
			reservation, artifact := f.prepareLegacy(t, i)
			go func() { done <- f.runtime.legacy.DeliverLegacy(reservation, artifact) }()
			synctest.Wait()
			c := artifact.Data().Context
			callbacks = append(callbacks, &tgbotapi.CallbackQuery{ID: strconv.Itoa(i), From: &tgbotapi.User{ID: 42}, Message: &tgbotapi.Message{MessageID: 100, Chat: &tgbotapi.Chat{ID: -42, Type: "supergroup"}}, Data: "v:a:" + c.Handle + ":" + c.Challenge})
		}
		for _, cb := range callbacks[:16] {
			for j := 0; j < 4; j++ {
				f.backend.handleCallback(cb)
			}
		}
		f.backend.handleCallback(callbacks[16])
		synctest.Wait()
		f.backend.approvalCallbacks.mu.Lock()
		count := f.backend.approvalCallbacks.count
		f.backend.approvalCallbacks.mu.Unlock()
		if count != 64 {
			t.Fatalf("queued %d callbacks", count)
		}
		answers := f.answers()
		if len(answers) != 1 || answers[0] != "not ready — tap again" {
			t.Fatalf("overflow answers: %v", answers)
		}
		f.backend.CloseApprovalCallbacks()
		close(release)
		for i := 0; i < 17; i++ {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		f.backend.approvalCallbacks.mu.Lock()
		count = f.backend.approvalCallbacks.count
		f.backend.approvalCallbacks.mu.Unlock()
		if count != 0 {
			t.Fatalf("queue retained %d callbacks", count)
		}
	})
}

func TestApprovalCallbackGrammar(t *testing.T) {
	for _, test := range []struct {
		data     string
		valid    bool
		decision string
	}{
		{"v:a:abcdefghijkl:0123456789abcdef", true, ap.VoteApprove},
		{"v:d:abcdefghijkl:0123456789abcdef", true, ap.VoteDeny},
		{"p:a:abcdefghijkl:0123456789abcdef", false, ""},
		{"v:x:abcdefghijkl:0123456789abcdef", false, ""},
		{"v:a:abcdefghijkl:0123456789abcdef:extra", false, ""},
		{"v:a:abcdefghijkl", false, ""},
		{"v:a:abc:0123456789abcdef", false, ""},
		{"v:a:abcdefghijk!:0123456789abcdef", false, ""},
		{"v:a:abcdefghijkl:0123", false, ""},
		{"v:a:abcdefghijkl:0123456789abcdeg", false, ""},
	} {
		t.Run(test.data, func(t *testing.T) {
			decision, handle, challenge, ok := parseApprovalCallback(test.data)
			if ok != test.valid {
				t.Fatalf("valid %v", ok)
			}
			if ok && (decision != test.decision || handle != "abcdefghijkl" || challenge != "0123456789abcdef") {
				t.Fatalf("parsed %q %q %q", decision, handle, challenge)
			}
		})
	}
}

func TestApprovalCallbackPreparingAndEarlyEdit(t *testing.T) {
	for _, mode := range []string{"preparing", "edit", "edit_deny", "edit_failure", "retired", "stale"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				if _, err := f.engine.Submit(context.Background(), st.PrincipalA, approvalDraft()); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- f.engine.Run(context.Background()) }()
				t.Cleanup(func() { f.engine.Close(); <-done })
				synctest.Wait()
				old := f.card(t)
				if !strings.HasPrefix(old.Data, "v:d:") {
					t.Fatal("preparing card offered approve")
				}
				old.Data = strings.Replace(old.Data, "v:d:", "v:a:", 1)
				if mode == "preparing" {
					f.backend.handleCallback(old)
					synctest.Wait()
					if f.record(t).Header.Decision != nil {
						t.Fatal("preparing approval accepted")
					}
					return
				}
				entered, release := make(chan struct{}), make(chan struct{})
				f.api.hook = func(r *http.Request, i int) (string, error) {
					if strings.HasSuffix(r.URL.Path, "/editMessageText") && strings.Contains(r.Form.Get("reply_markup"), "v:a:") {
						cb := callbackFromCall(approvalAPICall{form: r.Form}, old.Message.MessageID)
						if mode == "stale" {
							cb = old
						}
						if mode == "edit_deny" {
							cb.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
						}
						f.backend.handleCallback(cb)
						if mode == "edit" || mode == "edit_deny" {
							deny := *cb
							deny.ID = "deny"
							deny.Data = strings.Replace(cb.Data, "v:a:", "v:d:", 1)
							if mode == "edit_deny" {
								deny.Data = strings.Replace(cb.Data, "v:d:", "v:a:", 1)
							}
							f.backend.handleCallback(&deny)
						}
						close(entered)
						select {
						case <-release:
						case <-r.Context().Done():
							return "", r.Context().Err()
						}
						if mode == "edit_failure" {
							return `{"ok":false,"error_code":400,"description":"failed"}`, nil
						}
					}
					return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
				}
				f.clock.Advance(5 * time.Second)
				if err := f.engine.Reconcile(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				<-entered
				if f.record(t).Header.Decision != nil {
					t.Fatal("voted before edit commit")
				}
				if mode == "retired" {
					if _, err := f.engine.AdminCancel(ap.RecordHandle(ap.RecordKey(st.PrincipalA, st.ID(1))), ap.AdminCancel{PlanHash: f.record(t).Header.PlanHash, Admin: st.Admin}); err != nil {
						t.Fatal(err)
					}
				}
				close(release)
				synctest.Wait()
				rec := f.record(t)
				answers := f.answers()
				if mode == "edit" || mode == "edit_deny" {
					want := ap.ApprovalApproved
					wantAnswer := "approved"
					if mode == "edit_deny" {
						want = ap.ApprovalDenied
						wantAnswer = "denied"
					}
					if rec.Header.Decision == nil || rec.Header.Decision.Status != want {
						t.Fatalf("decision %+v", rec.Header.Decision)
					}
					if len(answers) != 2 || answers[0] != wantAnswer || answers[1] != wantAnswer {
						t.Fatalf("answers %v", answers)
					}
				} else if mode == "retired" {
					if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalCanceled || len(rec.Header.Votes) != 0 {
						t.Fatalf("retirement %+v", rec.Header)
					}
					if len(answers) != 1 || answers[0] == "approved" || answers[0] == "denied" {
						t.Fatalf("retired answer %v", answers)
					}
				} else if mode == "edit_failure" {
					if rec.Header.Decision != nil {
						t.Fatal("failed edit accepted a vote")
					}
					if len(answers) != 1 || answers[0] != "card updated — tap again" {
						t.Fatalf("failure answers %v", answers)
					}
				} else {
					if rec.Header.Decision != nil {
						t.Fatal("stale approve voted")
					}
					if len(answers) != 1 || answers[0] != "card updated — tap again" {
						t.Fatalf("stale answer %v", answers)
					}
				}
			})
		})
	}
}

func TestApprovalCallbackUnknownAudit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		for i := 0; i < 2; i++ {
			f.backend.handleCallback(&tgbotapi.CallbackQuery{ID: strconv.Itoa(i), From: &tgbotapi.User{ID: 42}, Message: &tgbotapi.Message{MessageID: 1, Chat: &tgbotapi.Chat{ID: 42, Type: "private"}}, Data: "v:a:abcdefghijkl:0123456789abcdef"})
		}
		synctest.Wait()
		f.audit.mu.Lock()
		events := append([]ap.AuditMetadata(nil), f.audit.events...)
		f.audit.mu.Unlock()
		if len(events) != 2 {
			t.Fatalf("unknown callbacks audit count %d", len(events))
		}
		for _, event := range events {
			if !event.Replay || event.Transition != "legacy_vote_refused{unknown_card}" {
				t.Fatalf("unknown callback produced resolution audit: %+v", event)
			}
		}
		answers := f.answers()
		if len(answers) != 2 || answers[0] != lc.LegacyTapRefused || answers[1] != lc.LegacyTapRefused {
			t.Fatalf("unknown answers: %v", answers)
		}
	})
}

func TestApprovalCallbackLegacyReplayAudit(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				reservation, artifact := f.prepareLegacy(t, 1)
				if err := f.runtime.legacy.DeliverLegacy(reservation, artifact); err != nil {
					t.Fatal(err)
				}
				cb := f.card(t)
				cb.Message.Chat = &tgbotapi.Chat{ID: -42, Type: "supergroup"}
				if expired {
					f.clock.Advance(10 * time.Minute)
				} else {
					f.backend.handleCallback(cb)
					synctest.Wait()
					if answers := f.answers(); len(answers) != 1 || answers[0] != "approved" {
						t.Fatalf("initial approval answer: %v", answers)
					}
					if reservation.Request().Wait().Status != "approved" {
						t.Fatal("initial approval failed")
					}
				}
				for _, released := range []bool{false, true} {
					if released {
						f.backend.approvalCallbacks.legacy.Release(artifact.Data().Instance)
					}
					for _, decision := range []string{"a", "d"} {
						copy := *cb
						fields := strings.Split(copy.Data, ":")
						fields[1] = decision
						copy.Data = strings.Join(fields, ":")
						f.backend.handleCallback(&copy)
					}
				}
				synctest.Wait()
				f.audit.mu.Lock()
				events := append([]ap.AuditMetadata(nil), f.audit.events...)
				f.audit.mu.Unlock()
				if len(events) != 4 {
					t.Fatalf("audit count %d: %+v", len(events), events)
				}
				want := "legacy_vote_replay"
				if expired {
					want = "legacy_vote_refused{expired}"
				}
				for _, event := range events {
					if !event.Replay || event.Transition != want {
						t.Fatalf("audit %+v want %s", event, want)
					}
				}
			})
		})
	}
}

func TestApprovalCallbackFailureAnswers(t *testing.T) {
	for _, reason := range []string{"stale_revision", "retired"} {
		if got := approvalVoteAnswer(ap.Answer{Noise: true, Reason: reason}, nil, ap.VoteApprove); got != "card updated — tap again" {
			t.Fatalf("%s: %q", reason, got)
		}
	}
	for _, code := range []ap.Code{ap.CodeStorageUncertain, ap.CodeLifecycleUnavailable} {
		if got := approvalVoteAnswer(ap.Answer{}, &ap.CodeError{Code: code}, ap.VoteApprove); got != "not recorded yet — tap again" {
			t.Fatalf("%s: %q", code, got)
		}
	}
}

func TestApprovalCallbackUncertainRecovery(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				f.start(t)
				cb := f.card(t)
				f.fault.Arm(landed)
				f.backend.handleCallback(cb)
				synctest.Wait()
				answers := f.answers()
				if len(answers) != 1 || answers[0] != "not recorded yet — tap again" {
					t.Fatalf("uncertain answer: %v", answers)
				}
				rec := f.record(t)
				if (rec.Header.Decision != nil) != landed {
					t.Fatalf("decision persistence: %+v", rec.Header.Decision)
				}
				f.engine.Close()
				recovered, err := lc.New(lc.Config{Store: f.store, Clock: f.clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}})
				if err != nil {
					t.Fatal(err)
				}
				defer recovered.Close()
				f.runtime.engine = recovered
				f.backend.handleCallback(cb)
				synctest.Wait()
				answers = f.answers()
				rec = f.record(t)
				if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalApproved || answers[len(answers)-1] != "approved" {
					t.Fatalf("recovery outcome: %+v %v", rec.Header.Decision, answers)
				}
				if len(rec.Header.Votes) != 1 {
					t.Fatalf("recovery recorded %d votes", len(rec.Header.Votes))
				}

			})
		})
	}
}

func TestApprovalCallbackReplacementDuringQueueRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		var replacement *lc.Engine
		replacementStore := &lc.MemStore{}
		completedCalls := 0
		f.runtime.current = func() (*lc.Engine, error) {
			rec, err := f.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if err == nil && len(rec.Payload.CardEntries) > 0 && rec.Payload.CardEntries[0].Outcome == ap.OutcomeSent {
				completedCalls++
				if completedCalls == 1 {
					return f.engine, nil
				}
				if replacement == nil {
					if err := replacementStore.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), rec); err != nil {
						return nil, err
					}
					replacement, err = lc.New(lc.Config{Store: replacementStore, Clock: f.clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}})
					if err != nil {
						return nil, err
					}
				}
				return replacement, nil
			}
			return f.engine, nil
		}
		f.api.hook = func(r *http.Request, i int) (string, error) {
			if r.Form.Get("reply_markup") != "" && strings.HasSuffix(r.URL.Path, "/sendMessage") {
				f.backend.handleCallback(callbackFromCall(approvalAPICall{form: r.Form}, i))
			}
			return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
		}
		f.start(t)
		synctest.Wait()
		if replacement == nil {
			t.Fatal("runtime did not replace generation")
		}
		defer replacement.Close()
		rec, err := replacementStore.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Header.Decision != nil {
			t.Fatal("queued old-generation tap decided replacement")
		}
		for _, event := range rec.Header.Outbox {
			if event.Kind == ap.EventVote {
				t.Fatalf("old-generation tap reached replacement vote: %+v", event)
			}
		}
		answers := f.answers()
		if len(answers) != 1 || answers[0] == "approved" {
			t.Fatalf("answers %v", answers)
		}
	})
}

func TestApprovalCallbackReplayBinding(t *testing.T) {
	for _, mode := range []string{"valid", "challenge", "message", "chat", "user", "retired_handle"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				if _, err := f.engine.Submit(context.Background(), st.PrincipalA, approvalDraft()); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- f.engine.Run(context.Background()) }()
				t.Cleanup(func() { f.engine.Close(); <-done })
				synctest.Wait()
				old := f.card(t)
				f.clock.Advance(5 * time.Second)
				if err := f.engine.Reconcile(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				var cb *tgbotapi.CallbackQuery
				for _, call := range f.api.snapshot() {
					if call.method == "editMessageText" && strings.Contains(call.form.Get("reply_markup"), "v:a:") {
						cb = callbackFromCall(call, old.Message.MessageID)
					}
				}
				if cb == nil {
					t.Fatal("no edited approval card")
				}
				f.backend.handleCallback(cb)
				synctest.Wait()
				if rec := f.record(t); rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalApproved {
					t.Fatal("initial approval failed")
				}
				switch mode {
				case "challenge":
					cb.Data = cb.Data[:len(cb.Data)-16] + "fedcba9876543210"
				case "message":
					cb.Message.MessageID++
				case "chat":
					cb.Message.Chat.ID++
				case "user":
					cb.From.ID++
				case "retired_handle":
					cb = old
					cb.Data = strings.Replace(cb.Data, "v:d:", "v:a:", 1)
				}
				f.backend.handleCallback(cb)
				synctest.Wait()
				answers := f.answers()
				want := lc.LegacyTapRefused
				if mode == "valid" {
					want = "approved"
				}
				if mode == "user" {
					want = "not authorized"
				}
				if len(answers) != 2 || answers[1] != want {
					t.Fatalf("replay answers %v want %s", answers, want)
				}
				if rec := f.record(t); rec.Header.Decision.Status != ap.ApprovalApproved || len(rec.Header.Votes) != 1 {
					t.Fatalf("replay altered decision: %+v", rec.Header)
				}
			})
		})
	}
}

type unavailableCallbackStore struct {
	lc.Store
	reads int
	armed bool
}

func (s *unavailableCallbackStore) Load(key string) (ap.R1, error) {
	if s.armed {
		s.reads++
		if s.reads == 2 {
			return ap.R1{}, &ap.CodeError{Code: ap.CodeLifecycleUnavailable}
		}
	}
	return s.Store.Load(key)
}

func TestApprovalCallbackUnavailableDuringQueueRelease(t *testing.T) {
	for _, mode := range []string{"closed_engine", "runtime_error", "runtime_uncertain", "vote_load"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				completedCalls := 0
				f.runtime.current = func() (*lc.Engine, error) {
					rec, err := f.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
					if err == nil && len(rec.Payload.CardEntries) > 0 && rec.Payload.CardEntries[0].Outcome == ap.OutcomeSent {
						completedCalls++
						if completedCalls == 1 {
							return f.engine, nil
						}
						if mode == "runtime_error" || mode == "runtime_uncertain" {
							code := ap.CodeLifecycleUnavailable
							if mode == "runtime_uncertain" {
								code = ap.CodeStorageUncertain
							}
							return nil, &ap.CodeError{Code: code}
						}
						if mode == "vote_load" {
							base := &lc.MemStore{}
							if err := base.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), rec); err != nil {
								return nil, err
							}
							store := &unavailableCallbackStore{Store: base}
							engine, err := lc.New(lc.Config{Store: store, Clock: f.clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}})
							if err != nil {
								return nil, err
							}
							t.Cleanup(func() { engine.Close() })
							store.armed = true
							return engine, nil
						}
						f.engine.Close()
					}
					return f.engine, nil
				}
				f.api.hook = func(r *http.Request, i int) (string, error) {
					if r.Form.Get("reply_markup") != "" && strings.HasSuffix(r.URL.Path, "/sendMessage") {
						f.backend.handleCallback(callbackFromCall(approvalAPICall{form: r.Form}, i))
					}
					return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
				}
				f.start(t)
				synctest.Wait()
				if rec := f.record(t); rec.Header.Decision != nil || len(rec.Header.Votes) != 0 {
					t.Fatalf("closed engine recorded a vote: %+v", rec.Header)
				}
				f.audit.mu.Lock()
				events := append([]ap.AuditMetadata(nil), f.audit.events...)
				f.audit.mu.Unlock()
				if len(events) != 1 || events[0].Transition != "legacy_vote_refused{unknown_card}" || !events[0].Replay {
					t.Fatalf("unavailable callback audit: %+v", events)
				}
				answers := f.answers()
				if len(answers) != 1 || answers[0] != lc.LegacyTapRefused {
					t.Fatalf("unavailable callback answers: %v", answers)
				}
			})
		})
	}
}

func TestApprovalCallbackAmbiguousHandle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCallbackFixture(t)
		f.backend.approvalCallbacks.legacy.destination = lc.LegacyDestination{ChatID: 42}
		reservation, artifact := f.prepareLegacy(t, 1)
		if err := f.runtime.legacy.DeliverLegacy(reservation, artifact); err != nil {
			t.Fatal(err)
		}
		cb := f.card(t)
		cb.Message.Chat = &tgbotapi.Chat{ID: 42, Type: "private"}
		c := artifact.Data().Context
		submit := st.SubmitOf(approvalDraft(), st.PrincipalA, st.T0, time.Hour)
		submit.ReviewSnapshot = notificationFixture(t, 1).Snapshot
		var rec *ap.R1
		for _, command := range []ap.Command{submit, ap.AssistDone{Unavailable: "test"}, ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{1}}, ap.CardStart{Handle: c.Handle, ChalHash: ap.ChallengeHash(c.Challenge)}, ap.CardDone{Handle: c.Handle, MsgID: int64(cb.Message.MessageID)}} {
			next, answer := ap.Apply(rec, command, ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
			if answer.Code != "" || !answer.Changed {
				t.Fatalf("fixture %T: %+v", command, answer)
			}
			rec = &next
		}
		store := &lc.MemStore{}
		key := ap.RecordKey(st.PrincipalA, st.ID(1))
		if err := store.Commit(key, *rec); err != nil {
			t.Fatal(err)
		}
		engine, err := lc.New(lc.Config{Store: store, Clock: f.clock, Freezer: approvalTestFreezer{}, SnapshotBuilder: approvalTestSnapshotter{}})
		if err != nil {
			t.Fatal(err)
		}
		defer engine.Close()
		f.runtime.engine = engine
		f.backend.handleCallback(cb)
		synctest.Wait()
		after, err := store.Load(key)
		if err != nil || after.Header.Decision != nil || len(after.Header.Votes) != 0 {
			t.Fatalf("ambiguous callback voted v2: %+v %v", after.Header, err)
		}
		f.runtime.legacy.Close()
		result := reservation.Request().Wait()
		if result.Status == "approved" || result.Status == "denied" {
			t.Fatalf("ambiguous callback voted legacy: %+v", result)
		}
		answers := f.answers()
		if len(answers) != 1 || answers[0] != lc.LegacyTapRefused {
			t.Fatalf("ambiguous answers: %v", answers)
		}
	})
}

func TestApprovalCallbackAttachment(t *testing.T) {
	for _, mode := range []string{"nil_runtime", "nil_legacy", "nil_notifier", "foreign_notifier", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			f := newCallbackFixture(t)
			backend := &TelegramBackend{}
			notifier := &TelegramLegacyNotifier{backend: backend}
			var runtime ApprovalCallbackRuntime = f.runtime
			switch mode {
			case "nil_runtime":
				runtime = nil
			case "nil_legacy":
				runtime = &callbackRuntime{engine: f.engine}
			case "nil_notifier":
				notifier = nil
			case "foreign_notifier":
				notifier = f.backend.approvalCallbacks.legacy
			case "duplicate":
				backend = f.backend
				notifier = f.backend.approvalCallbacks.legacy
			}
			t.Cleanup(backend.CloseApprovalCallbacks)
			if err := backend.AttachApprovalCallbacks(runtime, notifier); err == nil {
				t.Fatal("invalid callback attachment accepted")
			}
		})
	}
}

func TestApprovalCallbackReleasedBindingsBound(t *testing.T) {
	notifier, _, seed := legacyNotifierFixture(t)
	var first, last string
	for i := 0; i < 257; i++ {
		data := seed.Data()
		data.Instance = fmt.Sprintf("%032x", i+1)
		data.Context.Handle = ap.CardHandleFor(fmt.Sprintf("record-%d", i), 0)
		artifact, err := lc.NewPreparedLegacyApproval(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := notifier.Prepare(artifact); err != nil {
			t.Fatal(err)
		}
		notifier.entries[data.Instance].messageID = int64(i + 1)
		notifier.Release(data.Instance)
		if i == 0 {
			first = data.Context.Handle
		}
		last = data.Context.Handle
	}
	if len(notifier.bindings) != 256 || len(notifier.retired) != 256 || len(notifier.entries) != 0 {
		t.Fatalf("retained bindings=%d order=%d entries=%d", len(notifier.bindings), len(notifier.retired), len(notifier.entries))
	}
	cb := &tgbotapi.CallbackQuery{From: &tgbotapi.User{ID: 42}, Message: &tgbotapi.Message{MessageID: 1, Chat: &tgbotapi.Chat{ID: -42, Type: "supergroup"}}}
	if notifier.matchesCallback(first, cb) {
		t.Fatal("oldest binding retained")
	}
	cb.Message.MessageID = 257
	if !notifier.matchesCallback(last, cb) {
		t.Fatal("newest released binding lost")
	}
	data := seed.Data()
	data.Instance, data.Context.Handle = fmt.Sprintf("%032x", 258), last
	artifact, err := lc.NewPreparedLegacyApproval(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.Prepare(artifact); err != nil {
		t.Fatal(err)
	}
	notifier.entries[data.Instance].messageID = 258
	notifier.Release(data.Instance)
	cb.Message.MessageID = 258
	if len(notifier.bindings) != 256 || len(notifier.retired) != 256 || !notifier.matchesCallback(last, cb) {
		t.Fatal("reused handle evicted an unrelated binding")
	}
}

func TestApprovalCallbackUnconfigured(t *testing.T) {
	notifier, api, _ := legacyNotifierFixture(t)
	backend := notifier.backend
	backend.logger = log.New(io.Discard, "", 0)
	backend.notifications = make(chan func(), 1)
	backend.handleCallback(&tgbotapi.CallbackQuery{ID: "unconfigured", From: &tgbotapi.User{ID: 42}, Message: &tgbotapi.Message{MessageID: 1, Chat: &tgbotapi.Chat{ID: 42, Type: "private"}}, Data: "v:a:abcdefghijkl:0123456789abcdef"})
	if len(backend.notifications) != 1 {
		t.Fatal("unconfigured callback not answered")
	}
	(<-backend.notifications)()
	calls := api.snapshot()
	if len(calls) != 1 || calls[0].method != "answerCallbackQuery" || calls[0].form.Get("text") != lc.LegacyTapRefused {
		t.Fatalf("unconfigured callback answer: %+v", calls)
	}
}

func TestApprovalCallbackLegacyReleaseOrder(t *testing.T) {
	for _, mode := range []string{"reverse_release", "late_release"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				notifier := f.backend.approvalCallbacks.legacy
				approve := func(number int) (string, *tgbotapi.CallbackQuery) {
					reservation, artifact := f.prepareLegacy(t, number)
					if err := f.runtime.legacy.DeliverLegacy(reservation, artifact); err != nil {
						t.Fatal(err)
					}
					data := artifact.Data()
					notifier.mu.Lock()
					messageID := notifier.entries[data.Instance].messageID
					notifier.mu.Unlock()
					cb := &tgbotapi.CallbackQuery{ID: strconv.Itoa(number), From: &tgbotapi.User{ID: 42}, Message: &tgbotapi.Message{MessageID: int(messageID), Chat: &tgbotapi.Chat{ID: data.Context.Destination.ChatID, Type: "supergroup"}}, Data: "v:a:" + data.Context.Handle + ":" + data.Context.Challenge}
					f.backend.handleCallback(cb)
					synctest.Wait()
					for len(f.backend.notifications) > 0 {
						(<-f.backend.notifications)()
					}
					f.api.mu.Lock()
					last := f.api.calls[len(f.api.calls)-1]
					f.api.mu.Unlock()
					if last.method != "answerCallbackQuery" || last.form.Get("text") != "approved" {
						t.Fatalf("approval %d: %+v", number, last)
					}
					if result := reservation.Request().Wait(); result.Status != "approved" {
						t.Fatalf("approval %d result: %+v", number, result)
					}
					return data.Instance, cb
				}
				instances := make([]string, 256)
				var retained, second *tgbotapi.CallbackQuery
				for i := range instances {
					instances[i], retained = approve(i + 1)
					if i == 1 {
						second = retained
					}
				}
				if mode == "reverse_release" {
					for i := len(instances) - 1; i >= 0; i-- {
						notifier.Release(instances[i])
					}
					newest, _ := approve(257)
					notifier.Release(newest)
				} else {
					newest, _ := approve(257)
					for _, instance := range instances[1:] {
						notifier.Release(instance)
					}
					notifier.Release(newest)
					notifier.Release(instances[0])
					retained = second
				}
				handle := strings.Split(retained.Data, ":")[2]
				if !f.runtime.legacy.HasHandle(handle) {
					t.Fatal("retained request unexpectedly absent from lifecycle tombstones")
				}
				f.backend.handleCallback(retained)
				synctest.Wait()
				f.audit.mu.Lock()
				events := append([]ap.AuditMetadata(nil), f.audit.events...)
				f.audit.mu.Unlock()
				if len(events) != 1 || !events[0].Replay || events[0].Transition != "legacy_vote_replay" {
					t.Fatalf("retained request replay audit: %+v", events)
				}
			})
		})
	}
}

func TestApprovalCallbackReleaseDeadline(t *testing.T) {
	for _, plane := range []string{"v2", "legacy"} {
		for _, mode := range []string{"ready_at_expiry", "delayed_release", "wall_jump"} {
			t.Run(plane+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newCallbackFixture(t)
					var reservation *lc.LegacyReservation
					var artifact *lc.PreparedLegacyApproval
					if plane == "legacy" {
						reservation, artifact = f.prepareLegacy(t, 1)
					}
					entered, release := make(chan struct{}), make(chan struct{})
					completedCalls := 0
					f.runtime.current = func() (*lc.Engine, error) {
						committed := false
						if plane == "legacy" {
							c := artifact.Data().Context
							ready, err := f.runtime.legacy.CallbackReadiness(c.Handle, c.Challenge)
							committed = err == nil && !ready.Pending
						} else {
							rec, err := f.store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
							committed = err == nil && len(rec.Payload.CardEntries) > 0 && rec.Payload.CardEntries[0].Outcome == ap.OutcomeSent
						}
						if committed {
							completedCalls++
							if mode == "delayed_release" && completedCalls == 2 {
								close(entered)
								<-release
							}
						}
						return f.engine, nil
					}
					f.api.hook = func(r *http.Request, i int) (string, error) {
						if r.Form.Get("reply_markup") != "" && strings.HasSuffix(r.URL.Path, "/sendMessage") {
							cb := callbackFromCall(approvalAPICall{form: r.Form}, i)
							if plane == "legacy" {
								cb.Message.Chat = &tgbotapi.Chat{ID: -42, Type: "supergroup"}
							}
							f.backend.handleCallback(cb)
							// Advance the lifecycle clock without firing Go's wakeup timer.
							if mode == "ready_at_expiry" {
								f.clock.Advance(10 * time.Second)
							}
							if mode == "wall_jump" {
								f.clock.StepWall(20 * time.Second)
							}
						}
						return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
					}
					if plane == "legacy" {
						if err := f.runtime.legacy.DeliverLegacy(reservation, artifact); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
					} else {
						f.start(t)
					}
					if mode == "delayed_release" {
						select {
						case <-entered:
						default:
							t.Fatal("release did not reach casting barrier")
						}
						f.clock.Advance(11 * time.Second)
						close(release)
					}
					synctest.Wait()
					answers := f.answers()
					if len(answers) != 1 {
						t.Fatalf("answers: %v", answers)
					}
					wantVote := mode == "wall_jump"
					if (answers[0] == "approved") != wantVote {
						t.Fatalf("deadline answers: %v, want vote %v", answers, wantVote)
					}
					if plane == "legacy" {
						f.runtime.legacy.Close()
						result := reservation.Request().Wait()
						wantStatus := "timeout"
						if wantVote {
							wantStatus = "approved"
						}
						if result.Status != wantStatus {
							t.Fatalf("legacy decision: %+v, want status %s", result, wantStatus)
						}
					} else {
						rec := f.record(t)
						if (rec.Header.Decision != nil && rec.Header.Decision.Status == ap.ApprovalApproved) != wantVote || (!wantVote && len(rec.Header.Votes) != 0) {
							t.Fatalf("v2 decision: %+v, want vote %v", rec.Header, wantVote)
						}
					}
				})
			})
		}
	}
}
