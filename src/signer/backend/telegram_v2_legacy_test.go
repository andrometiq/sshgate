package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
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
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	ar "github.com/karthikeyan5/sshgate/src/approvalreview"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"go.uber.org/goleak"
)

// In-process Bot API transport: no listener, credentials or external network.
type legacyBotAPI struct {
	mu    sync.Mutex
	calls []approvalAPICall
	hook  func(*http.Request, int) (string, error)
}

func (a *legacyBotAPI) Do(r *http.Request) (*http.Response, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.calls = append(a.calls, approvalAPICall{method: r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], form: r.Form})
	i := len(a.calls)
	a.mu.Unlock()
	body := fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i)
	if a.hook != nil {
		var err error
		body, err = a.hook(r, i)
		if err != nil {
			return nil, err
		}
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}
func (a *legacyBotAPI) snapshot() []approvalAPICall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approvalAPICall(nil), a.calls...)
}
func (a *legacyBotAPI) reset() {
	a.mu.Lock()
	a.calls = nil
	a.mu.Unlock()
}

func legacyNotifierFixture(t *testing.T) (*TelegramLegacyNotifier, *legacyBotAPI, *lc.PreparedLegacyApproval) {
	t.Helper()
	api := &legacyBotAPI{}
	bot, err := tgbotapi.NewBotAPIWithClient(approvalTestToken, "http://bot.invalid/bot%s/%s", api)
	if err != nil {
		t.Fatal(err)
	}
	api.reset()
	backend := &TelegramBackend{bot: bot, chatStore: &MemChatStore{}, allowedUserID: 42}
	destination := lc.LegacyDestination{ChatID: -42, TopicID: 7}
	n, err := NewTelegramLegacyNotifier(backend, destination)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshot, err := ar.BuildLegacySnapshot(ar.LegacyRequest{RequestID: "legacy-request", Requester: "uid:1000", SubmittedAt: now, ExpiresAt: now.Add(time.Minute), Commands: []ar.LegacyCommand{{Server: "server", Command: strings.Repeat("x", 4000), TTLSeconds: 60}}}, &[32]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := ar.BuildView(snapshot, ar.Assist{State: ap.AssistUnavailable, Reason: assist.ReasonRedaction})
	if err != nil {
		t.Fatal(err)
	}
	handle, challenge := "abcdefghijkl", "0123456789abcdef"
	parts, err := ar.PackParts(view, handle)
	if err != nil {
		t.Fatal(err)
	}
	card, err := ar.DecisionCard(view, handle, len(parts))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := snapshot.Encode()
	if err != nil {
		t.Fatal(err)
	}
	data := lc.LegacyPreparedData{Instance: strings.Repeat("1", 32), Snapshot: raw, Context: lc.LegacyRenderContext{Destination: destination, Handle: handle, Challenge: challenge, Assist: assist.Snapshot{State: ap.AssistUnavailable, Reason: assist.ReasonRedaction}}}
	for _, part := range parts {
		data.Payload = append(data.Payload, lc.LegacyMessage{Bytes: []byte(part)})
	}
	data.Payload = append(data.Payload, lc.LegacyMessage{Bytes: []byte(card), ApproveLabel: view.ApproveLabel, DenyLabel: view.DenyLabel})
	artifact, err := lc.NewPreparedLegacyApproval(data)
	if err != nil {
		t.Fatal(err)
	}
	return n, api, artifact
}
func TestLegacyNotifierArtifactDelivery(t *testing.T) {
	n, api, p := legacyNotifierFixture(t)
	if n.Destination() != p.Data().Context.Destination {
		t.Fatal("destination")
	}
	if err := n.Prepare(p); err != nil {
		t.Fatal(err)
	}
	before := p.Data()
	// Neither the passed pointer nor a returned pointer owns the installed copy.
	*p = lc.PreparedLegacyApproval{}
	frozen, err := n.Prepared(before.Instance)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(frozen.Data(), before) {
		t.Fatal("artifact changed")
	}
	*frozen = lc.PreparedLegacyApproval{}
	p, err = n.Prepared(before.Instance)
	if err != nil {
		t.Fatal(err)
	}
	_ = n.backend.chatStore.Save(999) // Delivery must not reload the destination.
	report, err := n.Deliver(context.Background(), p)
	if err != nil || !report.AllDelivered {
		t.Fatalf("%+v %v", report, err)
	}
	calls := api.snapshot()
	if len(calls) != len(before.Payload) {
		t.Fatal("missing messages")
	}
	for i, call := range calls {
		if call.method != "sendMessage" || call.form.Get("text") != string(before.Payload[i].Bytes) || call.form.Get("chat_id") != "-42" || call.form.Get("message_thread_id") != "7" || call.form.Get("parse_mode") != "" {
			t.Fatalf("message %d: %+v", i, call)
		}
		if i < len(calls)-1 && call.form.Get("reply_markup") != "" {
			t.Fatal("buttons on review part")
		}
	}
	var keyboard tgbotapi.InlineKeyboardMarkup
	if err := json.Unmarshal([]byte(calls[len(calls)-1].form.Get("reply_markup")), &keyboard); err != nil {
		t.Fatal(err)
	}
	for i, verb := range []string{"a", "d"} {
		button := keyboard.InlineKeyboard[0][i]
		wantLabel := before.Payload[len(before.Payload)-1].ApproveLabel
		if i == 1 {
			wantLabel = before.Payload[len(before.Payload)-1].DenyLabel
		}
		if button.Text != wantLabel {
			t.Fatal("frozen button label changed")
		}
		if *button.CallbackData != "v:"+verb+":"+before.Context.Handle+":"+before.Context.Challenge || len(*button.CallbackData) > 35 {
			t.Fatal("callback binding")
		}
	}
	if err := n.EditStatus(context.Background(), p, "approved"); err != nil {
		t.Fatal(err)
	}
	calls = api.snapshot()
	edit := calls[len(calls)-1]
	if edit.method != "editMessageText" || edit.form.Get("message_id") != strconv.Itoa(len(before.Payload)) || edit.form.Get("chat_id") != "-42" || !strings.HasSuffix(edit.form.Get("text"), "\nApproval: approved") || edit.form.Get("reply_markup") != `{"inline_keyboard":[]}` {
		t.Fatal("terminal edit lost binding")
	}
	n.Release(before.Instance)
	if err := n.EditStatus(context.Background(), p, "approved"); err == nil {
		t.Fatal("released card edited")
	}
	if _, err := n.Prepared(before.Instance); err == nil {
		t.Fatal("release retained artifact")
	}
}
func TestLegacyNotifierPrepareGuards(t *testing.T) {
	for _, name := range []string{"nil", "invalid", "destination", "count", "part", "utf8", "total", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			n, api, p := legacyNotifierFixture(t)
			data := p.Data()
			switch name {
			case "nil":
				p = nil
			case "invalid":
				p = &lc.PreparedLegacyApproval{}
			case "destination":
				data.Context.Destination.ChatID++
			case "count":
				for len(data.Payload) <= ar.MaxMessages {
					data.Payload = append([]lc.LegacyMessage{{Bytes: []byte("part")}}, data.Payload...)
				}
			case "part":
				data.Payload[0].Bytes = []byte(strings.Repeat("x", ar.PartBytes))
			case "utf8":
				data.Payload[0].Bytes = []byte{0xff}
			case "total":
				for len(data.Payload) < ar.MaxMessages {
					data.Payload = append([]lc.LegacyMessage{{Bytes: []byte(strings.Repeat("x", ar.PartBytes-1))}}, data.Payload...)
				}
			case "duplicate":
				if err := n.Prepare(p); err != nil {
					t.Fatal(err)
				}
			}
			if name != "nil" && name != "invalid" {
				var err error
				p, err = lc.NewPreparedLegacyApproval(data)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := n.Prepare(p); err == nil {
				t.Fatal("bad preparation accepted")
			}
			if len(api.snapshot()) != 0 {
				t.Fatal("preparation performed I/O")
			}
		})
	}
	for _, d := range []lc.LegacyDestination{{}, {ChatID: 1, TopicID: -1}} {
		if _, err := NewTelegramLegacyNotifier(&TelegramBackend{}, d); err == nil {
			t.Fatal("bad destination")
		}
	}
	if _, err := NewTelegramLegacyNotifier(nil, lc.LegacyDestination{ChatID: 1}); err == nil {
		t.Fatal("nil backend")
	}
}
func TestLegacyNotifierDeliveryGuards(t *testing.T) {
	for _, name := range []string{"nil", "unknown", "mismatch", "duplicate", "canceled"} {
		t.Run(name, func(t *testing.T) {
			n, api, p := legacyNotifierFixture(t)
			if name != "unknown" {
				if err := n.Prepare(p); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			switch name {
			case "nil":
				p = nil
			case "mismatch":
				d := p.Data()
				d.Payload[0].Bytes = []byte("changed")
				p, _ = lc.NewPreparedLegacyApproval(d)
			case "duplicate":
				if _, err := n.Deliver(ctx, p); err != nil {
					t.Fatal(err)
				}
				api.reset()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			report, err := n.Deliver(ctx, p)
			if err == nil || report.AllDelivered || len(api.snapshot()) != 0 {
				t.Fatalf("unsafe delivery %+v %v (%d calls)", report, err, len(api.snapshot()))
			}
		})
	}
}
func TestLegacyNotifierPartialFailure(t *testing.T) {
	for _, mode := range []string{"part", "card", "transport", "receipt"} {
		t.Run(mode, func(t *testing.T) {
			n, api, p := legacyNotifierFixture(t)
			if err := n.Prepare(p); err != nil {
				t.Fatal(err)
			}
			fail := 2
			if mode == "card" {
				fail = len(p.Data().Payload)
			}
			api.hook = func(r *http.Request, i int) (string, error) {
				if i == fail {
					switch mode {
					case "transport":
						return "", errors.New("connection reset")
					case "receipt":
						return `{"ok":true,"result":{"message_id":0}}`, nil
					default:
						return `{"ok":false,"error_code":400,"description":"rejected"}`, nil
					}
				}
				return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
			}
			report, err := n.Deliver(context.Background(), p)
			if err == nil || report.AllDelivered {
				t.Fatal("partial reported complete")
			}
			if len(api.snapshot()) != fail {
				t.Fatal("cleanup ran before failure was returned")
			}
			var cleanup interface{ MarkIncomplete(context.Context) }
			if !errors.As(err, &cleanup) {
				t.Fatal("missing incomplete cleanup")
			}
			n.Release(p.Data().Instance)
			cleanup.MarkIncomplete(context.Background())
			if len(api.snapshot()) != fail+fail-1 {
				t.Fatalf("incomplete edits: %d", len(api.snapshot()))
			}
			for _, call := range api.snapshot()[fail:] {
				if call.method != "editMessageText" || call.form.Get("text") != "INCOMPLETE — NOT APPROVABLE" || call.form.Get("chat_id") != "-42" {
					t.Fatal("bad incomplete edit")
				}
			}
			if err := n.EditStatus(context.Background(), p, "approved"); err == nil {
				t.Fatal("failed card edited as approved")
			}
		})
	}
}
func TestLegacyNotifierStatusGuards(t *testing.T) {
	n, api, p := legacyNotifierFixture(t)
	if err := n.Prepare(p); err != nil {
		t.Fatal(err)
	}
	if err := n.EditStatus(context.Background(), p, "approved"); err == nil {
		t.Fatal("undelivered edit")
	}
	if _, err := n.Deliver(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	api.reset()
	for _, status := range []string{"", "error", "arbitrary"} {
		if err := n.EditStatus(context.Background(), p, status); err == nil {
			t.Fatal("invalid status")
		}
	}
	if err := n.EditStatus(context.Background(), nil, "approved"); err == nil {
		t.Fatal("nil artifact")
	}
	d := p.Data()
	d.Context.Destination.ChatID++
	bad, _ := lc.NewPreparedLegacyApproval(d)
	if err := n.EditStatus(context.Background(), bad, "approved"); err == nil {
		t.Fatal("mismatched edit")
	}
	if len(api.snapshot()) != 0 {
		t.Fatal("invalid edit reached API")
	}
	for _, status := range []string{"denied", "expired"} {
		if err := n.EditStatus(context.Background(), p, status); err != nil {
			t.Fatal(err)
		}
	}
	api.hook = func(*http.Request, int) (string, error) {
		return `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message"}`, nil
	}
	if err := n.EditStatus(context.Background(), p, "expired"); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyNotifierCancellationAndBurst(t *testing.T) {
	n, api, p := legacyNotifierFixture(t)
	if err := n.Prepare(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api.hook = func(r *http.Request, i int) (string, error) {
		if n.backend.policyNotifyMu.TryLock() {
			n.backend.policyNotifyMu.Unlock()
			t.Error("legacy burst did not hold policy lock")
		}
		if i == 2 {
			cancel()
			return `{"ok":false,"error_code":429,"description":"retry","parameters":{"retry_after":30}}`, nil
		}
		return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
	}
	report, err := n.Deliver(ctx, p)
	if !errors.Is(err, context.Canceled) || report.AllDelivered || len(api.snapshot()) != 2 {
		t.Fatalf("cancellation: %+v %v calls=%d", report, err, len(api.snapshot()))
	}
	api.reset()
	if err := n.edit(ctx, -42, 1, "expired"); !errors.Is(err, context.Canceled) || len(api.snapshot()) != 0 {
		t.Fatal("canceled edit reached API")
	}
}

func TestLegacyNotifierEditFailure(t *testing.T) {
	n, api, p := legacyNotifierFixture(t)
	if err := n.Prepare(p); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Deliver(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	api.hook = func(*http.Request, int) (string, error) {
		return `{"ok":false,"error_code":500,"description":"failed"}`, nil
	}
	if err := n.EditStatus(context.Background(), p, "expired"); err == nil {
		t.Fatal("edit failure hidden")
	}
}

func TestLegacyNotifierFailureBeforeSlowCleanup(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, mode := range []string{"budget", "close"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n, api, p := legacyNotifierFixture(t)
				clock := elapsedtest.NewFake(time.Now())
				service, err := lc.NewLegacyService(lc.LegacyConfig{Clock: clock, LegacyNotifier: n})
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				data := p.Data()
				reservation, err := service.ReserveLegacy(context.Background(), lc.LegacyInstance{ID: data.Instance, UID: 7, RequestID: "slow-cleanup", RedactionFailed: true}, data.Snapshot, assist.Input{})
				if err != nil {
					t.Fatal(err)
				}
				data.Context = reservation.RenderContext()
				p, err = lc.NewPreparedLegacyApproval(data)
				if err != nil {
					t.Fatal(err)
				}
				if err := n.Prepare(p); err != nil {
					t.Fatal(err)
				}
				clock.Advance(sigwire.ApprovalWindow - 500*time.Millisecond)
				entered, cancelled, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseCleanup := func() { releaseOnce.Do(func() { close(release) }) }
				defer releaseCleanup()
				api.hook = func(r *http.Request, i int) (string, error) {
					if strings.HasSuffix(r.URL.Path, "/editMessageText") {
						if !n.backend.policyNotifyMu.TryLock() {
							t.Error("cleanup holds burst lock")
						} else {
							n.backend.policyNotifyMu.Unlock()
						}
						if r.Context().Err() != nil {
							t.Error("cleanup inherited the canceled request context")
						}
						close(entered)
						<-r.Context().Done()
						close(cancelled)
						<-release
						close(finished)
						return "", r.Context().Err()
					}
					if i == 2 {
						return `{"ok":false,"error_code":400,"description":"send failed"}`, nil
					}
					return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
				}
				result := make(chan lc.LegacyResult, 1)
				go func() { result <- reservation.Request().Wait() }()
				delivered := make(chan error, 1)
				go func() { delivered <- service.DeliverLegacy(reservation, p) }()
				<-entered
				synctest.Wait()
				select {
				case got := <-result:
					if got.Status != "error" {
						t.Errorf("resolved %q", got.Status)
					}
				default:
					t.Error("cleanup preceded failure resolution")
				}
				select {
				case err := <-delivered:
					if err == nil {
						t.Error("lost delivery failure")
					}
				default:
					t.Error("cleanup delayed delivery failure")
				}
				if mode == "close" {
					closed := make(chan struct{})
					go func() { _ = service.Close(); close(closed) }()
					<-cancelled
					synctest.Wait()
					select {
					case <-closed:
						t.Error("Close returned before cleanup was released")
					default:
					}
					select {
					case <-finished:
						t.Error("cleanup passed its release barrier")
					default:
					}
					releaseCleanup()
					synctest.Wait()
					select {
					case <-closed:
					default:
						t.Error("Close did not join released cleanup")
					}
				} else {
					assertActive := func() {
						t.Helper()
						synctest.Wait()
						select {
						case <-cancelled:
							t.Error("cleanup expired before its elapsed deadline")
						default:
						}
					}
					// Timers wake the supervisor; neither timer nor wall time owns expiry.
					time.Sleep(2 * time.Second)
					assertActive()
					clock.StepWall(time.Hour)
					time.Sleep(time.Second)
					assertActive()
					clock.Advance(time.Second - time.Nanosecond)
					time.Sleep(time.Second)
					assertActive()
					clock.Advance(time.Nanosecond)
					time.Sleep(time.Second)
					synctest.Wait()
					select {
					case <-cancelled:
					default:
						t.Error("cleanup exceeded its elapsed budget")
					}
					releaseCleanup()
					synctest.Wait()
				}
				select {
				case <-finished:
				default:
					t.Error("cleanup did not finish after release")
				}
				if got := reservation.Request().Wait(); got.Status != "error" {
					t.Errorf("slow cleanup changed failure to %q", got.Status)
				}
			})
		})
	}
}
