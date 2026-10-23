package backend

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"go.uber.org/goleak"
)

func releaseVote(t *testing.T, f *callbackFixture, artifact *lc.PreparedLegacyApproval) {
	t.Helper()
	c := artifact.Data().Context
	result, err := f.runtime.legacy.VoteLegacy(ap.CastVote{Operator: "telegram:42", Decision: ap.VoteApprove, Card: &ap.CardTap{Handle: c.Handle, Challenge: c.Challenge}}, func(lc.LegacyTapResult) {})
	if err != nil || !result.Resolved {
		t.Fatalf("vote: %+v %v", result, err)
	}
}

func releaseCounts(t *testing.T, n *TelegramLegacyNotifier, entries int) {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.entries) != entries || len(n.bindings) > 256 || len(n.retired) > 256 {
		t.Fatalf("entries=%d bindings=%d retired=%d; want entries=%d and bounded bindings", len(n.entries), len(n.bindings), len(n.retired), entries)
	}
}

func TestLegacyOwnerRelease(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, mode := range []string{"completed", "cancelled", "abandoned", "late_prepare", "shutdown", "caller_cancel"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				n := f.backend.approvalCallbacks.legacy
				for i := 1; i <= 270; i++ {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					_, _, seed := legacyNotifierFixture(t)
					reservation, err := f.runtime.legacy.ReserveLegacy(ctx, lc.LegacyInstance{ID: fmt.Sprintf("%032x", i), UID: 1000, RequestID: fmt.Sprintf("release-%d", i), RedactionFailed: true}, seed.Data().Snapshot, assist.Input{})
					if err != nil {
						t.Fatal(err)
					}
					data := seed.Data()
					data.Instance = fmt.Sprintf("%032x", i)
					data.Context = reservation.RenderContext()
					artifact, err := lc.NewPreparedLegacyApproval(data)
					if err != nil {
						t.Fatal(err)
					}
					if err := n.Prepare(artifact); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "completed":
						if err := f.runtime.legacy.DeliverLegacy(reservation, artifact); err != nil {
							t.Fatal(err)
						}
						releaseVote(t, f, artifact)
					case "caller_cancel":
						cancel()
					case "cancelled":
						f.runtime.legacy.CancelLegacy(reservation)
					case "abandoned":
						if err := f.runtime.legacy.DeliverLegacy(reservation, nil); err == nil {
							t.Fatal("accepted missing artifact")
						}
					case "late_prepare":
						f.runtime.legacy.CancelLegacy(reservation)
						synctest.Wait()
						if err := n.Prepare(artifact); err != nil {
							t.Fatal(err)
						}
						f.runtime.legacy.CancelLegacy(reservation)
					}
					if mode != "shutdown" {
						cancel()
						synctest.Wait()
						releaseCounts(t, n, 0)
					}
				}
				if mode == "completed" {
					edits := 0
					for _, call := range f.api.snapshot() {
						if call.method == "editMessageText" {
							edits++
							if !strings.HasSuffix(call.form.Get("text"), "Approval: approved") {
								t.Fatal("missing terminal status")
							}
						}
					}
					n.mu.Lock()
					bindings, retired := len(n.bindings), len(n.retired)
					n.mu.Unlock()
					if bindings != 256 || retired != 256 {
						t.Fatalf("retained bindings=%d retired=%d, want 256", bindings, retired)
					}
					if edits != 270 {
						t.Fatalf("terminal edits=%d", edits)
					}
				}
				if err := f.runtime.legacy.Close(); err != nil {
					t.Fatal(err)
				}
				releaseCounts(t, n, 0)
			})
		})
	}
}

func TestLegacyOwnerReleaseWaitsForIO(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, mode := range []string{"delivery", "edit", "edit_error"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCallbackFixture(t)
				n := f.backend.approvalCallbacks.legacy
				reservation, artifact := f.prepareLegacy(t, 1)
				entered, finish := make(chan struct{}), make(chan struct{})
				releaseIO := sync.OnceFunc(func() { close(finish) })
				defer releaseIO()
				f.api.hook = func(r *http.Request, i int) (string, error) {
					if (mode == "delivery" && i == 1) || (mode != "delivery" && strings.HasSuffix(r.URL.Path, "/editMessageText")) {
						close(entered)
						<-finish
						if mode == "edit_error" {
							return "", fmt.Errorf("edit failed")
						}
					}
					return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, i), nil
				}
				var delivered chan error
				if mode == "delivery" {
					delivered = make(chan error, 1)
					go func() { delivered <- f.runtime.legacy.DeliverLegacy(reservation, artifact) }()
				} else {
					if err := f.runtime.legacy.DeliverLegacy(reservation, artifact); err != nil {
						t.Fatal(err)
					}
					releaseVote(t, f, artifact)
				}
				<-entered
				f.runtime.legacy.CancelLegacy(reservation)
				closed := make(chan error, 1)
				go func() { closed <- f.runtime.legacy.Close() }()
				synctest.Wait()
				releaseCounts(t, n, 1)
				select {
				case err := <-closed:
					t.Fatalf("Close returned before I/O settled: %v", err)
				default:
				}
				releaseIO()
				if delivered != nil {
					if err := <-delivered; err == nil {
						t.Fatal("cancelled delivery succeeded")
					}
				}
				if err := <-closed; err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				releaseCounts(t, n, 0)
			})
		})
	}
}
