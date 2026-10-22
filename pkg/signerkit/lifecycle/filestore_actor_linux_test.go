//go:build linux

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

func TestFileStoreActorCommitFaults(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, stage := range []string{"burst-start", "burst-done", "card-start", "card-done", "edit-start", "edit-done", "status-done", "flush", "assist", "clock"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%v", stage, landed), func(t *testing.T) {
				e, clock, s, _ := fileEngineFixture(t)
				submitJob(t, e, 1)
				if stage == "card-start" || stage == "card-done" {
					command(t, e, 1, ap.BurstStart{})
					command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1, 2}})
				}
				if stage == "edit-start" || stage == "edit-done" || stage == "status-done" {
					tap := readyCard(t, e, 1, stage == "status-done")
					if stage == "status-done" {
						if answer, err := e.Vote(tap); err != nil || answer.Noise {
							t.Fatal("status fixture vote", answer, err)
						}
					} else {
						command(t, e, 1, ap.AssistDone{Unavailable: "test"})
					}
				}
				arm := func() {
					fault := func() error { return securestate.ErrCommitUncertain }
					if landed {
						s.afterStoreUpdate = fault
					} else {
						s.beforeStoreUpdate = fault
					}
				}
				calls := 0
				n := &testNotifier{
					parts: func(Notification) ([]int64, error) {
						calls++
						if stage != "burst-done" {
							t.Error("unexpected parts call")
						}
						arm()
						return []int64{1, 2}, nil
					},
					card: func(Notification) (int64, error) {
						calls++
						if stage != "card-done" {
							t.Error("unexpected card call")
						}
						arm()
						return 3, nil
					},
					edit: func(Notification) (EditOutcome, error) {
						calls++
						if stage != "edit-done" {
							t.Error("unexpected edit call")
						}
						arm()
						return EditConfirmed, nil
					},
					status: func(string) {
						calls++
						if stage != "status-done" {
							t.Error("unexpected status call")
						}
						arm()
					},
					incomplete: func(int64) { t.Error("incomplete edit after uncertain commit") },
				}
				e.config.Notifier = n
				if stage == "burst-start" || stage == "card-start" || stage == "edit-start" {
					arm()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				actor := &notifyActor{engine: e, key: ap.RecordKey(st.PrincipalA, st.ID(1)), nudge: make(chan struct{}, 1)}
				done := make(chan error, 1)
				var eventKeys []string
				if stage == "flush" {
					e.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error {
						eventKeys = append(eventKeys, event.EventKey)
						arm()
						return nil
					})
					go func() { _, err := e.flushPass(ctx); done <- err }()
				} else if stage == "assist" {
					arm()
					go func() {
						e.mu.Lock()
						_, err := e.finishAssistLocked(actor.key, assist.Snapshot{Reason: assist.ReasonFailed})
						e.mu.Unlock()
						done <- err
					}()
				} else if stage == "clock" {
					clock.Advance(10 * time.Second)
					arm()
					go func() { done <- e.Reconcile() }()
				} else {
					go func() { done <- e.Run(ctx) }()
				}
				select {
				case err := <-done:
					checkCode(t, err, ap.CodeStorageUncertain)
				case <-ctx.Done():
					t.Fatal("actor self-joined or did not stop")
				}
				assertFileEngineStopped(t, e)
				if stage != "flush" {
					expected := 0
					if stage == "burst-done" || stage == "card-done" || stage == "edit-done" || stage == "status-done" {
						expected = 1
					}
					if calls != expected {
						t.Fatalf("transport calls=%d want %d", calls, expected)
					}
				}
				s.beforeStoreUpdate, s.afterStoreUpdate = nil, nil
				recovered := restartFileEngine(t, e, s)
				rec, err := s.Load(actor.key)
				if err != nil {
					t.Fatal(err)
				}
				switch stage {
				case "burst-start", "burst-done":
					// A landed BurstDone is known sent; an unacknowledged BurstStart is uncertain.
					if len(rec.Payload.Bursts) > 0 && !(stage == "burst-done" && landed) && ap.View(rec, recovered.now(), recovered.epoch, recovered.config.Settings, false).NotificationStatus != ap.NotificationUncertain {
						t.Fatal("unfinished send not uncertain", rec.Payload.Bursts)
					}
					if len(rec.Payload.Bursts) > 0 && ap.NotifyNext(rec, recovered.now(), recovered.epoch, recovered.config.Settings).Kind == ap.NotifyBurst {
						t.Fatal("recovery resends parts")
					}
				case "card-start", "card-done":
					if (stage == "card-start" && landed) || (stage == "card-done" && !landed) {
						if ap.View(rec, recovered.now(), recovered.epoch, recovered.config.Settings, false).NotificationStatus != ap.NotificationUncertain || ap.NotifyNext(rec, recovered.now(), recovered.epoch, recovered.config.Settings).Kind == ap.NotifyCard {
							t.Fatal("recovery did not suppress uncertain card")
						}
					}
				case "status-done":
					if (len(rec.Payload.StatusEdits) == 1) != landed {
						t.Fatal("status acknowledgement prefix changed")
					}
				case "edit-start", "edit-done":
					if len(rec.Payload.CardEntries) > 1 && !(stage == "edit-done" && landed) {
						nextActor := &notifyActor{engine: recovered, key: actor.key}
						after, _, ok, err := nextActor.startCard(context.Background(), true)
						if err != nil || !ok || len(after.Payload.CardEntries) != 3 || !after.Payload.CardEntries[1].Retired {
							t.Fatal("old edit not superseded once", err)
						}
					}
				case "flush":
					var replay []string
					recovered.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error {
						replay = append(replay, event.EventKey)
						return nil
					})
					if _, err := recovered.flushPass(context.Background()); err != nil {
						t.Fatal(err)
					}
					if !landed && (len(replay) == 0 || replay[0] != eventKeys[0]) {
						t.Fatal("outbox replay lost event identity")
					}
					if landed && len(replay) != 0 {
						t.Fatal("confirmed flush replayed")
					}
				}
			})
		}
	}
}

func TestFileStoreNonUncertainFailureKeepsCache(t *testing.T) {
	_, _, s, _ := fileEngineFixture(t)
	key, rec := fileRecordFixture(t)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("before transaction")
	s.beforeStoreUpdate = func() error { return fault }
	if err := s.Commit(key, rec); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := s.Load(key); err != nil {
		t.Fatal("ordinary failure poisoned store", err)
	}
}
