//go:build linux

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

func TestFileStorePublicCommandRecovery(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, name := range []string{"submit", "vote", "cancel", "claim", "report", "revoke", "reconcile", "shed", "delete"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", name, landed), func(t *testing.T) {
				e, clock, base, _ := fileEngineFixture(t)
				defer e.Close()
				var action func() error
				mintCalls := 0
				if name == "submit" {
					action = func() error { _, err := admissionSubmit(e, 1, st.PrincipalA); return err }
				} else if name == "revoke" {
					submitGrant(t, e, 1, st.PrincipalA)
					approve(t, e, 1)
					if len(e.projections.grants) != 1 {
						t.Fatal("grant fixture not live")
					}
					action = func() error { return e.Revoke("web-1") }
				} else {
					summary := submitJob(t, e, 1)
					switch name {
					case "vote":
						vote := readyCard(t, e, 1, true)
						action = func() error { _, err := e.Vote(vote); return err }
					case "cancel":
						action = func() error {
							_, err := e.AdminCancel(summary.RecordHandle, ap.AdminCancel{PlanHash: summary.PlanHash, Admin: st.Admin})
							return err
						}
					case "claim", "report":
						voteApprove(t, e, 1)
						flushRecord(t, e, 1)
						e.config.Minter = mintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
							mintCalls++
							return []string{fmt.Sprintf("signature-%d", mintCalls)}, nil
						})
						claim := claimOf(1, summary)
						if name == "claim" {
							action = func() error {
								answer, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
								if len(answer.Signatures) != 0 {
									t.Error("uncertain signatures released")
								}
								return err
							}
						} else {
							if _, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claim); err != nil {
								t.Fatal(err)
							}
							action = func() error {
								_, err := e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: claim.Token, PlanHash: summary.PlanHash, Body: finalBody(ap.StepSucceeded)})
								return err
							}
						}
					case "reconcile":
						clock.Advance(6 * time.Second)
						action = e.Reconcile
					case "shed", "delete":
						cancelAdmissionRecord(t, e, 1)
						if name == "shed" {
							action = func() error { _, err := e.Shed(st.PrincipalA, st.ID(1), true); return err }
						} else {
							clock.Advance(25 * time.Hour)
							action = func() error { _, err := e.Delete(st.PrincipalA, st.ID(1), true); return err }
						}
					}
				}
				before, loadErr := base.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				if loadErr != nil && name != "submit" {
					t.Fatal(loadErr)
				}
				oldEpoch := e.epoch
				fault := func() error { return securestate.ErrCommitUncertain }
				if landed {
					base.afterStoreUpdate = fault
				} else {
					base.beforeStoreUpdate = fault
				}
				checkCode(t, action(), ap.CodeStorageUncertain)
				assertFileEngineStopped(t, e)
				base.beforeStoreUpdate, base.afterStoreUpdate = nil, nil
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
				if err := base.Reopen(); err != nil {
					t.Fatal(err)
				}
				key := ap.RecordKey(st.PrincipalA, st.ID(1))
				after, err := base.Load(key)
				if name == "delete" && landed {
					if !errors.Is(err, ErrNotFound) {
						t.Fatal("delete not recovered", err)
					}
				} else if name == "submit" && !landed {
					if !errors.Is(err, ErrNotFound) {
						t.Fatal("uninstalled submit recovered", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if !landed && !reflect.DeepEqual(before, after) {
						t.Fatal("uninstalled mutation changed disk")
					}
					if landed && reflect.DeepEqual(before, after) {
						t.Fatal("installed mutation missing")
					}
					if landed {
						switch name {
						case "vote":
							if after.Header.Decision == nil || after.Header.Decision.Status != ap.ApprovalApproved {
								t.Fatal("vote outcome missing")
							}
						case "cancel":
							if after.Header.Decision == nil || after.Header.Decision.Status != ap.ApprovalCanceled {
								t.Fatal("cancel outcome missing")
							}
						case "claim":
							if after.Header.Mint == nil || !reflect.DeepEqual(after.Payload.Signatures, []string{"signature-1"}) {
								t.Fatal("mint outcome missing")
							}
						case "report":
							if after.Header.FinalReport == nil || len(after.Payload.Signatures) != 0 {
								t.Fatal("report outcome missing")
							}
						case "revoke":
							if after.Header.RevokedAt == nil {
								t.Fatal("revoke outcome missing")
							}
						case "reconcile":
							if after.Header.Assist == nil {
								t.Fatal("clock outcome missing")
							}
						case "shed":
							if after.Payload != nil {
								t.Fatal("shed outcome missing")
							}
						}
					}
				}
				e, err = New(e.config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.Close() })
				if e.epoch == oldEpoch || len(e.projections.grants) != 0 {
					t.Fatal("recovery retained authority")
				}
				switch name {
				case "vote", "cancel", "revoke", "shed":
					if err := action(); err != nil {
						t.Fatal("retry", err)
					}
				case "reconcile":
					if err := e.Reconcile(); err != nil {
						t.Fatal("retry", err)
					}
				case "submit":
					if _, err := admissionSubmit(e, 1, st.PrincipalA); err != nil {
						t.Fatal(err)
					}
				case "claim", "report":
					flushRecord(t, e, 1)
					sum, err := e.Get(st.PrincipalA, st.ID(1))
					if err != nil {
						t.Fatal(err)
					}
					expectedMints := 1
					if name == "claim" && !landed {
						expectedMints = 2
					}
					first, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
					if err != nil {
						t.Fatal(err)
					}
					second, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
					expectedSignatures := []string{fmt.Sprintf("signature-%d", mintCalls)}
					if name == "report" && landed {
						expectedSignatures = nil
						if first.Claim != ap.ClaimExecutionReported || second.Claim != ap.ClaimExecutionReported {
							t.Fatal("reported execution lost", first, second)
						}
					}
					if err != nil || !reflect.DeepEqual(first.Signatures, second.Signatures) || !reflect.DeepEqual(first.Signatures, expectedSignatures) {
						t.Fatal("signature identity changed", first, second, err)
					}
					if mintCalls != expectedMints {
						t.Fatal("unexpected remint", mintCalls, expectedMints)
					}
					if name == "report" {
						_, err := e.Report(st.PrincipalA, st.ID(1), ap.Report{Token: st.Token(st.ID(1)), PlanHash: sum.PlanHash, Body: finalBody(ap.StepSucceeded)})
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func assertFileEngineStopped(t *testing.T, e *Engine) {
	t.Helper()
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for _, call := range stoppedCalls(e) {
				var code *ap.CodeError
				if err := call(); !errors.As(err, &code) || code.Code != ap.CodeStorageUncertain {
					t.Errorf("stopped engine: %v", err)
				}
			}
		}()
	}
	group.Wait()
	if e.effectContext.Err() == nil {
		t.Fatal("effect context remains live")
	}
}

func TestFileStoreClockFirstVoteRecovery(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			e, clock, s, _ := fileEngineFixture(t)
			submitJob(t, e, 1)
			tap := readyCard(t, e, 1, true)
			before, err := e.Get(st.PrincipalA, st.ID(1))
			if err != nil || before.ApprovalStatus != ap.ApprovalPending {
				t.Fatal(before, err)
			}
			rec, err := s.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
			if err != nil {
				t.Fatal(err)
			}
			clock.Advance(rec.Header.RequestExpiresAt.Sub(clock.Wall()) + time.Second)
			fault := func() error { return securestate.ErrCommitUncertain }
			if landed {
				s.afterStoreUpdate = fault
			} else {
				s.beforeStoreUpdate = fault
			}
			_, err = e.Vote(tap)
			checkCode(t, err, ap.CodeStorageUncertain)
			assertFileEngineStopped(t, e)
			s.beforeStoreUpdate, s.afterStoreUpdate = nil, nil
			clock.StepWall(-3 * time.Minute)
			e = restartFileEngine(t, e, s)
			got, err := e.Get(st.PrincipalA, st.ID(1))
			if err != nil {
				t.Fatal(err)
			}
			want := ap.ApprovalPending
			if landed {
				want = ap.ApprovalExpired
			}
			if got.ApprovalStatus != want {
				t.Fatal("wrong clock prefix", got.ApprovalStatus, want)
			}
			answer, err := e.Vote(tap)
			if err != nil || answer.Noise != landed {
				t.Fatal("retap", answer, err)
			}
		})
	}
}

func TestFileStorePoisonJoinsHeldTransport(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, stage := range []string{"parts", "edit"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/landed=%t", stage, landed), func(t *testing.T) {
				e, _, s, _ := fileEngineFixture(t)
				submitJob(t, e, 1)
				if stage == "edit" {
					prepareCloseCard(t, e)
					command(t, e, 1, ap.AssistDone{Unavailable: "test"})
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(release) })
				calls := 0
				hold := func() error {
					calls++
					if calls != 1 {
						t.Error("post-stop transport")
						return errors.New("unexpected")
					}
					close(entered)
					<-release
					return errors.New("transport lost")
				}
				n := &testNotifier{incomplete: func(int64) { t.Error("INCOMPLETE after poison") }, status: func(string) { t.Error("status after poison") }, card: func(Notification) (int64, error) { t.Error("card after poison"); return 0, nil }}
				if stage == "parts" {
					n.parts = func(Notification) ([]int64, error) { return []int64{1}, hold() }
				} else {
					n.edit = func(Notification) (EditOutcome, error) { return EditConfirmed, hold() }
				}
				e.config.Notifier = n
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- e.Run(ctx) }()
				receiveNotify(t, entered)
				e.mu.Lock()
				fault := func() error { return securestate.ErrCommitUncertain }
				if landed {
					s.afterStoreUpdate = fault
				} else {
					s.beforeStoreUpdate = fault
				}
				e.mu.Unlock()
				_, err := admissionSubmit(e, 2, st.PrincipalA)
				checkCode(t, err, ap.CodeStorageUncertain)
				assertFileEngineStopped(t, e)
				select {
				case <-done:
					t.Fatal("Run returned before transport joined")
				default:
				}
				once.Do(func() { close(release) })
				checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
				if calls != 1 {
					t.Fatal("additional call", calls)
				}
				s.beforeStoreUpdate, s.afterStoreUpdate = nil, nil
				e = restartFileEngine(t, e, s)
				key := ap.RecordKey(st.PrincipalA, st.ID(1))
				rec, err := s.Load(key)
				if err != nil {
					t.Fatal(err)
				}
				if stage == "parts" {
					if ap.View(rec, e.now(), e.epoch, e.config.Settings, false).NotificationStatus != ap.NotificationUncertain || ap.NotifyNext(rec, e.now(), e.epoch, e.config.Settings).Kind == ap.NotifyBurst {
						t.Fatal("interrupted burst replayed")
					}
				} else {
					actor := &notifyActor{engine: e, key: key}
					after, _, ok, err := actor.startCard(context.Background(), true)
					if err != nil || !ok || len(after.Payload.CardEntries) != 3 || !after.Payload.CardEntries[1].Retired {
						t.Fatal("edit not superseded once", err)
					}
					if ap.NotifyNext(after, e.now(), e.epoch, e.config.Settings).Kind != ap.NotifyEditRetry {
						t.Fatal("replacement edit not current")
					}
				}
			})
		}
	}
}
