package lifecycletest

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// recoveryTrace enumerates the write-ahead cuts, including both edit revisions
// and a separately authorized renotify. Pure commands create fixtures only;
// every recovery and external effect runs through the real lifecycle owner.
func recoveryTrace(t *testing.T) []ap.R1 {
	t.Helper()
	now := ap.Now{Wall: st.T0}
	in := ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings}
	commands := []ap.Command{
		st.SubmitOf(draft(st.T0), st.PrincipalA, st.T0, time.Hour),
		ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{1, 2, 3}},
		ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")},
		ap.CardDone{Handle: "abcdefghijkl", MsgID: 4},
		ap.AssistDone{Unavailable: "test unavailable"},
		ap.EditStart{Handle: "mnopqrstuvwx", ChalHash: ap.ChallengeHash("fedcba9876543210")},
		ap.EditDone{Handle: "mnopqrstuvwx"},
		ap.Renotify{}, ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{5, 6, 7}},
		ap.CardStart{Handle: "yzabcdefghij", ChalHash: ap.ChallengeHash("1234567890abcdef")},
		ap.CardDone{Handle: "yzabcdefghij", MsgID: 8},
		ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: "yzabcdefghij", Challenge: "1234567890abcdef", MsgID: 8}},
	}
	var rec *ap.R1
	var trace []ap.R1
	for _, cmd := range commands {
		next, answer := ap.Apply(rec, cmd, now, in)
		if answer.Code != "" || !answer.Changed {
			t.Fatalf("fixture %T: %+v", cmd, answer)
		}
		if err := st.CheckTransition(rec, next, now); err != nil {
			t.Fatal(err)
		}
		trace = append(trace, next)
		rec = &next
	}
	return trace
}

func crashPrefixes(t *testing.T, factory StoreFactory) {
	trace := recoveryTrace(t)
	rec := trace[len(trace)-1]
	in := ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings, Minted: []string{st.Sig(st.ID(1), 1, 1)}}
	for _, cmd := range []ap.Command{ap.Flush{Through: rec.Header.OutboxSeq}, ap.Claim{Token: st.Token(st.ID(1)), PlanHash: rec.Header.PlanHash}} {
		next, answer := ap.Apply(&rec, cmd, ap.Now{Wall: st.T0}, in)
		if answer.Code != "" || !answer.Changed {
			t.Fatalf("claim prefix: %+v", answer)
		}
		trace = append(trace, next)
		rec = next
	}
	for cut := 1; cut <= len(trace); cut++ {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("commit_%02d/landed_%t", cut, landed), func(t *testing.T) {
				prefix := cut
				if !landed {
					prefix--
				}
				f := newFixture(t, factory)
				if prefix == 0 {
					f.open()
					if list, err := f.engine.List(st.PrincipalA); err != nil || len(list) != 0 {
						t.Fatal("unlanded Submit appeared")
					}
					return
				}
				before := trace[prefix-1]
				if err := f.store.Store.Commit(ap.RecordKey(st.PrincipalA, st.ID(1)), before); err != nil {
					t.Fatal(err)
				}
				f.store.reservations[ap.RecordKey(st.PrincipalA, st.ID(1))] = ap.R1Reservation(before)
				before = f.record()
				n := &notifier{}
				var mints atomic.Int32
				f.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, _ time.Time) ([]string, error) {
					mints.Add(1)
					return []string{st.Sig(p.RequestID, 1, 2)}, nil
				})
				f.config.Notifier = n
				f.config.AuditWriter = auditFunc(func(context.Context, ap.AuditMetadata) error { return nil })
				f.open()
				// No wall deadline is due. Startup must preserve the entire durable cut.
				if !reflect.DeepEqual(before, f.record()) {
					t.Fatal("Startup contradicted a landed fact")
				}
				step := ap.NotifyNext(before, ap.Now{Wall: st.T0}, st.Epoch(99), ap.LocalSettings)
				f.run()
				eventually(t, func() bool {
					r := f.record()
					return recoveredNotification(before, r, step.Kind) && r.Header.AuditedThrough == r.Header.OutboxSeq && ap.NotifyNext(r, ap.Now{Wall: st.T0}, st.Epoch(99), ap.LocalSettings).Kind == ap.NotifyNone
				})
				after := f.record()
				wantParts, wantCards := 0, 0
				if step.Kind == ap.NotifyBurst {
					wantParts, wantCards = 1, 1
				}
				if step.Kind == ap.NotifyCard {
					wantCards = 1
				}
				if n.count("parts") != wantParts || n.count("card") != wantCards {
					t.Fatalf("send replay/lost driver: step=%s parts=%d cards=%d", step.Kind, n.count("parts"), n.count("card"))
				}
				if step.Kind == ap.NotifyEdit && n.count("edit") != 1 {
					t.Fatal("interrupted edit had no superseding driver")
				}
				if step.Kind == ap.NotifyStatus && n.count("status") != 1 {
					t.Fatal("status edit was not recovered")
				}
				seen := map[int]bool{}
				for _, burst := range after.Payload.Bursts {
					if seen[burst.Gen] || burst.Gen > after.Header.RenotifyGen {
						t.Fatal("burst lacked a distinct committed authorization")
					}
					seen[burst.Gen] = true
				}
				for _, card := range after.Payload.CardEntries {
					if card.Kind != ap.CardEdit && card.MsgID != nil && card.Outcome != ap.OutcomeSent {
						t.Fatal("message ID without sent outcome")
					}
				}
				if err := st.CheckTransition(&before, after, ap.Now{Wall: st.T0}); err != nil {
					t.Fatal(err)
				}
				if after.Header.Decision != nil && after.Header.Decision.Status == ap.ApprovalApproved {
					claim := ap.Claim{Token: st.Token(st.ID(1)), PlanHash: after.Header.PlanHash}
					first, err := f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
					if err != nil || first.Claim != ap.ClaimSignatures {
						t.Fatalf("recovered Claim: %+v %v", first, err)
					}
					second, err := f.engine.Claim(context.Background(), st.PrincipalA, st.ID(1), claim)
					if err != nil || !reflect.DeepEqual(first.Signatures, second.Signatures) {
						t.Fatal("restart released two signature sets")
					}
					if before.Header.Mint != nil {
						if mints.Load() != 0 || !reflect.DeepEqual(before.Payload.Signatures, first.Signatures) {
							t.Fatal("landed mint was repeated")
						}
					} else if mints.Load() != 1 {
						t.Fatal("first claim did not mint once")
					}
				}
			})
		}
	}
}

func recoveredNotification(before, after ap.R1, kind ap.NotifyKind) bool {
	switch kind {
	case ap.NotifyBurst, ap.NotifyCard:
		cards := after.Payload.CardEntries
		return len(cards) > len(before.Payload.CardEntries) && cards[len(cards)-1].Outcome == ap.OutcomeSent
	case ap.NotifyEdit:
		cards := after.Payload.CardEntries
		return len(cards) > len(before.Payload.CardEntries) && cards[len(cards)-1].Confirmed
	case ap.NotifyStatus:
		return len(after.Payload.StatusEdits) > len(before.Payload.StatusEdits)
	default:
		return true
	}
}
