package lifecycletest

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func schedules(t *testing.T, factory StoreFactory) {
	for seed := uint64(1); seed <= 16; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			f := newFixture(t, factory)
			rec := recoveryTrace(t)[7]
			key := ap.RecordKey(st.PrincipalA, st.ID(1))
			if err := f.store.Store.Commit(key, rec); err != nil {
				t.Fatal(err)
			}
			f.store.reservations[key] = ap.R1Reservation(rec)
			f.open()
			random := rand.New(rand.NewPCG(seed, 19))
			for turn := 0; turn < 64; turn++ {
				var err error
				switch random.IntN(9) {
				case 0:
					before, count := f.record(), f.store.count()
					_, err = f.engine.Get(st.PrincipalA, st.ID(1))
					if !reflect.DeepEqual(before, f.record()) || count != f.store.count() {
						t.Fatal("view wrote")
					}
				case 1:
					f.clock.StepWall(time.Duration(random.IntN(7201)-3600) * time.Second)
				case 2:
					f.clock.Suspend(time.Duration(random.IntN(600)) * time.Second)
				case 3:
					err = f.engine.Reconcile()
				case 4:
					before := f.record()
					vote := ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: "mnopqrstuvwx", Challenge: "fedcba9876543210", MsgID: 4}}
					if random.IntN(2) == 0 {
						vote.Decision = ap.VoteDeny
					}
					answer, voteErr := f.engine.Vote(vote)
					err = voteErr
					after := f.record()
					if answer.Noise {
						delta := after.Header.OutboxSeq - before.Header.OutboxSeq + after.Header.NoiseDropped - before.Header.NoiseDropped
						// Clock may add facts in this same commit; count only replay events.
						noise := uint64(0)
						for _, event := range after.Header.Outbox {
							if event.Seq > before.Header.OutboxSeq && event.Replay {
								noise++
							}
						}
						if noise+after.Header.NoiseDropped-before.Header.NoiseDropped != 1 || delta == 0 {
							t.Fatal("refused/replayed vote lost its noise event")
						}
					} else if after.Header.Decision != nil && before.Header.Decision == nil && ap.Decide(ap.EffectivePolicy(after, ap.LocalVoteFlags), after.Header.Votes) != after.Header.Decision.Status {
						t.Fatal("decision did not use authoritative policy")
					}
				case 5:
					_, err = f.engine.AdminCancel(ap.RecordHandle(key), ap.AdminCancel{Admin: st.Admin, PlanHash: rec.Header.PlanHash})
				case 6:
					_, err = f.engine.Report(st.PrincipalA, st.ID(1), ap.Report{})
				case 7:
					f.engine.Close()
					f.open()
				case 8:
					err = f.engine.Revoke("web-1")
				}
				var code *ap.CodeError
				if err != nil && !errors.As(err, &code) {
					t.Fatalf("turn %d: %v", turn, err)
				}
			}
		})
	}
}
