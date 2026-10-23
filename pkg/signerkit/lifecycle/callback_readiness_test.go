package lifecycle

import (
	"context"
	"testing"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func TestCallbackReadinessCommittedTransitions(t *testing.T) {
	for _, outcome := range []string{"sent", "send_failed", "edit_confirmed", "edit_failed", "retired", "closed"} {
		t.Run(outcome, func(t *testing.T) {
			e, _, _, _ := engineFixture(t)
			defer e.Close()
			summary := submitGrant(t, e, 1, st.PrincipalA)
			command(t, e, 1, ap.BurstStart{})
			command(t, e, 1, ap.BurstDone{PartMsgIDs: []int64{1}})
			handle, challenge := "abcdefghijkl", "0123456789abcdef"
			command(t, e, 1, ap.CardStart{Handle: handle, ChalHash: ap.ChallengeHash(challenge)})
			if outcome == "edit_confirmed" || outcome == "edit_failed" {
				command(t, e, 1, ap.CardDone{Handle: handle, MsgID: 2})
				command(t, e, 1, ap.AssistDone{Unavailable: "test unavailable"})
				handle = "mnopqrstuvwx"
				command(t, e, 1, ap.EditStart{Handle: handle, ChalHash: ap.ChallengeHash(challenge)})
			}
			key := ap.RecordKey(st.PrincipalA, st.ID(1))
			e.notifyActors = map[string]*notifyActor{key: {engine: e, key: key}}
			if handle != "abcdefghijkl" {
				old, err := e.CallbackReadiness("abcdefghijkl", challenge)
				if err != nil || old.Pending {
					t.Fatalf("superseded handle: %+v %v", old, err)
				}
			}
			state, err := e.CallbackReadiness(handle, challenge)
			if err != nil || !state.Pending || state.Changed == nil {
				t.Fatalf("pending: %+v %v", state, err)
			}
			wrong, err := e.CallbackReadiness(handle, "fedcba9876543210")
			if err != nil || wrong.Pending {
				t.Fatalf("wrong challenge: %+v %v", wrong, err)
			}

			epoch := e.epoch
			e.epoch = "ffffffffffffffffffffffffffffffff"
			foreign, err := e.CallbackReadiness(handle, challenge)
			e.epoch = epoch
			if err != nil || foreign.Pending {
				t.Fatalf("foreign generation: %+v %v", foreign, err)
			}
			select {
			case <-state.Changed:
				t.Fatal("ready before commit")
			default:
			}
			switch outcome {
			case "sent", "send_failed":
				command(t, e, 1, ap.CardDone{Handle: handle, MsgID: 2, Failed: outcome == "send_failed"})
			case "edit_confirmed", "edit_failed":
				command(t, e, 1, ap.EditDone{Handle: handle, Failed: outcome == "edit_failed"})
			case "retired":
				command(t, e, 1, ap.AdminCancel{Admin: st.Admin, PlanHash: summary.PlanHash})
			case "closed":
				e.Close()
			}
			if outcome == "closed" {
				select {
				case <-state.Closed:
				default:
					t.Fatal("close not signaled")
				}
				return
			}
			select {
			case <-state.Changed:
			default:
				t.Fatal("commit not signaled")
			}
			state, err = e.CallbackReadiness(handle, challenge)
			if state.Decision != "" {
				t.Fatalf("undelivered decision: %q", state.Decision)
			}
			if err != nil || state.Pending {
				t.Fatalf("still pending: %+v %v", state, err)
			}
		})
	}
}

func TestLegacyCallbackReadinessDelivery(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "failed"}[fail], func(t *testing.T) {
			e, n := preparedFixture(t)
			r := reservePrepared(t, e, 1)
			n.artifact = preparedArtifact(t, r)
			var state CallbackReadiness
			n.deliver = func(context.Context, *PreparedLegacyApproval) (LegacyDelivery, error) {
				var err error
				c := r.RenderContext()
				state, err = e.legacy.CallbackReadiness(c.Handle, c.Challenge)
				if state.Destination != c.Destination {
					t.Fatal("destination lost")
				}
				if err != nil || !state.Pending || state.Changed == nil || state.Destination != c.Destination {
					t.Fatalf("pending: %+v %v", state, err)
				}
				wrong, _ := e.legacy.CallbackReadiness(c.Handle, "fedcba9876543210")
				if wrong.Pending {
					t.Fatal("wrong challenge waits")
				}
				select {
				case <-state.Changed:
					t.Fatal("ready before delivery")
				default:
				}
				return LegacyDelivery{AllDelivered: !fail}, nil
			}
			err := e.DeliverLegacy(r, n.artifact)
			if (err != nil) != fail {
				t.Fatalf("delivery: %v", err)
			}
			select {
			case <-state.Changed:
			default:
				t.Fatal("delivery not signaled")
			}
			c := r.RenderContext()
			state, err = e.legacy.CallbackReadiness(c.Handle, c.Challenge)
			if state.Destination != c.Destination {
				t.Fatal("destination lost")
			}
			if err != nil || state.Pending {
				t.Fatalf("still pending: %+v %v", state, err)
			}
		})
	}
}

type terminalLegacyNotifier struct {
	*preparedNotifier
	statuses chan string
}

func (n *terminalLegacyNotifier) EditStatus(_ context.Context, _ *PreparedLegacyApproval, status string) error {
	n.statuses <- status
	return nil
}

func TestLegacyTerminalEditOnce(t *testing.T) {
	for _, status := range []string{"approved", "denied", "expired", "undelivered", "failed"} {
		t.Run(status, func(t *testing.T) {
			e, n := preparedFixture(t)
			notifier := &terminalLegacyNotifier{preparedNotifier: n, statuses: make(chan string, 4)}
			e.legacy.config.LegacyNotifier = notifier
			r := reservePrepared(t, e, 1)
			n.artifact = preparedArtifact(t, r)
			if status == "failed" {
				n.deliver = func(context.Context, *PreparedLegacyApproval) (LegacyDelivery, error) { return LegacyDelivery{}, nil }
				if err := e.DeliverLegacy(r, n.artifact); err == nil {
					t.Fatal("failed delivery accepted")
				}
			} else if status != "undelivered" {
				if err := e.DeliverLegacy(r, n.artifact); err != nil {
					t.Fatal(err)
				}
			}
			if status == "approved" || status == "denied" {
				vote := reservationVote(r)
				if status == "denied" {
					vote.Decision = ap.VoteDeny
				}
				for i := 0; i < 2; i++ {
					if _, err := e.legacy.VoteLegacy(vote, func(LegacyTapResult) {}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := e.legacy.Close(); err != nil {
				t.Fatal(err)
			}
			if status == "undelivered" || status == "failed" {
				if len(notifier.statuses) != 0 {
					t.Fatal("edited undelivered card")
				}
			} else {
				if len(notifier.statuses) != 1 {
					t.Fatalf("edits: %d", len(notifier.statuses))
				}
				if got := <-notifier.statuses; got != status {
					t.Fatalf("status %q", got)
				}
			}
		})
	}
}

func TestCallbackReadinessDecisionBinding(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	defer e.Close()
	submitGrant(t, e, 1, st.PrincipalA)
	approve(t, e, 1)
	for _, challenge := range []string{"0123456789abcdef", "fedcba9876543210"} {
		state, err := e.CallbackReadiness("abcdefghijkl", challenge)
		if err != nil {
			t.Fatal(err)
		}
		if state.Pending {
			t.Fatal("resolved card pending")
		}
		if challenge == "0123456789abcdef" {
			if state.Decision != string(ap.ApprovalApproved) || state.MessageID != 2 {
				t.Fatalf("bound decision: %+v", state)
			}
		} else if state.Decision != "" || state.MessageID != 0 {
			t.Fatalf("unbound decision: %+v", state)
		}
	}
	e.epoch = "ffffffffffffffffffffffffffffffff"
	state, err := e.CallbackReadiness("abcdefghijkl", "0123456789abcdef")
	if err != nil || state.Decision != string(ap.ApprovalApproved) || state.MessageID != 2 {
		t.Fatalf("recovered delivered replay: %+v %v", state, err)
	}
}
