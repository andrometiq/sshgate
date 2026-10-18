package lifecycle

import (
	"context"
	"fmt"
	"testing"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

func TestLegacyDeliveryAndAuditSurviveReplacement(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			e, n := preparedFixture(t)
			sink := &legacyAuditSink{}
			e.legacy.config.AuditWriter = sink
			reservation := reservePrepared(t, e, 301)
			n.artifact = preparedArtifact(t, reservation)
			entered, release := make(chan struct{}), make(chan struct{})
			n.deliver = func(ctx context.Context, _ *PreparedLegacyApproval) (LegacyDelivery, error) {
				close(entered)
				select {
				case <-release:
					return LegacyDelivery{AllDelivered: true}, nil
				case <-ctx.Done():
					return LegacyDelivery{}, ctx.Err()
				}
			}
			delivered := make(chan error, 1)
			go func() { delivered <- e.DeliverLegacy(reservation, n.artifact) }()
			receiveNotify(t, entered)
			base := e.config.Store
			e.config.Store = &uncertainStore{Store: base, landed: landed}
			_, err := admissionSubmit(e, 1, st.PrincipalA)
			checkCode(t, err, ap.CodeStorageUncertain)
			e.Close()
			if e.legacy.ctx.Err() != nil {
				t.Fatal("engine closed legacy owner")
			}
			config := e.config
			config.Store = base
			replacement, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer replacement.Close()
			if replacement.legacy != e.legacy {
				t.Fatal("replacement lost legacy owner")
			}
			if _, err := replacement.ReserveLegacy(context.Background(), LegacyInstance{ID: legacyInstanceID(302), UID: 7, RequestID: legacyInstanceID(301)}, []byte("snapshot"), legacyInput(t)); err == nil {
				t.Fatal("pending reservation lost")
			}
			close(release)
			if err := receiveNotify(t, delivered); err != nil {
				t.Fatal(err)
			}
			vote := reservationVote(reservation)
			if !legacyTap(t, replacement, vote).Resolved {
				t.Fatal("replacement could not resolve delivered card")
			}
			if legacyTap(t, replacement, vote).Resolved {
				t.Fatal("tombstone replay resolved twice")
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			if len(sink.events) != 1 || sink.events[0].Transition != "legacy_vote_replay" {
				t.Fatalf("lost replay audit: %+v", sink.events)
			}
			if reservation.Request().Wait().Status != "approved" {
				t.Fatal("legacy result changed")
			}
		})
	}
}

func TestLegacyOwnerDoesNotWaitForEngineWriter(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	e, _, base, _ := engineFixture(t)
	defer closeLegacyFixture(e)
	request, vote := legacyRequest(t, e, context.Background(), 7, "independent", true)
	store := &uncertainStore{Store: base, entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-store.release:
		default:
			close(store.release)
		}
	}()
	e.config.Store = store
	done := make(chan error, 1)
	go func() { _, err := admissionSubmit(e, 1, st.PrincipalA); done <- err }()
	receiveNotify(t, store.entered)
	tapped := make(chan LegacyTapResult, 1)
	go func() {
		result, err := e.legacy.VoteLegacy(vote, func(LegacyTapResult) {})
		if err != nil {
			t.Error(err)
		}
		tapped <- result
	}()
	result := receiveNotify(t, tapped)
	close(store.release)
	checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
	if !result.Resolved || request.Wait().Status != "approved" {
		t.Fatal("legacy depended on v2 writer")
	}
}

func TestLegacyV2HandleCollisionRefusesDeliveryAndTap(t *testing.T) {
	e, n := preparedFixture(t)
	r := reservePrepared(t, e, 401)
	n.artifact = preparedArtifact(t, r)
	e.mu.Lock()
	e.projections.cards.add(r.RenderContext().Handle, "v2-record")
	e.mu.Unlock()
	if err := e.DeliverLegacy(r, n.artifact); err == nil || n.calls.Load() != 0 {
		t.Fatal("collision delivered", err)
	}
	called := false
	if _, err := e.VoteLegacy(reservationVote(r), func(LegacyTapResult) { called = true }); err == nil || called {
		t.Fatal("ambiguous tap routed", err)
	}
	if r.Request().Wait().Status != "error" {
		t.Fatal("collision left reservation live")
	}
}
