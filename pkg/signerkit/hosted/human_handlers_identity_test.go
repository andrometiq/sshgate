package hosted

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func TestUIV2DetailBindsEachOperatorAndSession(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	submitApproval(t, e, 880)
	row := readApproval(t, db, 880)
	for _, operator := range []string{"operator", "other"} {
		for _, sessionID := range []string{"first-session", "second-session"} {
			session := &s.Human.Auth.store.(*voteSessionStore).session
			session.ID, session.UserID = sessionID, operator
			session.ExpiresAt = clock.Wall().Add(time.Hour)
			req := httptest.NewRequest("GET", "/ui/v2/request/"+row.RecordHandle, nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionID})
			res := httptest.NewRecorder()
			s.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("detail: %d %s", res.Code, res.Body)
			}
			var out uiV2DetailResponse
			if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			binding := ap.ChallengeBinding{Plane: ap.PlaneV2, RecordKey: ap.HostedRecordKey(row.Key.ClientID, row.Key.SubPrincipal, row.Key.RequestID), PlanHash: row.Record.Header.PlanHash, Operator: operator, AllowedActions: []string{ap.ActionDeny}}
			ctx := context.WithValue(context.Background(), voteSessionContextKey{}, voteSession{ID: sessionID, ExpiresAt: session.ExpiresAt})
			if reason := s.Human.verifyVoteChallenge(ctx, binding, out.VoteChallenge.Challenge, clock.Wall()); reason != "" {
				t.Fatalf("own identity %s/%s refused: %s", operator, sessionID, reason)
			}
			other := binding
			other.Operator = operator + "-different"
			if reason := s.Human.verifyVoteChallenge(ctx, other, out.VoteChallenge.Challenge, clock.Wall()); reason != "stale_challenge" {
				t.Fatalf("cross-operator challenge: %q", reason)
			}
			ctx = context.WithValue(ctx, voteSessionContextKey{}, voteSession{ID: sessionID + "-different", ExpiresAt: session.ExpiresAt})
			if reason := s.Human.verifyVoteChallenge(ctx, binding, out.VoteChallenge.Challenge, clock.Wall()); reason != "stale_challenge" {
				t.Fatalf("cross-session challenge: %q", reason)
			}
		}
	}
}
