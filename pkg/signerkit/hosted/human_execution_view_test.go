package hosted

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func v2Execution(t *testing.T, s *Server, handle string) *uiV2Execution {
	t.Helper()
	var execution *uiV2Execution
	if data, ok := listJSON(t, s, "/ui/v2/request/"+handle)["execution"]; ok {
		if err := json.Unmarshal(data, &execution); err != nil {
			t.Fatal(err)
		}
	}
	return execution
}

// E49: report-derived execution views are labelled client-reported and the
// signer's own inferences signer-derived, on the detail view. The audit list
// stays a time-independent decision record (TestUIV2AuditBindingAfterShedRestart).
func TestUIV2ExecutionViewsAreLabelled(t *testing.T) {
	t.Run("client-reported", func(t *testing.T) {
		e, db, clock := approvalEngineFixture(t, false)
		s := lifecycleUI(t, e, db)
		claim := approvalReady(t, e, db)
		handle := readApproval(t, db, 1).RecordHandle
		if got := v2Execution(t, s, handle); got != nil {
			t.Fatalf("unclaimed approval shows execution: %+v", got)
		}
		if a, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil || a.Claim != ap.ClaimSignatures {
			t.Fatalf("claim: %+v %v", a, err)
		}
		want := uiV2Execution{Status: ap.ExecutionExecuting, Label: "client-reported"}
		if got := v2Execution(t, s, handle); got == nil || *got != want {
			t.Fatalf("executing: %+v", got)
		}
		clock.Advance(time.Minute)
		if _, err := e.Report(context.Background(), approvalKey(1), approvalReport(claim)); err != nil {
			t.Fatal(err)
		}
		want = uiV2Execution{Status: ap.ExecutionFinal, Class: ap.ClassSucceeded, Label: "client-reported"}
		if got := v2Execution(t, s, handle); got == nil || *got != want {
			t.Fatalf("final: %+v", got)
		}
	})
	t.Run("signer-derived", func(t *testing.T) {
		e, db, clock := approvalEngineFixture(t, false)
		s := lifecycleUI(t, e, db)
		approvalReady(t, e, db)
		handle := readApproval(t, db, 1).RecordHandle
		clock.Advance(48 * time.Hour)
		alignVoteSession(s, context.Background(), e.now().Wall)
		if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.Tick{}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
		want := uiV2Execution{Status: ap.ExecutionExpiredUnclaimed, Label: "signer-derived"}
		if got := v2Execution(t, s, handle); got == nil || *got != want {
			t.Fatalf("expired_unclaimed: %+v", got)
		}
	})
}

// The detail view hints the cancel control only to an admin, only while pending.
func TestUIViewerCanCancelHint(t *testing.T) {
	f := newCancelV1Fixture(t, 2)
	submitApproval(t, f.e, 1)
	alignVoteSession(f.s, context.Background(), f.e.now().Wall)
	v2 := readApproval(t, f.db, 1)
	session := &f.s.Human.Auth.store.(*voteSessionStore).session
	paths := []string{"/ui/request/r-cancel", "/ui/v2/request/" + v2.RecordHandle}
	for _, user := range []string{"operator", "root"} {
		session.UserID = user
		for _, path := range paths {
			_, hinted := listJSON(t, f.s, path)["viewer_can_cancel"]
			if hinted != (user == "root") {
				t.Fatalf("%s %s: hinted=%v", user, path, hinted)
			}
		}
	}
	if w := cancelHTTP(t, f.s, "root", "/ui/request/r-cancel/cancel", nil); w.Code != 200 {
		t.Fatalf("v1 cancel: %d %s", w.Code, w.Body)
	}
	if w := cancelHTTP(t, f.s, "root", paths[1]+"/cancel", cancelV2Request{PlanHash: v2.Record.Header.PlanHash}); w.Code != 200 {
		t.Fatalf("v2 cancel: %d %s", w.Code, w.Body)
	}
	session.UserID = "root"
	for _, path := range paths {
		if _, hinted := listJSON(t, f.s, path)["viewer_can_cancel"]; hinted {
			t.Fatalf("%s: hinted after resolution", path)
		}
	}
}
