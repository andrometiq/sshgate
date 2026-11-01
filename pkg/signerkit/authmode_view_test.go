package signerkit

import (
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// TestAuthMode_V2SummaryMatchesV1 pins ruling 16: the v2 Summary's auth_mode
// is the value authMode gives a v1 sign response and audit row for the same
// decision, so the two wires never disagree on how a write was authorized.
func TestAuthMode_V2SummaryMatchesV1(t *testing.T) {
	statuses := []ap.ApprovalStatus{ap.ApprovalApproved, ap.ApprovalDenied, ap.ApprovalCanceled, ap.ApprovalExpired, ap.ApprovalError}
	decidedBy := []string{
		"telegram:42", "telegram:42,telegram:43", "@alice", "id:7",
		ap.GrantDecidedPrefix + "a2_AAAAAAAAAAAAAAAAAAAAAA", ap.GrantDecidedPrefix,
		ap.DecidedByClock, ap.DecidedByNotifier, "admin", "",
	}
	at := time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)
	now := ap.Now{Wall: at, Elapsed: time.Hour}
	for _, kind := range []ap.Kind{ap.KindCommandJob, ap.KindStandingGrant} {
		pending := ap.R1{Header: ap.R1Header{Kind: kind, RequestID: "a2_BBBBBBBBBBBBBBBBBBBBBB", CreatedAt: at}}
		if got := ap.View(pending, now, "e", ap.Settings{}, false).AuthMode; got != "" {
			t.Errorf("%s pending: auth_mode = %q; want absent", kind, got)
		}
		for _, status := range statuses {
			for _, by := range decidedBy {
				rec := pending
				rec.Header.Decision = &ap.Decision{Status: status, DecidedAt: at, DecidedBy: by}
				got := ap.View(rec, now, "e", ap.Settings{}, false).AuthMode
				if want := authMode(status == ap.ApprovalApproved, by); got != want {
					t.Errorf("%s %s by %q: v2 auth_mode = %q; v1 authMode = %q", kind, status, by, got, want)
				}
			}
		}
	}
}
