package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"net/http"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

type displayAuditCore struct {
	humanVoteCore
	lines bytes.Buffer
}

func (c *displayAuditCore) Verdict(ctx context.Context, v signerkit.AuditVerdict) error {
	if err := c.humanVoteCore.Verdict(ctx, v); err != nil {
		return err
	}
	return signerkit.NewAppendOnlySink(&c.lines).Verdict(ctx, v)
}

func TestHumanLegacyDisplayLabels(t *testing.T) {
	if row := summarizeWithSalt(&store.Request{Commands: []byte("{")}, [32]byte{}); !row.DisplayFailed {
		t.Fatal("malformed command storage was displayed as an approvable empty row")
	}

	for _, secret := range []bool{false, true} {
		cmd := "echo ok"
		if secret {
			cmd = "PASSWORD=planted-secret-value true"
		}
		commands, _ := json.Marshal([]signRequestCmd{{Cmd: cmd}, {Cmd: "uptime"}})
		row := summarizeWithSalt(&store.Request{Commands: commands}, [32]byte{})
		if row.Redacted != secret || row.DisplayFailed || row.CommandDetails[0].Redacted != secret || row.CommandDetails[1].Redacted || row.CommandDetails[1].RedactedLabel != "" {
			t.Fatalf("flags: %+v", row)
		}
		want := ""
		if secret {
			want = ap.LabelRedactedDisplay
		}
		if row.CommandDetails[0].RedactedLabel != want {
			t.Fatalf("label: %+v", row)
		}
	}
}

func TestHumanLegacyDisplayFailure(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, now := voteChallengeFixture(t, false)
	h := s.Human
	h.Auth.now = func() time.Time { return now }
	h.Store = db
	core := &displayAuditCore{}
	h.Engine = &ApprovalEngine{Store: db, Core: core}
	h.legacyRedactor = func(raw string, _ [32]byte, _ []redact.Rule) (string, bool) { return raw, false }
	expiry := now.Add(time.Hour)
	row := &store.Request{RequestID: "r-display", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[{"cmd":"echo hidden"}]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 2}
	if err := db.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	summary := h.summarize(row)
	if !summary.DisplayFailed || !summary.Redacted || summary.Commands[0] != "[command unavailable]" || summary.CommandDetails[0].RedactedLabel != ap.LabelRedactedDisplay {
		t.Fatalf("display: %+v", summary)
	}
	token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
	if err != nil {
		t.Fatal(err)
	}
	path := "/ui/request/" + row.RequestID
	w := voteHTTP(t, s, path+"/approve", token.Challenge)
	if w.Code != http.StatusConflict || w.Body.String() != "{\"error\":\"command display unavailable; approval refused\"}\n" {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if len(core.verdicts) != 1 {
		t.Fatalf("audit count: %d", len(core.verdicts))
	}
	v := core.verdicts[0]
	if v.Approval == nil || v.Approval.Transition != "vote_refused{display_unavailable}" || !v.Approval.Replay || v.Approval.Decision != "approve" || v.CommandSHA256 != commandsSHA256(row.Commands) || v.RequestID != row.RequestID || v.Operator.ID != "operator" {
		t.Fatalf("audit: %+v", v)
	}
	wantLine := `{"kind":"verdict_inert","event":{"time":"2026-01-01T00:00:00Z","request_id":"r-display","operator":{"ID":"operator","DisplayName":"operator","Verified":true,"AuthnMethod":"session"},"command_sha256":"` + commandsSHA256(row.Commands) + `","approved":true,"approval":{"transition":"vote_refused{display_unavailable}","decision":"approve","replay":true}}}` + "\n"
	if core.lines.String() != wantLine {
		t.Fatalf("inert line: %s", core.lines.String())
	}
	votes, err := db.ListVotes(ctx, row.RequestID)
	if err != nil || len(votes) != 0 {
		t.Fatalf("refusal wrote votes: %+v %v", votes, err)
	}
	stored, err := db.GetByID(ctx, row.RequestID)
	if err != nil || stored.Status != store.StatusPending || len(stored.Signatures) != 0 {
		t.Fatalf("refusal changed row: %+v %v", stored, err)
	}
	if w := voteHTTP(t, s, path+"/deny", token.Challenge); w.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", w.Code, w.Body)
	}
	votes, err = db.ListVotes(ctx, row.RequestID)
	if err != nil || len(votes) != 1 || votes[0].Decision != store.DecisionDeny {
		t.Fatalf("deny votes: %+v %v", votes, err)
	}
}
