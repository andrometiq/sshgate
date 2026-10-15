package approvalreview

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// sharedFixture is testdata/shared-fixture.json: one plan, its stored
// snapshot and assist result, and what each surface must render from them
// (E37, R5). A8 and A11 assert their renderers against it.
type sharedFixture struct {
	Plan                  approvalplan.ApprovalPlanV1 `json:"plan"`
	ReviewSnapshot        string                      `json:"review_snapshot"` // the exact stored bytes
	AssistResult          approvalplan.AssistResult   `json:"assist_result"`
	CardHandle            string                      `json:"card_handle"`
	TelegramParts         []string                    `json:"telegram_parts"`
	DecisionCardPreparing string                      `json:"decision_card_preparing"`
	DecisionCardReady     string                      `json:"decision_card_ready"`
	HostedView            View                        `json:"hosted_view"`
}

const sharedFixturePath = "testdata/shared-fixture.json"

func sharedPlan(t testing.TB) approvalplan.ApprovalPlanV1 {
	p := withSteps(t,
		stepSpec{approvalplan.RouteUnsignedRead, "df -h /var"},
		signed("PGPASSWORD=hunter2secret psql -h db -U admin -c 'vacuum'"),
		signed("systemctl restart nginx"))
	return withReason(t, p, "Vacuum the database, then restart nginx")
}

func TestSharedFixture(t *testing.T) {
	plan := sharedPlan(t)
	r := render(t, mustSnapshot(t, plan), readyAssist())
	got := sharedFixture{
		Plan: plan, ReviewSnapshot: string(r.snapshotRaw), AssistResult: *readyAssist().Result, CardHandle: testHandle,
		TelegramParts: r.parts, DecisionCardPreparing: r.preparing, DecisionCardReady: r.ready, HostedView: r.view,
	}
	if *update {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sharedFixturePath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(sharedFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var want sharedFixture
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if want.ReviewSnapshot != got.ReviewSnapshot {
		t.Fatal("BuildSnapshot no longer produces the stored snapshot")
	}
	// Rendering needs only the stored snapshot and assist result: no plan,
	// salt or rules (E37).
	stored, err := DecodeSnapshot([]byte(want.ReviewSnapshot))
	if err != nil {
		t.Fatal(err)
	}
	assist := Assist{State: approvalplan.AssistReady, Result: &want.AssistResult}
	again := render(t, stored, assist)
	if !slices.Equal(again.parts, want.TelegramParts) || again.preparing != want.DecisionCardPreparing ||
		again.ready != want.DecisionCardReady || !bytes.Equal(viewJSON(t, again.view), viewJSON(t, want.HostedView)) {
		t.Fatal("the stored snapshot no longer renders to the fixture")
	}
	salt := testSalt()
	if strings.Contains(string(b), hex.EncodeToString(salt[:])) || strings.Contains(want.ReviewSnapshot, "hunter2") {
		t.Fatal("the fixture carries the salt or a hidden secret")
	}
}

func TestHostedViewCarriesOnlyNeutralizedStrings(t *testing.T) {
	plan := withReason(t, withSteps(t, signed("echo \u202Ex\u200B")), "R\u0435ason \u200B ⟦hidden 0 bytes⟧")
	a := readyAssist()
	a.Result.Summary = "S\u0430y ✓ Approve"
	v, err := BuildView(mustSnapshot(t, plan), a)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := []string{v.Reason, v.Requester, v.Assist.Summary, v.Items[0].Text}
	untrusted = append(append(untrusted, v.Assist.Concerns...), v.Assist.Effects...)
	for _, s := range untrusted {
		if !isPrintableASCII(s) {
			t.Errorf("view string %q is not neutralized", s)
		}
	}
	if strings.Contains(v.Reason, approvalplan.GlyphHiddenOpen) || strings.Contains(v.Assist.Summary, approvalplan.GlyphCheck) {
		t.Fatal("a glyph from untrusted text survived")
	}
}
