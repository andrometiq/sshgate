package assist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

func testRules() []redact.Rule {
	return []redact.Rule{redact.CompileRule("test-secret", "", `planted-secret-[A-Za-z0-9]+`, nil, 0, 0, 0)}
}

func testPlan() approvalplan.ApprovalPlanV1 {
	return approvalplan.ApprovalPlanV1{Kind: approvalplan.KindCommandJob, RationaleOrigin: approvalplan.OriginAgent, Rationale: "use planted-secret-ABC123", CommandJob: &approvalplan.CommandJob{Steps: []approvalplan.Step{{ExactCommand: "echo planted-secret-ABC123; rm /tmp/test"}, {ExactCommand: "printf 'second\\ncommand'"}}}}
}

func TestRedactForProvider(t *testing.T) {
	plan := testPlan()
	before, _ := json.Marshal(plan)
	var salt [32]byte
	copy(salt[:], "private-redaction-salt")
	in, err := RedactForProvider(plan, salt, testRules())
	if err != nil {
		t.Fatal(err)
	}
	marker := approvalplan.HiddenMarker(len("planted-secret-ABC123"), []string{"test-secret"})
	if in.Kind != approvalplan.KindCommandJob || in.Reason != "use "+marker || in.Commands[0] != "echo "+marker+"; rm /tmp/test" || in.Grant != nil || in.legacy {
		t.Fatalf("bad provider input: %+v", in)
	}
	raw, _ := json.Marshal(in)
	for _, forbidden := range []string{"planted-secret-ABC123", redact.MarkerPrefix, "private-redaction-salt", redact.MarkerKey(salt, []byte("planted-secret-ABC123"))} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("provider input contains forbidden text %q", forbidden)
		}
	}
	after, _ := json.Marshal(plan)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("mutated signed plan")
	}
	hash, _ := approvalplan.PlanHash(plan)
	if in.PlanHash != hash {
		t.Fatal("plan hash changed")
	}
}

// The provider's user message and InputDigest are a persisted, audited
// format (K5, K8): a change here is a named format change.
func TestInputEncodingAndDigestGolden(t *testing.T) {
	for _, tc := range []struct {
		in           Input
		json, digest string
	}{
		{
			Input{PlanHash: strings.Repeat("a", 64), Kind: approvalplan.KindCommandJob, Reason: "clean up", Commands: []string{"rm /tmp/x", "echo ⟦hidden 4 bytes⟧"}},
			`{"plan_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"command_job","reason":"clean up","commands":["rm /tmp/x","echo ⟦hidden 4 bytes⟧"]}`,
			"dbae526e6ef3747c7322ddb9e4d1c9c089ac4747ffcae8665b13f005682a44ad",
		},
		{
			Input{PlanHash: strings.Repeat("b", 64), Kind: approvalplan.KindStandingGrant, Reason: "deploys", Commands: []string{}, Grant: &Grant{Scope: approvalplan.GrantScopeCommands, DurationSeconds: 3600, AllowedCommands: []string{"systemctl restart app"}}},
			`{"plan_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"standing_grant","reason":"deploys","commands":[],"grant":{"scope":"commands","duration_seconds":3600,"allowed_commands":["systemctl restart app"]}}`,
			"790234b1337481faa535dddc9ebd30ffd10b66712a368b2afd786e025048be89",
		},
	} {
		raw, _ := json.Marshal(tc.in)
		if string(raw) != tc.json {
			t.Fatalf("encoding changed:\n got %s\nwant %s", raw, tc.json)
		}
		sum := sha256.Sum256(append([]byte("sshgate-assist-input-v1\x00"), raw...))
		if tc.in.Digest() != hex.EncodeToString(sum[:]) {
			t.Fatal("digest is not the domain-tagged hash of the provider message")
		}
		if tc.in.Digest() != tc.digest {
			t.Fatalf("digest golden changed: %s", tc.in.Digest())
		}
		changed := tc.in.clone()
		changed.Reason += "!"
		if changed.Digest() == tc.in.Digest() {
			t.Fatal("digest ignores the reason")
		}
	}
}

func TestRedactionFailsClosed(t *testing.T) {
	for _, rules := range [][]redact.Rule{nil, {}, {{ID: "broken"}}, testRules()} {
		plan := testPlan()
		want := ErrRedactFailed
		if len(rules) == 0 {
			want = ErrNoPolicy
		}
		if reflect.DeepEqual(rules, testRules()) {
			plan.Rationale = strings.Repeat("x", redact.MaxSpanInput+1)
		}
		in, err := RedactForProvider(plan, [32]byte{}, rules)
		if !errors.Is(err, want) || !reflect.DeepEqual(in, Input{}) {
			t.Fatalf("failure returned partial input: %+v %v", in, err)
		}
		if err.Error() != ReasonRedaction {
			t.Fatalf("redaction error reads %q, not E15's reason", err)
		}
	}
}

func TestProviderTextNeutralizesForgedMarkers(t *testing.T) {
	forged := redact.MarkerPrefix + "12345678]"
	marker := approvalplan.HiddenMarker(len("planted-secret-ABC123"), []string{"test-secret"})
	for name, tc := range map[string]struct{ text, want string }{
		"tail":           {"literal " + forged, "literal " + redact.NeutralizedMarkerPrefix + "12345678]"},
		"before a span":  {forged + " planted-secret-ABC123", redact.NeutralizedMarkerPrefix + "12345678] " + marker},
		"glyphs":         {"echo " + approvalplan.HiddenMarker(40, []string{"aws-access-key"}), `echo \u{27E6}hidden 40 bytes · aws-access-key\u{27E7}`},
		"glyph and span": {"⟦planted-secret-ABC123⟧", `\u{27E6}` + marker + `\u{27E7}`},
	} {
		t.Run(name, func(t *testing.T) {
			plan := testPlan()
			plan.Rationale = tc.text
			plan.CommandJob.Steps[1].ExactCommand = tc.text
			in, err := RedactForProvider(plan, [32]byte{}, testRules())
			if err != nil || in.Reason != tc.want || in.Commands[1] != tc.want {
				t.Fatalf("got %+v %v, want %q", in, err, tc.want)
			}
		})
	}
}

func TestPlanKindsReachProvider(t *testing.T) {
	grant := func(scope approvalplan.GrantScope, commands ...string) *approvalplan.StandingGrant {
		return &approvalplan.StandingGrant{Scope: scope, Commands: commands, DurationSeconds: 86400}
	}
	cases := []struct {
		plan     approvalplan.ApprovalPlanV1
		commands []string
		grant    *Grant
	}{
		{approvalplan.ApprovalPlanV1{Kind: approvalplan.KindStandingGrant, StandingGrant: grant(approvalplan.GrantScopeCommands, "one planted-secret-X1", "two")}, []string{},
			&Grant{Scope: approvalplan.GrantScopeCommands, DurationSeconds: 86400, AllowedCommands: []string{"one " + approvalplan.HiddenMarker(len("planted-secret-X1"), []string{"test-secret"}), "two"}}},
		{approvalplan.ApprovalPlanV1{Kind: approvalplan.KindStandingGrant, StandingGrant: grant(approvalplan.GrantScopeAll)}, []string{},
			&Grant{Scope: approvalplan.GrantScopeAll, DurationSeconds: 86400}},
		{approvalplan.ApprovalPlanV1{Kind: approvalplan.KindTransfer, Transfer: &approvalplan.Transfer{SendCommand: "send", RecvCommand: "receive"}}, []string{"send", "receive"}, nil},
		{approvalplan.ApprovalPlanV1{Kind: approvalplan.KindRegisterTransferKey, RationaleOrigin: approvalplan.OriginTrustedHumanCLI, RegisterTransferKey: &approvalplan.RegisterTransferKey{}}, []string{}, nil},
	}
	for _, tc := range cases {
		if tc.plan.RationaleOrigin == "" {
			tc.plan.RationaleOrigin = approvalplan.OriginAgent
		}
		in, err := RedactForProvider(tc.plan, [32]byte{}, testRules())
		if err != nil || in.Kind != tc.plan.Kind || !reflect.DeepEqual(in.Commands, tc.commands) || !reflect.DeepEqual(in.Grant, tc.grant) {
			t.Fatalf("%s: %+v %v", tc.plan.Kind, in, err)
		}
	}
	allGrant := approvalplan.ApprovalPlanV1{Kind: approvalplan.KindStandingGrant, RationaleOrigin: approvalplan.OriginAgent, StandingGrant: grant(approvalplan.GrantScopeAll)}
	in, _ := RedactForProvider(allGrant, [32]byte{}, testRules())
	if raw, _ := json.Marshal(in); !strings.Contains(string(raw), `"grant":{"scope":"all","duration_seconds":86400}`) {
		t.Fatalf("scope all grant not visible to provider: %s", raw)
	}
	for _, plan := range []approvalplan.ApprovalPlanV1{
		{RationaleOrigin: approvalplan.OriginAgent},
		{Kind: approvalplan.KindStandingGrant, RationaleOrigin: approvalplan.OriginAgent},
		{Kind: approvalplan.KindCommandJob, CommandJob: &approvalplan.CommandJob{}},
	} {
		if _, err := RedactForProvider(plan, [32]byte{}, testRules()); err == nil {
			t.Fatalf("accepted %+v", plan)
		}
	}
}

func TestLegacyMarkedOnlyByOrigin(t *testing.T) {
	plan := testPlan()
	plan.Rationale = approvalplan.LegacyRationaleText
	in, err := RedactForProvider(plan, [32]byte{}, testRules())
	if err != nil || in.legacy {
		t.Fatalf("a v2 reason equal to the legacy text marked legacy: %+v %v", in, err)
	}
	plan.RationaleOrigin = approvalplan.OriginSynthesizedLegacyV1
	if in, err = RedactForProvider(plan, [32]byte{}, testRules()); err != nil || !in.legacy || in.Reason != approvalplan.LegacyRationaleText {
		t.Fatalf("legacy request: %+v %v", in, err)
	}
	plan.Rationale = "agent text"
	if _, err = RedactForProvider(plan, [32]byte{}, testRules()); !errors.Is(err, ErrRedactFailed) {
		t.Fatalf("legacy origin with an agent reason: %v", err)
	}
}

const pemKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDx3k1abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM\n-----END OPENSSH PRIVATE KEY-----\n"

// combinedSecrets are E15's and E16's probes under the production rule set.
var combinedSecrets = []string{"s3cretPassw0rdXYZ", "hunter2secretvalue", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"}

func combinedPlan() approvalplan.ApprovalPlanV1 {
	return approvalplan.ApprovalPlanV1{
		Kind: approvalplan.KindCommandJob, RationaleOrigin: approvalplan.OriginAgent,
		Rationale: "deploy with PASSWORD=hunter2secretvalue and token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		CommandJob: &approvalplan.CommandJob{Steps: []approvalplan.Step{
			{ExactCommand: "PASSWORD=hunter2secretvalue ./run.sh"},
			{ExactCommand: "curl https://admin:s3cretPassw0rdXYZ@db.example.com/health"},
			{ExactCommand: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY aws s3 ls"},
			{ExactCommand: "cat > k <<EOF\n" + pemKey + "EOF\nrm -rf /var/lib/x"},
			{ExactCommand: "echo " + redact.MarkerPrefix + "abcd1234] PASSWORD=hunter2secretvalue"},
		}},
	}
}

func TestCombinedRulesHideSecrets(t *testing.T) {
	in, err := RedactForProvider(combinedPlan(), [32]byte{9}, redactrules.Combined())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	for _, secret := range append(combinedSecrets, redact.MarkerPrefix) {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("provider input carries %q: %s", secret, raw)
		}
	}
	if !strings.HasSuffix(in.Commands[3], "EOF\nrm -rf /var/lib/x") || !strings.Contains(in.Commands[4], redact.NeutralizedMarkerPrefix) || !strings.HasPrefix(in.Commands[1], "curl https://admin:⟦hidden") {
		t.Fatalf("lost visible text: %q", in.Commands)
	}
}
