package approvalreview

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

func TestPEMFollowedByDestructiveTailRendersTailVerbatim(t *testing.T) {
	pem := pemKey()
	cmd := "cat > /root/.ssh/id <<'EOF'\n" + pem + "EOF\nrm -rf /srv/data"
	s := mustSnapshot(t, withSteps(t, signed(cmd)))
	d := s.Steps[0].Command
	text := renderDisplay(d)
	if !strings.HasSuffix(text, `EOF\x0arm -rf /srv/data`) {
		t.Fatalf("the tail is not shown verbatim: %q", text)
	}
	marker := approvalplan.HiddenMarker(len(pem), d.Segments[1].RuleIDs)
	if d.HiddenBytes != len(pem) || !strings.Contains(text, marker) || !strings.Contains(marker, "private-key") {
		t.Fatalf("hidden %d (want %d), display %q", d.HiddenBytes, len(pem), text)
	}
	if strings.Contains(text, "b3BlbnNzaC1rZXkt") {
		t.Fatal("key material is displayed")
	}
	if d.SHA256 != sha256Hex(cmd) {
		t.Fatal("sha256 is not of the exact command bytes")
	}
}

func TestOverlappingSecretsHideOnlyTheirUnion(t *testing.T) {
	cmd := "PASSWORD=AKIA1234567890ABCDEF ./deploy"
	s := mustSnapshot(t, withSteps(t, signed(cmd)))
	d := s.Steps[0].Command
	if d.HiddenBytes == 0 || !strings.HasSuffix(renderDisplay(d), " ./deploy") || strings.Contains(renderDisplay(d), "AKIA") {
		t.Fatalf("display %q hidden %d", renderDisplay(d), d.HiddenBytes)
	}
	visible := 0
	for _, seg := range d.Segments {
		visible += len(seg.Text)
	}
	if visible+d.HiddenBytes != len(cmd) {
		t.Fatalf("visible %d + hidden %d != %d: a byte was hidden or lost", visible, d.HiddenBytes, len(cmd))
	}
}

func TestForcedSpanFailure(t *testing.T) {
	forceSpans(t, func(string, [32]byte, []redact.Rule) (redact.SpanResult, bool) { return redact.SpanResult{}, false })
	cmd := "export GITHUB_TOKEN=ghp_abcd1234efgh && ./deploy --verbose"
	salt := testSalt()
	_, err := BuildSnapshot(withSteps(t, signed(cmd)), &salt, testRules)
	if !IsUnrenderable(err) {
		t.Fatalf("v2 with ok=false: %v, want request_unrenderable", err)
	}

	req := legacyBase()
	req.Commands = []LegacyCommand{{Server: "web-1", Command: cmd, TTLSeconds: 60}}
	salt = testSalt()
	if _, err := BuildLegacySnapshot(req, &salt, testRules); !IsUnrenderable(err) {
		t.Fatalf("legacy: %v", err)
	}

}

func TestPanickingRedactorFailsClosed(t *testing.T) {
	forceSpans(t, func(string, [32]byte, []redact.Rule) (redact.SpanResult, bool) { panic("boom") })
	salt := testSalt()
	if _, err := BuildSnapshot(loadPlan(t, "write"), &salt, testRules); !IsUnrenderable(err) {
		t.Fatalf("got %v, want request_unrenderable", err)
	}
}

func TestMalformedSpansFailClosed(t *testing.T) {
	cases := map[string]redact.SpanResult{
		"past the end": {Spans: []redact.Span{{Start: 0, End: 999}}, HiddenBytes: 999},
		"wrong total":  {Spans: []redact.Span{{Start: 0, End: 4}}, HiddenBytes: 3},
		"overlapping":  {Spans: []redact.Span{{Start: 0, End: 4}, {Start: 2, End: 6}}, HiddenBytes: 8},
		"empty span":   {Spans: []redact.Span{{Start: 3, End: 3}}},
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			forceSpans(t, func(string, [32]byte, []redact.Rule) (redact.SpanResult, bool) { return result, true })
			salt := testSalt()
			if _, err := BuildSnapshot(loadPlan(t, "write"), &salt, testRules); !IsUnrenderable(err) {
				t.Fatalf("got %v, want request_unrenderable", err)
			}
		})
	}
}

func TestNilRulesDisplayVerbatim(t *testing.T) {
	cmd := "PASSWORD=hunter2secret ./run"
	salt := testSalt()
	s, err := BuildSnapshot(withSteps(t, signed(cmd)), &salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := s.Steps[0].Command; d.HiddenBytes != 0 || renderDisplay(d) != cmd {
		t.Fatalf("got %+v", d)
	}
}

func TestSaltNeverLeavesTheBuild(t *testing.T) {
	plan := withReason(t, withSteps(t,
		signed("PGPASSWORD=hunter2secret psql -c 'select 1'"),
		signed("cat > /k <<'EOF'\n"+pemKey()+"EOF")), "Load PASSWORD=hunter2secret into the app")
	salt := testSalt()
	s, err := BuildSnapshot(plan, &salt, testRules)
	if err != nil {
		t.Fatal(err)
	}
	if salt != ([32]byte{}) {
		t.Fatal("BuildSnapshot did not zero the salt")
	}
	raw := testSalt()
	needles := []string{string(raw[:]), hex.EncodeToString(raw[:]), base64.StdEncoding.EncodeToString(raw[:]),
		base64.RawURLEncoding.EncodeToString(raw[:]), redact.MarkerPrefix, "hunter2"}
	for _, text := range render(t, s, readyAssist()).texts() {
		for _, n := range needles {
			if strings.Contains(text, n) {
				t.Fatalf("output carries %q", n)
			}
		}
	}

	failing := testSalt()
	if _, err := BuildSnapshot(approvalplan.ApprovalPlanV1{}, &failing, testRules); err == nil || failing != ([32]byte{}) {
		t.Fatalf("an invalid plan: err %v, salt zeroed %v", err, failing == [32]byte{})
	}
}

func TestUpdateHashComesFromTheCommandBytes(t *testing.T) {
	plan := loadPlan(t, "update")
	step := &plan.CommandJob.Steps[0]
	commandHash := strings.TrimPrefix(step.ExactCommand, updatePrefix)
	other := strings.Repeat("cd", 32)
	td := *step.TrustedDisplay
	td.StagedBasename = "sshgate-gate sha256=" + other
	step.TrustedDisplay = &td
	v, err := BuildView(mustSnapshot(t, plan), Assist{State: approvalplan.AssistPreparing})
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(v.Items[0].Notes, "\n")
	if !strings.Contains(notes, "New gate SHA-256 (from the signed command bytes): "+commandHash+"\n") {
		t.Fatalf("notes %q", notes)
	}
	if !strings.Contains(notes, approvalplan.LabelBuildMetadataClient+":\n"+QuotePrefix+"staged_basename=sshgate-gate\\x20sha256="+other) {
		t.Fatalf("the client hash is not quoted under the client-supplied label: %q", notes)
	}

	// A draft cannot carry a binary hash at all: the strict decode refuses
	// the field, whatever its value (E33).
	draft, err := os.ReadFile(filepath.Join("..", "approvalplan", "testdata", "drafts", "update.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sum := range []string{commandHash, other} {
		forged := bytes.Replace(draft, []byte(`"trusted_display":{`), []byte(`"trusted_display":{"binary_sha256":"`+sum+`",`), 1)
		if bytes.Equal(forged, draft) {
			t.Fatal("fixture has no trusted_display")
		}
		if _, err := approvalplan.DecodeDraft(forged); err == nil {
			t.Fatalf("a draft carrying binary_sha256=%s decoded", sum)
		}
	}
}

func TestSnapshotRoundTripAndStrictDecode(t *testing.T) {
	s := mustSnapshot(t, loadPlan(t, "mixed-batch"))
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := got.Encode()
	if !bytes.Equal(again, raw) {
		t.Fatal("round trip changed the bytes")
	}
	bad := map[string][]byte{
		"whitespace":    append([]byte(" "), raw...),
		"trailing":      append(append([]byte(nil), raw...), "{}"...),
		"unknown field": bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"version":1,"salt":"x",`), 1),
		"newline":       bytes.Replace(raw, []byte(`"requester":"`), []byte(`"requester":"\n`), 1),
		"non-ascii":     bytes.Replace(raw, []byte(`"requester":"`), []byte(`"requester":"⟦`), 1),
		"bidi escape":   bytes.Replace(raw, []byte(`"requester":"`), []byte(`"requester":"\u202e`), 1),
		"version":       bytes.Replace(raw, []byte(`{"version":1,`), []byte(`{"version":2,`), 1),
	}
	for name, b := range bad {
		if bytes.Equal(b, raw) {
			t.Fatalf("%s: substitution did not apply", name)
		}
		if _, err := DecodeSnapshot(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// TestSnapshotFitsTheR1Contract stores a built snapshot in a real R1 record:
// approvalplan's codec must accept it (canonical JSON, under
// ReviewSnapshotMax) and round-trip it unchanged.
func TestSnapshotFitsTheR1Contract(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "approvalplan", "testdata", "r1-write.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := approvalplan.DecodeR1(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mustSnapshot(t, rec.Payload.Plan).Encode()
	if err != nil {
		t.Fatal(err)
	}
	rec.Payload.ReviewSnapshot = raw
	enc, err := approvalplan.EncodeR1(rec)
	if err != nil {
		t.Fatalf("R1 refuses the snapshot: %v", err)
	}
	back, err := approvalplan.DecodeR1(enc)
	if err != nil || !bytes.Equal(back.Payload.ReviewSnapshot, raw) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestOversizedSnapshotIsTooLarge(t *testing.T) {
	s := mustSnapshot(t, loadPlan(t, "write"))
	s.Steps[0].Command.Segments = []Segment{{Text: strings.Repeat("a", approvalplan.ReviewSnapshotMax)}}
	if _, err := s.Encode(); !isTooLarge(err) {
		t.Fatalf("got %v", err)
	}
}

func TestWorstCasePartCount(t *testing.T) {
	r := render(t, mustSnapshot(t, worstCasePlan(t)), readyAssist())
	// Pinned: a change in layout that moves the worst case must be deliberate.
	const want = 32
	if len(r.parts) != want {
		t.Fatalf("worst case packs into %d parts; pinned %d", len(r.parts), want)
	}
}

func TestLegacyBeyondTelegramBoundsIsRefused(t *testing.T) {
	req := legacyBase()
	for range 32 {
		req.Commands = append(req.Commands, LegacyCommand{Server: "web-1", Command: strings.Repeat("y", 4096), TTLSeconds: 60})
	}
	if _, err := BuildLegacySnapshot(req, saltPointer(), testRules); !isTooLarge(err) {
		t.Fatalf("got %v, want request_too_large at freeze", err)
	}
}

func TestLegacyNeedsExactlyOnePayload(t *testing.T) {
	req := legacyBase()
	if _, err := BuildLegacySnapshot(req, saltPointer(), testRules); err == nil {
		t.Fatal("no payload accepted")
	}
	req.Commands = []LegacyCommand{{Server: "a", Command: "true"}}
	req.Grant = &LegacyGrant{Alias: "a", Scope: "all"}
	if _, err := BuildLegacySnapshot(req, saltPointer(), testRules); err == nil {
		t.Fatal("two payloads accepted")
	}
}

func TestK16WarningOnSignedStepsAfterEarlierWork(t *testing.T) {
	s := mustSnapshot(t, withSteps(t,
		stepSpec{approvalplan.RouteUnsignedRead, "df -h"}, signed("true"), stepSpec{approvalplan.RouteUnsignedRead, "uptime"}, signed("true")))
	var got []bool
	for _, st := range s.Steps {
		got = append(got, st.ExpiryWarning)
	}
	if want := []bool{false, true, false, true}; !slices.Equal(got, want) {
		t.Fatalf("warnings %v, want %v", got, want)
	}
}
