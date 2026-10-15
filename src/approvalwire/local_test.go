package approvalwire_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mustLocalRequest(t *testing.T, req any) []byte {
	t.Helper()
	line, err := approvalwire.MarshalLocalRequest(req)
	if err != nil {
		t.Fatalf("MarshalLocalRequest(%T): %v", req, err)
	}
	return line
}

func TestMaxFrameBytesFitsTheDaemonsFirstRead(t *testing.T) {
	// HandleSignRequest reads its first line with policywire.MaxSocketFrameBytes.
	if approvalwire.MaxFrameBytes > policywire.MaxSocketFrameBytes {
		t.Fatalf("MaxFrameBytes %d exceeds policywire.MaxSocketFrameBytes %d", approvalwire.MaxFrameBytes, policywire.MaxSocketFrameBytes)
	}
	if approvalplan.MaxDraftBytes+4096 > approvalwire.MaxFrameBytes {
		t.Fatalf("a draft at MaxDraftBytes does not fit a submit frame")
	}
}

func TestGoldenLocalRequests(t *testing.T) {
	for name, req := range localRequests(t) {
		line := mustLocalRequest(t, req)
		golden(t, "local/request-"+name+".json", line)
		got, err := approvalwire.DecodeLocalRequest(line)
		if err != nil {
			t.Fatalf("%s: decode own golden: %v", name, err)
		}
		if !reflect.DeepEqual(got, req) {
			t.Errorf("%s: decoded %#v; want %#v", name, got, req)
		}
	}
}

func TestGoldenLocalResponses(t *testing.T) {
	answers := localResponses()
	for _, name := range sortedKeys(answers) {
		a := answers[name]
		line, err := approvalwire.MarshalLocalResponse(a.kind, a.resp)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		golden(t, "local/response-"+name+".json", line)
		got, err := approvalwire.DecodeLocalResponse(a.kind, line)
		if err != nil {
			t.Fatalf("%s: decode own golden: %v", name, err)
		}
		again, _ := approvalwire.MarshalLocalResponse(a.kind, got)
		if !bytes.Equal(again, line) {
			t.Errorf("%s: round trip changed the bytes", name)
		}
	}
}

// TestGoldenRefusals freezes the envelope of every code in the closed set, in
// approvalplan's wire order, with the fixed messages where a code has one.
func TestGoldenRefusals(t *testing.T) {
	var all bytes.Buffer
	for _, code := range approvalplan.AllCodes {
		line, err := approvalwire.MarshalLocalResponse(approvalwire.KindGet, refusal(code))
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		all.Write(line)
		_, err = approvalwire.DecodeLocalResponse(approvalwire.KindGet, line)
		var we *approvalwire.WireError
		if !errors.As(err, &we) || we.Code != code {
			t.Fatalf("%s: decode answered %v; want a *WireError with that code", code, err)
		}
	}
	golden(t, "local/refusals.jsonl", all.Bytes())
}

// TestSignerIncompatibleFrameIsE69sExactBytes pins the frame the A12 proxy
// answers for a hosted server without /v2/approvals.
func TestSignerIncompatibleFrameIsE69sExactBytes(t *testing.T) {
	const want = `{"approval_proto":1,"ok":false,"error":{"code":"signer_incompatible","message":"hosted signer-server does not serve /v2/approvals; upgrade it (migration 7) before this MCP"}}` + "\n"
	for _, kind := range approvalwire.Kinds {
		line, err := approvalwire.MarshalLocalResponse(kind, approvalwire.ErrorResponse(approvalplan.CodeSignerIncompatible, "ignored"))
		if err != nil {
			t.Fatal(err)
		}
		if string(line) != want {
			t.Fatalf("%s: frame\n%s\nwant\n%s", kind, line, want)
		}
		_, err = approvalwire.DecodeLocalResponse(kind, line)
		if !errors.Is(err, approvalwire.ErrSignerIncompatible) {
			t.Fatalf("%s: decode answered %v; want ErrSignerIncompatible", kind, err)
		}
	}
	golden(t, "local/response-signer-incompatible.json", []byte(want))
}

// legacyUnsupportedKind is the reply of a pre-v2 daemon:
// respondError(conn, peek.Kind, fmt.Sprintf("unsupported kind %q", peek.Kind))
// encoding signResponse{RequestID, Status, Error, ProtoVersion}
// (pkg/signerkit/daemon.go:519 and :762 at 2ffe928).
func legacyUnsupportedKind(kind string) []byte {
	b, _ := json.Marshal(struct {
		RequestID    string `json:"request_id"`
		Status       string `json:"status"`
		Error        string `json:"error"`
		ProtoVersion int    `json:"proto_version,omitempty"`
	}{kind, "error", fmt.Sprintf("unsupported kind %q", kind), 1})
	return append(b, '\n')
}

func TestLegacyUnsupportedKindIsSignerIncompatible(t *testing.T) {
	for _, kind := range approvalwire.Kinds {
		frame := legacyUnsupportedKind(kind)
		if want := fmt.Sprintf(`{"request_id":%q,"status":"error","error":"unsupported kind \"%s\"","proto_version":1}`+"\n", kind, kind); string(frame) != want {
			t.Fatalf("legacy fixture drifted: %s", frame)
		}
		if _, err := approvalwire.DecodeLocalResponse(kind, frame); !errors.Is(err, approvalwire.ErrSignerIncompatible) {
			t.Errorf("%s: %v; want ErrSignerIncompatible", kind, err)
		}
	}
	// Builds older than the proto check omit proto_version.
	old := []byte(`{"request_id":"approval_get_v2","status":"error","error":"unsupported kind \"approval_get_v2\""}`)
	if _, err := approvalwire.DecodeLocalResponse(approvalwire.KindGet, old); !errors.Is(err, approvalwire.ErrSignerIncompatible) {
		t.Errorf("pre-proto legacy frame: %v", err)
	}
	notIncompatible := map[string]string{
		"other kind named":   string(legacyUnsupportedKind(approvalwire.KindSubmit)),
		"other legacy error": `{"request_id":"approval_get_v2","status":"error","error":"malformed request: x","proto_version":1}`,
		"approved legacy":    `{"request_id":"approval_get_v2","status":"approved","error":"unsupported kind \"approval_get_v2\"","proto_version":1}`,
		"extra field":        `{"request_id":"approval_get_v2","status":"error","error":"unsupported kind \"approval_get_v2\"","proto_version":1,"auth_mode":"human"}`,
	}
	for name, frame := range notIncompatible {
		_, err := approvalwire.DecodeLocalResponse(approvalwire.KindGet, []byte(frame))
		if err == nil || errors.Is(err, approvalwire.ErrSignerIncompatible) {
			t.Errorf("%s: %v; want a malformed-response error", name, err)
		}
	}
}

func TestTypedRefusalsAreDistinct(t *testing.T) {
	sentinels := []error{approvalwire.ErrSignerIncompatible, approvalwire.ErrStorageUncertain, approvalwire.ErrBusy, approvalwire.ErrResponseLost, approvalwire.ErrTransport}
	want := map[approvalplan.Code]error{
		approvalplan.CodeSignerIncompatible: approvalwire.ErrSignerIncompatible,
		approvalplan.CodeStorageUncertain:   approvalwire.ErrStorageUncertain,
		approvalplan.CodeBusy:               approvalwire.ErrBusy,
	}
	for _, code := range approvalplan.AllCodes {
		line, _ := approvalwire.MarshalLocalResponse(approvalwire.KindClaim, refusal(code))
		_, err := approvalwire.DecodeLocalResponse(approvalwire.KindClaim, line)
		for _, s := range sentinels {
			if got := errors.Is(err, s); got != (want[code] == s) {
				t.Errorf("%s: errors.Is(%v) = %t", code, s, got)
			}
		}
	}
}

func TestNoResponseGoldenCarriesTheTokenHashOrDraftHash(t *testing.T) {
	answers := localResponses()
	for _, name := range sortedKeys(answers) {
		line, _ := approvalwire.MarshalLocalResponse(answers[name].kind, answers[name].resp)
		for _, banned := range []string{"executor_claim_token_hash", "claim_token_hash", "draft_hash"} {
			if bytes.Contains(line, []byte(banned)) {
				t.Errorf("%s carries %s", name, banned)
			}
		}
	}
	// A summary that tries to carry one is refused as an unknown field.
	line, _ := approvalwire.MarshalLocalResponse(approvalwire.KindGet, localResponses()["submit-ok"].resp)
	smuggled := bytes.Replace(line, []byte(`"plan_hash"`), []byte(`"draft_hash":"x","plan_hash"`), 1)
	if _, err := approvalwire.DecodeLocalResponse(approvalwire.KindGet, smuggled); err == nil {
		t.Fatal("a summary carrying draft_hash decoded")
	}
}

// TestNoFrameDeclaresThePolicyKind: the daemon routes any frame whose
// top-level kind is base_manifest_sign_v1 to the policy decoder
// (frameDeclaresPolicyKind, pkg/signerkit/daemon.go:632). A v2 frame's kind is
// always one of the six.
func TestNoFrameDeclaresThePolicyKind(t *testing.T) {
	for name, req := range localRequests(t) {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(mustLocalRequest(t, req), &top); err != nil {
			t.Fatal(err)
		}
		var kind string
		if err := json.Unmarshal(top["kind"], &kind); err != nil {
			t.Fatal(err)
		}
		if kind == policywire.Kind || !slices.Contains(approvalwire.Kinds, kind) {
			t.Errorf("%s: top-level kind %q", name, kind)
		}
		if _, ok := top["proto_version"]; ok {
			t.Errorf("%s carries proto_version", name)
		}
	}
}

// TestStrictLocalDecode refuses every frame the spec does not name.
func TestStrictLocalDecode(t *testing.T) {
	for _, name := range sortedKeys(localRequests(t)) {
		line := mustLocalRequest(t, localRequests(t)[name])
		mutations := map[string][]byte{
			"requester_sub":  bytes.Replace(line, []byte(`"approval_proto":1,`), []byte(`"approval_proto":1,"requester_sub":"local-uid:1000",`), 1),
			"proto_version":  bytes.Replace(line, []byte(`"approval_proto":1,`), []byte(`"approval_proto":1,"proto_version":1,`), 1),
			"unknown field":  bytes.Replace(line, []byte(`"approval_proto":1,`), []byte(`"approval_proto":1,"extra":true,`), 1),
			"approval_proto": bytes.Replace(line, []byte(`"approval_proto":1,`), []byte(`"approval_proto":2,`), 1),
			"whitespace":     bytes.Replace(line, []byte(`"approval_proto":1,`), []byte(`"approval_proto": 1,`), 1),
			"duplicate key":  bytes.Replace(line, []byte(`"approval_proto":1,`), []byte(`"approval_proto":1,"approval_proto":1,`), 1),
			"trailing value": append(bytes.TrimSuffix(line, []byte("\n")), []byte("{}\n")...),
			"two newlines":   append(bytes.Clone(line), '\n'),
		}
		for mutation, frame := range mutations {
			_, err := approvalwire.DecodeLocalRequest(frame)
			var ce *approvalplan.CodeError
			if !errors.As(err, &ce) || ce.Code != approvalplan.CodeInvalidRequest {
				t.Errorf("%s with %s: %v; want invalid_request", name, mutation, err)
			}
		}
	}
	for name, frame := range map[string]string{
		"unknown kind": `{"approval_proto":1,"kind":"approval_vote_v2","request_id":"a2_AAAAAAAAAAAAAAAAAAAAAA"}`,
		"policy kind":  `{"approval_proto":1,"kind":"base_manifest_sign_v1"}`,
		"no kind":      `{"approval_proto":1}`,
		"not json":     `nope`,
	} {
		if _, err := approvalwire.DecodeLocalRequest([]byte(frame)); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	big := bytes.Repeat([]byte{' '}, approvalwire.MaxFrameBytes+1)
	var ce *approvalplan.CodeError
	if _, err := approvalwire.DecodeLocalRequest(big); !errors.As(err, &ce) || ce.Code != approvalplan.CodeRequestTooLarge {
		t.Errorf("oversized frame: %v; want request_too_large", err)
	}
}

func TestRequestFieldBounds(t *testing.T) {
	tooMany := make([]string, approvalplan.AwaitMaxIDs+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("a2_%022d", i)
	}
	cases := map[string]any{
		"get bad id":         approvalwire.GetRequest{ApprovalProto: 1, Kind: approvalwire.KindGet, RequestID: "r_123"},
		"get wrong kind":     approvalwire.GetRequest{ApprovalProto: 1, Kind: approvalwire.KindClaim, RequestID: idOne},
		"list zero":          approvalwire.ListRequest{ApprovalProto: 1, Kind: approvalwire.KindList},
		"list over":          approvalwire.ListRequest{ApprovalProto: 1, Kind: approvalwire.KindList, Limit: approvalwire.MaxListLimit + 1},
		"list cursor":        approvalwire.ListRequest{ApprovalProto: 1, Kind: approvalwire.KindList, Limit: 1, Cursor: "a/b"},
		"wait none":          approvalwire.WaitRequest{ApprovalProto: 1, Kind: approvalwire.KindWait},
		"wait too many":      approvalwire.WaitRequest{ApprovalProto: 1, Kind: approvalwire.KindWait, RequestIDs: tooMany},
		"wait repeat":        approvalwire.WaitRequest{ApprovalProto: 1, Kind: approvalwire.KindWait, RequestIDs: []string{idOne, idOne}},
		"wait 56s":           approvalwire.WaitRequest{ApprovalProto: 1, Kind: approvalwire.KindWait, RequestIDs: []string{idOne}, WaitSeconds: 56},
		"wait negative":      approvalwire.WaitRequest{ApprovalProto: 1, Kind: approvalwire.KindWait, RequestIDs: []string{idOne}, WaitSeconds: -1},
		"claim short token":  approvalwire.ClaimRequest{ApprovalProto: 1, Kind: approvalwire.KindClaim, RequestID: idOne, ClaimToken: "01", PlanHash: planHash},
		"claim upper hash":   approvalwire.ClaimRequest{ApprovalProto: 1, Kind: approvalwire.KindClaim, RequestID: idOne, ClaimToken: tokenAHex, PlanHash: strings.ToUpper(planHash)},
		"report sequence 2":  reportWith(func(r *approvalwire.Report) { r.ReportSequence = 2 }),
		"report no steps":    reportWith(func(r *approvalwire.Report) { r.Steps = nil }),
		"report bad status":  reportWith(func(r *approvalwire.Report) { r.Steps[2].Status = "running" }),
		"report bad class":   reportWith(func(r *approvalwire.Report) { r.Class = "partial" }),
		"report ordinals":    reportWith(func(r *approvalwire.Report) { r.ExecutedOrdinals = []int{2, 1} }),
		"report digest":      reportWith(func(r *approvalwire.Report) { r.ResultDigest = "" }),
		"report negative":    reportWith(func(r *approvalwire.Report) { n := int64(-1); r.Steps[0].StdoutBytes = &n }),
		"submit no token":    submitWith(t, func(d *approvalplan.ApprovalDraft) { d.ExecutorClaimTokenHash = "" }),
		"submit bad reason":  submitWith(t, func(d *approvalplan.ApprovalDraft) { d.Rationale = "" }),
		"submit wrong proto": approvalwire.SubmitRequest{ApprovalProto: 2, Kind: approvalwire.KindSubmit, Draft: draft(t, "write")},
	}
	for name, req := range cases {
		_, err := approvalwire.MarshalLocalRequest(req)
		var ce *approvalplan.CodeError
		if !errors.As(err, &ce) {
			t.Errorf("%s: %v; want a *CodeError", name, err)
		}
	}
	// A report whose class disagrees with its steps is the signer's
	// invalid_report, not a wire refusal (SA-4 Report).
	if _, err := approvalwire.MarshalLocalRequest(reportWith(func(r *approvalwire.Report) { r.Class = approvalplan.ClassSucceeded })); err != nil {
		t.Errorf("incoherent but well-shaped report refused by the wire: %v", err)
	}
	if _, err := approvalwire.MarshalLocalRequest(struct{ Kind string }{"approval_get_v2"}); err == nil {
		t.Error("an arbitrary type marshaled as a request")
	}
}

func reportWith(f func(*approvalwire.Report)) approvalwire.ReportRequest {
	r := report()
	f(&r)
	return approvalwire.ReportRequest{ApprovalProto: 1, Kind: approvalwire.KindReport, RequestID: idOne, ClaimToken: tokenAHex, PlanHash: planHash, Report: r}
}

func submitWith(t *testing.T, f func(*approvalplan.ApprovalDraft)) approvalwire.SubmitRequest {
	d := draft(t, "write")
	f(&d)
	return approvalwire.SubmitRequest{ApprovalProto: 1, Kind: approvalwire.KindSubmit, Draft: d}
}

func TestDraftRefusalsKeepTheirCodeUnderDraft(t *testing.T) {
	d := draft(t, "write")
	d.CommandJob.Steps[0].ExactCommand = "SSHGATE_REVOKE"
	d.CommandJob.Steps[0].CommandSHA256 = hex64("SSHGATE_REVOKE")
	_, err := approvalwire.MarshalLocalRequest(approvalwire.SubmitRequest{ApprovalProto: 1, Kind: approvalwire.KindSubmit, Draft: d})
	var ce *approvalplan.CodeError
	if !errors.As(err, &ce) || ce.Code != approvalplan.CodeReservedVerb || !strings.HasPrefix(ce.Field, "draft.") {
		t.Fatalf("%v; want reserved_verb under draft.", err)
	}
	d = draft(t, "write")
	d.CommandJob.Steps[0].Target.ResolvedUser = strings.Repeat("<", approvalplan.MaxUserBytes)
	big := approvalwire.SubmitRequest{ApprovalProto: 1, Kind: approvalwire.KindSubmit, Draft: d}
	for len(mustJSON(t, big.Draft)) <= approvalplan.MaxDraftBytes {
		big.Draft.Rationale += "x"
		big.Draft.CommandJob.Steps = append(big.Draft.CommandJob.Steps, big.Draft.CommandJob.Steps[0])
	}
	_, err = approvalwire.MarshalLocalRequest(big)
	if !errors.As(err, &ce) || ce.Code != approvalplan.CodeRequestTooLarge || ce.Field != "draft" {
		t.Fatalf("oversized draft: %v; want request_too_large", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStrictLocalResponseDecode(t *testing.T) {
	submitOK, _ := approvalwire.MarshalLocalResponse(approvalwire.KindSubmit, localResponses()["submit-ok"].resp)
	claimOK, _ := approvalwire.MarshalLocalResponse(approvalwire.KindClaim, localResponses()["claim-signatures"].resp)
	notFound, _ := approvalwire.MarshalLocalResponse(approvalwire.KindGet, refusal(approvalplan.CodeNotFound))
	cases := map[string]struct {
		kind  string
		frame []byte
	}{
		"unknown field":         {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"ok":true`), []byte(`"ok":true,"x":1`), 1)},
		"summary for claim":     {approvalwire.KindClaim, submitOK},
		"claim for submit":      {approvalwire.KindSubmit, claimOK},
		"ok plus error":         {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"ok":true`), []byte(`"ok":true,"error":{"code":"busy","message":"x"}`), 1)},
		"refusal for no kind":   {"approval_vote_v2", notFound},
		"unknown code":          {approvalwire.KindGet, []byte(`{"approval_proto":1,"ok":false,"error":{"code":"clock_regressed","message":"x"}}`)},
		"not_found free text":   {approvalwire.KindGet, bytes.Replace(notFound, []byte(approvalwire.MessageNotFound), []byte("no such request for local-uid:1001"), 1)},
		"empty message":         {approvalwire.KindGet, []byte(`{"approval_proto":1,"ok":false,"error":{"code":"conflict","message":""}}`)},
		"control in message":    {approvalwire.KindGet, []byte(`{"approval_proto":1,"ok":false,"error":{"code":"conflict","message":"a\nb"}}`)},
		"refusal with payload":  {approvalwire.KindGet, []byte(`{"approval_proto":1,"ok":false,"error":{"code":"conflict","message":"x"},"next_cursor":"c"}`)},
		"proto 2":               {approvalwire.KindReport, []byte(`{"approval_proto":2,"ok":true}`)},
		"bad summary enum":      {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"approval_status":"pending"`), []byte(`"approval_status":"waiting"`), 1)},
		"signature not sig":     {approvalwire.KindClaim, bytes.Replace(claimOK, []byte("SSHGATE_SIG:"), []byte("SSHGATE_SIX:"), 1)},
		"claim reason on sigs":  {approvalwire.KindClaim, bytes.Replace(claimOK, []byte(`"status":"signatures"`), []byte(`"status":"signatures","reason":"clock_skew"`), 1)},
		"window_closed reason":  {approvalwire.KindClaim, []byte(`{"approval_proto":1,"ok":true,"claim":{"status":"materialization_error","reason":"window_closed"}}`)},
		"not_ready with sigs":   {approvalwire.KindClaim, bytes.Replace(claimOK, []byte(`"status":"signatures"`), []byte(`"status":"not_ready"`), 1)},
		"empty":                 {approvalwire.KindReport, []byte("\n")},
		"local time":            {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"created_at":"2026-10-15T09:30:00Z"`), []byte(`"created_at":"2026-10-15T15:00:00+05:30"`), 1)},
		"wait cursor":           {approvalwire.KindWait, []byte(`{"approval_proto":1,"ok":true,"next_cursor":"abc"}`)},
		"grant id on a job":     {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"class":"live"`), []byte(`"class":"live","grant_id":"a2_AAAAAAAAAAAAAAAAAAAAAA"`), 1)},
		"register key summary":  {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"kind":"command_job"`), []byte(`"kind":"register_transfer_key"`), 1)},
		"assist revision 2":     {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"assist_revision":0`), []byte(`"assist_revision":2`), 1)},
		"executed out of order": {approvalwire.KindSubmit, bytes.Replace(submitOK, []byte(`"execution_status":"none"`), []byte(`"execution_status":"none","executed_ordinals":[3,1]`), 1)},
	}
	for name, c := range cases {
		_, err := approvalwire.DecodeLocalResponse(c.kind, c.frame)
		var we *approvalwire.WireError
		if err == nil || errors.As(err, &we) || errors.Is(err, approvalwire.ErrSignerIncompatible) {
			t.Errorf("%s: %v; want a malformed-response error", name, err)
		}
	}
}

func FuzzDecodeLocalRequest(f *testing.F) {
	for _, req := range localRequests(f) {
		line, err := approvalwire.MarshalLocalRequest(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		req, err := approvalwire.DecodeLocalRequest(line)
		if err != nil {
			var ce *approvalplan.CodeError
			if !errors.As(err, &ce) {
				t.Fatalf("refusal %v is not a *CodeError", err)
			}
			return
		}
		again, err := approvalwire.MarshalLocalRequest(req)
		if err != nil {
			t.Fatalf("decoded request does not re-marshal: %v", err)
		}
		if !bytes.Equal(again, line) && !bytes.Equal(again, append(bytes.Clone(line), '\n')) {
			t.Fatalf("decode accepted a non-canonical frame:\n%q\n%q", line, again)
		}
	})
}

// TestWorstCasePagesFitOneFrame: List and Wait return summaries, not plans,
// and a Claim returns at most one signature per signed leg, so the largest
// legal answer of each fits MaxFrameBytes.
func TestWorstCasePagesFitOneFrame(t *testing.T) {
	worst := syncFinalSummary(idOne)
	reason := strings.Repeat("<", approvalwire.MaxMessageLen) // json escapes '<' to six bytes
	worst.TerminalReason, worst.NotExecutableReason, worst.Pruned = reason, reason, true
	worst.ExecutedOrdinals = make([]int, approvalplan.MaxSteps)
	for i := range worst.ExecutedOrdinals {
		worst.ExecutedOrdinals[i] = i + 1
	}
	page := make([]approvalplan.Summary, approvalwire.MaxListLimit)
	for i := range page {
		page[i] = worst
	}
	for _, kind := range []string{approvalwire.KindList, approvalwire.KindWait} {
		resp := ok()
		resp.Summaries = page
		if kind == approvalwire.KindList {
			resp.NextCursor = strings.Repeat("c", approvalwire.MaxCursorBytes)
		}
		if _, err := approvalwire.MarshalLocalResponse(kind, resp); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	// K19's byte budget spread over the most signed steps, every byte escaped
	// sixfold, as approvalplan's maxSignatureLen bounds an envelope.
	perStep := approvalplan.MaxTotalBytes / approvalplan.MaxSteps
	payload := 6*perStep + 6*approvalplan.MaxFingerprintBytes + 256
	sig := "SSHGATE_SIG:" + strings.Repeat("A", 86) + ":" + strings.Repeat("B", 4*((payload+2)/3))
	sigs := make([]string, approvalplan.MaxSteps)
	for i := range sigs {
		sigs[i] = sig
	}
	decided := t0
	resp := ok()
	resp.Claim = &approvalwire.ClaimAnswer{Status: approvalplan.ClaimSignatures, DecidedAt: &decided, Signatures: sigs}
	if _, err := approvalwire.MarshalLocalResponse(approvalwire.KindClaim, resp); err != nil {
		t.Fatal(err)
	}
}

func TestClaimSignaturesRequireBothFields(t *testing.T) {
	for _, missing := range []string{"decided_at", "signatures", "both"} {
		for _, hosted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hosted=%v", missing, hosted), func(t *testing.T) {
				answer := localResponses()["claim-signatures"]
				if missing != "signatures" {
					answer.resp.Claim.DecidedAt = nil
				}
				if missing != "decided_at" {
					answer.resp.Claim.Signatures = nil
				}
				// Preserve canonical field order so validation reaches the Claim.
				frame, err := json.Marshal(answer.resp)
				if err != nil {
					t.Fatal(err)
				}
				if hosted {
					_, err = approvalwire.ClassifyHostedResponse(approvalwire.KindClaim, 200, "application/json", frame)
				} else {
					_, err = approvalwire.DecodeLocalResponse(approvalwire.KindClaim, append(frame, '\n'))
				}
				if err == nil {
					t.Fatal("incomplete signatures answer accepted")
				}
			})
		}
	}
}

func FuzzClaimResponseNoPanic(f *testing.F) {
	for _, fields := range []string{``, `,"signatures":["x"]`, `,"decided_at":"2026-10-15T09:30:20Z"`} {
		f.Add([]byte(`{"approval_proto":1,"ok":true,"claim":{"status":"signatures"` + fields + `}}`))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		approvalwire.DecodeLocalResponse(approvalwire.KindClaim, append(bytes.Clone(body), '\n'))
		approvalwire.ClassifyHostedResponse(approvalwire.KindClaim, 200, "application/json", body)
	})
}
