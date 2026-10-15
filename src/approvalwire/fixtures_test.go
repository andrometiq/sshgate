package approvalwire_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
)

var update = flag.Bool("update", false, "rewrite the goldens in testdata/")

// golden compares got with testdata/name. The goldens freeze the wire: a
// change needs a new approval_proto, never a regenerated golden alone.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden %s differs\n got: %.600s\nwant: %.600s", name, got, want)
	}
}

const (
	idOne = "a2_AAAAAAAAAAAAAAAAAAAAAA"
	idTwo = "a2_BBBBBBBBBBBBBBBBBBBBBB"
)

var (
	t0        = time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)
	tokenA    = [32]byte{1, 2, 3}
	tokenAHex = hex.EncodeToString(tokenA[:])
	planHash  = hex64("plan")
	signature = "SSHGATE_SIG:" + strings.Repeat("Ab-_", 21) + "Q0" + ":eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCJ9"
)

func hex64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// draft loads one of approvalplan's golden drafts, so the wire freezes the
// same bytes the draft_hash goldens do.
func draft(t testing.TB, name string) approvalplan.ApprovalDraft {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "approvalplan", "testdata", "drafts", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := approvalplan.DecodeDraft(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func pendingSummary(id string) approvalplan.Summary {
	return approvalplan.Summary{
		RequestID: id, RecordHandle: approvalplan.RecordHandle(approvalplan.RecordKey("local-uid:1000", id)),
		Kind: approvalplan.KindCommandJob, PlanHash: planHash, Coordinator: approvalplan.CoordinatorExecutor,
		CreatedAt: t0, RequestExpiresAt: t0.Add(24 * time.Hour),
		ApprovalStatus: approvalplan.ApprovalPending, AssistState: approvalplan.AssistPreparing,
		ExecutionStatus: approvalplan.ExecutionNone, NotificationStatus: approvalplan.NotificationSending,
		Class: approvalplan.ClassLive,
	}
}

func syncFinalSummary(id string) approvalplan.Summary {
	s := pendingSummary(id)
	deadline, decided := t0.Add(approvalplan.SyncClaimWindow), t0.Add(20*time.Second)
	s.Coordinator, s.SyncClaimDeadline, s.DecidedAt = approvalplan.CoordinatorInProcessSync, &deadline, &decided
	s.ApprovalStatus, s.AssistState, s.AssistRevision = approvalplan.ApprovalApproved, approvalplan.AssistReady, 1
	s.ExecutionStatus, s.ExecutionClass = approvalplan.ExecutionFinal, approvalplan.ClassFailed
	s.ExecutedOrdinals, s.Partial = []int{1, 2}, true
	s.NotificationStatus, s.Class = approvalplan.NotificationSent, approvalplan.ClassSettled
	return s
}

func shedGrantSummary(id string) approvalplan.Summary {
	s := pendingSummary(id)
	decided, expires := t0.Add(time.Minute), t0.Add(time.Minute+time.Hour)
	s.Kind, s.Coordinator = approvalplan.KindStandingGrant, ""
	s.ApprovalStatus, s.DecidedAt, s.AssistState, s.AssistRevision = approvalplan.ApprovalApproved, &decided, approvalplan.AssistUnavailable, 1
	s.ExecutionStatus, s.NotificationStatus, s.Class = approvalplan.ExecutionNotApplicable, approvalplan.NotificationSent, approvalplan.ClassLive
	s.Pruned, s.GrantID, s.GrantExpiresAt = true, id, &expires
	return s
}

func deniedSummary(id string) approvalplan.Summary {
	s := pendingSummary(id)
	decided := t0.Add(2 * time.Minute)
	s.ApprovalStatus, s.TerminalReason, s.DecidedAt = approvalplan.ApprovalDenied, "denied by telegram:42", &decided
	s.AssistState, s.AssistRevision = approvalplan.AssistReady, 1
	s.NotificationStatus, s.Class = approvalplan.NotificationSent, approvalplan.ClassSettled
	return s
}

func report() approvalwire.Report {
	zero, exit1 := 0, 1
	out, errBytes := int64(120), int64(0)
	truncated := false
	return approvalwire.Report{
		ReportSequence: approvalwire.ReportSequence,
		Steps: []approvalplan.StepReport{
			{Ordinal: 1, Status: approvalplan.StepSucceeded, ExitCode: &zero, StdoutBytes: &out, StderrBytes: &errBytes, Truncated: &truncated},
			{Ordinal: 2, Status: approvalplan.StepFailed, ExitCode: &exit1, StdoutBytes: &errBytes, StderrBytes: &out, Truncated: &truncated},
			{Ordinal: 3, Status: approvalplan.StepSkipped},
		},
		Class: approvalplan.ClassFailed, ExecutedOrdinals: []int{1, 2}, Partial: true, ResultDigest: hex64("result"),
	}
}

func ok() approvalwire.Response {
	return approvalwire.Response{ApprovalProto: approvalwire.Proto, OK: true}
}

// localRequests is one golden frame per local kind, plus variants.
func localRequests(t testing.TB) map[string]any {
	return map[string]any{
		"submit-write":    approvalwire.SubmitRequest{ApprovalProto: 1, Kind: approvalwire.KindSubmit, Draft: draft(t, "write")},
		"submit-transfer": approvalwire.SubmitRequest{ApprovalProto: 1, Kind: approvalwire.KindSubmit, Draft: draft(t, "transfer")},
		"submit-grant":    approvalwire.SubmitRequest{ApprovalProto: 1, Kind: approvalwire.KindSubmit, Draft: draft(t, "grant-commands")},
		"get":             approvalwire.GetRequest{ApprovalProto: 1, Kind: approvalwire.KindGet, RequestID: idOne},
		"list-first":      approvalwire.ListRequest{ApprovalProto: 1, Kind: approvalwire.KindList, Limit: 50},
		"list-next":       approvalwire.ListRequest{ApprovalProto: 1, Kind: approvalwire.KindList, Limit: 50, Cursor: "c2_cursor-1"},
		"wait":            approvalwire.WaitRequest{ApprovalProto: 1, Kind: approvalwire.KindWait, RequestIDs: []string{idOne, idTwo}, WaitSeconds: 55},
		"claim":           approvalwire.ClaimRequest{ApprovalProto: 1, Kind: approvalwire.KindClaim, RequestID: idOne, ClaimToken: tokenAHex, PlanHash: planHash},
		"report":          approvalwire.ReportRequest{ApprovalProto: 1, Kind: approvalwire.KindReport, RequestID: idOne, ClaimToken: tokenAHex, PlanHash: planHash, Report: report()},
	}
}

type answer struct {
	kind string
	resp approvalwire.Response
}

// localResponses is one golden answer per kind and claim status, plus every
// refusal code.
func localResponses() map[string]answer {
	decided := t0.Add(20 * time.Second)
	with := func(f func(*approvalwire.Response)) approvalwire.Response {
		r := ok()
		f(&r)
		return r
	}
	claim := func(c approvalwire.ClaimAnswer) approvalwire.Response {
		return with(func(r *approvalwire.Response) { r.Claim = &c })
	}
	pending, final, grant, denied := pendingSummary(idOne), syncFinalSummary(idOne), shedGrantSummary(idOne), deniedSummary(idTwo)
	out := map[string]answer{
		"submit-ok":      {approvalwire.KindSubmit, with(func(r *approvalwire.Response) { r.Summary = &pending })},
		"get-final":      {approvalwire.KindGet, with(func(r *approvalwire.Response) { r.Summary = &final })},
		"get-shed-grant": {approvalwire.KindGet, with(func(r *approvalwire.Response) { r.Summary = &grant })},
		"list-page": {approvalwire.KindList, with(func(r *approvalwire.Response) {
			r.Summaries, r.NextCursor = []approvalplan.Summary{pending, denied}, "c2_cursor-2"
		})},
		"list-empty": {approvalwire.KindList, ok()},
		"wait-ok":    {approvalwire.KindWait, with(func(r *approvalwire.Response) { r.Summaries = []approvalplan.Summary{pending, denied} })},
		"claim-signatures": {approvalwire.KindClaim, claim(approvalwire.ClaimAnswer{
			Status: approvalplan.ClaimSignatures, DecidedAt: &decided, Signatures: []string{signature, signature},
		})},
		"claim-execution-reported":    {approvalwire.KindClaim, claim(approvalwire.ClaimAnswer{Status: approvalplan.ClaimExecutionReported, Class: approvalplan.ClassSucceeded})},
		"claim-materialization-error": {approvalwire.KindClaim, claim(approvalwire.ClaimAnswer{Status: approvalplan.ClaimMaterializationError, Reason: approvalplan.MintReasonGrantNotLive})},
		"report-ok":                   {approvalwire.KindReport, ok()},
	}
	for _, s := range []approvalplan.ClaimStatus{approvalplan.ClaimNotReady, approvalplan.ClaimDenied, approvalplan.ClaimCanceled, approvalplan.ClaimExpired, approvalplan.ClaimError} {
		out["claim-"+strings.ReplaceAll(string(s), "_", "-")] = answer{approvalwire.KindClaim, claim(approvalwire.ClaimAnswer{Status: s})}
	}
	return out
}

func refusal(code approvalplan.Code) approvalwire.Response {
	return approvalwire.ErrorResponse(code, "refused: "+string(code))
}
