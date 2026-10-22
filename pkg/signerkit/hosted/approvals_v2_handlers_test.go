package hosted

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

func approvalHTTPFixture(t *testing.T) (*Server, *ApprovalV2Engine, *sqlitestore.DB) {
	t.Helper()
	e, db, _ := approvalEngineFixture(t, false)
	s := NewServer("secret", db, log.New(io.Discard, "", 0))
	s.MachineClientID = "client"
	if err := s.AttachApprovals(e); err != nil {
		t.Fatal(err)
	}
	return s, e, db
}
func approvalHTTPRequest(s *Server, method, target string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func approvalHTTPBody(t *testing.T, body any) []byte {
	t.Helper()
	data, err := aw.MarshalHostedBody(body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func approvalHTTPResponse(t *testing.T, kind string, w *httptest.ResponseRecorder) aw.Response {
	t.Helper()
	resp, err := aw.ClassifyHostedResponse(kind, w.Code, w.Header().Get("Content-Type"), w.Body.Bytes())
	if err != nil {
		t.Fatalf("response: %d %s: %v", w.Code, w.Body.String(), err)
	}
	return resp
}
func approvalHTTPError(t *testing.T, w *httptest.ResponseRecorder, code ap.Code) {
	t.Helper()
	status, want, err := aw.MarshalHostedResponse(aw.KindGet, aw.ErrorResponse(code, string(code)))
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != status || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("got %d %s; want %d %s", w.Code, w.Body.String(), status, want)
	}
}

func TestApprovalHTTPRouting(t *testing.T) {
	golden, err := os.ReadFile("../../../src/approvalwire/testdata/hosted/response-not-found.json")
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := aw.MarshalHostedResponse(aw.KindGet, aw.ErrorResponse(ap.CodeNotFound, ""))
	if err != nil || !bytes.Equal(golden, encoded) {
		t.Fatal("not_found golden mismatch")
	}

	for _, policy := range []bool{false, true} {
		t.Run(fmt.Sprint(policy), func(t *testing.T) {
			s, e, _ := approvalHTTPFixture(t)
			if policy {
				p, _ := newPolicyRouteServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
				s.policyMachine = p.policyMachine
			}
			for _, path := range []string{"/v2", "/v2/", "/v2/other", "/v2/approvals/", "/v2/approvals/a/b", "/v2/approvals//claim", "/v2/approvals/" + statetest.ID(99), "/v2/approvals/%2f", "/v2/approvals/../approvals", "//v2/approvals", "/v2//approvals", "/v2/%61pprovals", "/x/../v2/approvals", "/ui/../v2/approvals", "/x%2fy/../v2/approvals"} {
				approvalHTTPError(t, approvalHTTPRequest(s, "GET", path, nil), ap.CodeNotFound)
			}
			submitApproval(t, e, 1)
			approvalHTTPResponse(t, aw.KindGet, approvalHTTPRequest(s, "GET", aw.HostedRoot+"/"+statetest.ID(1), nil))
		})
	}
}

func TestApprovalHTTPAttachAndAuth(t *testing.T) {
	s, e, db := approvalHTTPFixture(t)
	if s.AttachApprovals(e) == nil {
		t.Fatal("double attach accepted")
	}
	bare := NewServer("secret", db, log.New(io.Discard, "", 0))
	if bare.AttachApprovals(e) == nil {
		t.Fatal("empty client accepted")
	}
	bare.MachineClientID = "client"
	if bare.AttachApprovals(nil) == nil {
		t.Fatal("nil engine accepted")
	}
	data := approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: approvalDraft(1)})
	for _, auth := range []string{"", "Bearer wrong"} {
		r := httptest.NewRequest("POST", aw.HostedRoot, bytes.NewReader(data))
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("unauthenticated response %d", w.Code)
		}
	}
	if _, err := db.ReadV2(context.Background(), approvalKey(1)); err == nil {
		t.Fatal("unauthenticated submit stored")
	}
}

func TestApprovalHTTPOwnerAndPagination(t *testing.T) {
	s, _, _ := approvalHTTPFixture(t)
	for _, sub := range []string{"", "local-uid:1", "local-uid:2"} {
		for id := 1; id <= 2; id++ {
			body := approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, RequesterSub: sub, Draft: approvalDraft(id)})
			resp := approvalHTTPResponse(t, aw.KindSubmit, approvalHTTPRequest(s, "POST", aw.HostedRoot, body))
			if resp.Summary.RequestID != statetest.ID(id) {
				t.Fatal("wrong submit summary")
			}
		}
	}
	for _, sub := range []string{"", "local-uid:1", "local-uid:2"} {
		q, _ := (aw.HostedListQuery{RequesterSub: sub, Limit: 1}).Encode()
		page := approvalHTTPResponse(t, aw.KindList, approvalHTTPRequest(s, "GET", aw.HostedRoot+"?"+q, nil))
		if len(page.Summaries) != 1 || page.NextCursor == "" {
			t.Fatal("missing page")
		}
		q, _ = (aw.HostedListQuery{RequesterSub: sub, Limit: 1, Cursor: page.NextCursor}).Encode()
		next := approvalHTTPResponse(t, aw.KindList, approvalHTTPRequest(s, "GET", aw.HostedRoot+"?"+q, nil))
		if len(next.Summaries) != 1 || next.NextCursor != "" || next.Summaries[0].RequestID == page.Summaries[0].RequestID {
			t.Fatal("bad continuation")
		}
	}
	for _, sub := range []string{"local-uid:3"} {
		q, _ := (aw.HostedGetQuery{RequesterSub: sub}).Encode()
		approvalHTTPError(t, approvalHTTPRequest(s, "GET", aw.HostedRoot+"/"+statetest.ID(1)+"?"+q, nil), ap.CodeNotFound)
		body := approvalHTTPBody(t, aw.HostedWaitBody{ApprovalProto: 1, RequesterSub: sub, RequestIDs: []string{statetest.ID(1)}, WaitSeconds: 0})
		approvalHTTPError(t, approvalHTTPRequest(s, "POST", aw.HostedRoot+"/wait", body), ap.CodeNotFound)
	}
	s.MachineClientID = "foreign-client"
	approvalHTTPError(t, approvalHTTPRequest(s, "GET", aw.HostedRoot+"/"+statetest.ID(1), nil), ap.CodeNotFound)
}

func TestApprovalHTTPClaimAndReport(t *testing.T) {
	s, e, db := approvalHTTPFixture(t)
	claim := approvalHTTPReady(t, e, db)
	body := approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, ClaimToken: hex.EncodeToString(claim.Token[:]), PlanHash: claim.PlanHash})
	path := aw.HostedRoot + "/" + statetest.ID(1)
	foreign := approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, RequesterSub: "local-uid:99", ClaimToken: hex.EncodeToString(claim.Token[:]), PlanHash: claim.PlanHash})
	approvalHTTPError(t, approvalHTTPRequest(s, "POST", path+"/claim", foreign), ap.CodeNotFound)

	resp := approvalHTTPResponse(t, aw.KindClaim, approvalHTTPRequest(s, "POST", path+"/claim", body))
	if resp.Claim.Status != ap.ClaimSignatures || !reflect.DeepEqual(resp.Claim.Signatures, []string{approvalHTTPSignature}) {
		t.Fatal("claim lost signatures")
	}
	report := approvalReport(claim)
	data := approvalHTTPBody(t, aw.HostedReportBody{ApprovalProto: 1, ClaimToken: hex.EncodeToString(claim.Token[:]), PlanHash: claim.PlanHash, Report: aw.Report{ReportSequence: 1, Steps: report.Body.Steps, Class: report.Body.Class, ExecutedOrdinals: report.Body.ExecutedOrdinals, Partial: report.Body.Partial, ResultDigest: report.Body.ResultDigest}})

	var foreignReport aw.HostedReportBody
	if err := json.Unmarshal(data, &foreignReport); err != nil {
		t.Fatal(err)
	}
	foreignReport.RequesterSub = "local-uid:99"
	approvalHTTPError(t, approvalHTTPRequest(s, "POST", path+"/report", approvalHTTPBody(t, foreignReport)), ap.CodeNotFound)
	approvalHTTPResponse(t, aw.KindReport, approvalHTTPRequest(s, "POST", path+"/report", data))
	if readApproval(t, db, 1).Record.Header.FinalReport == nil {
		t.Fatal("report not committed")
	}
	resp = approvalHTTPResponse(t, aw.KindClaim, approvalHTTPRequest(s, "POST", path+"/claim", body))
	if resp.Claim.Status != ap.ClaimExecutionReported || len(resp.Claim.Signatures) != 0 {
		t.Fatal("report did not erase authority")
	}
}

func TestApprovalHTTPValidation(t *testing.T) {
	s, _, db := approvalHTTPFixture(t)
	body := approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: approvalDraft(1)})
	for _, data := range [][]byte{append(append([]byte{}, body...), '\n'), []byte(`{"approval_proto":1,"client_id":"other"}`), []byte(strings.Repeat("x", aw.MaxFrameBytes+1))} {
		w := approvalHTTPRequest(s, "POST", aw.HostedRoot, data)
		if w.Code != 400 && w.Code != 413 {
			t.Fatalf("bad body admitted: %d %s", w.Code, w.Body.String())
		}
	}
	for _, query := range []string{"limit=1&client_id=other", "limit=1&requester_sub=bad", "limit=1&limit=2", "cursor=YQ&limit=1"} {
		approvalHTTPError(t, approvalHTTPRequest(s, "GET", aw.HostedRoot+"?"+query, nil), ap.CodeInvalidRequest)
	}
	approvalHTTPError(t, approvalHTTPRequest(s, "POST", aw.HostedRoot+"?client_id=other", body), ap.CodeInvalidRequest)
	for _, raw := range []string{`{"c":0,"r":"bad"}`, `{"c":0,"r":"` + statetest.ID(1) + `","extra":0}`, `{"c":0,"r":"` + statetest.ID(1) + `"} `} {
		query, err := (aw.HostedListQuery{Limit: 1, Cursor: base64.RawURLEncoding.EncodeToString([]byte(raw))}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		approvalHTTPError(t, approvalHTTPRequest(s, "GET", aw.HostedRoot+"?"+query, nil), ap.CodeInvalidRequest)
	}

	if _, err := db.ReadV2(context.Background(), approvalKey(1)); err == nil {
		t.Fatal("bad input stored")
	}
}

func TestApprovalVoteRechecksRole(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	submitApproval(t, e, 1)
	before := readApproval(t, db, 1).Record
	for _, id := range []string{"missing", "operator"} {
		if id == "operator" {
			tx, err := db.BeginV2(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec("UPDATE users SET role='admin' WHERE id='operator'"); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		_, err := e.Vote(context.Background(), approvalKey(1), ap.CastVote{Operator: id, Decision: ap.VoteDeny, Authn: "webauthn", Hosted: &ap.HostedTap{PlanHash: before.Header.PlanHash, Actions: ap.ActionsAt(0)}})
		requireApprovalCode(t, err, ap.CodeInvalidRequest)
		after := readApproval(t, db, 1).Record
		a, _ := json.Marshal(before)
		b, _ := json.Marshal(after)
		if !bytes.Equal(a, b) {
			t.Fatal("ineligible vote changed row")
		}
	}
}

func TestApprovalHTTPUnsupportedAndReserved(t *testing.T) {
	for _, route := range []ap.Route{ap.RouteSignedWrite, ap.RouteSignedReveal, ap.RouteSignedAdmin, ap.RouteUnsignedRead} {
		t.Run(string(route), func(t *testing.T) {
			s, _, db := approvalHTTPFixture(t)
			draft := approvalDraft(1)
			draft.CommandJob.Steps[0].Route = route
			draft.CommandJob.Steps[0].ExactCommand = "SSHGATE_XFER_SEND test"
			raw, _ := json.Marshal(aw.HostedSubmitBody{ApprovalProto: 1, Draft: draft})
			approvalHTTPError(t, approvalHTTPRequest(s, "POST", aw.HostedRoot, raw), ap.CodeReservedVerb)
			if _, err := db.ReadV2(context.Background(), approvalKey(1)); err == nil {
				t.Fatal("reserved verb stored")
			}
		})
	}
	s, _, db := approvalHTTPFixture(t)
	draft := approvalDraft(1)
	draft.CommandJob.Steps[0].Route = ap.RouteSignedReveal
	raw := approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: draft})
	approvalHTTPError(t, approvalHTTPRequest(s, "POST", aw.HostedRoot, raw), ap.CodeInvalidRequest)
	draft = statetest.GrantDraft(statetest.ID(1), "web-1", time.Hour, statetest.T0, "true")
	raw = approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: draft})
	approvalHTTPError(t, approvalHTTPRequest(s, "POST", aw.HostedRoot, raw), ap.CodeInvalidRequest)
	if _, err := db.ReadV2(context.Background(), approvalKey(1)); err == nil {
		t.Fatal("unsupported kind stored")
	}
}

func TestApprovalHTTPBusyAndUncertain(t *testing.T) {
	for _, kind := range []string{aw.KindSubmit, aw.KindGet, aw.KindList, aw.KindWait, aw.KindClaim, aw.KindReport} {
		t.Run(kind, func(t *testing.T) {
			s, e, db := approvalHTTPFixture(t)
			claim := approvalHTTPReady(t, e, db)
			if kind == aw.KindReport {
				if _, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil {
					t.Fatal(err)
				}
			}
			before := readApproval(t, db, 1).Record
			token := hex.EncodeToString(claim.Token[:])
			method, path, _ := aw.HostedRoute(kind, func() string {
				if kind == aw.KindGet || kind == aw.KindClaim || kind == aw.KindReport {
					return statetest.ID(1)
				}
				return ""
			}())
			var body []byte
			switch kind {
			case aw.KindSubmit:
				body = approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: approvalDraft(2)})
			case aw.KindList:
				path += "?limit=1"
			case aw.KindWait:
				body = approvalHTTPBody(t, aw.HostedWaitBody{ApprovalProto: 1, RequestIDs: []string{statetest.ID(1)}, WaitSeconds: 0})
			case aw.KindClaim:
				body = approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, ClaimToken: token, PlanHash: claim.PlanHash})
			case aw.KindReport:
				report := approvalReport(claim)
				body = approvalHTTPBody(t, aw.HostedReportBody{ApprovalProto: 1, ClaimToken: token, PlanHash: claim.PlanHash, Report: aw.Report{ReportSequence: 1, Class: report.Body.Class, Steps: report.Body.Steps, ExecutedOrdinals: report.Body.ExecutedOrdinals, ResultDigest: report.Body.ResultDigest}})
			}
			faults := approvalFaultStore{ApprovalV2Store: db, beginErr: approvalBusy(5)}
			if kind == aw.KindGet || kind == aw.KindWait {
				faults.readErr = approvalBusy(5)
			}
			if kind == aw.KindList {
				faults.listErr = approvalBusy(5)
			}
			e.config.Store = faults
			w := approvalHTTPRequest(s, method, path, body)
			approvalHTTPError(t, w, ap.CodeBusy)
			if w.Header().Get("Retry-After") != "1" {
				t.Fatal("busy retry header")
			}
			if !reflect.DeepEqual(before, readApproval(t, db, 1).Record) {
				t.Fatal("busy changed record")
			}
			e.config.Store = db
			if kind == aw.KindSubmit || kind == aw.KindClaim || kind == aw.KindReport {
				e.commit = func(tx *sql.Tx) error {
					if err := tx.Commit(); err != nil {
						return err
					}
					return errors.New("lost commit acknowledgement")
				}
				approvalHTTPError(t, approvalHTTPRequest(s, method, path, body), ap.CodeStorageUncertain)
				e.commit = func(tx *sql.Tx) error { return tx.Commit() }
			}
			approvalHTTPResponse(t, kind, approvalHTTPRequest(s, method, path, body))
		})
	}
}

type approvalCountingBody struct{ count int }

func (b *approvalCountingBody) Read(p []byte) (int, error) {
	if b.count >= aw.MaxFrameBytes+100 {
		return 0, io.EOF
	}
	n := min(len(p), aw.MaxFrameBytes+100-b.count)
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	b.count += n
	return n, nil
}
func TestApprovalHTTPBodyBound(t *testing.T) {
	s, _, _ := approvalHTTPFixture(t)
	body := &approvalCountingBody{}
	r := httptest.NewRequest("POST", aw.HostedRoot, body)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	approvalHTTPError(t, w, ap.CodeRequestTooLarge)
	if body.count != aw.MaxFrameBytes+1 {
		t.Fatalf("read %d bytes", body.count)
	}
}

var approvalHTTPSignature = "SSHGATE_SIG:" + strings.Repeat("Ab-_", 21) + "Q0:eyJjbWQiOiJ0cnVlIn0"

func approvalHTTPReady(t *testing.T, e *ApprovalV2Engine, db *sqlitestore.DB) ap.Claim {
	t.Helper()
	claim := approvalReady(t, e, db)
	e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
		return []string{approvalHTTPSignature}, nil
	})
	return claim
}
