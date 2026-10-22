package hosted

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

func TestApprovalHTTPFullAndShedOwnerScope(t *testing.T) {
	for _, shed := range []bool{false, true} {
		t.Run(fmt.Sprint(shed), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			s := NewServer("secret", db, log.New(io.Discard, "", 0))
			s.MachineClientID = "client"
			if err := s.AttachApprovals(e); err != nil {
				t.Fatal(err)
			}
			claim := approvalHTTPReady(t, e, db)
			if _, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil {
				t.Fatal(err)
			}
			if shed {
				approvalWorkerSink(e)
				clock.Advance(20 * time.Minute)
				if err := e.reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
				if e.flushPass(context.Background()) {
					t.Fatal("flush failed")
				}
				if _, _, err := e.mutate(context.Background(), approvalKey(1), ap.ShedRecord{Pressure: true}, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
				if !readApproval(t, db, 1).Record.Header.Shed {
					t.Fatal("row not shed")
				}
			}
			before := readApproval(t, db, 1).RecordJSON
			path := aw.HostedRoot + "/" + statetest.ID(1)
			token := hex.EncodeToString(claim.Token[:])
			report := approvalReport(claim)
			for _, owner := range []struct{ client, sub string }{{"client", "local-uid:1"}, {"client", "local-uid:2"}, {"foreign", ""}} {
				s.MachineClientID = owner.client
				q, _ := (aw.HostedGetQuery{RequesterSub: owner.sub}).Encode()
				approvalHTTPError(t, approvalHTTPRequest(s, "GET", path+"?"+q, nil), ap.CodeNotFound)
				q, _ = (aw.HostedListQuery{RequesterSub: owner.sub, Limit: 10}).Encode()
				list := approvalHTTPResponse(t, aw.KindList, approvalHTTPRequest(s, "GET", aw.HostedRoot+"?"+q, nil))
				if len(list.Summaries) != 0 || list.NextCursor != "" {
					t.Fatal("foreign list disclosed row")
				}
				wait := approvalHTTPBody(t, aw.HostedWaitBody{ApprovalProto: 1, RequesterSub: owner.sub, RequestIDs: []string{statetest.ID(1)}, WaitSeconds: 0})
				approvalHTTPError(t, approvalHTTPRequest(s, "POST", aw.HostedRoot+"/wait", wait), ap.CodeNotFound)
				cl := approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, RequesterSub: owner.sub, ClaimToken: token, PlanHash: claim.PlanHash})
				approvalHTTPError(t, approvalHTTPRequest(s, "POST", path+"/claim", cl), ap.CodeNotFound)
				rep := approvalHTTPBody(t, aw.HostedReportBody{ApprovalProto: 1, RequesterSub: owner.sub, ClaimToken: token, PlanHash: claim.PlanHash, Report: aw.Report{ReportSequence: 1, Class: report.Body.Class, Steps: report.Body.Steps, ExecutedOrdinals: report.Body.ExecutedOrdinals, ResultDigest: report.Body.ResultDigest}})
				approvalHTTPError(t, approvalHTTPRequest(s, "POST", path+"/report", rep), ap.CodeNotFound)
				if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
					t.Fatal("foreign call changed row or outbox")
				}
			}
			s.MachineClientID = "client"
			own := approvalHTTPResponse(t, aw.KindGet, approvalHTTPRequest(s, "GET", path, nil))
			if own.Summary.Pruned != shed {
				t.Fatal("owner lost row")
			}
			rep := approvalHTTPBody(t, aw.HostedReportBody{ApprovalProto: 1, ClaimToken: token, PlanHash: claim.PlanHash, Report: aw.Report{ReportSequence: 1, Class: report.Body.Class, Steps: report.Body.Steps, ExecutedOrdinals: report.Body.ExecutedOrdinals, ResultDigest: report.Body.ResultDigest}})
			approvalHTTPResponse(t, aw.KindReport, approvalHTTPRequest(s, "POST", path+"/report", rep))
		})
	}
}

func TestApprovalHTTPReportMatrixWithWorker(t *testing.T) {
	for _, mode := range []string{"valid", "token", "plan", "class", "mask", "partial", "ordinal", "digest-replay"} {
		t.Run(mode, func(t *testing.T) {
			s, e, db := approvalHTTPFixture(t)
			claim := approvalHTTPReady(t, e, db)
			if _, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil {
				t.Fatal(err)
			}
			approvalWorkerSink(e)
			if err := s.StartOrdinaryWorkers(e); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			rep := approvalReport(claim)
			body := aw.HostedReportBody{ApprovalProto: 1, ClaimToken: hex.EncodeToString(claim.Token[:]), PlanHash: claim.PlanHash, Report: aw.Report{ReportSequence: 1, Class: rep.Body.Class, Steps: rep.Body.Steps, ExecutedOrdinals: rep.Body.ExecutedOrdinals, ResultDigest: rep.Body.ResultDigest}}
			path := aw.HostedRoot + "/" + statetest.ID(1) + "/report"
			if mode == "digest-replay" {
				approvalHTTPResponse(t, aw.KindReport, approvalHTTPRequest(s, "POST", path, approvalHTTPBody(t, body)))
			}
			switch mode {
			case "token":
				body.ClaimToken = strings.Repeat("0", 64)
			case "plan":
				body.PlanHash = strings.Repeat("0", 64)
			case "class":
				body.Report.Class = ap.ClassFailed
			case "mask":
				body.Report.ExecutedOrdinals = nil
			case "partial":
				body.Report.Partial = true
			case "ordinal":
				body.Report.Steps[0].Ordinal = 2
			case "digest-replay":
				body.Report.ResultDigest = strings.Repeat("b", 64)
			}
			data := approvalHTTPBody(t, body)
			w := approvalHTTPRequest(s, "POST", path, data)
			if mode == "valid" {
				approvalHTTPResponse(t, aw.KindReport, w)
				approvalHTTPResponse(t, aw.KindReport, approvalHTTPRequest(s, "POST", path, data))
				if readApproval(t, db, 1).Record.Header.FinalReport == nil {
					t.Fatal("missing final report")
				}
			} else {
				approvalHTTPError(t, w, ap.CodeInvalidReport)
				row := readApproval(t, db, 1).Record
				if mode != "digest-replay" && row.Header.FinalReport != nil {
					t.Fatal("invalid report committed")
				}
				if mode == "digest-replay" && row.Header.FinalReport.ResultDigest != rep.Body.ResultDigest {
					t.Fatal("report overwritten")
				}
			}
		})
	}
}

func TestApprovalHTTPImmediateClaimAndFlushRetry(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(failFirst), func(t *testing.T) {
			s, e, db := approvalHTTPFixture(t)
			claim := approvalUnflushedReady(t, e, db)
			e.config.Minter = approvalMintFunc(func(context.Context, ap.ApprovalPlanV1, time.Time) ([]string, error) {
				return []string{approvalHTTPSignature}, nil
			})
			var attempts atomic.Int32
			var decisions atomic.Int32
			e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
				n := attempts.Add(1)
				if failFirst && n == 1 {
					return fmt.Errorf("injected audit failure")
				}
				if c.Approval.Transition == ap.EventDecision {
					decisions.Add(1)
				}
				return nil
			})
			e.config.Logger = log.New(io.Discard, "", 0)
			if err := s.StartOrdinaryWorkers(e); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			body := approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, ClaimToken: hex.EncodeToString(claim.Token[:]), PlanHash: claim.PlanHash})
			response := approvalHTTPResponse(t, aw.KindClaim, approvalHTTPRequest(s, "POST", aw.HostedRoot+"/"+statetest.ID(1)+"/claim", body))
			if response.Claim.Status != ap.ClaimSignatures || decisions.Load() != 1 {
				t.Fatalf("claim=%s decision deliveries=%d", response.Claim.Status, decisions.Load())
			}
		})
	}
}

func TestApprovalHTTPWALReadsAndWriteContention(t *testing.T) {
	for _, kind := range []string{aw.KindSubmit, aw.KindClaim, aw.KindReport} {
		t.Run(kind, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, true)
			s := NewServer("secret", db, log.New(io.Discard, "", 0))
			s.MachineClientID = "client"
			if err := s.AttachApprovals(e); err != nil {
				t.Fatal(err)
			}
			claim := approvalHTTPReady(t, e, db)
			submitApproval(t, e, 2)
			if kind == aw.KindReport {
				if _, err := e.Claim(context.Background(), approvalKey(1), claim); err != nil {
					t.Fatal(err)
				}
			}
			before := readApproval(t, db, 1).RecordJSON
			tx, err := db.BeginV2(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			heldAt := time.Now()
			path := aw.HostedRoot + "/" + statetest.ID(1)
			for _, target := range []string{path, aw.HostedRoot + "?limit=10"} {
				start := time.Now()
				w := approvalHTTPRequest(s, "GET", target, nil)
				if w.Code != 200 || time.Since(start) >= time.Second {
					t.Fatalf("WAL read %s: %d %s", target, w.Code, w.Body.String())
				}
			}
			for _, id := range []int{1, 2} {
				body := approvalHTTPBody(t, aw.HostedWaitBody{ApprovalProto: 1, RequestIDs: []string{statetest.ID(id)}, WaitSeconds: 1})
				start := time.Now()
				response := approvalHTTPResponse(t, aw.KindWait, approvalHTTPRequest(s, "POST", aw.HostedRoot+"/wait", body))
				if len(response.Summaries) != 1 || time.Since(start) >= 2*time.Second {
					t.Fatal("WAL wait blocked by writer")
				}
				if id == 1 && time.Since(start) >= time.Second {
					t.Fatal("decided wait did not return immediately")
				}
				if id == 2 && time.Since(start) < time.Second {
					t.Fatal("pending wait ignored requested bound")
				}
			}
			token := hex.EncodeToString(claim.Token[:])
			var body []byte
			switch kind {
			case aw.KindSubmit:
				path = aw.HostedRoot
				body = approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: approvalDraft(3)})
			case aw.KindClaim:
				path += "/claim"
				body = approvalHTTPBody(t, aw.HostedClaimBody{ApprovalProto: 1, ClaimToken: token, PlanHash: claim.PlanHash})
			case aw.KindReport:
				path += "/report"
				report := approvalReport(claim)
				body = approvalHTTPBody(t, aw.HostedReportBody{ApprovalProto: 1, ClaimToken: token, PlanHash: claim.PlanHash, Report: aw.Report{ReportSequence: 1, Class: report.Body.Class, Steps: report.Body.Steps, ExecutedOrdinals: report.Body.ExecutedOrdinals, ResultDigest: report.Body.ResultDigest}})
			}
			w := approvalHTTPRequest(s, "POST", path, body)
			approvalHTTPError(t, w, ap.CodeBusy)
			if remaining := time.Until(heldAt.Add(6 * time.Second)); remaining > 0 {
				time.Sleep(remaining) // Keep the writer lock for the acceptance window.
			}
			if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
				t.Fatal("busy write changed row")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			approvalHTTPResponse(t, kind, approvalHTTPRequest(s, "POST", path, body))
		})
	}
}
