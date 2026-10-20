package signerkit

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	lct "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

func TestApprovalSocketReportMatrix(t *testing.T) {
	S, F, I, N, K, X := ap.StepSucceeded, ap.StepFailed, ap.StepIndeterminate, ap.StepNotRun, ap.StepSkipped, ap.StepExpiredUnexecuted
	cases := []struct {
		name     string
		steps    int
		claimed  bool
		statuses []ap.StepStatus
		edit     func(*aw.ReportRequest)
		invalid  bool
	}{
		{"negative without claim", 1, false, []ap.StepStatus{X}, nil, false},
		{"executed without claim", 1, false, []ap.StepStatus{S}, nil, true},
		{"wrong token", 1, true, []ap.StepStatus{S}, func(r *aw.ReportRequest) { r.ClaimToken = strings.Repeat("0", 64) }, true},
		{"wrong plan", 1, true, []ap.StepStatus{S}, func(r *aw.ReportRequest) { r.PlanHash = strings.Repeat("0", 64) }, true},
		{"wrong class", 1, true, []ap.StepStatus{S}, func(r *aw.ReportRequest) { r.Report.Class = ap.ClassFailed }, true},
		{"wrong partial", 2, true, []ap.StepStatus{F, I}, func(r *aw.ReportRequest) { r.Report.Partial = true }, true},
		{"wrong executed mask", 2, true, []ap.StepStatus{F, I}, func(r *aw.ReportRequest) { r.Report.ExecutedOrdinals = []int{1} }, true},
		{"failed indeterminate", 2, true, []ap.StepStatus{F, I}, nil, false},
		{"missing tail", 3, true, []ap.StepStatus{F, I}, nil, true},
		{"missing two steps", 3, true, []ap.StepStatus{F}, nil, true},
		{"misordered", 3, true, []ap.StepStatus{F, I, N}, func(r *aw.ReportRequest) { r.Report.Steps[1].Ordinal = 3; r.Report.Steps[2].Ordinal = 2 }, true},
		{"duplicate ordinal", 3, true, []ap.StepStatus{F, I, N}, func(r *aw.ReportRequest) { r.Report.Steps[2].Ordinal = 2 }, true},
		{"executed after not run", 3, true, []ap.StepStatus{N, S, S}, nil, true},
		{"executed after abort", 3, true, []ap.StepStatus{I, S, N}, nil, true},
		{"skipped before failed", 3, true, []ap.StepStatus{S, K, F}, nil, true},
		{"partial execution", 3, true, []ap.StepStatus{F, I, N}, nil, false},
		{"stop policy", 3, true, []ap.StepStatus{S, F, K}, nil, false},
		{"negative with tail", 3, false, []ap.StepStatus{X, N, N}, nil, false},
		{"stale target", 3, false, []ap.StepStatus{ap.StepStaleTarget, N, N}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				specs := []st.StepSpec{st.Write("touch /tmp/a", 60), st.Read("df"), st.Read("du")}[:tc.steps]
				h := newApprovalDispatchHarnessDraft(t, true, approvalDispatchDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, specs...))
				synctest.Wait()
				claim := h.requests()[4].(aw.ClaimRequest)
				if tc.claimed {
					response := approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, claim), nil), "")
					if response.Claim.Status != ap.ClaimSignatures {
						t.Fatal(response)
					}
				}
				report := h.requests()[5].(aw.ReportRequest)
				report.Report.Steps = nil
				for i, status := range tc.statuses {
					report.Report.Steps = append(report.Report.Steps, ap.StepReport{Ordinal: i + 1, Status: status})
				}
				report.Report.Class = ap.AggregateJobClass(tc.statuses)
				report.Report.Partial = ap.Partial(tc.statuses)
				report.Report.ExecutedOrdinals = ap.ExecutedOrdinals(tc.statuses)
				if tc.edit != nil {
					tc.edit(&report)
				}
				before, err := h.store.Load(ap.RecordKey(h.principal, st.ID(1)))
				if err != nil {
					t.Fatal(err)
				}
				code := ap.Code("")
				if tc.invalid {
					code = ap.CodeInvalidReport
				}
				// Deliberately malformed reports must reach the server's decoder, not the client validator.
				frame, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				approvalResponse(t, aw.KindReport, h.socket(t, append(frame, '\n'), nil), code)
				synctest.Wait()
				after, err := h.store.Load(ap.RecordKey(h.principal, st.ID(1)))
				if err != nil {
					t.Fatal(err)
				}
				if tc.invalid {
					if after.Header.FinalReport != nil || !reflect.DeepEqual(before.Payload.Signatures, after.Payload.Signatures) {
						t.Fatal("refused report changed result or erased signatures")
					}
				} else {
					if after.Header.FinalReport == nil || after.Header.FinalReport.Class != report.Report.Class || len(after.Payload.Signatures) != 0 {
						t.Fatal("report not committed or signatures retained")
					}
					response := approvalResponse(t, aw.KindGet, h.socket(t, approvalRequestFrame(t, h.requests()[1]), nil), "")
					if response.Summary.ExecutionStatus != ap.ExecutionFinal || response.Summary.ExecutionClass != report.Report.Class {
						t.Fatal("Get did not expose committed report")
					}
					// Exact replay acknowledges without another final-report event.
					approvalResponse(t, aw.KindReport, h.socket(t, append(frame, '\n'), nil), "")
					synctest.Wait()
					changed := report
					changed.Report.ResultDigest = strings.Repeat("c", 64)
					approvalResponse(t, aw.KindReport, h.socket(t, approvalRequestFrame(t, changed), nil), ap.CodeInvalidReport)
					synctest.Wait()
					replayed, err := h.store.Load(ap.RecordKey(h.principal, st.ID(1)))
					if err != nil || !reflect.DeepEqual(after.Header.FinalReport, replayed.Header.FinalReport) {
						t.Fatal("changed replay replaced final report")
					}
					refused := 0
					for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
						if row.Approval != nil && row.Approval.RequestID == st.ID(1) && row.Approval.Transition == "invalid_report{already_reported}" {
							refused++
						}
					}
					if refused != 1 {
						t.Fatalf("changed replay audit count %d", refused)
					}
				}
				transition := "final_report"
				if tc.invalid {
					transition = "invalid_report"
				}
				count := 0
				for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
					if row.Approval != nil && row.Approval.RequestID == st.ID(1) && strings.HasPrefix(row.Approval.Transition, transition) {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("%s audit count=%d rows=%+v", transition, count, approvalAuditRows(t, h.service, h.auditPath))
				}
			})
		})
	}
}

func TestApprovalSocketReportTerminalStates(t *testing.T) {
	for _, state := range []string{"pending", "denied", "canceled", "expired", "error", "closed unclaimed", "materialization error", "unreported full", "unreported shed"} {
		t.Run(state, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clock := elapsedtest.NewFake(st.T0)
				n := &grantSurfaceNotifier{Notifier: lct.NewNotifier(nil), cards: make(chan lc.Notification, 100)}
				h := newApprovalDispatchHarness(t, true, func(c *lc.Config) {
					c.Clock = clock
					c.Notifier = n
					if state == "error" {
						c.Notifier = lct.NewNotifier(func(_ context.Context, kind string) error {
							if kind == "parts" {
								return errors.New("delivery failed")
							}
							return nil
						})
					}
					if state == "materialization error" {
						c.Minter = &legacyTestMinter{}
					}
					c.Settings = ap.LocalSettings
					c.Settings.ReportHorizon = time.Minute
					if state == "unreported shed" {
						c.Settings.Retention = time.Minute
					}
					c.AssistPool = assist.NewPool(1, assist.Timers{Now: clock.Wall})
					c.AssistInputBuilder = lct.AssistBuilder{}
				})
				engine, err := h.service.approvals.Current()
				if err != nil {
					t.Fatal(err)
				}
				id := 1
				hash := h.planHash
				invalid := state == "pending" || state == "denied" || state == "canceled" || state == "expired" || state == "error"
				if invalid {
					id = 2
					submitted := h.submitAcceptance(t, id, ap.RouteSignedWrite, "touch /tmp/pending", nil)
					hash = submitted.Summary.PlanHash
					synctest.Wait()
					var card lc.Notification
					for len(n.cards) > 0 {
						card = <-n.cards
					}
					switch state {
					case "denied":
						answer, err := engine.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteDeny, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: card.Handle, Challenge: card.Challenge, MsgID: 4}})
						if err != nil || answer.Noise {
							t.Fatalf("deny: %+v %v", answer, err)
						}
					case "canceled":
						answer, err := engine.AdminCancel(submitted.Summary.RecordHandle, ap.AdminCancel{PlanHash: hash, Admin: st.Operator})
						if err != nil || !answer.Changed {
							t.Fatalf("cancel: %+v %v", answer, err)
						}
					case "expired":
						clock.Advance(2 * time.Hour)
						time.Sleep(time.Second)
					}
				} else {
					if state != "closed unclaimed" {
						response := approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, acceptanceClaim(id, hash)), nil), "")
						expected := ap.ClaimSignatures
						if state == "materialization error" {
							expected = ap.ClaimMaterializationError
						}
						if response.Claim.Status != expected {
							t.Fatal(response)
						}
						if state == "materialization error" && (response.Claim.Reason != ap.MintReasonSigningFailed || len(response.Claim.Signatures) != 0) {
							t.Fatal(response)
						}
					}
					clock.Advance(3 * time.Minute)
					time.Sleep(time.Second)
				}
				synctest.Wait()
				key := ap.RecordKey(h.principal, st.ID(id))
				before, err := h.store.Load(key)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]ap.ApprovalStatus{"denied": ap.ApprovalDenied, "canceled": ap.ApprovalCanceled, "expired": ap.ApprovalExpired, "error": ap.ApprovalError}[state]
				if want != "" && (before.Header.Decision == nil || before.Header.Decision.Status != want) {
					t.Fatalf("terminal fixture: %+v", before.Header)
				}
				if state == "pending" && before.Header.Decision != nil {
					t.Fatal("pending fixture resolved")
				}
				if strings.HasPrefix(state, "unreported") {
					view := approvalResponse(t, aw.KindGet, h.socket(t, approvalRequestFrame(t, aw.GetRequest{ApprovalProto: 1, Kind: aw.KindGet, RequestID: st.ID(id)}), nil), "")
					if view.Summary.ExecutionStatus != ap.ExecutionUnreported || before.Header.Shed != (state == "unreported shed") {
						t.Fatalf("late fixture: %+v", view)
					}
				}
				if !invalid && before.Payload != nil && len(before.Payload.Signatures) != 0 {
					t.Fatal("tick did not erase expired signatures")
				}
				report := h.requests()[5].(aw.ReportRequest)
				claim := acceptanceClaim(id, hash)
				report.RequestID, report.PlanHash, report.ClaimToken = claim.RequestID, claim.PlanHash, claim.ClaimToken
				if strings.HasPrefix(state, "unreported") {
					report.Report.Steps = []ap.StepReport{{Ordinal: 1, Status: ap.StepSucceeded}}
					report.Report.Class = ap.ClassSucceeded
					report.Report.ExecutedOrdinals = []int{1}
				}
				code := ap.Code("")
				if invalid {
					code = ap.CodeInvalidReport
				}
				approvalResponse(t, aw.KindReport, h.socket(t, approvalRequestFrame(t, report), nil), code)
				synctest.Wait()
				after, err := h.store.Load(key)
				if err != nil {
					t.Fatal(err)
				}
				if invalid {
					if after.Header.FinalReport != nil || !reflect.DeepEqual(before.Header.Decision, after.Header.Decision) {
						t.Fatal("invalid terminal report changed decision/result")
					}
				} else {
					if after.Header.FinalReport == nil || after.Header.FinalReport.Class != report.Report.Class || (after.Payload != nil && len(after.Payload.Signatures) != 0) {
						t.Fatal("late report not committed")
					}
					view := approvalResponse(t, aw.KindGet, h.socket(t, approvalRequestFrame(t, aw.GetRequest{ApprovalProto: 1, Kind: aw.KindGet, RequestID: st.ID(id)}), nil), "")
					if state == "materialization error" {
						if view.Summary.ExecutionStatus != ap.ExecutionNotExecutable || view.Summary.NotExecutableReason != ap.MintReasonSigningFailed {
							t.Fatal("SA-6.2 mint error lost precedence over accepted report")
						}
					} else if view.Summary.ExecutionStatus != ap.ExecutionFinal {
						t.Fatal("late report did not replace provisional unreported")
					}

				}
				transition := "final_report"
				if invalid {
					transition = "invalid_report"
				}
				count := 0
				for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
					if row.Approval != nil && row.Approval.RequestID == st.ID(id) && strings.HasPrefix(row.Approval.Transition, transition) {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("%s audit count %d", transition, count)
				}
			})
		})
	}
}
