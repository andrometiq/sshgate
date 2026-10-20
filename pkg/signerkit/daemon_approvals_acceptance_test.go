package signerkit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

func approvalAuditRows(t *testing.T, service *Service, path string) []AuditEvent {
	t.Helper()
	service.daemon.Audit.mu.Lock()
	defer service.daemon.Audit.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []AuditEvent
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var row AuditEvent
		if err := decoder.Decode(&row); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}

func approvalRefusalBytes(t *testing.T, h *approvalDispatchHarness) [][]byte {
	t.Helper()
	h.service.daemon.Audit.mu.Lock()
	defer h.service.daemon.Audit.mu.Unlock()
	data, err := os.ReadFile(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var row AuditEvent
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.Status == "error" {
			rows = append(rows, line)
		}
	}
	return rows
}

func grantAcceptanceHarness(t *testing.T) *approvalDispatchHarness {
	t.Helper()
	n := &grantSurfaceNotifier{Notifier: lct.NewNotifier(nil), cards: make(chan lc.Notification, 100)}
	h := newApprovalDispatchHarness(t, true, func(c *lc.Config) {
		c.Notifier = n
		c.AssistPool = assist.NewPool(1, assist.Timers{Now: c.Clock.Wall})
		c.AssistInputBuilder = lct.AssistBuilder{}
	})
	draft := st.GrantDraft(st.ID(10), "web-1", time.Hour, st.T0)
	draft.StandingGrant.TrustedHostFingerprint = approvalDispatchDraft(st.ID(90), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)).CommandJob.Steps[0].Target.TrustedHostFingerprint
	approvalResponse(t, aw.KindSubmit, h.socket(t, approvalRequestFrame(t, aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: draft}), nil), "")
	synctest.Wait()
	var card lc.Notification
	for len(n.cards) > 0 {
		card = <-n.cards
	}
	engine, err := h.service.approvals.Current()
	if err != nil {
		t.Fatal(err)
	}
	answer, err := engine.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: card.Handle, Challenge: card.Challenge, MsgID: 4}})
	if err != nil || answer.Noise {
		t.Fatalf("grant vote: %+v %v", answer, err)
	}
	synctest.Wait()
	grants, err := engine.ListGrants(h.principal)
	if err != nil || len(grants) != 1 || grants[0].RequestID != st.ID(10) {
		t.Fatalf("live grant: %+v %v", grants, err)
	}
	return h
}

func (h *approvalDispatchHarness) submitAcceptance(t *testing.T, id int, route ap.Route, command string, uid *uint32) aw.Response {
	t.Helper()
	draft := approvalDispatchDraft(st.ID(id), ap.CoordinatorExecutor, st.T0, st.Write(command, 60))
	draft.CommandJob.Steps[0].Route = route
	return approvalResponse(t, aw.KindSubmit, h.socket(t, approvalRequestFrame(t, aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: draft}), uid), "")
}
func acceptanceClaim(id int, hash string) aw.ClaimRequest {
	token := st.Token(st.ID(id))
	return aw.ClaimRequest{ApprovalProto: 1, Kind: aw.KindClaim, RequestID: st.ID(id), ClaimToken: hex.EncodeToString(token[:]), PlanHash: hash}
}

func TestApprovalReservedVerbsWithLiveGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := grantAcceptanceHarness(t)
		for i, route := range []ap.Route{ap.RouteUnsignedRead, ap.RouteSignedWrite, ap.RouteSignedReveal, ap.RouteSignedAdmin} {
			draft := approvalDispatchDraft(st.ID(20+i), ap.CoordinatorExecutor, st.T0, st.Write("SSHGATE_XFER_SEND forbidden", 60))
			draft.CommandJob.Steps[0].Route = route
			if route == ap.RouteUnsignedRead {
				draft.CommandJob.Steps[0].SignatureTTLSeconds = 0
			}
			frame, err := json.Marshal(aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: draft})
			if err != nil {
				t.Fatal(err)
			}
			response := h.socket(t, append(frame, '\n'), nil)
			approvalResponse(t, aw.KindSubmit, response, ap.CodeReservedVerb)
			synctest.Wait()
			if _, err := h.store.Load(ap.RecordKey(h.principal, draft.RequestID)); !errors.Is(err, lc.ErrNotFound) {
				t.Fatalf("reserved command left a record: %v", err)
			}
			if bytes.Contains(response, []byte("SSHGATE_SIG")) {
				t.Fatal("refusal released signature")
			}
			var rows []AuditEvent
			for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
				if row.RequestID == draft.RequestID {
					rows = append(rows, row)
				}
			}
			if len(rows) != 1 {
				t.Fatalf("refusal rows: %+v", rows)
			}
			assertApprovalRefusal(t, rows[0], aw.KindSubmit, draft.RequestID, h.principal, ap.CodeReservedVerb)
			if rows[0].AuthMode != "" || rows[0].ApprovedBy != "" {
				t.Fatal("refusal attributed as approval")
			}
		}
		for i, command := range []string{"SSHGATE_UPDATE " + strings.Repeat("a", 64), "SSHGATE_REVOKE", "touch /tmp/approved"} {
			route := ap.RouteSignedAdmin
			if i == 2 {
				route = ap.RouteSignedWrite
			}
			response := h.submitAcceptance(t, 30+i, route, command, nil)
			synctest.Wait()
			claimed := approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, acceptanceClaim(30+i, response.Summary.PlanHash)), nil), "")
			record, err := h.store.Load(ap.RecordKey(h.principal, st.ID(30+i)))
			if err != nil {
				t.Fatal(err)
			}
			if i < 2 {
				if record.Header.Decision != nil || claimed.Claim.Status != ap.ClaimNotReady || len(claimed.Claim.Signatures) != 0 {
					t.Fatalf("admin auto-approved: %+v", claimed)
				}
			} else if record.Header.Decision == nil || record.Header.Decision.DecidedBy != "grant:"+st.ID(10) || claimed.Claim.Status != ap.ClaimSignatures || len(claimed.Claim.Signatures) != 1 {
				t.Fatalf("benign write not grant signed: %+v", claimed)
			}
			synctest.Wait()
			grantAudit := false
			for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
				if row.Approval != nil && row.Approval.RequestID == st.ID(30+i) && strings.HasPrefix(row.Approval.DecidedBy, "grant:") {
					grantAudit = true
				}
			}
			if grantAudit != (i == 2) {
				t.Fatalf("grant audit attribution for %s: %v", command, grantAudit)
			}
		}
	})
}

type grantBoundaryBackend struct {
	StubBackend
	requests []ApprovalRequest
}

func (b *grantBoundaryBackend) Request(ctx context.Context, request ApprovalRequest) (<-chan Result, error) {
	b.requests = append(b.requests, request)
	return b.StubBackend.Request(ctx, request)
}

func TestApprovalGrantSigningBoundaries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := grantAcceptanceHarness(t)
		backend := &grantBoundaryBackend{}
		h.service.daemon.Backend = backend
		// The legacy backend denies; any accidental grant shortcut would release a signature.
		for i, host := range []string{approvalDispatchDraft(st.ID(90), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)).CommandJob.Steps[0].Target.TrustedHostFingerprint, legacyFingerprint("other")} {
			request := signRequest{Kind: "sign", RequestID: fmt.Sprintf("v1-%d", i), Commands: []signRequestCmd{{Server: "web-1", Host: host, Cmd: "touch /tmp/approved", TTLSec: 60}}}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			response := h.socket(t, append(raw, '\n'), nil)
			var result signResponse
			if err := json.Unmarshal(response, &result); err != nil {
				t.Fatal(err)
			}
			if result.Status != "denied" || len(result.Signatures) != 0 {
				t.Fatalf("v1 grant bypass: %s", response)
			}
			rows := approvalAuditRows(t, h.service, h.auditPath)
			found := false
			for _, row := range rows {
				if row.RequestID == request.RequestID {
					found = true
					if strings.HasPrefix(row.ApprovedBy, "grant:") || row.AuthMode == "grant" {
						t.Fatal(row)
					}
				}
			}
			if !found {
				t.Fatal("missing v1 audit")
			}
		}
		if len(backend.requests) != 2 {
			t.Fatalf("v1 prompts=%d", len(backend.requests))
		}
		other := h.uid + 1
		foreign := h.submitAcceptance(t, 40, ap.RouteSignedWrite, "touch /tmp/approved", &other)
		synctest.Wait()
		response := approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, acceptanceClaim(40, foreign.Summary.PlanHash)), &other), "")
		record, err := h.store.Load(ap.RecordKey(fmt.Sprintf("local-uid:%d", other), st.ID(40)))
		if err != nil {
			t.Fatal(err)
		}
		if record.Header.Decision != nil || response.Claim.Status != ap.ClaimNotReady || len(response.Claim.Signatures) != 0 {
			t.Fatal("foreign grant covered job")
		}

		own := h.submitAcceptance(t, 41, ap.RouteSignedWrite, "touch /tmp/approved", nil)
		synctest.Wait()
		frame := approvalRequestFrame(t, acceptanceClaim(41, own.Summary.PlanHash))
		lost := &approvalDispatchConn{Reader: bytes.NewReader(frame), failWrite: true}
		if err := h.service.HandleSignRequestWithPeer(context.Background(), lost, &PeerCredentials{UID: h.uid}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		record, err = h.store.Load(ap.RecordKey(h.principal, st.ID(41)))
		if err != nil {
			t.Fatal(err)
		}
		signatures := append([]string(nil), record.Payload.Signatures...)
		if record.Header.Decision.DecidedBy != "grant:"+st.ID(10) || len(signatures) != 1 {
			t.Fatal("lost response changed decision or signatures")
		}
		repeat := approvalResponse(t, aw.KindClaim, h.socket(t, frame, nil), "")
		if !reflect.DeepEqual(signatures, repeat.Claim.Signatures) {
			t.Fatal("repeat changed signature set")
		}
		synctest.Wait()
		found := false
		for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
			if row.Approval != nil && row.Approval.RequestID == st.ID(41) && row.Approval.DecidedBy == "grant:"+st.ID(10) {
				found = true
			}
		}
		if !found {
			t.Fatal("grant decision missing from audit after lost response")
		}

		pending := h.submitAcceptance(t, 42, ap.RouteSignedWrite, "touch /tmp/approved", nil)
		synctest.Wait()
		raw := []byte("{\"kind\":\"revoke_grant\",\"request_id\":\"revoke\",\"alias\":\"web-1\"}\n")
		var revoked revokeGrantResponse
		if err := json.Unmarshal(h.socket(t, raw, &other), &revoked); err != nil || revoked.Status != "approved" {
			t.Fatalf("revoke: %+v %v", revoked, err)
		}
		response = approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, acceptanceClaim(42, pending.Summary.PlanHash)), nil), "")
		if response.Claim.Status != ap.ClaimMaterializationError || response.Claim.Reason != ap.MintReasonGrantNotLive || len(response.Claim.Signatures) != 0 {
			t.Fatalf("revoked grant signed: %+v", response)
		}
	})
}

func TestLegacyTapAuditAdapterReplayAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newLegacyHarness(t)
				oldEntropy := randRead
				defer func() { randRead = oldEntropy }()
				randRead = fixedEntropy()
				response, done := h.begin(t, legacySignFrame(false))
				synctest.Wait()
				if fail {
					if err := h.service.daemon.Audit.Close(); err != nil {
						t.Fatal(err)
					}
				}
				h.vote(t, ap.VoteApprove)
				synctest.Wait()
				err := <-done
				if (!fail && err != nil) || (fail && (err == nil || !strings.Contains(err.Error(), "audit:"))) {
					t.Fatalf("audit result: %v", err)
				}
				original := bytes.Clone(response.Bytes())
				direct := newLegacyHarness(t)
				backend := NewMockBackend()
				backend.Approve("legacy", st.Operator)
				direct.service.daemon.Backend = backend
				raw, _ := json.Marshal(legacySignFrame(false))
				control := &dispatchConn{Reader: bytes.NewReader(append(raw, '\n'))}
				randRead = fixedEntropy()
				if err := direct.service.daemon.HandleSignRequest(context.Background(), control); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(control.Bytes(), original) {
					t.Fatal("audit failure changed response bytes")
				}

				var signed signResponse
				if err := json.Unmarshal(original, &signed); err != nil || len(signed.Signatures) != 1 {
					t.Fatalf("fail-open response: %s %v", original, err)
				}
				data := h.notifier.delivered[0].Data()
				for _, decision := range []string{ap.VoteApprove, ap.VoteDeny} {
					result, err := h.runtime.Legacy().VoteLegacy(ap.CastVote{Operator: st.Operator, Decision: decision, Card: &ap.CardTap{Handle: data.Context.Handle, Challenge: data.Context.Challenge}}, func(lc.LegacyTapResult) {})
					if err != nil || result.Resolved || result.Answer != lc.LegacyTapRefused {
						t.Fatalf("replay: %+v %v", result, err)
					}
					synctest.Wait()
					if !bytes.Equal(original, response.Bytes()) {
						t.Fatal("replay changed response")
					}
				}
				h.isolated(t, 1)
				if !fail {
					var votes []AuditEvent
					for _, row := range approvalAuditRows(t, h.service, h.auditPath) {
						if row.Approval != nil {
							votes = append(votes, row)
						}
					}
					if len(votes) != 2 {
						t.Fatalf("replay rows: %+v", votes)
					}
					for _, row := range votes {
						if row.Approval.Transition != "legacy_vote_replay" || !row.Approval.Replay || row.Approval.Principal != "local-uid:7" || row.Approval.RequestID != "legacy" {
							t.Fatal(row)
						}
					}
				}
			})
		})
	}
}

func TestApprovalSocketOwnershipAfterShed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clock := elapsedtest.NewFake(st.T0)
		n := &grantSurfaceNotifier{Notifier: lct.NewNotifier(nil), cards: make(chan lc.Notification, 100)}
		h := newApprovalDispatchHarness(t, true, func(c *lc.Config) {
			c.Clock = clock
			c.Notifier = n
			c.Settings = ap.LocalSettings
			c.Settings.Retention = time.Minute
			c.AssistPool = assist.NewPool(1, assist.Timers{Now: clock.Wall})
			c.AssistInputBuilder = lct.AssistBuilder{}
		})
		submitted := h.submitAcceptance(t, 2, ap.RouteSignedWrite, "touch /tmp/new", nil)
		synctest.Wait()
		engine, err := h.service.approvals.Current()
		if err != nil {
			t.Fatal(err)
		}
		other := h.uid + 1
		check := func() {
			t.Helper()
			token := st.Token(st.ID(2))
			requests := []any{
				aw.GetRequest{ApprovalProto: 1, Kind: aw.KindGet, RequestID: st.ID(2)},
				aw.WaitRequest{ApprovalProto: 1, Kind: aw.KindWait, RequestIDs: []string{st.ID(2)}},
				acceptanceClaim(2, submitted.Summary.PlanHash),
				aw.ReportRequest{ApprovalProto: 1, Kind: aw.KindReport, RequestID: st.ID(2), ClaimToken: hex.EncodeToString(token[:]), PlanHash: submitted.Summary.PlanHash, Report: aw.Report{ReportSequence: 1, Steps: []ap.StepReport{{Ordinal: 1, Status: ap.StepExpiredUnexecuted}}, Class: ap.ClassExpiredUnexecuted, ResultDigest: strings.Repeat("a", 64)}},
			}
			// The same absent lookup uses the same ID and peer against a separate empty engine.
			absent := newApprovalDispatchHarness(t, false)
			runtime, err := NewApprovalRuntime(runtimeConfig(t, absent.store))
			if err != nil {
				t.Fatal(err)
			}
			if err := absent.service.AttachApprovals(runtime); err != nil {
				t.Fatal(err)
			}
			startRuntime(t, runtime)
			before := len(approvalRefusalBytes(t, h))
			for i, request := range requests {
				kind := []string{aw.KindGet, aw.KindWait, aw.KindClaim, aw.KindReport}[i]
				frame := approvalRequestFrame(t, request)
				foreign := h.socket(t, frame, &other)
				missing := absent.socket(t, frame, &other)
				approvalResponse(t, kind, foreign, ap.CodeNotFound)
				if !bytes.Equal(foreign, missing) {
					t.Fatalf("%s reveals ownership", kind)
				}
			}
			list := approvalRequestFrame(t, aw.ListRequest{ApprovalProto: 1, Kind: aw.KindList, Limit: 100})
			foreign := h.socket(t, list, &other)
			missing := absent.socket(t, list, &other)
			response := approvalResponse(t, aw.KindList, foreign, "")
			if len(response.Summaries) != 0 || !bytes.Equal(foreign, missing) {
				t.Fatal("list reveals foreign record")
			}
			rows := approvalRefusalBytes(t, h)[before:]
			empty := approvalRefusalBytes(t, absent)
			a := bytes.Join(rows, []byte("\n"))
			b := bytes.Join(empty, []byte("\n"))
			if len(rows) != 4 || !bytes.Equal(a, b) {
				t.Fatalf("refusal audit reveals record: %s / %s", a, b)
			}
		}
		check()
		answer, err := engine.AdminCancel(submitted.Summary.RecordHandle, ap.AdminCancel{PlanHash: submitted.Summary.PlanHash, Admin: st.Operator})
		if err != nil || !answer.Changed {
			t.Fatalf("cancel: %+v %v", answer, err)
		}
		synctest.Wait()
		record, err := h.store.Load(ap.RecordKey(h.principal, st.ID(2)))
		if err != nil || record.Header.Decision.Status != ap.ApprovalCanceled || record.Header.OutboxSeq != record.Header.AuditedThrough {
			t.Fatalf("cancel not flushed: %+v %v", record.Header, err)
		}
		check()
		clock.Advance(2 * time.Minute)
		time.Sleep(time.Second)
		synctest.Wait()
		record, err = h.store.Load(ap.RecordKey(h.principal, st.ID(2)))
		if err != nil || !record.Header.Shed || record.Payload != nil {
			t.Fatalf("not shed: %+v %v", record.Header, err)
		}
		check()
		own := h.submitAcceptance(t, 2, ap.RouteSignedWrite, "touch /tmp/new", &other)
		if own.Summary.RecordHandle == submitted.Summary.RecordHandle {
			t.Fatal("same ID reused foreign record")
		}
		if _, err := h.store.Load(ap.RecordKey(fmt.Sprintf("local-uid:%d", other), st.ID(2))); err != nil {
			t.Fatal(err)
		}
	})
}
