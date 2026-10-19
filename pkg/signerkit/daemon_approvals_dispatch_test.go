package signerkit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

func approvalDispatchDraft(id string, coordinator ap.Coordinator, now time.Time, specs ...st.StepSpec) ap.ApprovalDraft {
	draft := st.JobDraft(id, coordinator, now, specs...)
	for i := range draft.CommandJob.Steps {
		step := &draft.CommandJob.Steps[i]
		step.Target.TrustedHostFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
		step.RegistryEntryDigest = step.Target.Digest()
	}
	return draft
}

type approvalDispatchHarness struct {
	service   *Service
	store     *runtimeStore
	auditPath string
	uid       uint32
	principal string
	planHash  string
}

func newApprovalDispatchHarness(t *testing.T, attached bool, configure ...func(*lc.Config)) *approvalDispatchHarness {
	t.Helper()
	h := &approvalDispatchHarness{store: &runtimeStore{}, uid: uint32(os.Getuid()), auditPath: filepath.Join(t.TempDir(), "audit.jsonl")}
	h.principal = fmt.Sprintf("local-uid:%d", h.uid)
	log, err := OpenAuditLog(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	key, _ := goldenSignerKey()
	h.service, err = New(Config{Signer: key, Backend: &StubBackend{}, Audit: log})
	if err != nil {
		t.Fatal(err)
	}
	h.service.daemon.NowFunc = func() time.Time { return st.T0 }
	if !attached {
		return h
	}
	draft := approvalDispatchDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/approved", 60))
	var record *ap.R1
	inputs := ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings}
	for _, cmd := range []ap.Command{
		st.SubmitOf(draft, h.principal, st.T0, time.Hour),
		ap.AssistDone{Unavailable: "test unavailable"},
		ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{1}},
		ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")},
		ap.CardDone{Handle: "abcdefghijkl", MsgID: 2},
		ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: "abcdefghijkl", Challenge: "0123456789abcdef", MsgID: 2}},
	} {
		next, answer := ap.Apply(record, cmd, ap.Now{Wall: st.T0}, inputs)
		if answer.Code != "" || answer.Noise || !answer.Changed {
			t.Fatalf("fixture %T: %+v", cmd, answer)
		}
		record = &next
	}
	h.planHash = record.Header.PlanHash
	if err := h.store.Commit(ap.RecordKey(h.principal, draft.RequestID), *record); err != nil {
		t.Fatal(err)
	}
	config := runtimeConfig(t, h.store)
	config.NewEngine = func(store lc.Store) (*lc.Engine, error) {
		c := lc.Config{Store: store, Clock: elapsedtest.NewFake(st.T0), Freezer: h.service.ApprovalFreezer(time.Hour), SnapshotBuilder: h.service.ApprovalSnapshotBuilder(), Minter: h.service.ApprovalMinter(), AuditWriter: h.service.ApprovalAuditWriter(), LegacyService: config.Legacy}
		for _, configure := range configure {
			configure(&c)
		}
		return lc.New(c)
	}
	runtime, err := NewApprovalRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Status(); err != nil {
		t.Fatal(err)
	}
	if err := h.service.AttachApprovals(runtime); err != nil {
		t.Fatal(err)
	}
	startRuntime(t, runtime)
	return h
}

func (h *approvalDispatchHarness) requests() []any {
	token := st.Token(st.ID(1))
	planHash := h.planHash
	if planHash == "" {
		planHash = strings.Repeat("a", 64)
	}
	return []any{
		aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: approvalDispatchDraft(st.ID(2), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/new", 60))},
		aw.GetRequest{ApprovalProto: 1, Kind: aw.KindGet, RequestID: st.ID(1)},
		aw.ListRequest{ApprovalProto: 1, Kind: aw.KindList, Limit: 100},
		aw.WaitRequest{ApprovalProto: 1, Kind: aw.KindWait, RequestIDs: []string{st.ID(1)}},
		aw.ClaimRequest{ApprovalProto: 1, Kind: aw.KindClaim, RequestID: st.ID(1), ClaimToken: hex.EncodeToString(token[:]), PlanHash: planHash},
		aw.ReportRequest{ApprovalProto: 1, Kind: aw.KindReport, RequestID: st.ID(1), ClaimToken: hex.EncodeToString(token[:]), PlanHash: planHash, Report: aw.Report{ReportSequence: 1, Steps: []ap.StepReport{{Ordinal: 1, Status: ap.StepExpiredUnexecuted}}, Class: ap.ClassExpiredUnexecuted, ResultDigest: strings.Repeat("b", 64)}},
	}
}

func approvalRequestFrame(t *testing.T, request any) []byte {
	t.Helper()
	frame, err := aw.MarshalLocalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func (h *approvalDispatchHarness) socket(t *testing.T, frame []byte, uid *uint32) []byte {
	t.Helper()
	accepted, client := peerTestConnections(t)
	server := &Server{Handler: h.service}
	if uid != nil {
		server.peerCredentials = func(*net.UnixConn) (uint32, error) { return *uid, nil }
	}
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	return []byte(runPeerTestConnection(t, server, accepted, client))
}

func approvalResponse(t *testing.T, kind string, frame []byte, code ap.Code) aw.Response {
	t.Helper()
	response, err := aw.DecodeLocalResponse(kind, frame)
	if code == "" {
		if err != nil {
			t.Fatalf("%s: %s: %v", kind, frame, err)
		}
	} else if response.Error == nil || response.Error.Code != code {
		t.Fatalf("%s: %s (%v), want %s", kind, frame, err, code)
	}
	return response
}

func (h *approvalDispatchHarness) refusals(t *testing.T) []AuditEvent {
	t.Helper()
	h.service.daemon.Audit.mu.Lock()
	defer h.service.daemon.Audit.mu.Unlock()
	data, err := os.ReadFile(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []AuditEvent
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var event AuditEvent
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if event.Status == "error" {
			out = append(out, event)
		}
	}
	return out
}

func assertApprovalRefusal(t *testing.T, event AuditEvent, kind, id, principal string, code ap.Code) {
	t.Helper()
	want := AuditEvent{TS: st.T0, RequestID: id, Status: "error", Approval: &ap.AuditMetadata{Kind: ap.Kind(kind), RequestID: id, Principal: principal, Transition: "refused{" + string(code) + "}"}}
	if !reflect.DeepEqual(event, want) {
		t.Fatalf("audit got %+v metadata %+v; want %+v", event, event.Approval, want)
	}
}

func TestApprovalDispatchSixKinds(t *testing.T) {
	h := newApprovalDispatchHarness(t, true)
	for i, req := range h.requests() {
		kind := aw.Kinds[i]
		response := approvalResponse(t, kind, h.socket(t, approvalRequestFrame(t, req), nil), "")
		switch kind {
		case aw.KindSubmit:
			if response.Summary.RequestID != st.ID(2) {
				t.Fatal(response)
			}
		case aw.KindGet:
			if response.Summary.PlanHash != h.planHash {
				t.Fatal(response)
			}
		case aw.KindList:
			if len(response.Summaries) != 2 {
				t.Fatal(response)
			}
		case aw.KindWait:
			if len(response.Summaries) != 1 || response.Summaries[0].RequestID != st.ID(1) {
				t.Fatal(response)
			}
		case aw.KindClaim:
			if response.Claim.Status != ap.ClaimSignatures || len(response.Claim.Signatures) != 1 || !response.Claim.DecidedAt.Equal(st.T0) {
				t.Fatal(response)
			}
		case aw.KindReport:
			record, err := h.store.Load(ap.RecordKey(h.principal, st.ID(1)))
			if err != nil || record.Header.FinalReport == nil || record.Header.FinalReport.Class != ap.ClassExpiredUnexecuted {
				t.Fatalf("report not stored: %+v %v", record, err)
			}
		}
	}
	if got := h.refusals(t); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestApprovalDispatchRefusalsEveryKind(t *testing.T) {
	for _, mode := range []string{"unattached", "unknown_field", "no_peer"} {
		t.Run(mode, func(t *testing.T) {
			h := newApprovalDispatchHarness(t, mode != "unattached")
			for i, req := range h.requests() {
				frame := approvalRequestFrame(t, req)
				code := ap.CodeInvalidRequest
				if mode == "unattached" {
					code = ap.CodeLifecycleUnavailable
				}
				if mode == "unknown_field" {
					frame = append(bytes.TrimSuffix(frame, []byte("}\n")), []byte(",\"requester_sub\":\"local-uid:0\"}\n")...)
				}
				principal := h.principal
				var reply []byte
				if mode == "no_peer" {
					conn := &approvalDispatchConn{Reader: bytes.NewReader(frame)}
					if err := h.service.HandleSignRequest(context.Background(), conn); err != nil {
						t.Fatal(err)
					}
					reply = conn.Bytes()
					principal = ""
				} else {
					reply = h.socket(t, frame, nil)
				}
				approvalResponse(t, aw.Kinds[i], reply, code)
				rows := h.refusals(t)
				if len(rows) != i+1 {
					t.Fatalf("audit count %d, want %d", len(rows), i+1)
				}
				id := st.ID(1)
				if i == 0 {
					id = st.ID(2)
				}
				if i == 2 || i == 3 {
					id = ""
				}
				assertApprovalRefusal(t, rows[i], aw.Kinds[i], id, principal, code)
			}
		})
	}
}

type approvalDispatchConn struct {
	*bytes.Reader
	bytes.Buffer
	failWrite bool
}

func (c *approvalDispatchConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }
func (c *approvalDispatchConn) Write(b []byte) (int, error) {
	if c.failWrite {
		return 0, io.ErrClosedPipe
	}
	return c.Buffer.Write(b)
}

func TestApprovalDispatchOwnerScopeAndPagination(t *testing.T) {
	h := newApprovalDispatchHarness(t, true)
	other := h.uid + 1
	requests := h.requests()
	for _, i := range []int{1, 3, 4, 5} {
		reply := h.socket(t, approvalRequestFrame(t, requests[i]), &other)
		approvalResponse(t, aw.Kinds[i], reply, ap.CodeNotFound)
	}
	rows := h.refusals(t)
	if len(rows) != 4 {
		t.Fatal(rows)
	}
	for n, i := range []int{1, 3, 4, 5} {
		id := st.ID(1)
		if i == 3 {
			id = ""
		}
		assertApprovalRefusal(t, rows[n], aw.Kinds[i], id, fmt.Sprintf("local-uid:%d", other), ap.CodeNotFound)
	}
	empty := approvalResponse(t, aw.KindList, h.socket(t, approvalRequestFrame(t, requests[2]), &other), "")
	if len(empty.Summaries) != 0 {
		t.Fatal("foreign list leaked")
	}
	draft := approvalDispatchDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/other-owner", 60))
	submit := aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: draft}
	response := approvalResponse(t, aw.KindSubmit, h.socket(t, approvalRequestFrame(t, submit), &other), "")
	if response.Summary.PlanHash == h.planHash {
		t.Fatal("foreign submit reused record")
	}
	for n := 2; n <= 4; n++ {
		submit.Draft = approvalDispatchDraft(st.ID(n), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/page", 60))
		approvalResponse(t, aw.KindSubmit, h.socket(t, approvalRequestFrame(t, submit), nil), "")
	}
	page := aw.ListRequest{ApprovalProto: 1, Kind: aw.KindList, Limit: 2}
	first := approvalResponse(t, aw.KindList, h.socket(t, approvalRequestFrame(t, page), nil), "")
	if len(first.Summaries) != 2 || first.Summaries[0].RequestID != st.ID(1) || first.Summaries[1].RequestID != st.ID(2) || first.NextCursor == "" {
		t.Fatal(first)
	}
	page.Cursor = first.NextCursor
	second := approvalResponse(t, aw.KindList, h.socket(t, approvalRequestFrame(t, page), nil), "")
	if len(second.Summaries) != 2 || second.Summaries[0].RequestID != st.ID(3) || second.Summaries[1].RequestID != st.ID(4) || second.NextCursor != "" {
		t.Fatal(second)
	}
	page.Cursor = "a"
	approvalResponse(t, aw.KindList, h.socket(t, approvalRequestFrame(t, page), nil), ap.CodeInvalidRequest)
	rows = h.refusals(t)
	if len(rows) != 5 {
		t.Fatal(rows)
	}
	assertApprovalRefusal(t, rows[4], aw.KindList, "", h.principal, ap.CodeInvalidRequest)
}

func TestApprovalDispatchSubmitRefusalAudit(t *testing.T) {
	for _, code := range []ap.Code{ap.CodeConflict, ap.CodeSubmitWindowClosed, ap.CodeReservedVerb} {
		t.Run(string(code), func(t *testing.T) {
			h := newApprovalDispatchHarness(t, true)
			draft := approvalDispatchDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/different", 60))
			switch code {
			case ap.CodeSubmitWindowClosed:
				draft.RequestID = st.ID(9)
				draft.SubmitNotAfter = st.T0.Add(-time.Hour)
			case ap.CodeReservedVerb:
				draft = approvalDispatchDraft(st.ID(9), ap.CoordinatorExecutor, st.T0, st.Write("SSHGATE_XFER_SEND forbidden", 60))
			}
			// Reserved verbs are rejected by the strict daemon decoder, so bypass the client validator.
			frame, err := json.Marshal(aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: draft})
			if err != nil {
				t.Fatal(err)
			}
			approvalResponse(t, aw.KindSubmit, h.socket(t, append(frame, '\n'), nil), code)
			rows := h.refusals(t)
			if len(rows) != 1 {
				t.Fatal(rows)
			}
			assertApprovalRefusal(t, rows[0], aw.KindSubmit, draft.RequestID, h.principal, code)
		})
	}
}

func TestApprovalDispatchAuditFailuresAndLostResponse(t *testing.T) {
	h := newApprovalDispatchHarness(t, false)
	req := h.requests()[1]
	frame := approvalRequestFrame(t, req)
	peer := &PeerCredentials{UID: h.uid}
	conn := &approvalDispatchConn{Reader: bytes.NewReader(frame), failWrite: true}
	if err := h.service.HandleSignRequestWithPeer(context.Background(), conn, peer); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	rows := h.refusals(t)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	assertApprovalRefusal(t, rows[0], aw.KindGet, st.ID(1), h.principal, ap.CodeLifecycleUnavailable)
	conn = &approvalDispatchConn{Reader: bytes.NewReader(frame)}
	if err := h.service.HandleSignRequestWithPeer(context.Background(), conn, peer); err != nil {
		t.Fatal(err)
	}
	expected := bytes.Clone(conn.Bytes())
	if err := h.service.daemon.Audit.Close(); err != nil {
		t.Fatal(err)
	}
	conn = &approvalDispatchConn{Reader: bytes.NewReader(frame)}
	if err := h.service.HandleSignRequestWithPeer(context.Background(), conn, peer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conn.Bytes(), expected) {
		t.Fatal("audit failure changed response")
	}
}

func TestApprovalDispatchNoiseStaysInOutbox(t *testing.T) {
	h := newApprovalDispatchHarness(t, true)
	requests := h.requests()
	claim := requests[4].(aw.ClaimRequest)
	claim.ClaimToken = strings.Repeat("0", 64)
	report := requests[5].(aw.ReportRequest)
	report.ClaimToken = claim.ClaimToken
	for i, req := range []any{claim, report} {
		code := []ap.Code{ap.CodeInvalidClaim, ap.CodeInvalidReport}[i]
		kind := []string{aw.KindClaim, aw.KindReport}[i]
		approvalResponse(t, kind, h.socket(t, approvalRequestFrame(t, req), nil), code)
	}
	if rows := h.refusals(t); len(rows) != 0 {
		t.Fatalf("duplicate direct audit: %+v", rows)
	}
	// Joining the runtime makes the audit snapshot stable; each event must be either
	// still durable in the outbox or already written through the audit adapter.
	h.service.Close()
	record, err := h.store.Load(ap.RecordKey(h.principal, st.ID(1)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{ap.EventInvalidClaim, ap.EventInvalidReport} {
		found := bytes.Contains(data, []byte("\"transition\":\""+kind))
		for _, event := range record.Header.Outbox {
			found = found || event.Kind == kind
		}
		if !found {
			t.Fatalf("%s has no durable audit", kind)
		}
	}
}

func TestApprovalDispatchQueueFullAudit(t *testing.T) {
	h := newApprovalDispatchHarness(t, true, func(c *lc.Config) { c.Caps.FullRecords = 1 })
	request := h.requests()[0]
	approvalResponse(t, aw.KindSubmit, h.socket(t, approvalRequestFrame(t, request), nil), ap.CodeQueueFull)
	rows := h.refusals(t)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	assertApprovalRefusal(t, rows[0], aw.KindSubmit, st.ID(2), h.principal, ap.CodeQueueFull)
}

func TestApprovalDispatchAllowedUIDs(t *testing.T) {
	h := newApprovalDispatchHarness(t, false)
	config := runtimeConfig(t, h.store)
	config.AllowedUIDs = []uint32{h.uid}
	runtime, err := NewApprovalRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.service.AttachApprovals(runtime); err != nil {
		t.Fatal(err)
	}
	startRuntime(t, runtime)
	other := h.uid + 1
	config.AllowedUIDs[0] = other // The runtime owns a copy of configuration.
	for i, request := range h.requests() {
		approvalResponse(t, aw.Kinds[i], h.socket(t, approvalRequestFrame(t, request), &other), ap.CodeNotFound)
	}
	rows := h.refusals(t)
	if len(rows) != 6 {
		t.Fatal(rows)
	}
	for i, row := range rows {
		id := st.ID(1)
		if i == 0 {
			id = st.ID(2)
		}
		if i == 2 || i == 3 {
			id = ""
		}
		assertApprovalRefusal(t, row, aw.Kinds[i], id, fmt.Sprintf("local-uid:%d", other), ap.CodeNotFound)
	}
	approvalResponse(t, aw.KindList, h.socket(t, approvalRequestFrame(t, h.requests()[2]), nil), "")
}

func TestApprovalDispatchReportReplay(t *testing.T) {
	h := newApprovalDispatchHarness(t, true)
	requests := h.requests()
	claim := requests[4].(aw.ClaimRequest)
	approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, claim), nil), "")
	report := requests[5].(aw.ReportRequest)
	report.Report.Steps = []ap.StepReport{{Ordinal: 1, Status: ap.StepSucceeded}}
	report.Report.Class = ap.ClassSucceeded
	report.Report.ExecutedOrdinals = []int{1}
	frame := approvalRequestFrame(t, report)
	for range 2 {
		approvalResponse(t, aw.KindReport, h.socket(t, frame, nil), "")
	}
	record, err := h.store.Load(ap.RecordKey(h.principal, st.ID(1)))
	if err != nil {
		t.Fatal(err)
	}
	stored := record.Header.FinalReport
	if stored == nil || stored.Class != ap.ClassSucceeded || !reflect.DeepEqual(stored.ExecutedOrdinals, []int{1}) || stored.ResultDigest != report.Report.ResultDigest {
		t.Fatalf("stored report: %+v", stored)
	}
	after := approvalResponse(t, aw.KindClaim, h.socket(t, approvalRequestFrame(t, claim), nil), "")
	if after.Claim.Status != ap.ClaimExecutionReported || after.Claim.Class != ap.ClassSucceeded || len(after.Claim.Signatures) != 0 {
		t.Fatal(after)
	}
	report.Report.ResultDigest = strings.Repeat("c", 64)
	approvalResponse(t, aw.KindReport, h.socket(t, approvalRequestFrame(t, report), nil), ap.CodeInvalidReport)
	if rows := h.refusals(t); len(rows) != 0 {
		t.Fatal(rows)
	}
}

type approvalDeadlineConn struct {
	approvalDispatchConn
	deadline time.Time
}

func (c *approvalDeadlineConn) SetDeadline(at time.Time) error { c.deadline = at; return nil }
func TestApprovalDispatchWriteGrace(t *testing.T) {
	h := newApprovalDispatchHarness(t, false)
	for _, request := range h.requests() {
		conn := &approvalDeadlineConn{approvalDispatchConn: approvalDispatchConn{Reader: bytes.NewReader(approvalRequestFrame(t, request))}}
		before := time.Now()
		if err := h.service.HandleSignRequestWithPeer(context.Background(), conn, &PeerCredentials{UID: h.uid}); err != nil {
			t.Fatal(err)
		}
		if !conn.deadline.After(before) {
			t.Fatal("response did not receive write grace")
		}
	}
}

func TestApprovalDispatchForeignAndMissingAreIdentical(t *testing.T) {
	foreign := newApprovalDispatchHarness(t, true)
	missing := newApprovalDispatchHarness(t, false)
	runtime, err := NewApprovalRuntime(runtimeConfig(t, missing.store))
	if err != nil {
		t.Fatal(err)
	}
	if err := missing.service.AttachApprovals(runtime); err != nil {
		t.Fatal(err)
	}
	startRuntime(t, runtime)
	other := foreign.uid + 1
	requests := foreign.requests()
	for _, i := range []int{1, 3, 4, 5} {
		frame := approvalRequestFrame(t, requests[i])
		first := foreign.socket(t, frame, &other)
		second := missing.socket(t, frame, &other)
		approvalResponse(t, aw.Kinds[i], first, ap.CodeNotFound)
		if !bytes.Equal(first, second) {
			t.Fatalf("%s reveals record existence", aw.Kinds[i])
		}
	}
	first, second := foreign.refusals(t), missing.refusals(t)
	if len(first) != 4 || !reflect.DeepEqual(first, second) {
		t.Fatalf("audit reveals record existence: %+v / %+v", first, second)
	}
}

func TestApprovalDispatchWaitWakesOnReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newApprovalDispatchHarness(t, true)
		synctest.Wait()
		request := h.requests()[3].(aw.WaitRequest)
		request.WaitSeconds = 55
		conn := &approvalDispatchConn{Reader: bytes.NewReader(approvalRequestFrame(t, request))}
		done := make(chan error, 1)
		go func() {
			done <- h.service.HandleSignRequestWithPeer(context.Background(), conn, &PeerCredentials{UID: h.uid})
		}()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("Wait returned before a change: %v", err)
		default:
		}
		report := h.requests()[5]
		reported := &approvalDispatchConn{Reader: bytes.NewReader(approvalRequestFrame(t, report))}
		if err := h.service.HandleSignRequestWithPeer(context.Background(), reported, &PeerCredentials{UID: h.uid}); err != nil {
			t.Fatal(err)
		}
		approvalResponse(t, aw.KindReport, reported.Bytes(), "")
		// The report must wake Wait now, not the 55-second timeout.
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("Wait did not wake on the report")
		}
		response := approvalResponse(t, aw.KindWait, conn.Bytes(), "")
		current := &approvalDispatchConn{Reader: bytes.NewReader(approvalRequestFrame(t, h.requests()[1]))}
		if err := h.service.HandleSignRequestWithPeer(context.Background(), current, &PeerCredentials{UID: h.uid}); err != nil {
			t.Fatal(err)
		}
		get := approvalResponse(t, aw.KindGet, current.Bytes(), "")
		if len(response.Summaries) != 1 || !reflect.DeepEqual(response.Summaries[0], *get.Summary) {
			t.Fatal("Wait did not return the committed report view")
		}
	})
}
