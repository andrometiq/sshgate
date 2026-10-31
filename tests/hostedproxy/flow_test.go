package hostedproxy_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

func TestHostedProxyEndToEnd(t *testing.T) {
	h := newProxyHarness(t)
	p := h.socket(7)
	ctx := context.Background()
	draft := h.draft(1)
	summary, err := p.client.Submit(ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	if summary.RequestID != draft.RequestID || summary.ApprovalStatus != ap.ApprovalPending {
		t.Fatalf("submit: %+v", summary)
	}
	if h.row(7, draft.RequestID).Record.Header.RequestID != draft.RequestID {
		t.Fatal("submit returned before commit")
	}
	h.approve(7, draft.RequestID)
	waited, err := p.client.Wait(ctx, []string{draft.RequestID}, 0)
	if err != nil || len(waited) != 1 || waited[0].ApprovalStatus != ap.ApprovalApproved {
		t.Fatalf("wait: %+v %v", waited, err)
	}
	token := statetest.Token(draft.RequestID)
	plan := h.row(7, draft.RequestID).Record.Header.PlanHash
	claim, err := p.client.Claim(ctx, draft.RequestID, plan, token)
	if err != nil || claim.Status != ap.ClaimSignatures || len(claim.Signatures) != 1 {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	replay, err := p.client.Claim(ctx, draft.RequestID, plan, token)
	if err != nil || !reflect.DeepEqual(claim, replay) {
		t.Fatalf("claim replay changed: %+v %v", replay, err)
	}
	report := successfulReport()
	if err = p.client.Report(ctx, draft.RequestID, plan, token, report); err != nil {
		t.Fatal(err)
	}
	after, err := p.client.Get(ctx, draft.RequestID)
	if err != nil || after.ExecutionClass != report.Class {
		t.Fatalf("reported: %+v %v", after, err)
	}
	if h.minter.count.Load() != 1 || h.row(7, draft.RequestID).Record.Header.FinalReport == nil {
		t.Fatal("expected one signature set and persisted final report")
	}
	if rows := p.auditRows(t); len(rows) != 0 {
		t.Fatalf("successful calls wrote refusal audit: %s", rows)
	}
}

func TestHostedProxyBusyResends(t *testing.T) {
	h := newProxyHarness(t)
	p := h.socket(7)
	ctx := context.Background()
	draft := h.draft(1)
	busyThenResend := func(name, path string, call func() error) {
		t.Helper()
		before := len(h.transport.recorded("POST " + path))
		release := h.holdWriter()
		start := time.Now()
		err := call()
		held := time.Since(start)
		release()
		if !errors.Is(err, aw.ErrBusy) {
			t.Fatalf("%s: %v, want ErrBusy", name, err)
		}
		if held < 4*time.Second {
			t.Fatalf("%s returned before SQLite busy timeout: %s", name, held)
		}
		rows := p.auditRows(t)
		if len(rows) == 0 || !bytes.Contains(rows[len(rows)-1], []byte(`"transition":"refused{busy}"`)) {
			t.Fatalf("missing busy audit: %s", rows)
		}
		auditCount := len(rows)
		if err = call(); err != nil {
			t.Fatalf("%s resend: %v", name, err)
		}
		if len(p.auditRows(t)) != auditCount {
			t.Fatal("successful resend wrote audit")
		}
		bodies := h.transport.recorded("POST " + path)[before:]
		if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
			t.Fatalf("%s body changed or retried automatically: %q", name, bodies)
		}
	}
	busyThenResend("submit", aw.HostedRoot, func() error { _, err := p.client.Submit(ctx, draft); return err })
	h.approve(7, draft.RequestID)
	plan := h.row(7, draft.RequestID).Record.Header.PlanHash
	token := statetest.Token(draft.RequestID)
	var claim aw.ClaimAnswer
	busyThenResend("claim", aw.HostedRoot+"/"+draft.RequestID+"/claim", func() error {
		var err error
		claim, err = p.client.Claim(ctx, draft.RequestID, plan, token)
		return err
	})
	if claim.Status != ap.ClaimSignatures || len(claim.Signatures) != 1 {
		t.Fatalf("claim: %+v", claim)
	}
	if got := h.row(7, draft.RequestID).Record.Payload.Signatures; !reflect.DeepEqual(got, claim.Signatures) {
		t.Fatalf("persisted signature set differs: %v", got)
	}
	replay, err := p.client.Claim(ctx, draft.RequestID, plan, token)
	if err != nil || !reflect.DeepEqual(claim, replay) {
		t.Fatalf("claim replay: %+v %v", replay, err)
	}
	busyThenResend("report", aw.HostedRoot+"/"+draft.RequestID+"/report", func() error { return p.client.Report(ctx, draft.RequestID, plan, token, successfulReport()) })
	rows, _, err := p.client.List(ctx, 10, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("records: %+v %v", rows, err)
	}
	row := h.row(7, draft.RequestID)
	if row.Record.Header.FinalReport == nil || row.Record.Header.FinalReport.ResultDigest != successfulReport().ResultDigest || !reflect.DeepEqual(row.Record.Header.FinalReport.Steps, successfulReport().Steps) {
		t.Fatal("busy retry duplicated/lost materialization or report")
	}
	audit := p.auditRows(t)
	if len(audit) != 3 {
		t.Fatalf("audit rows=%d want 3", len(audit))
	}
	for _, r := range audit {
		if !bytes.Contains(r, []byte(`"transition":"refused{busy}"`)) {
			t.Fatalf("nonbusy audit: %s", r)
		}
	}
}

func TestHostedProxyLostSubmit(t *testing.T) {
	h := newProxyHarness(t)
	p := h.socket(7)
	ctx := context.Background()
	draft := h.draft(1)
	p.peer.drop.Store(true)
	if _, err := p.client.Submit(ctx, draft); !errors.Is(err, aw.ErrResponseLost) {
		t.Fatalf("lost submit: %v", err)
	}
	got, err := p.client.Get(ctx, draft.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.client.Submit(ctx, draft)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("reconciliation: %+v %+v %v", got, again, err)
	}
	records, _, err := p.client.List(ctx, 10, "")
	if err != nil || len(records) != 1 {
		t.Fatalf("records: %d %v", len(records), err)
	}
}

func TestHostedProxyConcurrentOwnerIDs(t *testing.T) {
	for _, order := range [][]uint32{{7, 8}, {8, 7}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			h := newProxyHarness(t)
			a := h.socket(order[0])
			b := h.socketAs(order[1], a)
			ctx := context.Background()
			drafts := []ap.ApprovalDraft{h.draft(1), h.draft(1)}
			drafts[0].Rationale = "owner one"
			drafts[1].Rationale = "owner two"
			// Keep both A5 calls in flight while imposing each owner's commit order.
			firstSeen, secondSeen, firstDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			next := h.transport.next
			var arrivals atomic.Int32
			h.transport.next = transportFunc(func(req *http.Request) (*http.Response, error) {
				switch arrivals.Add(1) {
				case 1:
					close(firstSeen)
					defer close(firstDone)
					select {
					case <-secondSeen:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
					response, err := next.RoundTrip(req)
					return response, err
				case 2:
					close(secondSeen)
					select {
					case <-firstDone:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
				}
				return next.RoundTrip(req)
			})
			var wg sync.WaitGroup
			errs := make([]error, 2)
			wg.Add(1)
			go func() { defer wg.Done(); _, errs[0] = a.client.Submit(ctx, drafts[0]) }()
			select {
			case <-firstSeen:
			case <-time.After(5 * time.Second):
				t.Fatal("first submit did not reach transport")
			}
			wg.Add(1)
			go func() { defer wg.Done(); _, errs[1] = b.client.Submit(ctx, drafts[1]) }()

			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			bodies := h.transport.recorded("POST " + aw.HostedRoot)
			if len(bodies) != 2 {
				t.Fatalf("submit count %d", len(bodies))
			}
			for i, body := range bodies {
				var submitted aw.HostedSubmitBody
				if err := json.Unmarshal(body, &submitted); err != nil {
					t.Fatal(err)
				}
				if submitted.RequesterSub != fmt.Sprintf("local-uid:%d", order[i]) {
					t.Fatalf("admission order %d: %s", i, submitted.RequesterSub)
				}
			}
			first, second := h.row(order[0], drafts[0].RequestID), h.row(order[1], drafts[1].RequestID)
			if first.Record.Header.PlanHash == second.Record.Header.PlanHash || first.RecordHandle == second.RecordHandle {
				t.Fatal("owners collapsed to one record")
			}
			for i, p := range []*proxySocket{a, b} {
				records, _, err := p.client.List(ctx, 10, "")
				if err != nil || len(records) != 1 || records[0].PlanHash != h.row(order[i], drafts[i].RequestID).Record.Header.PlanHash {
					t.Fatalf("owner listing: %+v %v", records, err)
				}
			}
		})
	}
}

func TestHostedProxyOwnerScopeAndRestart(t *testing.T) {
	for _, shed := range []bool{false, true} {
		t.Run(fmt.Sprint(shed), func(t *testing.T) {
			h := newProxyHarness(t)
			a := h.socket(7)
			b := h.socketAs(8, a)
			ctx := context.Background()
			draft := h.draft(1)
			if _, err := a.client.Submit(ctx, draft); err != nil {
				t.Fatal(err)
			}
			h.approve(7, draft.RequestID)
			row := h.row(7, draft.RequestID)
			plan := row.Record.Header.PlanHash
			token := statetest.Token(draft.RequestID)
			if _, err := a.client.Claim(ctx, draft.RequestID, plan, token); err != nil {
				t.Fatal(err)
			}
			if shed {
				if err := a.client.Report(ctx, draft.RequestID, plan, token, successfulReport()); err != nil {
					t.Fatal(err)
				}
				h.shed(7, draft.RequestID)
			}
			for restart := 0; restart < 2; restart++ {
				for _, kind := range []string{aw.KindGet, aw.KindWait, aw.KindClaim, aw.KindReport} {
					for _, id := range []string{draft.RequestID, statetest.ID(99)} {
						var err error
						switch kind {
						case aw.KindGet:
							_, err = b.client.Get(ctx, id)
						case aw.KindWait:
							_, err = b.client.Wait(ctx, []string{id}, 0)
						case aw.KindClaim:
							_, err = b.client.Claim(ctx, id, plan, token)
						case aw.KindReport:
							err = b.client.Report(ctx, id, plan, token, successfulReport())
						}
						var wire *aw.WireError
						if !errors.As(err, &wire) || wire.Code != ap.CodeNotFound {
							t.Fatalf("%s client: %v", kind, err)
						}
					}

					foreign := ownerFrame(t, b, kind, draft.RequestID, plan, token)
					missing := ownerFrame(t, b, kind, statetest.ID(99), plan, token)
					if !bytes.Equal(foreign, missing) || !bytes.Contains(foreign, []byte(`"code":"not_found"`)) {
						t.Fatalf("%s foreign %s missing %s", kind, foreign, missing)
					}
				}
				list, _, err := b.client.List(ctx, 10, "")
				if err != nil || len(list) != 0 {
					t.Fatalf("foreign list: %+v %v", list, err)
				}
				own, err := a.client.Get(ctx, draft.RequestID)
				if err != nil || own.Pruned != shed {
					t.Fatalf("owner: %+v %v", own, err)
				}
				if restart == 0 {
					a.close()
					b.close()
					a = h.socket(7)
					b = h.socketAs(8, a)
				}
			}
		})
	}
}

// Raw frames supplement the A5-client calls so hidden and absent records can
// be compared byte-for-byte, including their fixed refusal text.
func ownerFrame(t *testing.T, p *proxySocket, kind, id, plan string, token [32]byte) []byte {
	t.Helper()
	var req any
	switch kind {
	case aw.KindGet:
		req = aw.GetRequest{ApprovalProto: 1, Kind: kind, RequestID: id}
	case aw.KindWait:
		req = aw.WaitRequest{ApprovalProto: 1, Kind: kind, RequestIDs: []string{id}}
	case aw.KindClaim:
		req = aw.ClaimRequest{ApprovalProto: 1, Kind: kind, RequestID: id, PlanHash: plan, ClaimToken: hex.EncodeToString(token[:])}
	case aw.KindReport:
		req = aw.ReportRequest{ApprovalProto: 1, Kind: kind, RequestID: id, PlanHash: plan, ClaimToken: hex.EncodeToString(token[:]), Report: successfulReport()}
	}
	frame, err := aw.MarshalLocalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", p.client.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type frameConn struct {
	*bytes.Reader
	bytes.Buffer
}

func (c *frameConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (h *proxyHarness) shed(uid uint32, id string) {
	h.t.Helper()
	h.clock.Advance(20 * time.Minute)
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := h.row(uid, id)
		if len(r.Record.Header.Outbox) == 0 && (r.Record.Payload == nil || len(r.Record.Payload.Signatures) == 0) {
			break
		}
		if time.Now().After(deadline) {
			h.t.Fatal("outbox did not drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tx, err := h.db.BeginV2(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback()
	key := sqlitestore.V2Key{ClientID: "client", SubPrincipal: fmt.Sprintf("local-uid:%d", uid), RequestID: id}
	row, err := h.db.GetV2(ctx, tx, key)
	if err != nil {
		h.t.Fatal(err)
	}
	now := ap.Now{Wall: h.clock.Wall(), Elapsed: h.clock.Elapsed()}
	settings := ap.Settings{Hosted: true, Retention: 7 * 24 * time.Hour, ReportHorizon: ap.ReportHorizonDefault}
	rec, answer := ap.Apply(&row.Record, ap.ShedRecord{Pressure: true}, now, ap.Inputs{Epoch: row.Record.Header.Decision.Epoch, Settings: settings})
	if answer.Code != "" || !rec.Header.Shed {
		h.t.Fatalf("shed: %+v", answer)
	}
	if err = h.db.PutV2(ctx, tx, key, rec, sqlitestore.V2Projection{Now: now, Epoch: row.Record.Header.Decision.Epoch, Settings: settings}); err != nil {
		h.t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		h.t.Fatal(err)
	}
}

// This companion deliberately uses no listeners. It validates the same daemon,
// HTTP, database and human-vote composition independently of socket permission.
func TestHostedProxyInProcessContention(t *testing.T) {
	h := newHarness(t, false)
	p := h.direct(7)
	draft := h.draft(1)
	invoke := func(kind string, req any) aw.Response {
		t.Helper()
		frame, err := aw.MarshalLocalRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		conn := &frameConn{Reader: bytes.NewReader(frame)}
		if err = p.peer.HandleSignRequest(context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		response, err := aw.DecodeLocalResponse(kind, bytes.TrimSuffix(conn.Buffer.Bytes(), []byte{'\n'}))
		var wire *aw.WireError
		if err != nil && !errors.As(err, &wire) {
			t.Fatal(err)
		}
		return response
	}
	busyResend := func(kind, path string, req any) aw.Response {
		t.Helper()
		before := len(h.transport.recorded("POST " + path))
		release := h.holdWriter()
		busy := invoke(kind, req)
		release()
		if busy.Error == nil || busy.Error.Code != ap.CodeBusy || !errors.Is(busy.Error, aw.ErrBusy) {
			t.Fatalf("busy response: %+v", busy)
		}
		rows := len(p.auditRows(t))
		answer := invoke(kind, req)
		if answer.Error != nil {
			t.Fatalf("resend: %+v", answer)
		}
		if len(p.auditRows(t)) != rows {
			t.Fatal("successful resend audited")
		}
		bodies := h.transport.recorded("POST " + path)[before:]
		if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
			t.Fatalf("resend bytes: %q", bodies)
		}
		return answer
	}
	busyResend(aw.KindSubmit, aw.HostedRoot, aw.SubmitRequest{ApprovalProto: 1, Kind: aw.KindSubmit, Draft: draft})
	h.approve(7, draft.RequestID)
	plan := h.row(7, draft.RequestID).Record.Header.PlanHash
	token := statetest.Token(draft.RequestID)
	claim := busyResend(aw.KindClaim, aw.HostedRoot+"/"+draft.RequestID+"/claim", aw.ClaimRequest{ApprovalProto: 1, Kind: aw.KindClaim, RequestID: draft.RequestID, PlanHash: plan, ClaimToken: hex.EncodeToString(token[:])})
	if claim.Claim == nil || claim.Claim.Status != ap.ClaimSignatures || !reflect.DeepEqual(claim.Claim.Signatures, h.row(7, draft.RequestID).Record.Payload.Signatures) {
		t.Fatalf("signature set: %+v", claim)
	}
	busyResend(aw.KindReport, aw.HostedRoot+"/"+draft.RequestID+"/report", aw.ReportRequest{ApprovalProto: 1, Kind: aw.KindReport, RequestID: draft.RequestID, PlanHash: plan, ClaimToken: hex.EncodeToString(token[:]), Report: successfulReport()})
	if len(p.auditRows(t)) != 3 {
		t.Fatalf("audit count %d", len(p.auditRows(t)))
	}
	for _, row := range p.auditRows(t) {
		if !bytes.Contains(row, []byte(`"transition":"refused{busy}"`)) {
			t.Fatalf("audit: %s", row)
		}
	}
	final := h.row(7, draft.RequestID).Record.Header.FinalReport
	if final == nil || final.ResultDigest != successfulReport().ResultDigest || !reflect.DeepEqual(final.Steps, successfulReport().Steps) {
		t.Fatal("missing or changed accepted report")
	}
	listed := invoke(aw.KindList, aw.ListRequest{ApprovalProto: 1, Kind: aw.KindList, Limit: 10})
	if listed.Error != nil || len(listed.Summaries) != 1 {
		t.Fatalf("record count: %+v", listed)
	}
	replay := invoke(aw.KindReport, aw.ReportRequest{ApprovalProto: 1, Kind: aw.KindReport, RequestID: draft.RequestID, PlanHash: plan, ClaimToken: hex.EncodeToString(token[:]), Report: successfulReport()})
	if replay.Error != nil || !reflect.DeepEqual(final, h.row(7, draft.RequestID).Record.Header.FinalReport) || len(p.auditRows(t)) != 3 {
		t.Fatalf("report replay changed accepted report: %+v", replay)
	}
	h.shed(7, draft.RequestID)
	if !h.row(7, draft.RequestID).Record.Header.Shed {
		t.Fatal("not shed")
	}
}
