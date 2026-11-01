package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// cancelHTTP posts a cancel as user through the full mux.
func cancelHTTP(t *testing.T, s *Server, user, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	session := &s.Human.Auth.store.(*voteSessionStore).session
	previous := session.UserID
	session.UserID = user
	defer func() { session.UserID = previous }()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(data))
	r.Header.Set("Origin", "https://localhost")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func createCancelAdmin(t *testing.T, db *sqlitestore.DB) {
	t.Helper()
	if err := db.CreateUser(context.Background(), &store.User{ID: "root", Username: "root", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
}

type cancelV1Fixture struct {
	s    *Server
	db   *sqlitestore.DB
	e    *ApprovalV2Engine
	core *humanVoteCore
	now  time.Time
	row  *store.Request
}

func newCancelV1Fixture(t *testing.T, required int) cancelV1Fixture {
	t.Helper()
	e, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, now := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.Auth.now = func() time.Time { return now }
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	core := &humanVoteCore{}
	h.Engine = &ApprovalEngine{Store: db, Core: core}
	createCancelAdmin(t, db)
	expiry := now.Add(time.Hour)
	row := &store.Request{RequestID: "r-cancel", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[{"server":"web","cmd":"true","ttl_seconds":60}]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: required}
	if err := db.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	return cancelV1Fixture{s: s, db: db, e: e, core: core, now: now, row: row}
}

func (f cancelV1Fixture) current(t *testing.T) *store.Request {
	t.Helper()
	row, err := f.db.GetByID(context.Background(), f.row.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func outboxRows(t *testing.T, db *sqlitestore.DB) map[string]string {
	t.Helper()
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT event_key,evidence FROM legacy_expiry_outbox`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, evidence string
		if err := rows.Scan(&key, &evidence); err != nil {
			t.Fatal(err)
		}
		out[key] = evidence
	}
	return out
}

func TestHumanCancelRefusesNonAdmin(t *testing.T) {
	f := newCancelV1Fixture(t, 1)
	submitApproval(t, f.e, 1)
	v2 := readApproval(t, f.db, 1)
	before := f.current(t)
	for _, user := range []string{"operator", "missing"} {
		if w := cancelHTTP(t, f.s, user, "/ui/request/r-cancel/cancel", nil); w.Code != 403 || !bytes.Contains(w.Body.Bytes(), []byte("admin role required")) {
			t.Fatalf("v1 %s: %d %s", user, w.Code, w.Body)
		}
		if w := cancelHTTP(t, f.s, user, "/ui/v2/request/"+v2.RecordHandle+"/cancel", cancelV2Request{PlanHash: v2.Record.Header.PlanHash}); w.Code != 403 {
			t.Fatalf("v2 %s: %d %s", user, w.Code, w.Body)
		}
	}
	if after := f.current(t); after.Status != before.Status || after.TerminalReason != "" {
		t.Fatalf("v1 row changed: %+v", after)
	}
	if !bytes.Equal(v2.RecordJSON, readApproval(t, f.db, 1).RecordJSON) || len(outboxRows(t, f.db)) != 0 {
		t.Fatal("refused cancel changed state")
	}
}

// r5.8: after a route cancel, an operator's vote gets today's 409 and exactly
// one inert vote_refused{canceled} line, and the row is unchanged.
func TestHumanCancelV1ThenVoteIsInert(t *testing.T) {
	f := newCancelV1Fixture(t, 2)
	ctx := context.Background()
	token, err := f.s.Human.issueVoteChallenge(alignVoteSession(f.s, ctx, f.now), legacyVoteBinding(f.row, "operator"), *f.row.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	w := cancelHTTP(t, f.s, "root", "/ui/request/r-cancel/cancel", nil)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"terminal_reason":"canceled"`)) {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	canceled := f.current(t)
	if canceled.Status != store.StatusDenied || canceled.TerminalReason != "canceled" || len(canceled.Signatures) != 0 {
		t.Fatalf("canceled row: %+v", canceled)
	}
	if w := cancelHTTP(t, f.s, "root", "/ui/request/r-cancel/cancel", struct{}{}); w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("request already resolved")) {
		t.Fatalf("repeat: %d %s", w.Code, w.Body)
	}
	if w := cancelHTTP(t, f.s, "root", "/ui/request/missing/cancel", nil); w.Code != 404 {
		t.Fatalf("missing: %d %s", w.Code, w.Body)
	}
	// The durable audit line names the admin.
	var lines []signerkit.AuditCall
	f.e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		lines = append(lines, c)
		return nil
	})
	if f.e.flushPass(ctx) {
		t.Fatal("flush failed")
	}
	if len(lines) != 1 || lines[0].Lifecycle != "legacy-canceled" || lines[0].Reason != "canceled" || lines[0].Operator == nil || lines[0].Operator.ID != "root" || lines[0].RequestID != "r-cancel" {
		t.Fatalf("cancel audit: %+v", lines)
	}
	before, _ := json.Marshal(canceled)
	if w := voteHTTP(t, f.s, "/ui/request/r-cancel/deny", token.Challenge); w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("request already resolved")) {
		t.Fatalf("vote after cancel: %d %s", w.Code, w.Body)
	}
	if len(f.core.verdicts) != 1 || f.core.verdicts[0].Approval == nil || !f.core.verdicts[0].Approval.Replay || f.core.verdicts[0].Approval.Transition != "vote_refused{canceled}" {
		t.Fatalf("inert line: %+v", f.core.verdicts)
	}
	after, _ := json.Marshal(f.current(t))
	if !bytes.Equal(before, after) {
		t.Fatalf("row changed:\n%s\n%s", before, after)
	}
	if votes, err := f.db.ListVotes(ctx, "r-cancel"); err != nil || len(votes) != 0 {
		t.Fatalf("vote stored: %v %v", votes, err)
	}
}

// E4c: a cancel does not wait for an unaudited vote, and records it as evidence.
func TestHumanCancelV1WithUnauditedVote(t *testing.T) {
	f := newCancelV1Fixture(t, 1)
	ctx := context.Background()
	if _, _, err := f.db.PrepareVote(ctx, &store.Vote{RequestID: "r-cancel", Operator: "operator", Decision: store.DecisionApprove, AuthnMethod: "session", TS: f.now}); err != nil {
		t.Fatal(err)
	}
	if w := cancelHTTP(t, f.s, "root", "/ui/request/r-cancel/cancel", nil); w.Code != 200 {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	row := f.current(t)
	if row.Status != store.StatusDenied || row.TerminalReason != "canceled" || len(row.Signatures) != 0 || row.ApprovedBy != "" {
		t.Fatalf("row: %+v", row)
	}
	outbox := outboxRows(t, f.db)
	if len(outbox) != 1 {
		t.Fatalf("outbox: %v", outbox)
	}
	for _, evidence := range outbox {
		var decoded sqlitestore.LegacyCancelEvidence
		if err := json.Unmarshal([]byte(evidence), &decoded); err != nil || decoded.Admin != "root" || len(decoded.Votes) != 1 || decoded.Votes[0].Audited {
			t.Fatalf("evidence: %s %v", evidence, err)
		}
	}
}

// mintRaceCore cancels through the route while the vote is minting.
type mintRaceCore struct {
	humanVoteCore
	duringMint func()
	minted     int
}

func (c *mintRaceCore) SignApproved(cmds []signerkit.HostedSignCommand, _ time.Time) ([]signerkit.HostedSignResult, error) {
	c.minted++
	c.duringMint()
	return []signerkit.HostedSignResult{}, nil
}

func TestHumanCancelV1RacingMintDiscardsSignatures(t *testing.T) {
	f := newCancelV1Fixture(t, 1)
	ctx := alignVoteSession(f.s, context.Background(), f.now)
	core := &mintRaceCore{}
	core.duringMint = func() {
		if w := cancelHTTP(t, f.s, "root", "/ui/request/r-cancel/cancel", nil); w.Code != 200 {
			t.Errorf("racing cancel: %d %s", w.Code, w.Body)
		}
	}
	f.s.Human.Engine = &ApprovalEngine{Store: f.db, Core: core}
	token, err := f.s.Human.issueVoteChallenge(ctx, legacyVoteBinding(f.row, "operator"), *f.row.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, f.s, "/ui/request/r-cancel/approve", token.Challenge); w.Code != 409 {
		t.Fatalf("racing vote: %d %s", w.Code, w.Body)
	}
	row := f.current(t)
	if core.minted != 1 || row.Status != store.StatusDenied || row.TerminalReason != "canceled" || len(row.Signatures) != 0 || row.ApprovedBy != "" {
		t.Fatalf("mint race: minted=%d row=%+v", core.minted, row)
	}
}

// An operator's ordinary deny keeps its veto; it is not an admin cancel.
func TestHumanOrdinaryDenyStillVetoes(t *testing.T) {
	f := newCancelV1Fixture(t, 2)
	f.s.Human.Cfg.ApprovalPolicy.DenyVeto = true
	ctx := alignVoteSession(f.s, context.Background(), f.now)
	token, err := f.s.Human.issueVoteChallenge(ctx, legacyVoteBinding(f.row, "operator"), *f.row.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, f.s, "/ui/request/r-cancel/deny", token.Challenge); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"flipped":true`)) {
		t.Fatalf("v1 veto: %d %s", w.Code, w.Body)
	}
	if row := f.current(t); row.Status != store.StatusDenied || row.TerminalReason != "" {
		t.Fatalf("v1 veto row: %+v", row)
	}
	f.e.config.RequiredApprovals = 2
	submitApproval(t, f.e, 1)
	v2 := readApproval(t, f.db, 1)
	ctx = alignVoteSession(f.s, ctx, f.e.now().Wall)
	token, err = f.s.Human.issueVoteChallenge(ctx, v2VoteBinding(v2, "operator"), v2.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, f.s, "/ui/v2/request/"+v2.RecordHandle+"/deny", token.Challenge); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"decision":"denied"`)) {
		t.Fatalf("v2 veto: %d %s", w.Code, w.Body)
	}
	if d := readApproval(t, f.db, 1).Record.Header.Decision; d == nil || d.Status != ap.ApprovalDenied || d.DecidedBy == "root" {
		t.Fatalf("v2 veto decision: %+v", d)
	}
}

func newCancelV2Fixture(t *testing.T, file bool) (*Server, *ApprovalV2Engine, *sqlitestore.DB) {
	t.Helper()
	e, db, _ := approvalEngineFixture(t, file)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	s.Human.ordinaryEngine = func() *ApprovalV2Engine { return e }
	alignVoteSession(s, ctx, e.now().Wall)
	createCancelAdmin(t, db)
	return s, e, db
}

func TestHumanCancelV2(t *testing.T) {
	s, e, db := newCancelV2Fixture(t, false)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	path := "/ui/v2/request/" + row.RecordHandle + "/cancel"
	for _, tc := range []struct {
		body    any
		code    int
		message string
	}{
		{nil, 400, "malformed request"},
		{map[string]string{}, 400, "plan_hash is required"},
		{map[string]string{"plan_hash": "x", "extra": "y"}, 400, "malformed request"},
		{cancelV2Request{PlanHash: "0000"}, 409, "view changed"},
	} {
		if w := cancelHTTP(t, s, "root", path, tc.body); w.Code != tc.code || !bytes.Contains(w.Body.Bytes(), []byte(tc.message)) {
			t.Fatalf("%v: %d %s", tc.body, w.Code, w.Body)
		}
		if !bytes.Equal(row.RecordJSON, readApproval(t, db, 1).RecordJSON) {
			t.Fatalf("%v changed the row", tc.body)
		}
	}
	if w := cancelHTTP(t, s, "root", "/ui/v2/request/NOSUCHHANDLE/cancel", cancelV2Request{PlanHash: "x"}); w.Code != 404 {
		t.Fatalf("unknown: %d %s", w.Code, w.Body)
	}
	w := cancelHTTP(t, s, "root", path, cancelV2Request{PlanHash: row.Record.Header.PlanHash})
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"approval_status":"canceled"`)) {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	d := readApproval(t, db, 1).Record.Header.Decision
	if d == nil || d.Status != ap.ApprovalCanceled || d.DecidedBy != "root" {
		t.Fatalf("decision: %+v", d)
	}
	if w := cancelHTTP(t, s, "root", path, cancelV2Request{PlanHash: row.Record.Header.PlanHash}); w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("already resolved")) {
		t.Fatalf("repeat: %d %s", w.Code, w.Body)
	}
	// A record a vote decided first answers "already resolved" and is unchanged.
	submitApproval(t, e, 2)
	voted := readApproval(t, db, 2)
	approvalDeny(t, e, db, 2)
	decided := readApproval(t, db, 2)
	if decided.Record.Header.Decision == nil {
		t.Fatal("vote did not decide")
	}
	if w := cancelHTTP(t, s, "root", "/ui/v2/request/"+voted.RecordHandle+"/cancel", cancelV2Request{PlanHash: voted.Record.Header.PlanHash}); w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("already resolved")) {
		t.Fatalf("decided: %d %s", w.Code, w.Body)
	}
	if !bytes.Equal(decided.RecordJSON, readApproval(t, db, 2).RecordJSON) {
		t.Fatal("cancel changed a decided record")
	}
}

// r5.1: two sub_principals with one request_id are two rows; a cancel acts on
// exactly the one its handle names.
func TestHumanCancelV2SameRequestIDTwoPrincipals(t *testing.T) {
	s, e, db := newCancelV2Fixture(t, false)
	ctx := context.Background()
	keys := []sqlitestore.V2Key{{ClientID: "client", SubPrincipal: "local-uid:1000", RequestID: approvalKey(1).RequestID}, {ClientID: "client", SubPrincipal: "local-uid:1001", RequestID: approvalKey(1).RequestID}}
	rows := make([]*sqlitestore.V2Row, len(keys))
	for i, key := range keys {
		if _, err := e.Submit(ctx, key.ClientID, key.SubPrincipal, approvalDraft(1)); err != nil {
			t.Fatal(err)
		}
		row, err := db.ReadV2(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = row
	}
	if rows[0].RecordHandle == rows[1].RecordHandle {
		t.Fatal("handles collide")
	}
	if w := cancelHTTP(t, s, "root", "/ui/request/"+keys[0].RequestID+"/cancel", nil); w.Code != 404 {
		t.Fatalf("bare request_id on v1 route: %d %s", w.Code, w.Body)
	}
	for i, row := range rows {
		if w := cancelHTTP(t, s, "root", "/ui/v2/request/"+row.RecordHandle+"/cancel", cancelV2Request{PlanHash: row.Record.Header.PlanHash}); w.Code != 200 {
			t.Fatalf("cancel %d: %d %s", i, w.Code, w.Body)
		}
		for j, key := range keys {
			current, err := db.ReadV2(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			canceled := current.Record.Header.Decision != nil
			if canceled != (j <= i) {
				t.Fatalf("after cancel %d, row %d canceled=%v", i, j, canceled)
			}
		}
	}
}

// E21 with A10's classifier: a held writer makes the v2 cancel answer 503 with
// the row byte-unchanged; the resend after release succeeds.
func TestHumanCancelV2HeldWriterLock(t *testing.T) {
	s, e, db := newCancelV2Fixture(t, true)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	released := make(chan struct{})
	go func() {
		timer := time.NewTimer(6 * time.Second)
		defer timer.Stop()
		<-timer.C
		_ = tx.Rollback()
		close(released)
	}()
	path := "/ui/v2/request/" + row.RecordHandle + "/cancel"
	body := cancelV2Request{PlanHash: row.Record.Header.PlanHash}
	if w := cancelHTTP(t, s, "root", path, body); w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("busy — retry")) {
		t.Fatalf("held writer: %d %s", w.Code, w.Body)
	}
	if !bytes.Equal(row.RecordJSON, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("busy cancel changed the row")
	}
	<-released
	if w := cancelHTTP(t, s, "root", path, body); w.Code != 200 {
		t.Fatalf("after release: %d %s", w.Code, w.Body)
	}
}

type cancelGetUserBusyStore struct{ *sqlitestore.DB }

func (cancelGetUserBusyStore) GetUser(context.Context, string) (*store.User, error) {
	return nil, approvalBusy(5)
}

// A busy role read: v2 answers 503; v1 keeps today's 500.
func TestHumanCancelBusyRoleRead(t *testing.T) {
	s, e, db := newCancelV2Fixture(t, false)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	s.Human.Store = cancelGetUserBusyStore{db}
	if w := cancelHTTP(t, s, "root", "/ui/v2/request/"+row.RecordHandle+"/cancel", cancelV2Request{PlanHash: row.Record.Header.PlanHash}); w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("busy — retry")) {
		t.Fatalf("v2: %d %s", w.Code, w.Body)
	}
	if w := cancelHTTP(t, s, "root", "/ui/request/r/cancel", nil); w.Code != 500 {
		t.Fatalf("v1: %d %s", w.Code, w.Body)
	}
	if !bytes.Equal(row.RecordJSON, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("busy read changed the row")
	}
}

// A plan_hash mismatch answers "view changed" even when Clock changed the
// record in the same call (the Clock part still commits).
func TestHumanCancelV2StalePlanWithClockChange(t *testing.T) {
	s, e, db := newCancelV2Fixture(t, false)
	clock := e.config.Clock.(interface{ Advance(time.Duration) })
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	clock.Advance(6 * time.Second)
	alignVoteSession(s, context.Background(), e.now().Wall)
	w := cancelHTTP(t, s, "root", "/ui/v2/request/"+row.RecordHandle+"/cancel", cancelV2Request{PlanHash: "stale"})
	if w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("view changed")) {
		t.Fatalf("stale plan: %d %s", w.Code, w.Body)
	}
	after := readApproval(t, db, 1).Record.Header
	if bytes.Equal(row.RecordJSON, readApproval(t, db, 1).RecordJSON) || after.Decision != nil {
		t.Fatalf("Clock did not commit or cancel landed: %+v", after.Decision)
	}
}

// With no engine generation running, a v2 cancel answers the uniform
// "approvals unavailable", not a busy retry.
func TestHumanCancelV2NoEngine(t *testing.T) {
	s, e, db := newCancelV2Fixture(t, false)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	s.Human.ordinaryEngine = func() *ApprovalV2Engine { return nil }
	w := cancelHTTP(t, s, "root", "/ui/v2/request/"+row.RecordHandle+"/cancel", cancelV2Request{PlanHash: row.Record.Header.PlanHash})
	if w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("approvals unavailable")) {
		t.Fatalf("no engine: %d %s", w.Code, w.Body)
	}
}
