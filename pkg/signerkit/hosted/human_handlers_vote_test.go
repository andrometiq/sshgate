package hosted

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pquerna/otp/totp"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

type humanVoteCore struct {
	HostedCore
	verdicts         []signerkit.AuditVerdict
	fail             bool
	ordinaryFailures int
	hook             func()
}

func (c *humanVoteCore) Verdict(_ context.Context, v signerkit.AuditVerdict) error {
	c.verdicts = append(c.verdicts, v)
	if v.Approval == nil && c.ordinaryFailures > 0 {
		c.ordinaryFailures--
		return errors.New("ordinary audit unavailable")
	}
	if c.hook != nil {
		c.hook()
	}
	if c.fail && v.Approval != nil {
		return errors.New("audit unavailable")
	}
	return nil
}

func voteHTTP(t *testing.T, s *Server, path, token string, codes ...string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]string{"challenge": token}
	if len(codes) > 0 {
		body["step_up_totp"] = codes[0]
	}
	data, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(data))
	r.Header.Set("Origin", "https://localhost")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: s.Human.Auth.store.(*voteSessionStore).session.ID})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestHumanVoteV2OrderedChecks(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	ctx = alignVoteSession(s, ctx, e.now().Wall)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	path := "/ui/v2/request/" + row.RecordHandle + "/approve"
	check := func(token string, status int, message string) {
		t.Helper()
		w := voteHTTP(t, s, path, token)
		if w.Code != status || (message != "" && !bytes.Contains(w.Body.Bytes(), []byte(message))) {
			t.Fatalf("got %d %s, want %d %s", w.Code, w.Body, status, message)
		}
	}
	check("", 400, "challenge")
	h.Cfg.RequireStepUp = true
	check("forged", 409, "view changed")
	rec := readApproval(t, db, 1).Record
	if len(rec.Header.Votes) != 0 || rec.Header.Outbox[len(rec.Header.Outbox)-1].Detail != "stale_challenge" {
		t.Fatalf("forged challenge altered votes or missed audit: %+v", rec.Header)
	}
	h.Cfg.RequireStepUp = false
	// A preparing challenge permits deny only, and cannot approve after assist lands.
	token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = e.mutate(ctx, row.Key, ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	check(token.Challenge, 409, "view changed")
	row = readApproval(t, db, 1)
	token, err = h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	check(token.Challenge, 200, `"flipped":true`)
	check(token.Challenge, 409, "request already resolved")
	rec = readApproval(t, db, 1).Record
	if len(rec.Header.Votes) != 1 || rec.Header.Outbox[len(rec.Header.Outbox)-1].Kind != ap.EventVoteReplay {
		t.Fatalf("replay: %+v", rec.Header)
	}
	if err := db.CreateUser(ctx, &store.User{ID: "admin", Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(rec)
	for _, user := range []string{"missing", "admin"} {
		s.Human.Auth.store.(*voteSessionStore).session.UserID = user
		check("", 409, "request already resolved")
		after, _ := json.Marshal(readApproval(t, db, 1).Record)
		if !bytes.Equal(before, after) {
			t.Fatalf("non-operator %s appended noise", user)
		}
	}
	s.Human.Auth.store.(*voteSessionStore).session.UserID = "other"
	check("", 409, "request already resolved")
	after := readApproval(t, db, 1).Record
	if len(after.Header.Outbox) != len(rec.Header.Outbox)+1 || after.Header.Outbox[len(after.Header.Outbox)-1].Detail != "resolved" {
		t.Fatal("operator resolved refusal not audited")
	}
	_ = clock
}

func TestHumanVoteV2BusyAndRole(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	ctx = alignVoteSession(s, ctx, e.now().Wall)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	path := "/ui/v2/request/" + row.RecordHandle + "/deny"
	token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	e.config.Store = approvalFaultStore{ApprovalV2Store: db, beginErr: approvalBusy(5)}
	if w := voteHTTP(t, s, path, token.Challenge); w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("busy — retry")) {
		t.Fatalf("busy: %d %s", w.Code, w.Body)
	}
	e.config.Store = db
	if err := db.CreateUser(ctx, &store.User{ID: "admin", Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	h.Auth.store.(*voteSessionStore).session.UserID = "admin"
	if w := voteHTTP(t, s, path, token.Challenge); w.Code != 403 {
		t.Fatalf("role: %d %s", w.Code, w.Body)
	}
	h.Auth.store.(*voteSessionStore).session.UserID = "operator"
	if w := voteHTTP(t, s, path, token.Challenge); w.Code != 200 {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
}

func TestHumanVoteV1ChallengeAndInertAudit(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, now := voteChallengeFixture(t, false)
	h := s.Human
	h.Auth.now = func() time.Time { return now }
	h.Store = db
	core := &humanVoteCore{}
	h.Engine = &ApprovalEngine{Store: db, Core: core}
	expiry := now.Add(time.Hour)
	row := &store.Request{RequestID: "r-vote", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 2}
	if err := db.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	path := "/ui/request/" + row.RequestID + "/deny"
	if w := voteHTTP(t, s, path, ""); w.Code != 400 {
		t.Fatalf("missing: %d %s", w.Code, w.Body)
	}
	if len(core.verdicts) != 0 {
		t.Fatal("missing challenge audited")
	}
	if w := voteHTTP(t, s, path, "forged"); w.Code != 409 {
		t.Fatalf("forged: %d %s", w.Code, w.Body)
	}
	if len(core.verdicts) != 1 || core.verdicts[0].Approval.Transition != "vote_refused{stale_challenge}" || !core.verdicts[0].Approval.Replay {
		t.Fatalf("audit: %+v", core.verdicts)
	}
	token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if w := voteHTTP(t, s, path, token.Challenge); w.Code != 200 {
			t.Fatalf("vote %d: %d %s", i, w.Code, w.Body)
		}
	}
	if len(core.verdicts) != 3 || core.verdicts[2].Approval.Transition != "vote_duplicate" {
		t.Fatalf("duplicate audit: %+v", core.verdicts)
	}
	if err := db.UpdateStatus(ctx, row.RequestID, store.StatusDenied, nil, ""); err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, s, path, ""); w.Code != 409 {
		t.Fatalf("terminal: %d %s", w.Code, w.Body)
	}
	if len(core.verdicts) != 4 || core.verdicts[3].Approval.Transition != "vote_duplicate" {
		t.Fatal("terminal duplicate not audited")
	}
}

type voteTOTPStore struct {
	store.Store
	calls    int
	busy     bool
	consumed func()
}

func (s *voteTOTPStore) ConsumeTOTPStep(ctx context.Context, user, secret string, step int64) (bool, error) {
	s.calls++
	if s.busy {
		return false, approvalBusy(5)
	}
	ok, err := s.Store.ConsumeTOTPStep(ctx, user, secret, step)
	if ok && err == nil && s.consumed != nil {
		s.consumed()
	}
	return ok, err
}

func TestHumanVoteStepUpContention(t *testing.T) {
	for _, stage := range []string{"begin", "refusal", "consume", "after-consume"} {
		t.Run(stage, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			s, ctx, _, _ := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = db
			h.ordinaryEngine = func() *ApprovalV2Engine { return e }
			ctx = alignVoteSession(s, ctx, e.now().Wall)
			h.Cfg.RequireStepUp = true
			h.Auth.now = clock.Wall
			st := &voteTOTPStore{Store: db}
			h.Auth.store.(*voteSessionStore).Store = st
			enrolled, err := h.Auth.EnrollTOTP(ctx, "operator", "operator")
			if err != nil {
				t.Fatal(err)
			}
			submitApproval(t, e, 1)
			row := readApproval(t, db, 1)
			token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			code, err := totp.GenerateCode(enrolled.Secret, clock.Wall())
			if err != nil {
				t.Fatal(err)
			}
			post := func(challenge, code string) *httptest.ResponseRecorder {
				data, _ := json.Marshal(map[string]string{"challenge": challenge, "step_up_totp": code})
				r := httptest.NewRequest("POST", "/ui/v2/request/"+row.RecordHandle+"/deny", bytes.NewReader(data))
				r.Header.Set("Origin", "https://localhost")
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				return w
			}
			if w := post("forged", code); w.Code != 409 || st.calls != 0 {
				t.Fatalf("stale spent TOTP: %d calls=%d", w.Code, st.calls)
			}
			original := e.config.Store
			switch stage {
			case "begin":
				e.config.Store = approvalFaultStore{ApprovalV2Store: db, beginErr: approvalBusy(5)}
			case "refusal":
				e.config.Store = &voteBeginFault{ApprovalV2Store: db, failAt: 2}
			case "consume":
				st.busy = true
			case "after-consume":
				st.consumed = func() { e.config.Store = approvalFaultStore{ApprovalV2Store: db, beginErr: approvalBusy(5)} }
			}
			challenge := token.Challenge
			if stage == "refusal" {
				challenge = "forged"
			}
			w := post(challenge, code)
			message := "busy — retry"
			if stage == "consume" || stage == "after-consume" {
				message += " with a fresh code"
			}
			if w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte(message)) {
				t.Fatalf("busy: %d %s", w.Code, w.Body)
			}
			if stage == "begin" || stage == "refusal" {
				if st.calls != 0 {
					t.Fatal("preflight spent code")
				}
			}
			if len(readApproval(t, db, 1).Record.Header.Votes) != 0 {
				t.Fatal("busy stored vote")
			}
			e.config.Store = original
			st.busy = false
			st.consumed = nil
			if stage == "after-consume" {
				if w := post(token.Challenge, code); w.Code != 401 {
					t.Fatalf("reused consumed code: %d %s", w.Code, w.Body)
				}
				code, err = totp.GenerateCode(enrolled.Secret, clock.Wall().Add(30*time.Second))
				if err != nil {
					t.Fatal(err)
				}
			}
			if w := post(token.Challenge, code); w.Code != 200 {
				t.Fatalf("retry: %d %s", w.Code, w.Body)
			}
		})
	}
}

type voteBeginFault struct {
	ApprovalV2Store
	calls, failAt int
}

func (s *voteBeginFault) BeginV2(ctx context.Context) (*sql.Tx, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, approvalBusy(5)
	}
	return s.ApprovalV2Store.BeginV2(ctx)
}

func TestHumanVoteV2NoiseFoldAndExpiry(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	ctx = alignVoteSession(s, ctx, e.now().Wall)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	path := "/ui/v2/request/" + row.RecordHandle + "/deny"
	for i := 0; i < 40; i++ {
		if w := voteHTTP(t, s, path, "forged"); w.Code != 409 {
			t.Fatalf("noise %d: %d %s", i, w.Code, w.Body)
		}
	}
	rec := readApproval(t, db, 1).Record
	noises := 0
	for _, event := range rec.Header.Outbox {
		if event.Kind == ap.EventVoteRefused {
			noises++
		}
	}
	if noises != 32 || rec.Header.NoiseDropped != 8 || len(rec.Header.Votes) != 0 {
		t.Fatalf("noise cap: %d, votes %d", noises, len(rec.Header.Votes))
	}
	submitApproval(t, e, 2)
	row = readApproval(t, db, 2)
	path = "/ui/v2/request/" + row.RecordHandle + "/deny"
	token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), clock.Wall().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	if w := voteHTTP(t, s, path, token.Challenge); w.Code != 409 {
		t.Fatalf("expired challenge: %d %s", w.Code, w.Body)
	}
	rec = readApproval(t, db, 2).Record
	if rec.Header.Outbox[len(rec.Header.Outbox)-1].Detail != "expired_challenge" {
		t.Fatal("wrong expiry reason")
	}
	clock.Advance(row.Record.Header.RequestExpiresAt.Sub(clock.Wall()))
	if w := voteHTTP(t, s, path, ""); w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("request already resolved")) {
		t.Fatalf("expired row: %d %s", w.Code, w.Body)
	}
	rec = readApproval(t, db, 2).Record
	if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalExpired || len(rec.Header.Votes) != 0 {
		t.Fatal("Clock not persisted")
	}
}

type voteListHook struct {
	store.Store
	hook func()
}

func (s *voteListHook) ListVotes(ctx context.Context, id string) ([]*store.Vote, error) {
	votes, err := s.Store.ListVotes(ctx, id)
	if s.hook != nil {
		hook := s.hook
		s.hook = nil
		hook()
	}
	return votes, err
}

func TestHumanVoteV1RefusalAndRaces(t *testing.T) {
	for _, scenario := range []string{"expired-challenge", "expired-row", "admin", "unaudited-same", "unaudited-opposite", "resolved-race", "duplicate-resolved-race", "cancel-after-audit", "audit-failure"} {
		t.Run(scenario, func(t *testing.T) {
			_, db, _ := approvalEngineFixture(t, false)
			s, ctx, _, now := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = db
			h.Auth.now = func() time.Time { return now }
			core := &humanVoteCore{}
			h.Engine = &ApprovalEngine{Store: db, Core: core}
			expiry := now.Add(time.Hour)
			row := &store.Request{RequestID: "r-edge", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 2}
			if err := db.Insert(ctx, row); err != nil {
				t.Fatal(err)
			}
			token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
			if err != nil {
				t.Fatal(err)
			}
			path := "/ui/request/" + row.RequestID + "/deny"
			want := 409
			transition := ""
			wantVotes := 0
			cancel := func() {
				if _, _, err := db.CancelLegacy(ctx, row.RequestID, now); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "expired-challenge":
				token, err = h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), now.Add(-time.Second))
				if err != nil {
					t.Fatal(err)
				}
				transition = "vote_refused{expired_challenge}"
			case "expired-row":
				now = expiry
				token.Challenge = ""
				transition = "vote_refused{expired}"
			case "admin":
				if err := db.CreateUser(ctx, &store.User{ID: "admin", Username: "admin", Role: "admin"}); err != nil {
					t.Fatal(err)
				}
				h.Auth.store.(*voteSessionStore).session.UserID = "admin"
				want = 403
			case "unaudited-same", "unaudited-opposite":
				if _, _, err := db.PrepareVote(ctx, &store.Vote{RequestID: row.RequestID, Operator: "operator", Decision: store.DecisionDeny, AuthnMethod: "session", TS: now}); err != nil {
					t.Fatal(err)
				}
				if scenario == "unaudited-same" {
					want = 200
					wantVotes = 1
				} else {
					path = "/ui/request/" + row.RequestID + "/approve"
					transition = "vote_duplicate"
				}
			case "resolved-race":
				h.Store = &voteListHook{Store: db, hook: cancel}
				transition = "vote_refused{canceled}"
			case "duplicate-resolved-race":
				if _, _, err := db.PrepareVote(ctx, &store.Vote{RequestID: row.RequestID, Operator: "operator", Decision: store.DecisionDeny, AuthnMethod: "session", TS: now}); err != nil {
					t.Fatal(err)
				}
				if err := db.MarkVoteAudited(ctx, row.RequestID, "operator"); err != nil {
					t.Fatal(err)
				}
				h.Store = &voteListHook{Store: db, hook: cancel}
				transition = "vote_duplicate"
				wantVotes = 1
			case "cancel-after-audit":
				core.hook = cancel
				wantVotes = 1
			case "audit-failure":
				core.fail = true
				token.Challenge = "forged"
				transition = "vote_refused{stale_challenge}"
			}
			w := voteHTTP(t, s, path, token.Challenge)
			if w.Code != want {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, want)
			}
			votes, err := db.ListVotes(ctx, row.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			if len(votes) != wantVotes {
				t.Fatalf("votes %d, want %d", len(votes), wantVotes)
			}
			if scenario == "admin" {
				if len(core.verdicts) != 0 {
					t.Fatal("admin audited")
				}
				return
			}
			if len(core.verdicts) != 1 {
				t.Fatalf("audit count %d, want 1", len(core.verdicts))
			}
			if transition != "" {
				v := core.verdicts[0]
				if v.Approval == nil || !v.Approval.Replay || v.Approval.Transition != transition {
					t.Fatalf("audit %+v", v)
				}
			} else if core.verdicts[0].Approval != nil {
				t.Fatal("real vote marked inert")
			}
		})
	}
}

func alignVoteSession(s *Server, ctx context.Context, now time.Time) context.Context {
	session := &s.Human.Auth.store.(*voteSessionStore).session
	session.ExpiresAt = now.Add(24 * time.Hour)
	return context.WithValue(ctx, voteSessionContextKey{}, voteSession{ID: session.ID, ExpiresAt: session.ExpiresAt})
}

func TestHumanVoteHeldWriter(t *testing.T) {
	for _, stepUp := range []bool{false, true} {
		t.Run(fmt.Sprint(stepUp), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, true)
			s, ctx, _, _ := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = db
			h.ordinaryEngine = func() *ApprovalV2Engine { return e }
			ctx = alignVoteSession(s, ctx, clock.Wall())
			h.Auth.now = clock.Wall
			h.Cfg.RequireStepUp = stepUp
			st := &voteTOTPStore{Store: db}
			h.Auth.store.(*voteSessionStore).Store = st
			code := ""
			if stepUp {
				enrollment, err := h.Auth.EnrollTOTP(ctx, "operator", "operator")
				if err != nil {
					t.Fatal(err)
				}
				code, err = totp.GenerateCode(enrollment.Secret, clock.Wall())
				if err != nil {
					t.Fatal(err)
				}
			}
			submitApproval(t, e, 1)
			row := readApproval(t, db, 1)
			token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginV2(ctx)
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
			path := "/ui/v2/request/" + row.RecordHandle + "/deny"
			w := voteHTTP(t, s, path, token.Challenge, code)
			if w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("busy — retry")) {
				t.Fatalf("held writer: %d %s", w.Code, w.Body)
			}
			if st.calls != 0 || !bytes.Equal(row.RecordJSON, readApproval(t, db, 1).RecordJSON) {
				t.Fatal("busy consumed step or changed row")
			}
			<-released
			if w := voteHTTP(t, s, path, token.Challenge, code); w.Code != 200 {
				t.Fatalf("after release: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestHumanVoteStorageUncertain(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	ctx = alignVoteSession(s, ctx, clock.Wall())
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	e.commit = func(*sql.Tx) error { return errors.New("uncertain commit") }
	w := voteHTTP(t, s, "/ui/v2/request/"+row.RecordHandle+"/deny", token.Challenge)
	if w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("storage uncertain — retry")) {
		t.Fatalf("uncertain: %d %s", w.Code, w.Body)
	}
	if len(readApproval(t, db, 1).Record.Header.Votes) != 0 {
		t.Fatal("uncertain vote stored")
	}
}

func TestHumanVoteV2PendingReplay(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	e.config.RequiredApprovals = 2
	s, ctx, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	ctx = alignVoteSession(s, ctx, clock.Wall())
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	path := "/ui/v2/request/" + row.RecordHandle
	if w := voteHTTP(t, s, path+"/deny", token.Challenge); w.Code != 200 {
		t.Fatalf("vote: %d %s", w.Code, w.Body)
	}
	if _, _, err = e.mutate(ctx, row.Key, ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, s, path+"/deny", token.Challenge); w.Code != 409 {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	row = readApproval(t, db, 1)
	if row.Record.Header.Outbox[len(row.Record.Header.Outbox)-1].Detail != "stale_challenge" {
		t.Fatal("stale replay misclassified")
	}
	token, err = h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), row.Record.Header.RequestExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"deny", "approve"} {
		if w := voteHTTP(t, s, path+"/"+action, token.Challenge); w.Code != 409 {
			t.Fatalf("replay: %d %s", w.Code, w.Body)
		}
	}
	row = readApproval(t, db, 1)
	if len(row.Record.Header.Votes) != 1 || row.Record.Header.Outbox[len(row.Record.Header.Outbox)-1].Kind != ap.EventVoteReplay {
		t.Fatal("duplicate altered vote")
	}
}

func TestHumanVoteExpiryDuringStepUp(t *testing.T) {
	for _, mode := range []string{"expiry", "role"} {
		t.Run(mode, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			s, ctx, _, _ := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = db
			h.ordinaryEngine = func() *ApprovalV2Engine { return e }
			ctx = alignVoteSession(s, ctx, clock.Wall())
			h.Auth.now = clock.Wall
			h.Cfg.RequireStepUp = true
			st := &voteTOTPStore{Store: db, consumed: func() {
				if mode == "expiry" {
					clock.Advance(2 * time.Second)
					return
				}
				tx, err := db.BeginV2(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err := tx.ExecContext(ctx, "UPDATE users SET role = ? WHERE id = ?", "admin", "operator"); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}}
			h.Auth.store.(*voteSessionStore).Store = st
			enrollment, err := h.Auth.EnrollTOTP(ctx, "operator", "operator")
			if err != nil {
				t.Fatal(err)
			}
			code, err := totp.GenerateCode(enrollment.Secret, clock.Wall())
			if err != nil {
				t.Fatal(err)
			}
			submitApproval(t, e, 1)
			row := readApproval(t, db, 1)
			token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, "operator"), clock.Wall().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			w := voteHTTP(t, s, "/ui/v2/request/"+row.RecordHandle+"/deny", token.Challenge, code)
			if mode == "role" {
				current := readApproval(t, db, 1)
				if w.Code != 403 || len(current.Record.Header.Votes) != 0 || current.Record.Header.OutboxSeq != row.Record.Header.OutboxSeq {
					t.Fatalf("role changed: %d %s", w.Code, w.Body)
				}
				return
			}
			if w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("view changed")) {
				t.Fatalf("expired while authenticating: %d %s", w.Code, w.Body)
			}
			row = readApproval(t, db, 1)
			if len(row.Record.Header.Votes) != 0 || row.Record.Header.Outbox[len(row.Record.Header.Outbox)-1].Detail != "expired_challenge" {
				t.Fatal("expired token counted or not audited")
			}
		})
	}
}

func TestHumanVoteV2QuorumAndVoteRoom(t *testing.T) {
	for _, veto := range []bool{false, true} {
		t.Run(fmt.Sprint(veto), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			e.config.RequiredApprovals = 3
			s, ctx, _, _ := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = db
			h.ordinaryEngine = func() *ApprovalV2Engine { return e }
			ctx = alignVoteSession(s, ctx, clock.Wall())
			h.Cfg.ApprovalPolicy.DenyVeto = veto
			for i := 0; i < 67; i++ {
				id := fmt.Sprintf("voter-%d", i)
				if err := db.CreateUser(ctx, &store.User{ID: id, Username: id, Role: "operator"}); err != nil {
					t.Fatal(err)
				}
			}
			submitApproval(t, e, 1)
			if _, _, err := e.mutate(ctx, approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
				t.Fatal(err)
			}
			post := func(operator, action string, want int) {
				t.Helper()
				row := readApproval(t, db, 1)
				h.Auth.store.(*voteSessionStore).session.UserID = operator
				token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, operator), row.Record.Header.RequestExpiresAt)
				if err != nil {
					t.Fatal(err)
				}
				w := voteHTTP(t, s, "/ui/v2/request/"+row.RecordHandle+"/"+action, token.Challenge)
				if w.Code != want {
					t.Fatalf("%s/%s: %d %s want %d", operator, action, w.Code, w.Body, want)
				}
				if want == 409 && !bytes.Contains(w.Body.Bytes(), []byte("vote limit reached: this vote cannot change the outcome")) {
					t.Fatalf("room response %s", w.Body)
				}
			}
			post("voter-0", "deny", 200)
			if veto {
				row := readApproval(t, db, 1)
				if row.Record.Header.Decision == nil || row.Record.Header.Decision.Status != ap.ApprovalDenied {
					t.Fatal("veto did not deny")
				}
				return
			}
			for i := 1; i < 63; i++ {
				post(fmt.Sprintf("voter-%d", i), "deny", 200)
			}
			post("voter-63", "deny", 409)
			post("client", "approve", 409)
			for i := 63; i < 66; i++ {
				post(fmt.Sprintf("voter-%d", i), "approve", 200)
			}
			row := readApproval(t, db, 1)
			if len(row.Record.Header.Votes) != 66 || row.Record.Header.Decision == nil || row.Record.Header.Decision.Status != ap.ApprovalApproved {
				t.Fatal("reserved quorum slots lost")
			}
			refused := 0
			for _, event := range row.Record.Header.Outbox {
				if event.Kind == ap.EventVoteRefused && event.Detail == "set_full" {
					refused++
				}
			}
			if refused != 2 {
				t.Fatalf("set_full events %d", refused)
			}
		})
	}
}

func TestHumanVoteV2SelfApprovalAndPrincipalIsolation(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	e.config.RequiredApprovals = 2
	s, ctx, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.ordinaryEngine = func() *ApprovalV2Engine { return e }
	ctx = alignVoteSession(s, ctx, clock.Wall())
	submitApproval(t, e, 1)
	if _, err := e.Submit(ctx, "other-client", "", approvalDraft(1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.mutate(ctx, approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	for _, operator := range []string{"client", "operator", "other"} {
		row := readApproval(t, db, 1)
		h.Auth.store.(*voteSessionStore).session.UserID = operator
		token, err := h.issueVoteChallenge(ctx, v2VoteBinding(row, operator), row.Record.Header.RequestExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if w := voteHTTP(t, s, "/ui/v2/request/"+row.RecordHandle+"/approve", token.Challenge); w.Code != 200 {
			t.Fatalf("vote %s: %d %s", operator, w.Code, w.Body)
		}
		row = readApproval(t, db, 1)
		if (row.Record.Header.Decision != nil) != (operator == "other") {
			t.Fatal("self vote counted toward quorum")
		}
	}
	key := approvalKey(1)
	key.ClientID = "other-client"
	other, err := db.ReadV2(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Record.Header.Votes) != 0 || other.Record.Header.Decision != nil {
		t.Fatal("vote crossed principal boundary")
	}
}

func TestHumanVoteV1BusyAndResolvedAdmin(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, now := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = db
	h.Auth.now = func() time.Time { return now }
	h.Cfg.RequireStepUp = true
	core := &humanVoteCore{}
	h.Engine = &ApprovalEngine{Store: db, Core: core}
	st := &voteTOTPStore{Store: db, busy: true}
	h.Auth.store.(*voteSessionStore).Store = st
	enrollment, err := h.Auth.EnrollTOTP(ctx, "operator", "operator")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, now)
	if err != nil {
		t.Fatal(err)
	}
	expiry := now.Add(time.Hour)
	row := &store.Request{RequestID: "r-busy", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 2}
	if err := db.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
	if err != nil {
		t.Fatal(err)
	}
	path := "/ui/request/" + row.RequestID + "/deny"
	if w := voteHTTP(t, s, path, token.Challenge, code); w.Code != 401 {
		t.Fatalf("v1 busy: %d %s", w.Code, w.Body)
	}
	if len(core.verdicts) != 0 {
		t.Fatal("step-up failure audited")
	}
	if err := db.CreateUser(ctx, &store.User{ID: "admin", Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	h.Auth.store.(*voteSessionStore).session.UserID = "admin"
	if err := db.UpdateStatus(ctx, row.RequestID, store.StatusDenied, nil, ""); err != nil {
		t.Fatal(err)
	}
	if w := voteHTTP(t, s, path, ""); w.Code != 409 {
		t.Fatalf("resolved admin: %d %s", w.Code, w.Body)
	}
	if len(core.verdicts) != 0 {
		t.Fatal("resolved admin audited")
	}
}

func TestHumanVoteV1ApprovedReplay(t *testing.T) {
	for _, operator := range []string{"operator", "other"} {
		for _, action := range []string{"approve", "deny"} {
			for _, failAudit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/fail=%v", operator, action, failAudit), func(t *testing.T) {
					_, db, _ := approvalEngineFixture(t, false)
					s, ctx, _, now := voteChallengeFixture(t, true)
					h := s.Human
					h.Store = db
					h.Auth.now = func() time.Time { return now }
					core := &humanVoteCore{HostedCore: h.Engine.Core}
					h.Engine = &ApprovalEngine{Store: db, Core: core}
					expiry := now.Add(time.Hour)
					row := &store.Request{RequestID: "r-approved", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[{"server":"example","cmd":"true","ttl_seconds":60,"host_key_fp":"SHA256:test"}]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 1}
					if err := db.Insert(ctx, row); err != nil {
						t.Fatal(err)
					}
					token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
					if err != nil {
						t.Fatal(err)
					}
					path := "/ui/request/" + row.RequestID
					if w := voteHTTP(t, s, path+"/approve", token.Challenge); w.Code != 200 {
						t.Fatalf("first approval: %d %s", w.Code, w.Body)
					}
					before, err := db.GetByID(ctx, row.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					if before.Status != store.StatusApproved || len(before.Signatures) == 0 {
						t.Fatal("real approval did not sign")
					}
					h.Auth.store.(*voteSessionStore).session.UserID = operator
					core.fail = failAudit
					if w := voteHTTP(t, s, path+"/"+action, token.Challenge); w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("request already resolved")) {
						t.Fatalf("terminal replay: %d %s", w.Code, w.Body)
					}
					after, err := db.GetByID(ctx, row.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					beforeJSON, _ := json.Marshal(before)
					afterJSON, _ := json.Marshal(after)
					if !bytes.Equal(beforeJSON, afterJSON) {
						t.Fatal("replay changed approved row")
					}
					votes, err := db.ListVotes(ctx, row.RequestID)
					if err != nil || len(votes) != 1 || votes[0].Decision != store.DecisionApprove {
						t.Fatalf("immutable votes: %+v %v", votes, err)
					}
					if len(core.verdicts) != 2 || core.verdicts[0].Approval != nil {
						t.Fatalf("normal/inert count: %+v", core.verdicts)
					}
					replay := core.verdicts[1]
					transition := "vote_refused{resolved}"
					if operator == "operator" {
						transition = "vote_duplicate"
					}
					if replay.Approval == nil || !replay.Approval.Replay || replay.Approval.Transition != transition || replay.Approval.Decision != action || replay.Approved != (action == "approve") || replay.Operator.ID != operator || replay.Operator.AuthnMethod != "session" || replay.CommandSHA256 != commandsSHA256(row.Commands) {
						t.Fatalf("wrong inert metadata: %+v", replay)
					}
				})
			}
		}
	}
}

func TestHumanVoteV1RepeatedRefusals(t *testing.T) {
	for _, scenario := range []string{"expired-row", "audited-expired-row", "expired-challenge", "canceled-row", "cancel-race", "duplicate-cancel-race", "other-session", "restart"} {
		for _, failAudit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fail=%v", scenario, failAudit), func(t *testing.T) {
				_, db, _ := approvalEngineFixture(t, false)
				s, ctx, _, now := voteChallengeFixture(t, false)
				h := s.Human
				h.Store = db
				h.Auth.now = func() time.Time { return now }
				h.Cfg.RequireStepUp = true
				core := &humanVoteCore{fail: failAudit}
				h.Engine = &ApprovalEngine{Store: db, Core: core}
				steps := &voteTOTPStore{Store: db}
				h.Auth.store.(*voteSessionStore).Store = steps
				expiry := now.Add(time.Minute)
				row := &store.Request{RequestID: "r-repeated", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 2}
				if err := db.Insert(ctx, row); err != nil {
					t.Fatal(err)
				}
				token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
				if err != nil {
					t.Fatal(err)
				}
				transition := "vote_refused{stale_challenge}"
				terminal := ""
				if scenario == "audited-expired-row" || scenario == "duplicate-cancel-race" {
					if _, _, err := db.PrepareVote(ctx, &store.Vote{RequestID: row.RequestID, Operator: "operator", Decision: store.DecisionDeny, AuthnMethod: "session", TS: now}); err != nil {
						t.Fatal(err)
					}
					if err := db.MarkVoteAudited(ctx, row.RequestID, "operator"); err != nil {
						t.Fatal(err)
					}
				}
				cancel := func() {
					if _, _, err := db.CancelLegacy(ctx, row.RequestID, now); err != nil {
						t.Fatal(err)
					}
				}
				switch scenario {
				case "expired-challenge":
					token, err = h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), now.Add(-time.Second))
					if err != nil {
						t.Fatal(err)
					}
					transition = "vote_refused{expired_challenge}"
				case "expired-row", "audited-expired-row":
					now = expiry
					terminal = "expired"
					transition = "vote_refused{expired}"
				case "canceled-row":
					cancel()
					terminal = "canceled"
					transition = "vote_refused{canceled}"
				case "cancel-race", "duplicate-cancel-race":
					h.Cfg.RequireStepUp = false
					h.Store = &voteListHook{Store: db, hook: cancel}
					terminal = "canceled"
					transition = "vote_refused{canceled}"
				case "other-session":
					h.Auth.store.(*voteSessionStore).session.ID = "fresh-session"
				case "restart":
					restarted := NewServer("test-key", db, nil)
					restarted.MachineClientID = "client"
					restarted.AttachHuman(&HumanAPI{Auth: h.Auth, Store: db, Engine: h.Engine, Cfg: h.Cfg})
					t.Cleanup(func() { _ = restarted.Close() })
					s = restarted
					h = s.Human
				}
				if scenario == "audited-expired-row" || scenario == "duplicate-cancel-race" {
					transition = "vote_duplicate"
				}
				snapshot := func() ([]byte, []byte) {
					t.Helper()
					current, err := db.GetByID(ctx, row.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					votes, err := db.ListVotes(ctx, row.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					r, err := json.Marshal(current)
					if err != nil {
						t.Fatal(err)
					}
					v, err := json.Marshal(votes)
					if err != nil {
						t.Fatal(err)
					}
					return r, v
				}
				beforeRow, beforeVotes := snapshot()
				path := "/ui/request/" + row.RequestID + "/deny"
				for attempt := 0; attempt < 2; attempt++ {
					w := voteHTTP(t, s, path, token.Challenge, "123456")
					message := "request already resolved"
					if terminal == "" {
						message = "view changed"
					}
					if w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte(message)) {
						t.Fatalf("attempt %d: %d %s", attempt, w.Code, w.Body)
					}
					if steps.calls != 0 {
						t.Fatal("inert refusal consumed a TOTP step")
					}
					if len(core.verdicts) != attempt+1 {
						t.Fatalf("attempt %d produced %d audit lines", attempt, len(core.verdicts))
					}
					verdict := core.verdicts[attempt]
					if verdict.Approval == nil || !verdict.Approval.Replay || verdict.Approval.Transition != transition || verdict.Approval.Decision != "deny" || verdict.Approved || verdict.Operator.ID != "operator" {
						t.Fatalf("wrong inert verdict %+v", verdict)
					}
					afterRow, afterVotes := snapshot()
					deliberateTransition := attempt == 0 && (scenario == "expired-row" || scenario == "audited-expired-row" || scenario == "cancel-race" || scenario == "duplicate-cancel-race")
					if !deliberateTransition && !bytes.Equal(beforeRow, afterRow) {
						t.Fatal("inert POST changed request")
					}
					if !bytes.Equal(beforeVotes, afterVotes) {
						t.Fatal("inert POST changed votes")
					}
					current, err := db.GetByID(ctx, row.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					if current.TerminalReason != terminal {
						t.Fatalf("terminal reason %q, want %q", current.TerminalReason, terminal)
					}
					beforeRow, beforeVotes = afterRow, afterVotes
				}
			})
		}
	}
}

func TestHumanVoteHandleReadBusy(t *testing.T) {
	s, _, _, _ := voteChallengeFixture(t, false)
	h := s.Human
	h.Store = uiHandleErrorStore{err: approvalBusy(5)}
	h.Cfg.RequireStepUp = true
	steps := &voteTOTPStore{}
	h.Auth.store.(*voteSessionStore).Store = steps
	w := voteHTTP(t, s, "/ui/v2/request/handle/approve", "unused", "123456")
	if w.Code != 503 || w.Body.String() != `{"error":"busy — retry"}`+"\n" {
		t.Fatalf("handle read busy: %d %s", w.Code, w.Body)
	}
	if steps.calls != 0 {
		t.Fatal("handle read contention consumed TOTP")
	}
}

type voteGetUserBusyStore struct{ *sqlitestore.DB }

func (s voteGetUserBusyStore) GetUser(context.Context, string) (*store.User, error) {
	return nil, fmt.Errorf("lookup: %w", approvalBusy(5))
}

func TestHumanVoteGetUserBusy(t *testing.T) {
	for _, isV2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v2=%v", isV2), func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			s, ctx, _, _ := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = voteGetUserBusyStore{db}
			h.ordinaryEngine = func() *ApprovalV2Engine { return e }
			ctx = alignVoteSession(s, ctx, clock.Wall())
			h.Auth.now = clock.Wall
			h.Cfg.RequireStepUp = true
			steps := &voteTOTPStore{Store: db}
			h.Auth.store.(*voteSessionStore).Store = steps
			enrollment, err := h.Auth.EnrollTOTP(ctx, "operator", "operator")
			if err != nil {
				t.Fatal(err)
			}
			code, err := totp.GenerateCode(enrollment.Secret, clock.Wall())
			if err != nil {
				t.Fatal(err)
			}
			expiry := clock.Wall().Add(time.Hour)
			legacy := &store.Request{RequestID: "r-user-busy", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[]`), CreatedAt: clock.Wall(), ExpiresAt: &expiry, RequiredApprovals: 2}
			if err := db.Insert(ctx, legacy); err != nil {
				t.Fatal(err)
			}
			submitApproval(t, e, 1)
			before := readApproval(t, db, 1)
			path := "/ui/request/" + legacy.RequestID + "/deny"
			binding := legacyVoteBinding(legacy, "operator")
			status, message := http.StatusInternalServerError, "get operator"
			if isV2 {
				path = "/ui/v2/request/" + before.RecordHandle + "/deny"
				binding = v2VoteBinding(before, "operator")
				expiry = before.Record.Header.RequestExpiresAt
				status, message = http.StatusServiceUnavailable, "busy — retry"
			}
			token, err := h.issueVoteChallenge(ctx, binding, expiry)
			if err != nil {
				t.Fatal(err)
			}
			w := voteHTTP(t, s, path, token.Challenge, code)
			if w.Code != status || w.Body.String() != fmt.Sprintf("{\"error\":%q}\n", message) {
				t.Fatalf("role lookup: %d %s", w.Code, w.Body)
			}
			if steps.calls != 0 || !bytes.Equal(before.RecordJSON, readApproval(t, db, 1).RecordJSON) {
				t.Fatal("role contention consumed TOTP or changed v2 state")
			}
			votes, err := db.ListVotes(ctx, legacy.RequestID)
			if err != nil || len(votes) != 0 {
				t.Fatalf("legacy votes: %+v %v", votes, err)
			}
		})
	}
}

func TestHumanVoteV1AuditResume(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, now := voteChallengeFixture(t, true)
	h := s.Human
	h.Store = db
	h.Auth.now = func() time.Time { return now }
	core := &humanVoteCore{HostedCore: h.Engine.Core, ordinaryFailures: 1}
	h.Engine = &ApprovalEngine{Store: db, Core: core}
	expiry := now.Add(time.Hour)
	row := &store.Request{RequestID: "r-audit-resume", ClientID: "client", Status: store.StatusPending, Commands: []byte(`[{"server":"example","cmd":"true","ttl_seconds":60,"host_key_fp":"SHA256:test"}]`), CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 1}
	if err := db.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	token, err := h.issueVoteChallenge(ctx, legacyVoteBinding(row, "operator"), expiry)
	if err != nil {
		t.Fatal(err)
	}
	path := "/ui/request/" + row.RequestID + "/approve"
	if w := voteHTTP(t, s, path, token.Challenge); w.Code != 500 {
		t.Fatalf("first audit failure: %d %s", w.Code, w.Body)
	}
	current, err := db.GetByID(ctx, row.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	votes, err := db.ListVotes(ctx, row.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != store.StatusPending || len(current.Signatures) != 0 || len(votes) != 0 {
		t.Fatal("failed audit published vote or signatures")
	}
	if len(core.verdicts) != 1 || core.ordinaryFailures != 0 {
		t.Fatal("first POST did not attempt ordinary audit")
	}
	if w := voteHTTP(t, s, path, token.Challenge); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"flipped":true`)) {
		t.Fatalf("audit resume: %d %s", w.Code, w.Body)
	}
	current, err = db.GetByID(ctx, row.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	votes, err = db.ListVotes(ctx, row.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != store.StatusApproved || len(current.Signatures) == 0 || len(votes) != 1 || votes[0].Operator != "operator" || votes[0].Decision != store.DecisionApprove {
		t.Fatalf("retry did not finalize immutable vote: row=%+v votes=%+v", current, votes)
	}
	if len(core.verdicts) != 2 {
		t.Fatalf("audit attempts %d, want 2", len(core.verdicts))
	}
	for _, verdict := range core.verdicts {
		if verdict.Approval != nil || !verdict.Approved || verdict.Operator.ID != "operator" {
			t.Fatalf("audit resume emitted inert or wrong verdict: %+v", verdict)
		}
	}
}
