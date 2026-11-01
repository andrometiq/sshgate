package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
)

type voteSessionStore struct {
	store.Store
	session store.Session
}

func (s *voteSessionStore) GetSession(_ context.Context, id string) (*store.Session, error) {
	if id != s.session.ID {
		return nil, store.ErrNotFound
	}
	copy := s.session
	return &copy, nil
}

func voteChallengeFixture(t *testing.T, highLevel bool) (*Server, context.Context, ap.ChallengeBinding, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := &voteSessionStore{session: store.Session{ID: "secret-session-id", UserID: "operator", ExpiresAt: now.Add(time.Hour)}}
	auth := AuthConfig{RPID: "localhost", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Hour}
	var s *Server
	if highLevel {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		core, err := signerkit.New(signerkit.Config{Signer: key, Audit: signerkit.NewAppendOnlySink(io.Discard)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { core.Close() })
		s, err = New(Config{Core: core, Store: st, APIKey: "test-key", MachineClientID: "client", RequiredApprovals: 1, Auth: auth})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		s = NewServer("test-key", st, nil)
		s.MachineClientID = "client"
		am, err := NewAuthManager(st, auth)
		if err != nil {
			t.Fatal(err)
		}
		s.AttachHuman(&HumanAPI{Auth: am, Store: st})
	}
	t.Cleanup(func() { s.Close() })
	var ctx context.Context
	handler := s.Human.withSession(func(w http.ResponseWriter, r *http.Request, user string) {
		if user != st.session.UserID {
			t.Fatalf("operator = %q", user)
		}
		ctx = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "https://localhost/ui/pending", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: st.session.ID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent || ctx == nil {
		t.Fatal("session middleware did not dispatch")
	}
	session, ok := ctx.Value(voteSessionContextKey{}).(voteSession)
	if !ok || session.ID != st.session.ID || !session.ExpiresAt.Equal(st.session.ExpiresAt) {
		t.Fatalf("session context = %+v", session)
	}
	for _, cookie := range []string{"", "wrong-session"} {
		req := httptest.NewRequest("GET", "https://localhost/ui/pending", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		s.Human.withSession(func(http.ResponseWriter, *http.Request, string) { t.Fatal("unauthenticated dispatch") }).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated status = %d", rec.Code)
		}
	}
	return s, ctx, ap.ChallengeBinding{Plane: ap.PlaneV2, RecordKey: "record", PlanHash: "plan", Operator: "operator", AssistRevision: 1, AssistDigest: "digest", AllowedActions: []string{ap.ActionApprove, ap.ActionDeny}}, now
}

func TestVoteChallengeConstructionAndSession(t *testing.T) {
	for _, highLevel := range []bool{false, true} {
		s, ctx, binding, now := voteChallengeFixture(t, highLevel)
		other := NewServer("test-key", nil, nil)
		if s.voteMACKey == ([32]byte{}) || other.voteMACKey == ([32]byte{}) || s.voteMACKey == other.voteMACKey {
			t.Fatal("keys must be fresh and nonzero")
		}
		if s.Human.voteMACKey != &s.voteMACKey {
			t.Fatal("human plane does not use server key")
		}
		challenge, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if challenge.ExpiresAt != now.Add(time.Hour).Unix() {
			t.Fatal("expiry exceeds session")
		}
		if reason := s.Human.verifyVoteChallenge(ctx, binding, challenge.Challenge, now); reason != "" {
			t.Fatal(reason)
		}
		data, _ := json.Marshal(challenge)
		if bytes.Contains(data, []byte("secret-session-id")) || bytes.Contains(data, []byte("session_binding")) || bytes.Contains(data, s.voteMACKey[:]) {
			t.Fatal("challenge exposed session or key")
		}
		other.MachineClientID = "client"
		other.AttachHuman(&HumanAPI{})
		if got := other.Human.verifyVoteChallenge(ctx, binding, challenge.Challenge, now); got != "stale_challenge" {
			t.Fatalf("restart: %q", got)
		}
	}
}

func TestVoteChallengeBindings(t *testing.T) {
	s, ctx, binding, now := voteChallengeFixture(t, false)
	for _, plane := range []string{ap.PlaneV1, ap.PlaneV2} {
		t.Run(plane, func(t *testing.T) {
			binding.Plane = plane
			challenge, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			changes := map[string]func(*ap.ChallengeBinding){
				"plane":    func(b *ap.ChallengeBinding) { b.Plane += "other" },
				"record":   func(b *ap.ChallengeBinding) { b.RecordKey += "other" },
				"plan":     func(b *ap.ChallengeBinding) { b.PlanHash += "other" },
				"operator": func(b *ap.ChallengeBinding) { b.Operator += "other" },
				"revision": func(b *ap.ChallengeBinding) { b.AssistRevision++ },
				"digest":   func(b *ap.ChallengeBinding) { b.AssistDigest += "other" },
				"actions":  func(b *ap.ChallengeBinding) { b.AllowedActions = []string{ap.ActionDeny} },
			}
			for name, change := range changes {
				t.Run(name, func(t *testing.T) {
					altered := binding
					change(&altered)
					if got := s.Human.verifyVoteChallenge(ctx, altered, challenge.Challenge, now); got != "stale_challenge" {
						t.Fatalf("changed binding: %q", got)
					}
				})
			}
			other := context.WithValue(ctx, voteSessionContextKey{}, voteSession{ID: "new-login-same-operator", ExpiresAt: now.Add(time.Hour)})
			if got := s.Human.verifyVoteChallenge(other, binding, challenge.Challenge, now); got != "stale_challenge" {
				t.Fatalf("other session: %q", got)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(challenge.Challenge)
			for i := range raw {
				altered := bytes.Clone(raw)
				altered[i] ^= 1
				if got := s.Human.verifyVoteChallenge(ctx, binding, base64.RawURLEncoding.EncodeToString(altered), now); got != "stale_challenge" {
					t.Fatalf("byte %d: %q", i, got)
				}
			}
			for _, delta := range []time.Duration{-time.Hour, 59 * time.Second, time.Minute, 2 * time.Minute} {
				want := ""
				if delta >= time.Minute {
					want = "expired_challenge"
				}
				if got := s.Human.verifyVoteChallenge(ctx, binding, challenge.Challenge, now.Add(delta)); got != want {
					t.Fatalf("time %s: %q want %q", delta, got, want)
				}
			}
			shorter := context.WithValue(ctx, voteSessionContextKey{}, voteSession{ID: "secret-session-id", ExpiresAt: now.Add(30 * time.Second)})
			if got := s.Human.verifyVoteChallenge(shorter, binding, challenge.Challenge, now); got != "stale_challenge" {
				t.Fatalf("session cap: %q", got)
			}
		})
	}
}

func TestVoteChallengeMalformedAndMissingContext(t *testing.T) {
	s, ctx, binding, now := voteChallengeFixture(t, false)
	challenge, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if len(raw) != 56 || int64(binary.BigEndian.Uint64(raw[16:24])) != challenge.ExpiresAt {
		t.Fatal("token layout")
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	noncanonical := challenge.Challenge[:74] + string(alphabet[strings.IndexByte(alphabet, challenge.Challenge[74])|1])
	for _, token := range []string{"", "x", strings.Repeat("!", 75), noncanonical, challenge.Challenge + "=", challenge.Challenge + "\n", base64.RawURLEncoding.EncodeToString(raw[:55])} {
		if got := s.Human.verifyVoteChallenge(ctx, binding, token, now); got != "stale_challenge" {
			t.Fatalf("malformed: %q", got)
		}
	}
	for _, session := range []any{nil, voteSession{}, voteSession{ID: "id"}, voteSession{ExpiresAt: now}} {
		empty := context.Background()
		if session != nil {
			empty = context.WithValue(empty, voteSessionContextKey{}, session)
		}
		if _, err := s.Human.issueVoteChallenge(empty, binding, now); err == nil {
			t.Fatal("issued without session")
		}
		if got := s.Human.verifyVoteChallenge(empty, binding, challenge.Challenge, now); got != "stale_challenge" {
			t.Fatal("verified without session")
		}
	}
	unattached := &HumanAPI{}
	if _, err := unattached.issueVoteChallenge(ctx, binding, now); err == nil {
		t.Fatal("issued without key")
	}
	if got := unattached.verifyVoteChallenge(ctx, binding, challenge.Challenge, now); got != "stale_challenge" {
		t.Fatal("verified without key")
	}
}

func TestVoteChallengeConcurrentNonces(t *testing.T) {
	s, ctx, binding, now := voteChallengeFixture(t, false)
	results := make(chan string, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			c, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(time.Minute))
			if err != nil {
				t.Error(err)
				return
			}
			if got := s.Human.verifyVoteChallenge(ctx, binding, c.Challenge, now); got != "" {
				t.Error(got)
			}
			results <- c.Challenge
		})
	}
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for token := range results {
		if seen[token] {
			t.Fatal("nonce reused")
		}
		seen[token] = true
	}
	if len(seen) != 32 {
		t.Fatal("missing challenge")
	}
}

type uiV2DetailResponse struct {
	RecordHandle  string               `json:"record_handle"`
	SubPrincipal  string               `json:"sub_principal"`
	Review        *approvalreview.View `json:"review"`
	VoteChallenge voteChallenge        `json:"vote_challenge"`
	Reason        string               `json:"rationale_redacted"`
	Pruned        bool                 `json:"pruned"`
	Details       string               `json:"details"`
}

// ServeHTTP with recorders keeps the route tests independent of socket access.
func TestUIV2DetailByHandle(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	session := voteSession{ID: "secret-session-id", ExpiresAt: clock.Wall().Add(time.Hour)}
	s.Human.Auth.store.(*voteSessionStore).session.ExpiresAt = session.ExpiresAt
	ctx = context.WithValue(ctx, voteSessionContextKey{}, session)
	draft := approvalDraft(610)
	draft.Rationale = "Check ✓ result"
	for _, sub := range []string{"local-uid:1001", "local-uid:1002"} {
		if _, err := e.Submit(ctx, "client", sub, draft); err != nil {
			t.Fatal(err)
		}
	}
	for _, sub := range []string{"local-uid:1001", "local-uid:1002"} {
		key := sqlitestore.V2Key{ClientID: "client", SubPrincipal: sub, RequestID: draft.RequestID}
		before, err := db.ReadV2(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		get := func() uiV2DetailResponse {
			req := httptest.NewRequest("GET", "/ui/v2/request/"+before.RecordHandle, nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
			res := httptest.NewRecorder()
			s.ServeHTTP(res, req)
			if res.Code != 200 {
				t.Fatalf("detail: %d %s", res.Code, res.Body)
			}
			var out uiV2DetailResponse
			if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.RecordHandle != before.RecordHandle || out.SubPrincipal != sub || out.Review == nil || out.Review.PlanHash != before.Record.Header.PlanHash {
				t.Fatalf("wrong view: %+v", out)
			}
			if out.Reason != out.Review.Reason || strings.Contains(out.Reason, "✓") {
				t.Fatal("reason differs from shared renderer", out.Reason, out.Review.Reason)
			}
			if strings.Contains(res.Body.String(), "secret-session-id") || strings.Contains(res.Body.String(), "claim_token_hash") {
				t.Fatal("private state exposed")
			}
			return out
		}
		out := get()
		binding := ap.ChallengeBinding{Plane: ap.PlaneV2, RecordKey: ap.HostedRecordKey("client", sub, draft.RequestID), PlanHash: before.Record.Header.PlanHash, Operator: "operator", AllowedActions: []string{ap.ActionDeny}}
		if reason := s.Human.verifyVoteChallenge(ctx, binding, out.VoteChallenge.Challenge, clock.Wall()); reason != "" {
			t.Fatal(reason)
		}
		if !reflect.DeepEqual(out.VoteChallenge.AllowedActions, []string{ap.ActionDeny}) {
			t.Fatal("preparing permits approval")
		}
		other := binding
		other.RecordKey = ap.HostedRecordKey("client", "other", draft.RequestID)
		if s.Human.verifyVoteChallenge(ctx, other, out.VoteChallenge.Challenge, clock.Wall()) != "stale_challenge" {
			t.Fatal("challenge crossed records")
		}
		clock.Advance(10 * time.Second)
		// An overdue assist remains preparing until the worker commits Clock.
		again := get()
		if again.VoteChallenge.AssistRevision != 0 || !reflect.DeepEqual(again.VoteChallenge.AllowedActions, []string{ap.ActionDeny}) {
			t.Fatal("GET advanced assist")
		}
		after, err := db.ReadV2(ctx, key)
		if err != nil || !bytes.Equal(before.RecordJSON, after.RecordJSON) {
			t.Fatal("GET wrote state", err)
		}
		if _, _, err := e.mutate(ctx, key, ap.Tick{}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
		terminal := get()
		row, err := db.ReadV2(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		binding.AssistRevision, binding.AssistDigest = 1, row.Record.Header.Assist.Digest
		binding.AllowedActions = []string{ap.ActionApprove, ap.ActionDeny}
		if terminal.VoteChallenge.AssistRevision != 1 || !reflect.DeepEqual(terminal.VoteChallenge.AllowedActions, binding.AllowedActions) {
			t.Fatal("terminal assist did not enable approval")
		}
		if reason := s.Human.verifyVoteChallenge(ctx, binding, terminal.VoteChallenge.Challenge, clock.Wall()); reason != "" {
			t.Fatal(reason)
		}
		if s.Human.verifyVoteChallenge(ctx, binding, out.VoteChallenge.Challenge, clock.Wall()) != "stale_challenge" {
			t.Fatal("old revision still valid")
		}

	}
	for _, path := range []string{"/ui/request/" + draft.RequestID, "/ui/v2/request/" + draft.RequestID} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
		res := httptest.NewRecorder()
		s.ServeHTTP(res, req)
		if res.Code != 404 {
			t.Fatalf("ID route: %d %s", res.Code, res.Body)
		}
	}
}

type uiHandleErrorStore struct {
	store.Store
	err error
}

func (s uiHandleErrorStore) ByHandleV2(context.Context, string) (*sqlitestore.V2Row, error) {
	return nil, s.err
}

func TestUIV2HandleGuards(t *testing.T) {
	s, _, _, _ := voteChallengeFixture(t, false)
	for _, tc := range []struct {
		err     error
		status  int
		message string
	}{
		{store.ErrNotFound, 404, "unknown handle"},
		{sqlitestore.ErrV2AmbiguousHandle, 409, "ambiguous handle"},
		{errors.New("private database error"), 500, "get request"},
	} {
		s.Human.Store = uiHandleErrorStore{err: tc.err}
		for _, route := range []struct{ method, suffix string }{{"GET", ""}, {"POST", "/approve"}, {"POST", "/deny"}} {
			req := httptest.NewRequest(route.method, "https://localhost/ui/v2/request/handle"+route.suffix, nil)
			req.Header.Set("Origin", "https://localhost")
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
			res := httptest.NewRecorder()
			s.ServeHTTP(res, req)
			if res.Code != tc.status || !strings.Contains(res.Body.String(), tc.message) {
				t.Fatalf("%s: %d %s", route.suffix, res.Code, res.Body)
			}
			req.Header.Del("Cookie")
			res = httptest.NewRecorder()
			s.ServeHTTP(res, req)
			if res.Code != 401 {
				t.Fatal("route bypassed session", res.Code)
			}
		}
	}
}

type uiHandleRowStore struct {
	store.Store
	row *sqlitestore.V2Row
}

func (s uiHandleRowStore) ByHandleV2(context.Context, string) (*sqlitestore.V2Row, error) {
	return s.row, nil
}

func TestUIV2DetailFailureAndTerminalViews(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	submitApproval(t, e, 611)
	row := readApproval(t, db, 611)
	s, _, _, _ := voteChallengeFixture(t, false)
	get := func(method, suffix string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "https://localhost/ui/v2/request/"+row.RecordHandle+suffix, nil)
		req.Header.Set("Origin", "https://localhost")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
		res := httptest.NewRecorder()
		s.ServeHTTP(res, req)
		return res
	}
	s.Human.Store = &voteSessionStore{}
	if res := get("GET", ""); res.Code != 503 {
		t.Fatal("missing backend", res.Code)
	}
	s.Human.Store = uiHandleRowStore{row: row}
	for _, suffix := range []string{"/approve", "/deny"} {
		if res := get("POST", suffix); res.Code != 503 {
			t.Fatal("vote must fail closed until transaction is attached", res.Code)
		}
		req := httptest.NewRequest("POST", "https://localhost/ui/v2/request/"+row.RecordHandle+suffix, nil)
		req.Header.Set("Origin", "https://untrusted.invalid")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
		res := httptest.NewRecorder()
		s.ServeHTTP(res, req)
		if res.Code != 403 {
			t.Fatal("cross-origin vote accepted", res.Code)
		}
	}
	raw := row.Record.Payload.ReviewSnapshot
	row.Record.Payload.ReviewSnapshot = []byte(`{}`)
	if res := get("GET", ""); res.Code != 500 {
		t.Fatal("bad snapshot", res.Code)
	}
	row.Record.Payload.ReviewSnapshot = raw
	row.Record.Header.Assist = &ap.AssistSlot{State: ap.AssistReady, Digest: "digest"}
	if res := get("GET", ""); res.Code != 500 {
		t.Fatal("missing ready result", res.Code)
	}
	row.Record.Header.Assist = nil
	key := s.Human.voteMACKey
	s.Human.voteMACKey = nil
	if res := get("GET", ""); res.Code != 500 {
		t.Fatal("missing challenge key", res.Code)
	}
	s.Human.voteMACKey = key
	row.Record.Header.Assist = &ap.AssistSlot{State: ap.AssistUnavailable, Reason: "deadline", Digest: "digest"}
	row.Record.Header.Shed = true
	row.Record.Header.Decision = &ap.Decision{Status: ap.ApprovalDenied}
	row.Record.Payload = nil
	res := get("GET", "")
	if res.Code != 200 {
		t.Fatalf("shed detail: %d %s", res.Code, res.Body)
	}
	var out uiV2DetailResponse
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Pruned || out.Details != "details pruned" || out.Review != nil || len(out.VoteChallenge.AllowedActions) != 0 {
		t.Fatalf("shed view: %+v", out)
	}
}

func TestUIV2DetailUnderWriterLock(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, true)
	submitApproval(t, e, 612)
	row := readApproval(t, db, 612)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	req := httptest.NewRequest("GET", "/ui/v2/request/"+row.RecordHandle, nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-session-id"})
	res := httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != 200 {
		t.Fatalf("WAL read under writer lock: %d %s", res.Code, res.Body)
	}
	var out uiV2DetailResponse
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil || out.VoteChallenge.Challenge == "" {
		t.Fatalf("challenge missing: %v %s", err, res.Body)
	}
}
