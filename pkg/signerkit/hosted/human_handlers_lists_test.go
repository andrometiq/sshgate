package hosted

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
)

func listHTTP(s *Server, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: s.Human.Auth.store.(*voteSessionStore).session.ID})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func listJSON(t *testing.T, s *Server, path string) map[string]json.RawMessage {
	t.Helper()
	w := listHTTP(s, path)
	if w.Code != 200 {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func pendingPage(t *testing.T, s *Server, cursor string) ([]map[string]json.RawMessage, string) {
	t.Helper()
	path := "/ui/pending"
	if cursor != "" {
		path += "?v2_cursor=" + url.QueryEscape(cursor)
	}
	out := listJSON(t, s, path)
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(out["v2_pending"], &rows); err != nil {
		t.Fatal(err)
	}
	var next string
	if raw, ok := out["v2_next_cursor"]; ok {
		if err := json.Unmarshal(raw, &next); err != nil {
			t.Fatal(err)
		}
	}
	if string(out["v2_has_more"]) != fmt.Sprint(next != "") {
		t.Fatalf("inconsistent continuation: %s", out)
	}
	for _, row := range rows {
		if _, ok := row["vote_challenge"]; ok {
			t.Fatal("pending must link to a fresh detail view")
		}
	}
	return rows, next
}

func TestUIListsV2PaginationAndCursorGuards(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	ctx := context.Background()
	// Every sort component breaks a tie. Insert in reverse order.
	var want []string
	for client := 1; client >= 0; client-- {
		for sub := 1; sub >= 0; sub-- {
			for id := 26; id >= 1; id-- {
				principal := []string{"client", "other"}[client]
				requester := fmt.Sprintf("local-uid:%d", sub)
				draft := approvalDraft(id)
				if _, err := e.Submit(ctx, principal, requester, draft); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, client := range []string{"client", "other"} {
		for sub := 0; sub < 2; sub++ {
			for id := 1; id <= 26; id++ {
				row, err := db.ReadV2(ctx, sqlitestore.V2Key{ClientID: client, SubPrincipal: fmt.Sprintf("local-uid:%d", sub), RequestID: approvalKey(id).RequestID})
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, row.RecordHandle)
			}
		}
	}
	// Reads show committed slots even while the expiry worker is paused.
	clock.Advance(time.Hour)
	first, cursor := pendingPage(t, s, "")
	if len(first) != 50 || cursor == "" {
		t.Fatalf("first page: %d %q", len(first), cursor)
	}
	originalCursor := cursor
	var got []string
	for _, row := range first {
		var handle string
		json.Unmarshal(row["record_handle"], &handle)
		got = append(got, handle)
	}
	// Resolve an earlier row: offset paging would skip a still-pending item.
	key := sqlitestore.V2Key{ClientID: "client", SubPrincipal: "local-uid:0", RequestID: approvalKey(1).RequestID}
	cancelRow, err := db.ReadV2(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.mutate(ctx, key, ap.AdminCancel{Admin: "operator", PlanHash: cancelRow.Record.Header.PlanHash}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	for cursor != "" {
		rows, next := pendingPage(t, s, cursor)
		if len(rows) > 50 {
			t.Fatal("unbounded page")
		}
		for _, row := range rows {
			var handle string
			json.Unmarshal(row["record_handle"], &handle)
			got = append(got, handle)
		}
		cursor = next
		if len(got) > len(want) {
			t.Fatal("pagination loop")
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered handles mismatch: got %v want %v", got, want)
	}
	fresh, _ := pendingPage(t, s, "")
	if bytes.Equal(fresh[0]["record_handle"], first[0]["record_handle"]) {
		t.Fatal("resolved row still pending")
	}
	token, _ := base64.RawURLEncoding.DecodeString(originalCursor)
	token[len(token)-1] ^= 1
	for _, query := range []string{"", "bad!", "AA", "%ZZ", originalCursor + "%0A", strings.Repeat("x", 4097), base64.RawURLEncoding.EncodeToString(token), originalCursor + "&v2_cursor=" + originalCursor} {
		if w := listHTTP(s, "/ui/pending?v2_cursor="+query); w.Code != 400 {
			t.Fatalf("bad cursor accepted: %d %s", w.Code, w.Body)
		}
	}
	session := &s.Human.Auth.store.(*voteSessionStore).session
	session.ID += "-other"
	if w := listHTTP(s, "/ui/pending?v2_cursor="+originalCursor); w.Code != 400 {
		t.Fatalf("foreign session: %d", w.Code)
	}
	session.ID = strings.TrimSuffix(session.ID, "-other")
	restarted, _, _, _ := voteChallengeFixture(t, false)
	restarted.Human.Store = db
	if w := listHTTP(restarted, "/ui/pending?v2_cursor="+originalCursor); w.Code != 400 {
		t.Fatalf("foreign server: %d", w.Code)
	}
}

func TestUIListsV2AuditShedAndRendering(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	ctx := context.Background()
	draft := approvalDraft(1)
	draft.Rationale = "review ✓ this path"
	draft.CommandJob.Steps[0].ExactCommand = "echo token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	digest := sha256.Sum256([]byte(draft.CommandJob.Steps[0].ExactCommand))
	draft.CommandJob.Steps[0].CommandSHA256 = hex.EncodeToString(digest[:])
	if _, err := e.Submit(ctx, "client", "", draft); err != nil {
		t.Fatal(err)
	}
	before := readApproval(t, db, 1).RecordJSON
	pending := listJSON(t, s, "/ui/pending")
	if bytes.Contains(pending["v2_pending"], []byte("ghp_abcdefghijklmnopqrstuvwxyz1234567890")) {
		t.Fatal("secret exposed")
	}

	if !bytes.Equal(before, readApproval(t, db, 1).RecordJSON) {
		t.Fatal("list changed record")
	}
	row := readApproval(t, db, 1)
	detail := listJSON(t, s, "/ui/v2/request/"+row.RecordHandle)
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(pending["v2_pending"], &items); err != nil || len(items) != 1 {
		t.Fatalf("pending items: %s %v", pending["v2_pending"], err)
	}
	if bytes.Contains(items[0]["rationale_redacted"], []byte("✓")) {
		t.Fatal("unneutralized rationale")
	}
	if !bytes.Equal(items[0]["review"], detail["review"]) || !bytes.Equal(items[0]["rationale_redacted"], detail["rationale_redacted"]) {
		t.Fatal("pending and detail disagree")
	}
	if _, _, err := e.mutate(ctx, approvalKey(1), ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	operator := "reviewer"
	if err := db.CreateUser(ctx, &store.User{ID: operator, Username: operator, Role: "operator", CreatedAt: clock.Wall()}); err != nil {
		t.Fatal(err)
	}
	approvalVote(t, e, db, operator, ap.VoteDeny, ap.VoteFlags{DenyVeto: true})
	row = readApproval(t, db, 1)
	audit := listJSON(t, s, "/ui/audit")
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(audit["v2_entries"], &entries); err != nil || len(entries) != 1 {
		t.Fatalf("audit: %s %v", audit, err)
	}
	votes := append([]ap.Vote(nil), row.Record.Header.Votes...)
	for i := range votes {
		votes[i].Operator = approvalreview.NeutralizeText(votes[i].Operator)
	}
	expected := map[string]any{"record_handle": row.RecordHandle, "sub_principal": "", "decision": ap.ApprovalDenied, "decided_at": row.Record.Header.Decision.DecidedAt, "decided_by": approvalreview.NeutralizeText(operator), "votes": votes, "rationale_redacted": row.Record.Header.RationaleRedacted, "assist_bound": row.Record.Header.Decision.AssistBound}
	for key, value := range expected {
		encoded, _ := json.Marshal(value)
		if !bytes.Equal(entries[0][key], encoded) {
			t.Fatalf("%s: %s want %s", key, entries[0][key], encoded)
		}
	}
	approvalWorkerSink(e)
	if e.flushPass(ctx) {
		t.Fatal("flush")
	}
	clock.Advance(25 * time.Hour)
	if _, _, err := e.mutate(ctx, approvalKey(1), ap.ShedRecord{Pressure: true}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	if !readApproval(t, db, 1).Record.Header.Shed {
		t.Fatal("not shed")
	}
	after := listJSON(t, s, "/ui/audit")
	if !bytes.Equal(audit["v2_entries"], after["v2_entries"]) {
		t.Fatalf("shed changed audit: %s", after)
	}
}

func TestUIListsV2RolesAndV1Fields(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	ctx := context.Background()
	if err := db.CreateUser(ctx, &store.User{ID: "admin", Username: "admin", Role: "admin", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"operator", "admin", "missing"} {
		s.Human.Auth.store.(*voteSessionStore).session.UserID = role
		for _, path := range []string{"/ui/pending", "/ui/audit"} {
			w := listHTTP(s, path)
			if role == "missing" {
				if w.Code != 403 {
					t.Fatalf("missing role: %d %s", w.Code, w.Body)
				}
				continue
			}
			if w.Code != 200 {
				t.Fatalf("%s read: %d %s", role, w.Code, w.Body)
			}
			out := listJSON(t, s, path)
			if path == "/ui/pending" {
				if string(out["pending"]) != "[]" || string(out["has_more"]) != "false" || out["next_offset"] != nil || string(out["v2_pending"]) != "[]" {
					t.Fatalf("legacy pending changed: %s", out)
				}
			} else if string(out["entries"]) != "[]" || string(out["v2_entries"]) != "[]" {
				t.Fatalf("legacy audit changed: %s", out)
			}
		}
	}
	// Bearer auth is never a UI session.
	r := httptest.NewRequest("GET", "/ui/pending", nil)
	r.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("machine read UI: %d", w.Code)
	}
}

func TestUIListsV2AuditLimitAndV1Pagination(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	ctx := context.Background()
	for id := 1; id <= 102; id++ {
		draft := approvalDraftAt(id, clock.Wall())
		if _, err := e.Submit(ctx, "client", "", draft); err != nil {
			t.Fatal(err)
		}
		row := readApproval(t, db, id)
		if _, _, err := e.mutate(ctx, row.Key, ap.AdminCancel{Admin: "admin", PlanHash: row.Record.Header.PlanHash}, ap.Inputs{}); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)
	}
	audit := listJSON(t, s, "/ui/audit")
	var entries []struct {
		RecordHandle string `json:"record_handle"`
	}
	if err := json.Unmarshal(audit["v2_entries"], &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 100 || entries[0].RecordHandle != readApproval(t, db, 102).RecordHandle || entries[99].RecordHandle != readApproval(t, db, 3).RecordHandle {
		t.Fatalf("audit not newest 100: %+v", entries)
	}
	for id := 1; id <= 51; id++ {
		if err := db.Insert(ctx, &store.Request{RequestID: fmt.Sprintf("r-%03d", id), Status: store.StatusPending, ClientID: "client", Commands: []byte(`[{"server":"web","cmd":"true","ttl_seconds":60}]`), CreatedAt: clock.Wall().Add(time.Duration(id) * time.Second), RequiredApprovals: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// A v1-only store facade gives the old path's exact fields for comparison.
	facade := struct{ store.Store }{db}
	for _, path := range []string{"/ui/pending", "/ui/pending?offset=50", "/ui/audit"} {
		s.Human.Store = facade
		legacy := listJSON(t, s, path)
		s.Human.Store = db
		mixed := listJSON(t, s, path)
		for _, key := range []string{"pending", "has_more", "next_offset", "entries"} {
			if !bytes.Equal(legacy[key], mixed[key]) {
				t.Fatalf("%s field %s changed: %s != %s", path, key, legacy[key], mixed[key])
			}
		}
	}
}

type listRoleStore struct {
	*sqlitestore.DB
	user *store.User
	err  error
}

func (s listRoleStore) GetUser(context.Context, string) (*store.User, error) { return s.user, s.err }

func TestUIListsV2RoleErrors(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	for _, test := range []struct {
		name   string
		user   *store.User
		err    error
		status int
	}{
		{"unknown", &store.User{Role: "auditor"}, nil, 403},
		{"nil", nil, nil, 403},
		{"missing", nil, store.ErrNotFound, 403},
		{"busy", nil, approvalBusy(5), 503},
		{"broken", nil, fmt.Errorf("broken"), 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			s.Human.Store = listRoleStore{DB: db, user: test.user, err: test.err}
			for _, path := range []string{"/ui/pending", "/ui/audit"} {
				if w := listHTTP(s, path); w.Code != test.status {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body)
				}
			}
		})
	}
}

func TestUIListsV2AuthenticatedMalformedCursor(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	block, err := aes.NewCipher(s.Human.voteMACKey[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("sshgate-ui-pending-v2\x00" + ap.SessionBinding(s.Human.Auth.store.(*voteSessionStore).session.ID))
	for _, data := range []string{
		`{`, `{}`, `{"CreatedAt":"2026-01-01T00:00:00Z","Key":{"ClientID":"client","RequestID":"bad"}}`,
		fmt.Sprintf(`{"CreatedAt":"2026-01-01T00:00:00Z","Key":{"ClientID":"client","RequestID":%q},"padding":%q}`, approvalKey(1).RequestID, strings.Repeat("x", 4096)),
	} {
		nonce := make([]byte, aead.NonceSize())
		token := base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(data), binding))
		if w := listHTTP(s, "/ui/pending?v2_cursor="+token); w.Code != 400 {
			t.Fatalf("invalid authenticated cursor: %d %s", w.Code, w.Body)
		}
	}
}

type listReadStore struct {
	*sqlitestore.DB
	rows []*sqlitestore.V2Row
	err  error
}

func (s listReadStore) ListPendingV2(context.Context, *sqlitestore.V2PendingCursor, int) ([]*sqlitestore.V2Row, error) {
	return s.rows, s.err
}
func (s listReadStore) RecentDecidedV2(context.Context, int) ([]*sqlitestore.V2Row, error) {
	return s.rows, s.err
}

func TestUIListsV2ReadFailures(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	for _, test := range []struct {
		err    error
		status int
	}{{approvalBusy(5), 503}, {fmt.Errorf("broken"), 500}} {
		s.Human.Store = listReadStore{DB: db, err: test.err}
		for _, path := range []string{"/ui/pending", "/ui/audit"} {
			if w := listHTTP(s, path); w.Code != test.status {
				t.Fatalf("%s: %d %s", path, w.Code, w.Body)
			}
		}
	}
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	row.Record.Payload.ReviewSnapshot = []byte(`{`)
	s.Human.Store = listReadStore{DB: db, rows: []*sqlitestore.V2Row{row}}
	for _, path := range []string{"/ui/pending", "/ui/audit"} {
		if w := listHTTP(s, path); w.Code != 500 {
			t.Fatalf("corrupt %s: %d %s", path, w.Code, w.Body)
		}
	}
}

func TestUIListsV2NeutralizesAuditMetadata(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	s, _, _, _ := voteChallengeFixture(t, false)
	submitApproval(t, e, 1)
	row := readApproval(t, db, 1)
	if _, _, err := e.mutate(context.Background(), row.Key, ap.AdminCancel{Admin: "admin", PlanHash: row.Record.Header.PlanHash}, ap.Inputs{}); err != nil {
		t.Fatal(err)
	}
	row = readApproval(t, db, 1)
	row.Record.Header.Decision.DecidedBy = "reviewer✓"
	row.Record.Header.Votes = []ap.Vote{{Operator: "reviewer✓", Decision: ap.VoteDeny, Authn: "session", TS: row.Record.Header.CreatedAt}}
	s.Human.Store = listReadStore{DB: db, rows: []*sqlitestore.V2Row{row}}
	out := listJSON(t, s, "/ui/audit")
	if bytes.Contains(out["v2_entries"], []byte("✓")) || !bytes.Contains(out["v2_entries"], []byte(`reviewer\\u{2713}`)) {
		t.Fatalf("audit metadata not neutralized: %s", out["v2_entries"])
	}
}
