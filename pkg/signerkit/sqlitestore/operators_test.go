package sqlitestore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// --- migration runner ---

// TestMigrations_AppliedAndIdempotent proves the runner records every
// migration once and that re-Opening the same DB applies nothing (a
// no-op): the schema_migrations row set is identical before and after a
// second Open, and the second Open does not error.
func TestMigrations_AppliedAndIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "migrate.db")

	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	before := readMigrationVersions(t, path)
	if len(before) < 2 {
		t.Fatalf("expected >=2 migrations recorded, got %v", before)
	}
	// Versions must be the contiguous 1..N with no gaps/dupes.
	for i, v := range before {
		if v != i+1 {
			t.Fatalf("migration versions = %v; want contiguous from 1", before)
		}
	}
	_ = db.Close()

	// Re-open: must succeed and not add/duplicate any migration rows.
	db2, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("second Open (idempotent re-run): %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	after := readMigrationVersions(t, path)
	if len(after) != len(before) {
		t.Fatalf("re-Open changed migration count: before %v, after %v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("re-Open changed migration set: before %v, after %v", before, after)
		}
	}

	// And the pre-existing requests CRUD still works after the second
	// Open — proving migrations did not disturb existing data paths.
	ctx := context.Background()
	r := &store.Request{RequestID: "r_after", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`)}
	if err := db2.Insert(ctx, r); err != nil {
		t.Fatalf("Insert after re-Open: %v", err)
	}
	if _, err := db2.GetByID(ctx, "r_after"); err != nil {
		t.Fatalf("GetByID after re-Open: %v", err)
	}
}

// TestMigrations_DataSurvivesReopen proves rows written before a re-Open
// are still present after — the runner is additive, never drop+recreate.
func TestMigrations_DataSurvivesReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "survive.db")
	ctx := context.Background()

	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Insert(ctx, &store.Request{
		RequestID: "r_keep", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	_ = db.Close()

	db2, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	got, err := db2.GetByID(ctx, "r_keep")
	if err != nil {
		t.Fatalf("GetByID after re-Open: %v", err)
	}
	if got.RequestID != "r_keep" {
		t.Fatalf("row lost across re-Open")
	}
}

// readMigrationVersions reads schema_migrations directly via a second
// connection, returning the recorded versions in ascending order.
func readMigrationVersions(t *testing.T, path string) []int {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT version FROM schema_migrations ORDER BY version ASC`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, v)
	}
	return out
}

// --- required_approvals column ---

func TestRequiredApprovals_DefaultAndSet(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()

	// Default: a Request with RequiredApprovals unset stores 1.
	if err := db.Insert(ctx, &store.Request{
		RequestID: "r_n", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := db.GetByID(ctx, "r_n")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.RequiredApprovals != 1 {
		t.Fatalf("default RequiredApprovals = %d; want 1", got.RequiredApprovals)
	}

	// Explicit set on insert.
	if err := db.Insert(ctx, &store.Request{
		RequestID: "r_n3", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`), RequiredApprovals: 3,
	}); err != nil {
		t.Fatalf("Insert n=3: %v", err)
	}
	got3, _ := db.GetByID(ctx, "r_n3")
	if got3.RequiredApprovals != 3 {
		t.Fatalf("RequiredApprovals = %d; want 3", got3.RequiredApprovals)
	}

	// SetRequiredApprovals updates a pending row.
	if err := db.SetRequiredApprovals(ctx, "r_n", 2); err != nil {
		t.Fatalf("SetRequiredApprovals: %v", err)
	}
	got2, _ := db.GetByID(ctx, "r_n")
	if got2.RequiredApprovals != 2 {
		t.Fatalf("after Set: RequiredApprovals = %d; want 2", got2.RequiredApprovals)
	}

	// SetRequiredApprovals on a missing row -> ErrNotFound.
	if err := db.SetRequiredApprovals(ctx, "nope", 5); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetRequiredApprovals(missing) = %v; want ErrNotFound", err)
	}
}

// --- users ---

func TestUsers_CRUD(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()

	u := &store.User{ID: "u1", Username: "alice", Role: "admin"}
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.CreatedAt.IsZero() {
		t.Fatalf("CreateUser did not stamp CreatedAt")
	}

	byID, err := db.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if byID.Username != "alice" || byID.Role != "admin" {
		t.Fatalf("GetUser = %+v; want alice/admin", byID)
	}

	byName, err := db.GetUserByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByName: %v", err)
	}
	if byName.ID != "u1" {
		t.Fatalf("GetUserByName id = %q; want u1", byName.ID)
	}

	// Duplicate id -> ErrDuplicate.
	if err := db.CreateUser(ctx, &store.User{ID: "u1", Username: "other", Role: "operator"}); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("dup id = %v; want ErrDuplicate", err)
	}
	// Duplicate username -> ErrDuplicate.
	if err := db.CreateUser(ctx, &store.User{ID: "u2", Username: "alice", Role: "operator"}); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("dup username = %v; want ErrDuplicate", err)
	}

	// Missing -> ErrNotFound.
	if _, err := db.GetUser(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUser(missing) = %v; want ErrNotFound", err)
	}
	if _, err := db.GetUserByName(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUserByName(missing) = %v; want ErrNotFound", err)
	}
}

// --- webauthn credentials ---

func TestCredentials_CRUD(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	mustUser(t, db, "u1", "alice")

	c1 := &store.Credential{UserID: "u1", CredentialID: []byte("cred-id-1"), Blob: []byte("blob-1")}
	if err := db.AddCredential(ctx, c1); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	if c1.ID == 0 {
		t.Fatalf("AddCredential did not populate rowid")
	}
	c2 := &store.Credential{UserID: "u1", CredentialID: []byte("cred-id-2"), Blob: []byte("blob-2")}
	if err := db.AddCredential(ctx, c2); err != nil {
		t.Fatalf("AddCredential 2: %v", err)
	}

	creds, err := db.ListCredentials(ctx, "u1")
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("ListCredentials len = %d; want 2", len(creds))
	}
	if string(creds[0].CredentialID) != "cred-id-1" || string(creds[0].Blob) != "blob-1" {
		t.Fatalf("ListCredentials[0] = %+v; want cred-id-1/blob-1", creds[0])
	}

	// Duplicate credential_id -> ErrDuplicate.
	dup := &store.Credential{UserID: "u1", CredentialID: []byte("cred-id-1"), Blob: []byte("blob-x")}
	if err := db.AddCredential(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("dup credential_id = %v; want ErrDuplicate", err)
	}

	// A user with no credentials gets an empty (non-error) slice.
	mustUser(t, db, "u2", "bob")
	empty, err := db.ListCredentials(ctx, "u2")
	if err != nil {
		t.Fatalf("ListCredentials(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListCredentials(empty) len = %d; want 0", len(empty))
	}
}

// --- totp ---

func TestTOTP_SetGetReplace(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	mustUser(t, db, "u1", "alice")

	if _, err := db.GetTOTP(ctx, "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetTOTP(unset) = %v; want ErrNotFound", err)
	}
	if err := db.SetTOTP(ctx, "u1", "SECRET1"); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	got, err := db.GetTOTP(ctx, "u1")
	if err != nil || got != "SECRET1" {
		t.Fatalf("GetTOTP = %q,%v; want SECRET1", got, err)
	}
	// Replace (one secret per user).
	if err := db.SetTOTP(ctx, "u1", "SECRET2"); err != nil {
		t.Fatalf("SetTOTP replace: %v", err)
	}
	got2, _ := db.GetTOTP(ctx, "u1")
	if got2 != "SECRET2" {
		t.Fatalf("GetTOTP after replace = %q; want SECRET2", got2)
	}

	consumed, err := db.ConsumeTOTPStep(ctx, "u1", "SECRET2", 100)
	if err != nil || !consumed {
		t.Fatalf("ConsumeTOTPStep(first) = %v,%v; want true,nil", consumed, err)
	}
	for name, step := range map[string]int64{"same": 100, "older": 99} {
		if consumed, err := db.ConsumeTOTPStep(ctx, "u1", "SECRET2", step); err != nil || consumed {
			t.Fatalf("ConsumeTOTPStep(%s) = %v,%v; want false,nil", name, consumed, err)
		}
	}
	if consumed, err := db.ConsumeTOTPStep(ctx, "u1", "SECRET1", 101); err != nil || consumed {
		t.Fatalf("ConsumeTOTPStep(rotated secret) = %v,%v; want false,nil", consumed, err)
	}

	// Rotation resets only the new factor's watermark. Concurrent consumers of
	// one timestep still have exactly one winner.
	if err := db.SetTOTP(ctx, "u1", "SECRET3"); err != nil {
		t.Fatal(err)
	}
	const contenders = 16
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := db.ConsumeTOTPStep(ctx, "u1", "SECRET3", 100)
			if err != nil {
				t.Errorf("ConsumeTOTPStep(concurrent): %v", err)
				return
			}
			if ok {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("concurrent TOTP consumers won=%d; want 1", got)
	}
}

// --- sessions ---

func TestSessions_LifecycleAndExpiry(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	mustUser(t, db, "u1", "alice")

	live := &store.Session{ID: "s_live", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.CreateSession(ctx, live); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := db.GetSession(ctx, "s_live")
	if err != nil {
		t.Fatalf("GetSession(live): %v", err)
	}
	if got.UserID != "u1" {
		t.Fatalf("GetSession user = %q; want u1", got.UserID)
	}

	// Duplicate id -> ErrDuplicate.
	if err := db.CreateSession(ctx, &store.Session{ID: "s_live", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("dup session = %v; want ErrDuplicate", err)
	}

	// Expired session reads back as ErrNotFound.
	expired := &store.Session{ID: "s_old", UserID: "u1", CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)}
	if err := db.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession(expired): %v", err)
	}
	if _, err := db.GetSession(ctx, "s_old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSession(expired) = %v; want ErrNotFound", err)
	}

	// Issuing another session sweeps expired rows. Reusing the expired ID
	// succeeds only if the old physical row was removed before insert.
	if err := db.CreateSession(ctx, &store.Session{ID: "s_old", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateSession(reuse expired id after sweep): %v", err)
	}
	if _, err := db.GetSession(ctx, "s_old"); err != nil {
		t.Fatalf("GetSession(reissued id): %v", err)
	}

	// Revoke removes the live session; subsequent get is ErrNotFound.
	if err := db.RevokeSession(ctx, "s_live"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := db.GetSession(ctx, "s_live"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSession(revoked) = %v; want ErrNotFound", err)
	}
	// Revoking a missing session is a no-op.
	if err := db.RevokeSession(ctx, "ghost"); err != nil {
		t.Fatalf("RevokeSession(missing) = %v; want nil", err)
	}

	// Missing -> ErrNotFound.
	if _, err := db.GetSession(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSession(missing) = %v; want ErrNotFound", err)
	}
}

// --- approvals (append-only vote ledger) ---

func TestApprovals_AppendOnlyOnePerOperator(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Insert(ctx, &store.Request{RequestID: "r1", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`)}); err != nil {
		t.Fatalf("seed request: %v", err)
	}

	v1 := &store.Vote{RequestID: "r1", Operator: "alice", Decision: store.DecisionApprove, AuthnMethod: "webauthn"}
	canonical, needsAudit, err := db.PrepareVote(ctx, v1)
	if err != nil || !needsAudit || canonical.Decision != store.DecisionApprove {
		t.Fatalf("PrepareVote = (%+v,%v,%v); want approve/needs-audit", canonical, needsAudit, err)
	}
	// Prepared votes are invisible until the external audit phase completes.
	if got, _ := db.ListVotes(ctx, "r1"); len(got) != 0 {
		t.Fatalf("unaudited vote became visible: %+v", got)
	}
	if err := db.MarkVoteAudited(ctx, "r1", "alice"); err != nil {
		t.Fatalf("MarkVoteAudited: %v", err)
	}
	// A second vote from the SAME operator on the SAME request is
	// rejected as a duplicate (append-only, one-per-operator); the
	// original is NOT mutated.
	v1b := &store.Vote{RequestID: "r1", Operator: "alice", Decision: store.DecisionDeny, AuthnMethod: "totp"}
	if _, _, err := db.PrepareVote(ctx, v1b); !errors.Is(err, store.ErrVoteConflict) {
		t.Fatalf("opposite duplicate vote = %v; want ErrVoteConflict", err)
	}

	// A different operator on the same request is allowed.
	v2 := &store.Vote{RequestID: "r1", Operator: "bob", Decision: store.DecisionApprove, AuthnMethod: "webauthn"}
	if _, needs, err := db.PrepareVote(ctx, v2); err != nil || !needs {
		t.Fatalf("PrepareVote bob: needs=%v err=%v", needs, err)
	}
	if err := db.MarkVoteAudited(ctx, "r1", "bob"); err != nil {
		t.Fatalf("MarkVoteAudited bob: %v", err)
	}

	votes, err := db.ListVotes(ctx, "r1")
	if err != nil {
		t.Fatalf("ListVotes: %v", err)
	}
	if len(votes) != 2 {
		t.Fatalf("ListVotes len = %d; want 2 (duplicate collapsed)", len(votes))
	}
	// alice's recorded decision is still the ORIGINAL approve, not the
	// rejected deny.
	for _, v := range votes {
		if v.Operator == "alice" && v.Decision != store.DecisionApprove {
			t.Fatalf("alice's vote mutated to %q; append-only violated", v.Decision)
		}
	}

	// Invalid decision rejected.
	if _, _, err := db.PrepareVote(ctx, &store.Vote{RequestID: "r1", Operator: "carol", Decision: "maybe"}); err == nil {
		t.Fatalf("PrepareVote(invalid decision) = nil; want error")
	}

	// A request with no votes -> empty slice.
	none, err := db.ListVotes(ctx, "r_empty")
	if err != nil {
		t.Fatalf("ListVotes(empty): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("ListVotes(empty) len = %d; want 0", len(none))
	}
}

func TestUpdateStatus_BlockedByUnauditedVote(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Insert(ctx, &store.Request{
		RequestID: "r_barrier", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PrepareVote(ctx, &store.Vote{
		RequestID: "r_barrier", Operator: "alice", Decision: store.DecisionDeny, AuthnMethod: "webauthn",
	}); err != nil {
		t.Fatal(err)
	}

	// A concurrent approval/timeout path must not cross the unaudited vote.
	if err := db.UpdateStatus(ctx, "r_barrier", store.StatusApproved, []byte(`[]`), "bob"); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetByID(ctx, "r_barrier")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusPending {
		t.Fatalf("status crossed unaudited-vote barrier: %q", got.Status)
	}

	if err := db.MarkVoteAudited(ctx, "r_barrier", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateStatus(ctx, "r_barrier", store.StatusDenied, nil, ""); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetByID(ctx, "r_barrier")
	if err != nil || got.Status != store.StatusDenied {
		t.Fatalf("audited vote did not release barrier: status=%q err=%v", got.Status, err)
	}
}

func TestMigration3_PublishesOnlyHistoricalTerminalVotes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "migration2.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);
		INSERT INTO schema_migrations VALUES (1, 'baseline_requests', 1), (2, 'operators_auth_and_approvals', 1);
		CREATE TABLE requests (
		  request_id TEXT PRIMARY KEY, status TEXT NOT NULL, client_id TEXT NOT NULL,
		  commands TEXT NOT NULL, signatures TEXT, created_at INTEGER NOT NULL,
		  resolved_at INTEGER, approved_by TEXT, required_approvals INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE approvals (
		  request_id TEXT NOT NULL, operator TEXT NOT NULL, decision TEXT NOT NULL,
		  authn_method TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (request_id, operator)
		);
		CREATE TABLE sessions (
		  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at INTEGER NOT NULL,
		  expires_at INTEGER NOT NULL
		);
		INSERT INTO requests (request_id,status,client_id,commands,created_at) VALUES
		  ('terminal','denied','c','[]',1), ('pending','pending','c','[]',2);
		INSERT INTO approvals VALUES
		  ('terminal','alice','deny','webauthn',1), ('pending','bob','approve','totp',2);
	`)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	terminalVotes, err := db.ListVotes(context.Background(), "terminal")
	if err != nil || len(terminalVotes) != 1 {
		t.Fatalf("terminal historical vote hidden: votes=%+v err=%v", terminalVotes, err)
	}
	if terminalVotes[0].Audited {
		t.Fatal("migration claimed legacy terminal vote reached the external audit sink")
	}
	pendingVotes, err := db.ListVotes(context.Background(), "pending")
	if err != nil || len(pendingVotes) != 0 {
		t.Fatalf("pending historical vote published without audit: votes=%+v err=%v", pendingVotes, err)
	}
}

// TestApprovals_ConcurrentVotesRaceSafe fires many goroutines recording
// votes — distinct operators succeed, duplicate operators collapse to
// exactly one stored row — without corruption or lost rows. Run with
// -race to catch data races (CGO is available in this env).
func TestApprovals_ConcurrentVotesRaceSafe(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Insert(ctx, &store.Request{RequestID: "r_race", Status: store.StatusPending, ClientID: "c", Commands: []byte(`[]`)}); err != nil {
		t.Fatalf("seed request: %v", err)
	}

	const operators = 16
	const dupAttempts = 8 // each operator votes dupAttempts times concurrently
	var (
		wg        sync.WaitGroup
		okCount   atomic.Int64
		failCount atomic.Int64
	)
	for op := 0; op < operators; op++ {
		operator := fmt.Sprintf("op-%d", op)
		for k := 0; k < dupAttempts; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				canonical, needsAudit, err := db.PrepareVote(ctx, &store.Vote{
					RequestID: "r_race", Operator: operator,
					Decision: store.DecisionApprove, AuthnMethod: "webauthn",
				})
				switch {
				case err == nil && needsAudit:
					okCount.Add(1)
					if err := db.MarkVoteAudited(ctx, canonical.RequestID, canonical.Operator); err != nil {
						failCount.Add(1)
						t.Errorf("MarkVoteAudited: %v", err)
					}
				case err == nil:
					okCount.Add(1)
				default:
					failCount.Add(1)
					t.Errorf("unexpected RecordVote error: %v", err)
				}
			}()
		}
	}
	wg.Wait()

	if failCount.Load() != 0 {
		t.Fatalf("had %d unexpected failures", failCount.Load())
	}
	if okCount.Load() != operators*dupAttempts {
		t.Fatalf("successful/idempotent prepares = %d; want %d", okCount.Load(), operators*dupAttempts)
	}
	votes, err := db.ListVotes(ctx, "r_race")
	if err != nil {
		t.Fatalf("ListVotes: %v", err)
	}
	if len(votes) != operators {
		t.Fatalf("stored votes = %d; want %d (one per operator)", len(votes), operators)
	}
}

func mustUser(t *testing.T, db *sqlitestore.DB, id, username string) {
	t.Helper()
	if err := db.CreateUser(context.Background(), &store.User{ID: id, Username: username, Role: "operator"}); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}
