package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	"time"
)

// operators.go implements the multi-operator + auth-backend half of the
// Store interface added for Tier 3: users, WebAuthn credentials, TOTP
// secrets, sessions, the append-only approvals vote ledger, and the
// per-request required_approvals threshold setter. The requests-table
// half lives in sqlite.go; both share the same *sql.DB and the same
// nullable/duplicate helpers.

// SetRequiredApprovals implements Store.SetRequiredApprovals. It only
// fires on a still-pending row (mirroring UpdateStatus's pending guard)
// so an N change cannot retroactively reopen a resolved request.
func (s *DB) SetRequiredApprovals(ctx context.Context, requestID string, n int) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE requests SET required_approvals = ?
		WHERE request_id = ? AND status = ?
	`, n, requestID, string(store.StatusPending))
	if err != nil {
		return fmt.Errorf("set required_approvals %s: %w", requestID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		// Either the row does not exist or it is already resolved. Probe
		// to give the caller the precise sentinel.
		if _, gerr := s.GetByID(ctx, requestID); gerr != nil {
			return gerr // ErrNotFound (or a wrapped infra error)
		}
		// Row exists but is non-pending: setting N on a resolved request
		// is a no-op, not an error (consistent with UpdateStatus's
		// idempotent no-op on resolved rows).
	}
	return nil
}

// CreateUser implements Store.CreateUser.
func (s *DB) CreateUser(ctx context.Context, u *store.User) error {
	if u == nil {
		return errors.New("store: CreateUser: nil user")
	}
	if u.ID == "" {
		return errors.New("store: CreateUser: empty id")
	}
	if u.Username == "" {
		return errors.New("store: CreateUser: empty username")
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, role, created_at) VALUES (?, ?, ?, ?)
	`, u.ID, u.Username, string(u.Role), u.CreatedAt.Unix())
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: user %s/%s", store.ErrDuplicate, u.ID, u.Username)
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// GetUser implements Store.GetUser.
func (s *DB) GetUser(ctx context.Context, id string) (*store.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, created_at FROM users WHERE id = ?
	`, id)
	return scanUser(row, id)
}

// GetUserByName implements Store.GetUserByName.
func (s *DB) GetUserByName(ctx context.Context, username string) (*store.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, created_at FROM users WHERE username = ?
	`, username)
	return scanUser(row, username)
}

// CountEligiblePolicyVoters mirrors the voter-freeze predicate used by policy
// admission. It is deployment introspection, not part of the portable Store
// mechanism interface.
func (s *DB) CountEligiblePolicyVoters(ctx context.Context, role, requesterID string, allowSelf, stepUp bool) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users u
		WHERE u.role = ?
		  AND (? = 1 OR u.id <> ?)
		  AND (
			(? = 1 AND EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id))
			OR (? = 0 AND (
				EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id)
				OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)
			))
		  )
	`, role, boolInteger(allowSelf), requesterID, boolInteger(stepUp), boolInteger(stepUp)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count eligible policy voters: %w", err)
	}
	return count, nil
}

func scanUser(row rowScanner, key string) (*store.User, error) {
	var (
		u           store.User
		role        string
		createdUnix int64
	)
	if err := row.Scan(&u.ID, &u.Username, &role, &createdUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("get user %s: %w", key, err)
	}
	u.Role = store.Role(role)
	u.CreatedAt = time.Unix(createdUnix, 0).UTC()
	return &u, nil
}

// AddCredential implements Store.AddCredential.
func (s *DB) AddCredential(ctx context.Context, c *store.Credential) error {
	if c == nil {
		return errors.New("store: AddCredential: nil credential")
	}
	if c.UserID == "" {
		return errors.New("store: AddCredential: empty user_id")
	}
	if len(c.CredentialID) == 0 {
		return errors.New("store: AddCredential: empty credential_id")
	}
	if len(c.Blob) == 0 {
		return errors.New("store: AddCredential: empty credential blob")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (user_id, credential_id, credential, created_at)
		VALUES (?, ?, ?, ?)
	`, c.UserID, c.CredentialID, c.Blob, c.CreatedAt.Unix())
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: credential_id already registered", store.ErrDuplicate)
		}
		return fmt.Errorf("add credential: %w", err)
	}
	if id, err := res.LastInsertId(); err == nil {
		c.ID = id
	}
	return nil
}

// ListCredentials implements Store.ListCredentials.
func (s *DB) ListCredentials(ctx context.Context, userID string) ([]*store.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, credential, created_at
		FROM webauthn_credentials WHERE user_id = ? ORDER BY id ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	var out []*store.Credential
	for rows.Next() {
		var (
			c           store.Credential
			createdUnix int64
		)
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.Blob, &createdUnix); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		c.CreatedAt = time.Unix(createdUnix, 0).UTC()
		out = append(out, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}
	return out, nil
}

// UpdateCredential implements Store.UpdateCredential. It rewrites only
// the opaque blob (the advanced signature counter lives inside it); the
// credential_id is immutable and is not touched.
func (s *DB) UpdateCredential(ctx context.Context, id int64, blob []byte) error {
	if len(blob) == 0 {
		return errors.New("store: UpdateCredential: empty blob")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials SET credential = ? WHERE id = ?
	`, blob, id)
	if err != nil {
		return fmt.Errorf("update credential %d: %w", id, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// SetTOTP implements Store.SetTOTP. Replacing a factor and clearing its replay
// watermark happen in one transaction, so an old factor cannot race a reset.
func (s *DB) SetTOTP(ctx context.Context, userID, secret string) error {
	if userID == "" {
		return errors.New("store: SetTOTP: empty user_id")
	}
	if secret == "" {
		return errors.New("store: SetTOTP: empty secret")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set totp: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO totp_secrets (user_id, secret, created_at) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at
	`, userID, secret, nowUnix()); err != nil {
		return fmt.Errorf("set totp: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_replay WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("set totp: clear replay state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("set totp: commit: %w", err)
	}
	return nil
}

// GetTOTP implements Store.GetTOTP.
func (s *DB) GetTOTP(ctx context.Context, userID string) (string, error) {
	var secret string
	err := s.db.QueryRowContext(ctx, `
		SELECT secret FROM totp_secrets WHERE user_id = ?
	`, userID).Scan(&secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", store.ErrNotFound
		}
		return "", fmt.Errorf("get totp %s: %w", userID, err)
	}
	return secret, nil
}

// ConsumeTOTPStep implements Store.ConsumeTOTPStep as one SQLite upsert. The
// SELECT binds consumption to the exact secret VerifyTOTP loaded; a concurrent
// factor rotation therefore returns consumed=false instead of accepting an old
// code against the new factor's replay state.
func (s *DB) ConsumeTOTPStep(ctx context.Context, userID, secret string, step int64) (bool, error) {
	if userID == "" || secret == "" || step < 0 {
		return false, errors.New("store: ConsumeTOTPStep: invalid input")
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_replay (user_id, last_step)
		SELECT user_id, ? FROM totp_secrets
		WHERE user_id = ? AND secret = ?
		ON CONFLICT(user_id) DO UPDATE SET last_step = excluded.last_step
		WHERE excluded.last_step > totp_replay.last_step
	`, step, userID, secret)
	if err != nil {
		return false, fmt.Errorf("consume totp step: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("consume totp step: rows affected: %w", err)
	}
	return affected == 1, nil
}

// CreateSession implements Store.CreateSession. Each issue opportunistically
// removes expired rows first so an attacker cannot grow the session table
// without bound by repeatedly authenticating.
func (s *DB) CreateSession(ctx context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("store: CreateSession: nil session")
	}
	if sess.ID == "" {
		return errors.New("store: CreateSession: empty id")
	}
	if sess.UserID == "" {
		return errors.New("store: CreateSession: empty user_id")
	}
	if sess.ExpiresAt.IsZero() {
		return errors.New("store: CreateSession: zero expires_at")
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create session: begin cleanup transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().UTC().Unix()); err != nil {
		return fmt.Errorf("create session: remove expired sessions: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)
	`, sess.ID, sess.UserID, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix())
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: session %s", store.ErrDuplicate, sess.ID)
		}
		return fmt.Errorf("create session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create session: commit: %w", err)
	}
	return nil
}

// GetSession implements Store.GetSession. An expired session reads back as
// ErrNotFound; CreateSession opportunistically removes expired rows.
func (s *DB) GetSession(ctx context.Context, id string) (*store.Session, error) {
	var (
		sess        store.Session
		createdUnix int64
		expiresUnix int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?
	`, id).Scan(&sess.ID, &sess.UserID, &createdUnix, &expiresUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("get session %s: %w", id, err)
	}
	sess.CreatedAt = time.Unix(createdUnix, 0).UTC()
	sess.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
	if !time.Now().UTC().Before(sess.ExpiresAt) {
		// now >= expires_at: expired.
		return nil, store.ErrNotFound
	}
	return &sess, nil
}

// RevokeSession implements Store.RevokeSession. Deleting a missing row
// is a no-op (no error) so revocation is idempotent.
func (s *DB) RevokeSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("revoke session %s: %w", id, err)
	}
	return nil
}

// PrepareVote implements the first phase of Store's vote/audit protocol.
// It atomically inserts an immutable unaudited vote only while the request is
// pending. On a duplicate it returns the canonical stored row: a same-decision
// retry resumes audit/finalization, while an opposite decision fails with
// ErrVoteConflict and can never reach the audit sink.
func (s *DB) PrepareVote(ctx context.Context, v *store.Vote) (*store.Vote, bool, error) {
	if v == nil {
		return nil, false, errors.New("store: PrepareVote: nil vote")
	}
	if v.RequestID == "" {
		return nil, false, errors.New("store: PrepareVote: empty request_id")
	}
	if v.Operator == "" {
		return nil, false, errors.New("store: PrepareVote: empty operator")
	}
	if !v.Decision.IsValid() {
		return nil, false, fmt.Errorf("store: PrepareVote: invalid decision %q", v.Decision)
	}
	ts := v.TS
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO approvals (request_id, operator, decision, authn_method, ts, audited)
		SELECT ?, ?, ?, ?, ?, 0
		WHERE EXISTS (
			SELECT 1 FROM requests WHERE request_id = ? AND status = 'pending'
		)
	`, v.RequestID, v.Operator, string(v.Decision), v.AuthnMethod, ts.UTC().Unix(), v.RequestID)
	if err != nil {
		if isUniqueConstraintErr(err) {
			existing, getErr := s.getVote(ctx, v.RequestID, v.Operator)
			if getErr != nil {
				return nil, false, getErr
			}
			if existing.Decision != v.Decision {
				return existing, false, fmt.Errorf("%w: %s already voted %s on %s", store.ErrVoteConflict, v.Operator, existing.Decision, v.RequestID)
			}
			return existing, !existing.Audited, nil
		}
		return nil, false, fmt.Errorf("prepare vote: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("prepare vote rows affected: %w", err)
	}
	if rows == 0 {
		var status string
		err := s.db.QueryRowContext(ctx, `SELECT status FROM requests WHERE request_id = ?`, v.RequestID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, store.ErrNotFound
		}
		if err != nil {
			return nil, false, fmt.Errorf("prepare vote request state: %w", err)
		}
		return nil, false, store.ErrRequestResolved
	}
	canonical := *v
	canonical.TS = ts.UTC()
	canonical.Audited = false
	return &canonical, true, nil
}

func (s *DB) getVote(ctx context.Context, requestID, operator string) (*store.Vote, error) {
	var (
		v        store.Vote
		decision string
		tsUnix   int64
		audited  int
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT request_id, operator, decision, authn_method, ts, audited
		FROM approvals WHERE request_id = ? AND operator = ?
	`, requestID, operator).Scan(&v.RequestID, &v.Operator, &decision, &v.AuthnMethod, &tsUnix, &audited)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get vote: %w", err)
	}
	v.Decision = store.Decision(decision)
	v.TS = time.Unix(tsUnix, 0).UTC()
	v.Audited = audited == 1
	return &v, nil
}

// MarkVoteAudited publishes a prepared vote to ListVotes after the external
// sink succeeds. The update is idempotent so retries after an uncertain DB
// response are safe.
func (s *DB) MarkVoteAudited(ctx context.Context, requestID, operator string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE approvals SET audited = 1
		WHERE request_id = ? AND operator = ? AND audited = 0
	`, requestID, operator)
	if err != nil {
		return fmt.Errorf("mark vote audited: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark vote audited rows affected: %w", err)
	}
	if rows != 0 {
		return nil
	}
	existing, err := s.getVote(ctx, requestID, operator)
	if err != nil {
		return err
	}
	if existing.Audited {
		return nil
	}
	return errors.New("mark vote audited: vote remained unaudited")
}

// ListVotes implements Store.ListVotes, oldest first. State 2 is a migration-
// only marker for votes on immutable terminal requests whose pre-migration
// external-audit outcome is unknowable; it is visible for history but remains
// Vote.Audited=false. Pending requests can contain only states 0/1, so the
// approval engine never counts a legacy-unknown vote toward a transition.
func (s *DB) ListVotes(ctx context.Context, requestID string) ([]*store.Vote, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT request_id, operator, decision, authn_method, ts, audited
		FROM approvals WHERE request_id = ? AND audited IN (1, 2) ORDER BY ts ASC, operator ASC
	`, requestID)
	if err != nil {
		return nil, fmt.Errorf("list votes: %w", err)
	}
	defer rows.Close()
	var out []*store.Vote
	for rows.Next() {
		var (
			v        store.Vote
			decision string
			tsUnix   int64
			audited  int
		)
		if err := rows.Scan(&v.RequestID, &v.Operator, &decision, &v.AuthnMethod, &tsUnix, &audited); err != nil {
			return nil, fmt.Errorf("scan vote: %w", err)
		}
		v.Decision = store.Decision(decision)
		v.TS = time.Unix(tsUnix, 0).UTC()
		v.Audited = audited == 1
		out = append(out, &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate votes: %w", err)
	}
	return out, nil
}
