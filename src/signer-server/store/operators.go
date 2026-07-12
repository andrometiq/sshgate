package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	`, n, requestID, string(StatusPending))
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
func (s *DB) CreateUser(ctx context.Context, u *User) error {
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
			return fmt.Errorf("%w: user %s/%s", ErrDuplicate, u.ID, u.Username)
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// GetUser implements Store.GetUser.
func (s *DB) GetUser(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, created_at FROM users WHERE id = ?
	`, id)
	return scanUser(row, id)
}

// GetUserByName implements Store.GetUserByName.
func (s *DB) GetUserByName(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, created_at FROM users WHERE username = ?
	`, username)
	return scanUser(row, username)
}

func scanUser(row rowScanner, key string) (*User, error) {
	var (
		u           User
		role        string
		createdUnix int64
	)
	if err := row.Scan(&u.ID, &u.Username, &role, &createdUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user %s: %w", key, err)
	}
	u.Role = Role(role)
	u.CreatedAt = time.Unix(createdUnix, 0).UTC()
	return &u, nil
}

// AddCredential implements Store.AddCredential.
func (s *DB) AddCredential(ctx context.Context, c *Credential) error {
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
			return fmt.Errorf("%w: credential_id already registered", ErrDuplicate)
		}
		return fmt.Errorf("add credential: %w", err)
	}
	if id, err := res.LastInsertId(); err == nil {
		c.ID = id
	}
	return nil
}

// ListCredentials implements Store.ListCredentials.
func (s *DB) ListCredentials(ctx context.Context, userID string) ([]*Credential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, credential, created_at
		FROM webauthn_credentials WHERE user_id = ? ORDER BY id ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	var out []*Credential
	for rows.Next() {
		var (
			c           Credential
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
		return ErrNotFound
	}
	return nil
}

// SetTOTP implements Store.SetTOTP. An upsert: a user has at most one
// TOTP secret, so re-setting replaces it.
func (s *DB) SetTOTP(ctx context.Context, userID, secret string) error {
	if userID == "" {
		return errors.New("store: SetTOTP: empty user_id")
	}
	if secret == "" {
		return errors.New("store: SetTOTP: empty secret")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_secrets (user_id, secret, created_at) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at
	`, userID, secret, nowUnix())
	if err != nil {
		return fmt.Errorf("set totp: %w", err)
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
			return "", ErrNotFound
		}
		return "", fmt.Errorf("get totp %s: %w", userID, err)
	}
	return secret, nil
}

// CreateSession implements Store.CreateSession.
func (s *DB) CreateSession(ctx context.Context, sess *Session) error {
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
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)
	`, sess.ID, sess.UserID, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix())
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: session %s", ErrDuplicate, sess.ID)
		}
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession implements Store.GetSession. An expired session reads back
// as ErrNotFound: the row may still physically exist (sweeping is a
// future concern), but it is no longer valid, so callers never receive
// a session they should reject.
func (s *DB) GetSession(ctx context.Context, id string) (*Session, error) {
	var (
		sess        Session
		createdUnix int64
		expiresUnix int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?
	`, id).Scan(&sess.ID, &sess.UserID, &createdUnix, &expiresUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session %s: %w", id, err)
	}
	sess.CreatedAt = time.Unix(createdUnix, 0).UTC()
	sess.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
	if !time.Now().UTC().Before(sess.ExpiresAt) {
		// now >= expires_at: expired.
		return nil, ErrNotFound
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

// RecordVote implements Store.RecordVote. The composite primary key
// (request_id, operator) makes a second vote from the same operator on
// the same request a UNIQUE violation, which surfaces as ErrDuplicate.
// The existing vote is left untouched — votes are immutable. This is
// the store-level half of the append-only / one-vote-per-operator
// guarantee the state machine relies on.
func (s *DB) RecordVote(ctx context.Context, v *Vote) error {
	if v == nil {
		return errors.New("store: RecordVote: nil vote")
	}
	if v.RequestID == "" {
		return errors.New("store: RecordVote: empty request_id")
	}
	if v.Operator == "" {
		return errors.New("store: RecordVote: empty operator")
	}
	if !v.Decision.IsValid() {
		return fmt.Errorf("store: RecordVote: invalid decision %q", v.Decision)
	}
	ts := v.TS
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO approvals (request_id, operator, decision, authn_method, ts)
		VALUES (?, ?, ?, ?, ?)
	`, v.RequestID, v.Operator, string(v.Decision), v.AuthnMethod, ts.UTC().Unix())
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: %s already voted on %s", ErrDuplicate, v.Operator, v.RequestID)
		}
		return fmt.Errorf("record vote: %w", err)
	}
	return nil
}

// ListVotes implements Store.ListVotes, oldest first.
func (s *DB) ListVotes(ctx context.Context, requestID string) ([]*Vote, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT request_id, operator, decision, authn_method, ts
		FROM approvals WHERE request_id = ? ORDER BY ts ASC, operator ASC
	`, requestID)
	if err != nil {
		return nil, fmt.Errorf("list votes: %w", err)
	}
	defer rows.Close()
	var out []*Vote
	for rows.Next() {
		var (
			v        Vote
			decision string
			tsUnix   int64
		)
		if err := rows.Scan(&v.RequestID, &v.Operator, &decision, &v.AuthnMethod, &tsUnix); err != nil {
			return nil, fmt.Errorf("scan vote: %w", err)
		}
		v.Decision = Decision(decision)
		v.TS = time.Unix(tsUnix, 0).UTC()
		out = append(out, &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate votes: %w", err)
	}
	return out, nil
}
