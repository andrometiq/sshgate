// Package store is the persistence layer for signer-server. It owns
// the SQLite schema, the wire-shape of stored sign requests, and the
// long-poll primitive that handler /v1/poll/{id} blocks on.
//
// v2.0 scaffold exposes one concrete implementation (sqlite.go); v2.1
// may add a Postgres backend for multi-instance deployments. The
// Store interface is the abstraction boundary.
//
// Concurrency model: one *DB instance backs an arbitrary number of
// concurrent callers. modernc.org/sqlite serialises writes internally
// (SQLite WAL mode), so callers don't need their own mutex.
package store

import (
	"context"
	"errors"
	"time"
)

// Status is one of the spec's resolution states. The wire form (the
// JSON string in poll responses and audit rows) is identical to the
// String() output below so the handlers and the store never need a
// mapping table.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusTimeout  Status = "timeout"
	StatusError    Status = "error"
)

// IsValid reports whether s is one of the recognised values. Used at
// the store boundary so a typo in a future caller surfaces as a
// validation error rather than silent data corruption.
func (s Status) IsValid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusDenied, StatusTimeout, StatusError:
		return true
	}
	return false
}

// Request is one row in the requests table. The wire-shape it implies
// (commands as JSON, signatures as JSON, status as a string) matches
// the schema in sqlite.go.
//
// Commands and Signatures are stored as raw []byte (JSON) rather than
// typed slices because the audit consumers (and the eventual web UI)
// only want to render them as opaque blobs; the store does not need
// to crack them open.
type Request struct {
	RequestID  string
	Status     Status
	ClientID   string
	Commands   []byte // JSON-encoded []signRequestCmd from the handlers package
	Signatures []byte // JSON-encoded []signedCmd; populated on approval
	CreatedAt  time.Time
	ResolvedAt *time.Time
	ApprovedBy string
	// RequiredApprovals is the number of distinct approving operators
	// this request needs before it crosses into approved (the N the
	// approval state machine reads). It is a MECHANISM input: the value
	// is a product/policy decision set by a caller, never defaulted by
	// the store to anything but the column fallback of 1.
	RequiredApprovals int
}

// Role is an operator's free-form authorization role. The store does
// not enforce an enum; the policy layer interprets it.
type Role string

// User is one operator who can authenticate and cast votes.
type User struct {
	ID        string
	Username  string
	Role      Role
	CreatedAt time.Time
}

// Credential is one stored WebAuthn passkey for a user. CredentialID is
// the raw WebAuthn credential ID (unique across users); Blob is the
// opaque serialized credential the auth layer owns.
type Credential struct {
	ID           int64
	UserID       string
	CredentialID []byte
	Blob         []byte
	CreatedAt    time.Time
}

// Session is a server-side login session. ExpiresAt is an absolute
// instant; GetSession treats an expired session as ErrNotFound.
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Decision is one operator's vote on a request. The wire form matches
// the approvals.decision column ('approve' | 'deny').
type Decision string

const (
	DecisionApprove Decision = "approve"
	DecisionDeny    Decision = "deny"
)

// IsValid reports whether d is a recognised vote.
func (d Decision) IsValid() bool {
	switch d {
	case DecisionApprove, DecisionDeny:
		return true
	}
	return false
}

// Vote is one APPEND-ONLY row in the approvals ledger: an operator's
// single, immutable decision on a request, plus how they authenticated
// for it. At most one Vote exists per (RequestID, Operator).
type Vote struct {
	RequestID   string
	Operator    string
	Decision    Decision
	AuthnMethod string
	TS          time.Time
	// Audited is true only after the external AuditSink has durably accepted
	// the immutable vote. Decision readers MUST ignore unaudited rows.
	Audited bool
}

// Store is the persistence interface. All methods MUST be safe for
// concurrent calls.
//
// WaitForResolution is the long-poll primitive: it blocks until the
// stored Status transitions to a non-pending value or until timeout
// fires, whichever happens first. v2.0 ships a polling implementation
// (sleep 100ms, re-read); v2.1 should upgrade to per-request channel
// wakeups once write QPS justifies it.
type Store interface {
	// Insert writes r as a new pending row. RequestID is the primary
	// key; a duplicate ID is a programming error and returns
	// ErrDuplicateID.
	Insert(ctx context.Context, r *Request) error

	// GetByID returns the row with the given ID. ErrNotFound if no
	// row exists.
	GetByID(ctx context.Context, id string) (*Request, error)

	// UpdateStatus transitions a row from pending to a terminal status.
	// signatures may be nil for non-approved transitions. approvedBy is the
	// human identifier (or "" if not applicable).
	//
	// ATOMICITY CONTRACT (C10 — this is the single-sign guarantee, not an
	// implementation detail): UpdateStatus MUST be an atomic compare-and-set
	// gated on status='pending'. For a given request, AT MOST ONE transition
	// out of pending may ever succeed; terminal states are IMMUTABLE (a later
	// UpdateStatus on an already-resolved row is a no-op that changes nothing —
	// it does NOT overwrite the signatures or approver of the winning
	// transition). The SQLite ref impl satisfies this with a single
	// `UPDATE ... WHERE request_id = ? AND status = 'pending'`.
	// It MUST also refuse the transition while any prepared vote for that
	// request remains Audited=false. That barrier ensures a terminal approve
	// cannot race past a deny whose durable audit write is still in flight.
	//
	// A read-then-write implementation (SELECT status; if pending then UPDATE)
	// is NON-CONFORMANT: two operators casting the final approve concurrently,
	// or a deny racing an approve, could both observe pending and both write —
	// corrupting the single-sign guarantee. The approval engine is stateless by
	// design (a hosted deployment may run multiple replicas against one DB), so
	// an in-process mutex is INSUFFICIENT; the atomicity must live in the store.
	// Every Store implementation MUST pass signerkit/storetest's concurrent-flip
	// conformance hammer.
	UpdateStatus(ctx context.Context, id string, status Status, signatures []byte, approvedBy string) error

	// WaitForResolution blocks until the row's status is non-pending
	// or timeout fires. Returns the final row (with whatever Status
	// it has at return time, including "pending" if timeout won).
	// On timeout the row is NOT mutated — callers that want to mark
	// the row as timed-out must call UpdateStatus themselves.
	WaitForResolution(ctx context.Context, id string, timeout time.Duration) (*Request, error)

	// ListPending returns all rows currently in StatusPending.
	// Ordered by created_at ascending so the oldest unresolved
	// request surfaces first.
	ListPending(ctx context.Context) ([]*Request, error)

	// RecentAudit returns up to limit most-recent rows regardless of
	// status, ordered by created_at descending. Limit <= 0 is
	// treated as 100.
	RecentAudit(ctx context.Context, limit int) ([]*Request, error)

	// SetRequiredApprovals sets the N threshold on a pending request.
	// ErrNotFound if no row exists. The value is a policy input; the
	// store stores it verbatim and never invents a default beyond the
	// column fallback.
	SetRequiredApprovals(ctx context.Context, requestID string, n int) error

	// --- Operators (users) ---

	// CreateUser inserts u. u.ID and u.Username are unique; a collision
	// on either returns ErrDuplicate. If u.CreatedAt is zero it is set
	// to time.Now().UTC().
	CreateUser(ctx context.Context, u *User) error

	// GetUser returns the user with the given id. ErrNotFound if none.
	GetUser(ctx context.Context, id string) (*User, error)

	// GetUserByName returns the user with the given username.
	// ErrNotFound if none.
	GetUserByName(ctx context.Context, username string) (*User, error)

	// --- WebAuthn credentials ---

	// AddCredential appends a passkey credential for a user. A duplicate
	// CredentialID returns ErrDuplicate. On success c.ID is populated
	// with the assigned rowid.
	AddCredential(ctx context.Context, c *Credential) error

	// ListCredentials returns all credentials for userID, oldest first.
	// An empty slice (not ErrNotFound) when the user has none.
	ListCredentials(ctx context.Context, userID string) ([]*Credential, error)

	// UpdateCredential replaces the opaque blob of the credential with the
	// given rowid. Used after a successful assertion to persist the
	// advanced signature counter (WebAuthn clone/replay detection). The
	// credential_id is immutable; only the blob changes. ErrNotFound if
	// no row has that id.
	UpdateCredential(ctx context.Context, id int64, blob []byte) error

	// --- TOTP ---

	// SetTOTP sets (or replaces) the user's TOTP secret. At most one
	// secret per user.
	SetTOTP(ctx context.Context, userID, secret string) error

	// GetTOTP returns the user's TOTP secret. ErrNotFound if unset.
	GetTOTP(ctx context.Context, userID string) (string, error)

	// ConsumeTOTPStep atomically records step as the latest successfully used
	// TOTP timestep for userID, but only if secret still matches the enrolled
	// factor and step is strictly newer than the previously consumed step.
	// It returns true for the single winning consumer and false for a replay,
	// stale step, or factor rotated concurrently. All authentication purposes
	// share this boundary so a login code cannot be reused for a vote.
	ConsumeTOTPStep(ctx context.Context, userID, secret string, step int64) (bool, error)

	// --- Sessions ---

	// CreateSession inserts s. A duplicate ID returns ErrDuplicate.
	CreateSession(ctx context.Context, s *Session) error

	// GetSession returns the session with the given id. ErrNotFound if
	// it does not exist OR has expired (expires_at <= now).
	GetSession(ctx context.Context, id string) (*Session, error)

	// RevokeSession deletes the session with the given id. Revoking a
	// missing (or already-revoked) session is a no-op, not an error.
	RevokeSession(ctx context.Context, id string) error

	// --- Approvals (append-only vote ledger) ---

	// PrepareVote atomically claims an immutable (request_id, operator) vote
	// while the request is pending. The returned Vote is the canonical stored
	// row. needsAudit is true until MarkVoteAudited succeeds. A same-decision
	// retry returns the existing row; an opposite-decision retry returns
	// ErrVoteConflict and never changes it. Implementations must persist new
	// votes as Audited=false.
	PrepareVote(ctx context.Context, v *Vote) (canonical *Vote, needsAudit bool, err error)

	// MarkVoteAudited makes a prepared vote visible to ListVotes. It is an
	// idempotent compare-and-set from unaudited to audited. The approval engine
	// calls it only after AuditSink.Verdict succeeds, so an unaudited vote can
	// never contribute to a decision. A crash after the sink write but before
	// this CAS may duplicate the same audit event on retry (at-least-once), but
	// can never audit or count an opposite decision.
	MarkVoteAudited(ctx context.Context, requestID, operator string) error

	// ListVotes returns every audited vote on requestID, oldest first.
	// Prepared-but-unaudited rows on a pending request are deliberately
	// invisible. An implementation migrating a pre-audit schema may also return
	// immutable votes for an already-terminal request with Audited=false to
	// preserve honest history without claiming the external sink accepted them;
	// such rows must never exist on a pending request.
	ListVotes(ctx context.Context, requestID string) ([]*Vote, error)

	// Close releases the underlying database handle. Idempotent.
	Close() error
}

// ErrNotFound is returned by GetByID and WaitForResolution when the
// requested row does not exist. Callers should errors.Is-check
// against this sentinel.
var ErrNotFound = errors.New("store: request not found")

// ErrDuplicateID is returned by Insert when the RequestID collides
// with an existing row.
var ErrDuplicateID = errors.New("store: duplicate request_id")

// ErrQueueFull is returned when a pending-request intake quota is exhausted.
// Callers should surface it as bounded backpressure (429/Retry-After), not an
// internal error or an unbounded allocation.
var ErrQueueFull = errors.New("store: pending request queue full")

// ErrDuplicate is the general "row already exists" sentinel for the
// multi-operator tables (users, credentials, sessions, votes). Insert
// keeps its own ErrDuplicateID for backward compatibility; new ops use
// ErrDuplicate. Both are checked with errors.Is.
var ErrDuplicate = errors.New("store: duplicate row")

// ErrVoteConflict means an operator already prepared an immutable vote with
// the opposite decision. The stored vote remains authoritative and unchanged.
var ErrVoteConflict = errors.New("store: conflicting duplicate vote")

// ErrRequestResolved means a vote claim raced with or followed a terminal
// transition. No vote row was inserted.
var ErrRequestResolved = errors.New("store: request already resolved")
