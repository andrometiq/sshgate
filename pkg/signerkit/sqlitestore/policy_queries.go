package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
)

const maxPolicyPageSize = 256

func policyPageLimit(limit int) (int, error) {
	if limit <= 0 || limit > maxPolicyPageSize {
		return 0, errors.New("policy page limit is outside 1..256")
	}
	return limit, nil
}

func (store *policyDB) GetByReviewID(ctx context.Context, reviewID string) (*policystore.Request, error) {
	if len(reviewID) != 35 || reviewID[:3] != "pr_" || !lowerHex(reviewID[3:]) {
		return nil, policystore.ErrNotFound
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		return nil, err
	}
	request, err := loadPolicyRequestByReviewID(ctx, store.database, reviewID)
	if err != nil || !request.SubmissionAudited {
		return nil, policystore.ErrNotFound
	}
	return request, nil
}

func (store *policyDB) ListPending(ctx context.Context, authorityID string, after *policystore.PendingCursor, limit int) (policystore.PendingPage, error) {
	limit, err := policyPageLimit(limit)
	if err != nil {
		return policystore.PendingPage{}, err
	}
	binding, err := store.VerifyAuthorityBinding(ctx)
	if err != nil {
		return policystore.PendingPage{}, err
	}
	if authorityID != binding.AuthorityID {
		return policystore.PendingPage{}, policystore.ErrAuthorityMismatch
	}
	created, principal, requestID := int64(-1), "", ""
	if after != nil {
		created, principal, requestID = after.CreatedAt, after.Principal, after.RequestID
	}
	rows, err := store.database.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.RequestColumns[:])+`
		FROM policy_requests WHERE authority_id=? AND storage_kind='full' AND state='pending' AND
		(created_at>? OR (created_at=? AND principal>?) OR (created_at=? AND principal=? AND request_id>?))
		ORDER BY created_at,principal,request_id LIMIT ?`, authorityID, created, created, principal, created, principal, requestID, limit+1)
	if err != nil {
		return policystore.PendingPage{}, err
	}
	requests, err := scanPolicyRequests(rows, limit+1)
	if err != nil {
		return policystore.PendingPage{}, err
	}
	page := policystore.PendingPage{Requests: requests}
	if len(page.Requests) > limit {
		last := page.Requests[limit-1]
		page.Requests = page.Requests[:limit]
		page.Next = &policystore.PendingCursor{CreatedAt: last.CreatedAt, Principal: last.Principal, RequestID: last.RequestID}
	}
	return page, nil
}

func (store *policyDB) ListRecovery(ctx context.Context, authorityID string, now time.Time, after *policystore.RecoveryCursor, limit int) (policystore.RecoveryPage, error) {
	limit, err := policyPageLimit(limit)
	if err != nil {
		return policystore.RecoveryPage{}, err
	}
	binding, err := store.VerifyAuthorityBinding(ctx)
	if err != nil {
		return policystore.RecoveryPage{}, err
	}
	if authorityID != binding.AuthorityID {
		return policystore.RecoveryPage{}, policystore.ErrAuthorityMismatch
	}
	updated, principal, requestID := int64(-1), "", ""
	if after != nil {
		updated, principal, requestID = after.UpdatedAt, after.Principal, after.RequestID
	}
	rows, err := store.database.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.RequestColumns[:])+`
		FROM policy_requests WHERE authority_id=? AND storage_kind='full' AND state IN
		('received_unaudited','rejection_unaudited','rejection_error_received','approved_materializing','approved_unexposed','no_op_unexposed','denial_received','error_received') AND
		(recovery_lease_owner='' OR recovery_lease_until<=? OR recovery_lease_until>?) AND
		(updated_at>? OR (updated_at=? AND principal>?) OR (updated_at=? AND principal=? AND request_id>?))
		ORDER BY updated_at,principal,request_id LIMIT ?`, authorityID, now.UTC().Unix(), now.Add(2*time.Minute).UTC().Unix(),
		updated, updated, principal, updated, principal, requestID, limit+1)
	if err != nil {
		return policystore.RecoveryPage{}, err
	}
	requests, err := scanPolicyRequests(rows, limit+1)
	if err != nil {
		return policystore.RecoveryPage{}, err
	}
	page := policystore.RecoveryPage{Requests: requests}
	if len(page.Requests) > limit {
		last := page.Requests[limit-1]
		page.Requests = page.Requests[:limit]
		page.Next = &policystore.RecoveryCursor{UpdatedAt: last.UpdatedAt, Principal: last.Principal, RequestID: last.RequestID}
	}
	return page, nil
}

func (store *policyDB) ListUnauditedVotes(ctx context.Context, authorityID string, after *policystore.RecoveryCursor, limit int) (policystore.VoteRecoveryPage, error) {
	limit, err := policyPageLimit(limit)
	if err != nil {
		return policystore.VoteRecoveryPage{}, err
	}
	binding, err := store.VerifyAuthorityBinding(ctx)
	if err != nil {
		return policystore.VoteRecoveryPage{}, err
	}
	if authorityID != binding.AuthorityID {
		return policystore.VoteRecoveryPage{}, policystore.ErrAuthorityMismatch
	}
	updated, principal, requestID := int64(-1), "", ""
	if after != nil {
		updated, principal, requestID = after.UpdatedAt, after.Principal, after.RequestID
	}
	// The cursor is request-shaped, so page request groups and include every
	// unaudited vote for each selected request. This cannot split or starve a
	// request that has several prepared audits.
	requestRows, err := store.database.QueryContext(ctx, `SELECT DISTINCT r.updated_at,r.principal,r.request_id
		FROM policy_requests r JOIN policy_votes v USING(principal,request_id)
		WHERE r.authority_id=? AND v.audited=0 AND
		(r.updated_at>? OR (r.updated_at=? AND r.principal>?) OR (r.updated_at=? AND r.principal=? AND r.request_id>?))
		ORDER BY r.updated_at,r.principal,r.request_id LIMIT ?`, authorityID, updated, updated, principal, updated, principal, requestID, limit+1)
	if err != nil {
		return policystore.VoteRecoveryPage{}, err
	}
	type rowKey struct {
		updated int64
		key     policystore.Key
	}
	var keys []rowKey
	for requestRows.Next() {
		var item rowKey
		if err := requestRows.Scan(&item.updated, &item.key.Principal, &item.key.RequestID); err != nil {
			requestRows.Close()
			return policystore.VoteRecoveryPage{}, err
		}
		keys = append(keys, item)
	}
	if err := requestRows.Close(); err != nil {
		return policystore.VoteRecoveryPage{}, err
	}
	page := policystore.VoteRecoveryPage{}
	if len(keys) > limit {
		last := keys[limit-1]
		keys = keys[:limit]
		page.Next = &policystore.RecoveryCursor{UpdatedAt: last.updated, Principal: last.key.Principal, RequestID: last.key.RequestID}
	}
	for _, item := range keys {
		votes, err := loadPolicyVotes(ctx, store.database, item.key, true)
		if err != nil {
			return policystore.VoteRecoveryPage{}, err
		}
		page.Votes = append(page.Votes, votes...)
	}
	return page, nil
}

func (store *policyDB) ListRecentTerminals(ctx context.Context, authorityID string, before *policystore.TerminalCursor, limit int) (policystore.TerminalPage, error) {
	return store.listTerminals(ctx, authorityID, time.Time{}, before, limit, false)
}

func (store *policyDB) ListTerminalCompactionCandidates(ctx context.Context, before time.Time, after *policystore.TerminalCursor, limit int) (policystore.CompactionPage, error) {
	page, err := store.listTerminals(ctx, "", before, after, limit, true)
	return policystore.CompactionPage{Requests: page.Requests, Next: page.Next}, err
}

func (store *policyDB) listTerminals(ctx context.Context, authorityID string, cutoff time.Time, cursor *policystore.TerminalCursor, limit int, compaction bool) (policystore.TerminalPage, error) {
	limit, err := policyPageLimit(limit)
	if err != nil {
		return policystore.TerminalPage{}, err
	}
	binding, err := store.VerifyAuthorityBinding(ctx)
	if err != nil {
		return policystore.TerminalPage{}, err
	}
	if authorityID == "" {
		authorityID = binding.AuthorityID
	} else if authorityID != binding.AuthorityID {
		return policystore.TerminalPage{}, policystore.ErrAuthorityMismatch
	}
	resolved, principal, requestID := int64(^uint64(0)>>1), "\U0010ffff", "\U0010ffff"
	if cursor != nil {
		resolved, principal, requestID = cursor.ResolvedAt, cursor.Principal, cursor.RequestID
	}
	storageClause := ""
	cutoffUnix := int64(^uint64(0) >> 1)
	if compaction {
		storageClause = " AND storage_kind='full'"
		cutoffUnix = cutoff.UTC().Unix()
	}
	rows, err := store.database.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.RequestColumns[:])+`
		FROM policy_requests WHERE authority_id=? AND state IN ('approved','denied','error')`+storageClause+` AND resolved_at<? AND
		(resolved_at<? OR (resolved_at=? AND principal<?) OR (resolved_at=? AND principal=? AND request_id<?))
		ORDER BY resolved_at DESC,principal DESC,request_id DESC LIMIT ?`, authorityID, cutoffUnix,
		resolved, resolved, principal, resolved, principal, requestID, limit+1)
	if err != nil {
		return policystore.TerminalPage{}, err
	}
	requests, err := scanPolicyRequests(rows, limit+1)
	if err != nil {
		return policystore.TerminalPage{}, err
	}
	page := policystore.TerminalPage{Requests: requests}
	if len(page.Requests) > limit {
		last := page.Requests[limit-1]
		page.Requests = page.Requests[:limit]
		page.Next = &policystore.TerminalCursor{ResolvedAt: last.ResolvedAt.Value, Principal: last.Principal, RequestID: last.RequestID}
	}
	return page, nil
}

func (store *policyDB) ListVotes(ctx context.Context, key policystore.Key, after *policystore.VoteCursor, limit int) (policystore.VotePage, error) {
	limit, err := policyPageLimit(limit)
	if err != nil {
		return policystore.VotePage{}, err
	}
	if _, err := store.Fetch(ctx, key); err != nil {
		return policystore.VotePage{}, err
	}
	operator := ""
	if after != nil {
		operator = after.Operator
	}
	rows, err := store.database.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.VoteColumns[:])+` FROM policy_votes WHERE principal=? AND request_id=? AND operator>? ORDER BY operator LIMIT ?`, key.Principal, key.RequestID, operator, limit+1)
	if err != nil {
		return policystore.VotePage{}, err
	}
	votes, err := scanPolicyVotes(rows, limit+1)
	if err != nil {
		return policystore.VotePage{}, err
	}
	page := policystore.VotePage{Votes: votes}
	if len(page.Votes) > limit {
		last := page.Votes[limit-1]
		page.Votes = page.Votes[:limit]
		page.Next = &policystore.VoteCursor{Operator: last.Operator}
	}
	return page, nil
}

func (store *policyDB) AcquireRecoveryLease(ctx context.Context, key policystore.Key, workerID string, now time.Time, ttl time.Duration) (policystore.Lease, error) {
	if err := policystore.ValidateIdentity(workerID); err != nil {
		return policystore.Lease{}, err
	}
	if ttl != time.Duration(policystore.RecoveryLeaseMaxTTLSeconds)*time.Second {
		return policystore.Lease{}, errors.New("policy recovery lease TTL must be exactly 120 seconds")
	}
	request, err := store.mutatePolicyRequest(ctx, key, func(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
		if request.State.Terminal() || (request.RecoveryLeaseOwner != "" && request.RecoveryLeaseUntil > now.UTC().Unix() && request.RecoveryLeaseUntil <= now.Add(2*time.Minute).UTC().Unix()) {
			return policystore.ErrUnavailable
		}
		if request.RecoveryLeaseGeneration >= uint64(^uint64(0)>>1) {
			return fmt.Errorf("%w: recovery lease generation exhausted", policystore.ErrCorrupt)
		}
		request.RecoveryLeaseGeneration++
		request.RecoveryLeaseOwner = workerID
		request.RecoveryLeaseUntil = now.Add(ttl).UTC().Unix()
		return setExactPolicyReservation(ctx, transaction, request)
	})
	if err != nil {
		return policystore.Lease{}, err
	}
	return policystore.Lease{Key: key, Owner: workerID, Generation: request.RecoveryLeaseGeneration, Until: now.Add(ttl).UTC()}, nil
}

func (store *policyDB) ReleaseRecoveryLease(ctx context.Context, lease policystore.Lease) error {
	_, err := store.mutatePolicyRequest(ctx, lease.Key, func(_ context.Context, _ *sql.Tx, request *policystore.Request) error {
		if !leaseMatches(request, lease) {
			return policystore.ErrLeaseLost
		}
		request.RecoveryLeaseOwner = ""
		request.RecoveryLeaseUntil = 0
		return nil
	})
	return err
}

// ClearRecoveryLease is the exclusive-maintenance operation. Generation is
// advanced before ownership is cleared so every outstanding fence loses.
func (store *policyDB) ClearRecoveryLease(ctx context.Context, reviewID string) error {
	_, err := withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (struct{}, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return struct{}{}, err
		}
		request, err := loadPolicyRequestByReviewID(ctx, transaction, reviewID)
		if err != nil {
			return struct{}{}, err
		}
		// Do not fabricate the durable first-owner-consumption marker.
		if !request.State.Terminal() && request.RecoveryLeaseOwner == "" && request.RecoveryLeaseGeneration == 0 {
			return struct{}{}, policystore.ErrLeaseLost
		}
		if request.RecoveryLeaseGeneration >= uint64(^uint64(0)>>1) {
			return struct{}{}, fmt.Errorf("%w: recovery lease generation exhausted", policystore.ErrCorrupt)
		}
		request.RecoveryLeaseGeneration++
		request.RecoveryLeaseOwner = ""
		request.RecoveryLeaseUntil = 0
		if err := updatePolicyRequest(ctx, transaction, request); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, finishPolicyMutation(ctx, transaction, meta)
	})
	return err
}

// ClearPolicyRecoveryLease exposes only the owner-maintenance lease clear,
// without making the implementation adapter or a generic update primitive
// public.
func (database *DB) ClearPolicyRecoveryLease(ctx context.Context, reviewID string) error {
	return (&policyDB{database: database.db}).ClearRecoveryLease(ctx, reviewID)
}

func scanPolicyRequests(rows *sql.Rows, maximum int) ([]*policystore.Request, error) {
	defer rows.Close()
	var requests []*policystore.Request
	for rows.Next() {
		fields, err := scanPolicyFields(rows, policystore.RequestColumns[:])
		if err != nil {
			return nil, err
		}
		request, err := policystore.RequestFromFields(fields)
		if err != nil {
			return nil, err
		}
		requests = append(requests, &request)
		if len(requests) > maximum {
			return nil, fmt.Errorf("%w: query exceeded bounded page", policystore.ErrCorrupt)
		}
	}
	return requests, rows.Err()
}

func scanPolicyVotes(rows *sql.Rows, maximum int) ([]*policystore.Vote, error) {
	defer rows.Close()
	var votes []*policystore.Vote
	for rows.Next() {
		fields, err := scanPolicyFields(rows, policystore.VoteColumns[:])
		if err != nil {
			return nil, err
		}
		vote, err := policystore.VoteFromFields(fields)
		if err != nil {
			return nil, err
		}
		votes = append(votes, &vote)
		if len(votes) > maximum {
			return nil, fmt.Errorf("%w: vote query exceeded bound", policystore.ErrCorrupt)
		}
	}
	return votes, rows.Err()
}

func loadPolicyVotes(ctx context.Context, queryer policyQueryer, key policystore.Key, unauditedOnly bool) ([]*policystore.Vote, error) {
	clause := ""
	if unauditedOnly {
		clause = " AND audited=0"
	}
	rows, err := queryer.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.VoteColumns[:])+` FROM policy_votes WHERE principal=? AND request_id=?`+clause+` ORDER BY operator`, key.Principal, key.RequestID)
	if err != nil {
		return nil, err
	}
	return scanPolicyVotes(rows, policystore.MaxVotesPerRequest)
}
