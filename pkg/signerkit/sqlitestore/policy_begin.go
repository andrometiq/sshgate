package sqlitestore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func (store *policyDB) Lookup(ctx context.Context, key policystore.Key, tuple policystore.RequestTuple) (policystore.LookupResult, error) {
	if err := validatePolicyLookup(key, tuple); err != nil {
		return policystore.LookupResult{}, err
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		return policystore.LookupResult{}, err
	}
	request, err := loadPolicyRequest(ctx, store.database, key)
	if errors.Is(err, policystore.ErrNotFound) {
		return policystore.LookupResult{Kind: policystore.LookupAbsent}, nil
	}
	if err != nil {
		return policystore.LookupResult{}, err
	}
	return classifyPolicyLookup(request, tuple), nil
}

func (store *policyDB) Fetch(ctx context.Context, key policystore.Key) (policystore.FetchResult, error) {
	if err := validatePolicyKey(key); err != nil {
		return policystore.FetchResult{}, err
	}
	if _, err := store.VerifyAuthorityBinding(ctx); err != nil {
		return policystore.FetchResult{}, err
	}
	request, err := loadPolicyRequest(ctx, store.database, key)
	if err != nil {
		return policystore.FetchResult{}, err
	}
	return policyFetchResult(request), nil
}

func (store *policyDB) Begin(ctx context.Context, input policystore.BeginInput) (policystore.BeginResult, error) {
	decoded, err := validatePolicyBeginInput(input)
	if err != nil {
		return policystore.BeginResult{}, err
	}
	return withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (policystore.BeginResult, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return policystore.BeginResult{}, err
		}
		if input.AuthorityID != meta.AuthorityID {
			return policystore.BeginResult{}, fmt.Errorf("%w: request authority differs from bound authority", policystore.ErrAuthorityMismatch)
		}
		existing, err := loadPolicyRequest(ctx, transaction, input.Key)
		if err == nil {
			lookup := classifyPolicyLookup(existing, input.Tuple)
			return policystore.BeginResult{Lookup: lookup, Request: lookup.Request}, nil
		}
		if !errors.Is(err, policystore.ErrNotFound) {
			return policystore.BeginResult{}, err
		}
		if err := verifyCurrentPolicyKey(ctx, transaction, meta.AuthorityID, input.SignerKeyID, input.SignerPublicKey); err != nil {
			return policystore.BeginResult{}, err
		}

		head, err := loadPolicyHead(ctx, transaction, meta.AuthorityID, input.Tuple.HostKeyFP)
		if err != nil && !errors.Is(err, policystore.ErrNotFound) {
			return policystore.BeginResult{}, err
		}
		if err == nil {
			if err := validatePolicyHeadRecord(head, meta.AuthorityID); err != nil {
				return policystore.BeginResult{}, err
			}
		} else {
			head = nil
		}

		errorCode := policywire.ErrorCode("")
		if input.Tuple.ExpectedSignerKeyID != input.SignerKeyID {
			errorCode = policywire.ErrorSignerKeyChanged
		}
		if errorCode == "" {
			var active int
			if err := transaction.QueryRowContext(ctx, `SELECT count(*) FROM policy_requests WHERE authority_id=? AND host_key_fp=? AND storage_kind='full' AND state IN ('received_unaudited','pending','approved_materializing','approved_unexposed','no_op_unexposed','denial_received','error_received')`, meta.AuthorityID, input.Tuple.HostKeyFP).Scan(&active); err != nil {
				return policystore.BeginResult{}, fmt.Errorf("check active policy host: %w", err)
			}
			if active != 0 {
				errorCode = policywire.ErrorPolicyRequestInProgress
			}
		}
		classification := policyauthority.Classify(decoded, authorityHead(head), input.SignerPublicKey)
		if errorCode == "" {
			errorCode = classification.ErrorCode
		}

		request, err := buildPolicyAdmission(ctx, transaction, meta, input, decoded, head, classification.NoOp, errorCode)
		if err != nil {
			return policystore.BeginResult{}, err
		}
		if err := enforcePolicyAdmission(ctx, transaction, meta, request, errorCode != "", input.Now); err != nil {
			return policystore.BeginResult{}, err
		}
		if err := insertPolicyRequest(ctx, transaction, request); err != nil {
			return policystore.BeginResult{}, err
		}
		if err := finishPolicyMutation(ctx, transaction, meta); err != nil {
			return policystore.BeginResult{}, err
		}
		lookup := classifyPolicyLookup(request, input.Tuple)
		return policystore.BeginResult{Lookup: lookup, Request: request}, nil
	})
}

func validatePolicyKey(key policystore.Key) error {
	if err := policystore.ValidateIdentity(key.Principal); err != nil {
		return fmt.Errorf("policy principal: %w", err)
	}
	// The strict wire decoder owns the request-id grammar. Decode a minimal
	// shape nowhere: the same grammar is short and is also enforced by SQLite.
	if len(key.RequestID) != 35 || key.RequestID[:3] != "pm_" || !lowerHex(key.RequestID[3:]) {
		return errors.New("policy request ID must be pm_ plus 32 lowercase hexadecimal characters")
	}
	return nil
}

func validatePolicyLookup(key policystore.Key, tuple policystore.RequestTuple) error {
	if err := validatePolicyKey(key); err != nil {
		return err
	}
	if tuple.RequestID != key.RequestID || tuple.Purpose != policywire.Purpose {
		return errors.New("policy lookup tuple identity mismatch")
	}
	if tuple.HostKeyFP == "" || len(tuple.ExpectedSignerKeyID) != 64 || !lowerHex(tuple.ExpectedSignerKeyID) ||
		len(tuple.PayloadSHA256) != 64 || !lowerHex(tuple.PayloadSHA256) ||
		(!tuple.Bootstrap && (len(tuple.ExpectedHeadDigest) != 64 || !lowerHex(tuple.ExpectedHeadDigest))) ||
		(tuple.Bootstrap && tuple.ExpectedHeadDigest != "") {
		return errors.New("policy lookup tuple is malformed")
	}
	return nil
}

func validatePolicyBeginInput(input policystore.BeginInput) (policywire.DecodedRequest, error) {
	if err := validatePolicyLookup(input.Key, input.Tuple); err != nil {
		return policywire.DecodedRequest{}, err
	}
	if err := policystore.ValidateIdentity(input.RequesterPrincipal); err != nil {
		return policywire.DecodedRequest{}, fmt.Errorf("policy requester principal: %w", err)
	}
	if input.RequesterPrincipal != input.Key.Principal || !policyauthority.ValidAuthorityID(input.AuthorityID) {
		return policywire.DecodedRequest{}, errors.New("policy begin identity mismatch")
	}
	if len(input.ReviewID) != 35 || input.ReviewID[:3] != "pr_" || !lowerHex(input.ReviewID[3:]) {
		return policywire.DecodedRequest{}, errors.New("policy review ID is malformed")
	}
	keyID, err := policy.SignerKeyID(input.SignerPublicKey)
	if err != nil || keyID != input.SignerKeyID {
		return policywire.DecodedRequest{}, errors.New("policy signer pair is malformed")
	}
	decoded, err := policywire.DecodeRequest(input.CanonicalRequest)
	if err != nil {
		return policywire.DecodedRequest{}, err
	}
	if !bytes.Equal(decoded.Payload, input.Payload) {
		return policywire.DecodedRequest{}, errors.New("policy canonical request payload differs from supplied payload")
	}
	payloadSHA, _, err := policywire.PayloadDigests(decoded.Payload)
	if err != nil {
		return policywire.DecodedRequest{}, err
	}
	want := policystore.RequestTuple{RequestID: decoded.Wire.RequestID, Purpose: policywire.Purpose,
		HostKeyFP: decoded.Wire.HostKeyFP, ExpectedSignerKeyID: decoded.Wire.ExpectedSignerKeyID,
		PayloadSHA256: payloadSHA, ExpectedHeadDigest: decoded.Wire.ExpectedHeadDigest, Bootstrap: decoded.Wire.Bootstrap}
	if input.Tuple != want {
		return policywire.DecodedRequest{}, errors.New("policy decoded request tuple differs from supplied tuple")
	}
	return decoded, nil
}

func classifyPolicyLookup(request *policystore.Request, tuple policystore.RequestTuple) policystore.LookupResult {
	if !policyTupleMatches(request, tuple) {
		return policystore.LookupResult{Kind: policystore.LookupConflict}
	}
	result := policystore.LookupResult{Kind: policystore.LookupExact, Request: request}
	if request.StorageKind == policystore.StorageTombstone {
		result.Class, result.Archive = policystore.RowTombstone, request.ArchiveRef()
	} else if request.State.Terminal() {
		result.Class = policystore.RowTerminal
	} else {
		result.Class = policystore.RowLive
	}
	if result.Class == policystore.RowLive && request.SubmissionAudited && request.State != policystore.StateRejectionUnaudited && request.State != policystore.StateRejectionErrorReceived {
		result.Visibility = policystore.VisibilityPending
	}
	return result
}

func policyFetchResult(request *policystore.Request) policystore.FetchResult {
	result := policystore.FetchResult{State: request.State}
	if request.StorageKind == policystore.StorageTombstone {
		result.Class, result.Archive = policystore.RowTombstone, request.ArchiveRef()
		if request.TerminalHTTPStatus.Valid {
			result.TerminalHTTPStatus = int(request.TerminalHTTPStatus.Value)
		}
	} else if request.State.Terminal() {
		result.Class = policystore.RowTerminal
		result.TerminalResponse = slices.Clone(request.TerminalResponse)
		if request.TerminalHTTPStatus.Valid {
			result.TerminalHTTPStatus = int(request.TerminalHTTPStatus.Value)
		}
	} else {
		result.Class = policystore.RowLive
	}
	if result.Class == policystore.RowLive && request.SubmissionAudited && request.State != policystore.StateRejectionUnaudited && request.State != policystore.StateRejectionErrorReceived {
		result.Visibility = policystore.VisibilityPending
	}
	return result
}

func policyTupleMatches(request *policystore.Request, tuple policystore.RequestTuple) bool {
	return request.RequestID == tuple.RequestID && request.Purpose == tuple.Purpose && request.HostKeyFP == tuple.HostKeyFP &&
		request.ExpectedSignerKeyID == tuple.ExpectedSignerKeyID && request.PayloadSHA256 == tuple.PayloadSHA256 &&
		request.ExpectedHeadDigest == tuple.ExpectedHeadDigest && request.Bootstrap == tuple.Bootstrap &&
		request.TupleDigest == policyauthority.TupleDigest(tuple)
}

func verifyCurrentPolicyKey(ctx context.Context, queryer policyQueryer, authorityID, keyID string, publicKey ed25519.PublicKey) error {
	var storedAuthority string
	var storedPublic []byte
	err := queryer.QueryRowContext(ctx, `SELECT authority_id,signer_public_key FROM policy_authority_key_bindings WHERE signer_key_id=?`, keyID).Scan(&storedAuthority, &storedPublic)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: current policy key is not bound", policystore.ErrAuthorityMismatch)
	}
	if err != nil {
		return fmt.Errorf("verify current policy key: %w", err)
	}
	if storedAuthority != authorityID || !bytes.Equal(storedPublic, publicKey) {
		return fmt.Errorf("%w: current policy key binding differs", policystore.ErrAuthorityMismatch)
	}
	return nil
}

func authorityHead(head *policystore.Head) *policyauthority.Head {
	if head == nil {
		return nil
	}
	return &policyauthority.Head{ManifestEnvelope: slices.Clone(head.ManifestEnvelope), BaseDigest: head.BaseDigest,
		SignerKeyID: head.SignerKeyID, SignerPublicKey: slices.Clone(head.SignerPublicKey)}
}

func buildPolicyAdmission(ctx context.Context, transaction *sql.Tx, meta policyMeta, input policystore.BeginInput,
	decoded policywire.DecodedRequest, head *policystore.Head, noOp bool, errorCode policywire.ErrorCode) (*policystore.Request, error) {
	payloadSHA, baseDigest, err := policywire.PayloadDigests(input.Payload)
	if err != nil {
		return nil, err
	}
	var epoch, revision [8]byte
	binary.BigEndian.PutUint64(epoch[:], decoded.Manifest.Epoch)
	binary.BigEndian.PutUint64(revision[:], decoded.Manifest.Revision)
	now := input.Now.UTC().Unix()
	request := &policystore.Request{
		Principal: input.Key.Principal, RequestID: input.Key.RequestID, ReviewID: input.ReviewID,
		AuthoritySingleton: 1, AuthorityID: meta.AuthorityID, StorageKind: policystore.StorageFull,
		Purpose: policywire.Purpose, CanonicalRequest: slices.Clone(input.CanonicalRequest), Payload: slices.Clone(input.Payload),
		TupleDigest: policyauthority.TupleDigest(input.Tuple), PayloadSHA256: payloadSHA, BaseDigest: baseDigest,
		HostKeyFP: input.Tuple.HostKeyFP, ExpectedHeadDigest: input.Tuple.ExpectedHeadDigest,
		ExpectedSignerKeyID: input.Tuple.ExpectedSignerKeyID, Bootstrap: input.Tuple.Bootstrap,
		FrozenSignerKeyID: policystore.NullableString{Value: input.SignerKeyID, Valid: true}, FrozenSignerPublicKey: slices.Clone(input.SignerPublicKey),
		EpochBE: epoch[:], RevisionBE: revision[:], MissAction: string(decoded.Manifest.MissAction), Growth: string(decoded.Manifest.Growth),
		EntryCount: int64(len(decoded.Manifest.Entries)), RevocationCount: int64(len(decoded.Manifest.RevokedPermitIDs)),
		VoteStepUpRequired: meta.VoteStepUpRequired, VoteAuthMethodsJSON: slices.Clone(meta.VoteAuthMethodsJSON),
		VoteAuthMethodsSHA256: digestBytes(meta.VoteAuthMethodsJSON), RequiredApprovals: int64(meta.RequiredApprovals),
		DenyVeto: meta.DenyVeto, AllowSelfApprove: meta.AllowSelfApprove, RequesterPrincipal: input.RequesterPrincipal,
		StateVersion: 1, NoOp: noOp, CreatedAt: now, UpdatedAt: now,
	}
	copyTrustedHead(request, head)
	var trustedManifest *policy.BaseManifest
	if head != nil {
		manifest, verifyErr := policy.VerifyBaseManifest(head.ManifestEnvelope, head.SignerPublicKey)
		if verifyErr != nil {
			return nil, fmt.Errorf("%w: trusted review head: %v", policystore.ErrCorrupt, verifyErr)
		}
		trustedManifest = &manifest
	}
	if !noOp {
		changes, changesErr := policyreview.Changes(trustedManifest, decoded.Manifest)
		if changesErr == nil {
			request.LogicalChangeCount = int64(changes.LogicalChanges)
		} else if errorCode == "" {
			return nil, changesErr
		}
	}
	if errorCode != "" {
		request.State = policystore.StateRejectionUnaudited
		request.ErrorFamily = policystore.ErrorFamilySemantic
		request.FailureCode = errorCode
		components, err := policystore.Matrix2AReservation(input.CanonicalRequest, input.Payload)
		if err != nil {
			return nil, err
		}
		request.ReservedBytes, err = policystore.AdmissionRemaining(components, nil)
		return request, err
	}

	if err := validatePolicyReview(meta, input, request); err != nil {
		return nil, err
	}
	voters, err := freezePolicyVoters(ctx, transaction, meta, input.RequesterPrincipal)
	if err != nil {
		return nil, err
	}
	if uint64(len(voters)) < meta.RequiredApprovals {
		return nil, fmt.Errorf("%w: frozen electorate cannot reach quorum", policystore.ErrCapacity)
	}
	votersJSON, err := json.Marshal(voters)
	if err != nil {
		return nil, err
	}
	request.EligibleVotersJSON = votersJSON
	request.EligibleVotersSHA256 = policystore.NullableString{Value: digestBytes(votersJSON), Valid: true}
	request.EligibleVoterCount = policystore.NullableInt64{Value: int64(len(voters)), Valid: true}
	pending, err := policywire.MarshalResponse(policywire.Response{RequestID: input.Key.RequestID, AuthorityID: meta.AuthorityID,
		Purpose: policywire.Purpose, Status: policywire.StatusPending, PayloadSHA256: payloadSHA, BaseDigest: baseDigest,
		SignerKeyID: input.SignerKeyID, Retryable: false})
	if err != nil {
		return nil, err
	}
	request.PendingResponse = pending
	request.State = policystore.StateReceivedUnaudited
	candidate, err := policystore.CandidateHeadImage(policystore.CandidateHeadInput{AuthorityID: meta.AuthorityID,
		HostKeyFP: input.Tuple.HostKeyFP, Payload: input.Payload, PayloadSHA256: payloadSHA, BaseDigest: baseDigest,
		SignerKeyID: input.SignerKeyID, SignerPublicKey: input.SignerPublicKey, RowVersion: candidateRowVersion(head), UpdatedAt: now})
	if err != nil {
		return nil, err
	}
	components, err := policystore.AcceptedReservation(input.CanonicalRequest, input.Payload, candidate, head)
	if err != nil {
		return nil, err
	}
	request.ReservedBytes, err = policystore.AdmissionRemaining(components, pending)
	return request, err
}

func validatePolicyReview(meta policyMeta, input policystore.BeginInput, request *policystore.Request) error {
	if len(input.ReviewJSON) == 0 || len(input.ReviewJSON) > 128<<10 || !json.Valid(input.ReviewJSON) ||
		input.ReviewRenderedBytes != int64(len(input.ReviewJSON)) || input.ReviewItemCount < 0 || input.ReviewItemCount > 40 ||
		input.ReviewRendererVersion != meta.ReviewRendererVersion || input.ReviewRulesDigest != meta.ReviewRulesDigest {
		return errors.New("policy review does not match bound renderer and bounds")
	}
	request.ReviewJSON = slices.Clone(input.ReviewJSON)
	request.ReviewSHA256 = policystore.NullableString{Value: digestBytes(input.ReviewJSON), Valid: true}
	request.ReviewRenderedBytes = policystore.NullableInt64{Value: input.ReviewRenderedBytes, Valid: true}
	request.ReviewItemCount = policystore.NullableInt64{Value: input.ReviewItemCount, Valid: true}
	request.ReviewRendererVersion = policystore.NullableString{Value: input.ReviewRendererVersion, Valid: true}
	request.ReviewRulesDigest = policystore.NullableString{Value: input.ReviewRulesDigest, Valid: true}
	return nil
}

func freezePolicyVoters(ctx context.Context, queryer policyQueryer, meta policyMeta, requester string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT u.id FROM users u WHERE u.role=? AND (?=1 OR u.id<>?) AND ((?=1 AND EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id)) OR (?=0 AND (EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id) OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)))) ORDER BY u.id`,
		meta.PolicyVoterRole, boolInteger(meta.AllowSelfApprove), requester, boolInteger(meta.VoteStepUpRequired), boolInteger(meta.VoteStepUpRequired))
	if err != nil {
		return nil, fmt.Errorf("freeze policy voters: %w", err)
	}
	defer rows.Close()
	var voters []string
	for rows.Next() {
		var voter string
		if err := rows.Scan(&voter); err != nil {
			return nil, err
		}
		if err := policystore.ValidateIdentity(voter); err != nil {
			return nil, fmt.Errorf("%w: eligible voter identity: %v", policystore.ErrCorrupt, err)
		}
		voters = append(voters, voter)
		if len(voters) > policystore.MaxVotesPerRequest {
			return nil, fmt.Errorf("%w: eligible voter set exceeds limit", policystore.ErrCapacity)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !sort.StringsAreSorted(voters) {
		return nil, fmt.Errorf("%w: voter query is not sorted", policystore.ErrCorrupt)
	}
	return voters, nil
}

func copyTrustedHead(request *policystore.Request, head *policystore.Head) {
	if head == nil {
		return
	}
	request.TrustedHeadEnvelope = slices.Clone(head.ManifestEnvelope)
	request.TrustedHeadDigest = policystore.NullableString{Value: head.BaseDigest, Valid: true}
	request.TrustedHeadKeyID = policystore.NullableString{Value: head.SignerKeyID, Valid: true}
	request.TrustedHeadPublicKey = slices.Clone(head.SignerPublicKey)
	request.TrustedHeadEpochBE = slices.Clone(head.EpochBE)
	request.TrustedHeadRevisionBE = slices.Clone(head.RevisionBE)
	request.TrustedHeadRowVersion = policystore.NullableInt64{Value: int64(head.RowVersion), Valid: true}
}

func enforcePolicyAdmission(ctx context.Context, queryer policyQueryer, meta policyMeta, request *policystore.Request, matrix2A bool, now time.Time) error {
	var full, activeGlobal, activePrincipal int64
	if err := queryer.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(CASE WHEN state IN ('received_unaudited','pending','approved_materializing','approved_unexposed','no_op_unexposed','denial_received','error_received') THEN 1 ELSE 0 END),0),coalesce(sum(CASE WHEN principal=? AND state IN ('received_unaudited','pending','approved_materializing','approved_unexposed','no_op_unexposed','denial_received','error_received') THEN 1 ELSE 0 END),0) FROM policy_requests WHERE storage_kind='full'`, request.Principal).Scan(&full, &activeGlobal, &activePrincipal); err != nil {
		return fmt.Errorf("check policy admission counts: %w", err)
	}
	if err := checkPolicyAdmissionCounts(meta, full, activeGlobal, activePrincipal, matrix2A, request.Bootstrap); err != nil {
		return err
	}
	if matrix2A {
		var recent, retained int64
		var retainedBytes sql.NullInt64
		cutoff := now.UTC().Unix() - policystore.RejectionWindowSeconds
		if err := queryer.QueryRowContext(ctx, `SELECT coalesce(sum(CASE WHEN created_at>? THEN 1 ELSE 0 END),0),count(*),sum(reserved_bytes) FROM policy_requests WHERE principal=? AND error_family='semantic-rejection' AND failure_code IN ('invalid_policy_request','policy_request_in_progress','signer_key_changed','stale_policy_head','policy_key_transition_required')`, cutoff, request.Principal).Scan(&recent, &retained, &retainedBytes); err != nil {
			return fmt.Errorf("check policy rejection budgets: %w", err)
		}
		if recent >= policystore.RejectionWindowLimit {
			oldest := int64(0)
			_ = queryer.QueryRowContext(ctx, `SELECT min(created_at) FROM (SELECT created_at FROM policy_requests WHERE principal=? AND error_family='semantic-rejection' AND failure_code IN ('invalid_policy_request','policy_request_in_progress','signer_key_changed','stale_policy_head','policy_key_transition_required') AND created_at>? ORDER BY created_at LIMIT 16)`, request.Principal, cutoff).Scan(&oldest)
			return &policystore.CapacityError{Kind: policystore.CapacityWindow, RetryAfter: time.Duration(oldest+policystore.RejectionWindowSeconds-now.UTC().Unix()) * time.Second}
		}
		if retained >= policystore.RejectionRetainedRowLimit {
			return &policystore.CapacityError{Kind: policystore.CapacityRetainedRows}
		}
		if retainedBytes.Valid && uint64(retainedBytes.Int64)+request.ReservedBytes > meta.MaxRejectionReservedBytesPerPrincipal {
			return &policystore.CapacityError{Kind: policystore.CapacityRetainedBytes}
		}
	}
	if err := setPolicyRequestLogicalBytes(request); err != nil {
		return err
	}
	addition, err := addPolicyBytes(request.LogicalBytes, request.ReservedBytes)
	if err != nil {
		return &policystore.CapacityError{Kind: policystore.CapacityGlobalHeadroom}
	}
	current, err := addPolicyBytes(meta.LogicalUsedBytes, meta.LogicalReservedBytes)
	if err != nil || addition > meta.MaxLogicalBytes || current > meta.MaxLogicalBytes-addition {
		return &policystore.CapacityError{Kind: policystore.CapacityGlobalHeadroom}
	}
	return nil
}

func checkPolicyAdmissionCounts(meta policyMeta, full, activeGlobal, activePrincipal int64, matrix2A, bootstrap bool) error {
	if full >= int64(meta.MaxRequests) || (!matrix2A && (activeGlobal >= int64(meta.MaxActiveGlobal) || activePrincipal >= int64(meta.MaxActivePerPrincipal))) {
		return &policystore.CapacityError{Kind: policystore.CapacityGlobalHeadroom}
	}
	if !matrix2A && bootstrap && meta.HeadCount >= meta.MaxHeads {
		return &policystore.CapacityError{Kind: policystore.CapacityGlobalHeadroom}
	}
	return nil
}

func candidateRowVersion(head *policystore.Head) uint64 {
	if head == nil {
		return 1
	}
	return head.RowVersion + 1
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func lowerHex(value string) bool {
	for index := range value {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func addPolicyBytes(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if ^uint64(0)-total < value {
			return 0, errors.New("policy byte count overflow")
		}
		total += value
	}
	return total, nil
}
