package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
)

func (store *policyDB) SnapshotTerminalArchive(ctx context.Context, key policystore.Key, expectedVersion uint64) (policystore.ArchiveRecord, error) {
	if err := validatePolicyKey(key); err != nil {
		return policystore.ArchiveRecord{}, err
	}
	binding, err := store.VerifyAuthorityBinding(ctx)
	if err != nil {
		return policystore.ArchiveRecord{}, err
	}
	request, err := loadPolicyRequest(ctx, store.database, key)
	if err != nil {
		return policystore.ArchiveRecord{}, err
	}
	if request.StorageKind != policystore.StorageFull || !request.State.Terminal() || request.StateVersion != expectedVersion ||
		request.TerminalResponse == nil {
		return policystore.ArchiveRecord{}, policystore.ErrStaleVersion
	}
	votes, err := loadPolicyVotes(ctx, store.database, key, false)
	if err != nil {
		return policystore.ArchiveRecord{}, err
	}
	hash := sha256.Sum256(request.TerminalResponse)
	record := policystore.ArchiveRecord{ArchiveID: binding.ArchiveID, AuthorityID: binding.AuthorityID,
		TerminalResponseSHA256: hex.EncodeToString(hash[:]), TerminalResponseBytes: int64(len(request.TerminalResponse)),
		Request: *request, Votes: make([]policystore.Vote, len(votes))}
	for index, vote := range votes {
		record.Votes[index] = *vote
	}
	if err := record.Validate(); err != nil {
		return policystore.ArchiveRecord{}, fmt.Errorf("snapshot policy archive: %w", err)
	}
	return record, nil
}

func (store *policyDB) CommitTerminalArchive(ctx context.Context, key policystore.Key, expectedVersion uint64, reference policystore.ArchiveRef) (policystore.CompactionResult, error) {
	if err := reference.Validate(); err != nil {
		return policystore.CompactionResult{}, err
	}
	return withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (policystore.CompactionResult, error) {
		meta, err := preparePolicyMutation(ctx, transaction)
		if err != nil {
			return policystore.CompactionResult{}, err
		}
		request, err := loadPolicyRequest(ctx, transaction, key)
		if err != nil {
			return policystore.CompactionResult{}, err
		}
		if request.StorageKind == policystore.StorageTombstone {
			if request.StateVersion == expectedVersion && request.ArchiveRef() != nil && *request.ArchiveRef() == reference {
				return policystore.CompactionResult{Request: request, AlreadyCompacted: true}, nil
			}
			return policystore.CompactionResult{}, policystore.ErrStaleVersion
		}
		if !request.State.Terminal() || request.StateVersion != expectedVersion || reference.ArchiveID != meta.ArchiveID ||
			int64(len(request.TerminalResponse)) != reference.TerminalResponseBytes || digestBytes(request.TerminalResponse) != reference.TerminalResponseSHA256 {
			return policystore.CompactionResult{}, policystore.ErrStaleVersion
		}
		beforeRequest := requestPolicyCounters(request)
		votes, err := loadPolicyVotes(ctx, transaction, key, false)
		if err != nil {
			return policystore.CompactionResult{}, err
		}
		var delta policyCounterDelta
		for _, vote := range votes {
			if err := delta.add(votePolicyCounters(vote), policyCounters{}); err != nil {
				return policystore.CompactionResult{}, err
			}
		}
		request.StorageKind = policystore.StorageTombstone
		request.CanonicalRequest = nil
		request.Payload = nil
		request.TrustedHeadEnvelope = nil
		request.TrustedHeadDigest = policystore.NullableString{}
		request.TrustedHeadKeyID = policystore.NullableString{}
		request.TrustedHeadPublicKey = nil
		request.TrustedHeadEpochBE = nil
		request.TrustedHeadRevisionBE = nil
		request.TrustedHeadRowVersion = policystore.NullableInt64{}
		request.ClaimedHeadEnvelope = nil
		request.ClaimedHeadDigest = policystore.NullableString{}
		request.ClaimedHeadKeyID = policystore.NullableString{}
		request.ClaimedHeadPublicKey = nil
		request.ClaimedHeadEpochBE = nil
		request.ClaimedHeadRevisionBE = nil
		request.ClaimedHeadRowVersion = policystore.NullableInt64{}
		request.FrozenSignerKeyID = policystore.NullableString{}
		request.FrozenSignerPublicKey = nil
		request.ReviewJSON = nil
		request.ReviewSHA256 = policystore.NullableString{}
		request.ReviewRenderedBytes = policystore.NullableInt64{}
		request.ReviewItemCount = policystore.NullableInt64{}
		request.ReviewRendererVersion = policystore.NullableString{}
		request.ReviewRulesDigest = policystore.NullableString{}
		request.EligibleVotersJSON = nil
		request.EligibleVotersSHA256 = policystore.NullableString{}
		request.EligibleVoterCount = policystore.NullableInt64{}
		request.ResultEnvelope = nil
		request.PendingResponse = nil
		request.TerminalResponse = nil
		request.ArchiveID = policystore.NullableString{Value: reference.ArchiveID, Valid: true}
		request.ArchiveObjectSHA256 = policystore.NullableString{Value: reference.ObjectSHA256, Valid: true}
		request.ArchiveRecordBytes = policystore.NullableInt64{Value: reference.RecordBytes, Valid: true}
		request.TerminalResponseSHA256 = policystore.NullableString{Value: reference.TerminalResponseSHA256, Valid: true}
		request.TerminalResponseBytes = policystore.NullableInt64{Value: reference.TerminalResponseBytes, Valid: true}
		request.CompactionDeleteGuard = true
		if err := updatePolicyRequest(ctx, transaction, request); err != nil {
			return policystore.CompactionResult{}, err
		}
		request.CompactionDeleteGuard = false // cleared atomically by the compaction trigger
		if err := delta.add(beforeRequest, requestPolicyCounters(request)); err != nil {
			return policystore.CompactionResult{}, err
		}
		if err := finishPolicyMutation(ctx, transaction, meta, delta); err != nil {
			return policystore.CompactionResult{}, err
		}
		stored, err := loadPolicyRequest(ctx, transaction, key)
		if err != nil {
			return policystore.CompactionResult{}, err
		}
		return policystore.CompactionResult{Request: stored}, nil
	})
}

// ResolveTerminalArchive validates archive bytes against every retained
// tombstone field and returns the canonical response only after equality.
func ResolveTerminalArchive(tombstone *policystore.Request, encoded []byte) ([]byte, error) {
	if tombstone == nil || tombstone.StorageKind != policystore.StorageTombstone {
		return nil, errors.New("policy archive resolution requires a tombstone")
	}
	reference := tombstone.ArchiveRef()
	if reference == nil || reference.Validate() != nil || int64(len(encoded)) != reference.RecordBytes || digestBytes(encoded) != reference.ObjectSHA256 {
		return nil, fmt.Errorf("%w: archive object reference mismatch", policystore.ErrCorrupt)
	}
	tombstoneFields, err := policystore.RequestFields(*tombstone)
	if err != nil {
		return nil, fmt.Errorf("%w: tombstone field image: %v", policystore.ErrCorrupt, err)
	}
	tombstoneCharge, err := policystore.RequestLogicalCharge(tombstoneFields)
	if err != nil || tombstone.LogicalBytes != tombstoneCharge {
		return nil, fmt.Errorf("%w: tombstone logical byte mismatch", policystore.ErrCorrupt)
	}
	record, err := policystore.DecodeArchiveRecord(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", policystore.ErrCorrupt, err)
	}
	if record.ArchiveID != reference.ArchiveID || record.AuthorityID != tombstone.AuthorityID ||
		record.TerminalResponseSHA256 != reference.TerminalResponseSHA256 || record.TerminalResponseBytes != reference.TerminalResponseBytes {
		return nil, fmt.Errorf("%w: archive outer binding mismatch", policystore.ErrCorrupt)
	}
	want := *tombstone
	want.StorageKind = policystore.StorageFull
	want.CanonicalRequest = slices.Clone(record.Request.CanonicalRequest)
	want.Payload = slices.Clone(record.Request.Payload)
	want.TrustedHeadEnvelope = slices.Clone(record.Request.TrustedHeadEnvelope)
	want.TrustedHeadDigest = record.Request.TrustedHeadDigest
	want.TrustedHeadKeyID = record.Request.TrustedHeadKeyID
	want.TrustedHeadPublicKey = slices.Clone(record.Request.TrustedHeadPublicKey)
	want.TrustedHeadEpochBE = slices.Clone(record.Request.TrustedHeadEpochBE)
	want.TrustedHeadRevisionBE = slices.Clone(record.Request.TrustedHeadRevisionBE)
	want.TrustedHeadRowVersion = record.Request.TrustedHeadRowVersion
	want.ClaimedHeadEnvelope = slices.Clone(record.Request.ClaimedHeadEnvelope)
	want.ClaimedHeadDigest = record.Request.ClaimedHeadDigest
	want.ClaimedHeadKeyID = record.Request.ClaimedHeadKeyID
	want.ClaimedHeadPublicKey = slices.Clone(record.Request.ClaimedHeadPublicKey)
	want.ClaimedHeadEpochBE = slices.Clone(record.Request.ClaimedHeadEpochBE)
	want.ClaimedHeadRevisionBE = slices.Clone(record.Request.ClaimedHeadRevisionBE)
	want.ClaimedHeadRowVersion = record.Request.ClaimedHeadRowVersion
	want.FrozenSignerKeyID = record.Request.FrozenSignerKeyID
	want.FrozenSignerPublicKey = slices.Clone(record.Request.FrozenSignerPublicKey)
	want.ReviewJSON = slices.Clone(record.Request.ReviewJSON)
	want.ReviewSHA256 = record.Request.ReviewSHA256
	want.ReviewRenderedBytes = record.Request.ReviewRenderedBytes
	want.ReviewItemCount = record.Request.ReviewItemCount
	want.ReviewRendererVersion = record.Request.ReviewRendererVersion
	want.ReviewRulesDigest = record.Request.ReviewRulesDigest
	want.EligibleVotersJSON = slices.Clone(record.Request.EligibleVotersJSON)
	want.EligibleVotersSHA256 = record.Request.EligibleVotersSHA256
	want.EligibleVoterCount = record.Request.EligibleVoterCount
	want.ResultEnvelope = slices.Clone(record.Request.ResultEnvelope)
	want.PendingResponse = slices.Clone(record.Request.PendingResponse)
	want.TerminalResponse = slices.Clone(record.Request.TerminalResponse)
	want.ArchiveID = policystore.NullableString{}
	want.ArchiveObjectSHA256 = policystore.NullableString{}
	want.ArchiveRecordBytes = policystore.NullableInt64{}
	want.TerminalResponseSHA256 = policystore.NullableString{}
	want.TerminalResponseBytes = policystore.NullableInt64{}
	// Exactly storage_kind and logical_bytes transform. The complete archived
	// full image must otherwise equal the reconstruction from retained fields.
	fields, err := policystore.RequestFields(want)
	if err != nil {
		return nil, err
	}
	want.LogicalBytes, err = policystore.RequestLogicalCharge(fields)
	if err != nil {
		return nil, err
	}
	if !policyRequestsEqual(want, record.Request) {
		return nil, fmt.Errorf("%w: archive record differs from retained tombstone", policystore.ErrCorrupt)
	}
	return slices.Clone(record.Request.TerminalResponse), nil
}

func policyRequestsEqual(left, right policystore.Request) bool {
	leftFields, leftErr := policystore.RequestFields(left)
	rightFields, rightErr := policystore.RequestFields(right)
	if leftErr != nil || rightErr != nil || len(leftFields) != len(rightFields) {
		return false
	}
	for index := range leftFields {
		if leftFields[index].Null != rightFields[index].Null || !bytes.Equal(leftFields[index].Bytes(), rightFields[index].Bytes()) {
			return false
		}
	}
	return true
}
