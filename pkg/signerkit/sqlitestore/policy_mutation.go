package sqlitestore

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func preparePolicyMutation(ctx context.Context, transaction *sql.Tx) (policyMeta, error) {
	meta, err := readPolicyMeta(ctx, transaction)
	if err != nil {
		return policyMeta{}, err
	}
	if err := validatePolicyMeta(meta); err != nil {
		return policyMeta{}, err
	}
	return meta, nil
}

type policyCounterDelta struct {
	before policyCounters
	after  policyCounters
}

func (delta *policyCounterDelta) add(before, after policyCounters) error {
	if err := addPolicyCounters(&delta.before, before); err != nil {
		return err
	}
	return addPolicyCounters(&delta.after, after)
}

func addPolicyCounters(total *policyCounters, add policyCounters) error {
	for _, pair := range []struct {
		name  string
		total *uint64
		add   uint64
	}{
		{"logical_used_bytes", &total.Used, add.Used},
		{"logical_reserved_bytes", &total.Reserved, add.Reserved},
		{"full_request_count", &total.Full, add.Full},
		{"head_count", &total.Heads, add.Heads},
		{"active_count", &total.Active, add.Active},
	} {
		if math.MaxUint64-*pair.total < pair.add {
			return fmt.Errorf("%w: %s mutation delta overflow", policystore.ErrCounterDrift, pair.name)
		}
		*pair.total += pair.add
	}
	return nil
}

func requestPolicyCounters(request *policystore.Request) policyCounters {
	if request == nil {
		return policyCounters{}
	}
	counters := policyCounters{Used: request.LogicalBytes, Reserved: request.ReservedBytes}
	if request.StorageKind == policystore.StorageFull {
		counters.Full = 1
		if request.State.Active() {
			counters.Active = 1
		}
	}
	return counters
}

func votePolicyCounters(vote *policystore.Vote) policyCounters {
	if vote == nil {
		return policyCounters{}
	}
	return policyCounters{Used: vote.LogicalBytes}
}

func headPolicyCounters(head *policystore.Head) policyCounters {
	if head == nil {
		return policyCounters{}
	}
	return policyCounters{Used: head.LogicalBytes, Heads: 1}
}

func applyPolicyCounterDelta(name string, stored, before, after uint64) (uint64, error) {
	if stored < before {
		return 0, fmt.Errorf("%w: %s mutation delta underflow", policystore.ErrCounterDrift, name)
	}
	next := stored - before
	if math.MaxUint64-next < after || next+after > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %s mutation delta overflow", policystore.ErrCounterDrift, name)
	}
	return next + after, nil
}

func finishPolicyMutation(ctx context.Context, transaction *sql.Tx, meta policyMeta, delta policyCounterDelta) error {
	var counters policyCounters
	updates := []struct {
		name                  string
		stored, before, after uint64
		output                *uint64
	}{
		{"logical_used_bytes", meta.LogicalUsedBytes, delta.before.Used, delta.after.Used, &counters.Used},
		{"logical_reserved_bytes", meta.LogicalReservedBytes, delta.before.Reserved, delta.after.Reserved, &counters.Reserved},
		{"full_request_count", meta.FullRequestCount, delta.before.Full, delta.after.Full, &counters.Full},
		{"head_count", meta.HeadCount, delta.before.Heads, delta.after.Heads, &counters.Heads},
		{"active_count", meta.ActiveCount, delta.before.Active, delta.after.Active, &counters.Active},
	}
	for _, update := range updates {
		next, err := applyPolicyCounterDelta(update.name, update.stored, update.before, update.after)
		if err != nil {
			return err
		}
		*update.output = next
	}
	result, err := transaction.ExecContext(ctx, `UPDATE policy_authority_meta SET
		logical_used_bytes=?,logical_reserved_bytes=?,full_request_count=?,head_count=?,active_count=?
		WHERE singleton=1 AND logical_used_bytes=? AND logical_reserved_bytes=?
		AND full_request_count=? AND head_count=? AND active_count=?`,
		policyInteger(counters.Used), policyInteger(counters.Reserved), policyInteger(counters.Full),
		policyInteger(counters.Heads), policyInteger(counters.Active), policyInteger(meta.LogicalUsedBytes),
		policyInteger(meta.LogicalReservedBytes), policyInteger(meta.FullRequestCount),
		policyInteger(meta.HeadCount), policyInteger(meta.ActiveCount))
	if err != nil {
		return fmt.Errorf("update policy counters: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update policy counters rows affected: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("%w: authority counters changed during mutation", policystore.ErrCounterDrift)
	}
	return nil
}

func policyInteger(value uint64) int64 {
	if value > math.MaxInt64 {
		panic("policy integer crossed MaxInt64 after checked validation")
	}
	return int64(value)
}

func setPolicyRequestLogicalBytes(request *policystore.Request) error {
	request.LogicalBytes = 0
	fields, err := policystore.RequestFields(*request)
	if err != nil {
		return err
	}
	charge, err := policystore.RequestLogicalCharge(fields)
	if err != nil {
		return err
	}
	if charge > math.MaxInt64 {
		return errors.New("policy request logical bytes exceed MaxInt64")
	}
	request.LogicalBytes = charge
	return nil
}

func insertPolicyRequest(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
	if err := setPolicyRequestLogicalBytes(request); err != nil {
		return err
	}
	fields, err := policystore.RequestFields(*request)
	if err != nil {
		return err
	}
	values, err := policyFieldValues(policystore.RequestColumns[:], fields)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO policy_requests (`+policyColumnNames(policystore.RequestColumns[:])+`) VALUES (`+policyPlaceholders(len(values))+`)`, values...)
	if err != nil {
		return fmt.Errorf("insert policy request: %w", err)
	}
	return nil
}

func updatePolicyRequest(ctx context.Context, transaction *sql.Tx, request *policystore.Request) error {
	if err := setPolicyRequestLogicalBytes(request); err != nil {
		return err
	}
	fields, err := policystore.RequestFields(*request)
	if err != nil {
		return err
	}
	values, err := policyFieldValues(policystore.RequestColumns[:], fields)
	if err != nil {
		return err
	}
	assignments := make([]string, 0, len(policystore.RequestColumns)-2)
	arguments := make([]any, 0, len(values))
	for index, column := range policystore.RequestColumns {
		if column.Name == "principal" || column.Name == "request_id" {
			continue
		}
		assignments = append(assignments, column.Name+"=?")
		arguments = append(arguments, values[index])
	}
	arguments = append(arguments, request.Principal, request.RequestID)
	result, err := transaction.ExecContext(ctx, `UPDATE policy_requests SET `+strings.Join(assignments, ",")+` WHERE principal=? AND request_id=?`, arguments...)
	if err != nil {
		return fmt.Errorf("update policy request: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update policy request rows affected: %w", err)
	}
	if affected != 1 {
		return policystore.ErrStaleVersion
	}
	return nil
}

func insertPolicyVote(ctx context.Context, transaction *sql.Tx, vote *policystore.Vote) error {
	vote.LogicalBytes = 0
	fields, err := policystore.VoteFields(*vote)
	if err != nil {
		return err
	}
	charge, err := policystore.VoteLogicalCharge(fields)
	if err != nil {
		return err
	}
	vote.LogicalBytes = charge
	fields, err = policystore.VoteFields(*vote)
	if err != nil {
		return err
	}
	values, err := policyFieldValues(policystore.VoteColumns[:], fields)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO policy_votes (`+policyColumnNames(policystore.VoteColumns[:])+`) VALUES (`+policyPlaceholders(len(values))+`)`, values...)
	if err != nil {
		return fmt.Errorf("insert policy vote: %w", err)
	}
	return nil
}

func upsertPolicyHead(ctx context.Context, transaction *sql.Tx, head *policystore.Head, bootstrap bool, trusted *policystore.Head) error {
	head.LogicalBytes = 0
	fields, err := policystore.HeadFields(*head)
	if err != nil {
		return err
	}
	charge, err := policystore.HeadLogicalCharge(fields)
	if err != nil {
		return err
	}
	head.LogicalBytes = charge
	fields, err = policystore.HeadFields(*head)
	if err != nil {
		return err
	}
	values, err := policyFieldValues(policystore.HeadColumns[:], fields)
	if err != nil {
		return err
	}
	if bootstrap {
		_, err = transaction.ExecContext(ctx, `INSERT INTO policy_heads (`+policyColumnNames(policystore.HeadColumns[:])+`) VALUES (`+policyPlaceholders(len(values))+`)`, values...)
		if err != nil {
			return fmt.Errorf("insert policy head: %w", err)
		}
		return nil
	}
	if trusted == nil {
		return fmt.Errorf("%w: successor lacks trusted head", policystore.ErrCorrupt)
	}
	assignments := make([]string, 0, len(policystore.HeadColumns)-3)
	arguments := make([]any, 0, len(values)+10)
	for index, column := range policystore.HeadColumns {
		if column.Name == "authority_singleton" || column.Name == "authority_id" || column.Name == "host_key_fp" {
			continue
		}
		assignments = append(assignments, column.Name+"=?")
		arguments = append(arguments, values[index])
	}
	arguments = append(arguments, trusted.AuthorityID, trusted.HostKeyFP, trusted.ManifestEnvelope, trusted.PayloadSHA256,
		trusted.BaseDigest, trusted.EpochBE, trusted.RevisionBE, trusted.SignerKeyID, []byte(trusted.SignerPublicKey), policyInteger(trusted.RowVersion))
	result, err := transaction.ExecContext(ctx, `UPDATE policy_heads SET `+strings.Join(assignments, ",")+`
		WHERE authority_id=? AND host_key_fp=? AND manifest_envelope=? AND payload_sha256=? AND base_digest=?
		AND epoch_be=? AND revision_be=? AND signer_key_id=? AND signer_public_key=? AND row_version=?`, arguments...)
	if err != nil {
		return fmt.Errorf("update policy head: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return policystore.ErrStaleVersion
	}
	return nil
}

func reservationComponentsForRequest(request *policystore.Request) (policystore.ReservationComponents, error) {
	if isMatrix2A(*request) {
		if request.StorageKind == policystore.StorageTombstone {
			terminal, err := policystore.TerminalGroupMaximum()
			if err != nil {
				return policystore.ReservationComponents{}, err
			}
			growth, err := policystore.RowGrowthMaximum(nil, true)
			if err != nil {
				return policystore.ReservationComponents{}, err
			}
			return policystore.ReservationComponents{Admission: request.ReservedBytes, Terminal: terminal.Matrix2A,
				TerminalPublication: terminal.Publication, Growth: growth, Matrix2A: true}, nil
		}
		return policystore.Matrix2AReservation(request.CanonicalRequest, request.Payload)
	}
	if !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize || request.Payload == nil {
		return policystore.ReservationComponents{}, fmt.Errorf("%w: accepted request lacks candidate head inputs", policystore.ErrCorrupt)
	}
	rowVersion := uint64(1)
	trusted, err := trustedHeadFromRequest(request)
	if err != nil {
		return policystore.ReservationComponents{}, err
	}
	if trusted != nil {
		if trusted.RowVersion == math.MaxInt64 {
			return policystore.ReservationComponents{}, fmt.Errorf("%w: head row version overflow", policystore.ErrCorrupt)
		}
		rowVersion = trusted.RowVersion + 1
	}
	candidate, err := policystore.CandidateHeadImage(policystore.CandidateHeadInput{
		AuthorityID: request.AuthorityID, HostKeyFP: request.HostKeyFP, Payload: request.Payload,
		PayloadSHA256: request.PayloadSHA256, BaseDigest: request.BaseDigest,
		SignerKeyID: request.FrozenSignerKeyID.Value, SignerPublicKey: ed25519.PublicKey(request.FrozenSignerPublicKey),
		RowVersion: rowVersion, UpdatedAt: request.CreatedAt,
	})
	if err != nil {
		return policystore.ReservationComponents{}, err
	}
	return policystore.AcceptedReservation(request.CanonicalRequest, request.Payload, candidate, trusted)
}

func trustedHeadFromRequest(request *policystore.Request) (*policystore.Head, error) {
	if request.Bootstrap {
		return nil, nil
	}
	if request.TrustedHeadEnvelope == nil || !request.TrustedHeadDigest.Valid || !request.TrustedHeadKeyID.Valid ||
		len(request.TrustedHeadPublicKey) != ed25519.PublicKeySize || len(request.TrustedHeadEpochBE) != 8 ||
		len(request.TrustedHeadRevisionBE) != 8 || !request.TrustedHeadRowVersion.Valid || request.TrustedHeadRowVersion.Value <= 0 {
		return nil, fmt.Errorf("%w: incomplete trusted predecessor", policystore.ErrCorrupt)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(request.TrustedHeadEnvelope)
	if err != nil {
		return nil, fmt.Errorf("%w: trusted head envelope", policystore.ErrCorrupt)
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(payload)
	if err != nil || baseDigest != request.TrustedHeadDigest.Value {
		return nil, fmt.Errorf("%w: trusted head digest", policystore.ErrCorrupt)
	}
	head := &policystore.Head{AuthoritySingleton: 1, AuthorityID: request.AuthorityID, HostKeyFP: request.HostKeyFP,
		ManifestEnvelope: append([]byte(nil), request.TrustedHeadEnvelope...), PayloadSHA256: payloadSHA,
		BaseDigest: baseDigest, EpochBE: append([]byte(nil), request.TrustedHeadEpochBE...),
		RevisionBE: append([]byte(nil), request.TrustedHeadRevisionBE...), SignerKeyID: request.TrustedHeadKeyID.Value,
		SignerPublicKey: append(ed25519.PublicKey(nil), request.TrustedHeadPublicKey...), RowVersion: uint64(request.TrustedHeadRowVersion.Value), UpdatedAt: request.CreatedAt}
	fields, err := policystore.HeadFields(*head)
	if err != nil {
		return nil, err
	}
	charge, err := policystore.HeadLogicalCharge(fields)
	if err != nil {
		return nil, err
	}
	head.LogicalBytes = charge
	return head, nil
}

func expectedRequestRemaining(ctx context.Context, queryer policyQueryer, request *policystore.Request) (uint64, error) {
	if request.State.Terminal() {
		return rejectionFloor(request), nil
	}
	components, err := reservationComponentsForRequest(request)
	if err != nil {
		return 0, err
	}
	var consumedVotes uint64
	if !components.Matrix2A {
		var voteBytes int64
		if err := queryer.QueryRowContext(ctx, `SELECT COALESCE(SUM(logical_bytes),0) FROM policy_votes WHERE principal=? AND request_id=?`, request.Principal, request.RequestID).Scan(&voteBytes); err != nil {
			return 0, err
		}
		if voteBytes < 0 || uint64(voteBytes) > components.Votes {
			return 0, fmt.Errorf("%w: vote reservation consumption", policystore.ErrCorrupt)
		}
		consumedVotes = uint64(voteBytes)
	}
	remaining, err := policystore.DeriveRemaining(policystore.RemainingInput{
		Components: components, State: request.State, ConsumedVotes: consumedVotes,
		ConsumedTerminal:     uint64(len(request.PendingResponse)),
		ClaimedGroupConsumed: request.ClaimedHeadEnvelope != nil,
		LeaseOwnerConsumed:   request.RecoveryLeaseGeneration > 0,
	})
	if err != nil {
		return 0, fmt.Errorf("%w: reservation state %s: %v", policystore.ErrCorrupt, request.State, err)
	}
	if remaining > math.MaxInt64 {
		return 0, errors.New("policy remaining commitment exceeds MaxInt64")
	}
	return remaining, nil
}

func u64FromBE(value []byte) (uint64, error) {
	if len(value) != 8 {
		return 0, errors.New("uint64 field is not eight bytes")
	}
	return binary.BigEndian.Uint64(value), nil
}
