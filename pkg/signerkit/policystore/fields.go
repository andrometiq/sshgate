package policystore

import (
	"errors"
	"fmt"
	"math"

	"github.com/karthikeyan5/sshgate/src/policywire"
)

func nullableText(value NullableString) Field {
	if !value.Valid {
		return NullField()
	}
	return TextField(value.Value)
}

func nullableInteger(value NullableInt64) Field {
	if !value.Valid {
		return NullField()
	}
	return IntegerField(value.Value)
}

func nullableBlob(value []byte) Field {
	if value == nil {
		return NullField()
	}
	return BlobField(value)
}

func boolField(value bool) Field {
	if value {
		return IntegerField(1)
	}
	return IntegerField(0)
}

func uintField(value uint64) (Field, error) {
	if value > math.MaxInt64 {
		return Field{}, errors.New("policy store: unsigned value exceeds MaxInt64")
	}
	return IntegerField(int64(value)), nil
}

// RequestFields returns the exact 83-column v3 census/archive image.
func RequestFields(request Request) ([]Field, error) {
	stateVersion, err := uintField(request.StateVersion)
	if err != nil {
		return nil, err
	}
	reservedBytes, err := uintField(request.ReservedBytes)
	if err != nil {
		return nil, err
	}
	leaseGeneration, err := uintField(request.RecoveryLeaseGeneration)
	if err != nil {
		return nil, err
	}
	logicalBytes, err := uintField(request.LogicalBytes)
	if err != nil {
		return nil, err
	}
	return []Field{
		TextField(request.Principal), TextField(request.RequestID), TextField(request.ReviewID),
		IntegerField(request.AuthoritySingleton), TextField(request.AuthorityID), TextField(string(request.StorageKind)),
		TextField(request.Purpose), nullableBlob(request.CanonicalRequest), nullableBlob(request.Payload),
		TextField(request.TupleDigest), TextField(request.PayloadSHA256), TextField(request.BaseDigest),
		TextField(request.HostKeyFP), TextField(request.ExpectedHeadDigest), TextField(request.ExpectedSignerKeyID),
		boolField(request.Bootstrap), nullableBlob(request.TrustedHeadEnvelope), nullableText(request.TrustedHeadDigest),
		nullableText(request.TrustedHeadKeyID), nullableBlob(request.TrustedHeadPublicKey),
		nullableBlob(request.TrustedHeadEpochBE), nullableBlob(request.TrustedHeadRevisionBE),
		nullableInteger(request.TrustedHeadRowVersion), nullableBlob(request.ClaimedHeadEnvelope),
		nullableText(request.ClaimedHeadDigest), nullableText(request.ClaimedHeadKeyID),
		nullableBlob(request.ClaimedHeadPublicKey), nullableBlob(request.ClaimedHeadEpochBE),
		nullableBlob(request.ClaimedHeadRevisionBE), nullableInteger(request.ClaimedHeadRowVersion),
		nullableText(request.FrozenSignerKeyID), nullableBlob(request.FrozenSignerPublicKey),
		nullableBlob(request.EpochBE), nullableBlob(request.RevisionBE), TextField(request.MissAction),
		TextField(request.Growth), IntegerField(request.EntryCount), IntegerField(request.RevocationCount),
		IntegerField(request.LogicalChangeCount), nullableBlob(request.ReviewJSON), nullableText(request.ReviewSHA256),
		nullableInteger(request.ReviewRenderedBytes), nullableInteger(request.ReviewItemCount),
		nullableText(request.ReviewRendererVersion), nullableText(request.ReviewRulesDigest),
		nullableBlob(request.EligibleVotersJSON), nullableText(request.EligibleVotersSHA256),
		nullableInteger(request.EligibleVoterCount), boolField(request.VoteStepUpRequired),
		nullableBlob(request.VoteAuthMethodsJSON), TextField(request.VoteAuthMethodsSHA256),
		IntegerField(request.RequiredApprovals), boolField(request.DenyVeto), boolField(request.AllowSelfApprove),
		TextField(request.RequesterPrincipal), TextField(string(request.State)), stateVersion,
		boolField(request.SubmissionAudited), boolField(request.PreMintAudited), boolField(request.ResultAudited),
		boolField(request.TerminalAudited), boolField(request.NoOp), TextField(string(request.ErrorFamily)),
		TextField(string(request.FailureCode)), nullableBlob(request.ResultEnvelope), TextField(request.ResultSHA256),
		nullableBlob(request.PendingResponse), nullableBlob(request.TerminalResponse), nullableInteger(request.TerminalHTTPStatus),
		reservedBytes, TextField(request.RecoveryLeaseOwner), IntegerField(request.RecoveryLeaseUntil), leaseGeneration,
		nullableText(request.ArchiveID), nullableText(request.ArchiveObjectSHA256), nullableInteger(request.ArchiveRecordBytes),
		nullableText(request.TerminalResponseSHA256), nullableInteger(request.TerminalResponseBytes),
		boolField(request.CompactionDeleteGuard), logicalBytes, IntegerField(request.CreatedAt),
		IntegerField(request.UpdatedAt), nullableInteger(request.ResolvedAt),
	}, nil
}

type fieldReader struct {
	columns []Column
	fields  []Field
}

func newFieldReader(columns []Column, fields []Field) (*fieldReader, error) {
	if len(columns) != len(fields) {
		return nil, fmt.Errorf("policy store: got %d fields, want %d", len(fields), len(columns))
	}
	for index := range fields {
		if err := validateField(columns[index], fields[index]); err != nil {
			return nil, fmt.Errorf("policy store: %s: %w", columns[index].Name, err)
		}
	}
	return &fieldReader{columns: columns, fields: fields}, nil
}

func (reader *fieldReader) text(index int) (string, error) {
	if reader.fields[index].Null {
		return "", fmt.Errorf("policy store: %s is NULL", reader.columns[index].Name)
	}
	return reader.fields[index].Text()
}
func (reader *fieldReader) nullableText(index int) (NullableString, error) {
	if reader.fields[index].Null {
		return NullableString{}, nil
	}
	value, err := reader.fields[index].Text()
	return NullableString{Value: value, Valid: err == nil}, err
}
func (reader *fieldReader) blob(index int) []byte {
	if reader.fields[index].Null {
		return nil
	}
	return reader.fields[index].Bytes()
}
func (reader *fieldReader) integer(index int) (int64, error) {
	if reader.fields[index].Null {
		return 0, fmt.Errorf("policy store: %s is NULL", reader.columns[index].Name)
	}
	return reader.fields[index].Integer()
}
func (reader *fieldReader) nullableInteger(index int) (NullableInt64, error) {
	if reader.fields[index].Null {
		return NullableInt64{}, nil
	}
	value, err := reader.fields[index].Integer()
	return NullableInt64{Value: value, Valid: err == nil}, err
}
func (reader *fieldReader) boolean(index int) (bool, error) {
	value, err := reader.integer(index)
	if err != nil {
		return false, err
	}
	if value != 0 && value != 1 {
		return false, fmt.Errorf("policy store: %s boolean is %d", reader.columns[index].Name, value)
	}
	return value == 1, nil
}
func (reader *fieldReader) unsigned(index int) (uint64, error) {
	value, err := reader.integer(index)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("policy store: %s is negative", reader.columns[index].Name)
	}
	return uint64(value), nil
}

// RequestFromFields decodes the exact 83-column v3 image without relaxing
// SQL NULL versus empty TEXT/BLOB distinctions.
func RequestFromFields(fields []Field) (Request, error) {
	r, err := newFieldReader(RequestColumns[:], fields)
	if err != nil {
		return Request{}, err
	}
	var out Request
	if out.Principal, err = r.text(0); err != nil {
		return out, err
	}
	if out.RequestID, err = r.text(1); err != nil {
		return out, err
	}
	if out.ReviewID, err = r.text(2); err != nil {
		return out, err
	}
	if out.AuthoritySingleton, err = r.integer(3); err != nil {
		return out, err
	}
	if out.AuthorityID, err = r.text(4); err != nil {
		return out, err
	}
	storage, e := r.text(5)
	if e != nil {
		return out, e
	}
	out.StorageKind = StorageKind(storage)
	if out.Purpose, err = r.text(6); err != nil {
		return out, err
	}
	out.CanonicalRequest = r.blob(7)
	out.Payload = r.blob(8)
	if out.TupleDigest, err = r.text(9); err != nil {
		return out, err
	}
	if out.PayloadSHA256, err = r.text(10); err != nil {
		return out, err
	}
	if out.BaseDigest, err = r.text(11); err != nil {
		return out, err
	}
	if out.HostKeyFP, err = r.text(12); err != nil {
		return out, err
	}
	if out.ExpectedHeadDigest, err = r.text(13); err != nil {
		return out, err
	}
	if out.ExpectedSignerKeyID, err = r.text(14); err != nil {
		return out, err
	}
	if out.Bootstrap, err = r.boolean(15); err != nil {
		return out, err
	}
	out.TrustedHeadEnvelope = r.blob(16)
	if out.TrustedHeadDigest, err = r.nullableText(17); err != nil {
		return out, err
	}
	if out.TrustedHeadKeyID, err = r.nullableText(18); err != nil {
		return out, err
	}
	out.TrustedHeadPublicKey = r.blob(19)
	out.TrustedHeadEpochBE = r.blob(20)
	out.TrustedHeadRevisionBE = r.blob(21)
	if out.TrustedHeadRowVersion, err = r.nullableInteger(22); err != nil {
		return out, err
	}
	out.ClaimedHeadEnvelope = r.blob(23)
	if out.ClaimedHeadDigest, err = r.nullableText(24); err != nil {
		return out, err
	}
	if out.ClaimedHeadKeyID, err = r.nullableText(25); err != nil {
		return out, err
	}
	out.ClaimedHeadPublicKey = r.blob(26)
	out.ClaimedHeadEpochBE = r.blob(27)
	out.ClaimedHeadRevisionBE = r.blob(28)
	if out.ClaimedHeadRowVersion, err = r.nullableInteger(29); err != nil {
		return out, err
	}
	if out.FrozenSignerKeyID, err = r.nullableText(30); err != nil {
		return out, err
	}
	out.FrozenSignerPublicKey = r.blob(31)
	out.EpochBE = r.blob(32)
	out.RevisionBE = r.blob(33)
	if out.MissAction, err = r.text(34); err != nil {
		return out, err
	}
	if out.Growth, err = r.text(35); err != nil {
		return out, err
	}
	if out.EntryCount, err = r.integer(36); err != nil {
		return out, err
	}
	if out.RevocationCount, err = r.integer(37); err != nil {
		return out, err
	}
	if out.LogicalChangeCount, err = r.integer(38); err != nil {
		return out, err
	}
	out.ReviewJSON = r.blob(39)
	if out.ReviewSHA256, err = r.nullableText(40); err != nil {
		return out, err
	}
	if out.ReviewRenderedBytes, err = r.nullableInteger(41); err != nil {
		return out, err
	}
	if out.ReviewItemCount, err = r.nullableInteger(42); err != nil {
		return out, err
	}
	if out.ReviewRendererVersion, err = r.nullableText(43); err != nil {
		return out, err
	}
	if out.ReviewRulesDigest, err = r.nullableText(44); err != nil {
		return out, err
	}
	out.EligibleVotersJSON = r.blob(45)
	if out.EligibleVotersSHA256, err = r.nullableText(46); err != nil {
		return out, err
	}
	if out.EligibleVoterCount, err = r.nullableInteger(47); err != nil {
		return out, err
	}
	if out.VoteStepUpRequired, err = r.boolean(48); err != nil {
		return out, err
	}
	out.VoteAuthMethodsJSON = r.blob(49)
	if out.VoteAuthMethodsSHA256, err = r.text(50); err != nil {
		return out, err
	}
	if out.RequiredApprovals, err = r.integer(51); err != nil {
		return out, err
	}
	if out.DenyVeto, err = r.boolean(52); err != nil {
		return out, err
	}
	if out.AllowSelfApprove, err = r.boolean(53); err != nil {
		return out, err
	}
	if out.RequesterPrincipal, err = r.text(54); err != nil {
		return out, err
	}
	state, e := r.text(55)
	if e != nil {
		return out, e
	}
	out.State = State(state)
	if out.StateVersion, err = r.unsigned(56); err != nil {
		return out, err
	}
	if out.SubmissionAudited, err = r.boolean(57); err != nil {
		return out, err
	}
	if out.PreMintAudited, err = r.boolean(58); err != nil {
		return out, err
	}
	if out.ResultAudited, err = r.boolean(59); err != nil {
		return out, err
	}
	if out.TerminalAudited, err = r.boolean(60); err != nil {
		return out, err
	}
	if out.NoOp, err = r.boolean(61); err != nil {
		return out, err
	}
	family, e := r.text(62)
	if e != nil {
		return out, e
	}
	out.ErrorFamily = ErrorFamily(family)
	code, e := r.text(63)
	if e != nil {
		return out, e
	}
	out.FailureCode = policyErrorCode(code)
	out.ResultEnvelope = r.blob(64)
	if out.ResultSHA256, err = r.text(65); err != nil {
		return out, err
	}
	out.PendingResponse = r.blob(66)
	out.TerminalResponse = r.blob(67)
	if out.TerminalHTTPStatus, err = r.nullableInteger(68); err != nil {
		return out, err
	}
	if out.ReservedBytes, err = r.unsigned(69); err != nil {
		return out, err
	}
	if out.RecoveryLeaseOwner, err = r.text(70); err != nil {
		return out, err
	}
	if out.RecoveryLeaseUntil, err = r.integer(71); err != nil {
		return out, err
	}
	if out.RecoveryLeaseGeneration, err = r.unsigned(72); err != nil {
		return out, err
	}
	if out.ArchiveID, err = r.nullableText(73); err != nil {
		return out, err
	}
	if out.ArchiveObjectSHA256, err = r.nullableText(74); err != nil {
		return out, err
	}
	if out.ArchiveRecordBytes, err = r.nullableInteger(75); err != nil {
		return out, err
	}
	if out.TerminalResponseSHA256, err = r.nullableText(76); err != nil {
		return out, err
	}
	if out.TerminalResponseBytes, err = r.nullableInteger(77); err != nil {
		return out, err
	}
	if out.CompactionDeleteGuard, err = r.boolean(78); err != nil {
		return out, err
	}
	if out.LogicalBytes, err = r.unsigned(79); err != nil {
		return out, err
	}
	if out.CreatedAt, err = r.integer(80); err != nil {
		return out, err
	}
	if out.UpdatedAt, err = r.integer(81); err != nil {
		return out, err
	}
	if out.ResolvedAt, err = r.nullableInteger(82); err != nil {
		return out, err
	}
	return out, nil
}

func policyErrorCode(value string) policywire.ErrorCode { return policywire.ErrorCode(value) }

// VoteFields returns the exact 15-column v3 census/archive image.
func VoteFields(vote Vote) ([]Field, error) {
	auditVersion, err := uintField(vote.AuditStateVersion)
	if err != nil {
		return nil, err
	}
	logicalBytes, err := uintField(vote.LogicalBytes)
	if err != nil {
		return nil, err
	}
	return []Field{
		TextField(vote.Principal), TextField(vote.RequestID), TextField(vote.Operator),
		TextField(string(vote.Decision)), TextField(string(vote.AuthnMethod)), IntegerField(vote.Timestamp),
		boolField(vote.Audited), auditVersion, TextField(vote.TupleDigest), TextField(vote.Purpose),
		TextField(vote.PayloadSHA256), TextField(vote.CandidateDigest), TextField(vote.HeadDigest),
		TextField(vote.SignerKeyID), logicalBytes,
	}, nil
}

func VoteFromFields(fields []Field) (Vote, error) {
	r, err := newFieldReader(VoteColumns[:], fields)
	if err != nil {
		return Vote{}, err
	}
	var out Vote
	if out.Principal, err = r.text(0); err != nil {
		return out, err
	}
	if out.RequestID, err = r.text(1); err != nil {
		return out, err
	}
	if out.Operator, err = r.text(2); err != nil {
		return out, err
	}
	decision, e := r.text(3)
	if e != nil {
		return out, e
	}
	out.Decision = Decision(decision)
	method, e := r.text(4)
	if e != nil {
		return out, e
	}
	out.AuthnMethod = AuthnMethod(method)
	if out.Timestamp, err = r.integer(5); err != nil {
		return out, err
	}
	if out.Audited, err = r.boolean(6); err != nil {
		return out, err
	}
	if out.AuditStateVersion, err = r.unsigned(7); err != nil {
		return out, err
	}
	if out.TupleDigest, err = r.text(8); err != nil {
		return out, err
	}
	if out.Purpose, err = r.text(9); err != nil {
		return out, err
	}
	if out.PayloadSHA256, err = r.text(10); err != nil {
		return out, err
	}
	if out.CandidateDigest, err = r.text(11); err != nil {
		return out, err
	}
	if out.HeadDigest, err = r.text(12); err != nil {
		return out, err
	}
	if out.SignerKeyID, err = r.text(13); err != nil {
		return out, err
	}
	if out.LogicalBytes, err = r.unsigned(14); err != nil {
		return out, err
	}
	return out, nil
}

// HeadFields returns the exact 13-column v3 census image.
func HeadFields(head Head) ([]Field, error) {
	rowVersion, err := uintField(head.RowVersion)
	if err != nil {
		return nil, err
	}
	logicalBytes, err := uintField(head.LogicalBytes)
	if err != nil {
		return nil, err
	}
	return []Field{
		IntegerField(head.AuthoritySingleton), TextField(head.AuthorityID), TextField(head.HostKeyFP),
		BlobField(head.ManifestEnvelope), TextField(head.PayloadSHA256), TextField(head.BaseDigest),
		BlobField(head.EpochBE), BlobField(head.RevisionBE), TextField(head.SignerKeyID),
		BlobField(head.SignerPublicKey), rowVersion, logicalBytes, IntegerField(head.UpdatedAt),
	}, nil
}

func HeadFromFields(fields []Field) (Head, error) {
	r, err := newFieldReader(HeadColumns[:], fields)
	if err != nil {
		return Head{}, err
	}
	var out Head
	if out.AuthoritySingleton, err = r.integer(0); err != nil {
		return out, err
	}
	if out.AuthorityID, err = r.text(1); err != nil {
		return out, err
	}
	if out.HostKeyFP, err = r.text(2); err != nil {
		return out, err
	}
	out.ManifestEnvelope = r.blob(3)
	if out.PayloadSHA256, err = r.text(4); err != nil {
		return out, err
	}
	if out.BaseDigest, err = r.text(5); err != nil {
		return out, err
	}
	out.EpochBE = r.blob(6)
	out.RevisionBE = r.blob(7)
	if out.SignerKeyID, err = r.text(8); err != nil {
		return out, err
	}
	out.SignerPublicKey = r.blob(9)
	if out.RowVersion, err = r.unsigned(10); err != nil {
		return out, err
	}
	if out.LogicalBytes, err = r.unsigned(11); err != nil {
		return out, err
	}
	if out.UpdatedAt, err = r.integer(12); err != nil {
		return out, err
	}
	return out, nil
}
