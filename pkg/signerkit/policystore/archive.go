package policystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

const ArchiveBindingFilename = ".sshgate-policy-archive-binding-v1"

type ArchiveRef struct {
	ArchiveID              string
	ObjectSHA256           string
	RecordBytes            int64
	TerminalResponseSHA256 string
	TerminalResponseBytes  int64
}

func (reference ArchiveRef) Validate() error {
	if !ValidArchiveID(reference.ArchiveID) || !validLowerHex(reference.ObjectSHA256, 64) ||
		!validLowerHex(reference.TerminalResponseSHA256, 64) || reference.RecordBytes <= 0 ||
		reference.TerminalResponseBytes <= 0 {
		return errors.New("policy store: invalid archive reference")
	}
	return nil
}

type ArchiveRecord struct {
	ArchiveID              string
	AuthorityID            string
	TerminalResponseSHA256 string
	TerminalResponseBytes  int64
	Request                Request
	Votes                  []Vote
}

func (record ArchiveRecord) Encode() ([]byte, error) {
	votes := append([]Vote(nil), record.Votes...)
	sort.Slice(votes, func(i, j int) bool { return votes[i].Operator < votes[j].Operator })
	record.Votes = votes
	if err := record.Validate(); err != nil {
		return nil, err
	}
	requestFields, err := RequestFields(record.Request)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.WriteString(ArchiveRecordVersion)
	output.WriteByte(0)
	writeUint32(&output, 4)
	for _, field := range []Field{TextField(record.ArchiveID), TextField(record.AuthorityID), TextField(record.TerminalResponseSHA256), IntegerField(record.TerminalResponseBytes)} {
		if err := encodeField(&output, field); err != nil {
			return nil, err
		}
	}
	writeUint32(&output, RequestColumnCount)
	for _, field := range requestFields {
		if err := encodeField(&output, field); err != nil {
			return nil, err
		}
	}
	writeUint32(&output, uint32(len(votes)))
	for _, vote := range votes {
		fields, err := VoteFields(vote)
		if err != nil {
			return nil, err
		}
		writeUint32(&output, VoteColumnCount)
		for _, field := range fields {
			if err := encodeField(&output, field); err != nil {
				return nil, err
			}
		}
	}
	return output.Bytes(), nil
}

func DecodeArchiveRecord(encoded []byte) (ArchiveRecord, error) {
	reader := bytes.NewReader(encoded)
	if err := readMagic(reader, ArchiveRecordVersion); err != nil {
		return ArchiveRecord{}, err
	}
	count, err := readUint32(reader)
	if err != nil || count != 4 {
		return ArchiveRecord{}, errors.New("policy store: archive outer field count is not 4")
	}
	outerKinds := []Column{{"archive_id", ColumnText}, {"authority_id", ColumnText}, {"terminal_response_sha256", ColumnText}, {"terminal_response_bytes", ColumnInteger}}
	outer, err := decodeFields(reader, outerKinds)
	if err != nil {
		return ArchiveRecord{}, err
	}
	archiveID, err := outer[0].Text()
	if err != nil {
		return ArchiveRecord{}, err
	}
	authorityID, err := outer[1].Text()
	if err != nil {
		return ArchiveRecord{}, err
	}
	terminalSHA, err := outer[2].Text()
	if err != nil {
		return ArchiveRecord{}, err
	}
	terminalBytes, err := outer[3].Integer()
	if err != nil {
		return ArchiveRecord{}, err
	}
	count, err = readUint32(reader)
	if err != nil || count != RequestColumnCount {
		return ArchiveRecord{}, errors.New("policy store: archive request field count is not 83")
	}
	requestFields, err := decodeFields(reader, RequestColumns[:])
	if err != nil {
		return ArchiveRecord{}, err
	}
	request, err := RequestFromFields(requestFields)
	if err != nil {
		return ArchiveRecord{}, err
	}
	voteCount, err := readUint32(reader)
	if err != nil {
		return ArchiveRecord{}, err
	}
	if voteCount > MaxVotesPerRequest {
		return ArchiveRecord{}, errors.New("policy store: archive vote count exceeds 256")
	}
	votes := make([]Vote, 0, voteCount)
	for index := uint32(0); index < voteCount; index++ {
		count, err = readUint32(reader)
		if err != nil || count != VoteColumnCount {
			return ArchiveRecord{}, errors.New("policy store: archive vote field count is not 15")
		}
		fields, err := decodeFields(reader, VoteColumns[:])
		if err != nil {
			return ArchiveRecord{}, err
		}
		vote, err := VoteFromFields(fields)
		if err != nil {
			return ArchiveRecord{}, err
		}
		votes = append(votes, vote)
	}
	if reader.Len() != 0 {
		return ArchiveRecord{}, errors.New("policy store: archive has trailing bytes")
	}
	record := ArchiveRecord{ArchiveID: archiveID, AuthorityID: authorityID, TerminalResponseSHA256: terminalSHA, TerminalResponseBytes: terminalBytes, Request: request, Votes: votes}
	if err := record.Validate(); err != nil {
		return ArchiveRecord{}, err
	}
	return record, nil
}

func (record ArchiveRecord) Validate() error {
	if !ValidArchiveID(record.ArchiveID) {
		return errors.New("policy store: archive record has invalid archive ID")
	}
	if !validAuthorityID(record.AuthorityID) {
		return errors.New("policy store: archive record has invalid authority ID")
	}
	if !validLowerHex(record.TerminalResponseSHA256, 64) || record.TerminalResponseBytes <= 0 {
		return errors.New("policy store: archive record has invalid terminal reference")
	}
	if record.Request.StorageKind != StorageFull || !record.Request.State.Terminal() || record.Request.ResolvedAt.Valid == false {
		return errors.New("policy store: archive request is not a full terminal")
	}
	if err := validateArchivedRequest(record.Request); err != nil {
		return err
	}
	if record.Request.AuthorityID != record.AuthorityID {
		return errors.New("policy store: archive authority mismatch")
	}
	if err := ValidateIdentity(record.Request.Principal); err != nil {
		return fmt.Errorf("policy store: archived principal: %w", err)
	}
	if err := ValidateIdentity(record.Request.RequesterPrincipal); err != nil {
		return fmt.Errorf("policy store: archived requester: %w", err)
	}
	if len(record.Request.EpochBE) != 8 || len(record.Request.RevisionBE) != 8 || record.Request.TerminalHTTPStatus.Valid == false || record.Request.TerminalResponse == nil {
		return errors.New("policy store: archived request has invalid terminal shape")
	}
	if record.Request.ArchiveID.Valid || record.Request.ArchiveObjectSHA256.Valid || record.Request.ArchiveRecordBytes.Valid || record.Request.TerminalResponseSHA256.Valid || record.Request.TerminalResponseBytes.Valid {
		return errors.New("policy store: archived full row has archive reference")
	}
	if int64(len(record.Request.TerminalResponse)) != record.TerminalResponseBytes {
		return errors.New("policy store: terminal response length mismatch")
	}
	hash := sha256.Sum256(record.Request.TerminalResponse)
	if hex.EncodeToString(hash[:]) != record.TerminalResponseSHA256 {
		return errors.New("policy store: terminal response hash mismatch")
	}
	requestFields, err := RequestFields(record.Request)
	if err != nil {
		return err
	}
	charge, err := RequestLogicalCharge(requestFields)
	if err != nil {
		return err
	}
	if charge != record.Request.LogicalBytes {
		return errors.New("policy store: archived request logical byte mismatch")
	}
	if len(record.Votes) > MaxVotesPerRequest {
		return errors.New("policy store: too many archived votes")
	}
	previous := ""
	for index, vote := range record.Votes {
		if vote.Principal != record.Request.Principal || vote.RequestID != record.Request.RequestID {
			return errors.New("policy store: archived vote belongs to another request")
		}
		if index > 0 && vote.Operator <= previous {
			return errors.New("policy store: archived votes are unsorted or duplicated")
		}
		if err := ValidateIdentity(vote.Operator); err != nil {
			return fmt.Errorf("policy store: archived vote operator: %w", err)
		}
		if vote.Decision != DecisionApprove && vote.Decision != DecisionDeny {
			return errors.New("policy store: archived vote has invalid decision")
		}
		if vote.AuthnMethod != AuthnSession && vote.AuthnMethod != AuthnTOTP {
			return errors.New("policy store: archived vote has invalid auth method")
		}
		voters, votersErr := DecodeFrozenIdentities(record.Request.EligibleVotersJSON)
		voterIndex := sort.SearchStrings(voters, vote.Operator)
		eligible := votersErr == nil && voterIndex < len(voters) && voters[voterIndex] == vote.Operator
		if !eligible || vote.AuditStateVersion == 0 || vote.AuditStateVersion > record.Request.StateVersion ||
			vote.TupleDigest != record.Request.TupleDigest || vote.Purpose != record.Request.Purpose ||
			vote.PayloadSHA256 != record.Request.PayloadSHA256 || vote.CandidateDigest != record.Request.BaseDigest ||
			vote.HeadDigest != record.Request.ExpectedHeadDigest || !record.Request.FrozenSignerKeyID.Valid ||
			vote.SignerKeyID != record.Request.FrozenSignerKeyID.Value ||
			(record.Request.VoteStepUpRequired && vote.AuthnMethod != AuthnTOTP) ||
			(!record.Request.VoteStepUpRequired && vote.AuthnMethod != AuthnSession) {
			return errors.New("policy store: archived vote differs from frozen request")
		}
		previous = vote.Operator
		fields, err := VoteFields(vote)
		if err != nil {
			return err
		}
		charge, err := VoteLogicalCharge(fields)
		if err != nil {
			return err
		}
		if charge != vote.LogicalBytes {
			return errors.New("policy store: archived vote logical byte mismatch")
		}
	}
	return nil
}

func validateArchivedRequest(request Request) error {
	if request.AuthoritySingleton != 1 || request.StateVersion == 0 || request.CompactionDeleteGuard ||
		request.Purpose != policywire.Purpose || request.CanonicalRequest == nil || request.Payload == nil ||
		len(request.CanonicalRequest) > policywire.MaxRequestFrameBytes || len(request.Payload) > policy.MaxPolicyPayloadBytes ||
		len(request.PendingResponse) > policywire.MaxResponseFrameBytes || len(request.TerminalResponse) > policywire.MaxResponseFrameBytes ||
		len(request.ResultEnvelope) > policy.MaxPolicyEnvelopeBytes ||
		!validLowerHex(request.TupleDigest, 64) || !validLowerHex(request.PayloadSHA256, 64) ||
		!validLowerHex(request.BaseDigest, 64) || !validLowerHex(request.ExpectedSignerKeyID, 64) ||
		len(request.EpochBE) != 8 || len(request.RevisionBE) != 8 {
		return errors.New("policy store: archived request has invalid required fields")
	}
	if len(request.RequestID) != 35 || request.RequestID[:3] != "pm_" || !validLowerHex(request.RequestID[3:], 32) ||
		len(request.ReviewID) != 35 || request.ReviewID[:3] != "pr_" || !validLowerHex(request.ReviewID[3:], 32) {
		return errors.New("policy store: archived request has invalid opaque ID")
	}
	if request.CreatedAt > request.UpdatedAt || !request.TerminalHTTPStatus.Valid || !request.ResolvedAt.Valid ||
		request.ResolvedAt.Value > request.UpdatedAt ||
		!((request.RecoveryLeaseOwner == "" && request.RecoveryLeaseUntil == 0) ||
			(request.RecoveryLeaseOwner != "" && request.RecoveryLeaseUntil > 0 && request.RecoveryLeaseGeneration > 0)) {
		return errors.New("policy store: archived request has invalid chronology or lease shape")
	}
	reviewPresent := request.ReviewJSON != nil || request.ReviewSHA256.Valid || request.ReviewRenderedBytes.Valid ||
		request.ReviewItemCount.Valid || request.ReviewRendererVersion.Valid || request.ReviewRulesDigest.Valid
	if reviewPresent && !completeReviewGroup(request) {
		return errors.New("policy store: archived request has partial or invalid review group")
	}
	voterPresent := request.EligibleVotersJSON != nil || request.EligibleVotersSHA256.Valid || request.EligibleVoterCount.Valid
	if voterPresent && !completeVoterGroup(request) {
		return errors.New("policy store: archived request has partial or invalid voter group")
	}
	frozenPresent := request.FrozenSignerKeyID.Valid || request.FrozenSignerPublicKey != nil
	if frozenPresent && (!request.FrozenSignerKeyID.Valid || !validLowerHex(request.FrozenSignerKeyID.Value, 64) ||
		len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize) {
		return errors.New("policy store: archived request has partial or invalid frozen signer pair")
	}
	if frozenPresent {
		keyID, err := policy.SignerKeyID(ed25519.PublicKey(request.FrozenSignerPublicKey))
		if err != nil || keyID != request.FrozenSignerKeyID.Value {
			return errors.New("policy store: archived request has mismatching frozen signer pair")
		}
	}
	wantMethods := `["session"]`
	if request.VoteStepUpRequired {
		wantMethods = `["totp"]`
	}
	if string(request.VoteAuthMethodsJSON) != wantMethods || request.RequiredApprovals <= 0 || request.RequiredApprovals > MaxVotesPerRequest {
		return errors.New("policy store: archived request has invalid frozen vote policy")
	}
	methodsHash := sha256.Sum256(request.VoteAuthMethodsJSON)
	if hex.EncodeToString(methodsHash[:]) != request.VoteAuthMethodsSHA256 {
		return errors.New("policy store: archived request has invalid vote-method digest")
	}
	if request.Bootstrap {
		if request.ExpectedHeadDigest != "" || predecessorPresent(request, true) || predecessorPresent(request, false) {
			return errors.New("policy store: archived bootstrap has predecessor")
		}
	} else if !validLowerHex(request.ExpectedHeadDigest, 64) || !predecessorComplete(request, true) {
		return errors.New("policy store: archived successor lacks trusted predecessor")
	}
	if predecessorPresent(request, false) && !predecessorComplete(request, false) {
		return errors.New("policy store: archived request has partial claimed predecessor")
	}
	matrix2A := request.ErrorFamily == ErrorFamilySemantic && request.FailureCode != policywire.ErrorQuorumUnattainable
	if matrix2A {
		if request.State != StateError || request.PendingResponse != nil || request.ResultEnvelope != nil || request.ResultSHA256 != "" || predecessorPresent(request, false) {
			return errors.New("policy store: archived Matrix-2a shape is invalid")
		}
		if !validMatrix2AError(request.FailureCode) {
			return errors.New("policy store: archived Matrix-2a code is invalid")
		}
		if request.ReservedBytes != uint64(len(request.CanonicalRequest))+uint64(len(request.Payload)) {
			return errors.New("policy store: archived Matrix-2a reservation is not its floor")
		}
	} else {
		if !request.SubmissionAudited || !request.FrozenSignerKeyID.Valid || !validLowerHex(request.FrozenSignerKeyID.Value, 64) || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize || request.PendingResponse == nil ||
			!completeReviewGroup(request) || !completeVoterGroup(request) {
			return errors.New("policy store: archived accepted-row shape is invalid")
		}
		keyID, err := policy.SignerKeyID(ed25519.PublicKey(request.FrozenSignerPublicKey))
		if err != nil || keyID != request.FrozenSignerKeyID.Value || keyID != request.ExpectedSignerKeyID {
			return errors.New("policy store: archived accepted-row signer mismatch")
		}
		if request.ReservedBytes != 0 {
			return errors.New("policy store: archived non-rejection terminal retains reservation")
		}
	}
	switch request.State {
	case StateApproved:
		if request.ErrorFamily != ErrorFamilyNone || request.FailureCode != "" || request.ResultEnvelope == nil || !validLowerHex(request.ResultSHA256, 64) || request.TerminalHTTPStatus.Value != 200 ||
			(request.NoOp && !request.TerminalAudited) || (!request.NoOp && (!request.PreMintAudited || !request.ResultAudited)) {
			return errors.New("policy store: archived approval shape is invalid")
		}
	case StateDenied:
		if request.ErrorFamily != ErrorFamilyNone || request.FailureCode != "" || request.ResultEnvelope != nil || request.ResultSHA256 != "" || request.TerminalHTTPStatus.Value != 200 || !request.TerminalAudited {
			return errors.New("policy store: archived denial shape is invalid")
		}
	case StateError:
		status, err := HTTPStatusForError(request.FailureCode)
		familyErr := ValidateErrorFamilyCode(request.ErrorFamily, request.FailureCode)
		if err != nil || familyErr != nil || int64(status) != request.TerminalHTTPStatus.Value || request.ErrorFamily == ErrorFamilyNone || !request.TerminalAudited {
			return errors.New("policy store: archived error shape is invalid")
		}
		if request.ResultEnvelope == nil && request.ResultSHA256 != "" || request.ResultEnvelope != nil && !validLowerHex(request.ResultSHA256, 64) {
			return errors.New("policy store: archived error has partial result")
		}
	}
	return nil
}

func predecessorPresent(request Request, trusted bool) bool {
	if trusted {
		return request.TrustedHeadEnvelope != nil || request.TrustedHeadDigest.Valid || request.TrustedHeadKeyID.Valid || request.TrustedHeadPublicKey != nil || request.TrustedHeadEpochBE != nil || request.TrustedHeadRevisionBE != nil || request.TrustedHeadRowVersion.Valid
	}
	return request.ClaimedHeadEnvelope != nil || request.ClaimedHeadDigest.Valid || request.ClaimedHeadKeyID.Valid || request.ClaimedHeadPublicKey != nil || request.ClaimedHeadEpochBE != nil || request.ClaimedHeadRevisionBE != nil || request.ClaimedHeadRowVersion.Valid
}

func predecessorComplete(request Request, trusted bool) bool {
	if trusted {
		return request.TrustedHeadEnvelope != nil && len(request.TrustedHeadEnvelope) <= policy.MaxPolicyEnvelopeBytes && request.TrustedHeadDigest.Valid && validLowerHex(request.TrustedHeadDigest.Value, 64) && request.TrustedHeadKeyID.Valid && validLowerHex(request.TrustedHeadKeyID.Value, 64) && len(request.TrustedHeadPublicKey) == ed25519.PublicKeySize && len(request.TrustedHeadEpochBE) == 8 && len(request.TrustedHeadRevisionBE) == 8 && request.TrustedHeadRowVersion.Valid && request.TrustedHeadRowVersion.Value > 0
	}
	return request.ClaimedHeadEnvelope != nil && len(request.ClaimedHeadEnvelope) <= policy.MaxPolicyEnvelopeBytes && request.ClaimedHeadDigest.Valid && validLowerHex(request.ClaimedHeadDigest.Value, 64) && request.ClaimedHeadKeyID.Valid && validLowerHex(request.ClaimedHeadKeyID.Value, 64) && len(request.ClaimedHeadPublicKey) == ed25519.PublicKeySize && len(request.ClaimedHeadEpochBE) == 8 && len(request.ClaimedHeadRevisionBE) == 8 && request.ClaimedHeadRowVersion.Valid && request.ClaimedHeadRowVersion.Value > 0
}

func completeReviewGroup(request Request) bool {
	if request.ReviewJSON == nil || !request.ReviewSHA256.Valid || !request.ReviewRenderedBytes.Valid || request.ReviewRenderedBytes.Value < 0 || !request.ReviewItemCount.Valid || request.ReviewItemCount.Value < 0 || !request.ReviewRendererVersion.Valid || request.ReviewRendererVersion.Value == "" || !request.ReviewRulesDigest.Valid || !validLowerHex(request.ReviewRulesDigest.Value, 64) {
		return false
	}
	if !json.Valid(request.ReviewJSON) || request.ReviewRenderedBytes.Value != int64(len(request.ReviewJSON)) ||
		request.ReviewRenderedBytes.Value > 128<<10 || request.ReviewItemCount.Value > 40 ||
		request.ReviewRendererVersion.Value != "sshgate-policy-review-v2" {
		return false
	}
	digest := sha256.Sum256(request.ReviewJSON)
	return hex.EncodeToString(digest[:]) == request.ReviewSHA256.Value
}

func completeVoterGroup(request Request) bool {
	if request.EligibleVotersJSON == nil || !request.EligibleVotersSHA256.Valid || !request.EligibleVoterCount.Valid || request.EligibleVoterCount.Value < 0 || request.EligibleVoterCount.Value > MaxVotesPerRequest {
		return false
	}
	identities, err := DecodeFrozenIdentities(request.EligibleVotersJSON)
	if err != nil || int64(len(identities)) != request.EligibleVoterCount.Value {
		return false
	}
	digest := sha256.Sum256(request.EligibleVotersJSON)
	return hex.EncodeToString(digest[:]) == request.EligibleVotersSHA256.Value
}

func (record ArchiveRecord) ObjectRef() (ArchiveRef, []byte, error) {
	encoded, err := record.Encode()
	if err != nil {
		return ArchiveRef{}, nil, err
	}
	hash := sha256.Sum256(encoded)
	return ArchiveRef{ArchiveID: record.ArchiveID, ObjectSHA256: hex.EncodeToString(hash[:]), RecordBytes: int64(len(encoded)), TerminalResponseSHA256: record.TerminalResponseSHA256, TerminalResponseBytes: record.TerminalResponseBytes}, encoded, nil
}

type ArchiveBinding struct{ ArchiveID, AuthorityID string }

func (binding ArchiveBinding) Encode() ([]byte, error) {
	if !ValidArchiveID(binding.ArchiveID) || !validAuthorityID(binding.AuthorityID) {
		return nil, errors.New("policy store: invalid archive binding")
	}
	var output bytes.Buffer
	output.WriteString(ArchiveBindingVersion)
	output.WriteByte(0)
	writeUint32(&output, 2)
	if err := encodeField(&output, TextField(binding.ArchiveID)); err != nil {
		return nil, err
	}
	if err := encodeField(&output, TextField(binding.AuthorityID)); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func DecodeArchiveBinding(encoded []byte) (ArchiveBinding, error) {
	reader := bytes.NewReader(encoded)
	if err := readMagic(reader, ArchiveBindingVersion); err != nil {
		return ArchiveBinding{}, err
	}
	count, err := readUint32(reader)
	if err != nil || count != 2 {
		return ArchiveBinding{}, errors.New("policy store: archive binding field count is not 2")
	}
	fields, err := decodeFields(reader, []Column{{"archive_id", ColumnText}, {"authority_id", ColumnText}})
	if err != nil {
		return ArchiveBinding{}, err
	}
	if reader.Len() != 0 {
		return ArchiveBinding{}, errors.New("policy store: archive binding has trailing bytes")
	}
	archiveID, err := fields[0].Text()
	if err != nil {
		return ArchiveBinding{}, err
	}
	authorityID, err := fields[1].Text()
	if err != nil {
		return ArchiveBinding{}, err
	}
	binding := ArchiveBinding{ArchiveID: archiveID, AuthorityID: authorityID}
	if !ValidArchiveID(binding.ArchiveID) || !validAuthorityID(binding.AuthorityID) {
		return ArchiveBinding{}, errors.New("policy store: invalid archive binding")
	}
	return binding, nil
}

func encodeField(writer io.Writer, field Field) error {
	if field.Null {
		_, err := writer.Write([]byte{0})
		return err
	}
	if _, err := writer.Write([]byte{1}); err != nil {
		return err
	}
	if uint64(len(field.raw)) > uint64(^uint32(0)) {
		return errors.New("policy store: archive field exceeds uint32")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field.raw)))
	if _, err := writer.Write(size[:]); err != nil {
		return err
	}
	_, err := writer.Write(field.raw)
	return err
}

func decodeFields(reader *bytes.Reader, columns []Column) ([]Field, error) {
	fields := make([]Field, len(columns))
	for index, column := range columns {
		marker, err := reader.ReadByte()
		if err != nil {
			return nil, errors.New("policy store: truncated archive field marker")
		}
		if marker == 0 {
			fields[index] = NullField()
			continue
		}
		if marker != 1 {
			return nil, errors.New("policy store: invalid archive field marker")
		}
		size, err := readUint32(reader)
		if err != nil {
			return nil, err
		}
		if uint64(size) > uint64(reader.Len()) {
			return nil, errors.New("policy store: truncated archive field")
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return nil, err
		}
		fields[index] = Field{raw: raw}
		if err := validateField(column, fields[index]); err != nil {
			return nil, fmt.Errorf("policy store: %s: %w", column.Name, err)
		}
	}
	return fields, nil
}

func writeUint32(writer io.Writer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	_, _ = writer.Write(raw[:])
}
func readUint32(reader io.Reader) (uint32, error) {
	var raw [4]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), nil
}
func readMagic(reader *bytes.Reader, magic string) error {
	expected := append([]byte(magic), 0)
	raw := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, raw); err != nil || !bytes.Equal(raw, expected) {
		return errors.New("policy store: archive magic mismatch")
	}
	return nil
}

func validAuthorityID(value string) bool {
	return len(value) == 38 && value[:6] == "pauth_" && validLowerHex(value[6:], 32)
}
