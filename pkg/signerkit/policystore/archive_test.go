package policystore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func TestArchiveFieldFramingNullEmptyAndInteger(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	for _, field := range []Field{NullField(), TextField(""), BlobField([]byte{}), IntegerField(-2)} {
		if err := encodeField(&output, field); err != nil {
			t.Fatal(err)
		}
	}
	want := []byte{
		0,
		1, 0, 0, 0, 0,
		1, 0, 0, 0, 0,
		1, 0, 0, 0, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	}
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatalf("field framing = %x, want %x", output.Bytes(), want)
	}
}

func archiveRecordFixture(t *testing.T) ArchiveRecord {
	t.Helper()
	terminal := []byte(`{"request_id":"pm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"approved"}`)
	terminalHash := sha256.Sum256(terminal)
	frozenPublicKey := make([]byte, 32)
	frozenKeyID, err := policy.SignerKeyID(frozenPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	reviewJSON := []byte(`{"review":1}`)
	reviewHash := sha256.Sum256(reviewJSON)
	votersJSON := []byte(`["operator"]`)
	votersHash := sha256.Sum256(votersJSON)
	methodsJSON := []byte(`["session"]`)
	methodsHash := sha256.Sum256(methodsJSON)
	request := Request{
		Principal: "requester", RequestID: "pm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ReviewID: "pr_0123456789abcdef0123456789abcdef", AuthoritySingleton: 1,
		AuthorityID: "pauth_0123456789abcdef0123456789abcdef", StorageKind: StorageFull,
		Purpose: policywire.Purpose, CanonicalRequest: []byte(`{"request":1}`), Payload: []byte(`{"payload":1}`),
		TupleDigest: strings.Repeat("1", 64), PayloadSHA256: strings.Repeat("2", 64), BaseDigest: strings.Repeat("3", 64),
		HostKeyFP: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ExpectedHeadDigest: "", ExpectedSignerKeyID: frozenKeyID,
		Bootstrap: true, FrozenSignerKeyID: NullableString{Value: frozenKeyID, Valid: true}, FrozenSignerPublicKey: frozenPublicKey,
		EpochBE: []byte{0, 0, 0, 0, 0, 0, 0, 1}, RevisionBE: []byte{0, 0, 0, 0, 0, 0, 0, 1},
		MissAction: "deny", Growth: "none", EntryCount: 0, RevocationCount: 0, LogicalChangeCount: 1,
		ReviewJSON: reviewJSON, ReviewSHA256: NullableString{Value: hex.EncodeToString(reviewHash[:]), Valid: true},
		ReviewRenderedBytes: NullableInt64{Value: 12, Valid: true}, ReviewItemCount: NullableInt64{Value: 1, Valid: true},
		ReviewRendererVersion: NullableString{Value: "sshgate-policy-review-v2", Valid: true}, ReviewRulesDigest: NullableString{Value: strings.Repeat("6", 64), Valid: true},
		EligibleVotersJSON: votersJSON, EligibleVotersSHA256: NullableString{Value: hex.EncodeToString(votersHash[:]), Valid: true},
		EligibleVoterCount: NullableInt64{Value: 1, Valid: true}, VoteAuthMethodsJSON: methodsJSON, VoteAuthMethodsSHA256: hex.EncodeToString(methodsHash[:]),
		RequiredApprovals: 1, RequesterPrincipal: "requester", State: StateApproved, StateVersion: 5,
		SubmissionAudited: true, PreMintAudited: true, ResultAudited: true, TerminalAudited: true,
		ResultEnvelope: []byte(`{"result":1}`), ResultSHA256: strings.Repeat("9", 64), PendingResponse: []byte(`{"status":"pending"}`),
		TerminalResponse: terminal, TerminalHTTPStatus: NullableInt64{Value: 200, Valid: true}, ReservedBytes: 0,
		RecoveryLeaseOwner: "", RecoveryLeaseUntil: 0, RecoveryLeaseGeneration: 1,
		CreatedAt: 10, UpdatedAt: 20, ResolvedAt: NullableInt64{Value: 20, Valid: true},
	}
	fields, err := RequestFields(request)
	if err != nil {
		t.Fatal(err)
	}
	request.LogicalBytes, err = RequestLogicalCharge(fields)
	if err != nil {
		t.Fatal(err)
	}
	vote := Vote{Principal: request.Principal, RequestID: request.RequestID, Operator: "operator", Decision: DecisionApprove,
		AuthnMethod: AuthnSession, Timestamp: 15, Audited: true, AuditStateVersion: 2, TupleDigest: request.TupleDigest,
		Purpose: request.Purpose, PayloadSHA256: request.PayloadSHA256, CandidateDigest: request.BaseDigest,
		HeadDigest: "", SignerKeyID: request.ExpectedSignerKeyID}
	voteFields, err := VoteFields(vote)
	if err != nil {
		t.Fatal(err)
	}
	vote.LogicalBytes, err = VoteLogicalCharge(voteFields)
	if err != nil {
		t.Fatal(err)
	}
	return ArchiveRecord{ArchiveID: "parch_abcdef0123456789abcdef0123456789", AuthorityID: request.AuthorityID,
		TerminalResponseSHA256: hex.EncodeToString(terminalHash[:]), TerminalResponseBytes: int64(len(terminal)), Request: request, Votes: []Vote{vote}}
}

func TestCensusAndFieldRoundTrip(t *testing.T) {
	t.Parallel()
	if len(MetaColumns) != 28 || len(RequestColumns) != 83 || len(VoteColumns) != 15 || len(HeadColumns) != 13 {
		t.Fatalf("census counts = %d/%d/%d/%d", len(MetaColumns), len(RequestColumns), len(VoteColumns), len(HeadColumns))
	}
	if got := reflect.TypeOf(Request{}).NumField(); got != RequestColumnCount {
		t.Fatalf("Request has %d fields, want %d", got, RequestColumnCount)
	}
	if got := reflect.TypeOf(Vote{}).NumField(); got != VoteColumnCount {
		t.Fatalf("Vote has %d fields, want %d", got, VoteColumnCount)
	}
	if got := reflect.TypeOf(Head{}).NumField(); got != HeadColumnCount {
		t.Fatalf("Head has %d fields, want %d", got, HeadColumnCount)
	}
	for _, columns := range [][]Column{MetaColumns[:], RequestColumns[:], VoteColumns[:], HeadColumns[:]} {
		seen := make(map[string]bool, len(columns))
		for _, column := range columns {
			if seen[column.Name] {
				t.Fatalf("duplicate census column %q", column.Name)
			}
			seen[column.Name] = true
		}
	}
	record := archiveRecordFixture(t)
	fields, err := RequestFields(record.Request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := RequestFromFields(fields)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, record.Request) {
		t.Fatalf("request field round trip changed value\n got %#v\nwant %#v", decoded, record.Request)
	}
	voteFields, err := VoteFields(record.Votes[0])
	if err != nil {
		t.Fatal(err)
	}
	vote, err := VoteFromFields(voteFields)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vote, record.Votes[0]) {
		t.Fatalf("vote field round trip changed value")
	}
}

func TestArchiveRecordGoldenAndRoundTrip(t *testing.T) {
	t.Parallel()
	record := archiveRecordFixture(t)
	encoded, err := record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	const goldenSHA256 = "3da4c209a33eb9c7c5e939a3e467adb9e04f08a4884682dfe4936f22307146c5"
	if got := hex.EncodeToString(hash[:]); got != goldenSHA256 {
		t.Fatalf("archive v3 golden changed: got %s want %s", got, goldenSHA256)
	}
	decoded, err := DecodeArchiveRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, record) {
		t.Fatalf("archive round trip changed record")
	}
	if _, err := DecodeArchiveRecord(append(encoded, 0)); err == nil {
		t.Fatal("archive trailing byte accepted")
	}
	ref, complete, err := record.ObjectRef()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(complete, encoded) || ref.RecordBytes != int64(len(encoded)) || !validLowerHex(ref.ObjectSHA256, 64) {
		t.Fatalf("object ref = %+v", ref)
	}
}

func TestArchiveRecordValidationRejectsBoundFieldCorruption(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*ArchiveRecord){
		"authority":     func(record *ArchiveRecord) { record.Request.AuthorityID = "pauth_1123456789abcdef0123456789abcdef" },
		"terminal hash": func(record *ArchiveRecord) { record.TerminalResponseSHA256 = strings.Repeat("0", 64) },
		"logical bytes": func(record *ArchiveRecord) { record.Request.LogicalBytes++ },
		"review accounting": func(record *ArchiveRecord) {
			record.Request.ReviewRenderedBytes.Value++
		},
		"vote frozen tuple": func(record *ArchiveRecord) { record.Votes[0].TupleDigest = strings.Repeat("0", 64) },
		"partial archive reference": func(record *ArchiveRecord) {
			record.Request.ArchiveID = NullableString{Value: record.ArchiveID, Valid: true}
		},
		"duplicate vote": func(record *ArchiveRecord) { record.Votes = append(record.Votes, record.Votes[0]) },
	} {
		record := archiveRecordFixture(t)
		mutate(&record)
		if _, err := record.Encode(); err == nil {
			t.Errorf("%s corruption encoded", name)
		}
	}
}

func TestArchiveBindingGoldenAndRoundTrip(t *testing.T) {
	t.Parallel()
	binding := ArchiveBinding{ArchiveID: "parch_abcdef0123456789abcdef0123456789", AuthorityID: "pauth_0123456789abcdef0123456789abcdef"}
	encoded, err := binding.Encode()
	if err != nil {
		t.Fatal(err)
	}
	const goldenHex = "737368676174652d706f6c6963792d617263686976652d62696e64696e672d76310000000002010000002670617263685f6162636465663031323334353637383961626364656630313233343536373839010000002670617574685f3031323334353637383961626364656630313233343536373839616263646566"
	if got := hex.EncodeToString(encoded); got != goldenHex {
		t.Fatalf("binding golden changed: got %s want %s", got, goldenHex)
	}
	decoded, err := DecodeArchiveBinding(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != binding {
		t.Fatalf("binding round trip = %+v", decoded)
	}
	if _, err := DecodeArchiveBinding(append(encoded, '\n')); err == nil {
		t.Fatal("binding trailing newline accepted")
	}
}
