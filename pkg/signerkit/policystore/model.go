package policystore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

type State string

const (
	StateReceivedUnaudited      State = "received_unaudited"
	StateRejectionUnaudited     State = "rejection_unaudited"
	StateRejectionErrorReceived State = "rejection_error_received"
	StatePending                State = "pending"
	StateApprovedMaterializing  State = "approved_materializing"
	StateApprovedUnexposed      State = "approved_unexposed"
	StateNoOpUnexposed          State = "no_op_unexposed"
	StateDenialReceived         State = "denial_received"
	StateErrorReceived          State = "error_received"
	StateApproved               State = "approved"
	StateDenied                 State = "denied"
	StateError                  State = "error"
)

var AllStates = [...]State{
	StateReceivedUnaudited, StateRejectionUnaudited,
	StateRejectionErrorReceived, StatePending, StateApprovedMaterializing,
	StateApprovedUnexposed, StateNoOpUnexposed, StateDenialReceived,
	StateErrorReceived, StateApproved, StateDenied, StateError,
}

func (state State) Valid() bool {
	for _, candidate := range AllStates {
		if state == candidate {
			return true
		}
	}
	return false
}

func (state State) Terminal() bool {
	return state == StateApproved || state == StateDenied || state == StateError
}

func (state State) Active() bool {
	switch state {
	case StateReceivedUnaudited, StatePending, StateApprovedMaterializing,
		StateApprovedUnexposed, StateNoOpUnexposed, StateDenialReceived,
		StateErrorReceived:
		return true
	default:
		return false
	}
}

type StorageKind string

const (
	StorageFull      StorageKind = "full"
	StorageTombstone StorageKind = "tombstone"
)

type ErrorFamily string

const (
	ErrorFamilyNone        ErrorFamily = ""
	ErrorFamilySemantic    ErrorFamily = "semantic-rejection"
	ErrorFamilyProcessing  ErrorFamily = "processing-error"
	ErrorFamilyPublication ErrorFamily = "publication-error"
)

type Decision string

const (
	DecisionApprove Decision = "approve"
	DecisionDeny    Decision = "deny"
)

type AuthnMethod string

const (
	AuthnSession AuthnMethod = "session"
	AuthnTOTP    AuthnMethod = "totp"
)

type Key struct {
	Principal string
	RequestID string
}

type RequestTuple = policyauthority.RequestTuple

type NullableString struct {
	Value string
	Valid bool
}

type NullableInt64 struct {
	Value int64
	Valid bool
}

type Request struct {
	Principal               string
	RequestID               string
	ReviewID                string
	AuthoritySingleton      int64
	AuthorityID             string
	StorageKind             StorageKind
	Purpose                 string
	CanonicalRequest        []byte
	Payload                 []byte
	TupleDigest             string
	PayloadSHA256           string
	BaseDigest              string
	HostKeyFP               string
	ExpectedHeadDigest      string
	ExpectedSignerKeyID     string
	Bootstrap               bool
	TrustedHeadEnvelope     []byte
	TrustedHeadDigest       NullableString
	TrustedHeadKeyID        NullableString
	TrustedHeadPublicKey    []byte
	TrustedHeadEpochBE      []byte
	TrustedHeadRevisionBE   []byte
	TrustedHeadRowVersion   NullableInt64
	ClaimedHeadEnvelope     []byte
	ClaimedHeadDigest       NullableString
	ClaimedHeadKeyID        NullableString
	ClaimedHeadPublicKey    []byte
	ClaimedHeadEpochBE      []byte
	ClaimedHeadRevisionBE   []byte
	ClaimedHeadRowVersion   NullableInt64
	FrozenSignerKeyID       NullableString
	FrozenSignerPublicKey   []byte
	EpochBE                 []byte
	RevisionBE              []byte
	MissAction              string
	Growth                  string
	EntryCount              int64
	RevocationCount         int64
	LogicalChangeCount      int64
	ReviewJSON              []byte
	ReviewSHA256            NullableString
	ReviewRenderedBytes     NullableInt64
	ReviewItemCount         NullableInt64
	ReviewRendererVersion   NullableString
	ReviewRulesDigest       NullableString
	EligibleVotersJSON      []byte
	EligibleVotersSHA256    NullableString
	EligibleVoterCount      NullableInt64
	VoteStepUpRequired      bool
	VoteAuthMethodsJSON     []byte
	VoteAuthMethodsSHA256   string
	RequiredApprovals       int64
	DenyVeto                bool
	AllowSelfApprove        bool
	RequesterPrincipal      string
	State                   State
	StateVersion            uint64
	SubmissionAudited       bool
	PreMintAudited          bool
	ResultAudited           bool
	TerminalAudited         bool
	NoOp                    bool
	ErrorFamily             ErrorFamily
	FailureCode             policywire.ErrorCode
	ResultEnvelope          []byte
	ResultSHA256            string
	PendingResponse         []byte
	TerminalResponse        []byte
	TerminalHTTPStatus      NullableInt64
	ReservedBytes           uint64
	RecoveryLeaseOwner      string
	RecoveryLeaseUntil      int64
	RecoveryLeaseGeneration uint64
	ArchiveID               NullableString
	ArchiveObjectSHA256     NullableString
	ArchiveRecordBytes      NullableInt64
	TerminalResponseSHA256  NullableString
	TerminalResponseBytes   NullableInt64
	CompactionDeleteGuard   bool
	LogicalBytes            uint64
	CreatedAt               int64
	UpdatedAt               int64
	ResolvedAt              NullableInt64
}

func (request *Request) Key() Key {
	if request == nil {
		return Key{}
	}
	return Key{Principal: request.Principal, RequestID: request.RequestID}
}

func (request *Request) ArchiveRef() *ArchiveRef {
	if request == nil || !request.ArchiveID.Valid || !request.ArchiveObjectSHA256.Valid ||
		!request.ArchiveRecordBytes.Valid || !request.TerminalResponseSHA256.Valid ||
		!request.TerminalResponseBytes.Valid {
		return nil
	}
	return &ArchiveRef{
		ArchiveID:              request.ArchiveID.Value,
		ObjectSHA256:           request.ArchiveObjectSHA256.Value,
		RecordBytes:            request.ArchiveRecordBytes.Value,
		TerminalResponseSHA256: request.TerminalResponseSHA256.Value,
		TerminalResponseBytes:  request.TerminalResponseBytes.Value,
	}
}

type Vote struct {
	Principal         string
	RequestID         string
	Operator          string
	Decision          Decision
	AuthnMethod       AuthnMethod
	Timestamp         int64
	Audited           bool
	AuditStateVersion uint64
	TupleDigest       string
	Purpose           string
	PayloadSHA256     string
	CandidateDigest   string
	HeadDigest        string
	SignerKeyID       string
	LogicalBytes      uint64
}

func (vote *Vote) Key() Key {
	if vote == nil {
		return Key{}
	}
	return Key{Principal: vote.Principal, RequestID: vote.RequestID}
}

type Head struct {
	AuthoritySingleton int64
	AuthorityID        string
	HostKeyFP          string
	ManifestEnvelope   []byte
	PayloadSHA256      string
	BaseDigest         string
	EpochBE            []byte
	RevisionBE         []byte
	SignerKeyID        string
	SignerPublicKey    ed25519.PublicKey
	RowVersion         uint64
	LogicalBytes       uint64
	UpdatedAt          int64
}

type AuthorityBinding struct {
	AuthorityID                           string
	ArchiveID                             string
	AccountingVersion                     string
	ConfigDigest                          string
	SignerKeyID                           string
	SignerPublicKey                       ed25519.PublicKey
	MaxRejectionReservedBytesPerPrincipal uint64
	Config                                ConfigDigestInput
}

type RowClass string

const (
	RowLive      RowClass = "live"
	RowTerminal  RowClass = "terminal"
	RowTombstone RowClass = "tombstone"
)

type Visibility string

const (
	VisibilityUnavailable Visibility = "unavailable"
	VisibilityPending     Visibility = "pending"
)

type LookupKind string

const (
	LookupAbsent   LookupKind = "absent"
	LookupExact    LookupKind = "exact"
	LookupConflict LookupKind = "conflict"
)

type LookupResult struct {
	Kind       LookupKind
	Class      RowClass
	Visibility Visibility
	Request    *Request
	Archive    *ArchiveRef
}

type FetchResult struct {
	Class              RowClass
	Visibility         Visibility
	State              State
	TerminalHTTPStatus int
	TerminalResponse   []byte
	Archive            *ArchiveRef
}

type BeginInput struct {
	Key                   Key
	Tuple                 RequestTuple
	CanonicalRequest      []byte
	Payload               []byte
	AuthorityID           string
	ReviewID              string
	RequesterPrincipal    string
	SignerKeyID           string
	SignerPublicKey       ed25519.PublicKey
	ReviewJSON            []byte
	ReviewRenderedBytes   int64
	ReviewItemCount       int64
	ReviewRendererVersion string
	ReviewRulesDigest     string
	Now                   time.Time
}

type BeginResult struct {
	Lookup  LookupResult
	Request *Request
}

type VoteInput struct {
	ReviewID    string
	Operator    string
	Decision    Decision
	AuthnMethod AuthnMethod
	Now         time.Time
}

type VoteResult struct {
	Vote       *Vote
	NeedsAudit bool
	Tally      TallyResult
}

type TallyResult struct {
	Approvals       int
	Denials         int
	Unaudited       int
	Required        int
	Eligible        int
	ApprovalReached bool
	DenialReached   bool
}

type AttainabilityResult struct {
	Examined     []Key
	Unattainable []Key
}

type Lease struct {
	Key        Key
	Owner      string
	Generation uint64
	Until      time.Time
}

type WorkLease struct {
	Lease
	StateVersion uint64
}

type PendingCursor struct {
	CreatedAt            int64
	Principal, RequestID string
}
type RecoveryCursor struct {
	UpdatedAt            int64
	Principal, RequestID string
}
type TerminalCursor struct {
	ResolvedAt           int64
	Principal, RequestID string
}
type VoteCursor struct{ Operator string }

type PendingPage struct {
	Requests []*Request
	Next     *PendingCursor
}
type RecoveryPage struct {
	Requests []*Request
	Next     *RecoveryCursor
}
type VoteRecoveryPage struct {
	Votes []*Vote
	Next  *RecoveryCursor
}
type TerminalPage struct {
	Requests []*Request
	Next     *TerminalCursor
}
type VotePage struct {
	Votes []*Vote
	Next  *VoteCursor
}
type CompactionPage struct {
	Requests []*Request
	Next     *TerminalCursor
}

type CompactionResult struct {
	Request          *Request
	AlreadyCompacted bool
}

var (
	ErrNotFound          = errors.New("policy store: not found")
	ErrConflict          = errors.New("policy store: conflict")
	ErrVoteConflict      = errors.New("policy store: vote conflict")
	ErrUnavailable       = errors.New("policy store: unavailable")
	ErrCapacity          = errors.New("policy store: capacity exceeded")
	ErrCounterDrift      = errors.New("policy store: counter drift")
	ErrCorrupt           = errors.New("policy store: corrupt")
	ErrStaleVersion      = errors.New("policy store: stale version")
	ErrLeaseLost         = errors.New("policy store: recovery lease lost")
	ErrUnauditedVote     = errors.New("policy store: unaudited vote")
	ErrAuthorityMismatch = errors.New("policy store: authority mismatch")
)

type CounterDriftError struct {
	Counter            string
	Stored, Recomputed uint64
}

func (err *CounterDriftError) Error() string {
	return fmt.Sprintf("policy counter drift: %s stored=%d recomputed=%d", err.Counter, err.Stored, err.Recomputed)
}
func (err *CounterDriftError) Unwrap() error { return ErrCounterDrift }

type CapacityKind string

const (
	CapacityWindow         CapacityKind = "rejection_window"
	CapacityRetainedRows   CapacityKind = "rejection_retained_rows"
	CapacityRetainedBytes  CapacityKind = "rejection_retained_bytes"
	CapacityGlobalHeadroom CapacityKind = "global_headroom"
)

type CapacityError struct {
	Kind       CapacityKind
	RetryAfter time.Duration
}

func (err *CapacityError) Error() string {
	return fmt.Sprintf("policy store: capacity exceeded: %s", err.Kind)
}
func (err *CapacityError) Unwrap() error { return ErrCapacity }

// Store is command-shaped around the durable trust boundaries.
type Store interface {
	BindAuthority(context.Context, AuthorityBinding) error
	VerifyAuthorityBinding(context.Context) (AuthorityBinding, error)
	Lookup(context.Context, Key, RequestTuple) (LookupResult, error)
	Fetch(context.Context, Key) (FetchResult, error)
	Begin(context.Context, BeginInput) (BeginResult, error)
	MarkSubmissionAudited(context.Context, Key, uint64) (*Request, error)
	MarkRejectionSubmissionAudited(context.Context, Key, uint64) (*Request, error)
	ActivateSubmission(context.Context, Key, uint64, time.Time) (*Request, error)
	StageRejectionError(context.Context, Key, uint64, time.Time) (*Request, error)
	PrepareVote(context.Context, VoteInput) (VoteResult, error)
	PublishVoteAudit(context.Context, Key, string, uint64) (TallyResult, error)
	ClaimDenial(context.Context, Key, uint64, time.Time) (*Request, error)
	ClaimApproval(context.Context, Key, uint64, string, time.Time, time.Duration) (WorkLease, error)
	ReconcilePendingAttainability(context.Context, string, time.Time) (AttainabilityResult, error)
	StageQuorumUnattainable(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkPreMintAudited(context.Context, WorkLease) (*Request, error)
	PersistMaterialized(context.Context, WorkLease, []byte, time.Time) (*Request, error)
	MarkResultAudited(context.Context, Key, uint64) (*Request, error)
	PublishApproved(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkNoOpTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishNoOp(context.Context, Key, uint64, time.Time) (*Request, error)
	StageIntakeKeyError(context.Context, Key, uint64, time.Time) (*Request, error)
	StageMaterializationError(context.Context, WorkLease, policywire.ErrorCode, time.Time) (*Request, error)
	StageNoOpError(context.Context, Key, uint64, policywire.ErrorCode, time.Time) (*Request, error)
	StagePublicationError(context.Context, Key, uint64, policywire.ErrorCode, time.Time) (*Request, error)
	MarkErrorTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishError(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkDenialTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishDenied(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkRejectionTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishRejection(context.Context, Key, uint64, time.Time) (*Request, error)
	GetByReviewID(context.Context, string) (*Request, error)
	ListPending(context.Context, string, *PendingCursor, int) (PendingPage, error)
	ListRecovery(context.Context, string, time.Time, *RecoveryCursor, int) (RecoveryPage, error)
	ListUnauditedVotes(context.Context, string, *RecoveryCursor, int) (VoteRecoveryPage, error)
	ListRecentTerminals(context.Context, string, *TerminalCursor, int) (TerminalPage, error)
	AcquireRecoveryLease(context.Context, Key, string, time.Time, time.Duration) (Lease, error)
	ReleaseRecoveryLease(context.Context, Lease) error
	ListVotes(context.Context, Key, *VoteCursor, int) (VotePage, error)
	ListTerminalCompactionCandidates(context.Context, time.Time, *TerminalCursor, int) (CompactionPage, error)
	SnapshotTerminalArchive(context.Context, Key, uint64) (ArchiveRecord, error)
	CommitTerminalArchive(context.Context, Key, uint64, ArchiveRef) (CompactionResult, error)
	Fenced(Lease) RecoveryStore
}

type RecoveryStore interface {
	MarkSubmissionAudited(context.Context, Key, uint64) (*Request, error)
	MarkRejectionSubmissionAudited(context.Context, Key, uint64) (*Request, error)
	ActivateSubmission(context.Context, Key, uint64, time.Time) (*Request, error)
	StageRejectionError(context.Context, Key, uint64, time.Time) (*Request, error)
	PublishVoteAudit(context.Context, Key, string, uint64) (TallyResult, error)
	ClaimDenial(context.Context, Key, uint64, time.Time) (*Request, error)
	ClaimApproval(context.Context, Key, uint64, string, time.Time, time.Duration) (WorkLease, error)
	ReconcilePendingAttainability(context.Context, string, time.Time) (AttainabilityResult, error)
	StageQuorumUnattainable(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkPreMintAudited(context.Context, WorkLease) (*Request, error)
	PersistMaterialized(context.Context, WorkLease, []byte, time.Time) (*Request, error)
	MarkResultAudited(context.Context, Key, uint64) (*Request, error)
	PublishApproved(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkNoOpTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishNoOp(context.Context, Key, uint64, time.Time) (*Request, error)
	StageIntakeKeyError(context.Context, Key, uint64, time.Time) (*Request, error)
	StageMaterializationError(context.Context, WorkLease, policywire.ErrorCode, time.Time) (*Request, error)
	StageNoOpError(context.Context, Key, uint64, policywire.ErrorCode, time.Time) (*Request, error)
	StagePublicationError(context.Context, Key, uint64, policywire.ErrorCode, time.Time) (*Request, error)
	MarkErrorTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishError(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkDenialTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishDenied(context.Context, Key, uint64, time.Time) (*Request, error)
	MarkRejectionTerminalAudited(context.Context, Key, uint64) (*Request, error)
	PublishRejection(context.Context, Key, uint64, time.Time) (*Request, error)
}
