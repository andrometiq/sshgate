package policystore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

type ReservationComponents struct {
	Admission           uint64 // A
	Votes               uint64 // V
	Terminal            uint64 // T, the maximal legal path total
	TerminalPending     uint64
	TerminalResult      uint64
	TerminalPublication uint64
	Head                uint64 // H
	Matrix2A            bool
}

func (components ReservationComponents) Total() (uint64, error) {
	return checkedAdd(components.Admission, components.Votes, components.Terminal, components.Head)
}

func (components ReservationComponents) Floor() uint64 {
	if components.Matrix2A {
		return components.Admission
	}
	return 0
}

// MaximalVote constructs, then charges, the maximal schema-legal vote row.
func MaximalVote() (Vote, uint64, error) {
	vote := Vote{
		Principal: strings.Repeat("p", MaxIdentityBytes),
		RequestID: "pm_" + strings.Repeat("a", 32),
		Operator:  strings.Repeat("o", MaxIdentityBytes),
		Decision:  DecisionApprove, AuthnMethod: AuthnSession,
		Timestamp: math.MaxInt64, Audited: true, AuditStateVersion: math.MaxInt64,
		TupleDigest: strings.Repeat("b", 64), Purpose: policywire.Purpose,
		PayloadSHA256: strings.Repeat("c", 64), CandidateDigest: strings.Repeat("d", 64),
		HeadDigest: strings.Repeat("e", 64), SignerKeyID: strings.Repeat("f", 64),
	}
	fields, err := VoteFields(vote)
	if err != nil {
		return Vote{}, 0, err
	}
	charge, err := VoteLogicalCharge(fields)
	if err != nil {
		return Vote{}, 0, err
	}
	vote.LogicalBytes = charge
	return vote, charge, nil
}

func MaxVoteCharge() (uint64, error) {
	_, charge, err := MaximalVote()
	return charge, err
}

type TerminalCommitments struct {
	Pending     uint64
	Result      uint64
	Publication uint64
	Accepted    uint64
	Matrix2A    uint64
}

// TerminalGroupMaximum derives T from the frozen field caps and types.
func TerminalGroupMaximum() (TerminalCommitments, error) {
	pending := uint64(policywire.MaxResponseFrameBytes)
	maxEnvelope, err := SignedEnvelopeLength(policy.MaxPolicyPayloadBytes)
	if err != nil {
		return TerminalCommitments{}, err
	}
	result, err := checkedAdd(maxEnvelope, 64)
	if err != nil {
		return TerminalCommitments{}, err
	}
	terminal, err := checkedAdd(uint64(policywire.MaxResponseFrameBytes), 8, 8)
	if err != nil {
		return TerminalCommitments{}, err
	}
	accepted, err := checkedAdd(pending, result, terminal)
	if err != nil {
		return TerminalCommitments{}, err
	}
	return TerminalCommitments{Pending: pending, Result: result, Publication: terminal, Accepted: accepted, Matrix2A: terminal}, nil
}

func PendingWriteCharge(response []byte) uint64 { return uint64(len(response)) }
func ResultWriteCharge(envelope []byte, sha256Text string) (uint64, error) {
	if len(envelope) == 0 || len(envelope) > policy.MaxPolicyEnvelopeBytes || !validLowerHex(sha256Text, 64) {
		return 0, errors.New("policy store: invalid result write")
	}
	return checkedAdd(uint64(len(envelope)), uint64(len(sha256Text)))
}
func TerminalWriteCharge(response []byte) (uint64, error) {
	if len(response) == 0 || len(response) > policywire.MaxResponseFrameBytes {
		return 0, errors.New("policy store: terminal response outside bounds")
	}
	return checkedAdd(uint64(len(response)), 8, 8)
}

// TerminalGroupCharge charges one concrete approval-path group image. Tests
// use it to prove the derived maximum against maximal legal field values.
func TerminalGroupCharge(pendingResponse, resultEnvelope []byte, resultSHA256 string, terminalResponse []byte) (uint64, error) {
	if len(pendingResponse) == 0 || len(pendingResponse) > policywire.MaxResponseFrameBytes {
		return 0, errors.New("policy store: pending response outside bounds")
	}
	result, err := ResultWriteCharge(resultEnvelope, resultSHA256)
	if err != nil {
		return 0, err
	}
	terminal, err := TerminalWriteCharge(terminalResponse)
	if err != nil {
		return 0, err
	}
	return checkedAdd(uint64(len(pendingResponse)), result, terminal)
}

// SignedEnvelopeLength returns the exact canonical envelope size for a payload
// and a fixed-size Ed25519 signature, without minting a signature.
func SignedEnvelopeLength(payloadLength int) (uint64, error) {
	if payloadLength <= 0 || payloadLength > policy.MaxPolicyPayloadBytes {
		return 0, errors.New("policy store: payload length outside policy bounds")
	}
	const emptyFrame = `{"payload_b64":"","signature_b64":""}`
	return checkedAdd(uint64(len(emptyFrame)), uint64(base64.StdEncoding.EncodedLen(payloadLength)), uint64(base64.StdEncoding.EncodedLen(ed25519.SignatureSize)))
}

type CandidateHeadInput struct {
	AuthorityID     string
	HostKeyFP       string
	Payload         []byte
	PayloadSHA256   string
	BaseDigest      string
	SignerKeyID     string
	SignerPublicKey ed25519.PublicKey
	RowVersion      uint64
	UpdatedAt       int64
}

// CandidateHeadImage constructs the exact row shape approval would persist.
// The signature bytes are fixed-size placeholders; only their deterministic
// canonical envelope length participates in accounting.
func CandidateHeadImage(input CandidateHeadInput) (Head, error) {
	if !validAuthorityID(input.AuthorityID) || input.HostKeyFP == "" || input.RowVersion == 0 || input.RowVersion > math.MaxInt64 {
		return Head{}, errors.New("policy store: invalid candidate head identity")
	}
	manifest, err := policy.ParseBaseManifest(input.Payload)
	if err != nil {
		return Head{}, fmt.Errorf("policy store: candidate payload: %w", err)
	}
	if manifest.Host != input.HostKeyFP {
		return Head{}, errors.New("policy store: candidate host mismatch")
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(input.Payload)
	if err != nil {
		return Head{}, err
	}
	if payloadSHA != input.PayloadSHA256 || baseDigest != input.BaseDigest {
		return Head{}, errors.New("policy store: candidate digest mismatch")
	}
	keyID, err := policy.SignerKeyID(input.SignerPublicKey)
	if err != nil || keyID != input.SignerKeyID {
		return Head{}, errors.New("policy store: candidate signer key mismatch")
	}
	envelope, err := policy.EncodeBaseManifestEnvelope(input.Payload, make([]byte, ed25519.SignatureSize))
	if err != nil {
		return Head{}, err
	}
	var epochBE, revisionBE [8]byte
	binary.BigEndian.PutUint64(epochBE[:], manifest.Epoch)
	binary.BigEndian.PutUint64(revisionBE[:], manifest.Revision)
	head := Head{AuthoritySingleton: 1, AuthorityID: input.AuthorityID, HostKeyFP: input.HostKeyFP,
		ManifestEnvelope: envelope, PayloadSHA256: input.PayloadSHA256, BaseDigest: input.BaseDigest,
		EpochBE: epochBE[:], RevisionBE: revisionBE[:], SignerKeyID: input.SignerKeyID,
		SignerPublicKey: append(ed25519.PublicKey(nil), input.SignerPublicKey...), RowVersion: input.RowVersion, UpdatedAt: input.UpdatedAt}
	fields, err := HeadFields(head)
	if err != nil {
		return Head{}, err
	}
	charge, err := HeadLogicalCharge(fields)
	if err != nil {
		return Head{}, err
	}
	head.LogicalBytes = charge
	return head, nil
}

// HeadGrowthReservation computes exact bootstrap insertion or successor growth.
func HeadGrowthReservation(candidate Head, trusted *Head) (uint64, error) {
	fields, err := HeadFields(candidate)
	if err != nil {
		return 0, err
	}
	newCharge, err := HeadLogicalCharge(fields)
	if err != nil {
		return 0, err
	}
	if candidate.LogicalBytes != 0 && candidate.LogicalBytes != newCharge {
		return 0, errors.New("policy store: candidate head logical byte mismatch")
	}
	if trusted == nil {
		return newCharge, nil
	}
	trustedFields, err := HeadFields(*trusted)
	if err != nil {
		return 0, err
	}
	trustedCharge, err := HeadLogicalCharge(trustedFields)
	if err != nil {
		return 0, err
	}
	if trusted.LogicalBytes != trustedCharge {
		return 0, errors.New("policy store: trusted head logical byte mismatch")
	}
	if newCharge <= trustedCharge {
		return 0, nil
	}
	return newCharge - trustedCharge, nil
}

func AcceptedReservation(canonicalRequest, payload []byte, candidate Head, trusted *Head) (ReservationComponents, error) {
	if len(canonicalRequest) == 0 || len(canonicalRequest) > policywire.MaxRequestFrameBytes || len(payload) == 0 || len(payload) > policy.MaxPolicyPayloadBytes {
		return ReservationComponents{}, errors.New("policy store: accepted admission bytes outside bounds")
	}
	a, err := checkedAdd(uint64(len(canonicalRequest)), uint64(len(payload)))
	if err != nil {
		return ReservationComponents{}, err
	}
	maxVote, err := MaxVoteCharge()
	if err != nil {
		return ReservationComponents{}, err
	}
	v, err := checkedMultiply(MaxVotesPerRequest, maxVote)
	if err != nil {
		return ReservationComponents{}, err
	}
	t, err := TerminalGroupMaximum()
	if err != nil {
		return ReservationComponents{}, err
	}
	h, err := HeadGrowthReservation(candidate, trusted)
	if err != nil {
		return ReservationComponents{}, err
	}
	components := ReservationComponents{Admission: a, Votes: v, Terminal: t.Accepted,
		TerminalPending: t.Pending, TerminalResult: t.Result, TerminalPublication: t.Publication, Head: h}
	_, err = components.Total()
	return components, err
}

func Matrix2AReservation(canonicalRequest, payload []byte) (ReservationComponents, error) {
	if len(canonicalRequest) == 0 || len(canonicalRequest) > policywire.MaxRequestFrameBytes || len(payload) == 0 || len(payload) > policy.MaxPolicyPayloadBytes {
		return ReservationComponents{}, errors.New("policy store: rejection admission bytes outside bounds")
	}
	a, err := checkedAdd(uint64(len(canonicalRequest)), uint64(len(payload)))
	if err != nil {
		return ReservationComponents{}, err
	}
	t, err := TerminalGroupMaximum()
	if err != nil {
		return ReservationComponents{}, err
	}
	components := ReservationComponents{Admission: a, Terminal: t.Matrix2A,
		TerminalPublication: t.Publication, Matrix2A: true}
	_, err = components.Total()
	return components, err
}

func AdmissionRemaining(components ReservationComponents, pendingResponse []byte) (uint64, error) {
	if err := components.validateTerminalSplit(); err != nil {
		return 0, err
	}
	charge := PendingWriteCharge(pendingResponse)
	if !components.Matrix2A && (len(pendingResponse) == 0 || len(pendingResponse) > policywire.MaxResponseFrameBytes) {
		return 0, errors.New("policy store: accepted admission pending response outside bounds")
	}
	if components.Matrix2A && charge != 0 {
		return 0, errors.New("policy store: Matrix-2a admission cannot write pending response")
	}
	if charge > components.Terminal {
		return 0, errors.New("policy store: pending write exceeds terminal commitment")
	}
	return checkedAdd(components.Admission, components.Votes, components.Terminal-charge, components.Head)
}

func CheckGlobalHeadroom(logicalUsedBytes, logicalReservedBytes uint64) error {
	total, err := checkedAdd(logicalUsedBytes, logicalReservedBytes)
	if err != nil || total > MaxLogicalBytes {
		return &CapacityError{Kind: CapacityGlobalHeadroom}
	}
	return nil
}

type RemainingInput struct {
	Components       ReservationComponents
	State            State
	ConsumedVotes    uint64
	ConsumedTerminal uint64
	HeadConsumed     bool
}

func (components ReservationComponents) validateTerminalSplit() error {
	if components.Matrix2A {
		if components.TerminalPending != 0 || components.TerminalResult != 0 ||
			components.TerminalPublication != components.Terminal {
			return errors.New("policy store: invalid Matrix-2a terminal commitment split")
		}
		return nil
	}
	total, err := checkedAdd(components.TerminalPending, components.TerminalResult, components.TerminalPublication)
	if err != nil || total != components.Terminal {
		return errors.New("policy store: invalid accepted terminal commitment split")
	}
	return nil
}

type Reachability struct{ Admission, Votes, Terminal, Head bool }

// StateReachability derives which writes remain reachable from the state graph.
func StateReachability(state State, matrix2A bool) (Reachability, error) {
	if !state.Valid() {
		return Reachability{}, errors.New("policy store: invalid state")
	}
	if state.Terminal() {
		if matrix2A && state != StateError {
			return Reachability{}, errors.New("policy store: invalid Matrix-2a terminal")
		}
		return Reachability{Admission: matrix2A}, nil
	}
	if matrix2A {
		if state != StateRejectionUnaudited && state != StateRejectionErrorReceived {
			return Reachability{}, errors.New("policy store: invalid Matrix-2a state")
		}
		return Reachability{Admission: true, Terminal: true}, nil
	}
	if state == StateRejectionUnaudited || state == StateRejectionErrorReceived {
		return Reachability{}, errors.New("policy store: rejection state without Matrix-2a origin")
	}
	reachable := Reachability{Admission: true, Terminal: true}
	reachable.Votes = state == StateReceivedUnaudited || state == StatePending
	switch state {
	case StateReceivedUnaudited, StatePending, StateApprovedMaterializing, StateApprovedUnexposed:
		reachable.Head = true
	}
	return reachable, nil
}

// DeriveRemaining mechanically applies the component rules to a row image.
func DeriveRemaining(input RemainingInput) (uint64, error) {
	if err := input.Components.validateTerminalSplit(); err != nil {
		return 0, err
	}
	reachable, err := StateReachability(input.State, input.Components.Matrix2A)
	if err != nil {
		return 0, err
	}
	if input.ConsumedVotes > input.Components.Votes || input.ConsumedTerminal > input.Components.TerminalPending {
		return 0, errors.New("policy store: consumed bytes exceed commitment")
	}
	var values []uint64
	if reachable.Admission {
		values = append(values, input.Components.Admission)
	}
	if reachable.Votes {
		values = append(values, input.Components.Votes-input.ConsumedVotes)
	}
	if reachable.Terminal {
		var terminal uint64
		switch input.State {
		case StateReceivedUnaudited, StatePending:
			terminal = input.Components.Terminal - input.ConsumedTerminal
		case StateApprovedMaterializing:
			terminal, err = checkedAdd(input.Components.TerminalResult, input.Components.TerminalPublication)
		case StateRejectionUnaudited, StateRejectionErrorReceived,
			StateApprovedUnexposed, StateNoOpUnexposed, StateDenialReceived, StateErrorReceived:
			terminal = input.Components.TerminalPublication
		default:
			return 0, errors.New("policy store: no terminal rule for state")
		}
		if err != nil {
			return 0, err
		}
		values = append(values, terminal)
	}
	if reachable.Head && !input.HeadConsumed {
		values = append(values, input.Components.Head)
	}
	return checkedAdd(values...)
}

type ReservationTransition struct {
	From, To                         State
	Before, After, Written, Released uint64
}

func DeriveTransition(from, to RemainingInput, written uint64) (ReservationTransition, error) {
	if from.Components != to.Components {
		return ReservationTransition{}, errors.New("policy store: transition changed reservation components")
	}
	before, err := DeriveRemaining(from)
	if err != nil {
		return ReservationTransition{}, err
	}
	after, err := DeriveRemaining(to)
	if err != nil {
		return ReservationTransition{}, err
	}
	consumedAndRemaining, err := checkedAdd(written, after)
	if err != nil {
		return ReservationTransition{}, err
	}
	if consumedAndRemaining > before {
		return ReservationTransition{}, errors.New("policy store: transition increases commitment")
	}
	return ReservationTransition{From: from.State, To: to.State, Before: before, After: after, Written: written, Released: before - consumedAndRemaining}, nil
}
