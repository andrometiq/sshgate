package policystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func candidateHeadFixture(t *testing.T) Head {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Epoch: 1, Revision: 1, MissAction: policy.MissActionDeny, Growth: policy.GrowthNone}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	head, err := CandidateHeadImage(CandidateHeadInput{AuthorityID: "pauth_0123456789abcdef0123456789abcdef", HostKeyFP: manifest.Host,
		Payload: payload, PayloadSHA256: payloadSHA, BaseDigest: baseDigest, SignerKeyID: keyID, SignerPublicKey: public, RowVersion: 1, UpdatedAt: 100})
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestGlobalHeadroomUsesPostMutationUsedPlusReserved(t *testing.T) {
	t.Parallel()
	if err := CheckGlobalHeadroom(MaxLogicalBytes-1, 1); err != nil {
		t.Fatal(err)
	}
	if err := CheckGlobalHeadroom(MaxLogicalBytes, 1); !errors.Is(err, ErrCapacity) {
		t.Fatalf("headroom error = %v", err)
	}
}

func TestMaxVoteChargeIsConstructedCensus(t *testing.T) {
	t.Parallel()
	vote, got, err := MaximalVote()
	if err != nil {
		t.Fatal(err)
	}
	if got != 686 {
		t.Fatalf("max vote charge = %d, want independently counted 686", got)
	}
	fields, err := VoteFields(vote)
	if err != nil {
		t.Fatal(err)
	}
	charged, err := VoteLogicalCharge(fields)
	if err != nil {
		t.Fatal(err)
	}
	if charged != got || vote.LogicalBytes != got {
		t.Fatalf("constructed row charge=(%d,%d), want %d", charged, vote.LogicalBytes, got)
	}
}

func TestTerminalMaximumIsDerived(t *testing.T) {
	t.Parallel()
	maximum, err := TerminalGroupMaximum()
	if err != nil {
		t.Fatal(err)
	}
	envelope := uint64(len(`{"payload_b64":"","signature_b64":""}`) + base64.StdEncoding.EncodedLen(policy.MaxPolicyPayloadBytes) + base64.StdEncoding.EncodedLen(ed25519.SignatureSize))
	wantAccepted := uint64(policywire.MaxResponseFrameBytes) + envelope + 64 + uint64(policywire.MaxResponseFrameBytes) + 16
	if maximum.Accepted != wantAccepted {
		t.Fatalf("accepted T = %d, want %d", maximum.Accepted, wantAccepted)
	}
	if maximum.Matrix2A != uint64(policywire.MaxResponseFrameBytes)+16 {
		t.Fatalf("Matrix-2a T = %d", maximum.Matrix2A)
	}
	constructed, err := TerminalGroupCharge(make([]byte, policywire.MaxResponseFrameBytes),
		make([]byte, envelope), string(make([]byte, 64)), make([]byte, policywire.MaxResponseFrameBytes))
	if err == nil {
		t.Fatal("non-hex maximal result digest accepted")
	}
	constructed, err = TerminalGroupCharge(make([]byte, policywire.MaxResponseFrameBytes),
		make([]byte, envelope), string(make([]byte, 0)), make([]byte, policywire.MaxResponseFrameBytes))
	if err == nil {
		t.Fatal("empty maximal result digest accepted")
	}
	constructed, err = TerminalGroupCharge(make([]byte, policywire.MaxResponseFrameBytes),
		make([]byte, envelope), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", make([]byte, policywire.MaxResponseFrameBytes))
	if err != nil {
		t.Fatal(err)
	}
	if constructed != maximum.Accepted {
		t.Fatalf("constructed terminal group=%d, maximum=%d", constructed, maximum.Accepted)
	}
}

func TestExactHeadGrowthBootstrapAndSuccessor(t *testing.T) {
	t.Parallel()
	candidate := candidateHeadFixture(t)
	payload, _, err := policy.DecodeBaseManifestEnvelope(candidate.ManifestEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	wantEnvelopeLength, err := SignedEnvelopeLength(len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(candidate.ManifestEnvelope)) != wantEnvelopeLength {
		t.Fatalf("candidate envelope length=%d, want %d", len(candidate.ManifestEnvelope), wantEnvelopeLength)
	}
	bootstrap, err := HeadGrowthReservation(candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap != candidate.LogicalBytes {
		t.Fatalf("bootstrap H=%d, head charge=%d", bootstrap, candidate.LogicalBytes)
	}
	trusted := candidate
	trusted.ManifestEnvelope = append([]byte(nil), candidate.ManifestEnvelope[:len(candidate.ManifestEnvelope)-9]...)
	fields, _ := HeadFields(trusted)
	trusted.LogicalBytes, _ = HeadLogicalCharge(fields)
	growth, err := HeadGrowthReservation(candidate, &trusted)
	if err != nil {
		t.Fatal(err)
	}
	if growth != 9 {
		t.Fatalf("successor growth H=%d, want 9", growth)
	}
	larger := candidate
	larger.ManifestEnvelope = append(append([]byte(nil), candidate.ManifestEnvelope...), make([]byte, 11)...)
	fields, _ = HeadFields(larger)
	larger.LogicalBytes, _ = HeadLogicalCharge(fields)
	if growth, err = HeadGrowthReservation(candidate, &larger); err != nil || growth != 0 {
		t.Fatalf("shrinking successor H=%d, %v", growth, err)
	}
}

func TestRowGrowthMaximumIsDerived(t *testing.T) {
	t.Parallel()
	trusted := candidateHeadFixture(t)
	growth, err := RowGrowthMaximum(&trusted, false)
	if err != nil {
		t.Fatal(err)
	}
	wantClaimed := uint64(len(trusted.ManifestEnvelope) + len(trusted.BaseDigest) + len(trusted.SignerKeyID) +
		len(trusted.SignerPublicKey) + len(trusted.EpochBE) + len(trusted.RevisionBE) + 8)
	wantSpelling := uint64((len(StateApprovedMaterializing) - len(StateReceivedUnaudited)) +
		len(ErrorFamilySemantic) + len(policywire.ErrorPolicyMaterializationFailed))
	if growth.ClaimedGroup != wantClaimed || growth.LeaseOwner != MaxIdentityBytes || growth.Spelling != wantSpelling {
		t.Fatalf("successor G = %+v; want claimed=%d owner=%d spelling=%d", growth, wantClaimed, MaxIdentityBytes, wantSpelling)
	}
	bootstrap, err := RowGrowthMaximum(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.ClaimedGroup != 0 || bootstrap.LeaseOwner != MaxIdentityBytes || bootstrap.Spelling != 51 {
		t.Fatalf("bootstrap G = %+v", bootstrap)
	}
	rejection, err := RowGrowthMaximum(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if rejection.ClaimedGroup != 0 || rejection.LeaseOwner != MaxIdentityBytes || rejection.Spelling != 5 {
		t.Fatalf("Matrix-2a G = %+v", rejection)
	}
	if total, err := rejection.Total(); err != nil || total != MaxIdentityBytes+5 {
		t.Fatalf("Matrix-2a G total = %d, %v", total, err)
	}
	accepted, err := AcceptedReservation([]byte{'r'}, []byte{'p'}, trusted, &trusted)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Growth != growth {
		t.Fatalf("AcceptedReservation G = %+v; want %+v", accepted.Growth, growth)
	}
	rejected, err := Matrix2AReservation([]byte{'r'}, []byte{'p'})
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Growth != rejection {
		t.Fatalf("Matrix2AReservation G = %+v; want %+v", rejected.Growth, rejection)
	}
	remaining, err := AdmissionRemaining(rejected, nil)
	total, totalErr := rejected.Total()
	if err != nil || totalErr != nil || remaining != total {
		t.Fatalf("Matrix-2a admission remaining/total = %d/%d, %v/%v", remaining, total, err, totalErr)
	}
}

func TestDerivedReservationTransitions(t *testing.T) {
	t.Parallel()
	components := ReservationComponents{Admission: 10, Votes: 100, Terminal: 100,
		TerminalPending: 10, TerminalResult: 30, TerminalPublication: 60, Head: 50,
		Growth: RowGrowthCommitments{ClaimedGroup: 40, LeaseOwner: 30, Spelling: 10}}
	received := RemainingInput{Components: components, State: StateReceivedUnaudited, ConsumedTerminal: 10}
	pending := received
	pending.State = StatePending
	audit, err := DeriveTransition(received, received, 0)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Before != audit.After || audit.Released != 0 {
		t.Fatalf("audit flip moved reservation: %+v", audit)
	}
	transition, err := DeriveTransition(received, pending, 0)
	if err != nil || transition.Released != components.Growth.Spelling {
		t.Fatalf("first state transition = %+v, %v", transition, err)
	}
	voted := pending
	voted.ConsumedVotes = 20
	if transition, err := DeriveTransition(pending, voted, 20); err != nil || transition.Released != 0 {
		t.Fatalf("vote transition = %+v, %v", transition, err)
	}
	materializing := voted
	materializing.State = StateApprovedMaterializing
	materializing.ClaimedGroupConsumed = true
	materializing.LeaseOwnerConsumed = true
	claimWrite := components.Growth.ClaimedGroup + components.Growth.LeaseOwner
	transition, err = DeriveTransition(voted, materializing, claimWrite)
	if err != nil {
		t.Fatal(err)
	}
	if transition.Released != 80 {
		t.Fatalf("leave-pending released %d, want vote remainder 80", transition.Released)
	}
	unexposed := materializing
	unexposed.State = StateApprovedUnexposed
	transition, err = DeriveTransition(materializing, unexposed, 20)
	if err != nil || transition.Released != 10 {
		t.Fatalf("result transition = %+v, %v", transition, err)
	}
	publicationError := unexposed
	publicationError.State = StateErrorReceived
	transition, err = DeriveTransition(unexposed, publicationError, 0)
	if err != nil || transition.Released != 50 {
		t.Fatalf("publication error transition = %+v, %v", transition, err)
	}
	published := publicationError
	published.State = StateError
	transition, err = DeriveTransition(publicationError, published, 20)
	if err != nil {
		t.Fatal(err)
	}
	if transition.After != 0 || transition.Released != 50 {
		t.Fatalf("terminal transition = %+v", transition)
	}

	rejection := ReservationComponents{Admission: 10, Terminal: 100, TerminalPublication: 100,
		Growth: RowGrowthCommitments{LeaseOwner: 30, Spelling: 10}, Matrix2A: true}
	admitted := RemainingInput{Components: rejection, State: StateRejectionUnaudited}
	leased := admitted
	leased.LeaseOwnerConsumed = true
	transition, err = DeriveTransition(admitted, leased, rejection.Growth.LeaseOwner)
	if err != nil || transition.Released != 0 {
		t.Fatalf("Matrix-2a first lease = %+v, %v", transition, err)
	}
	staged := leased
	staged.State = StateRejectionErrorReceived
	transition, err = DeriveTransition(leased, staged, rejection.Growth.Spelling)
	if err != nil || transition.Released != 0 {
		t.Fatalf("Matrix-2a first state transition = %+v, %v", transition, err)
	}
	terminal := staged
	terminal.State = StateError
	transition, err = DeriveTransition(staged, terminal, 20)
	if err != nil {
		t.Fatal(err)
	}
	if transition.After != 10 || transition.Released != 80 {
		t.Fatalf("Matrix-2a floor transition = %+v", transition)
	}
}

func TestStateReachabilityDerivedOracle(t *testing.T) {
	t.Parallel()
	for _, state := range AllStates {
		matrix2A := state == StateRejectionUnaudited || state == StateRejectionErrorReceived
		if state == StateError { // exercise both origins below
			matrix2A = false
		}
		reachable, err := StateReachability(state, matrix2A)
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		if state.Terminal() && (reachable.Votes || reachable.Terminal || reachable.Head || reachable.Admission || reachable.Growth) {
			t.Errorf("non-2a terminal %s retained components: %+v", state, reachable)
		}
		if state != StatePending && state != StateReceivedUnaudited && reachable.Votes {
			t.Errorf("%s retains V", state)
		}
		if !state.Terminal() && !reachable.Growth {
			t.Errorf("%s does not retain G", state)
		}
	}
	reachable, err := StateReachability(StateError, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable.Admission || reachable.Votes || reachable.Terminal || reachable.Head || reachable.Growth {
		t.Fatalf("Matrix-2a terminal reachability = %+v", reachable)
	}
}

func TestRowGrowthRemainingMilestones(t *testing.T) {
	t.Parallel()
	accepted := ReservationComponents{Growth: RowGrowthCommitments{ClaimedGroup: 40, LeaseOwner: 128, Spelling: 51}}
	for _, test := range []struct {
		name           string
		state          State
		claimed, owner bool
		want           uint64
	}{
		{name: "admission", state: StateReceivedUnaudited, want: 40 + 128 + 51},
		{name: "pending", state: StatePending, want: 40 + 128},
		{name: "materializing", state: StateApprovedMaterializing, claimed: true, owner: true},
		{name: "no-op retains unconsumed", state: StateNoOpUnexposed, want: 40 + 128},
		{name: "denial retains unconsumed", state: StateDenialReceived, want: 40 + 128},
		{name: "pre-claim error retains unconsumed", state: StateErrorReceived, want: 40 + 128},
		{name: "post-claim error", state: StateErrorReceived, claimed: true, owner: true},
		{name: "publication releases remainder", state: StateError, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := DeriveRemaining(RemainingInput{Components: accepted, State: test.state,
				ClaimedGroupConsumed: test.claimed, LeaseOwnerConsumed: test.owner})
			if err != nil || got != test.want {
				t.Fatalf("remaining G = %d, %v; want %d", got, err, test.want)
			}
		})
	}

	rejection := ReservationComponents{Growth: RowGrowthCommitments{LeaseOwner: 128, Spelling: 5}, Matrix2A: true}
	for _, test := range []struct {
		state State
		owner bool
		want  uint64
	}{
		{state: StateRejectionUnaudited, want: 133},
		{state: StateRejectionErrorReceived, want: 128},
		{state: StateRejectionErrorReceived, owner: true, want: 0},
		{state: StateError, owner: true, want: 0},
	} {
		got, err := DeriveRemaining(RemainingInput{Components: rejection, State: test.state, LeaseOwnerConsumed: test.owner})
		if err != nil || got != test.want {
			t.Fatalf("Matrix-2a %s owner=%t remaining G = %d, %v; want %d", test.state, test.owner, got, err, test.want)
		}
	}
}

func TestEveryLegalStateTransitionHasNonNegativeMonotoneRelease(t *testing.T) {
	t.Parallel()
	components := ReservationComponents{Admission: 10, Votes: 100, Terminal: 100,
		TerminalPending: 10, TerminalResult: 30, TerminalPublication: 60, Head: 50,
		Growth: RowGrowthCommitments{Spelling: 10}}
	image := func(state State) RemainingInput {
		return RemainingInput{Components: components, State: state, ConsumedVotes: 20, ConsumedTerminal: 5}
	}
	type edge struct {
		from, to State
		written  uint64
	}
	edges := []edge{
		{StateReceivedUnaudited, StatePending, 0},
		{StateReceivedUnaudited, StateNoOpUnexposed, 20},
		{StateReceivedUnaudited, StateErrorReceived, 0},
		{StatePending, StatePending, 0},
		{StatePending, StateApprovedMaterializing, 0},
		{StatePending, StateDenialReceived, 0},
		{StatePending, StateErrorReceived, 0},
		{StateApprovedMaterializing, StateApprovedUnexposed, 20},
		{StateApprovedMaterializing, StateErrorReceived, 0},
		{StateApprovedUnexposed, StateApproved, 20},
		{StateApprovedUnexposed, StateErrorReceived, 0},
		{StateNoOpUnexposed, StateApproved, 20},
		{StateNoOpUnexposed, StateErrorReceived, 0},
		{StateDenialReceived, StateDenied, 20},
		{StateErrorReceived, StateError, 20},
	}
	for _, test := range edges {
		transition, err := DeriveTransition(image(test.from), image(test.to), test.written)
		if err != nil {
			t.Fatalf("%s -> %s: %v", test.from, test.to, err)
		}
		if transition.After > transition.Before || transition.Released > transition.Before {
			t.Fatalf("%s -> %s is not monotone: %+v", test.from, test.to, transition)
		}
	}

	rejection := ReservationComponents{Admission: 10, Terminal: 60, TerminalPublication: 60,
		Growth: RowGrowthCommitments{Spelling: 10}, Matrix2A: true}
	rejectionImage := func(state State) RemainingInput {
		return RemainingInput{Components: rejection, State: state}
	}
	for _, test := range []edge{
		{StateRejectionUnaudited, StateRejectionErrorReceived, 0},
		{StateRejectionErrorReceived, StateError, 20},
	} {
		transition, err := DeriveTransition(rejectionImage(test.from), rejectionImage(test.to), test.written)
		if err != nil {
			t.Fatalf("Matrix-2a %s -> %s: %v", test.from, test.to, err)
		}
		if transition.After < rejection.Floor() || transition.After > transition.Before {
			t.Fatalf("Matrix-2a %s -> %s violates floor/monotonicity: %+v", test.from, test.to, transition)
		}
	}
}
