package policystore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"testing"
)

func configFixture() ConfigDigestInput {
	input := DefaultConfigDigestInput()
	input.RequesterOperatorID = "operator-a"
	input.RequiredApprovals = 2
	input.DenyVeto = true
	input.AllowSelfApprove = false
	input.PolicyVoterRole = "operator"
	input.VoterEligibilityVersion = "sshgate-policy-voters-v1"
	input.VoteAuthMethodsJSON = []byte(`["session"]`)
	input.ArchiveID = "parch_0123456789abcdef0123456789abcdef"
	input.ReviewRendererVersion = "sshgate-policy-review-v2"
	input.ReviewRulesDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return input
}

func independentConfigDigest(input ConfigDigestInput) string {
	b := func(value bool) string {
		if value {
			return "1"
		}
		return "0"
	}
	u := func(value uint64) string { return strconv.FormatUint(value, 10) }
	fields := []string{input.RequesterOperatorID, u(input.RequiredApprovals), b(input.DenyVeto), b(input.AllowSelfApprove), input.PolicyVoterRole,
		input.VoterEligibilityVersion, b(input.VoteStepUpRequired), string(input.VoteAuthMethodsJSON), u(input.MaxHeads), u(input.MaxRequests),
		u(input.MaxLogicalBytes), u(input.MaxActiveGlobal), u(input.MaxActivePerPrincipal), u(input.MaxVotesPerRequest), "16", "600", "64",
		u(input.MaxRejectionReservedBytesPerPrincipal), "120", "30", DurableAuditVersion, AccountingVersion, ArchiveRecordVersion,
		AuditEventVersion, input.ArchiveID, input.ReviewRendererVersion, input.ReviewRulesDigest}
	h := sha256.New()
	h.Write([]byte(ConfigDigestDomain))
	h.Write([]byte{0})
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(len(fields)))
	h.Write(raw[:])
	for _, field := range fields {
		binary.BigEndian.PutUint32(raw[:], uint32(len(field)))
		h.Write(raw[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestConfigDigestFrozenFraming(t *testing.T) {
	t.Parallel()
	input := configFixture()
	got, err := ConfigDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	if want := independentConfigDigest(input); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
	const golden = "dc6d98b148b60577a76d6cceaf53cb6b4a058478a5e0379170caa8a384c997b4"
	if got != golden {
		t.Fatalf("config digest golden changed: got %s want %s", got, golden)
	}
}

func TestConfigDigestPerturbations(t *testing.T) {
	t.Parallel()
	base := configFixture()
	original, err := ConfigDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*ConfigDigestInput){
		func(v *ConfigDigestInput) { v.RequesterOperatorID = "operator-b" },
		func(v *ConfigDigestInput) { v.RequiredApprovals = 3 },
		func(v *ConfigDigestInput) { v.DenyVeto = false },
		func(v *ConfigDigestInput) { v.AllowSelfApprove = true },
		func(v *ConfigDigestInput) { v.PolicyVoterRole = "operator-v2" },
		func(v *ConfigDigestInput) { v.VoterEligibilityVersion = "sshgate-policy-voters-v2" },
		func(v *ConfigDigestInput) { v.VoteStepUpRequired = true },
		func(v *ConfigDigestInput) { v.VoteAuthMethodsJSON = []byte(`["totp"]`) },
		func(v *ConfigDigestInput) { v.MaxHeads-- },
		func(v *ConfigDigestInput) { v.MaxRequests-- },
		func(v *ConfigDigestInput) { v.MaxLogicalBytes-- },
		func(v *ConfigDigestInput) { v.MaxActiveGlobal-- },
		func(v *ConfigDigestInput) { v.MaxActivePerPrincipal-- },
		func(v *ConfigDigestInput) { v.MaxVotesPerRequest-- },
		func(v *ConfigDigestInput) { v.MaxRejectionReservedBytesPerPrincipal-- },
		func(v *ConfigDigestInput) { v.ArchiveID = "parch_1123456789abcdef0123456789abcdef" },
		func(v *ConfigDigestInput) { v.ReviewRendererVersion += "x" },
		func(v *ConfigDigestInput) {
			v.ReviewRulesDigest = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		},
	}
	for index, mutate := range mutations {
		candidate := base
		candidate.VoteAuthMethodsJSON = append([]byte(nil), base.VoteAuthMethodsJSON...)
		mutate(&candidate)
		got, err := ConfigDigest(candidate)
		if err != nil {
			t.Fatalf("mutation %d: %v", index, err)
		}
		if got == original {
			t.Errorf("mutation %d did not change digest", index)
		}
	}
	for _, invalid := range []ConfigDigestInput{func() ConfigDigestInput { v := base; v.MaxHeads--; return v }(), func() ConfigDigestInput { v := base; v.MaxRejectionReservedBytesPerPrincipal = 0; return v }()} {
		if err := invalid.Validate(); err == nil {
			t.Error("invalid persisted configuration validated")
		}
	}
}
