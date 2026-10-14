package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

// proofCasesPhase2 are the gate's read-routing cases. The gate's proof adapter
// (src/gate/cmd/sshgate-gate) holds a literal copy, checked equal by
// TestGateProofCasesMatchManifest there.
func proofCasesPhase2() []harness.Case {
	var cases []harness.Case
	for _, name := range []string{"U-ExecReadConfineRequired", "U-SpecStrictSources"} {
		cases = append(cases, harness.Case{
			Name: name, Package: phase2Package, Kind: "Unit", ABIs: []string{"native", "abi1"},
			Names:       map[string]string{"native": "TestPhase2Tables/native/" + name, "abi1": "TestPhase2Tables/abi1/" + name},
			Obligations: []string{"control:decision"}, Markers: []string{"EFFECT:decision"},
		})
	}
	return cases
}
