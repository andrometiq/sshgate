package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

const phase2Package = "./src/gate/cmd/sshgate-gate"

// phase2Unit is a gate decision leg: a table checked against literals, which
// reports the decision effect when a hook flips it.
func phase2Unit(name string) harness.Leg {
	return harness.Leg{Name: name, Package: phase2Package, Names: map[string]string{"native": "TestPhase2Tables/native/" + name, "abi1": "TestPhase2Tables/abi1/" + name}, Markers: []string{"MUTATION-EFFECT decision"}}
}

// phase2Registry is the gate's read routing: P2.1.
func phase2Registry() []prot {
	one := func(id, leg string) []harness.MutationSet {
		return []harness.MutationSet{{IDs: []string{id}, Legs: []harness.Leg{phase2Unit(leg)}}}
	}
	return []prot{
		{ID: "P-G-CONFINE-REQUIRED", Site: "routeBeforeAttempt and routeAfterSetupFailure requires term", Class: "single", DirectLeg: "U-ExecReadConfineRequired", MutationSets: one("P-G-CONFINE-REQUIRED", "U-ExecReadConfineRequired")},
		{ID: "P-G-STRICT", Site: "readSpec Strict from a valid pin", Class: "multi", Partners: []string{"P-COVERS"}, DirectLeg: "U-SpecStrictSources", MutationSets: one("P-G-STRICT", "U-SpecStrictSources")},
		{ID: "P-G-NET-STRICT", Site: "readSpec Strict from required confinement", Class: "multi", Partners: []string{"P-COVERS"}, DirectLeg: "U-SpecStrictSources", MutationSets: one("P-G-NET-STRICT", "U-SpecStrictSources")},
	}
}
