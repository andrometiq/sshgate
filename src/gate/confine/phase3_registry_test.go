package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

// phase3Leg is a gate daemon-read leg: a decision table (U-) or a gate run
// (G-). Its omissions come from its case.
func phase3Leg(name string, markers ...string) harness.Leg {
	root := "TestJailMatrixPhase3/"
	if name[0] == 'U' {
		root = "TestPhase3Tables/"
	}
	leg := harness.Leg{Name: name, Package: phase2Package, Names: map[string]string{"native": root + "native/" + name, "abi1": root + "abi1/" + name}, Markers: markers}
	for _, c := range proofCasesPhase3() {
		if c.Name == name {
			leg.Omissions = append([]string(nil), c.Omissions...)
			leg.Root, leg.NonRoot = c.Root, c.NonRoot
		}
	}
	return leg
}

// phase3Registry is the daemon-read grammar (P3.1). The grammar and the
// redirect refusal list are two walls: removing the list alone leaves --user
// refused by the grammar, and only removing both lets it reach the client.
func phase3Registry() []prot {
	both := harness.MutationSet{IDs: []string{"P-L2-GRAMMAR", "P-L2-REDIRECT"}, Legs: []harness.Leg{phase3Leg("G-L2-REDIRECT", "MUTATION-EFFECT redirect-flag")}}
	return []prot{
		{ID: "P-L2-ADMIT", Site: "lane2Plan admission trust verdict", Class: "single", DirectLeg: "U-Lane2ELFSearchTags",
			EffectLegs: []string{"G-L2-ADMIT-WRITABLE-DIR", "G-L2-ADMIT-RUNPATH-ORIGIN", "G-L2-ADMIT-RUNPATH-UNTRUSTED", "G-L2-ADMIT-ENDPOINT"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-ADMIT"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2ELFSearchTags", "MUTATION-EFFECT decision"),
				phase3Leg("G-L2-ADMIT-WRITABLE-DIR", "MUTATION-EFFECT untrusted-ran"),
				phase3Leg("G-L2-ADMIT-RUNPATH-ORIGIN", "MUTATION-EFFECT lib-ran"),
				phase3Leg("G-L2-ADMIT-RUNPATH-UNTRUSTED", "MUTATION-EFFECT lib-ran"),
				phase3Leg("G-L2-ADMIT-ENDPOINT", "MUTATION-EFFECT endpoint-accepted"),
			}}}},
		{ID: "P-L2-GRAMMAR", Site: "lane2Parse refuses a non-grammar token", Class: "multi", Partners: []string{"P-L2-REDIRECT"}, DirectLeg: "U-Lane2Grammar",
			EffectLegs: []string{"G-L2-GRAMMAR"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-GRAMMAR"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2Grammar", "MUTATION-EFFECT decision"), phase3Leg("G-L2-GRAMMAR", "MUTATION-EFFECT grammar-flag")}}, both}},
		{ID: "P-L2-REDIRECT", Site: "lane2Redirect refusal list", Class: "multi", Partners: []string{"P-L2-GRAMMAR"}, DirectLeg: "U-Lane2RedirectList",
			EffectLegs: []string{"G-L2-REDIRECT"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-REDIRECT"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2RedirectList", "MUTATION-EFFECT decision"), phase3Leg("G-L2-REDIRECT")}}, both}},
	}
}
