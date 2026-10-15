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
			leg.ResidualABIs = c.ResidualABIs
		}
	}
	return leg
}

// phase3Registry is the daemon-read admission and grammar (P3.1) and its jail
// (P3.2).
func phase3Registry() []prot {
	return append([]prot{
		{ID: "P-L2-ADMIT", Site: "lane2Plan admission trust verdict", Class: "single", DirectLeg: "U-Lane2ELFSearchTags",
			EffectLegs: []string{"G-L2-ADMIT-WRITABLE-DIR", "G-L2-ADMIT-RUNPATH-ORIGIN", "G-L2-ADMIT-RUNPATH-UNTRUSTED", "G-L2-ADMIT-ENDPOINT"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-ADMIT"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2ELFSearchTags", "MUTATION-EFFECT decision"),
				phase3Leg("G-L2-ADMIT-WRITABLE-DIR", "MUTATION-EFFECT untrusted-ran"),
				phase3Leg("G-L2-ADMIT-RUNPATH-ORIGIN", "MUTATION-EFFECT lib-ran"),
				phase3Leg("G-L2-ADMIT-RUNPATH-UNTRUSTED", "MUTATION-EFFECT lib-ran"),
				phase3Leg("G-L2-ADMIT-ENDPOINT", "MUTATION-EFFECT endpoint-accepted"),
			}}}},
		{ID: "P-L2-INTERP", Site: "lane2Plan interpreter trust verdict", Class: "single", DirectLeg: "U-Lane2Interp",
			EffectLegs: []string{"G-L2-INTERP-UNTRUSTED"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-INTERP"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2Interp", "MUTATION-EFFECT decision"),
				phase3Leg("G-L2-INTERP-UNTRUSTED", "MUTATION-EFFECT interp-ran"),
			}}}},
	}, append(phase3GrammarRegistry(), phase3JailRegistry()...)...)
}

// phase3JailRegistry is the daemon-read jail (P3.2). Where a wall exists only
// from a Landlock ABI, a lane below it expects no marker: the leg reports its
// documented residual there instead.
func phase3JailRegistry() []prot {
	unit := func(name string) harness.Leg { return p15Unit("TestFilterTables", name) }
	decision := func(leg harness.Leg) harness.Leg {
		leg.Markers = []string{"MUTATION-EFFECT decision"}
		return leg
	}
	hostABI := ReadHostFacts().LandlockABI
	belowABI := func(leg harness.Leg, minimum int) harness.Leg {
		leg.ABIMarkers = map[string][]string{"abi1": {}}
		if hostABI < minimum {
			leg.ABIMarkers["native"] = []string{}
		}
		return leg
	}
	memfd := phase3Leg("G-L2-MEMFD-NOEXEC", "MUTATION-EFFECT memfd-ran")
	memfd.ABIMarkers = map[string][]string{}
	for _, abi := range []string{"native", "abi1"} {
		if memfdExecBlocked(abi) {
			memfd.ABIMarkers[abi] = []string{}
		}
	}
	memfdNarrow := harness.MutationSet{IDs: []string{"P-L2-MEMFD", "P-L2-EXEC-NARROW"}, Legs: []harness.Leg{phase3Leg("G-L2-MEMFD-NOEXEC", "MUTATION-EFFECT memfd-ran")}}
	unixConnect := p15Leg("L-UNIX-CONNECT", "MUTATION-EFFECT connected")
	unixConnect.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT connected"}}
	if hostABI >= 9 {
		unixConnect.Markers = nil
	}
	scopeAndResolve := harness.MutationSet{IDs: []string{"P-L2-SOCK-SCOPE", "P-LL-RESOLVE-UNIX"}, Legs: []harness.Leg{p15Leg("L-UNIX-CONNECT", "MUTATION-EFFECT connected")}}
	netBoth := harness.MutationSet{IDs: []string{"P-L2-NET-OFF", "P-L2-SPEC-NET"}, Legs: []harness.Leg{phase3Leg("G-L2-NET-OFF", "MUTATION-EFFECT tcp-connected")}}
	return []prot{
		{ID: "P-L2-EXEC-NARROW", Site: "landlockPlan: a daemon read's / has no EXECUTE", Class: "single", DirectLeg: "U-Lane2LandlockRules",
			EffectLegs: []string{"G-LANE2-PLUGIN-NOEXEC"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-EXEC-NARROW"}, Legs: []harness.Leg{
				decision(unit("U-Lane2LandlockRules")), phase3Leg("G-LANE2-PLUGIN-NOEXEC", "MUTATION-EFFECT plugin-ran")}}}},
		{ID: "P-L2-MEMFD", Site: "buildFilter: a daemon read's memfd_create and memfd_secret are denied", Class: "multi", Partners: []string{"P-L2-EXEC-NARROW"}, DirectLeg: "U-Lane2FilterRows",
			EffectLegs: []string{"G-L2-MEMFD-NOEXEC"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-MEMFD"}, Legs: []harness.Leg{decision(unit("U-Lane2FilterRows")), memfd}}, memfdNarrow}},
		{ID: "P-L2-SOCK-SCOPE", Site: "buildSocketFilter: Unix stream sockets only in a daemon read", Class: "multi", Partners: []string{"P-LL-RESOLVE-UNIX"}, DirectLeg: "U-Lane2SocketTable",
			EffectLegs: []string{"L-UNIX-CONNECT"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-SOCK-SCOPE"}, Legs: []harness.Leg{decision(unit("U-Lane2SocketTable")), unixConnect}}, scopeAndResolve}},
		{ID: "P-L2-SOCK-PIN", Site: "landlockPlan: RESOLVE_UNIX only on a daemon read's sockets", Class: "single", DirectLeg: "U-Lane2LandlockRules",
			EffectLegs: []string{"G-L2-SOCK-PIN", "G-L2-SOCK-SWAP-AFTER-OPEN"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-SOCK-PIN"}, Legs: []harness.Leg{
				decision(unit("U-Lane2LandlockRules")),
				belowABI(phase3Leg("G-L2-SOCK-PIN", "MUTATION-EFFECT unpinned-connected"), 9),
				belowABI(phase3Leg("G-L2-SOCK-SWAP-AFTER-OPEN", "MUTATION-EFFECT swapped-connected"), 9)}}}},
		{ID: "P-L2-NET-OFF", Site: "lane2Spec: a daemon read never has network", Class: "multi", Partners: []string{"P-L2-SPEC-NET"}, DirectLeg: "U-Lane2SpecNet",
			EffectLegs: []string{"G-L2-NET-OFF"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-NET-OFF"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2SpecNet", "MUTATION-EFFECT decision"), phase3Leg("G-L2-NET-OFF", "MUTATION-ABORT spec")}}, netBoth}},
		{ID: "P-L2-SPEC-NET", Site: "validate: a daemon-read Spec never has network", Class: "multi", Partners: []string{"P-L2-NET-OFF"}, DirectLeg: "U-Lane2SpecNet",
			EffectLegs: []string{"G-L2-NET-OFF"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-SPEC-NET"}, Legs: []harness.Leg{
				phase3Leg("U-Lane2SpecNet", "MUTATION-EFFECT decision"), phase3Leg("G-L2-NET-OFF")}}, netBoth}},
		{ID: "P-L2-ENV", Site: "lane2ExecEnv: a daemon read runs with Lane2Env", Class: "single", DirectLeg: "U-Lane2EnvConstant",
			EffectLegs: []string{"G-L2-ENV"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-ENV"}, Legs: []harness.Leg{
				decision(unit("U-Lane2EnvConstant")), phase3Leg("G-L2-ENV", "MUTATION-EFFECT env-leaked")}}}},
		{ID: "P-L2-IDENTITY", Site: "lane2Identity: the worker re-checks every admitted inode", Class: "single", DirectLeg: "U-Lane2IdentityCompare",
			EffectLegs: []string{"G-L2-IDENTITY-BINARY", "G-L2-IDENTITY-INTERP", "G-L2-IDENTITY-SOCKET"},
			MutationSets: []harness.MutationSet{{IDs: []string{"P-L2-IDENTITY"}, Legs: []harness.Leg{
				decision(unit("U-Lane2IdentityCompare")),
				phase3Leg("G-L2-IDENTITY-BINARY", "MUTATION-EFFECT replaced-ran"),
				phase3Leg("G-L2-IDENTITY-INTERP", "MUTATION-EFFECT replaced-ran"),
				phase3Leg("G-L2-IDENTITY-SOCKET", "MUTATION-EFFECT replaced-accepted")}}}},
	}
}

// phase3GrammarRegistry is the grammar and its redirect refusal list, two
// walls: removing the list alone leaves --user refused by the grammar, and only
// removing both lets it reach the client.
func phase3GrammarRegistry() []prot {
	both := harness.MutationSet{IDs: []string{"P-L2-GRAMMAR", "P-L2-REDIRECT"}, Legs: []harness.Leg{phase3Leg("G-L2-REDIRECT", "MUTATION-EFFECT redirect-flag")}}
	return []prot{
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
