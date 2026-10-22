package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

// proofCasesPhase3 are the daemon-read cases: the gate's, of which the gate's
// proof adapter holds a literal copy (checked equal by
// TestGateProofCasesMatchManifest there), and this package's filter tables.
func proofCasesPhase3() []harness.Case {
	var cases []harness.Case
	add := gateCaseAdder(&cases, "Phase3")
	for _, name := range []string{"U-Lane2Grammar", "U-Lane2RedirectList", "U-Lane2ELFSearchTags", "U-Lane2Interp"} {
		add(name, "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	}
	add("G-L2-GRAMMAR", "Effect", "Execute", nil, []string{"control:argv", "jailed:lane2", "observe:output"}, []string{"EFFECT:grammar-flag"}, nil)
	add("G-L2-REDIRECT", "Effect", "Execute", nil, []string{"control:argv", "jailed:lane2", "observe:output"}, []string{"EFFECT:redirect-flag"}, nil)
	add("G-L2-ADMIT-WRITABLE-DIR", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:untrusted-ran"}, nil)
	for _, name := range []string{"G-L2-ADMIT-RUNPATH-ORIGIN", "G-L2-ADMIT-RUNPATH-UNTRUSTED"} {
		add(name, "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:lib-ran"}, nil)
	}
	add("G-L2-ADMIT-ENDPOINT", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:endpoint-accepted"}, []string{"root-only"})
	cases[len(cases)-1].Root = true
	add("G-L2-INTERP-UNTRUSTED", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:interp-ran"}, nil)
	// P3.2: daemon reads run in the jail. The residual lanes follow this host's
	// Landlock ABI, as the registry's expected markers do.
	hostABI := ReadHostFacts().LandlockABI
	add("U-Lane2SpecNet", "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	add("G-LANE2-PLUGIN-NOEXEC", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:plugin-ran"}, nil)
	add("G-L2-MEMFD-NOEXEC", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:memfd-ran"}, nil)
	add("G-L2-SOCK-PIN", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:unpinned-connected"}, nil)
	cases[len(cases)-1].ResidualABIs = harness.ResidualBelowABI("R-L2-SOCKET-BELOW-ABI9", hostABI, 9)
	add("G-L2-SOCK-SWAP-AFTER-OPEN", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:swapped-connected"}, nil)
	cases[len(cases)-1].ResidualABIs = harness.ResidualBelowABI("R-L2-SOCKET-BELOW-ABI9", hostABI, 9)
	add("G-L2-NET-OFF", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"ABORT:spec", "EFFECT:tcp-connected"}, nil)
	add("G-L2-ENV", "Effect", "Execute", nil, []string{"control:env", "jailed:lane2", "observe:report"}, []string{"EFFECT:env-leaked"}, nil)
	for _, name := range []string{"G-L2-IDENTITY-BINARY", "G-L2-IDENTITY-INTERP"} {
		add(name, "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:replaced-ran"}, nil)
	}
	add("G-L2-IDENTITY-SOCKET", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:replaced-accepted"}, nil)
	add("C-L2-LOADER", "Execution", "Execute", nil, []string{"jailed:loader"}, nil, nil)
	cases[len(cases)-1].ResidualABIs = map[string]string{"native": "R-L2-LOADER-ROUTE", "abi1": "R-L2-LOADER-ROUTE"}
	add("C-L2-REEXEC", "Execution", "Execute", nil, []string{"jailed:reexec"}, nil, nil)
	add("C-L2-MEMFD-SECRET", "Execution", "Execute", nil, []string{"jailed:memfd-secret"}, nil, nil)
	add("C-L2-ABSTRACT", "Execution", "Execute", nil, []string{"jailed:abstract"}, nil, nil)
	cases[len(cases)-1].ResidualABIs = harness.ResidualBelowABI("R-L2-ABSTRACT-BELOW-ABI6", hostABI, 6)
	add("C-L2-UNIX-DGRAM", "Execution", "Execute", nil, []string{"jailed:dgram"}, nil, nil)
	for _, name := range []string{"U-Lane2LandlockRules", "U-Lane2FilterRows", "U-Lane2SocketTable", "U-Lane2IdentityCompare", "U-Lane2EnvConstant"} {
		cases = append(cases, harness.Case{Name: name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Unit", Obligations: []string{"control:decision"}, Markers: []string{"EFFECT:decision"}})
	}
	return cases
}
