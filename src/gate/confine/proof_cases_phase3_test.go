package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

// proofCasesPhase3 are the gate's daemon-read cases. The gate's proof adapter
// holds a literal copy, checked equal by TestGateProofCasesMatchManifest there.
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
	return cases
}
