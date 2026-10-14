package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

// proofCasesPhase2 are the gate's read-routing cases. The gate's proof adapter
// (src/gate/cmd/sshgate-gate) holds a literal copy, checked equal by
// TestGateProofCasesMatchManifest there.
func proofCasesPhase2() []harness.Case {
	var cases []harness.Case
	add := func(name, kind, mode string, modes, obligations, markers, omissions []string) {
		root := "TestJailMatrixPhase2/"
		if kind == "Unit" {
			root = "TestPhase2Tables/"
		}
		cases = append(cases, harness.Case{
			Name: name, Package: phase2Package, Kind: kind, Mode: mode, Modes: modes, ABIs: []string{"native", "abi1"},
			Names:       map[string]string{"native": root + "native/" + name, "abi1": root + "abi1/" + name},
			Obligations: obligations, Markers: markers, Omissions: omissions,
		})
	}
	for _, name := range []string{"U-ExecReadConfineRequired", "U-SpecStrictSources"} {
		add(name, "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	}
	add("G-CONFINE-REQUIRED-ABSENT", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:edit", "jailed:edit", "observe:target"}, []string{"EFFECT:ran-unconfined"}, nil)
	add("G-CONFINE-REQUIRED-LANE2", "Effect", "Execute", nil, []string{"control:lane2", "jailed:lane2", "observe:lane2"}, []string{"EFFECT:lane2-ran"}, nil)
	for _, name := range []string{"G-STRICT-UNMET-FUSE", "G-NET-STRICT-UNMET-FUSE"} {
		add(name, "Effect", "Execute", []string{"SetupAbort"}, []string{"control:facility", "jailed:probe", "observe:effects"}, []string{"ABORT:selfcheck", "EFFECT:fuse-ioctl"}, []string{"fuse-unavailable"})
	}
	add("G-UNPINNED-UNMET-FUSE", "Effect", "Execute", nil, []string{"control:facility", "jailed:probe", "observe:effects"}, []string{"EFFECT:fuse-ioctl"}, []string{"fuse-unavailable"})
	add("G-NSDROP-MNT", "Abort", "SetupAbort", []string{"Execute"}, []string{"control:intact", "jailed:attempt", "observe:mounts"}, []string{"ABORT:nsverify"}, nil)
	add("G-FAULT", "Abort", "SetupAbort", nil, []string{"control:intact", "jailed:attempt"}, nil, nil)
	add("G-FAULT-ABSENT", "Execution", "Execute", nil, []string{"jailed:fallback", "observe:target"}, nil, nil)
	add("G-INET-DENY", "Effect", "Execute", nil, []string{"control:connect", "jailed:connect", "observe:listener"}, []string{"EFFECT:connected"}, []string{"ipv6-unavailable"})
	add("G-INET-ALLOW", "Execution", "Execute", nil, []string{"jailed:connect", "observe:listener"}, nil, []string{"ipv6-unavailable"})
	return cases
}
