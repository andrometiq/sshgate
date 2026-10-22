package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func proofCasesPhase4() []harness.Case {
	var cases []harness.Case
	add := gateCaseAdder(&cases, "Phase4")
	for _, name := range []string{"U-EnvelopeParse", "U-EnvelopeFlags", "U-EnvelopeExpectNet", "U-DaemonReadNetRefused"} {
		add(name, "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	}
	add("G-ENVELOPE-GRAMMAR", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:agent-bytes"}, nil)
	add("G-ENVELOPE-NO-NET-UNPINNED", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:connected"}, nil)
	add("G-ENVELOPE-NO-NET-DENY", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:connected"}, nil)
	add("G-ENVELOPE-PIN-SNAPSHOT", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:ran-without-network"}, nil)
	add("G-NET-LANE2-AVAILABLE", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:lane2-ran"}, nil)
	add("G-ENVELOPE-ABSENT", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:ran-unconfined"}, nil)
	add("G-ENVELOPE-NET-ALLOW", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-ABSENT-TWIN", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-NEW-GATE", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-OLD-GATE", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-UNMET", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:facility", "jailed:probe", "observe:effects"}, []string{"ABORT:selfcheck", "EFFECT:fuse-ioctl"}, []string{"fuse-unavailable"})
	return cases
}
