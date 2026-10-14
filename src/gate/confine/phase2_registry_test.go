package confine

import (
	"slices"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

const phase2Package = "./src/gate/cmd/sshgate-gate"

// phase2Leg is a gate leg: a decision table (U-) or a gate run (G-). Its
// omissions come from its case.
func phase2Leg(name string, markers ...string) harness.Leg {
	root := "TestJailMatrixPhase2/"
	if name[0] == 'U' {
		root = "TestPhase2Tables/"
	}
	leg := harness.Leg{Name: name, Package: phase2Package, Names: map[string]string{"native": root + "native/" + name, "abi1": root + "abi1/" + name}, Markers: markers}
	for _, c := range proofCasesPhase2() {
		if c.Name == name {
			leg.Omissions = append([]string(nil), c.Omissions...)
		}
	}
	return leg
}

// phase2Registry is the gate's read routing: P2.1. Removing one Strict source
// together with the covers leaves the other source's run aborting, and the
// unpinned run reaching the uncovered FUSE mount.
func phase2Registry() []prot {
	fuse := func(strict string) harness.MutationSet {
		twin := map[string]string{"G-STRICT-UNMET-FUSE": "G-NET-STRICT-UNMET-FUSE", "G-NET-STRICT-UNMET-FUSE": "G-STRICT-UNMET-FUSE"}[strict]
		return harness.MutationSet{Legs: []harness.Leg{
			phase2Leg(strict, "MUTATION-EFFECT fuse-ioctl"),
			phase2Leg(twin, "MUTATION-ABORT selfcheck"),
			phase2Leg("G-UNPINNED-UNMET-FUSE", "MUTATION-EFFECT fuse-ioctl"),
		}}
	}
	strictSet, netStrictSet := fuse("G-STRICT-UNMET-FUSE"), fuse("G-NET-STRICT-UNMET-FUSE")
	strictSet.IDs, netStrictSet.IDs = []string{"P-G-STRICT", "P-COVERS"}, []string{"P-G-NET-STRICT", "P-COVERS"}
	one := func(id string, legs ...harness.Leg) harness.MutationSet {
		return harness.MutationSet{IDs: []string{id}, Legs: legs}
	}
	return []prot{
		{ID: "P-G-CONFINE-REQUIRED", Site: "routeBeforeAttempt and routeAfterSetupFailure requires term", Class: "single", DirectLeg: "U-ExecReadConfineRequired",
			EffectLegs: []string{"G-CONFINE-REQUIRED-ABSENT", "G-CONFINE-REQUIRED-LANE2"},
			MutationSets: []harness.MutationSet{one("P-G-CONFINE-REQUIRED", phase2Leg("U-ExecReadConfineRequired", "MUTATION-EFFECT decision"),
				phase2Leg("G-CONFINE-REQUIRED-ABSENT", "MUTATION-EFFECT ran-unconfined"), phase2Leg("G-CONFINE-REQUIRED-LANE2", "MUTATION-EFFECT lane2-ran"))}},
		{ID: "P-G-STRICT", Site: "readSpec Strict from a valid pin", Class: "multi", Partners: []string{"P-COVERS"}, DirectLeg: "U-SpecStrictSources",
			EffectLegs:   []string{"G-STRICT-UNMET-FUSE"},
			MutationSets: []harness.MutationSet{one("P-G-STRICT", phase2Leg("U-SpecStrictSources", "MUTATION-EFFECT decision")), strictSet}},
		{ID: "P-G-NET-STRICT", Site: "readSpec Strict from required confinement", Class: "multi", Partners: []string{"P-COVERS"}, DirectLeg: "U-SpecStrictSources",
			EffectLegs:   []string{"G-NET-STRICT-UNMET-FUSE"},
			MutationSets: []harness.MutationSet{one("P-G-NET-STRICT", phase2Leg("U-SpecStrictSources", "MUTATION-EFFECT decision")), netStrictSet}},
	}
}

// phase2Extend adds the gate legs to the walls they also prove: removing the
// covers aborts both strict gate runs and lets the unpinned one reach the
// FUSE mount; a dropped mount namespace aborts the gate's attempt at
// nsverify; removing the seccomp network wall lets a jailed gate read connect.
func phase2Extend(registry []prot) {
	for i := range registry {
		p := &registry[i]
		var legs []harness.Leg
		switch p.ID {
		case "P-COVERS":
			legs = []harness.Leg{phase2Leg("G-STRICT-UNMET-FUSE", "MUTATION-ABORT selfcheck"), phase2Leg("G-NET-STRICT-UNMET-FUSE", "MUTATION-ABORT selfcheck"), phase2Leg("G-UNPINNED-UNMET-FUSE", "MUTATION-EFFECT fuse-ioctl")}
		case "P-CLONE-MNT":
			legs = []harness.Leg{phase2Leg("G-NSDROP-MNT", "MUTATION-ABORT nsverify")}
		case "P-SC-NET":
			legs = []harness.Leg{phase2Leg("G-INET-DENY", "MUTATION-EFFECT connected")}
			p.EffectLegs = append(p.EffectLegs, "G-INET-DENY")
		default:
			continue
		}
		index := slices.IndexFunc(p.MutationSets, func(s harness.MutationSet) bool { return len(s.IDs) == 1 && s.IDs[0] == p.ID })
		p.MutationSets[index].Legs = append(p.MutationSets[index].Legs, legs...)
	}
}
