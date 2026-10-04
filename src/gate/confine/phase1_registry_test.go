package confine

import (
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"os"
	"strings"
)

func phase1Leg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixPhase1/native/" + name, "abi1": "TestJailMatrixPhase1/abi1/" + name}, Markers: markers}
}
func phase1Unit(name string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestPhase1Tables/native/" + name, "abi1": "TestPhase1Tables/abi1/" + name}, Markers: []string{"MUTATION-EFFECT decision"}}
}
func phase1Registry() []prot {
	var result []prot
	add := func(id, site string, sets ...harness.MutationSet) {
		result = append(result, prot{ID: id, Site: site, Class: "single", DirectLeg: sets[0].Legs[0].Name, MutationSets: sets})
	}
	one := func(id string, legs ...harness.Leg) harness.MutationSet {
		return harness.MutationSet{IDs: []string{id}, Legs: legs}
	}
	add("P-CLONE-USER", "cloneSysProcAttr user flag", one("P-CLONE-USER", phase1Unit("U-CloneUSER"), phase1Leg("L-CLONE-USER", "MUTATION-ABORT clone")), harness.MutationSet{IDs: []string{"P-CLONE-USER", "P-NSVERIFY"}, Legs: []harness.Leg{phase1Leg("L-CLONE-USER", "MUTATION-ABORT clone")}})
	add("P-CLONE-MNT", "cloneSysProcAttr mount flag", one("P-CLONE-MNT", phase1Unit("U-CloneMNT"), phase1Leg("L-CLONE-MNT", "MUTATION-ABORT nsverify")), harness.MutationSet{IDs: []string{"P-CLONE-MNT", "P-NSVERIFY"}, Legs: []harness.Leg{phase1Leg("L-CLONE-MNT", "MUTATION-ABORT private")}})
	for _, stage := range []string{"private", "setattr", "devnodes", "covers", "scratch"} {
		id := "P-FAULT-" + stage
		add(id, "setupMounts post-call error guard", one(id, phase1Leg("L-FAULT-"+stage, "MUTATION-EFFECT reached-exec")))
	}
	devLiteral := phase1Unit("U-DevNodesLiteral")
	devLiteral.Markers = nil
	add("P-DEV-SIX", "bindDevNodes per-device bind", one("P-DEV-SIX", devLiteral, phase1Leg("L-DEVNODE-WRITE", "MUTATION-EFFECT null-denied"), phase1Leg("L-READS-WORK")))
	add("P-SCRATCH-SIZE", "mountTmpfs size option", one("P-SCRATCH-SIZE", phase1Leg("L-SCRATCH-FILL", "MUTATION-EFFECT filled"), phase1Leg("L-SCRATCH-PRIVATE")))
	add("P-SCRATCH-FLAGS", "mountTmpfs flags", one("P-SCRATCH-FLAGS", phase1Leg("L-SCRATCH-NOEXEC", "MUTATION-ABORT selfcheck")), harness.MutationSet{IDs: []string{"P-SCRATCH-FLAGS", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{phase1Leg("L-SCRATCH-NOEXEC", "MUTATION-EFFECT executed"), phase1Leg("L-SCRATCH-PRIVATE")}})
	for _, resource := range []string{"NPROC", "FSIZE", "CORE"} {
		id := "P-RL-" + resource
		leg := phase1Leg("L-RL-"+resource, "MUTATION-EFFECT limit")
		if resource == "NPROC" {
			leg.CIOnly = true
			leg.Root = true
		}
		add(id, "setRlimits "+resource, one(id, leg))
	}
	add("P-FDS", "closeInheritedFDs close_range", one("P-FDS", phase1Leg("L-FDS", "MUTATION-EFFECT inherited-write")))
	for _, bit := range []string{"IOCTL-DEV", "TRUNCATE", "REFER"} {
		id := "P-LL-" + bit
		add(id, "handledFS access bit", one(id, phase1Unit("U-Handled-"+bit)))
	}
	opened := phase1Leg("L-DEV-OPEN", "MUTATION-EFFECT opened")
	tty := phase1Leg("L-TTY-STATE", "MUTATION-EFFECT tty-exclusive")
	partial := phase1Leg("L-TTY-STATE")
	partial.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT tty-exclusive"}}
	if abi, _ := probeLandlockABI(); abi < 5 {
		partial.Markers = []string{"MUTATION-EFFECT tty-exclusive"}
	}
	add("P-NODEV", "remountRootReadOnly NODEV", one("P-NODEV", phase1Leg("L-DEV-OPEN", "MUTATION-ABORT selfcheck")), harness.MutationSet{IDs: []string{"P-NODEV", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{opened, partial}}, harness.MutationSet{IDs: []string{"P-NODEV", "P-SELFCHECK-MOUNTS", "P-LL-IOCTL-DEV"}, Legs: []harness.Leg{opened, tty}})
	pattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		panic(err)
	}
	corePattern := strings.TrimSpace(string(pattern))
	for i := range result {
		if result[i].ID == "P-RL-CORE" {
			normal := p15Leg("L-CRASH-NO-HELPER")
			normal.CIOnly = true
			if strings.HasPrefix(corePattern, "|") {
				normal.Markers = []string{"MUTATION-EFFECT helper-record"}
			}
			result[i].MutationSets[0].Legs = append(result[i].MutationSets[0].Legs, normal)
			if !strings.HasPrefix(corePattern, "@") {
				normal.Markers = []string{"MUTATION-EFFECT helper-record"}
				result[i].MutationSets = append(result[i].MutationSets, harness.MutationSet{IDs: []string{"P-RL-CORE", "P-RO", "P-SELFCHECK-MOUNTS", "P-LL-FS"}, Legs: []harness.Leg{normal}})
			}
		}
		if result[i].ID == "P-LL-IOCTL-DEV" {
			result[i].MutationSets[0].Legs = append(result[i].MutationSets[0].Legs, phase1Leg("L-TTY-STATE"))
			result[i].MutationSets = append(result[i].MutationSets, harness.MutationSet{IDs: []string{"P-NODEV", "P-SELFCHECK-MOUNTS", "P-LL-IOCTL-DEV"}, Legs: []harness.Leg{opened, tty}})
		}
		if result[i].ID == "P-LL-TRUNCATE" {
			var legs []harness.Leg
			for _, name := range []string{"L-WRITE-ROOT", "L-WRITE-SUBMOUNT"} {
				leg := phase1Leg(name, "MUTATION-EFFECT truncate")
				for abi := range leg.Names {
					leg.Names[abi] = "TestJailMatrixP14/" + abi + "/" + name
				}
				legs = append(legs, leg)
				green := leg
				green.Markers = nil
				result[i].MutationSets[0].Legs = append(result[i].MutationSets[0].Legs, green)
			}
			result[i].MutationSets = append(result[i].MutationSets, harness.MutationSet{IDs: []string{"P-RO", "P-SELFCHECK-MOUNTS", "P-LL-TRUNCATE"}, Legs: legs})
		}
	}
	for i := range result {
		protection := &result[i]
		switch protection.ID {
		case "P-CLONE-USER", "P-CLONE-MNT":
			protection.Class = "multi"
			protection.Partners = []string{"P-NSVERIFY"}
		case "P-NODEV":
			protection.Class = "multi"
			protection.Partners = []string{"P-SELFCHECK-MOUNTS", "P-LL-IOCTL-DEV"}
			protection.EffectLegs = []string{"L-TTY-STATE"}
		case "P-DEV-SIX":
			protection.EffectLegs = []string{"L-DEVNODE-WRITE", "L-READS-WORK"}
		case "P-SCRATCH-FLAGS":
			protection.Class = "multi"
			protection.Partners = []string{"P-SELFCHECK-MOUNTS"}
			protection.EffectLegs = []string{"L-SCRATCH-PRIVATE"}
		case "P-SCRATCH-SIZE":
			protection.EffectLegs = []string{"L-SCRATCH-PRIVATE"}
		case "P-RL-CORE":
			protection.Class = "multi"
			protection.Partners = []string{"P-SC-RLIMIT-CORE", "P-RO", "P-SELFCHECK-MOUNTS", "P-LL-FS"}
			protection.EffectLegs = []string{"L-CRASH-NO-HELPER"}
		case "P-LL-IOCTL-DEV":
			protection.Class = "multi"
			protection.Partners = []string{"P-NODEV", "P-SELFCHECK-MOUNTS"}
			protection.EffectLegs = []string{"L-TTY-STATE"}
		case "P-LL-TRUNCATE":
			protection.Class = "multi"
			protection.Partners = []string{"P-RO", "P-SELFCHECK-MOUNTS"}
			protection.EffectLegs = []string{"L-WRITE-ROOT", "L-WRITE-SUBMOUNT"}
		case "P-LL-REFER":
			protection.Class = "direct"
		}
	}
	return result
}
