package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func writeRegistry() []prot {
	writeLegs := func(all bool) []harness.Leg {
		var legs []harness.Leg
		for _, name := range []string{"L-WRITE-ROOT", "L-WRITE-SUBMOUNT"} {
			leg := p12Leg(name, "")
			for abi := range leg.Names {
				leg.Names[abi] = "TestJailMatrixP14/" + abi + "/" + name
			}
			leg.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT truncate"}}
			if all {
				leg.Markers = []string{"MUTATION-EFFECT write", "MUTATION-EFFECT truncate"}
				leg.ABIMarkers = nil
			}
			legs = append(legs, leg)
		}
		return legs
	}
	partial := writeLegs(false)
	// Native ABIs below 3 have the same truncate gap as forced ABI 1.
	if probeLandlockABI() < 3 {
		for i := range partial {
			partial[i].Markers = []string{"MUTATION-EFFECT truncate"}
		}
	}
	check := coverSelfcheckLeg("L-SELFCHECK-MOUNTS", "MUTATION-ABORT selfcheck")
	return []prot{
		{ID: "P-RO", Site: "setupMounts recursive RDONLY", Class: "multi", Partners: []string{"P-SELFCHECK-MOUNTS", "P-LL-FS", "P-SC-META"}, MutationSets: []harness.MutationSet{
			{IDs: []string{"P-RO"}, Legs: []harness.Leg{check}},
			{IDs: []string{"P-RO", "P-SELFCHECK-MOUNTS"}, Legs: append(append(partial, writeMatrixLeg("L-WRITE-ERRNO", "MUTATION-EFFECT errno")), metadataLegs(false)...)},
			{IDs: []string{"P-RO", "P-SELFCHECK-MOUNTS", "P-LL-FS"}, Legs: writeLegs(true)},
			{IDs: []string{"P-SC-META", "P-RO", "P-SELFCHECK-MOUNTS"}, Legs: metadataLegs(true)},
		}},
		{ID: "P-LL-FS", Site: "applyLandlock root access rights", Class: "multi", Partners: []string{"P-RO", "P-SELFCHECK-MOUNTS"}, MutationSets: []harness.MutationSet{{IDs: []string{"P-LL-FS"}, Legs: []harness.Leg{writeMatrixLeg("L-FIFO-WRITE", "MUTATION-EFFECT delivered")}}, {IDs: []string{"P-RO", "P-SELFCHECK-MOUNTS", "P-LL-FS"}, Legs: writeLegs(true)}}},
		{ID: "P-NOSUID", Site: "setupMounts recursive NOSUID", Class: "direct", MutationSets: []harness.MutationSet{
			{IDs: []string{"P-NOSUID"}, Legs: []harness.Leg{check}},
			{IDs: []string{"P-NOSUID", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{credentialLeg("L-SETUID", "MUTATION-EFFECT nosuid-state")}},
		}},
	}
}

func coverSelfcheckLeg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixCovers/native/" + name, "abi1": "TestJailMatrixCovers/abi1/" + name}, Markers: markers}
}

func writeMatrixLeg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixWrite/native/" + name, "abi1": "TestJailMatrixWrite/abi1/" + name}, Markers: markers}
}

func metadataLegs(red bool) []harness.Leg {
	var markers []string
	if red {
		for _, effect := range []string{"mode", "mtime", "flags", "xattr-set", "xattr-remove"} {
			markers = append(markers, "MUTATION-EFFECT metadata-"+effect)
		}
	}
	var legs []harness.Leg
	for _, name := range []string{"L-META-EROFS", "L-META-ROOT", "L-META-SUBMOUNT"} {
		legs = append(legs, writeMatrixLeg(name, markers...))
	}
	return legs
}
