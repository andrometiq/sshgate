package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func coverLeg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixCovers/native/" + name, "abi1": "TestJailMatrixCovers/abi1/" + name}, Markers: markers}
}
func coverRegistry() []prot {
	abort := func(name string) harness.Leg { return coverLeg(name, "MUTATION-ABORT selfcheck") }
	effect := func(name, marker string) harness.Leg { return coverLeg(name, "MUTATION-EFFECT "+marker) }
	coverEffect := harness.MutationSet{IDs: []string{"P-COVERS", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{effect("L-FUSE-IOCTL", "fuse-ioctl"), coverLeg("L-COVER-WALKDENIED", "MUTATION-EFFECT fuse-ioctl-absolute", "MUTATION-EFFECT fuse-ioctl-cwd")}}
	trace := effect("L-TRACEFS", "trace-consumed")
	trace.Root = true
	trace.CIOnly = true
	coverEffect.Legs = append(coverEffect.Legs, trace)
	cwdEffect := harness.MutationSet{IDs: []string{"P-CWD", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{effect("L-COVER-CWD", "fuse-ioctl")}}
	reachEffect := harness.MutationSet{IDs: []string{"REACH-R3", "P-SELFCHECK-REACH"}, Legs: []harness.Leg{effect("L-COVER-STACKED", "fuse-ioctl")}}
	shimLandlock := harness.MutationSet{IDs: []string{"P-SHIM-SEAL", "SHIM-NOCAPS"}, Legs: []harness.Leg{coverLeg("L-SHIM-PROC")}}
	shimCaps := harness.MutationSet{IDs: []string{"P-SHIM-SEAL", "P-LL-REQUIRED", "P-SELFCHECK-LL"}, Legs: []harness.Leg{coverLeg("L-SHIM-PROC")}}
	shimSeal := harness.MutationSet{IDs: []string{"SHIM-NOCAPS", "P-LL-REQUIRED", "P-SELFCHECK-LL"}, Legs: []harness.Leg{coverLeg("L-SHIM-PROC")}}
	shimEffect := harness.MutationSet{IDs: []string{"P-SHIM-SEAL", "SHIM-NOCAPS", "P-LL-REQUIRED", "P-SELFCHECK-LL"}, Legs: []harness.Leg{effect("L-SHIM-PROC", "shim-proc")}}
	loop := coverLeg("L-COVER-LOOP", "MUTATION-EFFECT visible", "MUTATION-EFFECT nonempty")
	loop.Root = true
	loop.CIOnly = true
	privateEffect := harness.MutationSet{IDs: []string{"P-PRIVATE", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{effect("L-PRIVATE-PROPAGATION", "fuse-ioctl")}}
	privateWrite := harness.MutationSet{IDs: []string{"P-PRIVATE", "P-SELFCHECK-MOUNTS", "P-LL-FS"}, Legs: []harness.Leg{coverLeg("L-PRIVATE-PROPAGATION", "MUTATION-EFFECT fuse-ioctl", "MUTATION-EFFECT write")}}
	var result []prot
	add := func(id, site string, sets ...harness.MutationSet) {
		result = append(result, prot{ID: id, Site: site, Class: "multi", MutationSets: sets})
	}
	one := func(id string, leg harness.Leg) harness.MutationSet {
		return harness.MutationSet{IDs: []string{id}, Legs: []harness.Leg{leg}}
	}
	add("P-COVERS", "coverMounts", one("P-COVERS", abort("L-SELFCHECK-MOUNTS")), coverEffect)
	add("P-CWD", "command Dir / worker cwd", one("P-CWD", abort("L-COVER-CWD")), cwdEffect)
	add("P-REACH", "reachableMounts stack walk", one("P-REACH", abort("L-COVER-STACKED")))
	add("REACH-R3", "reachableMounts r3 characterization seam", one("REACH-R3", abort("L-COVER-STACKED")), reachEffect)
	add("P-SELFCHECK-REACH", "S2 stepwise lookup cross-check", reachEffect)
	add("P-SELFCHECK-MOUNTS", "S2 final mount state", coverEffect, cwdEffect, privateEffect, privateWrite)
	add("P-SHIM-SEAL", "RunShim PR_SET_DUMPABLE", one("P-SHIM-SEAL", coverLeg("L-SHIM-PROC")), shimLandlock, shimCaps, shimEffect)
	add("SHIM-NOCAPS", "RunShim drop shim capabilities seam", one("SHIM-NOCAPS", coverLeg("L-SHIM-PROC")), shimLandlock, shimSeal, shimEffect)
	add("P-BACKING", "mountAccepted backing device chain", one("P-BACKING", loop))
	add("P-PRIVATE", "setupMounts make-private", one("P-PRIVATE", abort("L-SELFCHECK-MOUNTS")), privateEffect, privateWrite)
	overlay := effect("L-COVER-OVERLAY", "delegated-read")
	overlay.Root = true
	add("SAFE-ADD=overlay", "mountAccepted overlay seam", one("SAFE-ADD=overlay", overlay))
	add("SAFE-DROP=ramfs", "mountAccepted unknown fstype seam", one("SAFE-DROP=ramfs", effect("L-COVER-UNKNOWN", "covered")))
	return result
}
func completeRegistry() []prot {
	result := append(append(append(append(append(p12Registry(), p15Registry()...), hostPIDRegistry()...), coverRegistry()...), credentialRegistry()...), writeRegistry()...)
	result = append(result, phase1Registry()...)
	for i := range result {
		protection := &result[i]
		for j := range protection.MutationSets {
			set := &protection.MutationSets[j]
			if set.Name() == "P-RO,P-SELFCHECK-MOUNTS,P-LL-FS" {
				crash := p15Leg("L-CRASH-NO-HELPER")
				crash.CIOnly = true
				set.Legs = append(set.Legs, crash)
			}
		}
		if protection.ID == "P-SC-SYNC" {
			// Only root can pin the FUSE bdi's min_ratio; without it strictlimit
			// writeback makes the observation a race on Linux 6.1.
			sync := coverLeg("L-SC-SYNC", "MUTATION-EFFECT sync-writeback")
			sync.Root = true
			protection.MutationSets[0].Legs = append(protection.MutationSets[0].Legs, sync)
		}
		if protection.ID == "P-SC-META" {
			protection.MutationSets[0].Legs = append(protection.MutationSets[0].Legs, metadataLegs(false)...)
			protection.MutationSets = append(protection.MutationSets, harness.MutationSet{IDs: []string{"P-SC-META", "P-RO", "P-SELFCHECK-MOUNTS"}, Legs: metadataLegs(true)})
		}
		if protection.ID != "P-MQ" {
			continue
		}
		protection.Partners = []string{"P-COVERS", "P-SELFCHECK-MOUNTS"}
		protection.MutationSets = append(protection.MutationSets, harness.MutationSet{IDs: []string{"P-MQ", "P-COVERS"}, Legs: []harness.Leg{coverLeg("L-SELFCHECK-MOUNTS", "MUTATION-ABORT selfcheck")}})
		mq := p12Leg("L-MQUEUE", "MUTATION-EFFECT queue-drained")
		mq.Names = map[string]string{"native": "TestJailMatrixP14/native/L-MQUEUE", "abi1": "TestJailMatrixP14/abi1/L-MQUEUE"}
		protection.MutationSets = append(protection.MutationSets, harness.MutationSet{IDs: []string{"P-MQ", "P-COVERS", "P-SELFCHECK-MOUNTS"}, Legs: []harness.Leg{mq}})
	}
	return result
}
