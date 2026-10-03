package harness

import "testing"

func TestRegistryValidation(t *testing.T) {
	makeRegistry := func() []Protection {
		return []Protection{{ID: "P-ONE", Site: "fixture", Class: "single", DirectLeg: "L-ONE", MutationSets: []MutationSet{{IDs: []string{"P-ONE"}, Legs: []Leg{{Name: "L-ONE", Package: "./fixture", Names: map[string]string{"native": "TestJail/native/L-ONE", "abi1": "TestJail/abi1/L-ONE"}, Markers: []string{"MUTATION-EFFECT write"}}}}}}}
	}
	if err := Validate(nil); err != nil {
		t.Fatal(err)
	}
	if err := Validate(makeRegistry()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unknown-mutation", "duplicate-mutation", "partner", "direct-leg", "missing-abi", "wrong-leg", "wrong-abi", "duplicate-marker", "bad-marker", "no-red"} {
		t.Run(name, func(t *testing.T) {
			registry := makeRegistry()
			set := &registry[0].MutationSets[0]
			leg := &set.Legs[0]
			switch name {
			case "unknown-mutation":
				set.IDs = append(set.IDs, "P-UNKNOWN")
			case "duplicate-mutation":
				set.IDs = append(set.IDs, "P-ONE")
			case "partner":
				registry[0].Partners = []string{"P-UNKNOWN"}
			case "direct-leg":
				registry[0].DirectLeg = "L-UNKNOWN"
			case "missing-abi":
				delete(leg.Names, "abi1")
			case "wrong-leg":
				leg.Names["native"] = "TestJail/native/L-UNRELATED"
			case "wrong-abi":
				leg.Names["abi1"] = leg.Names["native"]
			case "duplicate-marker":
				leg.Markers = append(leg.Markers, leg.Markers[0])
			case "bad-marker":
				leg.Markers = []string{"MUTATION-EFFECT write extra"}
			case "no-red":
				leg.ABIMarkers = map[string][]string{"abi1": {}}
			}
			if err := Validate(registry); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
