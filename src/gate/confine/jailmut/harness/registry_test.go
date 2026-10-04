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

func TestRegistryValidationRedundantGreenSets(t *testing.T) {
	green := Leg{Name: "L-ONE", Package: "./fixture", Names: map[string]string{"native": "TestJail/native/L-ONE", "abi1": "TestJail/abi1/L-ONE"}}
	red := green
	red.Markers = []string{"MUTATION-EFFECT write"}
	joint := MutationSet{IDs: []string{"P-ONE", "P-TWO"}, Legs: []Leg{red}}
	registry := []Protection{
		{ID: "P-ONE", Site: "first wall", Class: "multi", MutationSets: []MutationSet{{IDs: []string{"P-ONE"}, Legs: []Leg{green}}, joint}},
		{ID: "P-TWO", Site: "second wall", Class: "multi", MutationSets: []MutationSet{{IDs: []string{"P-TWO"}, Legs: []Leg{green}}, joint}},
	}
	if err := Validate(registry); err != nil {
		t.Fatal(err)
	}
	var reports []Report
	for _, root := range []bool{false, true} {
		report := Report{Root: root, CI: true}
		for _, abi := range []string{"native", "abi1"} {
			for _, set := range []string{"P-ONE", "P-TWO", "P-ONE,P-TWO"} {
				report.Outcomes = append(report.Outcomes, Outcome{Set: set, ABI: abi, Leg: "L-ONE", Red: set == "P-ONE,P-TWO"})
			}
		}
		reports = append(reports, report)
	}
	if err := CheckUnion(registry, reports); err != nil {
		t.Fatal(err)
	}
	missingGreen := append([]Report(nil), reports...)
	missingGreen[0].Outcomes = missingGreen[0].Outcomes[1:]
	if CheckUnion(registry, missingGreen) == nil {
		t.Fatal("accepted omitted green redundancy proof")
	}
	missingRed := append([]Report(nil), reports...)
	missingRed[0].Outcomes = append([]Outcome(nil), reports[0].Outcomes[:2]...)
	if CheckUnion(registry, missingRed) == nil {
		t.Fatal("accepted omitted red proof")
	}
	registry[0].MutationSets = registry[0].MutationSets[:1]
	if Validate(registry) == nil {
		t.Fatal("accepted protection with green proofs only")
	}
}

func TestRegistryValidationNestedLegName(t *testing.T) {
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{"TestJail/native/L-COVER-WALKDENIED/absolute", true},
		{"TestJail/native/L-COVER-WALKDENIED/relative", false},
		{"TestJail/native/other/L-COVER-WALKDENIED/absolute", false},
		{"TestJail/abi1/L-COVER-WALKDENIED/absolute", false},
		{"TestJail/native/not-L-COVER-WALKDENIED/absolute", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			leg := Leg{Name: "L-COVER-WALKDENIED/absolute", Package: "./fixture", Names: map[string]string{"native": test.name, "abi1": "TestJail/abi1/L-COVER-WALKDENIED/absolute"}, Markers: []string{"MUTATION-EFFECT ioctl"}}
			registry := []Protection{{ID: "P-COVER", Site: "fixture", Class: "single", MutationSets: []MutationSet{{IDs: []string{"P-COVER"}, Legs: []Leg{leg}}}}}
			err := Validate(registry)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}
