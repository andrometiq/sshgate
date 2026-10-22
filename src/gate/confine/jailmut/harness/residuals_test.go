package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	socketCode = "R-L2-SOCKET-BELOW-ABI9"
	loaderCode = "R-L2-LOADER-ROUTE"
)

func TestCaseResidualDeclarations(t *testing.T) {
	good := testCase()
	good.ABIs = []string{"native", "abi1"}
	good.ResidualABIs = map[string]string{"abi1": socketCode}
	if err := ValidateCases([]Case{good}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Case){
		"undocumented code":           func(c *Case) { c.ResidualABIs = map[string]string{"abi1": "R-UNLISTED"} },
		"undeclared ABI":              func(c *Case) { c.ResidualABIs = map[string]string{"abi9": socketCode} },
		"Residuals on an Effect case": func(c *Case) { c.Residuals = []string{"R-NUMA-EFFECT"} },
		"ResidualABIs on a Residual-kind case": func(c *Case) {
			c.Kind, c.Obligations, c.Residuals = "Residual", nil, []string{"R-NUMA-EFFECT"}
		},
		"root-only omission without Root":       func(c *Case) { c.Omissions = []string{"root-only"} },
		"nonroot-only omission without NonRoot": func(c *Case) { c.Omissions = []string{"nonroot-only"} },
	} {
		c := good
		change(&c)
		if ValidateCases([]Case{c}) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (ResidualBelowABI(socketCode, 4, 9)["native"] != socketCode) || ResidualBelowABI(socketCode, 9, 9)["native"] != "" || ResidualBelowABI(socketCode, 9, 9)["abi1"] != socketCode {
		t.Error("ResidualBelowABI lanes")
	}
}

func TestCaseResidualProofs(t *testing.T) {
	c := testCase()
	c.ABIs = []string{"native", "abi1"}
	c.ResidualABIs = map[string]string{"abi1": socketCode}
	complete := "PROOF-COMPLETE L-PROOF native markers=EFFECT:write\n"
	residual := "PROOF-RESIDUAL L-PROOF abi1 " + socketCode + "\n"
	if _, err := CheckManifest(strings.NewReader(complete+residual), []Case{c}, false, true); err != nil {
		t.Fatal(err)
	}
	for name, log := range map[string]string{
		"residual in a non-residual ABI": "PROOF-RESIDUAL L-PROOF native " + socketCode + "\n" + residual,
		"complete in a residual ABI":     complete + "PROOF-COMPLETE L-PROOF abi1 markers=\n",
		"another documented code":        complete + "PROOF-RESIDUAL L-PROOF abi1 " + loaderCode + "\n",
		"a residual with markers":        complete + "PROOF-RESIDUAL L-PROOF abi1 " + socketCode + " markers=EFFECT:write\n",
	} {
		if _, err := CheckManifest(strings.NewReader(log), []Case{c}, false, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	numa := Case{Name: "L-NUMA", Kind: "Residual", ABIs: []string{"native", "abi1"}, Residuals: []string{"R-NUMA-EFFECT"}}
	for _, log := range []string{"PROOF-RESIDUAL L-NUMA native R-NUMA-EFFECT\nPROOF-RESIDUAL L-NUMA abi1 R-NUMA-EFFECT\n", "PROOF-COMPLETE L-NUMA native markers=\nPROOF-RESIDUAL L-NUMA abi1 R-NUMA-EFFECT\n"} {
		if _, err := CheckManifest(strings.NewReader(log), []Case{numa}, false, true); err != nil {
			t.Errorf("legacy residual case changed: %v", err)
		}
	}
}

// judgeLine runs Judge over one passing leg that printed line.
func judgeLine(t *testing.T, leg Leg, abi, line string) error {
	t.Helper()
	var stream bytes.Buffer
	encoder := json.NewEncoder(&stream)
	name := leg.Names[abi]
	parent, _, _ := strings.Cut(name, "/")
	for _, event := range []Event{{Action: "output", Test: name, Output: line + "\n"}, {Action: "pass", Test: name}, {Action: "pass", Test: parent}, {Action: "pass"}} {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return Judge(&stream, "", 0, []Leg{leg}, abi)
}

func TestHarnessJudgeResiduals(t *testing.T) {
	leg := Leg{Name: "G-PIN", Names: map[string]string{"native": "TestP/native/G-PIN", "abi1": "TestP/abi1/G-PIN"},
		Markers: []string{"MUTATION-EFFECT unpinned"}, ABIMarkers: map[string][]string{"abi1": nil}, ResidualABIs: map[string]string{"abi1": socketCode}}
	residual := "PROOF-RESIDUAL G-PIN abi1 " + socketCode
	if err := judgeLine(t, leg, "abi1", residual); err != nil {
		t.Fatalf("expected residual: %v", err)
	}
	if err := judgeLine(t, leg, "native", "PROOF-COMPLETE G-PIN native markers=EFFECT:unpinned"); err != nil {
		t.Fatalf("red outside the residual lane: %v", err)
	}
	if err := judgeLine(t, leg, "native", "PROOF-RESIDUAL G-PIN native "+socketCode); err == nil {
		t.Error("residual in a non-residual lane accepted")
	}
	if err := judgeLine(t, leg, "abi1", "PROOF-COMPLETE G-PIN abi1 markers="); err == nil {
		t.Error("completion in a residual lane accepted")
	}
	expectRed := leg
	expectRed.ABIMarkers = nil
	if err := judgeLine(t, expectRed, "abi1", residual); err == nil || !strings.HasPrefix(err.Error(), "mutation not detected") {
		t.Errorf("residual where markers were expected: %v", err)
	}
	legacy := Leg{Name: "L-NUMA", Names: leg.Names, Markers: []string{"MUTATION-EFFECT moved"}, Residuals: []string{"R-NUMA-EFFECT"}}
	legacy.Names = map[string]string{"native": "TestP/native/L-NUMA", "abi1": "TestP/abi1/L-NUMA"}
	if err := judgeLine(t, legacy, "native", "PROOF-RESIDUAL L-NUMA native R-NUMA-EFFECT"); err != nil {
		t.Errorf("legacy residual changed: %v", err)
	}
}

// residualWorld is a synthetic manifest and registry as a host of Landlock ABI
// hostABI computes them: a per-lane residual Effect case (the G-L2-SOCK-PIN
// shape) beside a unit leg, a residual-only characterisation (the C-L2-LOADER
// shape) and the legacy NUMA case.
func residualWorld(hostABI int) ([]Case, []Protection) {
	pinLanes := ResidualBelowABI(socketCode, hostABI, 9)
	names := func(name string) map[string]string {
		return map[string]string{"native": "TestP/native/" + name, "abi1": "TestP/abi1/" + name}
	}
	both := []string{"native", "abi1"}
	cases := []Case{
		{Name: "U-RULES", Kind: "Unit", ABIs: both, Names: names("U-RULES"), Obligations: []string{"control:decision"}, Markers: []string{"EFFECT:decision"}},
		{Name: "G-PIN", Kind: "Effect", Mode: "Execute", ABIs: both, Names: names("G-PIN"), Obligations: []string{"control:connect", "jailed:lane2", "observe:listener"}, Markers: []string{"EFFECT:unpinned"}, ResidualABIs: pinLanes},
		{Name: "C-LOADER", Kind: "Execution", Mode: "Execute", ABIs: both, Names: names("C-LOADER"), Obligations: []string{"jailed:loader"}, ResidualABIs: map[string]string{"native": loaderCode, "abi1": loaderCode}},
		{Name: "L-NUMA", Kind: "Residual", ABIs: both, Names: names("L-NUMA"), Residuals: []string{"R-NUMA-EFFECT"}},
	}
	pin := Leg{Name: "G-PIN", Package: "p", Names: names("G-PIN"), Markers: []string{"MUTATION-EFFECT unpinned"}, ABIMarkers: map[string][]string{}, ResidualABIs: pinLanes}
	for abi := range pinLanes {
		pin.ABIMarkers[abi] = nil
	}
	unit := Leg{Name: "U-RULES", Package: "p", Names: names("U-RULES"), Markers: []string{"MUTATION-EFFECT decision"}}
	registry := []Protection{{ID: "P-PIN", Site: "pin", Class: "single", DirectLeg: "U-RULES", EffectLegs: []string{"G-PIN"},
		MutationSets: []MutationSet{{IDs: []string{"P-PIN"}, Legs: []Leg{unit, pin}}}}}
	return cases, registry
}

// lane is what one lane's runs produce: the baseline log, and the mutated
// proof line of each leg in each ABI.
type lane struct {
	baseline string
	mutated  map[string]string // "leg/abi" -> proof line
}

func honestLane(cases []Case, registry []Protection) lane {
	var log strings.Builder
	for _, c := range cases {
		for _, abi := range c.ABIs {
			switch {
			case c.ResidualABIs[abi] != "":
				fmt.Fprintf(&log, "PROOF-RESIDUAL %s %s %s\n", c.Name, abi, c.ResidualABIs[abi])
			case c.Kind == "Residual":
				fmt.Fprintf(&log, "PROOF-RESIDUAL %s %s %s\n", c.Name, abi, c.Residuals[0])
			default:
				fmt.Fprintf(&log, "PROOF-COMPLETE %s %s markers=\n", c.Name, abi)
			}
		}
	}
	mutated := map[string]string{}
	for _, leg := range registry[0].MutationSets[0].Legs {
		for _, abi := range []string{"native", "abi1"} {
			line := fmt.Sprintf("PROOF-RESIDUAL %s %s %s", leg.Name, abi, leg.ResidualABIs[abi])
			if leg.ResidualABIs[abi] == "" {
				var markers []string
				for _, marker := range leg.ExpectedMarkers(abi) {
					markers = append(markers, strings.Replace(strings.TrimPrefix(marker, "MUTATION-"), " ", ":", 1))
				}
				line = fmt.Sprintf("PROOF-COMPLETE %s %s markers=%s", leg.Name, abi, strings.Join(markers, ","))
			}
			mutated[leg.Name+"/"+abi] = line
		}
	}
	return lane{log.String(), mutated}
}

// runPipeline passes one lane pair through every check, as scripts/jailmut
// does, and returns the first error.
func runPipeline(t *testing.T, cases []Case, registry []Protection, lanes map[bool]lane) error {
	t.Helper()
	var reports []Report
	for _, root := range []bool{false, true} {
		report := Report{Root: root, CI: true}
		records, err := CheckManifest(strings.NewReader(lanes[root].baseline), cases, root, true)
		if err != nil {
			return err
		}
		report.Proofs = records
		set := registry[0].MutationSets[0]
		for _, abi := range []string{"native", "abi1"} {
			for _, leg := range set.Legs {
				line := lanes[root].mutated[leg.Name+"/"+abi]
				if err := judgeLine(t, leg, abi, line); err != nil {
					return err
				}
				proof, _ := ParseProof(line)
				if outcome, ok := ProofOutcome(set, leg, abi, proof); ok {
					report.Outcomes = append(report.Outcomes, outcome)
				}
			}
		}
		reports = append(reports, report)
	}
	if err := CheckCaseUnion(cases, registry, reports); err != nil {
		return err
	}
	return CheckUnion(registry, reports)
}

func TestUnionPipelinePerABIResiduals(t *testing.T) {
	for _, hostABI := range []int{4, 10} {
		cases, registry := residualWorld(hostABI)
		if err := ValidateCases(cases); err != nil {
			t.Fatal(err)
		}
		if err := Validate(registry); err != nil {
			t.Fatal(err)
		}
		good := honestLane(cases, registry)
		if err := runPipeline(t, cases, registry, map[bool]lane{false: good, true: good}); err != nil {
			t.Fatalf("ABI %d: honest lanes: %v", hostABI, err)
		}
	}
	cases, registry := residualWorld(10)
	good := honestLane(cases, registry)
	bad := func(change func(*lane)) map[bool]lane {
		broken := lane{good.baseline, map[string]string{}}
		for key, line := range good.mutated {
			broken.mutated[key] = line
		}
		change(&broken)
		return map[bool]lane{false: good, true: broken}
	}
	for name, lanes := range map[string]map[bool]lane{
		"baseline residual in a non-residual ABI": bad(func(l *lane) {
			l.baseline = strings.Replace(l.baseline, "PROOF-COMPLETE G-PIN native markers=", "PROOF-RESIDUAL G-PIN native "+socketCode, 1)
		}),
		"baseline completion in a residual ABI": bad(func(l *lane) {
			l.baseline = strings.Replace(l.baseline, "PROOF-RESIDUAL G-PIN abi1 "+socketCode, "PROOF-COMPLETE G-PIN abi1 markers=", 1)
		}),
		"a residual hides an expected-red mutation": bad(func(l *lane) {
			l.mutated["G-PIN/native"] = "PROOF-RESIDUAL G-PIN native " + socketCode
		}),
	} {
		if err := runPipeline(t, cases, registry, lanes); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Reports from a host below ABI 9, judged against the registry of a host
	// at ABI 9 or above: the residual outcome is green where red was expected.
	lowCases, lowRegistry := residualWorld(4)
	low := honestLane(lowCases, lowRegistry)
	if err := runPipeline(t, cases, registry, map[bool]lane{false: low, true: low}); err == nil {
		t.Error("reports from a low-ABI host passed a high-ABI host's union")
	}
}
