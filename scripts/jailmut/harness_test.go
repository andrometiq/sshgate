package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func fixtureLeg() harness.Leg {
	return harness.Leg{Name: "L-RED", Package: "./testdata/fixture", Names: map[string]string{"native": "TestFixture/native/L-RED", "abi1": "TestFixture/abi1/L-RED"}, Markers: []string{"MUTATION-EFFECT write"}}
}

func TestHarnessFixtures(t *testing.T) {
	for _, mode := range []string{"red", "marker-setup", "marker-unexpected", "panic", "timeout", "setup", "pass", "missing", "extra", "sibling", "ancestor", "skip", "build"} {
		t.Run(mode, func(t *testing.T) {
			path := "./testdata/fixture"
			if mode == "build" {
				path = "./testdata/buildfail"
			}
			timeout := "10s"
			if mode == "timeout" {
				timeout = "100ms"
			}
			command := exec.Command("go", "test", "-count=1", "-json", "-timeout", timeout, "-run", "^TestFixture$/^native$", path)
			command.Env = append(os.Environ(), "JAILMUT_FIXTURE="+mode)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			status := 0
			if err := command.Run(); err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					status = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			err := harness.Judge(&stdout, stderr.String(), status, []harness.Leg{fixtureLeg()}, "native")
			if mode == "red" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatalf("accepted %s infrastructure/undetected mutation", mode)
			}
			if (mode == "marker-setup" || mode == "marker-unexpected") && !strings.Contains(err.Error(), "infrastructure") {
				t.Fatalf("wrong marker-plus-infrastructure diagnostic: %v", err)
			}
			if mode == "pass" && !strings.Contains(err.Error(), "mutation not detected") {
				t.Fatalf("wrong diagnostic: %v", err)
			}
		})
	}
}

func TestHarnessInvalidStreams(t *testing.T) {
	for _, stream := range []string{"not json\n", `{"Action":"fail","Package":"fixture"}` + "\n", ""} {
		if err := harness.Judge(strings.NewReader(stream), "", 1, []harness.Leg{fixtureLeg()}, "native"); err == nil {
			t.Fatal("accepted invalid/missing test events")
		}
	}
	if err := harness.Judge(strings.NewReader(""), "", -1, nil, "native"); err == nil {
		t.Fatal("accepted signal")
	}
}

func TestHarnessLaneUnion(t *testing.T) {
	leg := fixtureLeg()
	leg.Root = true
	leg.CIOnly = true
	set := harness.MutationSet{IDs: []string{"P-FIXTURE"}, Legs: []harness.Leg{leg}}
	registry := []harness.Protection{{ID: "P-FIXTURE", Site: "fixture", Class: "single", MutationSets: []harness.MutationSet{set}}}
	legs, omitted := harness.Select(set, false, true)
	if len(legs) != 0 || len(omitted) != 1 || !strings.Contains(omitted[0], "MUTATE-OMITTED(root)") {
		t.Fatal("wrong non-root CI omission")
	}
	legs, omitted = harness.Select(set, true, false)
	if len(legs) != 0 || len(omitted) != 1 || !strings.Contains(omitted[0], "MUTATE-OMITTED(ci-only)") {
		t.Fatal("ciOnly red must be NOT-RUN off CI")
	}
	legs, omitted = harness.Select(set, true, true)
	if len(legs) != 1 || len(omitted) != 0 {
		t.Fatal("root CI omitted leg")
	}
	nonroot := harness.Report{CI: true}
	root := harness.Report{CI: true, Root: true}
	for _, abi := range []string{"native", "abi1"} {
		root.Outcomes = append(root.Outcomes, harness.Outcome{Set: set.Name(), ABI: abi, Leg: leg.Name, Red: true})
	}
	if err := harness.CheckUnion(registry, []harness.Report{nonroot, root}); err != nil {
		t.Fatal(err)
	}
	if err := harness.CheckUnion(registry, []harness.Report{nonroot}); err == nil {
		t.Fatal("accepted missing root run")
	}
	missing := root
	missing.Outcomes = nil
	if err := harness.CheckUnion(registry, []harness.Report{nonroot, missing}); err == nil {
		t.Fatal("accepted missing root coverage")
	}
	registry[0].MutationSets[0].Legs[0].Root = false
	if err := harness.CheckUnion(registry, []harness.Report{nonroot, root}); err == nil {
		t.Fatal("accepted ciOnly omission in non-root CI")
	}
}

func TestHarnessLaneExecution(t *testing.T) {
	leg := fixtureLeg()
	leg.CIOnly = true
	set := harness.MutationSet{IDs: []string{"P-FIXTURE"}, Legs: []harness.Leg{leg}}
	var output bytes.Buffer
	report := harness.Report{}
	if err := runSet(set, &report, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "NOT-RUN:") != 2 || !strings.Contains(output.String(), "MUTATE-OMITTED(ci-only)") || len(report.Outcomes) != 0 {
		t.Fatalf("off-CI report: %s %+v", &output, report)
	}
	output.Reset()
	report.CI = true
	if err := runSet(set, &report, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "NOT-RUN") || len(report.Outcomes) != 2 {
		t.Fatalf("CI omitted leg: %s %+v", &output, report)
	}
}

func TestHarnessMutationSelection(t *testing.T) {
	interaction := harness.MutationSet{IDs: []string{"P-A", "P-B"}}
	registry := []harness.Protection{
		{ID: "P-A", MutationSets: []harness.MutationSet{{IDs: []string{"P-A"}}, interaction}},
		{ID: "P-B", MutationSets: []harness.MutationSet{{IDs: []string{"P-B"}}, interaction}},
	}
	sets, err := selectMutationSets(registry, "P-B")
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || sets[0].Name() != "P-A,P-B" || sets[1].Name() != "P-B" {
		t.Fatalf("selection omitted interaction or duplicated set: %+v", sets)
	}
	sets, err = selectMutationSets(registry, "")
	if err != nil || len(sets) != 3 {
		t.Fatalf("full selection: %+v %v", sets, err)
	}
	if _, err := selectMutationSets(registry, "P-B,P-UNKNOWN"); err == nil {
		t.Fatal("accepted unknown MUTATE ID")
	}
}
