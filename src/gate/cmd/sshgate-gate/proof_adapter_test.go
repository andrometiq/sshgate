package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

const gateProofPackage = "./src/gate/cmd/sshgate-gate"

// gateProofCases is a literal copy of the confine manifest's cases for this
// package (proofCasesPhase2); TestGateProofCasesMatchManifest keeps the two
// equal.
func gateProofCases() []harness.Case {
	var cases []harness.Case
	for _, name := range []string{"U-ExecReadConfineRequired", "U-SpecStrictSources"} {
		cases = append(cases, harness.Case{
			Name: name, Package: gateProofPackage, Kind: "Unit", ABIs: []string{"native", "abi1"},
			Names:       map[string]string{"native": "TestPhase2Tables/native/" + name, "abi1": "TestPhase2Tables/abi1/" + name},
			Obligations: []string{"control:decision"}, Markers: []string{"EFFECT:decision"},
		})
	}
	return cases
}

// gateHooks are the protections whose mutation may show an effect here.
var gateHooks = []string{"P-G-CONFINE-REQUIRED", "P-G-STRICT", "P-G-NET-STRICT"}

// gateProof is the gate package's proof: one case, its obligations, and the
// markers its legs observed. Finish prints the one PROOF-COMPLETE line.
type gateProof struct {
	t        *testing.T
	abi      string
	caseDef  harness.Case
	done     map[string]bool
	markers  []string
	finished bool
}

func newProof(t *testing.T, name string) *gateProof {
	t.Helper()
	index := slices.IndexFunc(gateProofCases(), func(c harness.Case) bool { return c.Name == name })
	if index < 0 {
		t.Fatalf("SETUP: unknown gate proof %s", name)
	}
	c := gateProofCases()[index]
	abi := ""
	for _, part := range strings.Split(t.Name(), "/") {
		if slices.Contains(c.ABIs, part) {
			if abi != "" {
				t.Fatal("SETUP: ambiguous proof ABI")
			}
			abi = part
		}
	}
	if abi == "" || c.Names[abi] != t.Name() {
		t.Fatalf("SETUP: proof %s runs as %s", name, t.Name())
	}
	p := &gateProof{t: t, abi: abi, caseDef: c, done: map[string]bool{}}
	t.Cleanup(func() {
		if !p.finished {
			t.Error("SETUP: proof not finished")
		}
	})
	return p
}

// Control completes a control obligation; an invalid control fails the leg.
func (p *gateProof) Control(name string, valid bool) {
	p.t.Helper()
	key := "control:" + name
	if p.finished || !slices.Contains(p.caseDef.Obligations, key) || p.done[key] {
		p.t.Fatalf("SETUP: invalid or duplicate obligation %s", key)
	}
	if !valid {
		p.t.Fatalf("SETUP: control %s failed", name)
	}
	p.done[key] = true
}

// Effect records that a protection's effect was observed.
func (p *gateProof) Effect(assertion string, observed bool) {
	if observed && !slices.Contains(p.markers, "EFFECT:"+assertion) {
		p.markers = append(p.markers, "EFFECT:"+assertion)
	}
}

func (p *gateProof) Finish() {
	p.t.Helper()
	if p.finished {
		p.t.Fatal("SETUP: duplicate proof finalization")
	}
	for _, key := range p.caseDef.Obligations {
		if !p.done[key] {
			p.t.Fatalf("SETUP: unfinished obligation %s", key)
		}
	}
	if p.t.Failed() {
		return
	}
	mutated := slices.ContainsFunc(gateHooks, jailmut.On)
	if len(p.markers) > 0 && !mutated {
		p.t.Fatalf("protection effects observed in a normal build: %v", p.markers)
	}
	slices.Sort(p.markers)
	line := "PROOF-COMPLETE " + p.caseDef.Name + " " + p.abi + " markers=" + strings.Join(p.markers, ",")
	record, err := harness.ParseProof(line)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := harness.CheckProof(p.caseDef, record, os.Getuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1"); err != nil {
		p.t.Fatal(err)
	}
	p.finished = true
	p.t.Log(line)
}

// TestGateProofCasesMatchManifest: this package's proof cases are exactly the
// confine manifest's cases for this package, so the jail runner's manifest
// check and these legs cannot drift apart.
func TestGateProofCasesMatchManifest(t *testing.T) {
	if err := harness.ValidateCases(gateProofCases()); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("go", "test", "-count=1", "-run", "^TestProofCasesJSON$", "-v", "../../confine").CombinedOutput()
	if err != nil {
		t.Fatalf("read the confine manifest: %v\n%s", err, output)
	}
	var manifest []harness.Case
	for _, line := range strings.Split(string(output), "\n") {
		if data, ok := strings.CutPrefix(line, "JAIL-PROOF-CASES "); ok {
			if err := json.Unmarshal([]byte(data), &manifest); err != nil {
				t.Fatal(err)
			}
		}
	}
	var ours []harness.Case
	for _, c := range manifest {
		if c.Package == gateProofPackage {
			ours = append(ours, c)
		}
	}
	if !reflect.DeepEqual(ours, gateProofCases()) {
		t.Fatalf("manifest cases for %s:\n%+v\nadapter copy:\n%+v", gateProofPackage, ours, gateProofCases())
	}
}
