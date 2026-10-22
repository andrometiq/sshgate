package confine

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

// TestProofResidualMeetsEvidenceContract: a per-lane residual finalizes only
// after the evidence Finish requires, prints one PROOF-RESIDUAL line and no
// markers; the legacy Residual-kind case is unchanged.
func TestProofResidualMeetsEvidenceContract(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode, diagnostic string
		pass             bool
	}{
		{"complete", "PROOF-RESIDUAL L-RESIDUAL-FIXTURE native R-L2-LOADER-ROUTE", true},
		{"legacy", "PROOF-RESIDUAL L-LEGACY-FIXTURE native R-NUMA-EFFECT", true},
		{"no-control", "unfinished obligation control:decision", false},
		{"no-jailed", "unfinished obligation jailed:run", false},
		{"no-observe", "unfinished obligation observe:absence", false},
		{"unconsumed", "unconsumed jailed evidence", false},
		{"other-lane", "undeclared residual R-L2-LOADER-ROUTE in native", false},
		{"wrong-code", "undeclared residual R-NUMA-EFFECT in native", false},
		{"marker", "invalid residual", false},
	} {
		t.Run(test.mode, func(t *testing.T) {
			command := exec.Command(executable, "-test.run=^TestProofResidualFixture$", "-test.v")
			command.Env = append(os.Environ(), "SSHGATE_PROOF_RESIDUAL="+test.mode)
			output, err := command.CombinedOutput()
			if (err == nil) != test.pass || !strings.Contains(string(output), test.diagnostic) {
				t.Fatalf("pass=%t want %t, missing %q:\n%s", err == nil, test.pass, test.diagnostic, output)
			}
			if strings.Contains(string(output), "PROOF-COMPLETE") || strings.Count(string(output), "PROOF-RESIDUAL") != map[bool]int{true: 1, false: 0}[test.pass] {
				t.Fatalf("wrong finalization lines:\n%s", output)
			}
		})
	}
}

// This runs only in a child so Fatal and Cleanup execute exactly as in a leg.
func TestProofResidualFixture(t *testing.T) {
	mode := os.Getenv("SSHGATE_PROOF_RESIDUAL")
	if mode == "" {
		return
	}
	if mode == "legacy" {
		beginProof(t, harness.Case{Name: "L-LEGACY-FIXTURE", Kind: "Residual", ABIs: []string{"native"}, Residuals: []string{"R-NUMA-EFFECT"}}).Residual("R-NUMA-EFFECT")
		return
	}
	c := harness.Case{Name: "L-RESIDUAL-FIXTURE", Kind: "Effect", Mode: "Execute", ABIs: []string{"native", "abi1"},
		Obligations: []string{"control:decision", "jailed:run", "observe:absence"}, Markers: []string{"EFFECT:write"},
		ResidualABIs: map[string]string{"native": "R-L2-LOADER-ROUTE"}}
	if mode == "other-lane" {
		c.ResidualABIs = map[string]string{"abi1": "R-L2-LOADER-ROUTE"}
	}
	p := beginProof(t, c)
	evidence := func() JailedResult {
		token := new(bool)
		p.executions = append(p.executions, token)
		return JailedResult{validated: true, owner: p, token: token}
	}
	if mode != "no-control" {
		p.Control("decision", ControlResult{Valid: true})
	}
	if mode != "no-jailed" {
		p.Jailed("run", evidence())
	}
	if mode == "unconsumed" {
		evidence()
	}
	if mode != "no-observe" {
		p.Observed("absence", Observation{Conclusive: true, Sealed: true, Valid: true})
	}
	if mode == "marker" {
		p.record("EFFECT", c.Name, "write")
	}
	code := "R-L2-LOADER-ROUTE"
	if mode == "wrong-code" {
		code = "R-NUMA-EFFECT"
	}
	p.Residual(code)
}
