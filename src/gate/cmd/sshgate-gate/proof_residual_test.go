package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

// TestGateProofResidual: a declared residual in its lane prints exactly one
// PROOF-RESIDUAL line; outside its lane, with an obligation missing, or after
// a marker, it fails SETUP and prints none.
func TestGateProofResidual(t *testing.T) {
	for _, test := range []struct {
		mode, diagnostic string
		pass             bool
	}{
		{"complete", "PROOF-RESIDUAL G-RESIDUAL-FIXTURE abi1 R-L2-SOCKET-BELOW-ABI9", true},
		{"other-lane", "undeclared residual R-L2-SOCKET-BELOW-ABI9 in native", false},
		{"no-observe", "unfinished obligation observe:listener", false},
		{"marker", "undeclared residual", false},
	} {
		t.Run(test.mode, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestGateProofResidualFixture$", "-test.v", "-test.count=1")
			command.Env = append(os.Environ(), "SSHGATE_GATE_PROOF_RESIDUAL="+test.mode)
			output, err := command.CombinedOutput()
			lines := strings.Count(string(output), "PROOF-RESIDUAL G-")
			if (err == nil) != test.pass || !strings.Contains(string(output), test.diagnostic) || lines != map[bool]int{true: 1, false: 0}[test.pass] {
				t.Fatalf("pass=%t want %t, missing %q or %d residual lines:\n%s", err == nil, test.pass, test.diagnostic, lines, output)
			}
		})
	}
}

// This runs only in a child so Fatal and Cleanup execute exactly as in a leg.
func TestGateProofResidualFixture(t *testing.T) {
	mode := os.Getenv("SSHGATE_GATE_PROOF_RESIDUAL")
	if mode == "" {
		return
	}
	abi := "abi1"
	if mode == "other-lane" {
		abi = "native"
	}
	c := harness.Case{Name: "G-RESIDUAL-FIXTURE", Kind: "Effect", Mode: "Execute", ABIs: []string{"native", "abi1"},
		Obligations: []string{"control:connect", "jailed:lane2", "observe:listener"}, Markers: []string{"EFFECT:connected"},
		ResidualABIs: harness.ResidualBelowABI("R-L2-SOCKET-BELOW-ABI9", 10, 9)}
	if err := harness.ValidateCases([]harness.Case{c}); err != nil {
		t.Fatal(err)
	}
	p := &gateProof{t: t, abi: abi, caseDef: c, done: map[string]bool{}}
	t.Cleanup(func() {
		if !p.finished {
			t.Error("SETUP: proof not finished")
		}
	})
	p.Control("connect", true)
	p.Jailed("lane2", true)
	if mode != "no-observe" {
		p.Observed("listener", true)
	}
	if mode == "marker" {
		p.Effect("connected", true)
	}
	p.Residual("R-L2-SOCKET-BELOW-ABI9")
}
