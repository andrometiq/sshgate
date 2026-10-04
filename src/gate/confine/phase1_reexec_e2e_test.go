//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func TestPhase1ReexecFixture(t *testing.T) {
	mode := os.Getenv("SSHGATE_REEXEC_FIXTURE")
	if mode == "" {
		return
	}
	t.Run("L-RED", func(t *testing.T) {
		if os.Getenv("SSHGATE_REEXEC_CHILD") == "1" {
			t.Error("MUTATION-EFFECT L-RED effect")
			switch mode {
			case "extra":
				t.Error("MUTATION-EFFECT L-RED extra")
			case "unexpected":
				unexpected(t, "retained wall failed")
			case "incomplete":
				os.Exit(1)
			case "crash":
				panic("fixture crash")
			}
			return
		}
		pattern := "^TestPhase1ReexecFixture$/^L-RED$"
		if mode == "sibling" {
			pattern = "^TestPhase1ReexecFixture$"
		}
		child := exec.Command(os.Args[0], "-test.v", "-test.run="+pattern)
		child.Env = append(os.Environ(), "SSHGATE_REEXEC_CHILD=1")
		output, err := child.CombinedOutput()
		fmt.Print(string(output))
		propagateFixtureFailure(t, output, err)
	})
	if mode == "sibling" && os.Getenv("SSHGATE_REEXEC_CHILD") == "1" {
		t.Run("L-OTHER", func(t *testing.T) { t.Error("unrelated failure") })
	}
}

func TestPhase1ReexecFailurePropagation(t *testing.T) {
	for _, mode := range []string{"expected", "unexpected", "incomplete", "crash", "sibling", "extra"} {
		t.Run(mode, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.v=test2json", "-test.run=^TestPhase1ReexecFixture$")
			command.Env = append(os.Environ(), "SSHGATE_REEXEC_FIXTURE="+mode)
			output, runErr := command.CombinedOutput()
			convert := exec.Command("go", "tool", "test2json", "-p", "fixture")
			convert.Stdin = bytes.NewReader(output)
			stream, err := convert.Output()
			if err != nil {
				t.Fatalf("test2json: %v", err)
			}
			leg := harness.Leg{Name: "L-RED", Names: map[string]string{"native": "TestPhase1ReexecFixture/L-RED"}, Markers: []string{"MUTATION-EFFECT effect"}}
			err = harness.Judge(bytes.NewReader(stream), "", exitCodeOf(runErr), []harness.Leg{leg}, "native")
			if mode == "expected" {
				if err != nil {
					t.Fatalf("completed marker failure rejected: %v\n%s", err, output)
				}
			} else if err == nil || mode != "extra" && !strings.Contains(err.Error(), "infrastructure:") {
				t.Fatalf("%s child accepted: %v\n%s", mode, err, output)
			}
		})
	}
}
