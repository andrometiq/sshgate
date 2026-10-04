package confine

import (
	"errors"
	"os"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func statusRegistry() []prot {
	leg := harness.Leg{Name: "U-StatusProtocol", Package: "./src/gate/confine", Names: map[string]string{"native": "TestStatusMutation/native/U-StatusProtocol", "abi1": "TestStatusMutation/abi1/U-StatusProtocol"}, Markers: []string{"MUTATION-EFFECT status"}}
	return []prot{{ID: "P-STATUS", Site: "Jailed.Status report validation", Class: "single", DirectLeg: leg.Name, MutationSets: []harness.MutationSet{{IDs: []string{"P-STATUS"}, Legs: []harness.Leg{leg}}}}}
}

func TestStatusMutation(t *testing.T) {
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("U-StatusProtocol", func(t *testing.T) {
				p := newProof(t, "U-StatusProtocol")
				accepted := false
				for _, report := range []string{"", "X", "Fselfcheck:1\n", "I{}\nX", "I{\"profile\":\"ro-v1\",\"abi\":1,\"net\":false,\"lane2\":false}\nXFexec:2\n"} {
					reader, writer, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					if _, err = writer.WriteString(report); err != nil {
						t.Fatal(err)
					}
					if err = writer.Close(); err != nil {
						t.Fatal(err)
					}
					j := Jailed{statusR: reader, spec: Spec{Profile: ProfileROv1}}
					_, err = j.Status()
					if err == nil {
						accepted = true
						continue
					}
					var setup *SetupError
					if !errors.As(err, &setup) {
						t.Fatalf("unexpected status error: %v", err)
					}
				}
				mutationEffect(t, "U-StatusProtocol", "status", accepted)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "each malformed status rejected or recorded as mutation"})
				p.Finish()
			})
		})
	}
}
