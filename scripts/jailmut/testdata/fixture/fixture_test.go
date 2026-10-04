package fixture

import (
	"os"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func TestFixture(t *testing.T) {
	mode := os.Getenv("JAILMUT_FIXTURE")
	t.Log("fixture parent setup complete")
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("L-RED", func(t *testing.T) {
				switch mode {
				case "panic":
					panic("fixture panic")
				case "timeout":
					time.Sleep(time.Minute)
				case "setup":
					t.Fatal("SETUP: fixture unavailable")
				case "pass":
					t.Logf("PROOF-COMPLETE L-RED %s markers=", abi)
					return
				case "missing":
					t.Error("assertion without marker")
					return
				case "skip":
					t.Skip("fixture skipped")
				}
				if mode == "marker-unfinalized" {
					t.Log("MUTATION-EFFECT L-RED write")
					return
				}
				if mode == "wrong-markers" {
					t.Logf("PROOF-COMPLETE L-RED %s markers=EFFECT:other", abi)
					return
				}
				t.Logf("PROOF-COMPLETE L-RED %s markers=EFFECT:write", abi)
				if mode == "marker-plain-failure" {
					t.Error("unrelated assertion failed")
				}
				if mode == "marker-setup" {
					t.Fatal("SETUP: required invariant failed after expected marker")
				}
				if mode == "marker-unexpected" {
					harness.Unexpected(t, "retained wall failed after expected marker")
				}
				if mode == "extra" {
					t.Logf("PROOF-COMPLETE L-RED %s markers=EFFECT:extra", abi)
				}
			})
			if mode == "sibling" {
				t.Run("L-OTHER", func(t *testing.T) { t.Error("unexpected sibling failure") })
			}
			if mode == "ancestor" {
				t.Run("other", func(t *testing.T) { t.Run("L-NONRED", func(t *testing.T) { t.Error("unexpected descendant failure") }) })
			}
		})
	}
}
