//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestJailMatrixSyscallSweep(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			t.Run("L-SC-SWEEP", func(t *testing.T) {
				probe := buildProbe(t)
				var args, expected []string
				for _, row := range syscallTable {
					if row.action == "deny" || row.action == "enosys" {
						args = append(args, fmt.Sprintf("%s:%d", row.name, row.nr))
						expected = append(expected, row.name)
					}
				}
				output := requireProbeOutputMode(t, runP12(t, Spec{Profile: ProfileROv1, ForceABI: cfg.abi, Net: true}, probe+" sc-sweep "+strings.Join(args, " "), nil), probeExitObservations, expected...)
				for _, row := range syscallTable {
					if row.action != "deny" && row.action != "enosys" {
						continue
					}
					want := 1
					if row.action == "enosys" {
						want = 38
					}
					if !strings.Contains(output, fmt.Sprintf("%s=%d\n", row.name, want)) {
						t.Errorf("%s expected %d: %s", row.name, want, output)
					}
				}
				controlArgs := append([]string{"-Urmpf", probe, "sc-sweep"}, args...)
				controlOutput, err := exec.Command("unshare", controlArgs...).CombinedOutput()
				mutationSetup(t, err)
				observed := map[string]int{}
				for _, line := range strings.Split(strings.TrimSpace(string(controlOutput)), "\n") {
					name, value, ok := strings.Cut(line, "=")
					errno, err := strconv.Atoi(value)
					if !ok || err != nil {
						t.Fatalf("SETUP: malformed sweep control %q", line)
					}
					if _, duplicate := observed[name]; duplicate {
						t.Fatalf("SETUP: duplicate sweep control %s", name)
					}
					observed[name] = errno
				}
				// These literal rows require initial-userns capabilities before argument checks.
				initialCaps := map[string]bool{"KEXEC_LOAD": true, "KEXEC_FILE_LOAD": true, "INIT_MODULE": true, "FINIT_MODULE": true, "DELETE_MODULE": true, "SWAPON": true, "SWAPOFF": true, "SETTIMEOFDAY": true, "OPEN_BY_HANDLE_AT": true}
				for _, row := range syscallTable {
					if row.action != "deny" && row.action != "enosys" {
						continue
					}
					errno, ok := observed[row.name]
					if !ok {
						t.Fatalf("SETUP: missing %s control", row.name)
					}
					if initialCaps[row.name] {
						t.Logf("initial-userns-cap control %s=%d; exhaustive BPF evaluator supplies distinction", row.name, errno)
						continue
					}
					if row.action == "enosys" && errno == 38 {
						t.Logf("kernel-absent control %s=ENOSYS; exhaustive BPF evaluator supplies distinction", row.name)
						continue
					}
					want := 1
					if row.action == "enosys" {
						want = 38
					}
					if errno == want {
						t.Errorf("SETUP: indistinguishable %s control errno %d", row.name, errno)
					}
				}

			})
		})
	}
}
