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
				p := newProof(t, "L-SC-SWEEP")
				probe := buildProbe(t)
				var args, expected []string
				for _, row := range syscallTable {
					if row.action == "deny" || row.action == "enosys" {
						args = append(args, fmt.Sprintf("%s:%d", row.name, row.nr))
						expected = append(expected, row.name)
					}
				}
				result := runJailed(t, p, Spec{Profile: ProfileROv1, ForceABI: cfg.abi, Net: true}, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "sweep", Command: probe + " sc-sweep " + strings.Join(args, " "), Validate: func(stdout, stderr string, exit int) error {
					if stderr != "" || exit != 0 {
						return fmt.Errorf("sweep status %d stderr %q", exit, stderr)
					}
					lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
					if len(lines) != len(expected) {
						return fmt.Errorf("sweep rows %d want %d", len(lines), len(expected))
					}
					for i, name := range expected {
						key, value, ok := strings.Cut(lines[i], "=")
						errno, err := strconv.Atoi(value)
						if !ok || key != name || err != nil || errno < 0 || errno > 4095 {
							return fmt.Errorf("invalid sweep row %q", lines[i])
						}
					}
					return nil
				}}}})
				p.Jailed("sweep", result)
				output := result.stdout
				for _, row := range syscallTable {
					if row.action != "deny" && row.action != "enosys" {
						continue
					}
					want := 1
					if row.action == "enosys" {
						want = 38
					}
					if !strings.Contains(output, fmt.Sprintf("%s=%d\n", row.name, want)) {
						unexpected(t, "%s expected %d: %s", row.name, want, output)
					}
				}
				controlArgs := append([]string{"-Urmpf", probe, "sc-sweep"}, args...)
				controlOutput, err := exec.Command("unshare", controlArgs...).CombinedOutput()
				mutationSetup(t, err)
				observed := map[string]int{}
				for _, line := range strings.Split(strings.TrimSpace(string(controlOutput)), "\n") {
					name, value, ok := strings.Cut(line, "=")
					errno, err := strconv.Atoi(value)
					if !ok || err != nil || errno < 0 || errno > 4095 {
						t.Fatalf("SETUP: malformed sweep control %q", line)
					}
					if _, duplicate := observed[name]; duplicate {
						t.Fatalf("SETUP: duplicate sweep control %s", name)
					}
					observed[name] = errno
				}
				if len(observed) != len(expected) {
					t.Fatalf("SETUP: sweep control rows %d want %d", len(observed), len(expected))
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
				p.Control("distinction", ControlResult{Valid: !t.Failed(), Detail: "complete per-row namespace control; initial-capability and absent-kernel rows distinguished by BPF unit cases"})
				p.Finish()
			})
		})
	}
}
