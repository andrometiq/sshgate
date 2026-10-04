//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"

	"golang.org/x/sys/unix"
)

func TestJailMatrixCredentials(t *testing.T) {
	for _, configuration := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(configuration.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: configuration.abi, Net: true}
			t.Run("L-NNP-LANDLOCK", func(t *testing.T) {
				p := newProof(t, "L-NNP-LANDLOCK")
				inherited, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
				mutationSetup(t, err)
				if inherited != 0 {
					t.Fatal("SETUP: inherited NoNewPrivs=1 makes removal of the NNP wall unobservable")
				}
				control := credentialNNPControl(t, p, spec)
				p.Control("intact", ControlResult{Valid: control.stdout == "CONTROL_RAN", Jailed: &control})
				plan := RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "exec", Command: "printf COMMAND_RAN", Outcomes: []OpOutcome{{Stdout: "COMMAND_RAN"}}}}}
				if jailmut.On("P-NNP") {
					plan = RunPlan{Mode: SetupAbort, Stage: "landlock", Errno: syscall.EPERM, Command: "printf COMMAND_RAN"}
				}
				result := runJailed(t, p, spec, plan)
				p.Jailed("attempt", result)
				mutationAbort(t, "L-NNP-LANDLOCK", "landlock", plan.Mode == SetupAbort)
				p.Finish()
			})
			t.Run("L-SELFCHECK-CREDS", func(t *testing.T) {
				p := newProof(t, "L-SELFCHECK-CREDS")
				plan := RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "credentials", Command: "cat /proc/self/status", Validate: validateCredentialReport}}}
				if jailmut.On("P-CAPS") && !jailmut.On("P-SELFCHECK-CREDS") {
					plan = RunPlan{Mode: SetupAbort, Stage: "selfcheck", Command: "cat /proc/self/status"}
				}
				result := runJailed(t, p, spec, plan)
				p.Jailed("credentials", result)
				mutationAbort(t, "L-SELFCHECK-CREDS", "selfcheck", plan.Mode == SetupAbort)
				mutationEffect(t, "L-SELFCHECK-CREDS", "credentials", plan.Mode == Execute && selfcheckCredentials(result.stdout, os.Getuid() == 0) != nil)
				p.Finish()
			})
			t.Run("L-SELFCHECK-LL", func(t *testing.T) {
				p := newProof(t, "L-SELFCHECK-LL")
				control := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}})
				p.Control("intact", ControlResult{Valid: control.stdout == "CONTROL_RAN", Jailed: &control})
				without := spec
				without.ForceABI = ForceNoLandlock
				plan := RunPlan{Mode: SetupAbort, Stage: "landlock", Errno: syscall.ENOSYS, Command: "printf COMMAND_RAN"}
				if jailmut.On("P-LL-REQUIRED") {
					plan.Stage, plan.Errno = "selfcheck", 0
				}
				if jailmut.On("P-LL-REQUIRED") && jailmut.On("P-SELFCHECK-LL") {
					plan = RunPlan{Mode: Execute, AcceptFactsABI0: true, Ops: []ProofOp{{Name: "exec", Command: "printf COMMAND_RAN", Outcomes: []OpOutcome{{Stdout: "COMMAND_RAN"}}}}}
				}
				result := runJailed(t, p, without, plan)
				p.Jailed("attempt", result)
				mutationEffect(t, "L-SELFCHECK-LL", "reached-exec", plan.Mode == Execute)
				p.Finish()
			})
			t.Run("L-SETUID", func(t *testing.T) {
				p := newProof(t, "L-SETUID")
				control, err := os.ReadFile("/proc/self/mountinfo")
				mutationSetup(t, err)
				entries, err := parseMountInfo(strings.NewReader(string(control)))
				mutationSetup(t, err)
				if len(entries) == 0 {
					t.Fatal("SETUP: empty control mountinfo")
				}
				t.Logf("control mount flags: %v", entries[0].opts)
				hasSuidMount := false
				for _, entry := range entries {
					hasSuidMount = hasSuidMount || !slices.Contains(entry.opts, "nosuid")
				}
				p.Control("mounts", ControlResult{Valid: hasSuidMount, Detail: "host mountinfo has a mount without nosuid"})
				result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "state", Command: "cat /proc/self/status && printf '\\nMOUNTS\\n' && cat /proc/self/mountinfo", Validate: func(stdout, stderr string, exit int) error {
					parts := strings.SplitN(stdout, "\nMOUNTS\n", 2)
					if len(parts) != 2 {
						return fmt.Errorf("missing mount report")
					}
					if err := validateCredentialReport(parts[0], stderr, exit); err != nil {
						return err
					}
					mounts, err := parseMountInfo(strings.NewReader(parts[1]))
					if err != nil || len(mounts) == 0 {
						return fmt.Errorf("invalid mount report: %v", err)
					}
					return nil
				}}}})
				p.Jailed("state", result)
				if result.setupErr != nil || result.exit != 0 {
					t.Fatalf("SETUP: %+v", result)
				}
				parts := strings.SplitN(result.stdout, "\nMOUNTS\n", 2)
				if len(parts) != 2 {
					unexpected(t, "missing mount report")
					t.FailNow()
				}
				if !strings.Contains(parts[0], "NoNewPrivs:\t1\n") {
					unexpected(t, "NoNewPrivs is not 1")
					t.FailNow()
				}
				entries, err = parseMountInfo(strings.NewReader(parts[1]))
				mutationSetup(t, err)
				if len(entries) == 0 {
					unexpected(t, "empty jailed mountinfo")
					t.FailNow()
				}
				missing := false
				for _, entry := range entries {
					missing = missing || !slices.Contains(entry.opts, "nosuid")
				}
				mutationEffect(t, "L-SETUID", "nosuid-state", missing)
				p.Finish()
			})
		})
	}
}

func validateCredentialReport(stdout, stderr string, exit int) error {
	if exit != 0 || stderr != "" || !strings.HasSuffix(stdout, "\n") {
		return fmt.Errorf("incomplete credential report: exit=%d stderr=%q", exit, stderr)
	}
	required := map[string]int{"CapInh": 16, "CapPrm": 16, "CapEff": 16, "CapBnd": 16, "CapAmb": 16, "NoNewPrivs": 10, "Seccomp": 10, "Seccomp_filters": 10}
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		key, raw, ok := strings.Cut(line, ":")
		base, needed := required[key]
		if !needed {
			continue
		}
		if !ok || seen[key] {
			return fmt.Errorf("duplicate or malformed field %s", key)
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(raw), base, 64); err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		seen[key] = true
	}
	if len(seen) != len(required) {
		return fmt.Errorf("missing credential fields")
	}
	return nil
}
