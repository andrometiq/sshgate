//go:build linux && jail_e2e

package confine

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func credentialNNPControl(t *testing.T, p *proof, spec Spec) JailedResult {
	return runJailed(t, p, spec, RunPlan{Mode: Execute, Configure: func(j *Jailed) {
		original := append([]string(nil), j.Cmd.Args...)
		j.Cmd.Args = []string{original[0], "-test.run=^TestCredentialNNPEntrypoint$", "--", original[1], original[2]}
	}, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}})
}

func TestCredentialNNPEntrypoint(t *testing.T) {
	if len(os.Args) != 5 || os.Args[2] != "--" || os.Args[3] != SentinelShim {
		return
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// Exec on the same thread; the shim runtime's threads all inherit NNP.
	if err := syscall.Exec("/proc/self/exe", []string{os.Args[0], os.Args[3], os.Args[4]}, os.Environ()); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialProofReport(t *testing.T) {
	report := "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
	if err := validateCredentialReport(report, "", 0); err != nil {
		t.Fatal(err)
	}
	for _, report := range []string{strings.TrimSuffix(report, "\n"), strings.Replace(report, "Seccomp_filters:\t1\n", "", 1), report + "CapEff:\t0\n", strings.Replace(report, "CapBnd:\t0", "CapBnd:\tbad-hex", 1)} {
		if err := validateCredentialReport(report, "", 0); err == nil {
			t.Fatalf("accepted malformed report %q", report)
		}
	}
	if validateCredentialReport(report, "unexpected", 0) == nil || validateCredentialReport(report, "", 1) == nil {
		t.Fatal("accepted stderr or failed command")
	}
}
