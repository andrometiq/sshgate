package confine

import (
	"errors"
	"syscall"
	"testing"
)

func TestProofSetupAbortRequiresExactEvidence(t *testing.T) {
	plan := RunPlan{Mode: SetupAbort, Stage: "selfcheck", Errno: syscall.EPERM}
	good := JailedResult{jailResult: jailResult{exit: ExitSetupFailed, setupErr: &SetupError{Stage: "selfcheck", Errno: syscall.EPERM}}}
	for _, tc := range []struct {
		name   string
		change func(*JailedResult)
		valid  bool
	}{
		{"exact", func(*JailedResult) {}, true},
		{"wrong-stage", func(r *JailedResult) { r.setupErr = &SetupError{Stage: "exec", Errno: syscall.EPERM} }, false},
		{"wrong-errno", func(r *JailedResult) { r.setupErr = &SetupError{Stage: "selfcheck", Errno: syscall.EIO} }, false},
		{"command-output", func(r *JailedResult) { r.stdout = "ran" }, false},
		{"wrong-exit", func(r *JailedResult) { r.exit = 0 }, false},
		{"executed", func(r *JailedResult) { r.setupErr = nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := good
			tc.change(&result)
			if err := validateSetupAbort(result, plan); (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}
func TestProofSilentExecFailureRequiresExactEvidence(t *testing.T) {
	good := JailedResult{jailResult: jailResult{exit: ExitSetupFailed}, Worker: WorkerStatus{Known: true, Exited: true, Code: ExitSetupFailed}}
	for _, tc := range []struct {
		name   string
		change func(*JailedResult)
		valid  bool
	}{
		{"exact", func(*JailedResult) {}, true},
		{"reported-failure", func(r *JailedResult) { r.setupErr = &SetupError{Stage: "exec", Errno: syscall.ENOENT} }, false},
		{"command-output", func(r *JailedResult) { r.stdout = "COMMAND_RAN" }, false},
		{"diagnostic", func(r *JailedResult) { r.stderr = "sh: not found\n" }, false},
		{"command-exit", func(r *JailedResult) { r.Worker.Code = 0 }, false},
		{"worker-signal", func(r *JailedResult) { r.Worker = WorkerStatus{Known: true, Signal: syscall.SIGKILL} }, false},
		{"worker-unknown", func(r *JailedResult) { r.Worker = WorkerStatus{Unavailable: "no W record"} }, false},
		{"shim-exit", func(r *JailedResult) { r.exit = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := good
			tc.change(&result)
			if err := validateSilentExecFailure(result); (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}
func TestProofCancellationUsesDeliveredSignalAndWorkerPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		worker    WorkerStatus
		delivered bool
		want      int
		cleanup   error
		valid     bool
	}{
		{"unavailable", WorkerStatus{Unavailable: "shim killed"}, true, 143, nil, true},
		{"known-exit", WorkerStatus{Known: true, Exited: true, Code: 23}, true, 23, nil, true},
		{"known-signal", WorkerStatus{Known: true, Signal: syscall.SIGSEGV}, true, 139, nil, true},
		{"request-not-delivered", WorkerStatus{}, false, 143, nil, false},
		{"wrong-precedence", WorkerStatus{Known: true, Exited: true, Code: 23}, true, 143, nil, false},
		{"surviving-descendant", WorkerStatus{}, true, 143, errors.New("survived"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := JailedResult{jailResult: jailResult{exit: -1}, ShimExit: -1, Worker: tc.worker, Cancelled: tc.delivered}
			plan := RunPlan{ExpectExit: tc.want, CleanupEvidence: func() error { return tc.cleanup }}
			err := validateCancellation(&result, plan)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
			if err == nil && (result.exit != tc.want || result.ShimExit != -1) {
				t.Fatalf("precedence/status changed: %+v", result)
			}
		})
	}
}
func TestProofUnframedRequiresExactEvidence(t *testing.T) {
	plan := RunPlan{Validate: func(stdout, _ string, _ int) error {
		if stdout != "report\n" {
			return errors.New("report")
		}
		return nil
	}}
	good := JailedResult{jailResult: jailResult{stdout: "report\n"}, Worker: WorkerStatus{Known: true, Exited: true}}
	for _, tc := range []struct {
		name   string
		change func(*JailedResult, *RunPlan)
		valid  bool
	}{
		{"exact", func(*JailedResult, *RunPlan) {}, true},
		{"report", func(r *JailedResult, _ *RunPlan) { r.stdout = "other\n" }, false},
		{"no-validator", func(_ *JailedResult, p *RunPlan) { p.Validate = nil }, false},
		{"diagnostic", func(r *JailedResult, _ *RunPlan) { r.stderr = "x" }, false},
		{"setup", func(r *JailedResult, _ *RunPlan) { r.setupErr = &SetupError{Stage: "report"} }, false},
		{"shim-exit", func(r *JailedResult, _ *RunPlan) { r.ShimExit = 1 }, false},
		{"worker-exit", func(r *JailedResult, _ *RunPlan) { r.Worker.Code = 1 }, false},
		{"worker-signal", func(r *JailedResult, _ *RunPlan) { r.Worker = WorkerStatus{Known: true, Signal: syscall.SIGKILL} }, false},
		{"worker-unknown", func(r *JailedResult, _ *RunPlan) { r.Worker = WorkerStatus{Unavailable: "no W record"} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, run := good, plan
			tc.change(&result, &run)
			if err := validateUnframed(result, run); (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}
func TestProofShimSignalRequiresExactEvidence(t *testing.T) {
	plan := RunPlan{Validate: func(stdout, _ string, _ int) error {
		if stdout != "READY\n" {
			return errors.New("report")
		}
		return nil
	}}
	unreaped := WorkerStatus{Unavailable: "cancelled before worker reap"}
	for _, tc := range []struct {
		name   string
		worker WorkerStatus
		shim   int
		stdout string
		stderr string
		want   int
		valid  bool
	}{
		{"unreaped", unreaped, 143, "READY\n", "", 143, true},
		{"worker-killed", WorkerStatus{Known: true, Signal: syscall.SIGKILL}, 143, "READY\n", "", 137, true},
		{"worker-exited", WorkerStatus{Known: true, Exited: true}, 143, "READY\n", "", 0, false},
		{"worker-other-signal", WorkerStatus{Known: true, Signal: syscall.SIGTERM}, 143, "READY\n", "", 0, false},
		{"worker-other-unavailable", WorkerStatus{Unavailable: "no W record"}, 143, "READY\n", "", 0, false},
		{"shim-exited", unreaped, 0, "READY\n", "", 0, false},
		{"report", unreaped, 143, "", "", 0, false},
		{"diagnostic", unreaped, 143, "READY\n", "x", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := JailedResult{jailResult: jailResult{stdout: tc.stdout, stderr: tc.stderr}, Worker: tc.worker, ShimExit: tc.shim}
			err := validateShimSignal(&result, plan)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
			if err == nil && result.exit != tc.want {
				t.Fatalf("exit = %d, want %d", result.exit, tc.want)
			}
		})
	}
	result := JailedResult{jailResult: jailResult{stdout: "READY\n"}, Worker: unreaped, ShimExit: 143}
	if validateShimSignal(&result, RunPlan{}) == nil {
		t.Fatal("shim signal accepted without a report validator")
	}
}
