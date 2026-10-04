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
