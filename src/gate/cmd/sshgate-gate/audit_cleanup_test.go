package main

import (
	"context"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

func TestGateAuditCleanupError(t *testing.T) {
	original := executeCommand
	defer func() { executeCommand = original }()
	for _, exit := range []int{0, 23} {
		dir := t.TempDir()
		withGateDir(t, dir)
		executeCommand = func(_ context.Context, _ string, opts gate.ExecOpts) (gate.ExecResult, error) {
			if opts.Confine == nil {
				t.Fatal("confined execution lost")
			}
			return gate.ExecResult{ExitCode: exit, CleanupError: "descendant cleanup exceeded deadline"}, nil
		}
		code := execAndAudit(newAuditLogger(), "true", "read", "unsigned", false, execPlan{confine: &confine.Spec{Profile: confine.ProfileROv1}})
		records := auditRecords(t, dir)
		if code != exit || len(records) != 1 || records[0]["exit_code"] != float64(exit) || records[0]["cleanup_error"] != "descendant cleanup exceeded deadline" || records[0]["approval_status"] == "denied" {
			t.Fatalf("cleanup exit %d, audit %#v", code, records)
		}
	}
}
