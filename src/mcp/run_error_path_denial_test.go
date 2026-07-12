package mcp

import (
	"context"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// readOnlyRegistry builds a one-entry registry whose server is Tier-1
// read-only, so a write short-circuits into a structured Denial.
func readOnlyRegistry(t *testing.T, alias string) *registry.Servers {
	t.Helper()
	r, err := registry.New(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(alias, registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRunHandler_DenialSurvivesErrorPath is the #26-core §4 regression: before
// this fix, runHandler dropped the structured RunOutput on the Go-error path
// (SDK SetError discards the 2nd return when err!=nil). A recognised refusal
// must now come back as IsError=true AND carry a non-nil structured Denial.
func TestRunHandler_DenialSurvivesErrorPath(t *testing.T) {
	runner := &tools.Runner{Servers: readOnlyRegistry(t, "ro"), Sign: &hookFakeSign{}, SSH: &hookFakeSSH{}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0)}

	res, out, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "ro", Command: "rm /tmp/x"})
	// The handler now returns err=nil and hands the SDK a fully-formed error
	// result so the structured `out` (2nd return) is NOT discarded.
	if err != nil {
		t.Fatalf("handler err = %v; want nil (the refusal rides in the result, not the Go error)", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("res=%+v; want a non-nil IsError result", res)
	}
	if len(res.Content) == 0 {
		t.Error("res.Content is empty; want the prose error text for text-only clients")
	}
	if out.Denial == nil {
		t.Fatal("out.Denial is nil on the error path; the structured denial was LOST (regression)")
	}
	if out.Denial.VerdictClass != tools.VerdictReadOnlyServer {
		t.Errorf("VerdictClass=%q; want read_only_server", out.Denial.VerdictClass)
	}
}

// TestRunHandler_InfraErrorStaysTextOnly confirms the complement: a true infra
// error (unknown alias — not a verdict) keeps the current text-only IsError
// path with NO structured Denial.
func TestRunHandler_InfraErrorStaysTextOnly(t *testing.T) {
	runner := &tools.Runner{Servers: readOnlyRegistry(t, "ro"), Sign: &hookFakeSign{}, SSH: &hookFakeSSH{}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0)}

	res, out, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "nope", Command: "ls"})
	if err == nil {
		t.Fatal("expected a Go error for an unknown alias (infra error)")
	}
	if res != nil {
		t.Errorf("res=%+v; want nil (SDK builds the error result for a plain infra error)", res)
	}
	if out.Denial != nil {
		t.Errorf("out.Denial=%+v; an infra error must carry NO structured denial", out.Denial)
	}
}

// TestRunBatchHandler_DenialSurvivesErrorPath is the batch mirror: a batch
// write to a read-only host returns a Go error from RunBatch, and the handler
// must preserve the structured Denial rather than dropping it.
func TestRunBatchHandler_DenialSurvivesErrorPath(t *testing.T) {
	runner := &tools.Runner{Servers: readOnlyRegistry(t, "ro"), Sign: &hookFakeSign{}, SSH: &hookFakeSSH{}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0)}

	res, out, err := srv.runBatchHandler(context.Background(), nil, tools.RunBatchInput{
		Alias:    "ro",
		Commands: []string{"df -h", "rm /tmp/x"},
	})
	if err != nil {
		t.Fatalf("handler err = %v; want nil (refusal rides in the result)", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("res=%+v; want a non-nil IsError result", res)
	}
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictReadOnlyServer {
		t.Fatalf("out.Denial=%+v; want read_only_server (regression if nil)", out.Denial)
	}
}
