package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestRun_WriteToReadOnlyServer_NoSign asserts that a write aimed at a
// server registered read-only short-circuits BEFORE Sign is called — no
// Telegram approval tap is wasted on a write the gate is guaranteed to
// reject (audit item A).
func TestRun_WriteToReadOnlyServer_NoSign(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "ro", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true,
	})
	sign := &fakeSign{}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "ro", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error writing to a read-only server, got nil")
	}
	// #26-core: the structured Denial names the class + remedy.
	if out.Denial == nil {
		t.Fatal("out.Denial is nil; want a structured read_only_server denial")
	}
	if out.Denial.VerdictClass != tools.VerdictReadOnlyServer {
		t.Errorf("VerdictClass=%q; want %q", out.Denial.VerdictClass, tools.VerdictReadOnlyServer)
	}
	if out.Denial.RequiredAction != tools.ActionRephraseAsRead {
		t.Errorf("RequiredAction=%q; want %q", out.Denial.RequiredAction, tools.ActionRephraseAsRead)
	}
	if out.Denial.Retryable {
		t.Error("Retryable=true; want false for read_only_server")
	}
	if sign.signCalled {
		t.Error("Sign was called for a write to a read-only server; must short-circuit before signing")
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called for a write to a read-only server")
	}
	if !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), "/sshgate:setup") {
		t.Errorf("error %q is not the actionable read-only upgrade guidance", err.Error())
	}
	if !strings.Contains(err.Error(), "ro") {
		t.Errorf("error %q should name the alias", err.Error())
	}
}

// TestRunBatch_WriteToReadOnlyServer_NoSign is the batch equivalent: a
// batch containing a write against a read-only server must refuse before
// Sign is called.
func TestRunBatch_WriteToReadOnlyServer_NoSign(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "ro", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true,
	})
	sign := &batchSign{}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "ro",
		Commands: []string{"df -h", "rm /tmp/x"},
	})
	if err == nil {
		t.Fatal("expected error: batch with a write to a read-only server, got nil")
	}
	// #26-core: batch also carries the structured Denial on the error path.
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictReadOnlyServer {
		t.Errorf("out.Denial=%+v; want read_only_server", out.Denial)
	}
	if sign.calls != 0 {
		t.Errorf("Sign called %d times for a write to a read-only server; want 0", sign.calls)
	}
	if len(ssh.calls) != 0 {
		t.Errorf("SSH called %v for a write to a read-only server; want none", ssh.calls)
	}
	if !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), "/sshgate:setup") {
		t.Errorf("error %q is not the actionable read-only upgrade guidance", err.Error())
	}
}

// TestRunBatch_AllReadsToReadOnlyServer_OK confirms that reads against a
// read-only server are unaffected — the short-circuit only fires when the
// batch contains a write.
func TestRunBatch_AllReadsToReadOnlyServer_OK(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "ro", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true,
	})
	sign := &batchSign{}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "ro",
		Commands: []string{"df -h", "uptime"},
	})
	if err != nil {
		t.Fatalf("RunBatch (all reads to read-only server): %v", err)
	}
	if sign.calls != 0 {
		t.Errorf("Sign called %d times for all-reads batch; want 0", sign.calls)
	}
	if len(out.Results) != 2 {
		t.Fatalf("Results=%d; want 2", len(out.Results))
	}
}

// TestRun_WriteMissingKey_GivesSetupGuidance asserts the write path runs
// checkKeyReady up front: when the SSH key file is absent, the user gets
// "/sshgate:setup" guidance and Sign is never solicited (audit item C).
func TestRun_WriteMissingKey_GivesSetupGuidance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ssh", "sshgate_ed25519") // does not exist

	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh, KeyPath: keyPath}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error when SSH key is missing on a write, got nil")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Errorf("error %q does not mention setup — not actionable for a fresh user", err.Error())
	}
	// #26-core: missing key pre-setup → no_signer_configured / escalate.
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictNoSignerConfigured {
		t.Errorf("out.Denial=%+v; want no_signer_configured", out.Denial)
	}
	if sign.signCalled {
		t.Error("Sign was solicited before the missing-key check fired")
	}
}

// TestRunBatch_WriteMissingKey_GivesSetupGuidance is the batch
// equivalent of the missing-key pre-flight check.
func TestRunBatch_WriteMissingKey_GivesSetupGuidance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ssh", "sshgate_ed25519") // does not exist

	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &batchSign{}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh, KeyPath: keyPath}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/x"},
	})
	if err == nil {
		t.Fatal("expected error when SSH key is missing on a batch write, got nil")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Errorf("error %q does not mention setup", err.Error())
	}
	// #26-core: batch missing key pre-setup → no_signer_configured.
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictNoSignerConfigured {
		t.Errorf("out.Denial=%+v; want no_signer_configured", out.Denial)
	}
	if sign.calls != 0 {
		t.Error("Sign was solicited before the missing-key check fired")
	}
}

// TestRunBatch_AllReadsMissingKey_NoPreflightBlock confirms checkKeyReady
// is gated on there being writes: an all-reads batch should reach the
// (fake) SSH layer even with a missing key, matching the write-only
// placement of the pre-flight check.
func TestRunBatch_AllReadsMissingKey_NoBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ssh", "sshgate_ed25519") // does not exist

	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &batchSign{}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh, KeyPath: keyPath}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"df -h"},
	})
	if err != nil {
		t.Fatalf("all-reads batch with missing key should not pre-flight block: %v", err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("Results=%d; want 1", len(out.Results))
	}
}
