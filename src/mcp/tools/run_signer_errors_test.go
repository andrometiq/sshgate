package tools_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestRun_WritePermission_ActionableAndSentinel asserts that a signer
// permission error surfaces the actionable "log out and back in"
// guidance AND preserves the ErrSignerPermission sentinel for the MCP
// layer (audit item B).
func TestRun_WritePermission_ActionableAndSentinel(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrSignerPermission}
	ssh := &fakeSSH{}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           sign,
		SSH:            ssh,
		SignerSockPath: "/run/sshgatesigner/sign.sock",
	}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on signer permission denial")
	}
	if !errors.Is(err, signpkg.ErrSignerPermission) {
		t.Errorf("err = %v; want wrap of ErrSignerPermission", err)
	}
	// #26-core: structured Denial mirrors the sentinel (escalate, not retry).
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictSignerPermission {
		t.Errorf("out.Denial=%+v; want signer_permission", out.Denial)
	}
	if out.Denial != nil && out.Denial.RequiredAction != tools.ActionEscalateToHuman {
		t.Errorf("RequiredAction=%q; want escalate_to_human", out.Denial.RequiredAction)
	}
	if !strings.Contains(err.Error(), "sshgatesigner group") || !strings.Contains(err.Error(), "Log out") {
		t.Errorf("error %q is not the actionable group/relaunch guidance", err.Error())
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called despite signer permission failure")
	}
}

// TestRun_WriteUnreachable_SocketPresent_DaemonDownMessage asserts that
// when the signer socket file IS present but the dial is unreachable,
// the error points at the daemon (systemctl/journalctl), not the
// Tier-1 setup path (audit item D).
func TestRun_WriteUnreachable_SocketPresent_DaemonDownMessage(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})

	// Create a real file at SignerSockPath so signerSocketPresent() is true.
	dir := t.TempDir()
	sock := filepath.Join(dir, "sign.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	sign := &fakeSign{err: signpkg.ErrUnreachable}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh, SignerSockPath: sock}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on unreachable signer")
	}
	if !errors.Is(err, signpkg.ErrUnreachable) {
		t.Errorf("err = %v; want wrap of ErrUnreachable", err)
	}
	if !strings.Contains(err.Error(), "systemctl status sshgate-signer-telegram") {
		t.Errorf("error %q should point at the daemon (socket present, unreachable)", err.Error())
	}
	// #26-core: socket present + unreachable → signer_unreachable (daemon down).
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictSignerUnreachable {
		t.Errorf("out.Denial=%+v; want signer_unreachable", out.Denial)
	}
	if strings.Contains(err.Error(), "Tier-1") {
		t.Errorf("error %q should NOT be the Tier-1 message when the socket is present", err.Error())
	}
}

// TestRun_WriteUnreachable_SocketAbsent_Tier1Message asserts the
// no-socket case yields the Tier-1 "run /sshgate:setup" guidance.
func TestRun_WriteUnreachable_SocketAbsent_Tier1Message(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrUnreachable}
	ssh := &fakeSSH{}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           sign,
		SSH:            ssh,
		SignerSockPath: filepath.Join(t.TempDir(), "absent.sock"), // never created
	}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on unreachable signer")
	}
	if !errors.Is(err, signpkg.ErrUnreachable) {
		t.Errorf("err = %v; want wrap of ErrUnreachable", err)
	}
	if !strings.Contains(err.Error(), "Tier-1") || !strings.Contains(err.Error(), "/sshgate:setup") {
		t.Errorf("error %q should be the Tier-1 setup guidance when the socket is absent", err.Error())
	}
	// #26-core: socket absent + unreachable → no_signer_configured (Tier-1).
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictNoSignerConfigured {
		t.Errorf("out.Denial=%+v; want no_signer_configured", out.Denial)
	}
}

// TestRunBatch_WritePermission_Reason asserts the batch path maps a
// signer permission error to an actionable Reason carrying the
// group/relaunch guidance (audit item B).
func TestRunBatch_WritePermission_Reason(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &batchSign{err: signpkg.ErrSignerPermission}
	ssh := &batchSSH{}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           sign,
		SSH:            ssh,
		SignerSockPath: "/run/sshgatesigner/sign.sock",
	}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/x"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if !out.Denied {
		t.Error("Denied=false; want true on permission failure")
	}
	if !strings.Contains(out.Reason, "sshgatesigner group") || !strings.Contains(out.Reason, "Log out") {
		t.Errorf("Reason=%q; want the actionable group/relaunch guidance", out.Reason)
	}
	// #26-core: batch Denial mirrors the Reason token.
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictSignerPermission {
		t.Errorf("out.Denial=%+v; want signer_permission", out.Denial)
	}
	if len(ssh.calls) != 0 {
		t.Error("SSH was called despite signer permission failure")
	}
}

// TestRun_WriteGateDeny77_Annotated asserts that a gate deny (exit 77,
// err=nil) on a write is annotated with remediation instead of being
// surfaced as a silent non-zero exit (audit item E).
func TestRun_WriteGateDeny77_Annotated(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: "SSHGATE_SIG:a:b"}}}
	ssh := &fakeSSH{exit: 77} // gate deny: missing sig / read-only
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected an annotated error on gate deny exit 77, got nil")
	}
	if !strings.Contains(err.Error(), "exit 77") || !strings.Contains(err.Error(), "/sshgate:setup") {
		t.Errorf("error %q is not the exit-77 gate-deny remediation", err.Error())
	}
	// #26-core M1: exit 77 → missing_signature, escalate_to_human, NOT retryable
	// (the MCP already signed this Tier-2 write; 77 means tier mismatch /
	// stripped sig, so re-soliciting a fresh tap would loop).
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictMissingSignature {
		t.Errorf("out.Denial=%+v; want missing_signature", out.Denial)
	}
	if out.Denial != nil && out.Denial.Retryable {
		t.Error("Retryable=true for exit 77; want false (M1)")
	}
}

// TestRun_WriteGateDeny65_Annotated asserts exit 65 (bad/expired sig) is
// annotated with the clock-skew/retry remediation.
func TestRun_WriteGateDeny65_Annotated(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: "SSHGATE_SIG:a:b"}}}
	ssh := &fakeSSH{exit: 65} // gate deny: bad/expired signature
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected an annotated error on gate deny exit 65, got nil")
	}
	if !strings.Contains(err.Error(), "exit 65") || !strings.Contains(err.Error(), "retry") {
		t.Errorf("error %q is not the exit-65 gate-deny remediation", err.Error())
	}
	// #26-core: exit 65 → bad_signature, retry, retryable=true (retry once).
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictBadSignature {
		t.Errorf("out.Denial=%+v; want bad_signature", out.Denial)
	}
	if out.Denial != nil && (out.Denial.RequiredAction != tools.ActionRetry || !out.Denial.Retryable) {
		t.Errorf("exit 65 Denial action=%q retryable=%v; want retry/true", out.Denial.RequiredAction, out.Denial.Retryable)
	}
}

// TestRunBatch_WriteGateDeny77_AnnotatesStderr asserts the batch path
// folds the exit-77 remediation into the write result's Stderr.
func TestRunBatch_WriteGateDeny77_AnnotatesStderr(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	writes := []string{"rm /tmp/x"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	ssh := &batchSSH{byContains: []sshResponse{{match: "rm /tmp/x", exit: 77}}}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: writes,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("Results=%d; want 1", len(out.Results))
	}
	if out.Results[0].ExitCode != 77 {
		t.Errorf("ExitCode=%d; want 77", out.Results[0].ExitCode)
	}
	if !strings.Contains(out.Results[0].Stderr, "exit 77") {
		t.Errorf("Stderr=%q; want the exit-77 gate-deny annotation", out.Results[0].Stderr)
	}
	// #26-core N1: a per-command gate deny sets a batch-level Denial while the
	// batch ran (Denied=false, Results populated).
	if out.Denied {
		t.Error("Denied=true; want false — the batch ran, only a per-command gate deny occurred")
	}
	if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictMissingSignature {
		t.Errorf("out.Denial=%+v; want batch-level missing_signature", out.Denial)
	}
}
