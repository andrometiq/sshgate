package tools_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// batchSign is a batch-aware Sign fake. It records every sign call so
// tests can assert the request was made exactly once with the right
// commands.
type batchSign struct {
	mu       sync.Mutex
	calls    int
	gotReqID string
	gotCmds  []signpkg.CmdReq
	signed   []signpkg.Signed
	authMode string
	err      error
}

func (f *batchSign) Sign(_ context.Context, requestID string, cmds []signpkg.CmdReq) (signpkg.SignResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.gotReqID = requestID
	f.gotCmds = append([]signpkg.CmdReq(nil), cmds...)
	return signpkg.SignResult{Signed: f.signed, AuthMode: f.authMode}, f.err
}

// RequestGrant / RevokeGrant satisfy SignClient; batch tests never use
// the grant paths.
func (f *batchSign) RequestGrant(_ context.Context, _, _, _ string, _ []string, _ int64) (string, int64, error) {
	return "", 0, nil
}
func (f *batchSign) RevokeGrant(_ context.Context, _, _ string) error { return nil }
func (f *batchSign) ListGrants(_ context.Context, _, _ string) ([]signpkg.GrantInfo, error) {
	return nil, nil
}

// batchSSH records every Run call so tests can verify ordering, count,
// and per-command output mapping.
type batchSSH struct {
	mu sync.Mutex
	// responses keys on the *exact* command string passed to Run; if a
	// key is missing the default zero values + nil err apply. Tests
	// register write entries by their wire-prefix suffix (the literal
	// command) via the `byContains` map below.
	byContains  []sshResponse
	calls       []string
	defaultExit int
}

type sshResponse struct {
	// match is a substring; the first response whose match appears in
	// the cmd is returned. Order matters when overlap is possible.
	match  string
	stdout string
	stderr string
	exit   int
	err    error
}

func (f *batchSSH) Run(_ context.Context, _, _ string, _ int, cmd string) ([]byte, []byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	for _, r := range f.byContains {
		if strings.Contains(cmd, r.match) {
			return []byte(r.stdout), []byte(r.stderr), r.exit, r.err
		}
	}
	return nil, nil, f.defaultExit, nil
}

// makeSignedFor returns a []signpkg.Signed list parallel to writeCmds —
// each entry is a realistic SSHGATE_SIG wire prefix for that command.
func makeSignedFor(t *testing.T, writeCmds []string) []signpkg.Signed {
	t.Helper()
	out := make([]signpkg.Signed, len(writeCmds))
	for i, c := range writeCmds {
		payload := sigwire.SigPayload{Cmd: c, TS: 1, Exp: 60, Nonce: "n"}
		wire, err := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = signpkg.Signed{Cmd: c, Sig: wire}
	}
	return out
}

func newRegistryForBatch(t *testing.T) *registry.Servers {
	t.Helper()
	return newRegistryWith(t, "h1", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(),
	})
}

func TestRunBatch_AllReads_NoSignCall(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"df -h", "uptime", "whoami"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sign.calls != 0 {
		t.Errorf("sign called %d times for all-reads batch; want 0", sign.calls)
	}
	if len(ssh.calls) != 3 {
		t.Fatalf("ssh.calls=%d; want 3", len(ssh.calls))
	}
	if len(out.Results) != 3 {
		t.Fatalf("Results=%d; want 3", len(out.Results))
	}
	for i, res := range out.Results {
		if res.Kind != "read" {
			t.Errorf("Results[%d].Kind=%q; want read", i, res.Kind)
		}
		if res.Skipped {
			t.Errorf("Results[%d].Skipped=true; want false", i)
		}
	}
	if out.Approved {
		t.Error("Approved=true on all-reads batch; want false")
	}
}

func TestRunBatch_AllWrites_OneSignCall(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	writes := []string{"apt update", "apt install -y nginx", "systemctl restart nginx"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: writes,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sign.calls != 1 {
		t.Fatalf("sign.calls=%d; want 1", sign.calls)
	}
	if len(sign.gotCmds) != 3 {
		t.Errorf("sign.gotCmds=%d; want 3", len(sign.gotCmds))
	}
	for i, want := range writes {
		if sign.gotCmds[i].Cmd != want {
			t.Errorf("sign.gotCmds[%d].Cmd=%q; want %q", i, sign.gotCmds[i].Cmd, want)
		}
		// Spec defines Server as the registered alias, not the host
		// (audit M7).
		if sign.gotCmds[i].Server != "h1" {
			t.Errorf("sign.gotCmds[%d].Server=%q; want %q (alias, not host)", i, sign.gotCmds[i].Server, "h1")
		}
		if sign.gotCmds[i].TTLSec != 60 {
			t.Errorf("sign.gotCmds[%d].TTLSec=%d; want 60", i, sign.gotCmds[i].TTLSec)
		}
	}
	if sign.gotReqID == "" {
		t.Error("sign.gotReqID is empty")
	}
	if len(ssh.calls) != 3 {
		t.Fatalf("ssh.calls=%d; want 3", len(ssh.calls))
	}
	for i, c := range ssh.calls {
		if !strings.HasPrefix(c, "SSHGATE_SIG:") {
			t.Errorf("ssh.calls[%d]=%q; want SSHGATE_SIG: prefix", i, c)
		}
		if !strings.HasSuffix(c, " "+writes[i]) {
			t.Errorf("ssh.calls[%d]=%q; want suffix %q", i, c, " "+writes[i])
		}
	}
	if !out.Approved {
		t.Error("Approved=false; want true")
	}
	if out.Denied {
		t.Error("Denied=true; want false")
	}
	if len(out.Results) != 3 {
		t.Fatalf("Results=%d; want 3", len(out.Results))
	}
	for i, res := range out.Results {
		if res.Kind != "write" {
			t.Errorf("Results[%d].Kind=%q; want write", i, res.Kind)
		}
		if res.Command != writes[i] {
			t.Errorf("Results[%d].Command=%q; want %q", i, res.Command, writes[i])
		}
	}
}

// TestRunBatch_WritesPassRegistryFingerprint pins that every write in a batch
// is bound to the server's registry host-key fingerprint, read in code from
// the trusted entry — the agent (which supplies only alias + commands) can
// never influence the binding. Without this, a bulk approval could be minted
// unbound and replayed elsewhere.
func TestRunBatch_WritesPassRegistryFingerprint(t *testing.T) {
	t.Parallel()
	const wantFP = "SHA256:batchHostKeyFingerprintAAAAAAAAAAAAAAAAAAAAA"
	r := newRegistryWith(t, "h1", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: wantFP,
	})
	writes := []string{"apt update", "systemctl restart nginx"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	if _, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias: "h1", Commands: writes,
	}); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(sign.gotCmds) != 2 {
		t.Fatalf("sign.gotCmds=%d; want 2", len(sign.gotCmds))
	}
	for i := range sign.gotCmds {
		if sign.gotCmds[i].Host != wantFP {
			t.Errorf("sign.gotCmds[%d].Host=%q; want %q (registry fingerprint, not agent input)", i, sign.gotCmds[i].Host, wantFP)
		}
	}
}

func TestRunBatch_MixedReadWriteRead_SignsOnlyTheWrite(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	cmds := []string{"df -h", "rm /tmp/x", "uptime"}
	writes := []string{"rm /tmp/x"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: cmds,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sign.calls != 1 {
		t.Fatalf("sign.calls=%d; want 1", sign.calls)
	}
	if len(sign.gotCmds) != 1 || sign.gotCmds[0].Cmd != "rm /tmp/x" {
		t.Errorf("sign.gotCmds=%+v; want only the write", sign.gotCmds)
	}
	if len(ssh.calls) != 3 {
		t.Fatalf("ssh.calls=%d; want 3", len(ssh.calls))
	}
	if ssh.calls[0] != "df -h" {
		t.Errorf("ssh.calls[0]=%q; want raw read 'df -h'", ssh.calls[0])
	}
	if !strings.HasPrefix(ssh.calls[1], "SSHGATE_SIG:") || !strings.HasSuffix(ssh.calls[1], " rm /tmp/x") {
		t.Errorf("ssh.calls[1]=%q; want signed write", ssh.calls[1])
	}
	if ssh.calls[2] != "uptime" {
		t.Errorf("ssh.calls[2]=%q; want raw read 'uptime'", ssh.calls[2])
	}
	if !out.Approved {
		t.Error("Approved=false; want true (the write was approved)")
	}
	if len(out.Results) != 3 {
		t.Fatalf("Results=%d; want 3", len(out.Results))
	}
	if out.Results[0].Kind != "read" {
		t.Errorf("Results[0].Kind=%q; want read", out.Results[0].Kind)
	}
	if out.Results[1].Kind != "write" {
		t.Errorf("Results[1].Kind=%q; want write", out.Results[1].Kind)
	}
	if out.Results[2].Kind != "read" {
		t.Errorf("Results[2].Kind=%q; want read", out.Results[2].Kind)
	}
}

func TestRunBatch_WriteDenied_NoSSH(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{err: signpkg.ErrDenied}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/x", "uptime"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(ssh.calls) != 0 {
		t.Errorf("ssh.calls=%v; want 0 on denial", ssh.calls)
	}
	if !out.Denied {
		t.Error("Denied=false; want true")
	}
	if out.Approved {
		t.Error("Approved=true; want false on denial")
	}
	if out.Reason != "denied" {
		t.Errorf("Reason=%q; want denied", out.Reason)
	}
	if len(out.Results) != 0 {
		t.Errorf("Results=%d; want 0 on denial", len(out.Results))
	}
}

func TestRunBatch_WriteTimeout(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{err: signpkg.ErrTimeout}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/x"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if out.Reason != "timeout" {
		t.Errorf("Reason=%q; want timeout", out.Reason)
	}
	if !out.Denied {
		t.Error("Denied=false; want true on timeout")
	}
	if len(ssh.calls) != 0 {
		t.Errorf("ssh called on timeout: %v", ssh.calls)
	}
}

func TestRunBatch_WriteUnreachable(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{err: signpkg.ErrUnreachable}
	ssh := &batchSSH{}
	// No SignerSockPath set → the socket is absent on disk, so an
	// unreachable error is the Tier-1 "no signer configured" case and
	// the Reason carries the actionable upgrade path (audit item D).
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/x"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if !strings.Contains(out.Reason, "no signer configured") || !strings.Contains(out.Reason, "/sshgate:setup") {
		t.Errorf("Reason=%q; want the Tier-1 'no signer configured … /sshgate:setup' guidance", out.Reason)
	}
	if !out.Denied {
		t.Error("Denied=false; want true on unreachable")
	}
}

// TestRunBatch_AllReadDefault_ContinuesOnError pins the W5-12 default: an
// ALL-READ batch with no explicit stop_on_error CONTINUES past a non-zero
// exit (reads are independent diagnostics that legitimately fail — an absent
// file, an empty crontab — so one failure must not skip the rest).
func TestRunBatch_AllReadDefault_ContinuesOnError(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	// All reads (no sign call); second command exits non-zero.
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "uptime", exit: 0, stdout: "up"},
			{match: "false-cmd", exit: 1, stderr: "boom"},
			{match: "df -h", exit: 0, stdout: "ok"},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	// Use only read commands so failure semantics aren't tangled with
	// approvals; leave stop_on_error nil to exercise the read-batch default.
	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"uptime", "grep -r 'false-cmd' /etc", "df -h"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(out.Results) != 3 {
		t.Fatalf("Results=%d; want 3", len(out.Results))
	}
	if out.Results[1].ExitCode != 1 {
		t.Errorf("Results[1].ExitCode=%d; want 1 (the failing command)", out.Results[1].ExitCode)
	}
	// The KEY assertion: the third read still runs — no skip on an all-read
	// batch with the default.
	for i, res := range out.Results {
		if res.Skipped {
			t.Errorf("Results[%d].Skipped=true; want false (all-read default is continue-on-error)", i)
		}
	}
	if len(ssh.calls) != 3 {
		t.Errorf("ssh.calls=%d; want 3 (all reads run on the all-read default)", len(ssh.calls))
	}
}

// TestRunBatch_AllReadExplicitStopOnError_Aborts pins that an EXPLICIT
// stop_on_error=true still aborts an all-read batch (the caller's explicit
// value always wins over the read-batch default).
func TestRunBatch_AllReadExplicitStopOnError_Aborts(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "uptime", exit: 0, stdout: "up"},
			{match: "false-cmd", exit: 1, stderr: "boom"},
			{match: "df -h", exit: 0, stdout: "ok"},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	stop := true
	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:       "h1",
		Commands:    []string{"uptime", "grep -r 'false-cmd' /etc", "df -h"},
		StopOnError: &stop,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if !out.Results[2].Skipped {
		t.Error("Results[2].Skipped=false; want true (explicit stop_on_error=true aborts)")
	}
	if len(ssh.calls) != 2 {
		t.Errorf("ssh.calls=%d; want 2 (third skipped on explicit stop)", len(ssh.calls))
	}
}

// TestRunBatch_WriteBatchDefault_AbortsOnError pins that a batch containing
// ANY write keeps the stop-on-error default (write ordering matters): with
// stop_on_error nil, a non-zero write aborts the remainder.
func TestRunBatch_WriteBatchDefault_AbortsOnError(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	writes := []string{"rm /tmp/a"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	// The write exits non-zero; the trailing read must be skipped.
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "rm /tmp/a", exit: 1, stderr: "boom"},
			{match: "df -h", exit: 0, stdout: "ok"},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"rm /tmp/a", "df -h"}, // write + read → default stop
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if out.Results[0].Kind != "write" {
		t.Fatalf("Results[0].Kind=%q; want write", out.Results[0].Kind)
	}
	if !out.Results[1].Skipped {
		t.Error("Results[1].Skipped=false; want true (write batch defaults to stop-on-error)")
	}
	if len(ssh.calls) != 1 {
		t.Errorf("ssh.calls=%d; want 1 (read skipped after the failing write)", len(ssh.calls))
	}
}

// TestRunBatch_WriteBatchExplicitStopFalse_RunsAll pins that an explicit
// stop_on_error=false runs a write batch to completion despite a non-zero
// exit (explicit override wins over the write-batch default).
func TestRunBatch_WriteBatchExplicitStopFalse_RunsAll(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	writes := []string{"rm /tmp/a"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "rm /tmp/a", exit: 1, stderr: "boom"},
			{match: "df -h", exit: 0, stdout: "ok"},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	stop := false
	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:       "h1",
		Commands:    []string{"rm /tmp/a", "df -h"},
		StopOnError: &stop,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	for i, res := range out.Results {
		if res.Skipped {
			t.Errorf("Results[%d].Skipped=true; want false (explicit stop_on_error=false runs all)", i)
		}
	}
	if len(ssh.calls) != 2 {
		t.Errorf("ssh.calls=%d; want 2 (both run despite the failing write)", len(ssh.calls))
	}
}

func TestRunBatch_StopOnErrorFalse_RunsAll(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "uptime", exit: 0},
			{match: "false-cmd", exit: 1},
			{match: "df", exit: 0},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	stop := false
	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:       "h1",
		Commands:    []string{"uptime", "grep -r 'false-cmd' /etc", "df -h"},
		StopOnError: &stop,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if len(out.Results) != 3 {
		t.Fatalf("Results=%d; want 3", len(out.Results))
	}
	for i, res := range out.Results {
		if res.Skipped {
			t.Errorf("Results[%d].Skipped=true; want false (StopOnError=false runs all)", i)
		}
	}
	if len(ssh.calls) != 3 {
		t.Errorf("ssh.calls=%d; want 3", len(ssh.calls))
	}
}

func TestRunBatch_EmptyCommands_NoCalls(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: nil,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sign.calls != 0 {
		t.Errorf("sign.calls=%d; want 0 on empty input", sign.calls)
	}
	if len(ssh.calls) != 0 {
		t.Errorf("ssh.calls=%d; want 0 on empty input", len(ssh.calls))
	}
	if len(out.Results) != 0 {
		t.Errorf("Results=%d; want 0", len(out.Results))
	}
	if out.Approved {
		t.Error("Approved=true; want false on empty input")
	}
}

func TestRunBatch_SingleCommandActsLikeRun(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	ssh := &batchSSH{
		byContains: []sshResponse{{match: "df -h", exit: 0, stdout: "ok"}},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"df -h"},
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sign.calls != 0 {
		t.Errorf("sign.calls=%d; want 0 for single read", sign.calls)
	}
	if len(out.Results) != 1 || out.Results[0].Kind != "read" {
		t.Errorf("Results=%+v; want one read result", out.Results)
	}
	if out.Results[0].Stdout != "ok" {
		t.Errorf("Results[0].Stdout=%q; want ok", out.Results[0].Stdout)
	}
}

func TestRunBatch_UnknownAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	runner := &tools.Runner{Servers: r, Sign: &batchSign{}, SSH: &batchSSH{}}

	_, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "nope",
		Commands: []string{"df -h"},
	})
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should mention the alias: %v", err)
	}
}
