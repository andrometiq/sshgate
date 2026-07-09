package tools_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestPing_ReachableServer asserts a server whose probe returns SSHGATE_OK
// reports Reachable=true, and — critically — that ping is READ-class: the
// probe carries the empty SSH_ORIGINAL_COMMAND and the signer is NEVER
// engaged (no sign request, no approval).
func TestPing_ReachableServer(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	ssh := &fakeSSH{stdout: []byte("SSHGATE_OK\n")}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Ping(context.Background(), tools.PingInput{Alias: "h1"})
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !out.Reachable {
		t.Errorf("Reachable=false; want true (err=%q)", out.Error)
	}
	if out.Alias != "h1" {
		t.Errorf("Alias=%q; want h1", out.Alias)
	}
	// The probe must be the empty SSHGATE_OK probe — no shell command.
	if ssh.gotCmd != "" {
		t.Errorf("probe cmd=%q; want empty (SSHGATE_OK probe)", ssh.gotCmd)
	}
	// Read-class: the signer must never be touched by ping.
	if sign.signCalled {
		t.Error("sign was called by ping; ping must be read-only (no signer, no tap)")
	}
}

// TestPing_SSHError asserts a probe failure is REPORTED in the output
// (Reachable=false + Error), not surfaced as a Go error — a reachability
// verdict for a known alias is always data, never an error.
func TestPing_SSHError(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{err: errors.New("dial: connection refused")}}

	out, err := runner.Ping(context.Background(), tools.PingInput{Alias: "h1"})
	if err != nil {
		t.Fatalf("Ping returned a Go error; want the verdict in the output: %v", err)
	}
	if out.Reachable {
		t.Error("Reachable=true; want false on an SSH error")
	}
	if out.Error == "" {
		t.Error("Error is empty; want the dial-failure string")
	}
}

// TestPing_NonGateOKProbeUnreachable asserts a probe that succeeds at the
// SSH layer but whose body is not SSHGATE_OK is treated as unreachable
// (same rule status uses).
func TestPing_NonGateOKProbeUnreachable(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte("hello world\n")}}

	out, err := runner.Ping(context.Background(), tools.PingInput{Alias: "h1"})
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if out.Reachable {
		t.Error("Reachable=true; want false (probe body was not SSHGATE_OK)")
	}
}

// TestPing_UnknownAlias asserts an unregistered alias is a Go error naming
// the alias (there is nothing to probe).
func TestPing_UnknownAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}

	_, err := runner.Ping(context.Background(), tools.PingInput{Alias: "nope"})
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should mention the alias: %v", err)
	}
}

// TestPing_SurfacesReadOnlyTier asserts ping reports the server's tier from
// the registry regardless of reachability (an unreachable read-only server
// still has a known tier — W3-7).
func TestPing_SurfacesReadOnlyTier(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "ro", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{err: errors.New("down")}}

	out, err := runner.Ping(context.Background(), tools.PingInput{Alias: "ro"})
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if out.Reachable {
		t.Error("Reachable=true; want false (server is down)")
	}
	if !out.ReadOnly {
		t.Error("ReadOnly=false; want true (registry read-only entry, reported even when unreachable)")
	}
}

// TestPing_NilSSHRejected asserts a nil SSH dependency is a configuration
// error rather than a panic.
func TestPing_NilSSHRejected(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}}
	_, err := runner.Ping(context.Background(), tools.PingInput{Alias: "h1"})
	if err == nil {
		t.Fatal("expected error when SSH is nil")
	}
}
