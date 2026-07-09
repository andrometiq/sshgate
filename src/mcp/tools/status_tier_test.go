package tools_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestStatus_Tier1SignerNotConfigured asserts that when the signer
// socket does not exist (Tier 1: no daemon installed), status reports
// Configured=false rather than presenting it as a failure. Audit M4.
func TestStatus_Tier1SignerNotConfigured(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            newTrackingSSH(),
		SignerSockPath: filepath.Join(dir, "nonexistent.sock"),
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if out.SignerSocket.Reachable {
		t.Error("Reachable = true; want false (socket absent)")
	}
	if out.SignerSocket.Configured {
		t.Error("Configured = true; want false (Tier 1: socket file absent)")
	}
	// The probed path must be reported verbatim.
	if out.SignerSocket.Path != runner.SignerSockPath {
		t.Errorf("Path = %q; want %q", out.SignerSocket.Path, runner.SignerSockPath)
	}
}

// TestStatus_Tier2SignerConfiguredAndReachable asserts that when the
// socket exists and dials, both Configured and Reachable are true.
func TestStatus_Tier2SignerConfiguredAndReachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "signer.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            newTrackingSSH(),
		SignerSockPath: sockPath,
	}
	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !out.SignerSocket.Reachable {
		t.Errorf("Reachable = false; want true (err=%q)", out.SignerSocket.Error)
	}
	if !out.SignerSocket.Configured {
		t.Error("Configured = false; want true (socket present and dialable)")
	}
}

// TestStatus_SurfacesReadOnlyTier asserts status reports each server's tier
// (ServerStatus.ReadOnly) from the registry — and, critically, that the tier
// is reported REGARDLESS of reachability (an unreachable read-only server
// still has a known tier). W3-7.
func TestStatus_SurfacesReadOnlyTier(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := r.Add("ro-up", registry.Entry{Host: "up.example.com", Port: 22, User: "u", AddedAt: now, ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("ro-down", registry.Entry{Host: "down.example.com", Port: 22, User: "u", AddedAt: now, ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("rw", registry.Entry{Host: "rw.example.com", Port: 22, User: "u", AddedAt: now}); err != nil {
		t.Fatal(err)
	}
	ssh := newTrackingSSH()
	ssh.setOK("up.example.com", "SSHGATE_OK\n")
	ssh.setErr("down.example.com", fmt.Errorf("dial: connection refused"))
	ssh.setOK("rw.example.com", "SSHGATE_OK\n")
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            ssh,
		SignerSockPath: filepath.Join(dir, "absent.sock"),
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	byAlias := make(map[string]tools.ServerStatus, len(out.Servers))
	for _, sv := range out.Servers {
		byAlias[sv.Alias] = sv
	}
	if !byAlias["ro-up"].ReadOnly || !byAlias["ro-up"].Reachable {
		t.Errorf("ro-up = %+v; want ReadOnly=true Reachable=true", byAlias["ro-up"])
	}
	if !byAlias["ro-down"].ReadOnly || byAlias["ro-down"].Reachable {
		t.Errorf("ro-down = %+v; want ReadOnly=true (tier surfaced even when unreachable) Reachable=false", byAlias["ro-down"])
	}
	if byAlias["rw"].ReadOnly {
		t.Errorf("rw = %+v; want ReadOnly=false (signed-write)", byAlias["rw"])
	}
}
